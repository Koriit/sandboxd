//! UDP listener: emit one `deny` event per received datagram, discard
//! the payload, send no response.
//!
//! Spec reference: Part 3 / "Listener design / UDP listener" (lines
//! 812-818) and "Hardening rules" §§ 1, 2, 4.
//!
//! ## Pre-DNAT recovery (M12-S1)
//!
//! The cmsg path (`IP_RECVORIGDSTADDR` / `IP_ORIGDSTADDR`) is unsuitable
//! for the gateway's UDP deny path: PREROUTING rewrites the destination
//! to `gateway_ip:10002` (the deny-logger's bind address), and the
//! kernel populates `IP_ORIGDSTADDR` with the *post-DNAT* destination,
//! not the original VM-targeted one. TCP escapes this because
//! `getsockopt(SO_ORIGINAL_DST)` reads from the conntrack entry the
//! kernel threaded through the accepted socket fd; UDP has no per-flow
//! fd.
//!
//! The supported recovery path is a netfilter conntrack netlink lookup
//! ([`crate::conntrack`]). For each datagram we:
//!
//! 1. Read the post-DNAT 4-tuple `(src, dst)` from `recvmsg` —
//!    `src = vm_ip:vm_port` (the datagram's peer), `dst =
//!    gateway_ip:10002` (the listener's own bind address).
//! 2. Send an `IPCTNL_MSG_CT_GET` keyed on the REPLY tuple
//!    `(gateway_ip:10002 → vm_ip:vm_port)`. Conntrack records the
//!    REPLY direction with the *post-DNAT* source (because the reply
//!    will come from the rewritten destination), so the post-DNAT
//!    4-tuple is exactly the REPLY direction.
//! 3. Parse `CTA_TUPLE_ORIG.dst` from the kernel reply — that is the
//!    pre-DNAT destination the VM dialled.
//!
//! On lookup failure (entry GC'd, kernel race, protocol error) the
//! receive loop falls back to emitting the deny event with the
//! post-DNAT destination plus a `tracing::warn!` so the failure mode is
//! observable. We intentionally do **not** drop the deny event on
//! lookup failure: losing a deny attribution is strictly worse than
//! emitting one with a less-accurate destination, since downstream
//! discovery flows can still recognise the wrong-tuple shape (and the
//! warn log is the operator signal).
//!
//! The receive buffer is a fixed 128 bytes on the stack — per-datagram
//! allocation would be an unbounded memory footprint under a deny
//! storm, violating hardening invariant #2. The full datagram is
//! received but discarded; only conntrack and the recvmsg peer
//! contribute to the emitted event.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use nix::sys::socket::{MsgFlags, SockaddrIn, recvmsg};
use tokio::io::Interest;
use tokio::net::UdpSocket;

use chrono::Utc;

use crate::conntrack::{ConntrackLookup, LookupError};
use crate::event::{DenyRecord, EventEmitter, Protocol};
use crate::limits::{Admit, RateCap};

/// Fixed per-datagram receive buffer size. Anything longer than this is
/// silently truncated by `recvmsg` — acceptable since we never inspect
/// payload bytes (hardening invariant #4). Spec Part 3 / "Hardening
/// rules" § 2 calls for a fixed small buffer "sized for headers only".
const RECV_BUF_SIZE: usize = 128;

/// Bind a UDP listener on `(bind_ip, port)`.
///
/// Note: previous revisions set `IP_RECVORIGDSTADDR=1` here so the
/// receive loop could read the cmsg destination — that path was removed
/// in M12-S1 because the cmsg returns the post-DNAT destination, not
/// the pre-DNAT one. Pre-DNAT recovery now happens via conntrack
/// netlink lookup; the listener no longer reads any cmsg, so the
/// setsockopt is unnecessary.
pub async fn bind(bind_ip: Ipv4Addr, port: u16) -> io::Result<UdpSocket> {
    let addr = SocketAddr::V4(SocketAddrV4::new(bind_ip, port));
    UdpSocket::bind(addr).await
}

/// Run the receive loop against an already-bound UDP `socket`, emitting
/// one deny event per received datagram.
///
/// `bind_addr` is the listener's own `(ip, port)` — this is the
/// post-DNAT destination as seen by the kernel and must be passed in
/// so the conntrack lookup can construct the REPLY tuple. It is
/// deterministic per-process (set at startup from CLI args) so passing
/// it explicitly avoids a `getsockname` per datagram.
///
/// `lookup` is the [`ConntrackLookup`] handle owned by this loop.
/// `Option`-typed so unit tests on loopback (no DNAT in play) can pass
/// `None` and exercise the post-DNAT-fallback path; production always
/// supplies `Some(lookup)`.
///
/// This function is `async` because it bridges tokio's readiness model
/// with `nix::recvmsg`: `socket.ready(Interest::READABLE).await` yields
/// control to the reactor, and `try_io` keeps the call in non-blocking
/// territory (returning `WouldBlock` → we re-await readiness rather than
/// spinning).
pub async fn run(
    socket: UdpSocket,
    bind_addr: SocketAddrV4,
    mut lookup: Option<ConntrackLookup>,
    emitter: Arc<EventEmitter>,
    rate_cap: Arc<RateCap>,
) -> io::Result<()> {
    loop {
        socket.ready(Interest::READABLE).await?;
        match recv_one(&socket) {
            Ok(Some(post_dnat_src)) => {
                let orig_dst = match lookup.as_mut() {
                    Some(lk) => match lk.lookup_pre_dnat_dst(post_dnat_src, bind_addr) {
                        Ok(pre) => pre,
                        Err(LookupError::NotFound) => {
                            // Race with conntrack GC or no DNAT was
                            // applied (e.g. unit-test loopback). Fall
                            // back to bind_addr so the deny event is
                            // still emitted; the warn lets operators
                            // distinguish this case from a real
                            // pre-DNAT match against bind_addr (which
                            // can't happen in production since the
                            // listener bind is internal).
                            tracing::warn!(
                                src = %post_dnat_src,
                                dst = %bind_addr,
                                "conntrack lookup miss; falling back to post-DNAT dst"
                            );
                            bind_addr
                        }
                        Err(err) => {
                            tracing::warn!(
                                src = %post_dnat_src,
                                dst = %bind_addr,
                                error = %err,
                                "conntrack lookup failed; falling back to post-DNAT dst"
                            );
                            bind_addr
                        }
                    },
                    None => bind_addr,
                };
                let record = DenyRecord {
                    orig_dst_ip: *orig_dst.ip(),
                    orig_dst_port: orig_dst.port(),
                    protocol: Protocol::Udp,
                    src_ip: *post_dnat_src.ip(),
                    src_port: post_dnat_src.port(),
                };
                // Rate cap check happens *after* recvmsg — we must
                // drain the datagram from the kernel queue regardless
                // of whether we emit (leaving it would stall the
                // listener). Over-cap datagrams are dropped silently
                // and counted into the periodic summary.
                if rate_cap.try_admit(Utc::now()) == Admit::Ok {
                    emitter.emit_deny(record);
                }
            }
            Ok(None) => {
                // recvmsg returned no peer address — kernel-level
                // anomaly (should not happen for a connected datagram
                // socket). Count it in operator logs.
                tracing::warn!("udp datagram missing peer address");
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => {
                tracing::warn!(error = %err, "udp recvmsg failed");
                continue;
            }
        }
    }
}

/// Single-shot `recvmsg` call. Returns `Some(src)` with the datagram's
/// peer address on a successfully-received datagram, `None` if recvmsg
/// returned no peer (kernel anomaly), or an `io::Error` on kernel
/// error.
///
/// This is a pure data-plane operation — it no longer parses cmsgs.
/// Pre-DNAT destination recovery is the caller's responsibility (via
/// [`crate::conntrack::ConntrackLookup`]).
fn recv_one(socket: &UdpSocket) -> io::Result<Option<SocketAddrV4>> {
    let mut buf = [0u8; RECV_BUF_SIZE];
    let mut iov = [io::IoSliceMut::new(&mut buf)];

    let msg = socket.try_io(Interest::READABLE, || {
        recvmsg::<SockaddrIn>(socket.as_raw_fd(), &mut iov, None, MsgFlags::empty())
            .map_err(|errno| io::Error::from_raw_os_error(errno as i32))
    })?;

    let src = msg
        .address
        .map(|a: SockaddrIn| SocketAddrV4::new(a.ip(), a.port()));

    Ok(src)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket as StdUdpSocket;
    use std::sync::Arc;
    use std::time::Duration;

    /// A loopback UDP round-trip without any PREROUTING DNAT in play.
    /// With `lookup = None` (no conntrack consultation, post-DNAT
    /// fallback), the listener emits a deny record carrying the
    /// listener's own bind address as `orig_dst` and the sender's
    /// peer address as `src`. This pins the wire shape and the
    /// post-DNAT-fallback path for the unit-test path.
    ///
    /// We can't easily exercise the full conntrack lookup in a unit
    /// test (it requires `CAP_NET_ADMIN` and a real conntrack-DNAT
    /// flow); the integration test
    /// `integration_udp_send_to_non_allowlisted_destination_emits_deny_event`
    /// in `sandboxd/tests/m10_s3_end_to_end.rs` covers that path
    /// against a real gateway container, and a load-shape test
    /// `integration_udp_load_pre_dnat_attribution_holds_under_concurrent_flows`
    /// asserts attribution under multi-flow contention.
    #[tokio::test]
    async fn udp_emits_one_deny_event_per_datagram() {
        use crate::limits::RateCap;
        use chrono::Utc;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = Arc::new(EventEmitter::open(&path).unwrap());
        let rate_cap = Arc::new(RateCap::new(1_000, Arc::clone(&emitter), Utc::now()));
        let socket = bind(Ipv4Addr::LOCALHOST, 0).await.unwrap();
        let local = socket.local_addr().unwrap();
        let bind_addr = match local {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => panic!("ipv4 bind"),
        };

        let emit_for_task = Arc::clone(&emitter);
        let rate_cap_for_task = Arc::clone(&rate_cap);
        let task = tokio::spawn(async move {
            let _ = run(socket, bind_addr, None, emit_for_task, rate_cap_for_task).await;
        });

        // Send one datagram from a blocking std socket so the test
        // doesn't race tokio's async send semantics.
        let client = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client_local = client.local_addr().unwrap();
        client.send_to(b"hello", local).unwrap();

        // Wait briefly for the emitter to flush.
        tokio::time::sleep(Duration::from_millis(100)).await;
        task.abort();

        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "expected exactly one deny event; got {lines:?}"
        );
        let json: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(json["event"], "deny");
        assert_eq!(json["protocol"], "udp");
        // With `lookup = None`, the listener falls back to bind_addr
        // for orig_dst — which on loopback is the listener's own
        // ephemeral port.
        assert_eq!(json["orig_dst_port"], local.port());
        assert_eq!(json["src_port"], client_local.port());
    }
}
