//! UDP listener: emit one `deny` event per received datagram, discard
//! the payload, send no response.
//!
//! Spec reference: Part 3 / "Listener design / UDP listener" (lines
//! 812-818) and "Hardening rules" §§ 1, 2, 4.
//!
//! The socket is opened with `setsockopt(IP_RECVORIGDSTADDR, 1)` so that
//! `recvmsg` yields the pre-DNAT destination via the `IP_ORIGDSTADDR`
//! ancillary cmsg. The receive buffer is a fixed 128 bytes on the
//! stack — per-datagram allocation would be an unbounded memory footprint
//! under a deny storm, violating hardening invariant #2. The full
//! datagram is received but discarded; only the cmsg contributes to the
//! emitted event.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use nix::libc;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrIn, recvmsg, setsockopt, sockopt};
use tokio::io::Interest;
use tokio::net::UdpSocket;

use chrono::Utc;

use crate::event::{DenyRecord, EventEmitter, Protocol};
use crate::limits::{Admit, RateCap};

/// Fixed per-datagram receive buffer size. Anything longer than this is
/// silently truncated by `recvmsg` — acceptable since we never inspect
/// payload bytes (hardening invariant #4). Spec Part 3 / "Hardening
/// rules" § 2 calls for a fixed small buffer "sized for headers only".
const RECV_BUF_SIZE: usize = 128;

/// Bind a UDP listener on `(bind_ip, port)` with `IP_RECVORIGDSTADDR=1`
/// so `recvmsg` will surface the pre-DNAT destination as an
/// `Ipv4OrigDstAddr` cmsg.
pub async fn bind(bind_ip: Ipv4Addr, port: u16) -> io::Result<UdpSocket> {
    let addr = SocketAddr::V4(SocketAddrV4::new(bind_ip, port));
    let socket = UdpSocket::bind(addr).await?;
    // `setsockopt` is a plain syscall — safe to call from async land.
    setsockopt(&socket, sockopt::Ipv4OrigDstAddr, &true)
        .map_err(|e| io::Error::other(format!("IP_RECVORIGDSTADDR: {e}")))?;
    Ok(socket)
}

/// Run the receive loop against an already-bound UDP `socket`, emitting
/// one deny event per received datagram.
///
/// This function is `async` because it bridges tokio's readiness model
/// with `nix::recvmsg`: `socket.ready(Interest::READABLE).await` yields
/// control to the reactor, and `try_io` keeps the call in non-blocking
/// territory (returning `WouldBlock` → we re-await readiness rather than
/// spinning).
pub async fn run(
    socket: UdpSocket,
    emitter: Arc<EventEmitter>,
    rate_cap: Arc<RateCap>,
) -> io::Result<()> {
    loop {
        socket.ready(Interest::READABLE).await?;
        match recv_one(&socket) {
            Ok(Some((record, _payload_len))) => {
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
                // Datagram arrived without an `Ipv4OrigDstAddr` cmsg —
                // can happen pre-DNAT or when the kernel strips the
                // cmsg on a rare error. Count it in operator logs but
                // don't emit a half-attributed event.
                tracing::warn!("udp datagram missing IP_ORIGDSTADDR cmsg");
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => {
                tracing::warn!(error = %err, "udp recvmsg failed");
                continue;
            }
        }
    }
}

/// Single-shot `recvmsg` call. Returns `Some((record, payload_len))`
/// on a fully-attributed datagram, `None` if the cmsg was missing, or
/// an `io::Error` on kernel error.
fn recv_one(socket: &UdpSocket) -> io::Result<Option<(DenyRecord, usize)>> {
    let mut buf = [0u8; RECV_BUF_SIZE];
    let mut iov = [io::IoSliceMut::new(&mut buf)];
    // Space for one `Ipv4OrigDstAddr` cmsg — a `sockaddr_in` plus the
    // `cmsghdr`. `nix`'s `cmsg_space!` macro computes the alignment
    // for us.
    let mut cmsg_space = nix::cmsg_space!(libc::sockaddr_in);

    let msg = socket.try_io(Interest::READABLE, || {
        recvmsg::<SockaddrIn>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_space),
            MsgFlags::empty(),
        )
        .map_err(|errno| io::Error::from_raw_os_error(errno as i32))
    })?;

    let src = msg
        .address
        .map(|a: SockaddrIn| SocketAddrV4::new(a.ip(), a.port()))
        .ok_or_else(|| io::Error::other("udp recvmsg: missing peer address"))?;

    let mut orig_dst: Option<SocketAddrV4> = None;
    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::Ipv4OrigDstAddr(sin) = cmsg {
            let port = u16::from_be(sin.sin_port);
            let octets = sin.sin_addr.s_addr.to_ne_bytes();
            orig_dst = Some(SocketAddrV4::new(
                Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]),
                port,
            ));
        }
    }

    let Some(orig) = orig_dst else {
        return Ok(None);
    };

    Ok(Some((
        DenyRecord {
            orig_dst_ip: *orig.ip(),
            orig_dst_port: orig.port(),
            protocol: Protocol::Udp,
            src_ip: *src.ip(),
            src_port: src.port(),
        },
        msg.bytes,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket as StdUdpSocket;
    use std::sync::Arc;
    use std::time::Duration;

    /// A loopback UDP round-trip without any PREROUTING DNAT in play
    /// still produces an `Ipv4OrigDstAddr` cmsg once `IP_RECVORIGDSTADDR`
    /// is set — the kernel fills it with the destination address the
    /// sender used (which equals the listener's bind address, since no
    /// DNAT rewrote it). We assert that a single deny event is emitted
    /// with `protocol: "udp"` and the expected 5-tuple.
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

        let emit_for_task = Arc::clone(&emitter);
        let rate_cap_for_task = Arc::clone(&rate_cap);
        let task = tokio::spawn(async move {
            let _ = run(socket, emit_for_task, rate_cap_for_task).await;
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
        assert_eq!(json["orig_dst_port"], local.port());
        assert_eq!(json["src_port"], client_local.port());
    }
}
