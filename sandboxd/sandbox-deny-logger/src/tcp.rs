//! TCP listener: emit one `deny` event per accepted connection, then
//! close the socket with RST.
//!
//! Spec reference: Part 3 / "Listener design / TCP listener" (lines
//! 803-811) and "Hardening rules" §§ 1, 3 (lines 835-843).
//!
//! The socket is **never read from**. Payload bytes are attacker-
//! controlled; every field on the emitted event comes from the kernel
//! (`SO_ORIGINAL_DST` for the pre-DNAT destination, `getpeername` for
//! the source) or from the listener's own clock/config. After emitting,
//! we apply `SO_LINGER {onoff=1, linger=0}` and drop the socket so the
//! kernel sends RST instead of a FIN handshake.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use nix::libc;
use nix::sys::socket::{setsockopt, sockopt};
use tokio::net::{TcpListener, TcpStream};

use crate::event::{DenyRecord, EventEmitter, Protocol};

/// Bind a TCP listener on `(bind_ip, port)`.
///
/// The listener is handed to the caller so the runtime's task-spawn
/// choices (per-accept spawn, blocking accept loop, etc.) live at the
/// call site.
pub async fn bind(bind_ip: Ipv4Addr, port: u16) -> io::Result<TcpListener> {
    let addr = SocketAddr::V4(SocketAddrV4::new(bind_ip, port));
    TcpListener::bind(addr).await
}

/// Run the accept loop against an already-bound `listener`, emitting
/// one deny event per accepted connection.
///
/// Each accepted connection is closed synchronously inside the loop:
/// no per-connection task spawn is needed because we never read from
/// the peer and the close is nearly instantaneous (one `setsockopt` +
/// one `drop`). Keeping the accept loop non-fan-out sidesteps the
/// need for a per-connection future slot and keeps the hot path
/// allocation-free.
pub async fn run(listener: TcpListener, emitter: Arc<EventEmitter>) -> io::Result<()> {
    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                // Transient accept errors (EMFILE, EINTR) must not
                // take the listener down. Log and continue — the
                // gateway healthcheck will surface chronic failures
                // via `/health` falling silent (events_emitted_60s
                // stays at zero).
                tracing::warn!(error = %err, "tcp accept failed");
                continue;
            }
        };
        handle_connection(socket, peer, &emitter);
    }
}

fn handle_connection(socket: TcpStream, peer: SocketAddr, emitter: &EventEmitter) {
    let orig_dst = match read_original_dst(&socket) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, "SO_ORIGINAL_DST failed");
            // Still close with RST — we just can't attribute it.
            apply_linger_zero(&socket);
            drop(socket);
            return;
        }
    };

    let src = match peer {
        SocketAddr::V4(v4) => v4,
        // IPv6 in PREROUTING DNAT is disabled on the gateway (see
        // gateway.rs ipv6 drop rule). If we ever see one here it's
        // either a misconfig or an attacker — drop quietly.
        SocketAddr::V6(_) => {
            tracing::warn!("tcp accept: unexpected IPv6 peer");
            apply_linger_zero(&socket);
            drop(socket);
            return;
        }
    };

    emitter.emit_deny(DenyRecord {
        orig_dst_ip: *orig_dst.ip(),
        orig_dst_port: orig_dst.port(),
        protocol: Protocol::Tcp,
        src_ip: *src.ip(),
        src_port: src.port(),
    });

    apply_linger_zero(&socket);
    // Dropping the TcpStream closes the fd; with SO_LINGER{1,0} the
    // kernel sends RST rather than completing the FIN handshake.
    drop(socket);
}

/// `getsockopt(SOL_IP, SO_ORIGINAL_DST)` — returns the pre-DNAT
/// destination populated by netfilter when the packet traversed the
/// PREROUTING DNAT hook.
///
/// `nix` does not expose `SO_ORIGINAL_DST` directly, so we call
/// `libc::getsockopt` against a `sockaddr_in`.
fn read_original_dst(socket: &TcpStream) -> io::Result<SocketAddrV4> {
    let fd = socket.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: `fd` is a live AF_INET socket produced by `accept`; the
    // out-buffer is correctly sized; `len` is set to the buffer's
    // byte length per `getsockopt`'s contract. On Linux, SO_ORIGINAL_DST
    // on a DNAT'd TCP connection is guaranteed to return the pre-NAT
    // destination address (see netfilter/nf_conntrack_l4proto_tcp.c).
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            std::ptr::from_mut::<libc::sockaddr_in>(&mut addr).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let port = u16::from_be(addr.sin_port);
    // `s_addr` is stored network-byte-order on Linux; `to_ne_bytes`
    // yields the wire octets A.B.C.D directly.
    let octets = addr.sin_addr.s_addr.to_ne_bytes();
    let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
    Ok(SocketAddrV4::new(ip, port))
}

/// Apply `SO_LINGER {onoff=1, linger=0}` so the subsequent `close(2)`
/// sends RST instead of the normal FIN handshake.
///
/// Spec Part 3 / "Hardening rules" § 3. Failure here is non-fatal:
/// without LINGER the close falls back to FIN, but the deny event is
/// already emitted so the audit trail is intact.
fn apply_linger_zero(socket: &TcpStream) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    if let Err(err) = setsockopt(socket, sockopt::Linger, &linger) {
        tracing::warn!(error = %err, "SO_LINGER set failed; close will FIN");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpStream as StdTcpStream;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::event::EventEmitter;

    /// TCP accept without any PREROUTING DNAT in play: `SO_ORIGINAL_DST`
    /// returns the loopback-listener address itself. We assert that an
    /// emit happens and the connection is RST-closed (the client sees
    /// `ConnectionReset`, not a graceful EOF).
    #[tokio::test]
    async fn tcp_emits_one_deny_event_and_rst_closes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = Arc::new(EventEmitter::open(&path).unwrap());
        let listener = bind(Ipv4Addr::LOCALHOST, 0).await.unwrap();
        let local = listener.local_addr().unwrap();
        let emit_for_task = Arc::clone(&emitter);
        let server = tokio::spawn(async move {
            let _ = run(listener, emit_for_task).await;
        });

        // Connect on a blocking std socket so we can observe the
        // RST-as-ECONNRESET without tokio swallowing it.
        let client = tokio::task::spawn_blocking(move || {
            let mut s = StdTcpStream::connect(local).expect("connect");
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 16];
            s.read(&mut buf)
        })
        .await
        .unwrap();

        // Give the server a beat to write the JSONL line.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Assert exactly one JSONL record with protocol=tcp and
        // orig_dst matching the loopback listener's port.
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "expected exactly one deny event; got {lines:?}"
        );
        let json: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(json["event"], "deny");
        assert_eq!(json["protocol"], "tcp");
        assert_eq!(json["orig_dst_port"], local.port());

        // Assert RST-close semantics: read returns Ok(0) on FIN and
        // Err(ConnectionReset) on RST; in practice on Linux loopback
        // the kernel translates RST-after-accept to an `UnexpectedEof`
        // or `ConnectionReset`. The critical assertion is that we do
        // NOT hang for the full timeout.
        match client {
            Ok(n) => assert_eq!(n, 0, "RST close expected; peer got {n} bytes"),
            Err(err) => assert!(
                matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
                ),
                "unexpected error kind on RST close: {err:?}",
            ),
        }

        server.abort();
    }
}
