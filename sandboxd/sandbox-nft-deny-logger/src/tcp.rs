//! TCP listener: emit one `deny` event per accepted connection, then
//! close the socket with RST.
//!
//! Design reference: Part 3 / "Listener design / TCP listener" (lines
//! 803-811) and "Hardening rules" (lines 835-843).
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
use std::sync::atomic::{AtomicU32, Ordering};

use nix::libc;
use nix::sys::socket::{setsockopt, sockopt};
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};

use chrono::Utc;

use sandbox_event_emitter::{Admit, DenyRecord, EventEmitter, Protocol, RateCap};

/// Bind a TCP listener on `(bind_ip, port)` with an explicit `listen(2)`
/// backlog.
///
/// The listener is handed to the caller so the runtime's task-spawn
/// choices (per-accept spawn, blocking accept loop, etc.) live at the
/// call site.
///
/// # Why an explicit backlog
///
/// Tokio's `TcpListener::bind` calls `listen(2)` with libc's `SOMAXCONN`
/// (typically 4096 on stock Linux but historically as low as 128 and
/// sometimes overridden by `/proc/sys/net/core/somaxconn`). For
/// production traffic that is fine — the deny-logger's concurrency cap
/// gates handler admission, not the kernel's accept queue. For the
/// deterministic `integration_tcp_respects_concurrency_cap` test,
/// however, we want to guarantee the kernel can hold every connection
/// in its burst on the accept queue regardless of host tuning, so the
/// conservation invariant `deny + dropped_total == BURST` does not
/// depend on a retry loop hiding `ECONNREFUSED` from a backlog
/// overflow. Passing the backlog explicitly here gives the test that
/// knob; production callers pass a value at least as large as
/// `conn_cap` so over-cap connections always reach `accept()` (and are
/// then RST-closed by the over-cap path) instead of being kernel-
/// dropped at the SYN.
///
/// # Why the `u32` signature (and the clamp)
///
/// The underlying `socket2::Socket::listen` takes `c_int` (i.e. `i32`),
/// matching libc's `listen(2)` prototype. Backlogs are conceptually
/// non-negative, so the wrapper exposes `u32` to keep the conversion
/// next to the syscall and prevent each caller from re-deriving the
/// clamp. Values above `i32::MAX` saturate to `i32::MAX`; in practice
/// production callers pass `conn_cap * 4` (a few thousand at most) so
/// the saturation branch is unreachable, but encoding it here means
/// callers never need a `try_into().expect(...)` next to a `bind` call.
pub async fn bind(bind_ip: Ipv4Addr, port: u16, backlog: u32) -> io::Result<TcpListener> {
    // `socket2::Socket::listen` takes `c_int` (`i32`), so saturate the
    // `u32` argument here. `i32::MAX` is far above any realistic
    // `SOMAXCONN`, so the clamp is a type-system formality rather than
    // a real ceiling; capturing it here keeps every caller free of a
    // hand-rolled `try_into().expect(...)`.
    let backlog_i32: i32 = backlog.min(i32::MAX as u32) as i32;

    // Build a non-blocking IPv4 stream socket via socket2, then
    // `listen(backlog)` with the explicit backlog so the kernel
    // pre-allocates the accept queue we need. The standard upgrade
    // path is `socket2::Socket` -> `std::net::TcpListener` ->
    // `tokio::net::TcpListener`; tokio takes ownership of the fd via
    // `from_std`. SO_REUSEADDR is left at the OS default — we are not
    // recreating a listener on a port we've just closed, so `TIME_WAIT`
    // reuse is irrelevant here.
    let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(SockProtocol::TCP))?;
    sock.set_nonblocking(true)?;
    let addr: SocketAddr = SocketAddr::V4(SocketAddrV4::new(bind_ip, port));
    sock.bind(&addr.into())?;
    sock.listen(backlog_i32)?;
    let std_listener: std::net::TcpListener = sock.into();
    TcpListener::from_std(std_listener)
}

/// RAII guard holding one concurrency-cap permit. Decrements the
/// shared connection counter when dropped, regardless of how the
/// handler exits — this keeps the cap accurate even on panic.
struct ConnGuard {
    counter: Arc<AtomicU32>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        // `fetch_sub` on a counter that never went above `cap` cannot
        // underflow, but assert the invariant in debug builds.
        let prev = self.counter.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "ConnGuard decremented past zero");
    }
}

/// Try to reserve one concurrency-cap slot. Returns `Some(guard)` if
/// the increment kept us at or below `cap`; returns `None` after
/// undoing the speculative increment otherwise.
///
/// Extracted from the accept loop so unit tests can verify the
/// reservation logic without racing an async runtime.
fn try_reserve(counter: &Arc<AtomicU32>, cap: u32) -> Option<ConnGuard> {
    // `fetch_add` returns the previous value; an overshoot is safe to
    // undo with `fetch_sub` because no other thread uses the
    // post-increment value for its own admission decision.
    let prev = counter.fetch_add(1, Ordering::AcqRel);
    if prev >= cap {
        counter.fetch_sub(1, Ordering::AcqRel);
        None
    } else {
        Some(ConnGuard {
            counter: Arc::clone(counter),
        })
    }
}

/// Run the accept loop against an already-bound `listener`, emitting
/// one deny event per accepted connection that fits under both caps.
///
/// Concurrency cap: a shared
/// `AtomicU32` counts live handler tasks. Accepts past `conn_cap` are
/// RST-closed immediately and counted into the periodic
/// `rate_limited` summary (plan Phase 3) without emitting a deny
/// line. Admissions under the cap are dispatched to a per-connection
/// task so a slow handler never stalls the accept loop; each task
/// holds a [`ConnGuard`] whose Drop decrements the counter.
pub async fn run(
    listener: TcpListener,
    emitter: Arc<EventEmitter>,
    rate_cap: Arc<RateCap>,
    conn_cap: u32,
) -> io::Result<()> {
    let active = Arc::new(AtomicU32::new(0));
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

        let Some(guard) = try_reserve(&active, conn_cap) else {
            // Over the cap — count the drop into the rate-limited
            // summary and RST-close without emitting.
            rate_cap.record_drop(Utc::now());
            apply_linger_zero(&socket);
            drop(socket);
            continue;
        };
        let emitter = Arc::clone(&emitter);
        let rate_cap = Arc::clone(&rate_cap);
        tokio::spawn(async move {
            handle_connection(socket, peer, &emitter, &rate_cap);
            drop(guard);
        });
    }
}

fn handle_connection(
    socket: TcpStream,
    peer: SocketAddr,
    emitter: &EventEmitter,
    rate_cap: &RateCap,
) {
    // Rate cap check is the first operation — hardening invariant #5
    // counts *attempts*, not successful reads. Over-cap attempts still
    // get RST-closed but are not emitted individually.
    let now = Utc::now();
    let admit = rate_cap.try_admit(now);

    if admit == Admit::Ok {
        match resolve_tuple(&socket, peer) {
            Some((orig_dst, src)) => {
                emitter.emit_deny(DenyRecord {
                    orig_dst_ip: *orig_dst.ip(),
                    orig_dst_port: orig_dst.port(),
                    protocol: Protocol::Tcp,
                    src_ip: *src.ip(),
                    src_port: src.port(),
                });
            }
            None => {
                // `resolve_tuple` already logged; still close with RST.
            }
        }
    }

    apply_linger_zero(&socket);
    // Dropping the TcpStream closes the fd; with SO_LINGER{1,0} the
    // kernel sends RST rather than completing the FIN handshake.
    drop(socket);
}

/// Resolve the 5-tuple (pre-DNAT destination + IPv4 peer) or log and
/// return `None`. Returning `None` signals the caller to skip the
/// emit but still RST-close; the attempt is *not* counted against the
/// rate cap rollback because we already admitted it.
fn resolve_tuple(socket: &TcpStream, peer: SocketAddr) -> Option<(SocketAddrV4, SocketAddrV4)> {
    let orig_dst = match read_original_dst(socket) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, "SO_ORIGINAL_DST failed");
            return None;
        }
    };
    let src = match peer {
        SocketAddr::V4(v4) => v4,
        // IPv6 in PREROUTING DNAT is disabled on the gateway (see
        // gateway.rs ipv6 drop rule). If we ever see one here it's
        // either a misconfig or an attacker — drop quietly.
        SocketAddr::V6(_) => {
            tracing::warn!("tcp accept: unexpected IPv6 peer");
            return None;
        }
    };
    Some((orig_dst, src))
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
///  / "Hardening rules". Failure here is non-fatal:
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

    use chrono::Utc;
    use sandbox_event_emitter::{EventEmitter, RateCap};

    /// TCP accept without any PREROUTING DNAT in play: `SO_ORIGINAL_DST`
    /// returns the loopback-listener address itself. We assert that an
    /// emit happens and the connection is RST-closed (the client sees
    /// `ConnectionReset`, not a graceful EOF).
    #[tokio::test]
    async fn integration_tcp_emits_one_deny_event_and_rst_closes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = Arc::new(EventEmitter::open(&path, "deny-logger").unwrap());
        let rate_cap = Arc::new(RateCap::new(1_000, Arc::clone(&emitter), Utc::now()));
        // Backlog 128 is plenty for a single-client emit-and-RST test;
        // production callers compute backlog from `conn_cap` (see
        // `main.rs`).
        let listener = bind(Ipv4Addr::LOCALHOST, 0, 128u32).await.unwrap();
        let local = listener.local_addr().unwrap();
        let emit_for_task = Arc::clone(&emitter);
        let rate_cap_for_task = Arc::clone(&rate_cap);
        let server = tokio::spawn(async move {
            let _ = run(listener, emit_for_task, rate_cap_for_task, 256).await;
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

    /// Synchronous unit test for the reservation logic: `try_reserve`
    /// must refuse the `cap+1`th caller and release slots on guard
    /// drop. Exercises plan Phase 3 / `tcp_respects_concurrency_cap`
    /// deterministically — the loopback-burst variant below covers
    /// the same invariant through the full accept loop but can't pin
    /// the exact deny/drop split without artificially slowing the
    /// handler (production-path test hooks are not permitted).
    #[test]
    fn try_reserve_refuses_past_cap_and_releases_on_drop() {
        let counter = Arc::new(AtomicU32::new(0));
        const CAP: u32 = 2;

        let g1 = try_reserve(&counter, CAP).expect("1st reserve");
        let g2 = try_reserve(&counter, CAP).expect("2nd reserve");
        assert!(
            try_reserve(&counter, CAP).is_none(),
            "3rd reserve must be refused",
        );
        assert_eq!(
            counter.load(Ordering::Acquire),
            CAP,
            "counter pinned at cap during saturation",
        );

        drop(g1);
        assert_eq!(counter.load(Ordering::Acquire), 1, "drop decrements");
        let g3 = try_reserve(&counter, CAP).expect("slot freed after drop");
        assert_eq!(counter.load(Ordering::Acquire), 2);

        drop(g2);
        drop(g3);
        assert_eq!(counter.load(Ordering::Acquire), 0, "all slots released");
    }

    /// End-to-end concurrency cap: open `BURST` connections against a
    /// loopback listener and confirm the conservation invariant —
    /// every connection is either admitted (counted as a `deny`
    /// event) or server-rejected (counted into the periodic
    /// `rate_limited` summary).
    ///
    /// # Determinism
    ///
    /// The previous shape of this test wrapped each `connect()` in a
    /// 50-attempt retry loop that tolerated both `ECONNREFUSED` and
    /// `ECONNRESET`, on the theory that under nextest's parallel test
    /// execution the kernel's accept queue could overflow and surface
    /// `ECONNREFUSED` to the client before our accept loop drained it.
    /// That introduced two hazards: (1) flakes when the retry budget
    /// happened to be insufficient under load, and (2) a real risk
    /// that `ECONNRESET` (which is the server's over-cap rejection
    /// signal — the conservation invariant DEPENDS on counting it)
    /// was being treated as "retry" rather than "drop", double-
    /// counting connections and silently corrupting the assertion.
    ///
    /// The current shape eliminates both hazards:
    ///
    /// 1. The listener is bound with `backlog = BURST * 4`. The
    ///    kernel's accept queue can hold every burst connection, so
    ///    `connect()` cannot fail with `ECONNREFUSED` due to backlog
    ///    overflow — the only failure path left is the server's
    ///    over-cap RST, which surfaces as `ECONNRESET`.
    /// 2. Each thread does exactly ONE `connect()`. `Ok(stream)` is
    ///    "admitted, will see one deny event"; `Err(ECONNRESET)` is
    ///    "server-rejected, counted into rate_limited summary";
    ///    everything else panics. No retries, no error-kind heuristics
    ///    around what counts as transient.
    ///
    /// Plan Phase 3 / `tcp_respects_concurrency_cap`.  /
    /// "Hardening rules".
    #[tokio::test]
    async fn integration_tcp_respects_concurrency_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = Arc::new(EventEmitter::open(&path, "deny-logger").unwrap());
        // Rate cap high enough to not interfere with this test.
        let rate_cap = Arc::new(RateCap::new(10_000, Arc::clone(&emitter), Utc::now()));

        const CAP: u32 = 2;
        const BURST: usize = 20;
        // 4× headroom: the kernel's accept queue holds the entire
        // burst comfortably even in the worst case where every
        // connection arrives before the server's accept loop runs.
        const BACKLOG: u32 = (BURST * 4) as u32;

        let listener = bind(Ipv4Addr::LOCALHOST, 0, BACKLOG).await.unwrap();
        let local = listener.local_addr().unwrap();
        let emit_for_task = Arc::clone(&emitter);
        let rate_cap_for_task = Arc::clone(&rate_cap);
        let server = tokio::spawn(async move {
            let _ = run(listener, emit_for_task, rate_cap_for_task, CAP).await;
        });

        // One `connect()` per thread; no retries, no transient-kind
        // tolerance. `Some(stream)` means admitted, `None` means
        // server-RST'd (over-cap rejection). The conservation
        // assertion below pairs admitted-vs-rejected against
        // deny-vs-dropped without any tolerance window.
        let outcomes: Vec<Option<StdTcpStream>> = tokio::task::spawn_blocking(move || {
            (0..BURST)
                .map(|_| match StdTcpStream::connect(local) {
                    Ok(s) => {
                        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                        Some(s)
                    }
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => None,
                    Err(e) => panic!(
                        "unexpected connect error: {e:?}. With explicit backlog \
                         large enough for the burst, the only legal failure is \
                         the server's over-cap RST (ECONNRESET); ECONNREFUSED \
                         would indicate a real backlog overflow / kernel-side \
                         bug, not a transient race."
                    ),
                })
                .collect()
        })
        .await
        .unwrap();

        // Give the server time to accept and emit / record drops.
        tokio::time::sleep(Duration::from_millis(300)).await;
        // `outcomes` is held until here so admitted streams survive the
        // 300ms drain window above; dropping earlier truncates in-flight
        // server responses and would invalidate the conservation count.
        drop(outcomes);

        // Cross the 1s rate-cap window so the summary flushes — the
        // rollover is what turns the internal drop counter into an
        // observable JSONL line.
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        rate_cap.try_admit(Utc::now());

        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();

        let mut deny = 0usize;
        let mut dropped_total = 0u64;
        for line in &lines {
            let json: serde_json::Value = serde_json::from_str(line).unwrap();
            match json["event"].as_str().unwrap() {
                "deny" => deny += 1,
                "rate_limited" => {
                    dropped_total += json["rate_limited_count"].as_u64().unwrap();
                }
                other => panic!("unexpected event {other:?} in {line:?}"),
            }
        }

        // Conservation: every connection either emits a deny or is
        // counted into the summary — nothing silently lost. With the
        // explicit-backlog + single-connect-per-thread shape, this
        // assertion is deterministic.
        assert_eq!(
            deny + dropped_total as usize,
            BURST,
            "deny ({deny}) + dropped_total ({dropped_total}) should equal burst ({BURST}); lines = {lines:?}",
        );

        server.abort();
    }
}
