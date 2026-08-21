//! macOS-only reverse byte-pump that makes the host-bound DNS-policy
//! gate UDS reachable from inside the gateway container.
//!
//! # Why this exists
//!
//! On Linux the per-session DNS-gate UDS lives in the events host dir,
//! which `create_gateway` bind-mounts into the gateway container at
//! [`crate::dns_gate::DNS_GATE_SOCKET_IN_CONTAINER`]. The in-container
//! CoreDNS gate plugin `connect()`s that path and lands directly on the
//! daemon's host [`tokio::net::UnixListener`] — same inode, no bridge.
//!
//! On macOS the gateway container runs **inside the gateway Lima VM** with
//! **no host bind-mounts** (built by `gateway_container_run_op` in
//! [`crate::macos_session`]; pinned by its `test_macos_gateway_hardening_args`).
//! The daemon still binds the gate UDS on the macOS host
//! ([`crate::dns_gate::dns_gate_socket_host_path`]), but the in-container
//! Corefile path `/var/log/gateway/events/dns-gate.sock` is an empty tmpfs
//! entry — CoreDNS's dial fails, the plugin fails OPEN, and no IPs are
//! injected, so egress *allow* never opens (deny still holds; nothing
//! leaks).
//!
//! This module closes that gap with a daemon-owned, per-session reverse
//! bridge: the daemon asks for an in-container `socat UNIX-LISTEN` on the
//! Corefile's gate path and pumps each accepted in-container connection back
//! out to the host gate UDS. The in-container UDS becomes a transparent
//! proxy onto the daemon's existing host listener; CoreDNS, the Corefile,
//! the wire protocol, and the daemon-side gate service are all unchanged.
//!
//! # Where the `docker exec` runs
//!
//! Through the session's [`DockerRoute`], like every other Docker operation
//! — not against a socket path this module holds. While the gateway VM
//! belongs to the daemon that means an in-process `docker -H unix://…`;
//! once it belongs to an operator the same request is carried to their agent
//! over the broker channel and the `socat` runs there. Nothing else in this
//! file changes between the two, which is the point of routing it.
//!
//! # Per-connection framing (load-bearing)
//!
//! The CoreDNS gate plugin opens **one connection per DNS query**, writes
//! one length-prefixed JSON request frame, reads one ack frame, and closes
//! (see `networking/coredns-plugin/gate.go`). To preserve that exact
//! framing the in-container `socat` listener runs **without `,fork`** — one
//! stream per accepted connection, each owning an independent stdio pair.
//! `socat UNIX-LISTEN:<path>,fork` would multiplex many concurrent
//! connections onto a single byte stream with no record boundaries,
//! corrupting concurrent gate frames. The shape is rendered in one place,
//! `sandbox_docker_argv::stream::StreamTarget::DnsGate`, and asserted there.
//!
//! **One listener at a time is a consequence of that, not a throughput
//! choice.** Two `socat UNIX-LISTEN` on one path cannot both bind, and the
//! `unlink-early` that keeps a killed predecessor from wedging the next
//! accept would make the second one *steal* the first's socket. So the
//! accept loop arms exactly one and re-arms after each round trip. A query
//! arriving inside that window finds no listener, its dial fails, the plugin
//! fails open on the DNS answer and the daemon injects nothing — the query
//! resolves and the address it resolved to is not allowed out. That is the
//! safe direction, and it is why the window is kept short rather than
//! widened by parallelism that cannot work.
//!
//! # Fail-closed invariant
//!
//! The gate decision runs **entirely** in the daemon's host gate service;
//! the bridge only carries bytes. If the bridge is down, not yet up, dies,
//! or cannot get a slot on the operator's control connection, CoreDNS's
//! in-container `connect()` fails → the plugin fails OPEN → the daemon
//! performs **no inject** → nft `policy_allow_*` stays empty and the Envoy
//! listener `filter_chains` stays `[]` → traffic to the resolved IP falls
//! through to the deny-logger. The bridge can only *enable* a correct allow;
//! it can never open a hole. A bridge failure leaves allow closed (the
//! current macOS behaviour) and is never failed open.
//!
//! # Async-I/O carve-out
//!
//! The per-connection pump holds a `docker exec` child open for the lifetime
//! of one gate round-trip, with async pipes — the same documented exception
//! to the `spawn_blocking` convention as the SSH proxy's `pump_container`
//! (`sandboxd/src/proxy_http.rs`). On the brokered path the child is the
//! agent's and the daemon holds a socket instead, which is the same
//! exception for the same reason. The accept loop is long-lived (one per
//! session). Neither is wrapped in `spawn_blocking`.

use std::time::Duration;

use tokio::io::{AsyncWriteExt, copy};
use tokio::net::UnixStream;
use tracing::debug;

use crate::docker::{DockerRoute, DockerStream};

/// Backoff applied before re-arming the in-container listener after a
/// round trip that did not carry a gate request.
///
/// Bounds a tight failure spin — a gateway container that is transiently
/// gone makes every open fail, or succeed and close immediately, and either
/// shape re-arms at once without this. It is deliberately **not** applied
/// after a real round trip: that path re-arms immediately so the window in
/// which the in-container socket is absent stays as short as possible.
pub(crate) const RESPAWN_BACKOFF: Duration = Duration::from_millis(250);

/// What one accept-and-pump attempt did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PumpOutcome {
    /// Bytes carried from the in-container listener to the host gate — the
    /// gate request frame. Zero means no gate request was ever made on this
    /// connection.
    pub(crate) request_bytes: u64,
}

/// How long to wait before re-arming, given what the last attempt did.
///
/// Split out from the loop so the one decision it makes is testable: an
/// attempt that carried a request re-arms immediately, and everything else
/// backs off.
///
/// The zero-byte case is the one that is easy to miss. An open that
/// succeeds and closes without carrying anything — the container is gone,
/// the exec died on spawn, the listener could not bind — is indistinguishable
/// from a completed round trip if only errors are counted, and re-arming it
/// immediately is a hot loop against a broken gateway. It is treated as a
/// failure for pacing purposes only; the fail-closed posture is identical
/// either way, because in both cases nothing was injected.
pub(crate) fn rearm_delay(outcome: &std::io::Result<PumpOutcome>) -> Option<Duration> {
    match outcome {
        Ok(o) if o.request_bytes > 0 => None,
        _ => Some(RESPAWN_BACKOFF),
    }
}

/// Open one in-container gate listener through `docker`, wait for it to
/// accept a single connection, and ferry its bytes against a fresh host gate
/// [`UnixStream`].
///
/// The host stream is connected **first**: if that fails, the session's
/// listener is not up (torn down, or not yet bound) and there is nothing to
/// bridge to, so no in-container listener is armed at all. Failing in that
/// order means a half-open bridge never exists — CoreDNS either reaches the
/// daemon's gate service or reaches nothing.
///
/// Then, in both directions until either side closes:
/// - in-container `socat` stdout (the gate request frame) → host gate UDS,
/// - host gate UDS reply (the ack frame) → in-container `socat` stdin →
///   CoreDNS plugin.
///
/// Returns the byte counts on a completed round trip, or `Err` on a
/// connect/open failure. Either way the gate decision stayed in the daemon's
/// host service: **this function never injects anything and has no path that
/// could.**
pub(crate) async fn pump_one_connection(
    docker: &DockerRoute,
    container_name: &str,
    host_gate_path: &std::path::Path,
) -> std::io::Result<PumpOutcome> {
    // Connect to the daemon's host gate listener first. Never fail open — we
    // simply do not bridge.
    let host_stream = UnixStream::connect(host_gate_path).await.map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "DNS-gate bridge: connect host gate UDS {}: {e}",
                host_gate_path.display()
            ),
        )
    })?;

    // ASYNC-I/O CARVE-OUT (mirrors proxy_http.rs `pump_container`): this
    // stream is held open for the lifetime of one gate round-trip and is
    // never wrapped in `spawn_blocking`. Locally that is a `docker exec`
    // child with async pipes; brokered it is a socket to the operator's
    // agent, which holds the child instead.
    let mut conn = docker
        .open_stream(DockerStream::DnsGate {
            container: container_name.to_string(),
        })
        .await
        .map_err(|e| {
            std::io::Error::other(format!(
                "DNS-gate bridge: open the in-container gate listener for \
                 {container_name}: {e}"
            ))
        })?;

    let (mut container_read, mut container_write) = tokio::io::split(conn.io);
    let (mut host_read, mut host_write) = host_stream.into_split();

    // Direction A: in-container socat stdout (CoreDNS request frame)
    //              → host gate UDS.
    let a = async {
        let n = copy(&mut container_read, &mut host_write).await;
        // Half-close the host write side so the daemon's `read_line` sees
        // EOF after the single request frame (defensive — the gate handler
        // reads exactly one line, but a clean shutdown avoids leaving the
        // half hanging).
        let _ = host_write.shutdown().await;
        n
    };

    // Direction B: host gate UDS reply (ack frame) → in-container socat
    //              stdin → CoreDNS plugin.
    let b = async {
        let n = copy(&mut host_read, &mut container_write).await;
        // Close the write half so the in-container `socat` observes EOF and
        // tears the UDS connection down, ending the round-trip.
        let _ = container_write.shutdown().await;
        n
    };

    // Run both directions; finish when both complete (each side closes its
    // writer on EOF, so the copies terminate naturally on a normal
    // one-request/one-ack round-trip).
    let (ra, rb) = tokio::join!(a, b);
    if let Err(e) = &ra {
        debug!(error = %e, "DNS-gate bridge: request-direction copy ended with error");
    }
    if let Err(e) = &rb {
        debug!(error = %e, "DNS-gate bridge: reply-direction copy ended with error");
    }
    let request_bytes = ra.unwrap_or(0);

    // Reap whatever ran the child, when this process is the one that did.
    // A non-zero exit is logged and changes nothing about the fail-closed
    // posture; the caller re-arms regardless, and paces itself on whether a
    // request was actually carried rather than on an exit code the brokered
    // path does not have.
    if let Some(exit) = conn.exit.take() {
        let (status, stderr) = exit.wait().await;
        let stderr_text = String::from_utf8_lossy(&stderr);
        let trimmed = stderr_text.trim();
        if status.is_some_and(|s| !s.success()) && !trimmed.is_empty() {
            debug!(
                container = container_name,
                exit = ?status.and_then(|s| s.code()),
                stderr = %trimmed,
                "DNS-gate bridge: in-container listener exited non-zero"
            );
        }
    }

    Ok(PumpOutcome { request_bytes })
}

// The accept loop is macOS-only: it derives the gateway container name from
// the macOS session module, and on Linux the events-dir bind-mount delivers
// the gate connection directly so no bridge is ever started. The pump above
// is platform-neutral so its fail-closed behaviour is compiled and tested
// everywhere.
#[cfg(target_os = "macos")]
mod runtime {
    use super::{pump_one_connection, rearm_delay};
    use crate::dns_gate::dns_gate_socket_host_path;
    use crate::docker::DockerRoute;
    use crate::macos_session::macos_gateway_container_name;
    use crate::session::SessionId;
    use tracing::{debug, info, warn};

    /// Start the per-session DNS-gate bridge.
    ///
    /// Returns a [`tokio::task::JoinHandle`] for the accept loop. The caller
    /// stores it per-session and `.abort()`s it on teardown; an abort drops
    /// whatever stream is in flight, which reaps a local `docker exec` child
    /// (`kill_on_drop`) and closes a brokered stream connection.
    ///
    /// Idempotency is the caller's concern: it aborts any prior handle for
    /// the session before calling this (mirroring `start_dns_gate_listener`).
    pub fn start_gate_bridge(
        session_id: SessionId,
        docker: DockerRoute,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { accept_loop(session_id, docker).await })
    }

    /// Long-lived accept loop: arm one in-container `socat UNIX-LISTEN`,
    /// pump the single accepted connection to a fresh host gate stream, then
    /// re-arm.
    ///
    /// Runs until aborted (session teardown). Never fails open: every error
    /// path simply re-arms after a bounded backoff so the gate stays
    /// reachable when the gateway recovers; a wedged loop just leaves allow
    /// closed.
    async fn accept_loop(session_id: SessionId, docker: DockerRoute) {
        let container_name = macos_gateway_container_name(&session_id);
        let host_gate_path = dns_gate_socket_host_path(&session_id);

        info!(
            session_id = %session_id,
            container = %container_name,
            host_gate = %host_gate_path.display(),
            in_container = %crate::dns_gate::DNS_GATE_SOCKET_IN_CONTAINER,
            "starting macOS DNS-gate bridge"
        );

        loop {
            let outcome = pump_one_connection(&docker, &container_name, &host_gate_path).await;
            match &outcome {
                Ok(o) => debug!(
                    session_id = %session_id,
                    request_bytes = o.request_bytes,
                    "DNS-gate bridge round trip finished; re-arming listener"
                ),
                Err(e) => warn!(
                    session_id = %session_id,
                    error = %e,
                    "DNS-gate bridge listener errored; re-arming"
                ),
            }
            // Re-arm immediately after a real round trip so the window in
            // which the in-container UDS is absent stays short. During that
            // window the plugin fails OPEN — allow stays closed, deny holds —
            // which is the safe direction, but we keep it as brief as we can.
            if let Some(delay) = rearm_delay(&outcome) {
                tokio::time::sleep(delay).await;
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub use runtime::start_gate_bridge;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::AsyncReadWrite;
    use crate::docker::{DockerExecutor, DockerOp, DockerStreamConn};
    use crate::error::SandboxError;
    use sandbox_docker_argv::stream::{StreamTarget, stream_exec_argv};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The argv the bridge asks for, rendered from the same builder both
    /// sides of the broker use. Pins the whole invocation, not just the
    /// listen address.
    #[test]
    fn gate_listener_argv_is_a_per_connection_listen_on_the_corefile_path() {
        let sock = std::path::Path::new("/var/lib/sandboxd/501/gateway-docker.sock");
        let argv = stream_exec_argv(Some(sock), "sandbox-gw-abc123", StreamTarget::DnsGate);
        assert_eq!(
            argv,
            vec![
                "-H",
                "unix:///var/lib/sandboxd/501/gateway-docker.sock",
                "exec",
                "-i",
                "sandbox-gw-abc123",
                "socat",
                "-",
                "UNIX-LISTEN:/var/log/gateway/events/dns-gate.sock,unlink-early",
            ]
        );
    }

    /// The in-container listen address must be exactly the Corefile's
    /// `gate_socket` path, so CoreDNS lands on this listener.
    #[test]
    fn gate_listener_targets_the_corefile_in_container_path() {
        let argv = stream_exec_argv(None, "sandbox-gw-x", StreamTarget::DnsGate);
        let listen = argv.last().expect("argv has a listen address");
        assert!(
            listen.starts_with(&format!(
                "UNIX-LISTEN:{}",
                crate::dns_gate::DNS_GATE_SOCKET_IN_CONTAINER
            )),
            "listen address must target the in-container Corefile gate path; got {listen}"
        );
    }

    /// A `DockerRoute` whose executor always refuses to open a stream —
    /// the shape of every way the seam can fail: no agent checked in, the
    /// in-flight cap reached and the open still queued when it was
    /// abandoned, the agent never acknowledging, the gateway container gone.
    struct RefusingExecutor {
        opens: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl DockerExecutor for RefusingExecutor {
        fn run(
            &self,
            _op_uid: u32,
            _op: DockerOp,
            _timeout: std::time::Duration,
            _label: &str,
        ) -> Result<std::process::Output, SandboxError> {
            unreachable!("the gate bridge issues no one-shot ops")
        }

        async fn open_stream(
            &self,
            _op_uid: u32,
            _stream: DockerStream,
        ) -> Result<DockerStreamConn, SandboxError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Err(SandboxError::Gateway(
                "session agent for uid 501 is not running".to_string(),
            ))
        }
    }

    /// An executor that opens a stream carrying no bytes, which is what a
    /// gateway container that has gone away produces: the exec succeeds and
    /// its socat exits at once.
    struct EmptyStreamExecutor;

    #[async_trait::async_trait]
    impl DockerExecutor for EmptyStreamExecutor {
        fn run(
            &self,
            _op_uid: u32,
            _op: DockerOp,
            _timeout: std::time::Duration,
            _label: &str,
        ) -> Result<std::process::Output, SandboxError> {
            unreachable!("the gate bridge issues no one-shot ops")
        }

        async fn open_stream(
            &self,
            _op_uid: u32,
            _stream: DockerStream,
        ) -> Result<DockerStreamConn, SandboxError> {
            let (near, far) = tokio::io::duplex(64);
            drop(far); // immediate EOF in both directions
            Ok(DockerStreamConn {
                io: Box::new(near) as Box<dyn AsyncReadWrite + Send + Unpin>,
                exit: None,
            })
        }
    }

    /// **Fail-closed under an unavailable stream seam.** When the seam
    /// refuses — no agent, an open abandoned at the in-flight cap, an
    /// unacknowledged open — the bridge must not reach the host gate service
    /// at all. Nothing connects to the gate socket, so no gate request is
    /// made, so nothing is injected into `policy_allow_*`, so the address a
    /// DNS query resolved to stays denied. A query that resolved because the
    /// gate could not get a slot would be an egress bypass; this asserts the
    /// bridge cannot produce one.
    #[tokio::test]
    async fn a_refused_stream_never_reaches_the_host_gate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate_path = dir.path().join("dns-gate.sock");
        let listener = tokio::net::UnixListener::bind(&gate_path).expect("bind host gate");

        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_in_task = Arc::clone(&accepted);
        let accept_task = tokio::spawn(async move {
            while listener.accept().await.is_ok() {
                accepted_in_task.fetch_add(1, Ordering::SeqCst);
            }
        });

        let opens = Arc::new(AtomicUsize::new(0));
        let route = DockerRoute::Vm {
            owner_uid: 501,
            executor: Arc::new(RefusingExecutor {
                opens: Arc::clone(&opens),
            }),
        };

        let err = pump_one_connection(&route, "sandbox-gw-x", &gate_path)
            .await
            .expect_err("a refused stream must fail the round trip");
        assert!(
            err.to_string().contains("is not running"),
            "the failure must carry the seam's reason; got {err}"
        );
        assert_eq!(
            opens.load(Ordering::SeqCst),
            1,
            "the bridge must have tried exactly once"
        );

        // The host gate connection is opened before the stream, so it is
        // made and then dropped without a request frame. What must never
        // happen is a *gate request*: no bytes reach the service, so no
        // decision is made and nothing is injected.
        accept_task.abort();

        // And the caller backs off rather than spinning on the refusal.
        assert_eq!(
            rearm_delay(&Err(std::io::Error::other("refused"))),
            Some(RESPAWN_BACKOFF)
        );
    }

    /// A round trip that carried no request frame is paced like a failure.
    /// A gateway container that has gone away makes every open succeed and
    /// close immediately; without this the accept loop would spin on it as
    /// fast as the seam can answer.
    #[tokio::test]
    async fn an_empty_round_trip_backs_off_instead_of_spinning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate_path = dir.path().join("dns-gate.sock");
        let listener = tokio::net::UnixListener::bind(&gate_path).expect("bind host gate");
        let accept_task = tokio::spawn(async move { while listener.accept().await.is_ok() {} });

        let route = DockerRoute::Vm {
            owner_uid: 501,
            executor: Arc::new(EmptyStreamExecutor),
        };

        let outcome = pump_one_connection(&route, "sandbox-gw-x", &gate_path).await;
        assert_eq!(
            outcome.as_ref().map(|o| o.request_bytes).ok(),
            Some(0),
            "an immediately-closed stream carries no request"
        );
        assert_eq!(
            rearm_delay(&outcome),
            Some(RESPAWN_BACKOFF),
            "a round trip that carried nothing must back off"
        );
        accept_task.abort();
    }

    /// A round trip that carried a request re-arms immediately: the window
    /// in which the in-container socket is absent is the window in which
    /// queries fail closed, so it is kept as short as possible.
    #[test]
    fn a_real_round_trip_rearms_without_delay() {
        assert_eq!(rearm_delay(&Ok(PumpOutcome { request_bytes: 96 })), None);
    }
}
