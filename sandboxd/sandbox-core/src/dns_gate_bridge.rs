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
//! **no host bind-mounts** ([`crate::macos_session::build_macos_gateway_docker_args`]).
//! The daemon still binds the gate UDS on the macOS host
//! ([`crate::dns_gate::dns_gate_socket_host_path`]), but the in-container
//! Corefile path `/var/log/gateway/events/dns-gate.sock` is an empty tmpfs
//! entry — CoreDNS's dial fails, the plugin fails OPEN, and no IPs are
//! injected, so egress *allow* never opens (deny still holds; nothing
//! leaks).
//!
//! This module closes that gap with a daemon-owned, per-session reverse
//! bridge over the forwarded gateway-VM Docker socket: the daemon listens
//! on the in-container Corefile path (via `docker exec ... socat
//! UNIX-LISTEN:<gate-path>`) and pumps each accepted in-container
//! connection back out to the host gate UDS. The in-container UDS becomes
//! a transparent proxy onto the daemon's existing host listener; CoreDNS,
//! the Corefile, the wire protocol, and the daemon-side gate service are
//! all unchanged.
//!
//! # Per-connection framing (load-bearing)
//!
//! The CoreDNS gate plugin opens **one connection per DNS query**, writes
//! one length-prefixed JSON request frame, reads one ack frame, and closes
//! (see `networking/coredns-plugin/gate.go`). To preserve that exact
//! framing the bridge runs the in-container `socat` listener **without
//! `,fork`** — i.e. one `docker exec` per accepted connection, each owning
//! an independent stdio pair. `socat UNIX-LISTEN:<path>,fork` would
//! multiplex many concurrent connections onto a single stdio byte stream
//! with no record boundaries, corrupting concurrent gate frames. The
//! daemon owns the accept loop: it spawns a one-shot `socat UNIX-LISTEN`
//! exec, pumps it to a fresh host [`tokio::net::UnixStream`], and re-spawns
//! when the connection closes.
//!
//! # Fail-closed invariant
//!
//! The gate decision runs **entirely** in the daemon's host gate service;
//! the bridge only carries bytes. If the bridge is down, not yet up, or
//! dies, CoreDNS's in-container `connect()` fails → the plugin fails OPEN
//! → the daemon performs **no inject** → nft `policy_allow_*` stays empty
//! and the Envoy listener `filter_chains` stays `[]` → traffic to the
//! resolved IP falls through to the deny-logger. The bridge can only
//! *enable* a correct allow; it can never open a hole. A bridge failure
//! leaves allow closed (the current macOS behaviour) and is never failed
//! open.
//!
//! # Async-I/O carve-out
//!
//! The per-connection pump holds a `docker exec` child open for the
//! lifetime of one gate round-trip and uses `tokio::process::Command`
//! with async pipes — the same documented exception to the
//! `spawn_blocking` convention as the SSH proxy's `pump_container`
//! (`sandboxd/src/proxy_http.rs`). The accept loop is long-lived (one per
//! session). Neither is wrapped in `spawn_blocking`.

use crate::dns_gate::DNS_GATE_SOCKET_IN_CONTAINER;

/// Build the `docker exec` argv for one per-connection in-container gate
/// listener:
/// `[-H unix://<sock>] exec -i <container> socat - UNIX-LISTEN:<gate-path>,unlink-early`.
///
/// Pure function so the per-connection (no `,fork`) shape and the
/// socket-awareness (`-H` on macOS, absent otherwise) can be asserted
/// without spawning a process — mirroring `container_proxy_exec_argv` in
/// the SSH proxy.
///
/// Properties this builder guarantees:
/// * **No `,fork`.** Each invocation accepts exactly one in-container UDS
///   connection, pumps it to the exec's stdio, and exits — one independent
///   stdio pair per gate connection, so concurrent gate requests can never
///   interleave on a shared byte stream.
/// * **`unlink-early`.** Removes any stale socket inode left by a prior
///   listener before binding, so a killed-mid-flight predecessor cannot
///   wedge the next accept with `Address already in use`.
/// * **In-container path is `DNS_GATE_SOCKET_IN_CONTAINER`** — the exact
///   path the baked-in Corefile dials, so CoreDNS lands on this listener.
///
/// On macOS the gateway container runs inside the gateway VM, so
/// `docker_socket` is `Some` and the argv carries `-H unix://<sock>`. On
/// Linux this bridge is never started; the builder still accepts `None`
/// (byte-identical to host docker) so the pure shape is testable on all
/// platforms.
pub fn gate_listener_exec_argv(
    docker_socket: Option<&std::path::Path>,
    container_name: &str,
) -> Vec<String> {
    let mut argv: Vec<String> = Vec::with_capacity(8);
    if let Some(sock) = docker_socket {
        argv.push("-H".to_string());
        argv.push(format!("unix://{}", sock.display()));
    }
    argv.push("exec".to_string());
    argv.push("-i".to_string());
    argv.push(container_name.to_string());
    argv.push("socat".to_string());
    argv.push("-".to_string());
    // No `,fork`: one accepted connection per exec. `unlink-early` clears a
    // stale socket left by a killed predecessor before binding.
    argv.push(format!(
        "UNIX-LISTEN:{DNS_GATE_SOCKET_IN_CONTAINER},unlink-early"
    ));
    argv
}

// The runtime accept loop + per-connection pump are macOS-only: they
// spawn `docker exec` against the forwarded gateway-VM socket, which only
// exists on macOS. Linux uses the events-dir bind-mount and never starts a
// bridge.
#[cfg(target_os = "macos")]
mod runtime {
    use super::gate_listener_exec_argv;
    use crate::dns_gate::dns_gate_socket_host_path;
    use crate::macos_session::macos_gateway_container_name;
    use crate::session::SessionId;
    use std::path::PathBuf;
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use tokio::process::Command as TokioCommand;
    use tracing::{debug, info, warn};

    /// Backoff applied before re-spawning the in-container listener after a
    /// spawn/exec error. Bounds a tight failure spin (e.g. the gateway
    /// container is transiently gone) without delaying steady-state
    /// re-arm after a normal connection close (that path skips the
    /// backoff — see [`accept_loop`]).
    const RESPAWN_BACKOFF: Duration = Duration::from_millis(250);

    /// Start the per-session DNS-gate bridge.
    ///
    /// Returns a [`tokio::task::JoinHandle`] for the accept loop. The
    /// caller stores it per-session and `.abort()`s it on teardown
    /// (`kill_on_drop(true)` on each per-connection child means an abort
    /// also reaps any in-flight `docker exec`).
    ///
    /// Idempotency is the caller's concern: it aborts any prior handle for
    /// the session before calling this (mirroring
    /// `start_dns_gate_listener`).
    pub fn start_gate_bridge(
        session_id: SessionId,
        gateway_docker_socket: PathBuf,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { accept_loop(session_id, gateway_docker_socket).await })
    }

    /// Long-lived accept loop: repeatedly spawn a one-shot in-container
    /// `socat UNIX-LISTEN` exec, pump the single accepted connection to a
    /// fresh host gate `UnixStream`, then re-arm.
    ///
    /// Runs until aborted (session teardown). Never fails open: every
    /// error path simply re-arms after a bounded backoff so the gate stays
    /// reachable when the gateway recovers; a wedged loop just leaves allow
    /// closed.
    async fn accept_loop(session_id: SessionId, gateway_docker_socket: PathBuf) {
        let container_name = macos_gateway_container_name(&session_id);
        let host_gate_path = dns_gate_socket_host_path(&session_id);
        let argv = gate_listener_exec_argv(Some(&gateway_docker_socket), &container_name);

        info!(
            session_id = %session_id,
            container = %container_name,
            host_gate = %host_gate_path.display(),
            in_container = %crate::dns_gate::DNS_GATE_SOCKET_IN_CONTAINER,
            "starting macOS DNS-gate bridge"
        );

        loop {
            match pump_one_connection(&argv, &container_name, &host_gate_path).await {
                Ok(()) => {
                    // Normal connection close (one gate round-trip done).
                    // Re-arm immediately to minimise the window in which
                    // the in-container UDS is absent — during that window
                    // the plugin fails OPEN (allow stays closed; deny
                    // holds), which is the safe direction, but we keep it
                    // as short as possible.
                    debug!(
                        session_id = %session_id,
                        "DNS-gate bridge connection closed; re-arming listener"
                    );
                }
                Err(e) => {
                    // Spawn/exec/connect error: back off before re-arming
                    // to avoid a tight spin while the gateway is down.
                    // Fail-closed is preserved: while we back off the
                    // in-container UDS is absent → plugin fails OPEN →
                    // daemon injects nothing → allow stays closed.
                    warn!(
                        session_id = %session_id,
                        error = %e,
                        "DNS-gate bridge listener errored; re-arming after backoff"
                    );
                    tokio::time::sleep(RESPAWN_BACKOFF).await;
                }
            }
        }
    }

    /// Spawn one in-container `socat UNIX-LISTEN` exec, wait for it to
    /// accept a single connection, and ferry its stdio bidirectionally
    /// against a fresh host gate `UnixStream`.
    ///
    /// The host stream is connected **lazily, only after** the exec is
    /// spawned. We open the host gate connection up front (the daemon's
    /// host listener is always bound for a live session) and copy bytes
    /// both ways until either side closes:
    /// - in-container `socat` stdout (the gate request frame) → host gate
    ///   UDS,
    /// - host gate UDS reply (the ack frame) → in-container `socat` stdin
    ///   → CoreDNS plugin.
    ///
    /// Returns `Ok(())` on a clean round-trip (either side closed), `Err`
    /// on a spawn/connect/exit failure so the caller backs off. Either way
    /// the gate decision stayed in the daemon's host service.
    async fn pump_one_connection(
        argv: &[String],
        container_name: &str,
        host_gate_path: &std::path::Path,
    ) -> std::io::Result<()> {
        // Connect to the daemon's host gate listener first. If this fails
        // the session's listener is not up (torn down / not yet bound);
        // surface as an error so the caller backs off and re-arms. Never
        // fail open — we simply do not bridge.
        let host_stream = UnixStream::connect(host_gate_path).await.map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "DNS-gate bridge: connect host gate UDS {}: {e}",
                    host_gate_path.display()
                ),
            )
        })?;

        // ASYNC-I/O CARVE-OUT (mirrors proxy_http.rs `pump_container`):
        // `tokio::process::Command` with async pipes is mandatory here —
        // the `docker exec` child is held open for the lifetime of one
        // gate connection. `kill_on_drop(true)` ensures an aborted accept
        // loop reaps any in-flight exec. Do NOT wrap in `spawn_blocking`.
        let mut command = TokioCommand::new("docker");
        command
            .args(argv)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn().map_err(|e| {
            std::io::Error::other(format!(
                "DNS-gate bridge: spawn docker exec socat for {container_name}: {e}"
            ))
        })?;

        let mut child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("docker exec child has no stdin"))?;
        let mut child_stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("docker exec child has no stdout"))?;
        let mut child_stderr = child.stderr.take();

        // Split the host stream so the two directions run independently.
        let (mut host_read, mut host_write) = host_stream.into_split();

        // Direction A: in-container socat stdout (CoreDNS request frame)
        //              → host gate UDS.
        let a = async {
            let n = tokio::io::copy(&mut child_stdout, &mut host_write).await;
            // Half-close the host write side so the daemon's `read_line`
            // sees EOF after the single request frame (defensive — the
            // gate handler reads exactly one line, but a clean shutdown
            // avoids leaving the half hanging).
            let _ = host_write.shutdown().await;
            n
        };

        // Direction B: host gate UDS reply (ack frame) → in-container
        //              socat stdin → CoreDNS plugin.
        let b = async {
            let n = tokio::io::copy(&mut host_read, &mut child_stdin).await;
            // Close the child's stdin so its `socat` observes EOF and
            // tears the UDS connection down, ending the round-trip.
            let _ = child_stdin.shutdown().await;
            n
        };

        // Run both directions; finish when both complete (each side closes
        // its writer on EOF, so the copies terminate naturally on a normal
        // one-request/one-ack round-trip).
        let (ra, rb) = tokio::join!(a, b);
        if let Err(e) = ra {
            debug!(error = %e, "DNS-gate bridge: request-direction copy ended with error");
        }
        if let Err(e) = rb {
            debug!(error = %e, "DNS-gate bridge: reply-direction copy ended with error");
        }

        // Reap the exec. A non-zero exit is logged but does not change the
        // fail-closed posture; the caller re-arms regardless.
        let status = child.wait().await.ok();
        if let Some(st) = status {
            if !st.success() {
                let mut stderr_buf = Vec::new();
                if let Some(ref mut se) = child_stderr {
                    let _ = se.read_to_end(&mut stderr_buf).await;
                }
                let stderr_text = String::from_utf8_lossy(&stderr_buf);
                let trimmed = stderr_text.trim();
                // A normal connection close can race the socat exit; only
                // surface as an error when stderr indicates a real failure
                // (e.g. the container is gone). Otherwise treat as a clean
                // round-trip so the caller re-arms without backoff.
                if !trimmed.is_empty() {
                    return Err(std::io::Error::other(format!(
                        "DNS-gate bridge: docker exec socat for {container_name} exited \
                         {:?}; stderr: {trimmed}",
                        st.code()
                    )));
                }
            }
        }

        Ok(())
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

    /// macOS bridge: the per-connection in-container listener argv must
    /// carry `-H unix://<sock>` (the forwarded gateway-VM socket), use
    /// `socat - UNIX-LISTEN:<in-container-gate-path>`, and **never** use
    /// `,fork` — one accepted connection per exec is what preserves the
    /// gate's one-connection-per-query framing.
    #[test]
    fn gate_listener_exec_argv_with_socket_is_per_connection_listen() {
        let sock = std::path::Path::new("/var/lib/sandboxd/501/gateway-docker.sock");
        let argv = gate_listener_exec_argv(Some(sock), "sandbox-gw-abc123");
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
    /// `gate_socket` path so CoreDNS lands on the bridge listener. Pins the
    /// path to `DNS_GATE_SOCKET_IN_CONTAINER` (the same constant the
    /// Corefile is generated from on both platforms).
    #[test]
    fn gate_listener_exec_argv_targets_corefile_in_container_path() {
        let sock = std::path::Path::new("/tmp/gw.sock");
        let argv = gate_listener_exec_argv(Some(sock), "sandbox-gw-x");
        let listen = argv.last().expect("argv has a listen address");
        assert!(
            listen.starts_with(&format!("UNIX-LISTEN:{DNS_GATE_SOCKET_IN_CONTAINER}")),
            "listen address must target the in-container Corefile gate path; got {listen}"
        );
    }

    /// The per-connection argv must NEVER carry `,fork`: a forked listener
    /// would multiplex concurrent gate connections onto one stdio byte
    /// stream and corrupt the per-connection request/ack framing. This is a
    /// fail-closed-adjacent correctness guard on the egress decision path.
    #[test]
    fn gate_listener_exec_argv_never_uses_fork() {
        let sock = std::path::Path::new("/tmp/gw.sock");
        let argv = gate_listener_exec_argv(Some(sock), "sandbox-gw-x");
        assert!(
            !argv.iter().any(|a| a.contains("fork")),
            "gate bridge listener must not use socat ,fork (per-connection only); got {argv:?}"
        );
    }

    /// Linux / host-docker shape: with no forwarded socket the argv carries
    /// no `-H` flag. On Linux the bridge is never started (the runtime
    /// `start_gate_bridge` is `#[cfg(target_os = "macos")]`), but the pure
    /// builder stays platform-neutral and testable; this pins that a
    /// hypothetical `None` invocation emits a byte-identical host-docker
    /// argv with no `-H`.
    #[test]
    fn gate_listener_exec_argv_no_socket_omits_host_flag() {
        let argv = gate_listener_exec_argv(None, "sandbox-gw-abc123");
        assert_eq!(
            argv,
            vec![
                "exec",
                "-i",
                "sandbox-gw-abc123",
                "socat",
                "-",
                "UNIX-LISTEN:/var/log/gateway/events/dns-gate.sock,unlink-early",
            ]
        );
        assert!(
            !argv.iter().any(|a| a == "-H"),
            "host-docker gate bridge argv must not carry -H: {argv:?}"
        );
    }
}
