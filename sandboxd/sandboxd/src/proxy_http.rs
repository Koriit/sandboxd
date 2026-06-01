//! `GET /sessions/{id}/proxy` — WebSocket byte mover between the
//! daemon-side socket and the in-session sshd.
//!
//! Implements the cross-user CLI access spec § Daemon API → `GET
//! /sessions/{id}/proxy`. Upgrades the request to a WebSocket (binary
//! frames only — no per-frame framing layer; SSH does its own
//! multiplexing inside the tunnel), then ferries bytes bidirectionally
//! between the WebSocket halves and the session's sshd transport.
//!
//! ## Per-backend transport
//!
//! * **Container** — spawn `docker exec -i <ctr> socat - TCP:127.0.0.1:22`
//!   as a `tokio::process::Command` child with async stdio. Same byte
//!   mover the cross-user sshd integration test (`tests/
//!   integration_lite_image_sshd_cross_user.rs`) used as a
//!   `ProxyCommand`, now lifted into the daemon.
//! * **Lima** — discover the host-side TCP port Lima forwards to the
//!   in-VM sshd's port 22 via `limactl list --json`'s `sshLocalPort`
//!   field, then open a `tokio::net::TcpStream` to
//!   `127.0.0.1:<sshLocalPort>`. The one-shot `limactl list` query
//!   uses `spawn_blocking` per the project's standard `std::process::
//!   Command` convention.
//!
//! ## Async-I/O carve-out
//!
//! The project convention (per `CLAUDE.md`) is to wrap
//! `std::process::Command` calls in `spawn_blocking`. The container
//! byte pump deliberately departs from that convention: a long-lived
//! `docker exec`/`socat` byte pipe held inside a `spawn_blocking` task
//! would occupy a blocking-task slot for the entire SSH session
//! (potentially hours for an IDE) and deadlock the executor under
//! load. The carve-out is restricted to **this file**'s container path
//! and the proxy handler itself; one-shot probes (e.g. `limactl list`)
//! continue to use `spawn_blocking`. A future drive-by sweep that
//! tries to "add `spawn_blocking` everywhere" must leave this site
//! alone — see Spec § Architecture → Async I/O note for the rationale.
//!
//! ## No SSH-protocol parsing
//!
//! The handler is a dumb byte mover. Binary WebSocket frames carry raw
//! SSH bytes; the proxy never inspects the payload. SSH authentication
//! and channel multiplexing happen end-to-end between the operator's
//! SSH client and the in-session sshd.

use std::process::Stdio;
use std::sync::Arc;

use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use futures_util::SinkExt;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use sandbox_core::LimaManager;
use sandbox_core::backend::BackendKind;
use sandbox_core::{LimaManagerRegistry, SandboxError, Session, SessionId, SessionStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command as TokioCommand;
use tracing::{debug, error, info, warn};

/// WebSocket close codes the daemon uses to signal structured failure
/// to the CLI shim. The CLI (`sandbox-cli::proxy`) matches on these so
/// it can render operator-actionable messages on top of the generic
/// SSH-disconnect path.
///
/// We use the IANA-reserved private range (4000-4999) for application-
/// specific codes so we do not collide with RFC 6455 standard codes
/// (1000-1015) or `tokio-tungstenite` reserved codes (1016-2999, 3000-
/// 3999).
pub mod close_codes {
    /// Backend dial / readiness failure — sshd is not listening, the
    /// VM/container is stopped, the route helper is down, etc.
    pub const BACKEND_UNAVAILABLE: u16 = 4001;
    /// Backend exited non-zero or unexpectedly mid-stream.
    pub const BACKEND_ERROR: u16 = 4002;
}

/// State the proxy handler depends on. Borrows the daemon's
/// `SessionStore` (for the per-caller ownership check) and
/// `LimaManagerRegistry` (for `sshLocalPort` discovery on the Lima path,
/// routed through `sandbox-lima-helper list-json --op-uid`).
///
/// The container path needs neither: it shells out to `docker exec
/// <name> socat ...`, deriving the container name from the session id
/// alone (the convention every other container-backend call site uses
/// — see `RuntimeHandle::from_session_id`).
pub struct ProxyState {
    pub store: Arc<SessionStore>,
    pub lima_registry: Arc<LimaManagerRegistry>,
}

/// Entry point for `GET /sessions/{id}/proxy`.
///
/// Performs the session-ownership check **before** the WebSocket
/// handshake so a foreign-owner caller sees `404 Not Found` over plain
/// HTTP, not a successful upgrade followed by an opaque WebSocket
/// close. After the check passes, hands the upgrade off to
/// [`run_proxy`] which runs the per-backend byte pump.
pub async fn handle_proxy(
    state: Arc<ProxyState>,
    operator_name: String,
    id: String,
    ws: WebSocketUpgrade,
) -> Result<axum::response::Response, ProxyHttpError> {
    let session = match state.store.get_session_by_name_or_id(&id, &operator_name) {
        Ok(Some(s)) => s,
        Ok(None) => return Err(ProxyHttpError::NotFound(id)),
        Err(e) => return Err(ProxyHttpError::Store(e)),
    };
    let backend = session.backend;
    let session_id = session.id;
    info!(
        session = %session_id,
        backend = ?backend,
        operator = %operator_name,
        "opening proxy WebSocket",
    );

    // sshd-readiness short-circuit (container backend only).
    //
    // When the session's probe recorded `Some(false)` — sshd did not
    // start inside the container — refuse the tunnel immediately with
    // `BACKEND_UNAVAILABLE` (4001) rather than connecting a channel
    // that will hang or return an opaque SSH error. A `None` value
    // (Lima session, pre-V010 row, or probe error at create time)
    // falls through to the legacy "attempt the tunnel" path so no
    // existing behaviour regresses.
    if session.sshd_ready == Some(false) {
        warn!(
            session = %session_id,
            "proxy: sshd_ready=false; refusing tunnel with BACKEND_UNAVAILABLE"
        );
        return Ok(ws.on_upgrade(|socket| async move {
            close_with_code(
                socket,
                close_codes::BACKEND_UNAVAILABLE,
                "sshd did not start in this session",
            )
            .await;
        }));
    }

    // The upgrade closure may not borrow state captures (it outlives
    // the handler future), so hand it owned clones.
    let lima_registry_for_upgrade = Arc::clone(&state.lima_registry);
    Ok(ws.on_upgrade(move |socket| async move {
        run_proxy(socket, session, lima_registry_for_upgrade).await;
    }))
}

/// HTTP-shaped errors the proxy handler emits **before** the WebSocket
/// handshake completes. Mapped to the standard daemon error response
/// shape by [`ProxyHttpError::into_response`].
#[derive(Debug)]
pub enum ProxyHttpError {
    NotFound(String),
    Store(SandboxError),
}

impl axum::response::IntoResponse for ProxyHttpError {
    fn into_response(self) -> axum::response::Response {
        let err = match self {
            ProxyHttpError::NotFound(id) => SandboxError::SessionNotFound(id),
            ProxyHttpError::Store(e) => e,
        };
        crate::error::error_response(err).into_response()
    }
}

/// Run the per-backend byte pump until either side closes. On error
/// (backend dial failure, mid-stream backend exit, etc.) close the
/// WebSocket with a structured code from [`close_codes`] so the CLI
/// shim (`sandbox-cli::proxy`) can render a useful diagnostic.
async fn run_proxy(socket: WebSocket, session: Session, lima_registry: Arc<LimaManagerRegistry>) {
    let session_id = session.id;
    match session.backend {
        BackendKind::Container => {
            if let Err(e) = pump_container(socket, &session_id).await {
                warn!(
                    session = %session_id,
                    error = %e,
                    "container proxy pump exited with error",
                );
            }
        }
        BackendKind::Lima => {
            // Operator uid from the session row (post-V009, always Some).
            let op_uid = match session.operator_uid {
                Some(uid) => uid,
                None => {
                    error!(
                        session = %session_id,
                        "Lima proxy: session has no operator_uid (pre-V009 row?); closing"
                    );
                    close_with_code(
                        socket,
                        close_codes::BACKEND_ERROR,
                        "session has no operator_uid",
                    )
                    .await;
                    return;
                }
            };
            let lima = match lima_registry.get_or_create(op_uid) {
                Ok(m) => m,
                Err(e) => {
                    error!(
                        session = %session_id,
                        error = %e,
                        "Lima proxy: failed to provision operator LIMA_HOME; closing"
                    );
                    close_with_code(
                        socket,
                        close_codes::BACKEND_ERROR,
                        "failed to provision operator LIMA_HOME",
                    )
                    .await;
                    return;
                }
            };
            if let Err(e) = pump_lima(socket, &session_id, lima).await {
                warn!(
                    session = %session_id,
                    error = %e,
                    "lima proxy pump exited with error",
                );
            }
        }
    }
}

/// Container path: spawn `docker exec -i <name> socat -
/// TCP:127.0.0.1:22` with async pipes, then ferry bytes between the
/// WebSocket halves and the child's stdio. Same byte mover the
/// cross-user sshd integration test used as a `ProxyCommand`.
async fn pump_container(socket: WebSocket, session_id: &SessionId) -> Result<(), SandboxError> {
    let container_name = format!("sandbox-{session_id}");

    // ASYNC-I/O CARVE-OUT (cross-user CLI access spec § Architecture
    // → Async I/O note): `tokio::process::Command` with async pipes is
    // **mandatory** here. A `std::process::Command` wrapped in
    // `spawn_blocking` would occupy a blocking-task slot for the
    // entire SSH session — long-running IDE connections (VS Code
    // Remote-SSH, JetBrains Gateway) hold this open for hours.
    // Project-wide `spawn_blocking` convention does NOT apply to
    // long-lived byte pumps. Do not "fix" this site by wrapping it.
    let mut command = TokioCommand::new("docker");
    command
        .args([
            "exec",
            "-i",
            &container_name,
            "socat",
            "-",
            "TCP:127.0.0.1:22",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    debug!(container = %container_name, "spawning docker exec socat for proxy");
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("failed to spawn docker exec for {container_name}: {e}");
            close_with_code(socket, close_codes::BACKEND_UNAVAILABLE, &msg).await;
            return Err(SandboxError::Gateway(msg));
        }
    };

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| SandboxError::Internal("docker exec child has no stdin".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SandboxError::Internal("docker exec child has no stdout".into()))?;
    let stderr = child.stderr.take();

    // Drive the byte pump. On an early/unexpected backend exit (backend
    // EOF while the WebSocket is still open), `bidirectional_ferry`
    // returns `FerryOutcome::BackendExitedEarly` with the reclaimed WS
    // sink so we can send a structured `BACKEND_ERROR` (4002) close
    // frame. On a normal client-initiated close it returns
    // `FerryOutcome::ClientClosed` and we leave the socket alone.
    let ferry_outcome = bidirectional_ferry(socket, stdin, stdout).await;

    // Capture exit status + any stderr produced before close.
    let exit_status = child.wait().await.ok();
    let stderr_bytes = if let Some(mut s) = stderr {
        let mut buf = Vec::with_capacity(256);
        let _ = AsyncReadExt::read_to_end(&mut s, &mut buf).await;
        buf
    } else {
        Vec::new()
    };

    match ferry_outcome {
        Ok(FerryOutcome::ClientClosed(stats)) => {
            debug!(
                container = %container_name,
                bytes_ws_to_backend = stats.ws_to_backend,
                bytes_backend_to_ws = stats.backend_to_ws,
                "proxy pump finished (client closed)",
            );
        }
        Ok(FerryOutcome::BackendExitedEarly { stats, mut ws_sink }) => {
            debug!(
                container = %container_name,
                bytes_ws_to_backend = stats.ws_to_backend,
                bytes_backend_to_ws = stats.backend_to_ws,
                "proxy pump: backend exited while WebSocket still open",
            );
            // Backend exited while WS was still open. Check exit status:
            // non-zero → BACKEND_ERROR (4002) with detail so the CLI
            // shim can render an actionable diagnostic; zero / unknown
            // → clean Close(None) (normal sshd session end raced the WS).
            let is_error = exit_status.as_ref().map(|s| !s.success()).unwrap_or(false);
            if is_error {
                let stderr_text = String::from_utf8_lossy(&stderr_bytes);
                let code = exit_status.as_ref().and_then(|s| s.code()).unwrap_or(-1);
                let msg = format!(
                    "docker exec for {container_name} exited with {code}; stderr: {}",
                    stderr_text.trim()
                );
                error!(
                    container = %container_name,
                    exit = code,
                    stderr = %stderr_text.trim(),
                    "docker exec socat exited non-zero while WebSocket was open"
                );
                // Reclaimed sink: send the structured 4002 close frame
                // that was unreachable before this restructure.
                close_sink_with_code(ws_sink, close_codes::BACKEND_ERROR, &msg).await;
                return Err(SandboxError::Gateway(msg));
            } else {
                // Normal clean backend exit (socat/sshd finished cleanly).
                // Send a graceful Close(None) so the operator's SSH client
                // observes a clean disconnect.
                let _ = ws_sink.send(Message::Close(None)).await;
            }
        }
        Err(e) => {
            warn!(
                container = %container_name,
                error = %e,
                "proxy pump errored",
            );
        }
    }

    if let Some(status) = exit_status {
        if !status.success() {
            let stderr_text = String::from_utf8_lossy(&stderr_bytes);
            error!(
                container = %container_name,
                exit = ?status.code(),
                stderr = %stderr_text,
                "docker exec socat exited non-zero (client had already closed)",
            );
            return Err(SandboxError::Gateway(format!(
                "docker exec for {container_name} exited with {:?}; stderr: {}",
                status.code(),
                stderr_text.trim()
            )));
        }
    }
    Ok(())
}

/// Lima path: look up the per-VM `sshLocalPort` via
/// `sandbox-lima-helper list-json --op-uid`, open a
/// `tokio::net::TcpStream` to `127.0.0.1:<port>`, then ferry bytes.
/// The port lookup is a one-shot `std::process::Command` invocation
/// behind `spawn_blocking` per the project's standard convention —
/// the async-I/O carve-out applies only to the long-lived byte pump
/// (which here is the `TcpStream`).
///
/// `lima` is the per-operator [`LimaManager`] obtained from the
/// registry using the session's `operator_uid`.
async fn pump_lima(
    socket: WebSocket,
    session_id: &SessionId,
    lima: Arc<LimaManager>,
) -> Result<(), SandboxError> {
    // One-shot `sandbox-lima-helper list-json`. The manager's
    // `ssh_local_port_for_session` wraps `std::process::Command`
    // synchronously; dispatch through `spawn_blocking` per the
    // project's standard convention. (The long-lived byte pump below
    // is a deliberate carve-out — see the container path's comment.)
    let session_id_for_blocking = *session_id;
    let lima_for_blocking = Arc::clone(&lima);
    let port = match tokio::task::spawn_blocking(move || {
        lima_for_blocking.ssh_local_port_for_session(&session_id_for_blocking)
    })
    .await
    {
        Ok(Ok(Some(p))) => p,
        Ok(Ok(None)) => {
            let msg = format!(
                "Lima session sandbox-{session_id} has no sshLocalPort assigned (VM stopped?)",
            );
            close_with_code(socket, close_codes::BACKEND_UNAVAILABLE, &msg).await;
            return Err(SandboxError::Lima(msg));
        }
        Ok(Err(e)) => {
            close_with_code(socket, close_codes::BACKEND_UNAVAILABLE, &e.to_string()).await;
            return Err(e);
        }
        Err(join) => {
            let msg = format!("spawn_blocking for limactl list failed: {join}");
            close_with_code(socket, close_codes::BACKEND_ERROR, &msg).await;
            return Err(SandboxError::Internal(msg));
        }
    };

    debug!(session = %session_id, port, "dialing Lima sshd via host port-forward");
    let tcp = match TcpStream::connect(("127.0.0.1", port)).await {
        Ok(t) => t,
        Err(e) => {
            let msg = format!("failed to connect to 127.0.0.1:{port}: {e}");
            close_with_code(socket, close_codes::BACKEND_UNAVAILABLE, &msg).await;
            return Err(SandboxError::Lima(msg));
        }
    };

    let (tcp_read, tcp_write) = tcp.into_split();
    match bidirectional_ferry(socket, tcp_write, tcp_read).await {
        Ok(FerryOutcome::ClientClosed(stats)) => {
            debug!(
                session = %session_id,
                bytes_ws_to_backend = stats.ws_to_backend,
                bytes_backend_to_ws = stats.backend_to_ws,
                "Lima proxy pump finished (client closed)",
            );
        }
        Ok(FerryOutcome::BackendExitedEarly { stats, mut ws_sink }) => {
            // Lima TCP stream ended while WS was still open. There is no
            // exit code for a TCP stream — a clean close means sshd exited
            // normally (operator's SSH session ended). Send a clean
            // Close(None) so the operator's SSH client observes a
            // graceful disconnect.
            debug!(
                session = %session_id,
                bytes_ws_to_backend = stats.ws_to_backend,
                bytes_backend_to_ws = stats.backend_to_ws,
                "Lima proxy pump: TCP stream ended (backend exited first)",
            );
            let _ = ws_sink.send(Message::Close(None)).await;
        }
        Err(e) => warn!(session = %session_id, error = %e, "Lima proxy pump errored"),
    }
    Ok(())
}

/// WebSocket close frames are control frames: RFC 6455 caps the total
/// payload at 125 bytes, 2 of which are the status code — leaving 123
/// bytes for the reason. Backend error strings (e.g. a docker/limactl
/// failure) can exceed that; an oversized control frame is rejected
/// outright by a compliant client (`ControlFrameTooBig`), which also
/// discards the close code. Truncate on a UTF-8 char boundary so the
/// frame stays spec-compliant and the code/reason survive.
const MAX_CLOSE_REASON_BYTES: usize = 123;

fn truncate_close_reason(reason: &str) -> &str {
    if reason.len() <= MAX_CLOSE_REASON_BYTES {
        return reason;
    }
    let mut end = MAX_CLOSE_REASON_BYTES;
    while end > 0 && !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason[..end]
}

/// Close the WebSocket with a structured close code + human-readable
/// reason. Best-effort: a closed socket is the failure-mode floor.
async fn close_with_code(mut socket: WebSocket, code: u16, reason: &str) {
    let frame = CloseFrame {
        code,
        reason: Utf8Bytes::from(truncate_close_reason(reason)),
    };
    let _ = socket.send(Message::Close(Some(frame))).await;
}

/// Send a structured close frame on a reclaimed `SplitSink`. Used by
/// the `BackendExitedEarly` branch of `bidirectional_ferry` callers to
/// emit `BACKEND_ERROR` (4002) after the ferry has already consumed
/// the `WebSocket` into its split halves. Best-effort.
async fn close_sink_with_code(mut ws_sink: SplitSink<WebSocket, Message>, code: u16, reason: &str) {
    let frame = CloseFrame {
        code,
        reason: Utf8Bytes::from(truncate_close_reason(reason)),
    };
    let _ = ws_sink.send(Message::Close(Some(frame))).await;
}

// ---------------------------------------------------------------------------
// Bidirectional byte ferry
// ---------------------------------------------------------------------------

/// Byte counters returned by [`bidirectional_ferry`] for structured
/// logging. Mirrors the shape `tokio::io::copy_bidirectional` produces.
#[derive(Debug, Clone, Copy)]
struct FerryStats {
    ws_to_backend: u64,
    backend_to_ws: u64,
}

/// How the ferry ended.
///
/// Distinguishing the two terminal cases lets callers send a structured
/// `BACKEND_ERROR` (4002) close frame only when the backend exited
/// unexpectedly while the WebSocket was still alive — not on a normal
/// client-initiated close, which would produce a spurious 4002.
enum FerryOutcome {
    /// The WebSocket-to-backend direction finished first (WS close frame
    /// received, or the WS stream ended). Normal client-initiated close.
    /// The WS sink was consumed inside the `ws_to_backend` task and is
    /// not recoverable; callers must not attempt to send any more frames.
    ClientClosed(FerryStats),
    /// The backend-to-WS direction finished first (backend EOF or stream
    /// end) while the WebSocket was still open. The WS sink is returned
    /// so callers can send a structured close frame (e.g. `BACKEND_ERROR`
    /// 4002) before the session is torn down.
    BackendExitedEarly {
        stats: FerryStats,
        ws_sink: SplitSink<WebSocket, Message>,
    },
}

/// Ferry bytes between a WebSocket and the backend's
/// `AsyncWrite`/`AsyncRead` halves.
///
/// We split the WebSocket into its `Sink`/`Stream` halves so we can run
/// the two directions as independent tokio tasks. The naïve
/// `tokio::io::copy_bidirectional` shape would require an
/// `AsyncRead + AsyncWrite` adapter over the WebSocket, which is not
/// safely expressible without re-borrowing the same `&mut WebSocket`
/// from both halves at once (UB). The split + two-task shape is what
/// every production WebSocket-to-byte-stream proxy in the Rust
/// ecosystem ends up using (see e.g. `tokio-tungstenite`'s examples,
/// `hyper-tungstenite`'s reverse-proxy template).
///
/// **Half-close semantics:** when either direction terminates (EOF,
/// close frame, or error), we abort the other task to ensure the
/// child process tears down promptly. The container's `socat` child
/// noticing its stdin closed will close the TCP socket to sshd, which
/// will then close its stdout — but only after sshd's own draining
/// completes, which can be slow. We bound that delay by aborting.
///
/// **Outcome discrimination:** when the WS-to-backend direction
/// finishes first (client closed the WS), the function returns
/// `FerryOutcome::ClientClosed` — the WS sink is gone and the caller
/// must not send further frames. When the backend-to-WS direction
/// finishes first (backend exited or stream ended while WS is open),
/// the function returns `FerryOutcome::BackendExitedEarly` carrying the
/// reclaimed WS sink so the caller can emit a structured `BACKEND_ERROR`
/// (4002) close frame.
async fn bidirectional_ferry<W, R>(
    ws: WebSocket,
    backend_writer: W,
    backend_reader: R,
) -> Result<FerryOutcome, std::io::Error>
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let (ws_sink, ws_stream) = ws.split();

    // Direction 1: WebSocket -> backend stdin.
    // Returns the byte count; the WS stream and backend writer are
    // consumed inside the task.
    let mut dir1 = tokio::spawn(ws_to_backend(ws_stream, backend_writer));
    // Direction 2: backend stdout -> WebSocket.
    // Returns (byte_count, ws_sink) so we can reclaim the sink when the
    // backend exits first.
    let mut dir2 = tokio::spawn(backend_to_ws(backend_reader, ws_sink));

    // Wait for either side to finish, then cancel the other. This is
    // the standard "select_first + abort" pattern for byte ferries —
    // half-close on either side propagates to the other within one
    // task-poll cycle. We `&mut` the join handles so the unfinished
    // task is still awaitable after the select arm completes (for
    // resource teardown via `.abort()` + final `.await`).
    tokio::select! {
        // WS-to-backend direction finished first → ClientClosed.
        r = &mut dir1 => {
            let ws_to_b = match r {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    debug!(error = %e, "ws->backend ferry exited with error");
                    0
                }
                Err(join) => {
                    return Err(std::io::Error::other(format!(
                        "ws->backend ferry task panic: {join}"
                    )));
                }
            };
            dir2.abort();
            let b_to_ws = match dir2.await {
                Ok(Ok((n, _sink))) => n,
                Ok(Err(e)) => {
                    debug!(error = %e, "backend->ws ferry exited with error (after abort)");
                    0
                }
                Err(_) => 0, // abort -> JoinError::Cancelled
            };
            Ok(FerryOutcome::ClientClosed(FerryStats {
                ws_to_backend: ws_to_b,
                backend_to_ws: b_to_ws,
            }))
        }
        // Backend-to-WS direction finished first → BackendExitedEarly.
        // Reclaim the WS sink from the task result so the caller can
        // send a structured close frame.
        r = &mut dir2 => {
            let (b_to_ws, reclaimed_sink) = match r {
                Ok(Ok((n, sink))) => (n, Some(sink)),
                Ok(Err(e)) => {
                    debug!(error = %e, "backend->ws ferry exited with error");
                    (0, None)
                }
                Err(join) => {
                    return Err(std::io::Error::other(format!(
                        "backend->ws ferry task panic: {join}"
                    )));
                }
            };
            dir1.abort();
            let ws_to_b = match dir1.await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    debug!(error = %e, "ws->backend ferry exited with error (after abort)");
                    0
                }
                Err(_) => 0,
            };
            let stats = FerryStats {
                ws_to_backend: ws_to_b,
                backend_to_ws: b_to_ws,
            };
            match reclaimed_sink {
                Some(ws_sink) => Ok(FerryOutcome::BackendExitedEarly { stats, ws_sink }),
                // Sink was lost due to an error in the task; treat as
                // ClientClosed so callers don't try to use a None sink.
                None => Ok(FerryOutcome::ClientClosed(stats)),
            }
        }
    }
}

/// Read binary WebSocket frames; write the payload bytes to the
/// backend's stdin. Text frames are dropped silently (the proxy is
/// binary-only — a misbehaving client cannot wedge the pump by sending
/// text). Close frames terminate the direction cleanly.
async fn ws_to_backend<W>(
    mut ws_stream: SplitStream<WebSocket>,
    mut backend_writer: W,
) -> std::io::Result<u64>
where
    W: AsyncWrite + Unpin,
{
    let mut total: u64 = 0;
    while let Some(msg) = ws_stream.next().await {
        match msg {
            Ok(Message::Binary(bytes)) => {
                backend_writer.write_all(&bytes).await?;
                total = total.saturating_add(bytes.len() as u64);
            }
            Ok(Message::Text(_)) => {
                debug!("ignoring inbound WebSocket text frame on binary-only proxy");
            }
            Ok(Message::Close(_)) => {
                debug!("inbound WebSocket close frame received; ending ws->backend ferry");
                break;
            }
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {
                // Auto-handled by axum's underlying tungstenite layer;
                // nothing to do here.
            }
            Err(e) => {
                return Err(std::io::Error::other(format!("websocket recv error: {e}")));
            }
        }
    }
    // EOF or close: flush and shut down the writer so the backend
    // child observes EOF on its stdin.
    backend_writer.shutdown().await.ok();
    Ok(total)
}

/// Read bytes from the backend's stdout; pack each read into one
/// `Message::Binary` frame and send it. Returns `(bytes_transferred,
/// ws_sink)` on backend EOF so the caller can reclaim the sink and
/// send a structured close frame (e.g. `BACKEND_ERROR` 4002) when
/// the backend exited unexpectedly while the WebSocket was still open.
///
/// Unlike `ws_to_backend`, this function does **not** emit a
/// `Message::Close` internally on EOF — the caller is now responsible
/// for deciding which close code to send based on context (normal
/// backend completion vs. unexpected early exit). This is the key
/// change that makes the 4002 close frame reachable.
async fn backend_to_ws<R>(
    mut backend_reader: R,
    mut ws_sink: SplitSink<WebSocket, Message>,
) -> std::io::Result<(u64, SplitSink<WebSocket, Message>)>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = backend_reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let chunk = buf[..n].to_vec();
        ws_sink
            .send(Message::Binary(chunk.into()))
            .await
            .map_err(|e| std::io::Error::other(format!("websocket send error: {e}")))?;
        total = total.saturating_add(n as u64);
    }
    // Return the sink to the caller rather than closing here. The caller
    // now controls whether to send Close(None) (normal backend EOF) or
    // Close(Some(BACKEND_ERROR)) (unexpected early exit).
    Ok((total, ws_sink))
}

// ---------------------------------------------------------------------------
// Hermetic tests
// ---------------------------------------------------------------------------
//
// These tests cover the parts of the handler that do not require a
// real backend: the session-ownership / not-found branch, the
// `ProxyHttpError -> HTTP response` mapping, the structured close-code
// constants, and the byte ferry itself driven over an in-memory
// WebSocket pair plus a `tokio::io::duplex` backend stand-in.

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[test]
    fn truncate_close_reason_caps_at_123_bytes_on_char_boundary() {
        // Short reasons pass through untouched.
        let short = "backend unavailable";
        assert_eq!(truncate_close_reason(short), short);

        // An over-long ASCII reason is capped to <= 123 bytes (the RFC 6455
        // control-frame budget after the 2-byte close code).
        let long = "x".repeat(500);
        let t = truncate_close_reason(&long);
        assert_eq!(t.len(), MAX_CLOSE_REASON_BYTES);

        // Truncation never splits a multi-byte char: a string of 'é' (2 bytes
        // each) truncated at the 123-byte budget lands on a char boundary, so
        // the result stays valid UTF-8 and is <= 123 bytes (122 here).
        let multibyte = "é".repeat(200);
        let t = truncate_close_reason(&multibyte);
        assert!(t.len() <= MAX_CLOSE_REASON_BYTES);
        assert!(multibyte.starts_with(t));
        // Round-trips as valid UTF-8 (would panic on a mid-char split).
        let _ = Utf8Bytes::from(t);
    }

    /// `ProxyHttpError::NotFound` maps to `404` via the shared
    /// `error_response` helper. Pins the contract the CLI shim
    /// consumes for lazy-cleanup of stale local entries.
    #[tokio::test]
    async fn proxy_http_error_not_found_maps_to_404() {
        let resp = ProxyHttpError::NotFound("nonesuch".into()).into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// `ProxyHttpError::Store` propagates the underlying
    /// `SandboxError`'s status code (here, `Internal` → 500).
    /// Pins the "do not swallow store errors" contract from the
    /// session-ownership-check path.
    #[tokio::test]
    async fn proxy_http_error_store_propagates_status() {
        let resp = ProxyHttpError::Store(SandboxError::Internal("db lost".into())).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// `ProxyHttpError::Store` carrying a `SessionNotFound` should
    /// also surface as 404 — the variant-driven mapping must not
    /// collapse store errors to 500 indiscriminately.
    #[tokio::test]
    async fn proxy_http_error_store_session_not_found_maps_to_404() {
        let resp = ProxyHttpError::Store(SandboxError::SessionNotFound("x".into())).into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// The IANA-private close codes the daemon uses to signal failure
    /// to the CLI live in the 4000-4999 range. The CLI matches
    /// against these constants directly; drift here would silently
    /// break the CLI's "render an actionable error" path.
    #[test]
    fn close_codes_are_in_iana_private_range() {
        assert!(
            (4000..=4999).contains(&close_codes::BACKEND_UNAVAILABLE),
            "BACKEND_UNAVAILABLE close code must live in the IANA private 4000-4999 range",
        );
        assert!(
            (4000..=4999).contains(&close_codes::BACKEND_ERROR),
            "BACKEND_ERROR close code must live in the IANA private 4000-4999 range",
        );
        assert_ne!(
            close_codes::BACKEND_UNAVAILABLE,
            close_codes::BACKEND_ERROR,
            "close codes must be distinct so the CLI can tell them apart",
        );
    }

    /// Session-ownership check happens against
    /// `get_session_by_name_or_id`, which returns `Ok(None)` for both
    /// "no such session" and "session belongs to another operator".
    /// We hit the store directly with a fresh `SessionStore` (no rows)
    /// to pin the not-found behaviour the handler relies on for the
    /// 404-before-upgrade contract.
    #[tokio::test]
    async fn unknown_session_looks_up_as_none_in_store() {
        use sandbox_core::SessionStore;
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("tempdir");
        let (store, _orphans) =
            SessionStore::new(tmp.path().to_path_buf()).expect("open SessionStore");

        let session = store
            .get_session_by_name_or_id("does-not-exist", "anyone")
            .expect("store call succeeds");
        assert!(
            session.is_none(),
            "unknown id must look up as None; got {session:?}"
        );
    }

    /// Foreign-owner session reads as `Ok(None)` for a non-owner
    /// caller via the same `get_session_by_name_or_id` filter, so a
    /// caller targeting another operator's session sees the same 404
    /// as a truly nonexistent session — no information leak about
    /// neighbouring operators.
    ///
    /// We synthesise a session row via the public store API and look
    /// it up under a foreign operator name.
    #[tokio::test]
    async fn foreign_owner_session_is_invisible_via_store_filter() {
        use sandbox_core::SessionConfig;
        use sandbox_core::SessionStore;
        use tempfile::TempDir;

        let tmp = TempDir::new().expect("tempdir");
        let (store, _orphans) =
            SessionStore::new(tmp.path().to_path_buf()).expect("open SessionStore");

        let cfg = SessionConfig::default();
        let session = store
            .create_session(cfg, None, "alice", 0, "")
            .expect("create_session under owner alice");
        let id = session.id;

        // Alice (owner) sees it.
        let alice = store
            .get_session_by_name_or_id(id.as_str(), "alice")
            .expect("store call succeeds");
        assert!(alice.is_some(), "owner must see their own session");

        // Bob does not.
        let bob = store
            .get_session_by_name_or_id(id.as_str(), "bob")
            .expect("store call succeeds");
        assert!(
            bob.is_none(),
            "foreign-owner session must be invisible to non-owner; got {bob:?}"
        );
    }

    /// `FerryOutcome::BackendExitedEarly` carries the WS sink so the
    /// caller can send a structured 4002 close frame. Verify the
    /// discriminant values are correct and that `BackendExitedEarly`
    /// and `ClientClosed` are distinct so callers can pattern-match
    /// them without ambiguity.
    ///
    /// This is a compile-time/structural test — we cannot construct
    /// a `WebSocket` (no public ctor) so we verify the `FerryOutcome`
    /// enum shape and `FerryStats` fields statically.
    #[test]
    fn ferry_outcome_variants_are_distinct_and_carry_stats() {
        // FerryStats must carry both counters.
        let s = FerryStats {
            ws_to_backend: 42,
            backend_to_ws: 17,
        };
        assert_eq!(s.ws_to_backend, 42);
        assert_eq!(s.backend_to_ws, 17);

        // The ClientClosed variant wraps FerryStats directly.
        let client_closed = FerryOutcome::ClientClosed(FerryStats {
            ws_to_backend: 100,
            backend_to_ws: 200,
        });
        match client_closed {
            FerryOutcome::ClientClosed(stats) => {
                assert_eq!(stats.ws_to_backend, 100);
                assert_eq!(stats.backend_to_ws, 200);
            }
            FerryOutcome::BackendExitedEarly { .. } => {
                panic!("expected ClientClosed");
            }
        }
    }

    /// `sshd_ready = Some(false)` must round-trip through serde with
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]` so
    /// a record written by a newer daemon with the field set is readable
    /// by an older daemon (unknown field ignored) and a pre-V010 record
    /// with no field deserialises to `None`.
    #[test]
    fn sshd_ready_serde_forward_compat() {
        use sandbox_core::Session;

        // A pre-V010 session JSON (no sshd_ready key) must deserialise
        // with sshd_ready = None.
        let json_without = r#"{
            "id": "abcdef012345",
            "state": "running",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "config": {"cpus": 2, "memory_mb": 4096, "disk_gb": 20},
            "owner_username": "alice"
        }"#;
        let s: Session = serde_json::from_str(json_without).unwrap();
        assert!(
            s.sshd_ready.is_none(),
            "pre-V010 record must deserialise with sshd_ready = None; got {:?}",
            s.sshd_ready
        );

        // A record with sshd_ready = false must round-trip.
        let json_false = r#"{
            "id": "abcdef012345",
            "state": "running",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "config": {"cpus": 2, "memory_mb": 4096, "disk_gb": 20},
            "owner_username": "alice",
            "sshd_ready": false
        }"#;
        let s: Session = serde_json::from_str(json_false).unwrap();
        assert_eq!(
            s.sshd_ready,
            Some(false),
            "sshd_ready=false must round-trip; got {:?}",
            s.sshd_ready
        );

        // sshd_ready=None must be omitted from the wire (skip_serializing_if).
        let mut session = sandbox_core::Session::new(Some("test".into()));
        session.sshd_ready = None;
        let serialised = serde_json::to_string(&session).unwrap();
        assert!(
            !serialised.contains("sshd_ready"),
            "sshd_ready=None must be omitted from wire; got {serialised}"
        );

        // sshd_ready=Some(true) must appear on the wire.
        session.sshd_ready = Some(true);
        let serialised = serde_json::to_string(&session).unwrap();
        assert!(
            serialised.contains("\"sshd_ready\":true"),
            "sshd_ready=Some(true) must be emitted on wire; got {serialised}"
        );
    }
}
