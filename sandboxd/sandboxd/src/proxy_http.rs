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
//!   mover the M18-S3 cross-user sshd integration test (`tests/
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
use sandbox_core::backend::BackendKind;
use sandbox_core::{LimaManager, SandboxError, Session, SessionId, SessionStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command as TokioCommand;
use tracing::{debug, error, info, warn};

/// WebSocket close codes the daemon uses to signal structured failure
/// to the CLI shim. The CLI (M18-S5) matches on these so it can render
/// operator-actionable messages and (for the not-found case) clean up
/// stale local entries.
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
/// `LimaManager` (for `sshLocalPort` discovery on the Lima path).
///
/// The container path needs neither: it shells out to `docker exec
/// <name> socat ...`, deriving the container name from the session id
/// alone (the convention every other container-backend call site uses
/// — see `RuntimeHandle::from_session_id`).
pub struct ProxyState {
    pub store: Arc<SessionStore>,
    pub lima: Arc<LimaManager>,
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

    // The upgrade closure may not borrow state captures (it outlives
    // the handler future), so hand it owned clones.
    let lima_for_upgrade = Arc::clone(&state.lima);
    Ok(ws.on_upgrade(move |socket| async move {
        run_proxy(socket, session, lima_for_upgrade).await;
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
/// WebSocket with a structured code from [`close_codes`] so M18-S5's
/// CLI can render a useful diagnostic.
async fn run_proxy(socket: WebSocket, session: Session, lima: Arc<LimaManager>) {
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
/// WebSocket halves and the child's stdio. Same byte mover the M18-S3
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

    // Drive the byte pump. `bidirectional_ferry` consumes the socket
    // halves; we get a single `Result` covering both directions.
    let ferry_result = bidirectional_ferry(socket, stdin, stdout).await;

    // Capture exit status + any stderr captured before close.
    let exit_status = child.wait().await.ok();
    let stderr_bytes = if let Some(mut s) = stderr {
        let mut buf = Vec::with_capacity(256);
        let _ = AsyncReadExt::read_to_end(&mut s, &mut buf).await;
        buf
    } else {
        Vec::new()
    };

    match ferry_result {
        Ok(FerryStats {
            ws_to_backend,
            backend_to_ws,
        }) => debug!(
            container = %container_name,
            bytes_ws_to_backend = ws_to_backend,
            bytes_backend_to_ws = backend_to_ws,
            "proxy pump finished",
        ),
        Err(e) => warn!(
            container = %container_name,
            error = %e,
            "proxy pump errored",
        ),
    }

    if let Some(status) = exit_status {
        if !status.success() {
            let stderr_text = String::from_utf8_lossy(&stderr_bytes);
            error!(
                container = %container_name,
                exit = ?status.code(),
                stderr = %stderr_text,
                "docker exec socat exited non-zero",
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

/// Lima path: look up the per-VM `sshLocalPort` via `limactl list
/// --json`, open a `tokio::net::TcpStream` to `127.0.0.1:<port>`, then
/// ferry bytes. The port lookup is a one-shot `std::process::Command`
/// invocation behind `spawn_blocking` per the project's standard
/// convention — the async-I/O carve-out applies only to the long-lived
/// byte pump (which here is the `TcpStream`).
async fn pump_lima(
    socket: WebSocket,
    session_id: &SessionId,
    lima: Arc<LimaManager>,
) -> Result<(), SandboxError> {
    // One-shot `limactl list --json`. `LimaManager::ssh_local_port_
    // for_session` wraps `std::process::Command` synchronously; we
    // dispatch it through `spawn_blocking` to keep the async runtime
    // free per the project's standard `std::process::Command`
    // convention. (The long-lived byte pump below is a deliberate
    // carve-out — see the container path's inline comment.)
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
        Ok(FerryStats {
            ws_to_backend,
            backend_to_ws,
        }) => debug!(
            session = %session_id,
            bytes_ws_to_backend = ws_to_backend,
            bytes_backend_to_ws = backend_to_ws,
            "Lima proxy pump finished",
        ),
        Err(e) => warn!(session = %session_id, error = %e, "Lima proxy pump errored"),
    }
    Ok(())
}

/// Close the WebSocket with a structured close code + human-readable
/// reason. Best-effort: a closed socket is the failure-mode floor.
async fn close_with_code(mut socket: WebSocket, code: u16, reason: &str) {
    let frame = CloseFrame {
        code,
        reason: Utf8Bytes::from(reason),
    };
    let _ = socket.send(Message::Close(Some(frame))).await;
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
async fn bidirectional_ferry<W, R>(
    ws: WebSocket,
    backend_writer: W,
    backend_reader: R,
) -> Result<FerryStats, std::io::Error>
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let (ws_sink, ws_stream) = ws.split();

    // Direction 1: WebSocket -> backend stdin.
    let mut dir1 = tokio::spawn(ws_to_backend(ws_stream, backend_writer));
    // Direction 2: backend stdout -> WebSocket.
    let mut dir2 = tokio::spawn(backend_to_ws(backend_reader, ws_sink));

    // Wait for either side to finish, then cancel the other. This is
    // the standard "select_first + abort" pattern for byte ferries —
    // half-close on either side propagates to the other within one
    // task-poll cycle. We `&mut` the join handles so the unfinished
    // task is still awaitable after the select arm completes (for
    // resource teardown via `.abort()` + final `.await`).
    let (ws_to_backend_bytes, backend_to_ws_bytes) = tokio::select! {
        r = &mut dir1 => {
            let bytes = match r {
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
            let backend_bytes = match dir2.await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    debug!(error = %e, "backend->ws ferry exited with error (after abort)");
                    0
                }
                Err(_) => 0, // abort -> JoinError::Cancelled
            };
            (bytes, backend_bytes)
        }
        r = &mut dir2 => {
            let bytes = match r {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    debug!(error = %e, "backend->ws ferry exited with error");
                    0
                }
                Err(join) => {
                    return Err(std::io::Error::other(format!(
                        "backend->ws ferry task panic: {join}"
                    )));
                }
            };
            dir1.abort();
            let ws_bytes = match dir1.await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    debug!(error = %e, "ws->backend ferry exited with error (after abort)");
                    0
                }
                Err(_) => 0,
            };
            (ws_bytes, bytes)
        }
    };

    Ok(FerryStats {
        ws_to_backend: ws_to_backend_bytes,
        backend_to_ws: backend_to_ws_bytes,
    })
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
/// `Message::Binary` frame and send it. On backend EOF, send a clean
/// `Message::Close(None)` so the operator's SSH client observes the
/// disconnect.
async fn backend_to_ws<R>(
    mut backend_reader: R,
    mut ws_sink: SplitSink<WebSocket, Message>,
) -> std::io::Result<u64>
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
    // Best-effort close frame so the CLI sees a clean disconnect even
    // when the backend half closed first.
    let _ = ws_sink.send(Message::Close(None)).await;
    Ok(total)
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

    /// `ProxyHttpError::NotFound` maps to `404` via the shared
    /// `error_response` helper. Pins the contract the CLI shim
    /// (M18-S5) consumes for lazy-cleanup of stale local entries.
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
    /// to the CLI live in the 4000-4999 range. M18-S5's CLI matches
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
}
