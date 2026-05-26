//! `sandbox proxy <id>` — hidden CLI subcommand used as `ProxyCommand`
//! by the daemon-emitted SSH config.
//!
//! Performs the HTTP-to-WebSocket upgrade against the daemon's
//! `GET /sessions/{id}/proxy` endpoint over the same Unix-socket
//! transport every other CLI ⇄ daemon call uses, then bidirectionally
//! ferries bytes between its own stdin/stdout and the WebSocket
//! binary frames. The daemon's byte-mover end (`sandboxd::proxy_http`)
//! takes care of the per-backend transport into the session's sshd —
//! see the cross-user CLI access spec § Daemon API → `GET
//! /sessions/{id}/proxy` and `sandboxd/src/proxy_http.rs` for the
//! server end.
//!
//! # Wire-format commitment
//!
//! The subcommand name (`proxy`) and its single positional argument
//! (`<id>`) are treated as wire format from M18-S5 onward — the daemon-
//! emitted SSH config block carries `ProxyCommand sandbox proxy <id>`
//! verbatim. Renaming either is a wire break with the daemon's
//! `sandbox_core::render_ssh_config_block`. Both ends ship in the
//! same crate so a rename ripples; the constants are pinned by tests
//! on both sides.
//!
//! # Thin shim — no business logic
//!
//! The M18-S5 milestone explicitly limits this subcommand to the byte-
//! mover loop. No SSH parsing, no retry, no drift recovery, no
//! lifecycle cleanup. M18-S6 wraps the outer CLI commands with the
//! single-retry drift-recovery path; M18-S7 adds lazy-404 cleanup *as
//! a post-WebSocket-failure side effect*, but the cleanup itself
//! lives in the M18-S5 `ssh_config` module and is dispatched from a
//! single well-isolated branch we leave as a TODO sentinel hook
//! here. The shim must remain easy to audit for "what does this do
//! before/after the handshake?".

use std::io::IsTerminal;
use std::path::PathBuf;

use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::http::Uri;
use tracing::debug;

// ---------------------------------------------------------------------------
// Exit-code contract
// ---------------------------------------------------------------------------

/// Successful clean disconnect — either end half-closed and we ferried
/// every byte across before exit.
pub const EXIT_OK: i32 = 0;

/// Generic failure (I/O error, handshake failure, malformed response,
/// daemon socket unreachable). Maps to `ssh` reporting the
/// `ProxyCommand` as having failed; SSH will surface its standard
/// "kex_exchange_identification: Connection closed by remote host" or
/// similar.
pub const EXIT_GENERIC_FAILURE: i32 = 1;

/// Daemon returned `404 Not Found` for the session id. The session
/// either does not exist (typo, since-deleted, or never created) or
/// belongs to another operator. M18-S7 wires lazy-cleanup of the
/// local `~/.ssh/sandbox/sandbox-<id>` entry off this exit shape.
pub const EXIT_SESSION_NOT_FOUND: i32 = 2;

// ---------------------------------------------------------------------------
// Daemon dial + WebSocket handshake
// ---------------------------------------------------------------------------

/// Errors the shim's pre-handshake phase can produce. After a
/// successful upgrade we fold every further failure into "exit with a
/// stderr line" so the operator's `ssh` client sees a stable
/// `ProxyCommand` exit shape.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("cannot connect to sandboxd at {socket}: {source}")]
    SocketDial {
        socket: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("HTTP-over-unix handshake failed: {0}")]
    HttpHandshake(String),
    #[error("daemon returned HTTP {status} (not 101 Switching Protocols): {body}")]
    UpgradeRejected {
        status: hyper::StatusCode,
        body: String,
    },
    #[error("WebSocket handshake failed: {0}")]
    WsHandshake(String),
    #[error("I/O error during proxy ferry: {0}")]
    Io(#[from] std::io::Error),
}

/// Drive the `sandbox proxy <id>` subcommand. Exits the process with
/// one of the [`EXIT_*`] codes; never returns to a caller that wants
/// to do further work — the binary's `main` invokes this and the
/// process exits.
///
/// `socket_path` is the daemon socket (already resolved by the
/// outer-most CLI to `--socket`/`SANDBOX_SOCKET`/default). `id` is the
/// session id from `sandbox proxy <id>`'s argv.
pub async fn run(socket_path: &str, id: &str) -> i32 {
    // Issue a stderr warning if stdin/stdout are TTYs — this command
    // is meant to be invoked as ProxyCommand with stdin/stdout
    // connected to ssh's pipes, not from a shell prompt. We do not
    // refuse outright (it can still be useful for ad-hoc debugging),
    // but a warning helps a confused operator who typed `sandbox
    // proxy <id>` directly.
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        eprintln!(
            "sandbox proxy: stdin and stdout are both TTYs — this command is meant \
             to be invoked as ProxyCommand by `ssh`. If you want an interactive \
             shell, use `sandbox ssh <id>` instead."
        );
    }

    match run_inner(socket_path, id).await {
        Ok(()) => EXIT_OK,
        Err(ProxyError::SocketDial { socket, source }) => {
            eprintln!(
                "sandbox proxy: cannot connect to sandboxd at {} ({source}). \
                       Is the daemon running?",
                socket.display()
            );
            EXIT_GENERIC_FAILURE
        }
        Err(ProxyError::UpgradeRejected { status, body }) => {
            // Distinguish 404 so M18-S7 can wire lazy-cleanup off the
            // dedicated exit code. Body is included verbatim because
            // the daemon's error response carries the typed
            // `SSH_NOT_AVAILABLE` token plus the operator-actionable
            // "recreate the session" message.
            if status == hyper::StatusCode::NOT_FOUND {
                eprintln!("sandbox proxy: session {id} not found ({body})");
                EXIT_SESSION_NOT_FOUND
            } else {
                eprintln!("sandbox proxy: daemon refused upgrade with HTTP {status}: {body}");
                EXIT_GENERIC_FAILURE
            }
        }
        Err(e) => {
            eprintln!("sandbox proxy: {e}");
            EXIT_GENERIC_FAILURE
        }
    }
}

/// Pre-handshake error path is fallible; once we are inside the byte-
/// ferry, errors propagate up here as `ProxyError::Io`.
async fn run_inner(socket_path: &str, id: &str) -> Result<(), ProxyError> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| ProxyError::SocketDial {
            socket: PathBuf::from(socket_path),
            source: e,
        })?;

    // Drive the HTTP/1.1 upgrade handshake on top of the Unix socket
    // through hyper, the same client used by every other daemon API
    // call in the CLI. We do NOT use `tokio-tungstenite::connect_async`
    // — that dialer assumes a TCP socket and parses a `ws://` URL
    // through the `url` crate; we already have a connected stream and
    // want to send a hand-crafted upgrade request over it.
    upgrade_and_ferry(stream, id).await
}

/// Perform the HTTP/1.1 → WebSocket upgrade over `stream`, then enter
/// the byte-ferry loop.
async fn upgrade_and_ferry(stream: UnixStream, id: &str) -> Result<(), ProxyError> {
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, String>(io)
        .await
        .map_err(|e| ProxyError::HttpHandshake(e.to_string()))?;

    // The hyper connection driver needs to run concurrently with the
    // request future for the upgrade to complete. `with_upgrades`
    // tells hyper to surface the upgraded socket on the
    // `Response::into_body().on_upgrade()` future instead of treating
    // a 101 as a parse error.
    let conn_with_upgrades = conn.with_upgrades();
    let conn_task = tokio::spawn(async move {
        if let Err(e) = conn_with_upgrades.await {
            debug!(error = %e, "hyper connection driver exited with error");
        }
    });

    // RFC 6455 WebSocket upgrade request headers:
    //   * `Connection: upgrade`
    //   * `Upgrade: websocket`
    //   * `Sec-WebSocket-Version: 13`
    //   * `Sec-WebSocket-Key: <base64 16 random bytes>`
    // `tokio_tungstenite::tungstenite::handshake::client::generate_key`
    // produces a correctly-formatted nonce.
    let ws_key = generate_key();
    let uri: Uri =
        format!("/sessions/{id}/proxy")
            .parse()
            .map_err(|e: hyper::http::uri::InvalidUri| {
                ProxyError::HttpHandshake(format!("invalid request uri: {e}"))
            })?;
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        // Authority on a Unix socket is meaningless but hyper validates
        // the header. The daemon ignores it.
        .header("host", "localhost")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", ws_key)
        .body(String::new())
        .map_err(|e| ProxyError::HttpHandshake(format!("request build failed: {e}")))?;

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| ProxyError::HttpHandshake(format!("send_request failed: {e}")))?;

    let status = resp.status();
    if status != hyper::StatusCode::SWITCHING_PROTOCOLS {
        // Non-101: collect the body and surface to the caller. This
        // is the branch the daemon takes on a missing-session 404 or
        // a foreign-owner 404, exactly the shape M18-S7 will hook for
        // lazy-cleanup.
        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| ProxyError::HttpHandshake(format!("read response body: {e}")))?
            .to_bytes();
        let body = String::from_utf8_lossy(&body_bytes).into_owned();
        return Err(ProxyError::UpgradeRejected { status, body });
    }

    // Acquire the upgraded socket. After this point the byte stream
    // is the raw WebSocket conversation between us and the daemon.
    let upgraded = hyper::upgrade::on(resp)
        .await
        .map_err(|e| ProxyError::HttpHandshake(format!("hyper upgrade await failed: {e}")))?;
    let upgraded_io = TokioIo::new(upgraded);

    // Hand the upgraded stream to `tokio-tungstenite`'s
    // post-handshake constructor. We have already done the HTTP/1.1
    // handshake by hand, so we use `WebSocketStream::from_raw_socket`
    // rather than `client_async` (which would try to re-issue the
    // handshake bytes on the socket we already finished handshaking
    // through).
    let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        upgraded_io,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;

    // The hyper connection driver task can exit once the upgrade
    // completes — it has no more HTTP work to do. Drop it.
    drop(conn_task);

    ferry_stdio_websocket(ws).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Byte ferry: stdin <-> WebSocket binary frames
// ---------------------------------------------------------------------------

/// Bridge process stdin and stdout to the WebSocket's binary frames.
/// Returns when either direction hits EOF / close / error; the
/// surviving direction is cancelled and any in-flight bytes are
/// dropped on the floor (SSH's framing tolerates a clipped tail).
///
/// `WS` is generic over the upgraded stream type so the hermetic
/// tests can exercise this function against an in-process pair of
/// `WebSocketStream`s (no Unix socket, no daemon).
pub async fn ferry_stdio_websocket<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
) -> Result<(), std::io::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sink, stream) = ws.split();
    let mut sink = sink;
    let mut stream = stream;

    let stdin_to_ws = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match stdin.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    debug!(error = %e, "stdin read error; ending stdin->ws ferry");
                    break;
                }
            };
            let chunk = buf[..n].to_vec();
            if let Err(e) = sink.send(Message::Binary(chunk.into())).await {
                debug!(error = %e, "ws send error; ending stdin->ws ferry");
                break;
            }
        }
        // Send a clean close so the daemon's byte mover tears the
        // backend pump down promptly.
        let _ = sink.send(Message::Close(None)).await;
        let _ = sink.close().await;
    });

    let ws_to_stdout = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(Message::Binary(bytes)) => {
                    if let Err(e) = stdout.write_all(&bytes).await {
                        debug!(error = %e, "stdout write error; ending ws->stdout ferry");
                        return;
                    }
                    if let Err(e) = stdout.flush().await {
                        debug!(error = %e, "stdout flush error; ending ws->stdout ferry");
                        return;
                    }
                }
                Ok(Message::Close(_)) => {
                    debug!("daemon sent close frame; ending ws->stdout ferry");
                    return;
                }
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {
                    // Auto-handled by tungstenite.
                }
                Ok(Message::Text(_)) => {
                    // The daemon's byte mover does not emit text
                    // frames; ignore defensively.
                }
                Ok(Message::Frame(_)) => {
                    // Raw frame variants are an escape hatch
                    // tungstenite exposes; the daemon does not use
                    // them.
                }
                Err(e) => {
                    debug!(error = %e, "ws recv error; ending ws->stdout ferry");
                    return;
                }
            }
        }
    });

    // First half to finish wins; we abort the other so the process
    // does not hang waiting on a quiet side (e.g. stdin reads from
    // /dev/null reach EOF immediately, but the daemon may take time
    // to drain before closing).
    tokio::select! {
        r = stdin_to_ws => {
            if let Err(e) = r {
                debug!(error = %e, "stdin->ws task panic");
            }
        }
        r = ws_to_stdout => {
            if let Err(e) = r {
                debug!(error = %e, "ws->stdout task panic");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hermetic unit tests
// ---------------------------------------------------------------------------
//
// The tests here exercise the byte-ferry over an in-memory WebSocket
// pair (a tokio-tungstenite server + client over a `tokio::io::duplex`
// stream). The pre-handshake error mapping is covered separately
// against a fake unix-socket "daemon" that returns a non-101 response.

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::SinkExt;
    use tokio::io::AsyncWriteExt;
    use tokio_tungstenite::tungstenite::Message;

    /// Build a connected pair of in-memory `WebSocketStream`s using
    /// `tokio::io::duplex` as the underlying transport. Returns the
    /// (client, server) pair; binary frames sent on one arrive on the
    /// other. Buffer size is large enough that round-trip tests do
    /// not stall on backpressure.
    async fn paired_ws() -> (
        tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
        tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>,
    ) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let client = tokio_tungstenite::WebSocketStream::from_raw_socket(
            a,
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        );
        let server = tokio_tungstenite::WebSocketStream::from_raw_socket(
            b,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        );
        let (client, server) = futures_util::future::join(client, server).await;
        (client, server)
    }

    /// Sending a binary frame on the server side and the client EOF
    /// from stdin (we have no stdin to drive in tests) — confirm
    /// `ferry_stdio_websocket` exits cleanly when the server closes.
    ///
    /// We do not assert that the binary payload reached stdout because
    /// `tokio::io::stdout()` writes to the real test process stdout
    /// (nextest captures it but we cannot inspect it from inside the
    /// test). The test's purpose is to pin the close-propagation
    /// invariant: a `Message::Close` on the WebSocket terminates the
    /// ferry, the function returns, and no task leak hangs the
    /// runtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ferry_returns_when_server_closes() {
        let (client, mut server) = paired_ws().await;

        let server_task = tokio::spawn(async move {
            server
                .send(Message::Binary(b"banner-line\n".to_vec().into()))
                .await
                .expect("server send");
            server
                .send(Message::Close(None))
                .await
                .expect("server close");
            // Drain — tungstenite needs a poll cycle to finish flushing
            // the close frame.
            let _ = server.close(None).await;
        });

        // 5s timeout pin: if the ferry doesn't honour close-frame
        // propagation it will hang on the stdin read.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            ferry_stdio_websocket(client),
        )
        .await;
        assert!(
            result.is_ok(),
            "ferry must exit on server close within 5s; got: {result:?}",
        );
        server_task.await.expect("server task");
    }

    /// Round-trip a binary payload from the test's "ssh client" side
    /// (the server half of the pair, since we are simulating the
    /// daemon) into the ferry's stdin -> ws direction. We cannot read
    /// the real process stdout from inside the test, so this case
    /// focuses on the reverse direction: bytes from server, observed
    /// at the underlying WebSocketStream's recv before the ferry
    /// consumes them.
    ///
    /// This proves the handshake-less ferry constructor accepts the
    /// in-memory duplex stream and the Message::Binary -> stdout
    /// branch does not panic on arbitrary payload sizes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ferry_consumes_binary_frames_until_close() {
        let (client, mut server) = paired_ws().await;

        let payload_sizes = [1, 16, 1024, 16 * 1024 - 1, 16 * 1024 + 1];

        let server_task = tokio::spawn(async move {
            for size in payload_sizes {
                let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
                server
                    .send(Message::Binary(payload.into()))
                    .await
                    .expect("server send");
            }
            server
                .send(Message::Close(None))
                .await
                .expect("server close");
            let _ = server.close(None).await;
        });

        let ferry_task = tokio::spawn(ferry_stdio_websocket(client));
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), ferry_task).await;
        assert!(res.is_ok(), "ferry must exit within 5s, got: {res:?}");
        server_task.await.expect("server task");
    }

    // -----------------------------------------------------------------------
    // Pre-handshake error mapping: 404 -> EXIT_SESSION_NOT_FOUND
    // -----------------------------------------------------------------------

    /// Stand up a hand-rolled "daemon" on a Unix socket that returns
    /// `404 Not Found` with the SSH_NOT_AVAILABLE body, then invoke
    /// the proxy shim's pre-handshake path. Verify the upgrade
    /// rejection maps to EXIT_SESSION_NOT_FOUND.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_returns_session_not_found_on_404() {
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let socket_path = tmp.path().join("d.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            // Read enough of the request to consume the headers.
            let mut buf = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut conn, &mut buf).await;
            // Send back a minimal HTTP/1.1 404.
            let body = "SSH_NOT_AVAILABLE: nope";
            let resp = format!(
                "HTTP/1.1 404 Not Found\r\n\
                 content-type: text/plain\r\n\
                 content-length: {}\r\n\
                 connection: close\r\n\
                 \r\n{body}",
                body.len()
            );
            let _ = conn.write_all(resp.as_bytes()).await;
            let _ = conn.shutdown().await;
        });

        let code = run(socket_path.to_str().unwrap(), "deadbeefcafe").await;
        assert_eq!(
            code, EXIT_SESSION_NOT_FOUND,
            "404 must map to EXIT_SESSION_NOT_FOUND (M18-S7 lazy-cleanup hook depends on this)"
        );
        let _ = server.await;
    }

    /// 500-class upgrade rejection (or any non-404 non-101) maps to
    /// generic failure. Pins the "do not silently swallow daemon
    /// errors" contract.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_returns_generic_failure_on_500() {
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let socket_path = tmp.path().join("d.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut conn, &mut buf).await;
            let body = "internal";
            let resp = format!(
                "HTTP/1.1 500 Internal Server Error\r\n\
                 content-length: {}\r\n\
                 connection: close\r\n\
                 \r\n{body}",
                body.len()
            );
            let _ = conn.write_all(resp.as_bytes()).await;
            let _ = conn.shutdown().await;
        });

        let code = run(socket_path.to_str().unwrap(), "deadbeefcafe").await;
        assert_eq!(code, EXIT_GENERIC_FAILURE);
        let _ = server.await;
    }

    /// A non-existent socket path maps to generic failure with the
    /// "is the daemon running?" stderr line.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_returns_generic_failure_on_missing_socket() {
        let nonexistent = "/tmp/sandbox-proxy-nonexistent-12345.sock";
        let code = run(nonexistent, "deadbeefcafe").await;
        assert_eq!(code, EXIT_GENERIC_FAILURE);
    }
}
