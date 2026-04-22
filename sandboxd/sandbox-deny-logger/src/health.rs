//! Minimal HTTP/1.1 health server.
//!
//! Spec reference: Part 3 / "Listener design / Healthcheck listener"
//! (lines 820-828) and "Liveness posture" (lines 853-872).
//!
//! `GET /health` returns `200 OK` with
//! `{"tcp_listener": "ok", "udp_listener": "ok", "events_emitted_60s": N}`.
//! Any other path returns `404`. Request parsing is intentionally
//! strict-but-small: we read up to one CRLF-terminated request line,
//! then close. The health probe is gateway-internal (Docker
//! `HEALTHCHECK` + sandboxd's `docker exec` probe) so we do not need
//! full HTTP/1.1 semantics — keep-alive, chunked encoding, and header
//! tolerance are out of scope.
//!
//! The `events_emitted_60s` value is pulled from a shared
//! [`EventEmitter`] counter that the deny-event emit path increments; a
//! background ticker resets it every 60 seconds so the value
//! approximates "events in the last minute" without the cost of a
//! sliding-window histogram.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::event::EventEmitter;

/// Interval at which the rolling events gauge is reset.
const GAUGE_WINDOW: Duration = Duration::from_secs(60);

/// Bind the HTTP health listener on `(bind_ip, port)`.
pub async fn bind(bind_ip: Ipv4Addr, port: u16) -> io::Result<TcpListener> {
    let addr = SocketAddr::V4(SocketAddrV4::new(bind_ip, port));
    TcpListener::bind(addr).await
}

/// Spawn the rolling-gauge reset ticker and run the accept loop.
///
/// Returns only on a fatal listener error (propagated from
/// `TcpListener::accept`).
pub async fn run(listener: TcpListener, emitter: Arc<EventEmitter>) -> io::Result<()> {
    let ticker_emitter = Arc::clone(&emitter);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(GAUGE_WINDOW);
        // First tick fires immediately per tokio's default; skip so we
        // don't wipe a counter that's already at zero right at start.
        interval.tick().await;
        loop {
            interval.tick().await;
            ticker_emitter.reset_gauge();
        }
    });

    loop {
        let (socket, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                tracing::warn!(error = %err, "health accept failed");
                continue;
            }
        };
        let emitter = Arc::clone(&emitter);
        tokio::spawn(async move {
            if let Err(err) = handle(socket, &emitter).await {
                tracing::debug!(error = %err, "health handler error");
            }
        });
    }
}

async fn handle(mut socket: TcpStream, emitter: &EventEmitter) -> io::Result<()> {
    // Read up to 1 KiB of request-line + headers, stopping at the
    // first `\r\n\r\n` (end of HTTP headers). Any larger request is a
    // misbehaving client — close.
    let mut buf = [0u8; 1024];
    let mut read = 0usize;
    loop {
        if read == buf.len() {
            // Headers exceed buffer — treat as malformed.
            return write_status(&mut socket, 400, b"").await;
        }
        let n = socket.read(&mut buf[read..]).await?;
        if n == 0 {
            break;
        }
        read += n;
        if buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let head = &buf[..read];
    let first_line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(head.len());
    let request_line = &head[..first_line_end];

    // Strictly accept `GET /health HTTP/1.{0,1}`; anything else → 404.
    const PREFIX: &[u8] = b"GET /health ";
    if !request_line.starts_with(PREFIX) {
        return write_status(&mut socket, 404, b"").await;
    }

    let body = format!(
        "{{\"tcp_listener\":\"ok\",\"udp_listener\":\"ok\",\"events_emitted_60s\":{}}}",
        emitter.events_emitted_60s()
    );
    write_response(&mut socket, 200, "OK", body.as_bytes()).await
}

async fn write_status(socket: &mut TcpStream, code: u16, body: &[u8]) -> io::Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Unknown",
    };
    write_response(socket, code, reason, body).await
}

async fn write_response(
    socket: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &[u8],
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    socket.write_all(head.as_bytes()).await?;
    if !body.is_empty() {
        socket.write_all(body).await?;
    }
    socket.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Probe `GET /health` end-to-end: assert `200 OK`, JSON body, and
    /// the three spec-named keys. Covers the happy path that Docker
    /// `HEALTHCHECK` and sandboxd's component-health probe hit.
    #[tokio::test]
    async fn health_responds_200_ok_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = Arc::new(EventEmitter::open(&path).unwrap());
        let listener = bind(Ipv4Addr::LOCALHOST, 0).await.unwrap();
        let local = listener.local_addr().unwrap();

        let server_emitter = Arc::clone(&emitter);
        let server = tokio::spawn(async move {
            let _ = run(listener, server_emitter).await;
        });

        // Send a manual HTTP/1.1 request.
        let mut sock = TcpStream::connect(local).await.unwrap();
        sock.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), sock.read_to_end(&mut response))
            .await
            .expect("timed out reading /health response")
            .unwrap();

        let text = String::from_utf8(response).unwrap();
        assert!(
            text.starts_with("HTTP/1.1 200 OK\r\n"),
            "status line: {text:?}"
        );
        let body_start = text.find("\r\n\r\n").unwrap() + 4;
        let body = &text[body_start..];
        let json: serde_json::Value =
            serde_json::from_str(body).unwrap_or_else(|e| panic!("parse {body:?}: {e}"));
        assert_eq!(json["tcp_listener"], "ok");
        assert_eq!(json["udp_listener"], "ok");
        // Fresh emitter — no deny events emitted yet.
        assert_eq!(json["events_emitted_60s"], 0);

        server.abort();
    }
}
