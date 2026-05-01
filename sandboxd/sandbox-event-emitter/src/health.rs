//! Minimal HTTP/1.1 health server.
//!
//! Spec reference: `2026-04-21-port-explicit-policies-presets-observability-design.md`
//! Part 3 / "Listener design / Healthcheck listener" and "Liveness
//! posture", with M12-S2 Resolution 5 pinning the response field
//! names across the binary rename.
//!
//! `GET /health` returns `200 OK` with a JSON body whose field set is
//! supplied by the caller via the [`HealthShape`] callback. Any other
//! path returns `404`. Request parsing is intentionally strict-but-
//! small: we read up to one CRLF-terminated request line, then close.
//! The health probe is gateway-internal (Docker `HEALTHCHECK` +
//! sandboxd's `docker exec` probe) so we do not need full HTTP/1.1
//! semantics — keep-alive, chunked encoding, and header tolerance are
//! out of scope.
//!
//! ## Field-name evolution across the M12-S2 rename
//!
//! Resolution 5 of the M12-S2 design spec preserves the bulk of the
//! `/health` JSON shape across the binary rename, but renames the one
//! field whose name pinned the old (now-removed) implementation: the
//! `udp_listener` key has become `nflog_socket` because the UDP deny
//! path no longer runs a userland datagram listener — the kernel
//! emits NFLOG netlink messages and the binary's NFLOG subscriber
//! parses them. Operator-tooling that pinned the literal key name
//! needs an update; tooling that probes for top-level field
//! *presence* keeps working.
//!
//! ## Per-binary response shape
//!
//! M12-S2 Phase 3 introduces `sandbox-nft-allow-logger` as a sibling
//! binary; it shares this lib but exposes a different `/health`
//! payload (`allow_events_emitted_60s`, `rate_limited_count`,
//! `nfct_socket: "ok"` in place of the deny-logger's `tcp_listener` /
//! `nflog_socket` / `events_emitted_60s`). Rather than fork the
//! handler, we let the calling binary pass a [`HealthShape`] closure
//! that takes the current emitter gauge value and returns the JSON
//! body to send. The lib stays the single source of truth for the
//! HTTP framing, the rolling-gauge reset cadence, the request parser,
//! and the strict path-match — only the body bytes are caller-shaped.
//!
//! The `events_emitted_60s` (deny-logger) and
//! `allow_events_emitted_60s` (allow-logger) values are pulled from a
//! shared [`EventEmitter`] counter that the emit path increments; a
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

/// Caller-supplied response-body builder.
///
/// Receives the current `events_emitted_60s` counter snapshot and must
/// return the bytes of the JSON object to ship as the `/health`
/// response body (no surrounding HTTP framing — the lib adds that).
///
/// Trait alias around `Fn(u64) -> String + Send + Sync + 'static` so
/// closures, function pointers, and explicit struct impls all
/// compose; bound at construction (`run`) so the spawned per-request
/// tasks can clone an `Arc<HealthShape>` without further bound noise.
pub trait HealthShape: Fn(u64) -> String + Send + Sync + 'static {}
impl<F> HealthShape for F where F: Fn(u64) -> String + Send + Sync + 'static {}

/// Bind the HTTP health listener on `(bind_ip, port)`.
pub async fn bind(bind_ip: Ipv4Addr, port: u16) -> io::Result<TcpListener> {
    let addr = SocketAddr::V4(SocketAddrV4::new(bind_ip, port));
    TcpListener::bind(addr).await
}

/// Spawn the rolling-gauge reset ticker and run the accept loop.
///
/// `body_builder` is invoked per `GET /health` request with the
/// current emitter gauge value; its return string is shipped as the
/// response body. Callers pass distinct builders so the deny-logger
/// and allow-logger can expose different field sets without forking
/// the HTTP framing.
///
/// Returns only on a fatal listener error (propagated from
/// `TcpListener::accept`).
pub async fn run<F>(
    listener: TcpListener,
    emitter: Arc<EventEmitter>,
    body_builder: F,
) -> io::Result<()>
where
    F: HealthShape,
{
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

    let body_builder = Arc::new(body_builder);
    loop {
        let (socket, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                tracing::warn!(error = %err, "health accept failed");
                continue;
            }
        };
        let emitter = Arc::clone(&emitter);
        let body_builder = Arc::clone(&body_builder);
        tokio::spawn(async move {
            if let Err(err) = handle(socket, &emitter, body_builder.as_ref()).await {
                tracing::debug!(error = %err, "health handler error");
            }
        });
    }
}

async fn handle<F>(
    mut socket: TcpStream,
    emitter: &EventEmitter,
    body_builder: &F,
) -> io::Result<()>
where
    F: HealthShape,
{
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

    let body = body_builder(emitter.events_emitted_60s());
    write_response(&mut socket, 200, "OK", body.as_bytes()).await
}

/// Stock body builder for `sandbox-nft-deny-logger`'s `/health`.
///
/// Exposes the deny-logger's three legacy field names (preserved
/// across the M12-S2 binary rename per Resolution 5):
///
/// - `tcp_listener: "ok"` — the listener on `:10001` is up.
/// - `nflog_socket: "ok"` — the NFLOG receive task is bound (replaces
///   the legacy `udp_listener` field; M12-S2 Decision 2 removed the
///   userland UDP listener).
/// - `events_emitted_60s: <gauge>` — rolling deny-event count over
///   the last 60 seconds.
pub fn deny_logger_body(events_emitted_60s: u64) -> String {
    format!(
        "{{\"tcp_listener\":\"ok\",\"nflog_socket\":\"ok\",\"events_emitted_60s\":{events_emitted_60s}}}",
    )
}

/// Stock body builder for `sandbox-nft-allow-logger`'s `/health`.
///
/// Field set parallels `deny_logger_body` but for the allow side
/// (M12-S2 Phase 3 / Resolution 5):
///
/// - `nfct_socket: "ok"` — the NFCT (`nfnetlink_conntrack`)
///   subscription is bound and receiving multicast events.
/// - `allow_events_emitted_60s: <gauge>` — rolling allow-event count.
///
/// `rate_limited_count` is intentionally *not* exposed at `/health`
/// time: the per-process `RateCap` flushes a `rate_limited` summary
/// to the JSONL file on every window rollover, which is the
/// authoritative count. Putting a parallel counter into `/health`
/// would create a second source of truth that operators would have to
/// reconcile against the JSONL stream.
pub fn allow_logger_body(allow_events_emitted_60s: u64) -> String {
    format!("{{\"nfct_socket\":\"ok\",\"allow_events_emitted_60s\":{allow_events_emitted_60s}}}",)
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

    async fn read_health_body(local: SocketAddr) -> serde_json::Value {
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
        serde_json::from_str(body).unwrap_or_else(|e| panic!("parse {body:?}: {e}"))
    }

    /// Probe `GET /health` end-to-end against the deny-logger body
    /// builder: assert `200 OK`, JSON body, and the three spec-named
    /// keys. Covers the happy path that Docker `HEALTHCHECK` and
    /// sandboxd's component-health probe hit on the deny-logger.
    #[tokio::test]
    async fn health_responds_200_ok_json_for_deny_logger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = Arc::new(EventEmitter::open(&path, "deny-logger").unwrap());
        let listener = bind(Ipv4Addr::LOCALHOST, 0).await.unwrap();
        let local = listener.local_addr().unwrap();

        let server_emitter = Arc::clone(&emitter);
        let server = tokio::spawn(async move {
            let _ = run(listener, server_emitter, deny_logger_body).await;
        });

        let json = read_health_body(local).await;
        assert_eq!(json["tcp_listener"], "ok");
        assert_eq!(
            json["nflog_socket"], "ok",
            "M12-S2 Phase 2 renamed udp_listener → nflog_socket: the UDP \
             deny path is now NFLOG-driven, no userland datagram listener"
        );
        assert!(
            json.get("udp_listener").is_none(),
            "the legacy udp_listener field must not survive the M12-S2 \
             rename"
        );
        // Fresh emitter — no deny events emitted yet.
        assert_eq!(json["events_emitted_60s"], 0);

        server.abort();
    }

    /// `/health` for the allow-logger exposes a different field set
    /// (M12-S2 Phase 3 / Resolution 5): `nfct_socket: "ok"` plus
    /// `allow_events_emitted_60s`. Pin the shape so the deny-side
    /// keys (`tcp_listener`, `nflog_socket`) do not leak into the
    /// allow-logger response.
    #[tokio::test]
    async fn health_responds_200_ok_json_for_allow_logger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nft-allow.jsonl");
        let emitter = Arc::new(EventEmitter::open(&path, "allow-logger").unwrap());
        let listener = bind(Ipv4Addr::LOCALHOST, 0).await.unwrap();
        let local = listener.local_addr().unwrap();

        let server_emitter = Arc::clone(&emitter);
        let server = tokio::spawn(async move {
            let _ = run(listener, server_emitter, allow_logger_body).await;
        });

        let json = read_health_body(local).await;
        assert_eq!(json["nfct_socket"], "ok");
        assert_eq!(json["allow_events_emitted_60s"], 0);
        // Deny-logger keys must not appear on the allow-logger.
        for legacy in [
            "tcp_listener",
            "nflog_socket",
            "events_emitted_60s",
            "udp_listener",
        ] {
            assert!(
                json.get(legacy).is_none(),
                "allow-logger /health must not expose `{legacy}`; json = {json}"
            );
        }
        server.abort();
    }
}
