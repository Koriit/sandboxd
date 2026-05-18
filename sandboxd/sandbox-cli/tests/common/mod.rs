//! Shared helpers for `sandbox-cli` integration tests.
//!
//! Per the cargo integration-test convention, every test file that uses
//! these helpers must declare `mod common;` at its top. Items are
//! tagged `#[allow(dead_code)]` because each call site uses a subset.

#![allow(dead_code)]

use std::path::Path;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Total time to wait for the fake daemon to become ready before
/// failing. Five seconds is generous enough that a genuinely broken
/// test fails loudly rather than hanging, but far above any plausible
/// userspace-accept scheduling latency under nextest concurrent load.
const READINESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Inter-probe sleep. Short enough to feel instantaneous in the happy
/// path (typically 1-2 iterations on a warm host) but long enough that
/// the budget covers ~500 retries before the deadline trips.
const PROBE_INTERVAL: Duration = Duration::from_millis(10);

/// Block until the fake daemon at `sock_path` answers an HTTP `200`
/// to `GET <probe_path>`, or the readiness timeout trips.
///
/// Replaces the fixed `tokio::time::sleep(50 ms)` heuristic that used
/// to follow `axum::serve` spawn calls in these tests. The race that
/// motivated the swap: `UnixListener::bind` registers the socket with
/// the kernel synchronously, so a client `connect(2)` succeeds before
/// the spawned axum task is scheduled to `accept(2)` it. The CLI
/// writes its request, hyper's response future gets dropped/canceled
/// when the test runtime tears down the connection, and the test
/// fails with `request failed: operation was canceled` -- but only
/// under nextest concurrent load, where the userspace accept may sit
/// behind dozens of ready tasks. Probing for a real `200` response
/// proves the full request/response loop is wired before the CLI
/// dials in.
pub async fn wait_for_daemon_ready(sock_path: &Path, probe_path: &str) -> Result<(), String> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        let last_err = match probe_once(sock_path, probe_path).await {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "fake daemon at {} did not answer 200 on `{}` within {:?}; last error: {}",
                sock_path.display(),
                probe_path,
                READINESS_TIMEOUT,
                last_err,
            ));
        }
        tokio::time::sleep(PROBE_INTERVAL).await;
    }
}

/// One probe attempt: connect, send a minimal `GET <path> HTTP/1.1`
/// request with `Connection: close`, then drain the response to EOF
/// and confirm the status line begins with `HTTP/1.1 200`.
///
/// Draining to EOF (rather than reading just the status-line prefix)
/// is load-bearing: it lets the server's connection-handler task run
/// to its natural completion before our side of the socket closes. A
/// half-read probe leaves the server task writing into a closed peer
/// half the time, which under heavy nextest load occasionally
/// destabilizes the listener's task graph and produces "operation was
/// canceled" on the NEXT connection's response future.
///
/// Returns `Err` (without surfacing the specific I/O error kind) for
/// connection refused, EOF, partial reads, or non-200 status lines --
/// the caller treats every flavor as "not ready yet" and retries until
/// the deadline.
async fn probe_once(sock_path: &Path, probe_path: &str) -> Result<(), String> {
    let mut stream = UnixStream::connect(sock_path)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let request =
        format!("GET {probe_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;

    // Drain to EOF so the server's connection-handler task completes
    // cleanly before we drop our side. With `Connection: close` set,
    // the server signals end-of-response by closing the socket, so the
    // total read size is bounded by the response body length.
    let mut buf = Vec::with_capacity(256);
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("drain: {e}"))?;
    if buf.is_empty() {
        return Err("eof before status line".into());
    }
    // Status line is ASCII; lossy lets us match without hard-failing
    // on a body that happens to contain non-utf8 bytes.
    let head: String = String::from_utf8_lossy(&buf[..buf.len().min(16)]).into_owned();
    if head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200") {
        Ok(())
    } else {
        Err(format!("unexpected status prefix: {head:?}"))
    }
}
