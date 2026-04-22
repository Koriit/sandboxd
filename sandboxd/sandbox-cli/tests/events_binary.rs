//! Binary-level regression test for `sandbox events` (non-follow).
//!
//! Pins the end-to-end process exit behavior that M10-S4 Phase 6b
//! restored: after the daemon finishes streaming the bounded JSONL
//! body, the CLI must drop its request machinery, let hyper's
//! connection driver return, and exit — *without* waiting on a
//! keep-alive idle timeout.
//!
//! ## What this test covers
//!
//! - Spawns the compiled `sandbox` binary (path via
//!   `CARGO_BIN_EXE_sandbox`) as a subprocess.
//! - Runs a minimal axum server on a temp Unix socket that mimics the
//!   real daemon's non-follow contract: it serves exactly one
//!   `/sessions/{id}/events` request, returns `Content-Type:
//!   application/jsonl`, writes two JSONL lines, and ends the body.
//! - Asserts that the subprocess exits cleanly within 5 seconds and
//!   that the two JSONL lines round-tripped to its stdout.
//!
//! Before the Phase 6b fix, the CLI would buffer the body and then
//! hang on `conn_task.await` — the hyper HTTP/1.1 driver stayed alive
//! waiting for a next request that would never come — until the
//! 5-second test timeout elapsed, failing the test.
//!
//! After the fix (`connection: close` header + drop sender/response
//! before awaiting the conn driver), the subprocess exits in well
//! under a second once the last byte is sent.
//!
//! This test deliberately does *not* reach into `sandbox-cli`
//! internals: it is a binary-level contract test, because the bug it
//! guards against is a whole-process lifecycle concern that unit
//! tests of helper functions cannot observe.

use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::routing::get;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;
use tokio::process::Command;

/// Two deterministic JSONL lines — enough to prove the body round-trips
/// without the test caring about the daemon's real schema.  The shape
/// mirrors what the production `event_to_jsonl_line` serializer emits
/// so the CLI's JSON output mode accepts it verbatim.
const LINE_A: &str = r#"{"layer":"deny-logger","timestamp":"2026-04-23T00:00:00.000Z","session":"test-session","event":"deny","orig_dst_ip":"1.2.3.4","orig_dst_port":80}"#;
const LINE_B: &str = r#"{"layer":"deny-logger","timestamp":"2026-04-23T00:00:01.000Z","session":"test-session","event":"deny","orig_dst_ip":"1.2.3.5","orig_dst_port":443}"#;

/// Handler that returns a bounded JSONL body with `Content-Type:
/// application/jsonl`.  Matches the daemon's non-follow contract
/// (`sandboxd/src/events_http.rs::get_session_events` non-follow
/// branch).
async fn events_handler() -> (StatusCode, HeaderMap, String) {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/jsonl"));
    let body = format!("{LINE_A}\n{LINE_B}\n");
    (StatusCode::OK, headers, body)
}

/// Bind a tiny axum server on a temp Unix socket and serve at most one
/// request — enough for the `sandbox events` non-follow path.  Returns
/// the temp dir (kept alive to own the socket file) and the socket
/// path string the CLI should dial.
async fn spawn_test_server() -> (TempDir, String, tokio::task::JoinHandle<()>) {
    let tmp = tempfile::tempdir().expect("create tempdir for socket");
    let socket_path = tmp.path().join("sandboxd.sock");
    let socket_str = socket_path
        .to_str()
        .expect("socket path is valid utf-8")
        .to_string();

    let listener = UnixListener::bind(&socket_path).expect("bind unix socket");

    // `/sessions/{id}/events` is the exact route the CLI hits; the
    // handler ignores the session id.
    let app: Router = Router::new().route("/sessions/{session}/events", get(events_handler));

    // `axum::serve` over a `UnixListener` Just Works in axum 0.8. We
    // use graceful shutdown on the server drop so a leftover task
    // can't leak across test cases.
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);

    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown_clone.notified().await;
            })
            .await;
    });

    // Stash the shutdown trigger inside the JoinHandle's task via a
    // side channel would complicate the return type; simpler: leak
    // the shutdown Arc into the server task above and rely on the
    // test dropping the tempdir + aborting the server handle.
    // The JoinHandle lets the test abort the server explicitly.
    drop(shutdown);

    (tmp, socket_str, server)
}

/// End-to-end: the `sandbox events <session>` subprocess must
/// terminate on its own within a few seconds once the daemon finishes
/// streaming.  Before the Phase 6b fix this hung for ~60 s (the CLI's
/// per-call subprocess timeout in the E2E suite) and had to be
/// SIGKILLed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sandbox_events_non_follow_exits_when_body_ends() {
    // Binary produced by `cargo build` for this workspace member.
    let bin = env!("CARGO_BIN_EXE_sandbox");

    let (_tmp, socket_path, server_task) = spawn_test_server().await;

    // Spawn the real `sandbox` binary with stdout captured so we can
    // assert the body round-tripped.  `--socket` overrides the CLI
    // default; `events <id>` with no `--follow` exercises the
    // non-follow code path we're regression-testing.
    let mut child = Command::new(bin)
        .arg("--socket")
        .arg(&socket_path)
        .arg("events")
        .arg("test-session")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn sandbox binary");

    let stdout = child.stdout.take().expect("child stdout piped");
    let stdout_reader = BufReader::new(stdout);

    // Read lines from the child with a generous budget so we see both
    // JSONL records before the child exits.  We drive the reader on
    // its own task so the `child.wait()` timeout is measured from the
    // moment the last byte is on the wire, not from the last read.
    let lines_task = tokio::spawn(async move {
        let mut lines = stdout_reader.lines();
        let mut collected: Vec<String> = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            collected.push(line);
        }
        collected
    });

    // 5 s is ~8x the expected happy-path exit time (~50 ms on a warm
    // cargo cache) and ~12x faster than the buggy hang (~60 s).  If
    // the fix regresses, this timeout trips and the test fails loud.
    let deadline = Duration::from_secs(5);
    let started = Instant::now();
    let status = match tokio::time::timeout(deadline, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => panic!("child.wait() failed: {e}"),
        Err(_) => {
            // Kill the subprocess to avoid leaking it into the next test
            // run; the test has already failed.
            let _ = child.start_kill();
            panic!(
                "`sandbox events <session>` did not exit within {deadline:?} \
                 — Phase 6b regression (see `stream_events_to_stdout`)"
            );
        }
    };
    let elapsed = started.elapsed();

    // Drain stdout now that the child is gone.
    let collected = lines_task.await.expect("stdout reader task must complete");

    // Shut down the test server.
    server_task.abort();

    assert!(
        status.success(),
        "sandbox exited non-zero: {status:?}, stdout: {collected:?}"
    );
    assert!(
        collected.iter().any(|l| l == LINE_A),
        "expected stdout to contain LINE_A, got: {collected:?}"
    );
    assert!(
        collected.iter().any(|l| l == LINE_B),
        "expected stdout to contain LINE_B, got: {collected:?}"
    );
    // Sanity: the happy-path exit should be far below the deadline.
    assert!(
        elapsed < deadline,
        "exit took {elapsed:?} (deadline {deadline:?}) — suspiciously close to hang"
    );
}
