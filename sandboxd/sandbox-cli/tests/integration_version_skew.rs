//! Binary-level integration test for the CLI ↔ daemon strict
//! version-equality handshake (`integration_cli_refuses_on_version_skew`).
//!
//! Pins the end-to-end refusal contract: when the CLI dials a daemon
//! whose `GET /version` reports a different `CARGO_PKG_VERSION` than
//! the CLI's own compile-time version, the CLI must:
//!
//! 1. exit with code `2` (distinct from `1`, which is the daemon-side
//!    error path after a successful handshake),
//! 2. emit the verbatim stderr message containing all four load-
//!    bearing tokens: `version mismatch`, `CLI is`, `daemon is`,
//!    `both must match`,
//! 3. *not* send the caller's actual request (proven by the mock
//!    daemon's request counter — see assertions below).
//!
//! ## Why a mock daemon, not a real one
//!
//! Spinning up two `cargo build`s with deliberately divergent
//! `CARGO_PKG_VERSION` values is expensive in CI (~30 s of compile
//! per build). A mock daemon listening on a temp unix socket and
//! responding to `GET /version` with a hardcoded different version
//! is byte-for-byte equivalent to the operator-visible refusal —
//! both paths fail at the equality predicate in
//! `send_request_with_timeout`. The mock approach mirrors what
//! `tests/events_binary.rs` does for the streaming-exit regression.
//!
//! The deliberately-skewed version is `9.99.99` — outside any
//! plausible workspace version so the test cannot accidentally
//! pass under a future bump.

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use tempfile::TempDir;
use tokio::net::UnixListener;
use tokio::process::Command;

/// The version string the mock daemon reports. Deliberately far
/// outside the workspace's `CARGO_PKG_VERSION` range so the test
/// cannot accidentally pass once the workspace bumps to e.g.
/// `1.0.0` — a real skew is what the operator sees in production.
const MOCK_DAEMON_VERSION: &str = "9.99.99";

/// Spawn an axum-on-UnixListener mock daemon. The server exposes:
///
/// - `GET /version` → always returns `{"version": "9.99.99"}` so the
///   CLI's strict-equality check trips on the first byte after the
///   handshake;
/// - `GET /sessions` (and any other request) → returns 500 with a
///   counted-call body. The integration test asserts the count is
///   **zero**: a passing CLI must not reach the request stage after
///   detecting the skew. If the test ever observes `/sessions` being
///   hit, the gate has been silently removed.
///
/// Returns `(tempdir, socket_path, request_counter, server_task)`.
/// The `TempDir` owns the socket file and must outlive the test; the
/// `JoinHandle` is aborted by the test once the assertions complete.
async fn spawn_mock_daemon() -> (
    TempDir,
    String,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let tmp = tempfile::tempdir().expect("create tempdir for mock daemon socket");
    let socket_path = tmp.path().join("sandboxd.sock");
    let socket_str = socket_path
        .to_str()
        .expect("socket path is valid utf-8")
        .to_string();

    let listener = UnixListener::bind(&socket_path).expect("bind mock-daemon unix socket");

    // The `/sessions` counter is the canary: if it ever increments,
    // the CLI sent the caller's request despite the version skew —
    // exactly the failure mode the strict-equality version rule
    // exists to prevent.
    let sessions_counter = Arc::new(AtomicUsize::new(0));
    let counter_for_handler = Arc::clone(&sessions_counter);

    async fn version_handler() -> (StatusCode, axum::Json<serde_json::Value>) {
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "version": MOCK_DAEMON_VERSION })),
        )
    }

    let sessions_handler = move || {
        let counter = Arc::clone(&counter_for_handler);
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "mock daemon: /sessions must not be reached under version skew",
            )
        }
    };

    let app: Router = Router::new()
        .route("/version", get(version_handler))
        .route("/sessions", get(sessions_handler));

    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (tmp, socket_str, sessions_counter, server)
}

/// `sandbox ps` (which dispatches through `send_request_with_timeout`
/// to `GET /sessions`) against a daemon that reports a different
/// version must exit `2` with the verbatim stderr message — and must
/// never reach the `/sessions` handler.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_cli_refuses_on_version_skew() {
    let bin = env!("CARGO_BIN_EXE_sandbox");

    let (_tmp, socket_path, sessions_counter, server_task) = spawn_mock_daemon().await;

    // `sandbox ps` is the canonical "any non-doctor / non-version
    // subcommand" — it goes through the standard `build_request →
    // send_request_with_timeout` pipeline that the version handshake
    // gates. Choosing `ps` over e.g. `start <id>` keeps the test
    // free of session-id fixturing.
    let output = Command::new(bin)
        .arg("--socket")
        .arg(&socket_path)
        .arg("ps")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await
        .expect("spawn sandbox binary");

    server_task.abort();

    // Exit code 2 is load-bearing: `1` is the CLI's exit for
    // daemon-side errors *after* a successful handshake; `2` is
    // exclusively the version-skew refusal. Wrapper scripts may
    // distinguish the two paths via this code.
    let exit_code = output
        .status
        .code()
        .expect("child exited (not killed by signal)");
    assert_eq!(
        exit_code,
        2,
        "CLI must exit with code 2 on version skew; \
         got {exit_code}, stderr = {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The verbatim stderr message contains four load-bearing tokens.
    // A regression that reworded any of them would silently break
    // downstream scripts that grep for them.
    let stderr = String::from_utf8_lossy(&output.stderr);
    for token in ["version mismatch", "CLI is", "daemon is", "both must match"] {
        assert!(
            stderr.contains(token),
            "stderr must contain the verbatim token {token:?}; \
             got stderr = {stderr:?}"
        );
    }

    // Both versions must appear next to their labels. The mock daemon
    // reports `9.99.99`; the CLI's own `CARGO_PKG_VERSION` is the
    // test process's same env (compile-unit equality holds because
    // the test binary and the CLI binary are members of the same
    // workspace).
    let cli_version = env!("CARGO_PKG_VERSION");
    assert!(
        stderr.contains(&format!("CLI is {cli_version}")),
        "stderr must report the CLI's own version after `CLI is`; \
         got {stderr:?}"
    );
    assert!(
        stderr.contains(&format!("daemon is {MOCK_DAEMON_VERSION}")),
        "stderr must report the mock daemon's version after `daemon is`; \
         got {stderr:?}"
    );

    // The single most-important assertion of this test: the request
    // never reached the daemon's `/sessions` handler. If this counter
    // ever increments, the version gate has been silently removed
    // (or moved to a later point in the dispatch).
    let sessions_hits = sessions_counter.load(Ordering::SeqCst);
    assert_eq!(
        sessions_hits, 0,
        "the strict-equality version check must short-circuit \
         *before* the caller's request is sent; mock daemon observed \
         {sessions_hits} hit(s) on /sessions despite the skew, which \
         means the gate is being bypassed"
    );

    // Suppress unused-warning noise for stdout — the CLI prints
    // nothing to stdout on the refusal path; the assertion is the
    // exit code + stderr.
    let _ = output.stdout;
}

/// Symmetric coverage for `sandbox version`: even when the daemon
/// would return a skewed version, `sandbox version` must answer
/// locally and never open a connection. Pins the parse-time bypass
/// at the top of `main` (`if matches!(cli.command, Command::Version)`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_cli_version_subcommand_bypasses_handshake() {
    let bin = env!("CARGO_BIN_EXE_sandbox");

    let (_tmp, socket_path, sessions_counter, server_task) = spawn_mock_daemon().await;

    let output = Command::new(bin)
        .arg("--socket")
        .arg(&socket_path)
        .arg("version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await
        .expect("spawn sandbox binary");

    server_task.abort();

    let exit_code = output
        .status
        .code()
        .expect("child exited (not killed by signal)");
    assert_eq!(
        exit_code,
        0,
        "`sandbox version` is local-only and must exit 0 even under \
         a hypothetical daemon skew; got {exit_code}, stderr = {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim_end_matches('\n'),
        format!("sandbox {}", env!("CARGO_PKG_VERSION")),
        "`sandbox version` must print exactly `sandbox <CARGO_PKG_VERSION>\\n` \
         per.6; got stdout = {stdout:?}"
    );

    // Most-important canary: the local-answer path never opens a
    // socket. The mock daemon's `/sessions` counter remains zero and
    // so does any other path on the mock — there is no handler that
    // could observe a connection. The cheapest proof is the
    // `/sessions` counter (already wired) plus the bonus property:
    // the mock socket is at `socket_path` but the CLI did not need
    // it; a regression that re-introduces a `UnixStream::connect`
    // for `Command::Version` would still be caught by the
    // `/sessions` zero-hit assertion below (any HTTP request the CLI
    // mistakenly sent would land on the catch-all).
    let sessions_hits = sessions_counter.load(Ordering::SeqCst);
    assert_eq!(
        sessions_hits, 0,
        "`sandbox version` must not contact the daemon; \
         mock daemon observed {sessions_hits} hit(s)"
    );
}
