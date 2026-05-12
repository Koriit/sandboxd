//! Integration test: the CLI fires exactly one `GET /backends` per
//! invocation.
//!
//! Spec § "CLI learns capabilities via `GET /backends`" mandates a
//! single fetch per CLI invocation. This is what makes capability
//! validation cheap enough to run on every `create` without waiting on
//! a daemon roundtrip per check; it also keeps the daemon's audit log
//! concise (one cap-fetch line per `sandbox` invocation, not one per
//! validator step).
//!
//! The test spins up a fake `sandboxd` HTTP server on a tempdir Unix
//! socket. The server has a single `AtomicUsize` counter shared between
//! the `/backends` and `/sessions` handlers. After the CLI subprocess
//! exits successfully the test asserts the counter is exactly 1.
//!
//! Both the [`BackendsCache`] unit-test (`cache_starts_empty`) and this
//! binary-level test live in the repo because the spec invariant holds
//! at *both* layers — the cache module enforces single-fetch via its
//! `Option<Vec<_>>` cache field, and `main`'s dispatch must not
//! construct a second `BackendsCache` for the same invocation.

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::time::timeout;

/// Counts of each route the fake daemon served.
#[derive(Default)]
struct RouteCounters {
    backends: AtomicUsize,
    sessions: AtomicUsize,
}

type CountersHandle = Arc<RouteCounters>;

/// Spin a fake daemon that serves `/backends` (Lima-only matrix) and
/// `/sessions` (success), counting hits to each.
///
/// Returns the tempdir (so the socket survives the test) and the
/// counter handle the test asserts on.
async fn spawn_counting_daemon() -> (TempDir, String, CountersHandle) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("sandboxd.sock");
    let sock_str = sock_path.to_string_lossy().into_owned();
    let counters: CountersHandle = Arc::new(RouteCounters::default());

    let counters_for_routes = counters.clone();
    let app = Router::new()
        .route(
            "/backends",
            get(|State(state): State<CountersHandle>| async move {
                state.backends.fetch_add(1, Ordering::SeqCst);
                let infos = vec![sandbox_core::backend::BackendInfo {
                    kind: sandbox_core::BackendKind::Lima,
                    capabilities: sandbox_core::Capabilities::for_lima(),
                }];
                Json(serde_json::to_value(infos).expect("serialize"))
            }),
        )
        .route(
            "/sessions",
            post(
                |State(state): State<CountersHandle>, _body: String| async move {
                    state.sessions.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::CREATED, Json(fake_session_dto_json()))
                },
            ),
        )
        // The CLI's strict CLI ↔ daemon version-equality handshake
        // fires `GET /version` on every `send_request_with_timeout`
        // connection. Reporting our own CARGO_PKG_VERSION keeps the
        // gate passing so the `/backends` cache assertion fires
        // exactly once per create — the contract these tests pin.
        .route(
            "/version",
            get(|| async {
                (
                    StatusCode::OK,
                    Json(json!({ "version": env!("CARGO_PKG_VERSION") })),
                )
            }),
        )
        .with_state(counters_for_routes);

    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    // Let the spawned accept-loop register before the CLI dials in.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (tmp, sock_str, counters)
}

/// Minimal `SessionDto`-shaped JSON the CLI's `handle_response` can
/// parse without erroring out (the CLI's strict deserialise would
/// otherwise mask the test's real assertion).
fn fake_session_dto_json() -> Value {
    json!({
        "id": "abcdef012345",
        "name": "single-fetch-test",
        "state": "creating",
        "created_at": "2026-04-23T00:00:00Z",
        "updated_at": "2026-04-23T00:00:00Z",
        "config": {
            "cpus": 2,
            "memory_mb": 4096,
            "disk_gb": 20,
            "hardened": true,
        },
    })
}

/// Run the compiled `sandbox` binary against the fake daemon socket
/// and return the captured exit-status + stderr (stdout is discarded).
async fn run_sandbox(args: &[&str], socket: &str) -> (std::process::ExitStatus, String) {
    let binary = env!("CARGO_BIN_EXE_sandbox");
    let mut cmd = Command::new(binary);
    cmd.arg("--yes")
        .arg("--socket")
        .arg(socket)
        .args(args)
        // Pin XDG so a developer's local config does not perturb the
        // resolver. The CLI's config-loader treats a missing
        // `~/.config/sandboxd/config.json` as "no override", which is
        // what we want here — every tier above tier-5 must come from
        // the test, not the host.
        .env("XDG_CONFIG_HOME", "/nonexistent/xdg")
        // Strip any inherited SANDBOX_DEFAULT_BACKEND so tier-3 of
        // the resolver does not perturb the test.
        .env_remove("SANDBOX_DEFAULT_BACKEND")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let child = cmd.spawn().expect("spawn sandbox");
    let output = timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .expect("sandbox did not exit within 15s")
        .expect("collect output");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status, stderr)
}

#[tokio::test]
async fn integration_backends_cache_create_fires_exactly_one_get_backends() {
    let (_tmp, sock, counters) = spawn_counting_daemon().await;

    // A vanilla `sandbox create` (no `--lite`, no `--backend`) — the
    // resolver lands on Lima (tier 5), the preflight fetches /backends
    // once, validates, then sends one POST /sessions. Anything that
    // accidentally constructs a second `BackendsCache` (or refetches
    // mid-dispatch) shows up as `backends > 1`.
    let (status, stderr) = run_sandbox(&["create", "--name", "single-fetch"], &sock).await;
    assert!(
        status.success(),
        "create exited non-zero. stderr:\n{stderr}"
    );

    let backends_hits = counters.backends.load(Ordering::SeqCst);
    let sessions_hits = counters.sessions.load(Ordering::SeqCst);
    assert_eq!(
        backends_hits, 1,
        "spec § \"CLI learns capabilities via GET /backends\" mandates exactly one fetch per \
         invocation; observed {backends_hits}"
    );
    assert_eq!(
        sessions_hits, 1,
        "the create should have produced exactly one POST /sessions"
    );
}
