//! Integration tests: `sandbox create --no-cache` is rejected
//! client-side when the resolved backend is the container backend.
//!
//! Spec § "CLI & UX → `sandbox create --no-cache` is forbidden on
//! container" mandates that the CLI surface this mismatch with exit
//! code 2 (clap-style misuse) *before* the daemon is contacted, so the
//! operator never burns a Unix-socket roundtrip on a guaranteed-to-fail
//! request. The three tests below pin the three reachable code paths:
//!
//! - `--lite --no-cache` — the `--lite` sugar resolves to container.
//! - `--backend container --no-cache` — explicit selector.
//! - `--backend lima --no-cache` — the negative case: Lima permits
//!   `--no-cache`, so the CLI must hand the request through to the
//!   fake daemon, which records the POST.
//!
//! The fake daemon serves a Lima+Container `/backends` matrix so the
//! CLI's preflight finds whichever backend the test selected. In the
//! rejection cases the CLI exits before sending `POST /sessions`, so
//! the daemon's session counter stays at zero — that double-checks the
//! "before the daemon is contacted" half of the spec contract.

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

type SessionsCounter = Arc<AtomicUsize>;

/// Spin a fake daemon serving `/backends` (Lima + Container) and
/// `/sessions` (success). Returns the counter so the test can assert
/// rejection paths never reach the daemon.
async fn spawn_dual_backend_daemon() -> (TempDir, String, SessionsCounter) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("sandboxd.sock");
    let sock_str = sock_path.to_string_lossy().into_owned();
    let counter: SessionsCounter = Arc::new(AtomicUsize::new(0));

    let counter_clone = counter.clone();
    let app = Router::new()
        .route(
            "/backends",
            get(|| async {
                // The /backends payload is the wire-shape the daemon
                // emits — `Vec<BackendInfo>` serialised as JSON. We
                // hand-roll it instead of constructing
                // [`sandbox_core::Capabilities`] directly because the
                // struct is `#[non_exhaustive]` and external callers
                // (this test) cannot brace-construct it. Hard-coding
                // the JSON keeps the test independent of any
                // sandbox-core constructor reshape.
                //
                // The container capability matrix mirrors
                // `capabilities_for_container()` in
                // sandbox-core/backend/container.rs: no nested-virt,
                // no privileged ops, no raw network, no hardening
                // flag, no per-session no-cache, and an EMPTY
                // workspace-modes set (Phase 1B intentionally rejects
                // both `Shared` and `Clone` until M11-S4/S5 wire the
                // bind-mount plumbing).
                Json(json!([
                    {
                        "kind": "lima",
                        "capabilities": {
                            "kind": "lima",
                            "isolation": "vm",
                            "nested_virt": true,
                            "privileged_ops": true,
                            "raw_network": true,
                            "hardening_flag": true,
                            "per_session_no_cache": true,
                            "workspace_modes": ["shared", "clone"]
                        }
                    },
                    {
                        "kind": "container",
                        "capabilities": {
                            "kind": "container",
                            "isolation": "container",
                            "nested_virt": false,
                            "privileged_ops": false,
                            "raw_network": false,
                            "hardening_flag": false,
                            "per_session_no_cache": false,
                            "workspace_modes": []
                        }
                    }
                ]))
            }),
        )
        .route(
            "/sessions",
            post(
                |State(state): State<SessionsCounter>, _body: String| async move {
                    state.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::CREATED, Json(fake_session_dto_json()))
                },
            ),
        )
        .with_state(counter_clone);

    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    // Let the spawned accept-loop register before the CLI dials in.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (tmp, sock_str, counter)
}

fn fake_session_dto_json() -> Value {
    json!({
        "id": "abcdef012345",
        "name": "no-cache-test",
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

async fn run_sandbox(args: &[&str], socket: &str) -> (std::process::ExitStatus, String) {
    let binary = env!("CARGO_BIN_EXE_sandbox");
    let mut cmd = Command::new(binary);
    cmd.arg("--yes")
        .arg("--socket")
        .arg(socket)
        .args(args)
        .env("XDG_CONFIG_HOME", "/nonexistent/xdg")
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
async fn integration_no_cache_rejection_with_lite_flag_exits_two() {
    let (_tmp, sock, sessions) = spawn_dual_backend_daemon().await;

    let (status, stderr) = run_sandbox(
        &["create", "--lite", "--no-cache", "--name", "lite-nc"],
        &sock,
    )
    .await;

    assert_eq!(
        status.code(),
        Some(2),
        "spec mandates exit code 2 (misuse) for --no-cache on container backend; \
         got {:?}\nstderr:\n{stderr}",
        status.code()
    );
    assert_eq!(
        sessions.load(Ordering::SeqCst),
        0,
        "rejection must run BEFORE the daemon is contacted: no POST /sessions allowed"
    );
    // The user-visible error must clearly name `--no-cache` so the
    // operator can find the offending flag at a glance. The exact
    // wording is pinned by the byte-equality unit test on
    // `render_no_cache_rejection_for_container`; here we only sanity-
    // check the most distinctive token.
    assert!(
        stderr.contains("--no-cache"),
        "stderr should mention the offending flag, got:\n{stderr}"
    );
}

#[tokio::test]
async fn integration_no_cache_rejection_with_backend_container_exits_two() {
    let (_tmp, sock, sessions) = spawn_dual_backend_daemon().await;

    let (status, stderr) = run_sandbox(
        &[
            "create",
            "--backend",
            "container",
            "--no-cache",
            "--name",
            "ctr-nc",
        ],
        &sock,
    )
    .await;

    assert_eq!(
        status.code(),
        Some(2),
        "spec mandates exit code 2 (misuse) for --no-cache on container backend; \
         got {:?}\nstderr:\n{stderr}",
        status.code()
    );
    assert_eq!(
        sessions.load(Ordering::SeqCst),
        0,
        "rejection must run BEFORE the daemon is contacted: no POST /sessions allowed"
    );
}

#[tokio::test]
async fn integration_no_cache_with_backend_lima_passes_through_to_daemon() {
    let (_tmp, sock, sessions) = spawn_dual_backend_daemon().await;

    let (status, stderr) = run_sandbox(
        &[
            "create",
            "--backend",
            "lima",
            "--no-cache",
            "--name",
            "lima-nc",
        ],
        &sock,
    )
    .await;

    assert!(
        status.success(),
        "Lima permits --no-cache; CLI must hand the request through. status={:?}\nstderr:\n{stderr}",
        status.code()
    );
    assert_eq!(
        sessions.load(Ordering::SeqCst),
        1,
        "exactly one POST /sessions should reach the daemon for the Lima case"
    );
}
