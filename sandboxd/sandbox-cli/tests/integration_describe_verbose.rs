//! Integration test: `sandbox describe -v` renders a Capabilities
//! block per session, fetched from the daemon's `/backends` endpoint.
//!
//! Spec § "sandbox inspect → -v view" (lines 769-775) — the human-
//! readable detail view (the CLI's `describe` command, see handoff
//! § "Spec/CLI nomenclature discrepancy") under `-v` shows the full
//! capability matrix for each session's backend.
//!
//! This test pins the end-to-end wiring: the CLI subprocess fetches
//! `/backends`, threads the matching `Capabilities` value through
//! describe rendering, and emits a `Capabilities:` block on stdout
//! containing several distinguishing fields. Without `-v` no
//! `Capabilities` block appears.

use std::process::Stdio;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::get;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::time::timeout;

async fn spawn_describe_daemon(session_id: &str, backend: &str) -> (TempDir, String) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("sandboxd.sock");
    let sock_str = sock_path.to_string_lossy().into_owned();
    let session_id_owned = session_id.to_string();
    let backend_owned = backend.to_string();

    let app = Router::new()
        .route(
            "/backends",
            get(|| async {
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
            // Single-session lookup endpoint that `describe` fans out
            // to. The path is parameterised over `session_id` so each
            // test can drive a session of either backend.
            "/sessions/{id}",
            get({
                move |_path: axum::extract::Path<String>| {
                    let dto = session_dto_json(&session_id_owned, &backend_owned);
                    async move { (StatusCode::OK, Json(dto)) }
                }
            }),
        )
        // The CLI's `send_request_with_timeout` issues `GET /version`
        // on every connection (strict CLI ↔ daemon version-equality
        // rule). Reporting our own CARGO_PKG_VERSION keeps the
        // handshake passing so the describe-verbose rendering reaches
        // both the per-session lookup and the capability matrix.
        .route(
            "/version",
            get(|| async {
                (
                    StatusCode::OK,
                    Json(json!({ "version": env!("CARGO_PKG_VERSION") })),
                )
            }),
        );

    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    (tmp, sock_str)
}

fn session_dto_json(id: &str, backend: &str) -> Value {
    json!({
        "id": id,
        "name": "describe-test",
        "state": "running",
        "created_at": "2026-04-23T00:00:00Z",
        "updated_at": "2026-04-23T00:00:00Z",
        "config": {
            "cpus": 2,
            "memory_mb": 4096,
            "disk_gb": 20,
            "hardened": true,
        },
        "guest_agent_status": "connected",
        "gateway_status": "running",
        "backend": backend,
    })
}

async fn run_sandbox(args: &[&str], socket: &str) -> (std::process::ExitStatus, String, String) {
    let binary = env!("CARGO_BIN_EXE_sandbox");
    let mut cmd = Command::new(binary);
    cmd.arg("--yes")
        .arg("--socket")
        .arg(socket)
        .args(args)
        .env("XDG_CONFIG_HOME", "/nonexistent/xdg")
        .env_remove("SANDBOX_DEFAULT_BACKEND")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = cmd.spawn().expect("spawn sandbox");
    let output = timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .expect("sandbox did not exit within 15s")
        .expect("collect output");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status, stdout, stderr)
}

/// `sandbox describe <id>` (no `-v`) shows backend in the Session
/// block and does NOT emit a Capabilities block.
#[tokio::test]
async fn integration_describe_default_view_shows_backend_no_caps_block() {
    let (_tmp, sock) = spawn_describe_daemon("aaaabbbbcccc", "container").await;
    let (status, stdout, stderr) = run_sandbox(&["describe", "aaaabbbbcccc"], &sock).await;

    assert!(
        status.success(),
        "describe should succeed; got {:?}\nstderr:\n{stderr}",
        status.code()
    );
    assert!(
        stdout.contains("Backend:      container"),
        "default describe must show Backend line, got stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("Capabilities:"),
        "default describe must NOT include a Capabilities block, got stdout:\n{stdout}"
    );
}

/// `sandbox describe -v <id>` for a Lima session renders a
/// Capabilities block with several pinned distinguishing fields.
#[tokio::test]
async fn integration_describe_verbose_lima_renders_capabilities() {
    let (_tmp, sock) = spawn_describe_daemon("aaaabbbbcccc", "lima").await;
    let (status, stdout, stderr) = run_sandbox(&["describe", "-v", "aaaabbbbcccc"], &sock).await;

    assert!(
        status.success(),
        "describe -v should succeed; got {:?}\nstderr:\n{stderr}",
        status.code()
    );
    assert!(
        stdout.contains("Capabilities:"),
        "verbose describe must include Capabilities block, got stdout:\n{stdout}"
    );
    // Pin the most distinguishing Lima fields. Three independent
    // fields catch most accidental shape regressions without
    // brittle-ifying every label byte.
    assert!(
        stdout.contains("isolation:            vm"),
        "Lima isolation must serialize as `vm`, got stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("hardening_flag:       true"),
        "Lima honours hardening, got stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("workspace_modes:      shared, clone"),
        "Lima advertises both workspace modes, got stdout:\n{stdout}"
    );
}

/// `sandbox describe -v <id>` for a Container session renders the
/// same block with container-shaped values — distinct from Lima so
/// the wiring fetched the right capability matrix.
#[tokio::test]
async fn integration_describe_verbose_container_renders_capabilities() {
    let (_tmp, sock) = spawn_describe_daemon("ddddeeeeffff", "container").await;
    let (status, stdout, stderr) = run_sandbox(&["describe", "-v", "ddddeeeeffff"], &sock).await;

    assert!(
        status.success(),
        "describe -v should succeed; got {:?}\nstderr:\n{stderr}",
        status.code()
    );
    assert!(
        stdout.contains("Capabilities:"),
        "verbose describe must include Capabilities block, got stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("isolation:            container"),
        "Container isolation must serialize as `container`, got stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("hardening_flag:       false"),
        "Container does not honour hardening, got stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("workspace_modes:      -"),
        "empty workspace_modes must render as `-`, got stdout:\n{stdout}"
    );
}
