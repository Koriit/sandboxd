//! Integration tests: the per-create isolation warning fires for the
//! container backend (and only the container backend).
//!
//! Spec § "Isolation warning" (lines 751-762) mandates that **every**
//! `--lite` / `--backend container` create prints a fixed two-line
//! warning to stderr **before** the daemon round-trip, and that
//! `--backend lima` does **not** print anything. The byte-equality
//! contract for the warning text itself is pinned by the unit test in
//! `backend.rs`; this test exercises the wire-up — that the warning
//! actually emerges on stderr from a real subprocess invocation, and
//! that Lima creates stay silent.
//!
//! Reuses the dual-backend fake-daemon scaffold from
//! `integration_no_cache_rejection.rs` (Phase 4A) so the test stays
//! hermetic — no real daemon, no Docker, no Lima.

use std::process::Stdio;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::time::timeout;

/// Spin a fake daemon serving `/backends` (Lima + Container) and
/// `/sessions` (success). The warning is emitted client-side before
/// the daemon is contacted, but `/sessions` must still answer so the
/// CLI exits 0 on the Lima passthrough case.
async fn spawn_dual_backend_daemon() -> (TempDir, String) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("sandboxd.sock");
    let sock_str = sock_path.to_string_lossy().into_owned();

    let app = Router::new()
        .route(
            "/backends",
            get(|| async {
                // Hand-rolled JSON mirrors `capabilities_for_container`
                // and `Capabilities::for_lima` — see
                // integration_no_cache_rejection.rs for the same trick.
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
                |_body: String| async move { (StatusCode::CREATED, Json(fake_session_dto_json())) },
            ),
        );

    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    (tmp, sock_str)
}

fn fake_session_dto_json() -> Value {
    json!({
        "id": "abcdef012345",
        "name": "iso-test",
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

/// `sandbox create --lite` emits the spec's exact two-line warning to
/// stderr. Pin both lines (including the em dash and the six-space
/// indent on line 2) — this is the wire-format contract.
#[tokio::test]
async fn integration_isolation_warning_fires_for_lite_flag() {
    let (_tmp, sock) = spawn_dual_backend_daemon().await;

    let (status, stderr) = run_sandbox(&["create", "--lite", "--name", "lite-warn"], &sock).await;

    assert!(
        status.success(),
        "create --lite should succeed against the fake daemon; got {:?}\nstderr:\n{stderr}",
        status.code()
    );
    // The warning is the first two lines of stderr — assert the exact
    // bytes per spec § "Isolation warning". A subsequent unit test in
    // backend.rs pins this same string at the renderer level; the
    // duplication here verifies the wiring (eprint! reaches the
    // subprocess's stderr) without re-pinning the bytes a third time.
    let expected = "lite: container-backed session \u{2014} container-level isolation only (not VM-grade)\n      see docs/lite.md for the trade-off details\n";
    assert!(
        stderr.starts_with(expected),
        "stderr must begin with the spec warning bytes; got:\n{stderr}"
    );
}

/// `sandbox create --backend container` also emits the warning — it
/// is per-create, not gated on the `--lite` sugar specifically.
#[tokio::test]
async fn integration_isolation_warning_fires_for_backend_container() {
    let (_tmp, sock) = spawn_dual_backend_daemon().await;

    let (status, stderr) = run_sandbox(
        &["create", "--backend", "container", "--name", "ctr-warn"],
        &sock,
    )
    .await;

    assert!(
        status.success(),
        "create --backend container should succeed; got {:?}\nstderr:\n{stderr}",
        status.code()
    );
    assert!(
        stderr.contains("lite: container-backed session"),
        "stderr must contain the warning, got:\n{stderr}"
    );
    assert!(
        stderr.contains("see docs/lite.md for the trade-off details"),
        "stderr must include the docs reference line, got:\n{stderr}"
    );
}

/// `sandbox create --backend lima` must NOT emit the warning — it is
/// container-specific. The negative case is the one that protects the
/// spec invariant from drifting into "always print".
#[tokio::test]
async fn integration_isolation_warning_silent_for_backend_lima() {
    let (_tmp, sock) = spawn_dual_backend_daemon().await;

    let (status, stderr) = run_sandbox(
        &["create", "--backend", "lima", "--name", "lima-no-warn"],
        &sock,
    )
    .await;

    assert!(
        status.success(),
        "create --backend lima should succeed; got {:?}\nstderr:\n{stderr}",
        status.code()
    );
    assert!(
        !stderr.contains("container-backed session"),
        "Lima must NOT emit the lite isolation warning, got stderr:\n{stderr}"
    );
}
