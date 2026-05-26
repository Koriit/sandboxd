//! Integration test: `sandbox sync` dispatches to `rsync -e ssh
//! sandbox-<id>:…` via the daemon-mediated SSH proxy.
//!
//! Under M18-S6 the per-backend remote-shell selection
//! (`limactl shell` / `docker exec -i`) is collapsed into the
//! `sandbox-<id>` SSH alias the operator's `~/.ssh/config` (via our
//! managed `Include` block) resolves through `ProxyCommand sandbox
//! proxy <id>`. This test pins the new dispatch surface:
//!
//! * The CLI sources its ssh-config from
//!   `GET /sessions/{id}/ssh-config`.
//! * The CLI invokes `rsync` with the baseline flag set
//!   (`-a --delete -e ssh`) and the `sandbox-<id>:<path>` remote spec.
//! * Direction (upload vs download) drives src/dst ordering.
//! * Trailing-slash auto-append on directory uploads survives the
//!   rewrite.
//! * Pass-through rsync flags splice between baseline and operands.
//! * Both-remote and neither-remote argument shapes are rejected.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::get;
use sandbox_core::render_ssh_config_block;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::time::timeout;

mod common;

const TEST_SESSION_ID: &str = "abcdef012345";
const TEST_SESSION_NAME: &str = "sync-dispatch-test";

/// Stand up a fake daemon serving the two endpoints the sync flow
/// touches: `GET /sessions/{id}` and
/// `GET /sessions/{id}/ssh-config`.
async fn spawn_fake_daemon(backend: &str) -> (TempDir, String) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("sandboxd.sock");
    let sock_str = sock_path.to_string_lossy().into_owned();
    let backend_owned = backend.to_string();

    let app = Router::new()
        .route(
            "/sessions/{id}",
            get({
                move |_path: axum::extract::Path<String>| {
                    let dto = session_dto_json(TEST_SESSION_ID, &backend_owned);
                    async move { (StatusCode::OK, Json(dto)) }
                }
            }),
        )
        .route(
            "/sessions/{id}/ssh-config",
            get({
                move |_path: axum::extract::Path<String>| async move {
                    let dto = json!({
                        "config": render_ssh_config_block(TEST_SESSION_ID),
                        "private_key": format!(
                            "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-bytes-for-{TEST_SESSION_ID}\n-----END OPENSSH PRIVATE KEY-----\n"
                        ),
                    });
                    (StatusCode::OK, Json(dto))
                }
            }),
        )
        // Strict CLI ↔ daemon version-equality handshake.
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
    common::wait_for_daemon_ready(&sock_path, "/version")
        .await
        .expect("fake daemon failed to become ready");

    (tmp, sock_str)
}

fn session_dto_json(id: &str, backend: &str) -> Value {
    json!({
        "id": id,
        "name": TEST_SESSION_NAME,
        "state": "running",
        "created_at": "2026-04-25T00:00:00Z",
        "updated_at": "2026-04-25T00:00:00Z",
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

/// Write a shim script at `dir/<name>` that records its argv (one
/// argument per line) to `record_file` and exits with `exit_code`.
///
/// **Why `printf` and not `echo`.** rsync's argv legitimately
/// contains `-e` (the remote-shell flag); bash's builtin `echo`
/// silently consumes `-e` as its own "interpret escapes" switch,
/// producing an empty line and corrupting the recorded argv.
fn install_shim(
    dir: &Path,
    name: &str,
    record_file: &Path,
    exit_code: i32,
    stderr_msg: Option<&str>,
) {
    let shim_path = dir.join(name);
    let stderr_line = stderr_msg
        .map(|m| format!("printf '%s\\n' '{m}' >&2\n"))
        .unwrap_or_default();
    let body = format!(
        "#!/bin/bash\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> '{record}'; done\n{stderr}exit {code}\n",
        record = record_file.display(),
        stderr = stderr_line,
        code = exit_code
    );
    std::fs::write(&shim_path, body).expect("write shim");
    let mut perms = std::fs::metadata(&shim_path)
        .expect("shim metadata")
        .permissions();
    use std::os::unix::fs::PermissionsExt as _;
    perms.set_mode(0o755);
    std::fs::set_permissions(&shim_path, perms).expect("chmod shim");
}

/// Run `sandbox sync` against the fake daemon with `path_dir`
/// prepended to `PATH` (so the `rsync` shim wins) and `$HOME` pointed
/// at a fresh tempdir (so the CLI's `~/.ssh/sandbox/` mutations land
/// in a hermetic location).
async fn run_sandbox_sync(
    args: &[&str],
    socket: &str,
    path_dir: &Path,
    home_dir: &Path,
) -> (std::process::ExitStatus, String, String) {
    let binary = env!("CARGO_BIN_EXE_sandbox");
    let existing_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{existing_path}", path_dir.display());

    let mut cmd = Command::new(binary);
    cmd.arg("--yes")
        .arg("--socket")
        .arg(socket)
        .arg("sync")
        .args(args)
        .env("PATH", &new_path)
        .env("HOME", home_dir)
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

fn read_recorded_argv(record_file: &Path) -> Vec<String> {
    let raw = std::fs::read_to_string(record_file).unwrap_or_default();
    raw.lines().map(|l| l.to_string()).collect()
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

/// `sandbox sync ./local-dir <session>:/remote` invokes
/// `rsync -a --delete -e ssh <src> sandbox-<id>:<remote>` against the
/// canonical alias. Backend-independent — the daemon-mediated proxy
/// abstracts over the underlying VM/container.
#[tokio::test]
async fn integration_sync_upload_invokes_rsync_against_sandbox_alias() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "rsync", &record_file, 0, None);
    let home_dir = tempfile::tempdir().expect("home dir");

    let (status, _stdout, stderr) = run_sandbox_sync(
        &[
            "./local/dir",
            &format!("{TEST_SESSION_NAME}:/home/sandbox/workspace/dir"),
        ],
        &sock,
        shim_dir.path(),
        home_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox sync should propagate shim exit 0; status={:?}, stderr=\n{stderr}",
        status.code()
    );

    let argv = read_recorded_argv(&record_file);
    assert_eq!(
        argv,
        vec![
            "-a".to_string(),
            "--delete".to_string(),
            "-e".to_string(),
            "ssh".to_string(),
            "./local/dir".to_string(),
            format!("sandbox-{TEST_SESSION_ID}:/home/sandbox/workspace/dir"),
        ],
        "rsync argv must use bare `ssh` transport against the daemon-issued sandbox-<id> alias"
    );
}

/// Directory-source upload without a trailing slash: the dispatch
/// site stats the host path and the planner auto-appends `/` so
/// rsync mirrors *contents* (rsync's long-standing idiom). Pins the
/// historical `sandbox sync ./src <session>:./dst` UX through the
/// rewrite.
#[tokio::test]
async fn integration_sync_upload_directory_source_appends_trailing_slash() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "rsync", &record_file, 0, None);
    let home_dir = tempfile::tempdir().expect("home dir");

    let src_dir = tempfile::tempdir().expect("src dir");
    let src_path = src_dir.path().to_string_lossy().into_owned();
    assert!(
        !src_path.ends_with('/'),
        "tempdir path unexpectedly ends with '/' — test would not exercise auto-append"
    );

    let (status, _stdout, stderr) = run_sandbox_sync(
        &[
            &src_path,
            &format!("{TEST_SESSION_NAME}:/home/sandbox/workspace/dir"),
        ],
        &sock,
        shim_dir.path(),
        home_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox sync should propagate shim exit 0; status={:?}, stderr=\n{stderr}",
        status.code()
    );

    let expected_src = format!("{src_path}/");
    let argv = read_recorded_argv(&record_file);
    assert_eq!(
        argv,
        vec![
            "-a".to_string(),
            "--delete".to_string(),
            "-e".to_string(),
            "ssh".to_string(),
            expected_src,
            format!("sandbox-{TEST_SESSION_ID}:/home/sandbox/workspace/dir"),
        ],
        "directory-source upload must auto-append trailing slash for contents-mirror"
    );
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

/// `sandbox sync <session>:/remote ./local` swaps src/dst around the
/// same baseline flag set. The host-side path stays unchanged
/// (downloads don't remote-stat).
#[tokio::test]
async fn integration_sync_download_swaps_src_and_dst_args() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("container").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "rsync", &record_file, 0, None);
    let home_dir = tempfile::tempdir().expect("home dir");

    let (status, _stdout, stderr) = run_sandbox_sync(
        &[
            &format!("{TEST_SESSION_NAME}:/home/sandbox/workspace/output"),
            "./local/output",
        ],
        &sock,
        shim_dir.path(),
        home_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox sync download should succeed; status={:?}, stderr=\n{stderr}",
        status.code()
    );

    let argv = read_recorded_argv(&record_file);
    assert_eq!(
        argv,
        vec![
            "-a".to_string(),
            "--delete".to_string(),
            "-e".to_string(),
            "ssh".to_string(),
            format!("sandbox-{TEST_SESSION_ID}:/home/sandbox/workspace/output"),
            "./local/output".to_string(),
        ]
    );
}

// ---------------------------------------------------------------------------
// Pass-through args
// ---------------------------------------------------------------------------

/// Operator-supplied rsync flags after `--` splice between the
/// baseline (`-a --delete -e ssh`) and the source/destination
/// operands. rsync's synopsis is `rsync [OPTION...] SRC... [DEST]`,
/// so trailing-position flags would be treated as additional sources.
#[tokio::test]
async fn integration_sync_pass_through_args_splice_between_baseline_and_operands() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "rsync", &record_file, 0, None);
    let home_dir = tempfile::tempdir().expect("home dir");

    let (status, _stdout, stderr) = run_sandbox_sync(
        &[
            "./local/src",
            &format!("{TEST_SESSION_NAME}:/home/sandbox/workspace/dst"),
            "--",
            "--exclude",
            "*.log",
            "--bwlimit=1m",
        ],
        &sock,
        shim_dir.path(),
        home_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox sync should propagate shim exit 0; status={:?}, stderr=\n{stderr}",
        status.code()
    );

    let argv = read_recorded_argv(&record_file);
    assert_eq!(
        argv,
        vec![
            "-a".to_string(),
            "--delete".to_string(),
            "-e".to_string(),
            "ssh".to_string(),
            "--exclude".to_string(),
            "*.log".to_string(),
            "--bwlimit=1m".to_string(),
            "./local/src".to_string(),
            format!("sandbox-{TEST_SESSION_ID}:/home/sandbox/workspace/dst"),
        ],
        "pass-through args must splice between baseline and operands"
    );
}

// ---------------------------------------------------------------------------
// Per-session entry side-effect
// ---------------------------------------------------------------------------

/// After a successful dispatch the per-session SSH config + key
/// files MUST be on disk under `$HOME/.ssh/sandbox/`. Mirrors the
/// `integration_cp_writes_per_session_entry_under_managed_home`
/// invariant for cp.
#[tokio::test]
async fn integration_sync_writes_per_session_entry_under_managed_home() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "rsync", &record_file, 0, None);
    let home_dir = tempfile::tempdir().expect("home dir");

    let (status, _stdout, stderr) = run_sandbox_sync(
        &[
            "./local/src",
            &format!("{TEST_SESSION_NAME}:/home/sandbox/workspace/dst"),
        ],
        &sock,
        shim_dir.path(),
        home_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox sync must succeed for entry to be written; status={:?}, stderr=\n{stderr}",
        status.code()
    );

    let sandbox_dir = home_dir.path().join(".ssh").join("sandbox");
    let cfg = sandbox_dir.join(format!("sandbox-{TEST_SESSION_ID}"));
    let key = sandbox_dir.join(format!("sandbox-{TEST_SESSION_ID}.key"));
    assert!(cfg.exists(), "per-session config must be on disk");
    assert!(key.exists(), "per-session key must be on disk");
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

/// Both source and destination prefixed with `session:` is a misuse.
#[tokio::test]
async fn integration_sync_rejects_both_sides_remote() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let home_dir = tempfile::tempdir().expect("home dir");

    let (status, _stdout, stderr) = run_sandbox_sync(
        &["a:foo", "b:bar"],
        &sock,
        shim_dir.path(),
        home_dir.path(),
    )
    .await;

    assert_eq!(
        status.code(),
        Some(1),
        "two-remote misuse must exit 1, got {:?}\nstderr:\n{stderr}",
        status.code()
    );
    assert!(
        stderr.contains("both source and destination cannot be remote"),
        "stderr must explain the two-remote misuse, got:\n{stderr}"
    );
}

/// Neither side prefixed with `session:` is also a misuse.
#[tokio::test]
async fn integration_sync_rejects_no_remote_side() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let home_dir = tempfile::tempdir().expect("home dir");

    let (status, _stdout, stderr) = run_sandbox_sync(
        &["./local/a", "./local/b"],
        &sock,
        shim_dir.path(),
        home_dir.path(),
    )
    .await;

    assert_eq!(
        status.code(),
        Some(1),
        "no-remote misuse must exit 1, got {:?}\nstderr:\n{stderr}",
        status.code()
    );
    assert!(
        stderr.contains("one of source or destination must be a remote path"),
        "stderr must include the usage hint, got:\n{stderr}"
    );
}
