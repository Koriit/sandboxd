//! Integration test: `sandbox sync` dispatches to the host's `rsync`
//! with the backend's native shell as the remote-shell (`-e`)
//! transport — `limactl shell` for Lima, `docker exec -i` for
//! container. Sibling of `integration_cp_dispatch.rs`; they share the
//! same fake-daemon + tempdir-shim harness pattern.
//!
//! This test pins the end-to-end CLI surface so a future regression
//! cannot silently rearrange the rsync argv shape (e.g. drop
//! `--delete`, swap to `ssh -F lima-ssh-config` without justification,
//! or forget the `-i` on `docker exec`).
//!
//! The test stages a tempdir shim on `PATH` for `rsync` that records
//! its argv to a sentinel file. A fake `sandboxd` Unix-socket daemon
//! serves a `SessionDto` with the backend kind under test. We then
//! run the real `sandbox sync` binary and assert the shim was invoked
//! with the expected `(program, args)` tuple — that proves the
//! planner and dispatch glue both wired correctly without booting a
//! real VM, container, or pulling a real `rsync` over a real
//! transport.

use std::path::Path;
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

const TEST_SESSION_ID: &str = "abcdef012345";

/// Stand up a fake daemon serving `GET /sessions/{id}` -> `SessionDto`
/// with `backend = <backend>` and the canonical test session id.
async fn spawn_fake_daemon(backend: &str) -> (TempDir, String) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock_path = tmp.path().join("sandboxd.sock");
    let sock_str = sock_path.to_string_lossy().into_owned();
    let backend_owned = backend.to_string();

    let app = Router::new().route(
        "/sessions/{id}",
        get({
            move |_path: axum::extract::Path<String>| {
                let dto = session_dto_json(TEST_SESSION_ID, &backend_owned);
                async move { (StatusCode::OK, Json(dto)) }
            }
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
        "name": "sync-dispatch-test",
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
/// Optionally writes `stderr_msg` to stderr so error-clarity tests
/// can pin the message.
///
/// **Why `printf` and not `echo`.** rsync's argv legitimately
/// contains `-e` (the remote-shell flag); bash's builtin `echo`
/// silently consumes `-e` as its own "interpret escapes" switch,
/// producing an empty line and corrupting the recorded argv. The
/// cp-side shim happens to never see a `-e` so it can get away with
/// `echo` — we cannot. `printf '%s\n'` has no such trap.
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
/// prepended to `PATH` so the shim wins over any real `rsync`.
async fn run_sandbox_sync(
    args: &[&str],
    socket: &str,
    path_dir: &Path,
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
// Lima dispatch
// ---------------------------------------------------------------------------

/// `sandbox sync ./local-dir/ <session>:/remote-dir` (directory-source
/// upload, with trailing slash) against a Lima session invokes
/// `rsync -a --delete -e 'limactl shell' <src>/ sandbox-<id>:/remote`
/// and preserves the operator-supplied trailing slash idempotently —
/// the planner does not double it. rsync's contents-mirroring idiom
/// requires the trailing slash, and the CLI also auto-appends one
/// when the operator forgot it (covered by
/// `integration_sync_lima_upload_directory_source_appends_trailing_slash`).
#[tokio::test]
async fn integration_sync_lima_upload_invokes_rsync_with_limactl_shell_rsh() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "rsync", &record_file, 0, None);

    let (status, _stdout, stderr) = run_sandbox_sync(
        &[
            "./local/dir",
            "sync-dispatch-test:/home/agent/workspace/dir",
        ],
        &sock,
        shim_dir.path(),
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
            "limactl shell".to_string(),
            "./local/dir".to_string(),
            format!("sandbox-{TEST_SESSION_ID}:/home/agent/workspace/dir"),
        ],
        "recorded argv shape regressed"
    );
}

/// `sandbox sync <bare-dir-path-without-slash> <session>:/remote`
/// auto-appends a trailing slash to the host-side source when it's a
/// real directory, so rsync mirrors the *contents* of the source into
/// the destination (rsync's long-standing convention) instead of
/// landing them at `<dst>/<basename(src)>/...`. The planner stats the
/// host-side source at the call site in `handle_sync` so the planner
/// itself stays a pure function.
#[tokio::test]
async fn integration_sync_lima_upload_directory_source_appends_trailing_slash() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "rsync", &record_file, 0, None);

    let src_dir = tempfile::tempdir().expect("src dir");
    let src_path = src_dir.path().to_string_lossy().into_owned();
    // Sanity: the path we hand to the CLI does *not* already end in `/`.
    assert!(
        !src_path.ends_with('/'),
        "tempdir path unexpectedly ends with '/' — test would not exercise auto-append"
    );

    let (status, _stdout, stderr) = run_sandbox_sync(
        &[&src_path, "sync-dispatch-test:/home/agent/workspace/dir"],
        &sock,
        shim_dir.path(),
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
            "limactl shell".to_string(),
            expected_src,
            format!("sandbox-{TEST_SESSION_ID}:/home/agent/workspace/dir"),
        ],
        "directory-source upload must auto-append trailing slash for contents-mirror"
    );
}

/// Download direction on Lima: `sandbox sync <session>:/remote
/// ./local` swaps src and dst around the same baseline flag set.
#[tokio::test]
async fn integration_sync_lima_download_swaps_src_and_dst_args() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "rsync", &record_file, 0, None);

    let (status, _stdout, stderr) = run_sandbox_sync(
        &[
            "sync-dispatch-test:/home/agent/workspace/output",
            "./local/output",
        ],
        &sock,
        shim_dir.path(),
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
            "limactl shell".to_string(),
            format!("sandbox-{TEST_SESSION_ID}:/home/agent/workspace/output"),
            "./local/output".to_string(),
        ]
    );
}

// ---------------------------------------------------------------------------
// Container dispatch
// ---------------------------------------------------------------------------

/// `sandbox sync ./local <session>:/remote` against a container
/// session invokes `rsync -a --delete -e 'docker exec -i' ./local
/// sandbox-<id>:/remote`. The `-i` (and *no* `-t`) is load-bearing:
/// rsync's binary protocol breaks if a TTY is allocated.
#[tokio::test]
async fn integration_sync_container_upload_invokes_rsync_with_docker_exec_i_rsh() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("container").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "rsync", &record_file, 0, None);

    let (status, _stdout, stderr) = run_sandbox_sync(
        &[
            "./local/dir",
            "sync-dispatch-test:/home/agent/workspace/dir",
        ],
        &sock,
        shim_dir.path(),
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
            "docker exec -i".to_string(),
            "./local/dir".to_string(),
            format!("sandbox-{TEST_SESSION_ID}:/home/agent/workspace/dir"),
        ]
    );
}

/// Download direction on the container backend.
#[tokio::test]
async fn integration_sync_container_download_swaps_src_and_dst_args() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("container").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "rsync", &record_file, 0, None);

    let (status, _stdout, stderr) = run_sandbox_sync(
        &[
            "sync-dispatch-test:/home/agent/workspace/output",
            "./local/output",
        ],
        &sock,
        shim_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox sync container download should succeed; status={:?}, stderr=\n{stderr}",
        status.code()
    );

    let argv = read_recorded_argv(&record_file);
    assert_eq!(
        argv,
        vec![
            "-a".to_string(),
            "--delete".to_string(),
            "-e".to_string(),
            "docker exec -i".to_string(),
            format!("sandbox-{TEST_SESSION_ID}:/home/agent/workspace/output"),
            "./local/output".to_string(),
        ]
    );
}

// ---------------------------------------------------------------------------
// Error propagation — native rsync style
// ---------------------------------------------------------------------------

/// When rsync exits non-zero (e.g. source-not-found), the CLI
/// propagates the exit code unchanged and forwards rsync's stderr
/// verbatim. Mirrors the cp-side guarantee: callers see the same
/// diagnostic they would get from `rsync` directly.
#[tokio::test]
async fn integration_sync_lima_propagates_native_error_and_exit_code() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    // rsync exits 23 ("partial transfer due to error") for missing
    // source files, with a recognizable stderr line. We assert on the
    // exit code passing through and the stderr line surviving.
    install_shim(
        shim_dir.path(),
        "rsync",
        &record_file,
        23,
        Some("rsync: link_stat \"./missing/dir\" failed: No such file or directory (2)"),
    );

    let (status, _stdout, stderr) = run_sandbox_sync(
        &[
            "./missing/dir",
            "sync-dispatch-test:/home/agent/workspace/dir",
        ],
        &sock,
        shim_dir.path(),
    )
    .await;

    assert_eq!(
        status.code(),
        Some(23),
        "exit code must match the shim's (rsync's) exit"
    );
    assert!(
        stderr.contains("rsync: link_stat") && stderr.contains("No such file or directory"),
        "native stderr must be propagated verbatim; got:\n{stderr}"
    );
}

/// Both source and destination prefixed with `session:` is a misuse;
/// the CLI rejects it locally before dispatching anywhere. Mirrors
/// the cp-side rejection so the two commands stay symmetric.
#[tokio::test]
async fn integration_sync_rejects_both_sides_remote() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    // No shim binaries needed — we should never reach a subprocess.

    let (status, _stdout, stderr) =
        run_sandbox_sync(&["a:foo", "b:bar"], &sock, shim_dir.path()).await;

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

/// Trailing rsync flags (everything after `--`) are spliced between
/// the baseline `-a --delete -e <shell>` and the source/destination
/// operands, matching rsync's `[OPTION...] SRC... [DEST]` synopsis.
/// Pins both the layout and the literal preservation of multi-token
/// flag values like `--exclude '*.log'`.
#[tokio::test]
async fn integration_sync_lima_passes_through_trailing_rsync_flags() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "rsync", &record_file, 0, None);

    let (status, _stdout, stderr) = run_sandbox_sync(
        &[
            "./local/dir",
            "sync-dispatch-test:/home/agent/workspace/dir",
            "--",
            "--exclude",
            "*.log",
            "--info=progress2",
        ],
        &sock,
        shim_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox sync with trailing flags should succeed; status={:?}, stderr=\n{stderr}",
        status.code()
    );

    let argv = read_recorded_argv(&record_file);
    assert_eq!(
        argv,
        vec![
            "-a".to_string(),
            "--delete".to_string(),
            "-e".to_string(),
            "limactl shell".to_string(),
            "--exclude".to_string(),
            "*.log".to_string(),
            "--info=progress2".to_string(),
            "./local/dir".to_string(),
            format!("sandbox-{TEST_SESSION_ID}:/home/agent/workspace/dir"),
        ],
        "trailing rsync flags must splice between baseline and operands"
    );
}

/// Neither side prefixed with `session:` is also a misuse; the CLI
/// emits the documented sync-shaped usage hint (referring to dirs,
/// not files like cp does).
#[tokio::test]
async fn integration_sync_rejects_no_remote_side() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");

    let (status, _stdout, stderr) =
        run_sandbox_sync(&["./local/a", "./local/b"], &sock, shim_dir.path()).await;

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
    // The sync-side hint references *directories*, not files. Pin
    // that the message wording is sync-shaped, not a verbatim copy
    // of the cp message.
    assert!(
        stderr.contains("sandbox sync"),
        "stderr should mention `sandbox sync` usage, got:\n{stderr}"
    );
}
