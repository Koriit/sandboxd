//! Integration test: `sandbox cp` dispatches to the backend's native
//! copy tool (`limactl cp` for Lima, `docker cp` for container).
//!
//! `sandbox cp` dispatches directly to the backend's native copy
//! tool rather than relaying bytes through the daemon. This test
//! pins the end-to-end CLI surface so a regression cannot silently
//! reintroduce a daemon-relayed pump or wire the wrong argument
//! shape.
//!
//! The test stages a tempdir shim on `PATH` for both `limactl` and
//! `docker` that records its argv to a sentinel file. A fake
//! `sandboxd` Unix-socket daemon serves a `SessionDto` with the
//! backend kind under test. We then run the real `sandbox cp` binary
//! and assert the shim was invoked with the expected `(program, args)`
//! tuple — that proves the planner and dispatch glue both wired
//! correctly without booting a real VM or container runtime.

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
        "name": "cp-dispatch-test",
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
/// Optionally writes `stderr_msg` to stderr so error-clarity tests can
/// pin the message.
fn install_shim(
    dir: &Path,
    name: &str,
    record_file: &Path,
    exit_code: i32,
    stderr_msg: Option<&str>,
) {
    let shim_path = dir.join(name);
    // The shim writes one arg per line so the assertion side can read
    // the recorded argv unambiguously even when paths contain spaces
    // (none of the test paths do, but pinning the format keeps the
    // protocol explicit).
    let stderr_line = stderr_msg
        .map(|m| format!("echo '{m}' >&2\n"))
        .unwrap_or_default();
    let body = format!(
        "#!/bin/bash\nfor a in \"$@\"; do echo \"$a\" >> '{record}'; done\n{stderr}exit {code}\n",
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

/// Run `sandbox cp` against the fake daemon with `path_dir` prepended
/// to `PATH` so the shim wins over any real `limactl` / `docker`.
async fn run_sandbox_cp(
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
        .arg("cp")
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

/// Read the recorded argv lines from the shim's sentinel file.
fn read_recorded_argv(record_file: &Path) -> Vec<String> {
    let raw = std::fs::read_to_string(record_file).unwrap_or_default();
    raw.lines().map(|l| l.to_string()).collect()
}

// ---------------------------------------------------------------------------
// Lima dispatch
// ---------------------------------------------------------------------------

/// `sandbox cp ./local-file <session>:/remote-file` (file-source
/// upload) against a Lima session invokes `limactl cp <src> <dst>` —
/// **without** `-r`. Lima 2.x's `limactl cp` is rsync-backed: passing
/// `-r` against a regular-file source aborts with rsync exit code 23
/// (rsync tries to `chdir` into the source, hits ENOTDIR). The CLI
/// stats the host-side source and only emits `-r` when it's a
/// directory.
#[tokio::test]
async fn integration_cp_lima_upload_file_source_omits_recurse_flag() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "limactl", &record_file, 0, None);

    // Stage a real file on disk so the CLI's `std::fs::metadata` call
    // resolves (`is_dir() == false`), confirming the file-source code
    // path is exercised rather than the "stat failed → fall back"
    // path. Either path produces no `-r`, but pinning the live-stat
    // case keeps this test honest about what it covers.
    let src_dir = tempfile::tempdir().expect("src dir");
    let src_file = src_dir.path().join("file.txt");
    std::fs::write(&src_file, b"contents").expect("write src file");
    let src_path = src_file.to_string_lossy().into_owned();

    let (status, _stdout, stderr) = run_sandbox_cp(
        &[&src_path, "cp-dispatch-test:/home/agent/workspace/file.txt"],
        &sock,
        shim_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox cp should propagate shim exit 0; status={:?}, stderr=\n{stderr}",
        status.code()
    );

    let argv = read_recorded_argv(&record_file);
    assert_eq!(
        argv,
        vec![
            "cp".to_string(),
            src_path,
            format!("sandbox-{TEST_SESSION_ID}:/home/agent/workspace/file.txt"),
        ],
        "file-source upload must not pass -r (rsync ENOTDIR regression)"
    );
}

/// `sandbox cp ./local-dir <session>:/remote-dir` (directory-source
/// upload) against a Lima session invokes `limactl cp -r <src> <dst>`.
/// `-r` is conditional on the host-side source being a directory; the
/// planner stats it at the call site.
#[tokio::test]
async fn integration_cp_lima_upload_directory_source_keeps_recurse_flag() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "limactl", &record_file, 0, None);

    let src_dir = tempfile::tempdir().expect("src dir");
    let src_path = src_dir.path().to_string_lossy().into_owned();

    let (status, _stdout, stderr) = run_sandbox_cp(
        &[&src_path, "cp-dispatch-test:/home/agent/workspace/dir"],
        &sock,
        shim_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox cp directory upload should succeed; status={:?}, stderr=\n{stderr}",
        status.code()
    );

    let argv = read_recorded_argv(&record_file);
    assert_eq!(
        argv,
        vec![
            "cp".to_string(),
            "-r".to_string(),
            src_path,
            format!("sandbox-{TEST_SESSION_ID}:/home/agent/workspace/dir"),
        ],
        "directory-source upload must pass -r"
    );
}

/// Download direction on Lima: `sandbox cp <session>:/remote ./local`
/// invokes `limactl cp <src> <dst>` (src/dst swapped from upload),
/// **without** `-r`. Downloads always omit `-r` because the source
/// lives on the VM side and remote-stat'ing from the host would
/// require a daemon round-trip we deliberately avoid; users wanting a
/// directory download invoke `sandbox sync` instead.
#[tokio::test]
async fn integration_cp_lima_download_swaps_src_and_dst_args() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "limactl", &record_file, 0, None);

    let (status, _stdout, stderr) = run_sandbox_cp(
        &[
            "cp-dispatch-test:/home/agent/workspace/output.log",
            "./local/output.log",
        ],
        &sock,
        shim_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox cp download should succeed; status={:?}, stderr=\n{stderr}",
        status.code()
    );

    let argv = read_recorded_argv(&record_file);
    assert_eq!(
        argv,
        vec![
            "cp".to_string(),
            format!("sandbox-{TEST_SESSION_ID}:/home/agent/workspace/output.log"),
            "./local/output.log".to_string(),
        ]
    );
}

// ---------------------------------------------------------------------------
// Container dispatch
// ---------------------------------------------------------------------------

/// `sandbox cp ./local <session>:/remote` against a container session
/// invokes `docker cp ./local sandbox-<id>:/remote` — no `-r` flag,
/// because `docker cp` recurses by default and rejects unknown flags.
#[tokio::test]
async fn integration_cp_container_upload_invokes_docker_cp_without_recurse_flag() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("container").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "docker", &record_file, 0, None);

    let (status, _stdout, stderr) = run_sandbox_cp(
        &[
            "./local/file.txt",
            "cp-dispatch-test:/home/agent/workspace/file.txt",
        ],
        &sock,
        shim_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox cp should propagate shim exit 0; status={:?}, stderr=\n{stderr}",
        status.code()
    );

    let argv = read_recorded_argv(&record_file);
    assert_eq!(
        argv,
        vec![
            "cp".to_string(),
            "./local/file.txt".to_string(),
            format!("sandbox-{TEST_SESSION_ID}:/home/agent/workspace/file.txt"),
        ]
    );
}

/// Download direction on container backend: src/dst swapped from
/// upload, same `docker cp` shape (no `-r`).
#[tokio::test]
async fn integration_cp_container_download_swaps_src_and_dst_args() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("container").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "docker", &record_file, 0, None);

    let (status, _stdout, stderr) = run_sandbox_cp(
        &[
            "cp-dispatch-test:/home/agent/workspace/output.log",
            "./local/output.log",
        ],
        &sock,
        shim_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox cp container download should succeed; status={:?}, stderr=\n{stderr}",
        status.code()
    );

    let argv = read_recorded_argv(&record_file);
    assert_eq!(
        argv,
        vec![
            "cp".to_string(),
            format!("sandbox-{TEST_SESSION_ID}:/home/agent/workspace/output.log"),
            "./local/output.log".to_string(),
        ]
    );
}

// ---------------------------------------------------------------------------
// Error propagation — native tooling style
// ---------------------------------------------------------------------------

/// When the native tool exits non-zero (e.g. source-not-found), the
/// CLI propagates the exit code unchanged and forwards the native
/// stderr verbatim — callers see the same diagnostic they would get
/// from `limactl cp` / `docker cp` directly.
#[tokio::test]
async fn integration_cp_lima_propagates_native_error_and_exit_code() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    // Mimic scp's "no such file" exit. scp's exit codes vary by
    // platform, but a generic non-zero with a recognizable stderr is
    // what the CLI must propagate. Use `1` here — that's the canonical
    // scp/`limactl cp` style failure.
    install_shim(
        shim_dir.path(),
        "limactl",
        &record_file,
        1,
        Some("scp: ./missing/file.txt: No such file or directory"),
    );

    let (status, _stdout, stderr) = run_sandbox_cp(
        &[
            "./missing/file.txt",
            "cp-dispatch-test:/home/agent/workspace/file.txt",
        ],
        &sock,
        shim_dir.path(),
    )
    .await;

    assert_eq!(
        status.code(),
        Some(1),
        "exit code must match the shim's (native tool's) exit"
    );
    assert!(
        stderr.contains("scp:") && stderr.contains("No such file or directory"),
        "native stderr must be propagated verbatim; got:\n{stderr}"
    );
}

/// Both source and destination prefixed with `session:` is a misuse;
/// the CLI rejects it locally before dispatching anywhere. This pins
/// that the existing user-facing error message survives the refactor.
#[tokio::test]
async fn integration_cp_rejects_both_sides_remote() {
    // We don't even need a daemon for this — the CLI rejects the
    // misuse before any HTTP work. Stand one up anyway so we don't
    // bypass the binary's startup path entirely.
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    // No shim binaries needed — we should never reach a subprocess.

    let (status, _stdout, stderr) =
        run_sandbox_cp(&["a:foo", "b:bar"], &sock, shim_dir.path()).await;

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

/// Neither side prefixed with `session:` is also a misuse; the CLI
/// emits the documented usage hint.
#[tokio::test]
async fn integration_cp_rejects_no_remote_side() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");

    let (status, _stdout, stderr) =
        run_sandbox_cp(&["./local/a", "./local/b"], &sock, shim_dir.path()).await;

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
