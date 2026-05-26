//! Integration test: `sandbox cp` dispatches to `scp sandbox-<id>:…`
//! via the daemon-mediated SSH proxy.
//!
//! Under M18-S6, `sandbox cp` no longer reaches into the backend
//! directly (`limactl cp` / `docker cp`); it ensures a per-session
//! ssh-config entry under `~/.ssh/sandbox/`, then exec's `scp` against
//! the alias `sandbox-<id>`. The operator's `~/.ssh/config` (via our
//! managed `Include` block) resolves that alias to a stanza whose
//! `ProxyCommand sandbox proxy <id>` line tunnels the bytes through
//! the daemon.
//!
//! This test pins the new dispatch surface:
//!
//! * The CLI sources its ssh-config from `GET /sessions/{id}/ssh-config`.
//! * The CLI invokes `scp` (not `limactl cp` / `docker cp`).
//! * The argv shape is `scp [-r] <src> <dst>` against
//!   `sandbox-<id>:<path>`.
//! * Direction (upload vs download) drives src/dst ordering.
//! * `-r` is conditional on the host-side source being a directory.
//! * Non-zero exit from `scp` propagates verbatim.
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
const TEST_SESSION_NAME: &str = "cp-dispatch-test";

/// Stand up a fake daemon serving the two endpoints the cp flow touches:
///
/// * `GET /sessions/{id}` → `SessionDto` with the requested backend.
/// * `GET /sessions/{id}/ssh-config` → `SshConfigDto` with the canonical
///   config block (CLI rewrites the `IdentityFile` placeholder before
///   landing it on disk) and a synthetic private-key blob.
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
        // The CLI fetches `GET /version` on every send_request_with_timeout
        // call (strict CLI ↔ daemon version-equality rule). Report the
        // test binary's own CARGO_PKG_VERSION so the handshake passes
        // and the cp-dispatch flow reaches the SSH-config-fetch handler.
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
/// to `PATH` (so the `scp` shim wins over the real one) and `$HOME`
/// pointed at a fresh tempdir (so the CLI's `~/.ssh/sandbox/`
/// mutations land in a hermetic location).
async fn run_sandbox_cp(
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
        .arg("cp")
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

/// Read the recorded argv lines from the shim's sentinel file.
fn read_recorded_argv(record_file: &Path) -> Vec<String> {
    let raw = std::fs::read_to_string(record_file).unwrap_or_default();
    raw.lines().map(|l| l.to_string()).collect()
}

// ---------------------------------------------------------------------------
// Upload (file source) — no `-r`
// ---------------------------------------------------------------------------

/// File-source upload: `sandbox cp ./local-file
/// <session>:/remote-file` invokes `scp <src> <dst>` against
/// `sandbox-<id>:<path>` — **without** `-r`. `scp -r` on a file source
/// is wasteful but accepted; the planner deliberately omits it to
/// match `cp`'s historical "single file" affordance.
#[tokio::test]
async fn integration_cp_file_upload_emits_scp_against_sandbox_alias_without_recurse() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "scp", &record_file, 0, None);
    let home_dir = tempfile::tempdir().expect("home dir");

    let src_dir = tempfile::tempdir().expect("src dir");
    let src_file = src_dir.path().join("file.txt");
    std::fs::write(&src_file, b"contents").expect("write src file");
    let src_path = src_file.to_string_lossy().into_owned();

    let (status, _stdout, stderr) = run_sandbox_cp(
        &[
            &src_path,
            &format!("{TEST_SESSION_NAME}:/home/sandbox/workspace/file.txt"),
        ],
        &sock,
        shim_dir.path(),
        home_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox cp should propagate scp shim exit 0; status={:?}, stderr=\n{stderr}",
        status.code()
    );
    let argv = read_recorded_argv(&record_file);
    assert_eq!(
        argv,
        vec![
            src_path,
            format!("sandbox-{TEST_SESSION_ID}:/home/sandbox/workspace/file.txt"),
        ],
        "file-source upload must invoke `scp <src> <dst>` against the alias"
    );
}

/// Directory-source upload: `sandbox cp ./local-dir
/// <session>:/remote-dir` invokes `scp -r <src> <dst>` against
/// `sandbox-<id>:<path>`. `-r` is conditional on the planner's
/// `source_is_dir` flag, which the dispatch site stats at the host
/// path.
#[tokio::test]
async fn integration_cp_directory_upload_passes_recurse_flag() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "scp", &record_file, 0, None);
    let home_dir = tempfile::tempdir().expect("home dir");

    let src_dir = tempfile::tempdir().expect("src dir");
    let src_path = src_dir.path().to_string_lossy().into_owned();

    let (status, _stdout, stderr) = run_sandbox_cp(
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
        "sandbox cp directory upload should succeed; status={:?}, stderr=\n{stderr}",
        status.code()
    );
    let argv = read_recorded_argv(&record_file);
    assert_eq!(
        argv,
        vec![
            "-r".to_string(),
            src_path,
            format!("sandbox-{TEST_SESSION_ID}:/home/sandbox/workspace/dir"),
        ],
        "directory-source upload must pass -r"
    );
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

/// Download: `sandbox cp <session>:/remote ./local` invokes `scp
/// <src> <dst>` with the src/dst swapped from upload, **without**
/// `-r`. Downloads always omit `-r` — the source lives on the VM side
/// and remote-stat'ing from the host would require a daemon
/// round-trip we deliberately avoid; operators wanting a directory
/// download fall through to `sandbox sync`.
#[tokio::test]
async fn integration_cp_download_swaps_src_and_dst_args() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("container").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "scp", &record_file, 0, None);
    let home_dir = tempfile::tempdir().expect("home dir");

    let (status, _stdout, stderr) = run_sandbox_cp(
        &[
            &format!("{TEST_SESSION_NAME}:/home/sandbox/workspace/output.log"),
            "./local/output.log",
        ],
        &sock,
        shim_dir.path(),
        home_dir.path(),
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
            format!("sandbox-{TEST_SESSION_ID}:/home/sandbox/workspace/output.log"),
            "./local/output.log".to_string(),
        ]
    );
}

// ---------------------------------------------------------------------------
// Per-session entry side-effect
// ---------------------------------------------------------------------------

/// After a successful dispatch the per-session SSH config + key
/// files MUST be on disk under `$HOME/.ssh/sandbox/`. This pins the
/// "ensure entry before exec" invariant the CLI promises.
#[tokio::test]
async fn integration_cp_writes_per_session_entry_under_managed_home() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(shim_dir.path(), "scp", &record_file, 0, None);
    let home_dir = tempfile::tempdir().expect("home dir");

    let src_dir = tempfile::tempdir().expect("src dir");
    let src_file = src_dir.path().join("entry.txt");
    std::fs::write(&src_file, b"hello").expect("write src");
    let src_path = src_file.to_string_lossy().into_owned();

    let (status, _stdout, stderr) = run_sandbox_cp(
        &[
            &src_path,
            &format!("{TEST_SESSION_NAME}:/home/sandbox/workspace/entry.txt"),
        ],
        &sock,
        shim_dir.path(),
        home_dir.path(),
    )
    .await;

    assert!(
        status.success(),
        "sandbox cp must succeed for entry to be written; status={:?}, stderr=\n{stderr}",
        status.code()
    );

    let sandbox_dir = home_dir.path().join(".ssh").join("sandbox");
    let cfg = sandbox_dir.join(format!("sandbox-{TEST_SESSION_ID}"));
    let key = sandbox_dir.join(format!("sandbox-{TEST_SESSION_ID}.key"));
    assert!(
        cfg.exists(),
        "per-session config must be staged under $HOME/.ssh/sandbox/"
    );
    assert!(
        key.exists(),
        "per-session key must be staged under $HOME/.ssh/sandbox/"
    );
    // The global Include block lands in `~/.ssh/config`.
    let global = home_dir.path().join(".ssh").join("config");
    assert!(
        global.exists(),
        "~/.ssh/config must be created with the managed Include block"
    );
}

// ---------------------------------------------------------------------------
// Error propagation
// ---------------------------------------------------------------------------

/// When `scp` exits non-zero (e.g. source-not-found), the CLI
/// propagates the exit code unchanged and forwards the native stderr
/// verbatim — callers see the same diagnostic they would get from
/// invoking `scp` themselves.
///
/// Note: `LC_ALL=C` / `LANG=C` are injected by the CLI; the stderr
/// substring sniffer (`looks_like_publickey_drift`) doesn't trigger
/// here because the simulated message is a generic "No such file or
/// directory" — drift recovery is matched only on the canonical
/// `Permission denied (publickey)` substring.
#[tokio::test]
async fn integration_cp_propagates_native_error_and_exit_code() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let record_file = shim_dir.path().join("argv.log");
    install_shim(
        shim_dir.path(),
        "scp",
        &record_file,
        1,
        Some("scp: ./missing/file.txt: No such file or directory"),
    );
    let home_dir = tempfile::tempdir().expect("home dir");

    let (status, _stdout, stderr) = run_sandbox_cp(
        &[
            "./missing/file.txt",
            &format!("{TEST_SESSION_NAME}:/home/sandbox/workspace/file.txt"),
        ],
        &sock,
        shim_dir.path(),
        home_dir.path(),
    )
    .await;

    assert_eq!(
        status.code(),
        Some(1),
        "exit code must match the scp shim's"
    );
    assert!(
        stderr.contains("scp:") && stderr.contains("No such file or directory"),
        "scp stderr must be propagated verbatim; got:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

/// Both source and destination prefixed with `session:` is a misuse;
/// the CLI rejects it locally before dispatching anywhere.
#[tokio::test]
async fn integration_cp_rejects_both_sides_remote() {
    let (_tmp_daemon, sock) = spawn_fake_daemon("lima").await;
    let shim_dir = tempfile::tempdir().expect("shim dir");
    let home_dir = tempfile::tempdir().expect("home dir");

    let (status, _stdout, stderr) =
        run_sandbox_cp(&["a:foo", "b:bar"], &sock, shim_dir.path(), home_dir.path()).await;

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
    let home_dir = tempfile::tempdir().expect("home dir");

    let (status, _stdout, stderr) = run_sandbox_cp(
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
