//! Graceful-shutdown integration test.
//!
//! Spawns the real `sandboxd` binary with tempdir seams, waits until it is
//! listening on its Unix socket, sends SIGTERM, and asserts:
//!   - the process exits with status 0 within a short window, AND
//!   - the Unix socket file is removed on exit.
//!
//! The test uses the same seam set as `integration_macos_daemon_startup.rs`
//! so it runs as the current user without root or any system group membership.
//!
//! ## Invocation
//!
//! ```
//! cd sandboxd && cargo nextest run --profile integration \
//!   --features sandbox-route-helper/test-env-override,sandbox-lima-helper/test-env-override \
//!   -E 'test(integration_graceful_shutdown)'
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn sandboxd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandboxd"))
}

fn current_username() -> String {
    let uid = nix::unistd::Uid::current();
    nix::unistd::User::from_uid(uid)
        .expect("getpwuid_r succeeded")
        .expect("uid maps to a passwd entry")
        .name
}

/// Spin up the daemon with tempdir seams and return the child process,
/// the socket path, and the TempDir (kept alive to prevent cleanup).
///
/// Seams applied (mirrors integration_macos_daemon_startup.rs):
///   - `--base-dir` → tempdir
///   - `--socket`   → tempdir/sandboxd.sock
///   - `SANDBOX_USERS_CONF` → tempdir/users.conf
///   - `SANDBOX_BROKER_SOCKET` → tempdir/broker.sock (macOS broker redirect)
///   - `XDG_DATA_HOME`, `XDG_RUNTIME_DIR` → tempdir
///
/// The daemon is given `--log-file <tempdir>/daemon.log` so the macOS
/// rolling-appender path (which writes to the system /var/log/sandbox/)
/// is not activated — the test runs as a normal user and cannot write there.
fn spawn_daemon() -> (std::process::Child, PathBuf, TempDir) {
    let tmp = TempDir::new().expect("tempdir");

    let users_conf_path = tmp.path().join("users.conf");
    let socket_path = tmp.path().join("sandboxd.sock");
    let base_dir = tmp.path().join("state");
    let broker_socket_path = tmp.path().join("broker.sock");
    let log_file = tmp.path().join("daemon.log");

    let username = current_username();
    let users_conf = format!(
        r#"{{"_schema_version":1,"subnets":[{{"cidr":"10.209.0.0/24","allow_users":["{username}"]}}]}}"#
    );
    {
        let mut f = std::fs::File::create(&users_conf_path).expect("create users.conf");
        f.write_all(users_conf.as_bytes())
            .expect("write users.conf");
    }

    let child = Command::new(sandboxd_bin())
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--socket")
        .arg(&socket_path)
        .arg("--log-file")
        .arg(&log_file)
        .env("XDG_DATA_HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", tmp.path())
        .env("SANDBOX_USERS_CONF", &users_conf_path)
        .env("SANDBOX_BROKER_SOCKET", &broker_socket_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sandboxd");

    (child, socket_path, tmp)
}

/// Poll until the socket file appears (daemon is listening) or the deadline
/// passes. Returns true when the socket is ready.
fn wait_for_socket(socket_path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if socket_path.exists() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Poll until the child process has exited or the deadline passes.
/// Returns the exit code if the process exited, or None on timeout.
fn wait_for_exit(child: &mut std::process::Child, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status.code().unwrap_or(-1)),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return None;
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("try_wait failed: {e}"),
        }
    }
}

/// Main graceful-shutdown contract test.
///
/// Verifies the full sequence on SIGTERM:
///   1. Daemon reaches the listening state (socket appears).
///   2. SIGTERM is sent.
///   3. Daemon exits with code 0 within 15 seconds.
///   4. The Unix socket file is removed on exit.
#[test]
fn integration_graceful_shutdown_exits_zero_and_removes_socket() {
    let (mut child, socket_path, _tmp) = spawn_daemon();

    // Wait up to 60 seconds for the socket to appear. A freshly built binary
    // can take 20–25s on its first exec due to syspolicyd code-signature
    // validation; 60s gives comfortable headroom on CI / Tart without making
    // a real failure take forever. If the socket still doesn't appear, kill
    // the child and report a clear action: `sudo killall syspolicyd`.
    let socket_ready = wait_for_socket(&socket_path, Duration::from_secs(60));
    if !socket_ready {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "sandboxd did not start listening within 60s. \
             If syspolicyd is wedged, run: sudo killall syspolicyd"
        );
    }

    // The socket exists: daemon is listening. Send SIGTERM.
    let pid = child.id();
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }

    // Wait up to 15 seconds for the daemon to exit cleanly.
    let exit_code = wait_for_exit(&mut child, Duration::from_secs(15));

    match exit_code {
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("sandboxd did not exit within 15s after SIGTERM");
        }
        Some(code) => {
            assert_eq!(
                code, 0,
                "daemon must exit 0 after SIGTERM; got exit code {code}"
            );
        }
    }

    // The socket file must be removed as part of the graceful shutdown.
    assert!(
        !socket_path.exists(),
        "sandboxd must remove the socket file on graceful shutdown, \
         but {:?} still exists",
        socket_path
    );
}
