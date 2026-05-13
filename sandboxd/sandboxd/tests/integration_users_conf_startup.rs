//! Black-box integration tests verifying that the daemon refuses
//! to start unless `users.conf` exists, parses, and contains a subnet
//! entry whose `allow_users` resolves to the daemon's own uid.
//!
//! Each test spawns the freshly-built `sandboxd` binary with
//! `SANDBOX_USERS_CONF` pointing at a tempfile we own, asserts the
//! process exits non-zero in well under 5 seconds, and pins the stderr
//! shape so operators get a discoverable error.
//!
//! A happy-path "starts successfully when users.conf has a matching
//! subnet" test would require booting Lima + the gateway container — out
//! of scope for this phase. The existing E2E suite is the implicit
//! happy-path canary.
//!
//! Test names start with `integration_users_conf_startup_` so they are
//! selected by the `integration` nextest profile (see
//! `sandboxd/.config/nextest.toml`).

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// Path to the `sandboxd` binary produced by `cargo build`. Cargo sets
/// `CARGO_BIN_EXE_<name>` for the integration test crate.
fn sandboxd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandboxd"))
}

/// Spin up the daemon with the given `users.conf` content (or, if
/// `users_conf` is `None`, a path that doesn't exist) and wait for it to
/// exit. Returns the captured stderr and the exit-status code.
///
/// Uses a unique temp directory for socket + base-dir so tests don't
/// race on the developer's real `~/.local/share/sandboxd/`.
fn spawn_and_wait_for_exit(users_conf: Option<&str>) -> (String, i32) {
    let tmp = TempDir::new().expect("tempdir");
    let users_conf_path = tmp.path().join("users.conf");
    let socket_path = tmp.path().join("sandboxd.sock");
    let base_dir = tmp.path().join("state");

    // Either materialize a users.conf or arrange for the path to be a
    // missing file (the env var still points there — the loader maps
    // `NotFound` to `UsersConfigError::FileNotFound`).
    if let Some(contents) = users_conf {
        let mut f = std::fs::File::create(&users_conf_path).expect("create users.conf");
        f.write_all(contents.as_bytes()).expect("write users.conf");
        f.flush().expect("flush users.conf");
    }

    let mut child = Command::new(sandboxd_bin())
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--socket")
        .arg(&socket_path)
        // Suppress any chance of the daemon trying to read the
        // operator's actual `~/.local/share/sandboxd/` — pin XDG_*
        // paths inside the tempdir.
        .env("XDG_DATA_HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", tmp.path())
        .env("SANDBOX_USERS_CONF", &users_conf_path)
        // Default tracing → stderr; we capture stderr to assert on
        // the message text. The substring assertions key off `eprintln`
        // output, not log output, so `warn` is enough — it keeps any
        // genuine warnings visible on failure without piping info-level
        // init noise that pressures slow CI's stderr buffer.
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sandboxd");

    // Poll for exit. The failure path doesn't initialize Lima or the
    // gateway, so 5 s is generous — the daemon should exit within
    // milliseconds.
    let deadline = Instant::now() + Duration::from_secs(5);
    let exit_code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code().unwrap_or(-1),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "sandboxd did not exit within 5s; expected immediate failure on \
                         users.conf validation. tmp dir: {:?}",
                        tmp.path()
                    );
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("try_wait failed: {e}"),
        }
    };

    let mut stderr_output = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut stderr_output);
    }

    // `tmp` is held until end of function; on drop it cleans up the
    // socket / base dir / users.conf. Must come after stderr read —
    // closing the tempdir while stderr is still draining drops the
    // abstract socket binding underneath the daemon.
    drop(tmp);

    (stderr_output, exit_code)
}

#[test]
fn integration_users_conf_startup_refuses_when_file_missing() {
    let (stderr, code) = spawn_and_wait_for_exit(None);
    assert_ne!(
        code, 0,
        "daemon must exit non-zero when users.conf is missing; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("users.conf not found"),
        "stderr must mention 'users.conf not found'; got:\n{stderr}"
    );
    // The `FileNotFound` variant's Display includes the path; verify
    // it bubbled all the way out so operators know which file the
    // daemon was looking at.
    assert!(
        stderr.contains("users.conf"),
        "stderr must reference users.conf; got:\n{stderr}"
    );
}

#[test]
fn integration_users_conf_startup_refuses_when_file_malformed() {
    let (stderr, code) = spawn_and_wait_for_exit(Some("not json"));
    assert_ne!(
        code, 0,
        "daemon must exit non-zero when users.conf is malformed; stderr was:\n{stderr}"
    );
    // The loader's `ParseFailed` variant includes the path and a
    // `serde_json` error fragment; we just assert the file is
    // referenced so operators can locate it.
    assert!(
        stderr.contains("users.conf"),
        "stderr must reference users.conf; got:\n{stderr}"
    );
    assert!(
        stderr.contains("parse"),
        "stderr must mention parse failure; got:\n{stderr}"
    );
}

#[test]
fn integration_users_conf_startup_refuses_when_no_matching_subnet() {
    // Sentinel username that cannot resolve via `getpwnam_r` on any
    // real host — Phase 2A's loader treats `Ok(None)` as a non-match.
    let raw = r#"{
        "_schema_version": 1,
        "subnets": [
            {
                "cidr": "10.209.0.0/20",
                "allow_users": ["definitely-not-a-real-user-9c3f"]
            }
        ]
    }"#;
    let (stderr, code) = spawn_and_wait_for_exit(Some(raw));
    assert_ne!(
        code, 0,
        "daemon must exit non-zero when no subnet matches the daemon uid; \
         stderr was:\n{stderr}"
    );
    // Grep-stable prefix that Phase 2D's install docs will reference.
    assert!(
        stderr.contains("no users.conf subnet matches daemon user"),
        "stderr must use the grep-stable prefix; got:\n{stderr}"
    );
    let runner_uid = nix::unistd::Uid::current().as_raw();
    assert!(
        stderr.contains(&runner_uid.to_string()),
        "stderr must include the daemon uid {runner_uid}; got:\n{stderr}"
    );
    assert!(
        stderr.contains("docs/start/installation.md"),
        "stderr must point at install docs; got:\n{stderr}"
    );
}
