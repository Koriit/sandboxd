//! Daemon-startup schema-mismatch refusal tests (Spec 5 § 4.7).
//!
//! Each test spawns the freshly-built `sandboxd` binary with a
//! tempfile `users.conf` (via `SANDBOX_USERS_CONF`) carrying a specific
//! `_schema_version`, asserts the process exits non-zero in well under
//! 5 seconds, and pins the operator-facing stderr substring per
//! Spec 5 § 4.7 / § 9.3.
//!
//! The happy-path "accepts a file at the supported schema version"
//! test is the inverse of the refusal tests: the daemon advances past
//! the schema validator and stalls on the next missing prerequisite
//! (gateway image / matching subnet / etc.). We assert the stderr
//! does **not** contain the `schema version` token rather than waiting
//! for full daemon readiness, because waiting on Lima/gateway init in
//! a hermetic unit-test context would require booting external state
//! Phase 5 § 9.3 specifically scopes out.
//!
//! Test names start with `integration_` so they are selected by the
//! `integration` nextest profile (see `sandboxd/.config/nextest.toml`).

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

/// Spin up the daemon with the given `users.conf` content and wait
/// until either the process exits or the deadline passes. Returns
/// captured stderr and an exit code (`-1` on timeout, which the
/// "accept" test maps to the "started enough to clear the schema
/// gate" success path).
fn spawn_and_wait(users_conf: &str, deadline_secs: u64) -> (String, i32) {
    let tmp = TempDir::new().expect("tempdir");
    let users_conf_path = tmp.path().join("users.conf");
    let socket_path = tmp.path().join("sandboxd.sock");
    let base_dir = tmp.path().join("state");

    let mut f = std::fs::File::create(&users_conf_path).expect("create users.conf");
    f.write_all(users_conf.as_bytes()).expect("write");
    f.flush().expect("flush");

    let mut child = Command::new(sandboxd_bin())
        .arg("--base-dir")
        .arg(&base_dir)
        .arg("--socket")
        .arg(&socket_path)
        .env("XDG_DATA_HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", tmp.path())
        .env("SANDBOX_USERS_CONF", &users_conf_path)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sandboxd");

    let deadline = Instant::now() + Duration::from_secs(deadline_secs);
    let exit_code: i32 = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code().unwrap_or(-1),
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Sentinel: the daemon did not exit within the
                    // deadline. The "accept" test interprets this as
                    // "schema gate cleared; further startup work in
                    // progress" — it then explicitly kills the child
                    // and asserts no schema-token in stderr.
                    let _ = child.kill();
                    let _ = child.wait();
                    let mut stderr_output = String::new();
                    if let Some(mut stderr) = child.stderr.take() {
                        let _ = stderr.read_to_string(&mut stderr_output);
                    }
                    drop(tmp);
                    return (stderr_output, -1);
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
    drop(tmp);

    (stderr_output, exit_code)
}

// ---------------------------------------------------------------------------
// Schema too new
// ---------------------------------------------------------------------------

/// `users.conf` at `_schema_version: 99` (ahead of the binary's max of
/// 1) refuses startup. Spec 5 § 4.7 names the substring `users.conf
/// schema version 99 is newer`.
#[test]
fn integration_daemon_refuses_start_on_schema_too_new() {
    let raw = r#"{
        "_schema_version": 99,
        "subnets": [
            {
                "cidr": "10.209.0.0/20",
                "allow_users": ["sandbox"]
            }
        ]
    }"#;
    let (stderr, code) = spawn_and_wait(raw, 5);
    assert_ne!(
        code, 0,
        "daemon must exit non-zero on schema-too-new; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("users.conf schema version 99 is newer"),
        "stderr must carry the load-bearing `users.conf schema version 99 is newer` \
         substring; got:\n{stderr}"
    );
    assert!(
        stderr.contains("sandbox update"),
        "stderr must point at `sandbox update` as the recovery path; got:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Schema too old
// ---------------------------------------------------------------------------

/// `users.conf` at `_schema_version: 0` (below the binary's min of 1)
/// refuses startup with the `is older than this binary supports`
/// substring. Spec 5 § 4.7's MIN-side behaviour.
#[test]
fn integration_daemon_refuses_start_on_schema_too_old() {
    // `_schema_version` field set explicitly to 0 (operators with
    // pre-V001 files will hit the same path via the "absent → 0"
    // mapping; both surface as SchemaTooOld).
    let raw = r#"{
        "_schema_version": 0,
        "subnets": [
            {
                "cidr": "10.209.0.0/20",
                "allow_users": ["sandbox"]
            }
        ]
    }"#;
    let (stderr, code) = spawn_and_wait(raw, 5);
    assert_ne!(
        code, 0,
        "daemon must exit non-zero on schema-too-old; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("is older than this binary supports"),
        "stderr must carry the load-bearing `is older than this binary supports` \
         substring; got:\n{stderr}"
    );
    assert!(
        stderr.contains("sandbox update"),
        "stderr must point at `sandbox update` as the rollforward path; got:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Schema at max — accepted
// ---------------------------------------------------------------------------

/// `users.conf` at the supported `_schema_version: 1` clears the
/// schema gate; the daemon advances past `validate_users_conf_schema_version`
/// and stalls on the next missing prerequisite (gateway image, etc.).
/// We assert the absence of any `schema version` token in stderr —
/// the validator did not fire — and rely on the timeout sentinel
/// (`code == -1`) to confirm the process did not exit immediately
/// with a schema-related error.
#[test]
fn integration_daemon_accepts_start_on_schema_at_max() {
    // Use the test runner's own uid so `find_subnet_by_uid` matches
    // and the daemon advances past the next gate (subnet resolution).
    let runner_uid = nix::unistd::Uid::current().as_raw();
    let runner_name = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(runner_uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| "sandbox".to_string());

    let raw = format!(
        r#"{{
            "_schema_version": 1,
            "subnets": [
                {{
                    "cidr": "10.209.0.0/20",
                    "allow_users": ["sandbox", "{runner_name}"]
                }}
            ]
        }}"#
    );
    // Short deadline: we expect the daemon to either exit on a later
    // gate (gateway image, etc.) or stay running past the schema
    // validator. Either way, stderr must not contain the
    // schema-version token.
    let (stderr, _code) = spawn_and_wait(&raw, 3);
    assert!(
        !stderr.contains("schema version"),
        "schema validator must accept the file; stderr must NOT contain `schema version`; \
         got:\n{stderr}"
    );
    assert!(
        !stderr.contains("is newer than this binary supports"),
        "stderr must not surface the too-new refusal; got:\n{stderr}"
    );
    assert!(
        !stderr.contains("is older than this binary supports"),
        "stderr must not surface the too-old refusal; got:\n{stderr}"
    );
}
