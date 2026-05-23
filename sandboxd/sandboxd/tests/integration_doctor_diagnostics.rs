//! End-to-end coverage for `sandbox doctor` + `GET /diagnostics`.
//!
//!
//! for the daemon-productionization revision:
//!
//! - `integration_doctor_hard_fails_on_missing_gateway_image`
//! - `integration_doctor_informational_on_missing_lite_image`
//! - `integration_doctor_full_pass_against_running_daemon`
//! - `integration_kvm_check_via_daemon_diagnostics`
//! - `integration_subdir_mode_correction_at_startup`
//!
//! All five live in this file because they share a daemon-spawn
//! fixture and exercise the same wire boundary (`GET /diagnostics`
//! over the unix socket; `sandbox doctor` over the same socket via
//! the CLI binary). Test names use the workspace `integration_*`
//! prefix so the default nextest profile filters them out; the
//! integration profile selects them.
//!
//! # Binary resolution
//!
//! The `sandboxd` and `sandbox` binaries live next to each other in
//! the same `target/<profile>/` directory. `CARGO_BIN_EXE_sandboxd`
//! is set by cargo for this crate's tests; the `sandbox` CLI binary
//! is resolved relative to that path (sibling), which works for both
//! `cargo test` and `cargo nextest` invocations.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tempfile::TempDir;
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// Binary resolution
// ---------------------------------------------------------------------------

fn sandboxd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandboxd"))
}

/// Resolve the `sandbox` CLI binary path. Cargo only sets
/// `CARGO_BIN_EXE_<name>` for binaries defined in the current crate,
/// so we fall back to "sibling of sandboxd in target/<profile>/". The
/// CLI is a workspace-mate of sandboxd; the assumption holds for the
/// nextest invocation pattern the integration profile uses.
fn sandbox_cli_bin() -> PathBuf {
    let sandboxd = sandboxd_bin();
    sandboxd
        .parent()
        .expect("sandboxd binary has a parent dir")
        .join("sandbox")
}

// ---------------------------------------------------------------------------
// users.conf fixture
// ---------------------------------------------------------------------------

fn current_username() -> String {
    let uid = nix::unistd::Uid::current();
    nix::unistd::User::from_uid(uid)
        .expect("getpwuid_r succeeded")
        .expect("uid maps to a passwd entry")
        .name
}

/// Write a `users.conf` whose single subnet's `allow_users` resolves
/// to the test process's own uid so the daemon starts up. The subnet
/// itself is irrelevant for the diagnostics path — no session is
/// ever created here. We pick a non-overlapping /24 per fixture so
/// concurrent test runs don't collide on the same allocation pool.
fn write_users_conf(dir: &Path, user: &str, cidr: &str) -> PathBuf {
    let path = dir.join("users.conf");
    let body = format!(
        r#"{{"_schema_version":1,"subnets":[{{"cidr":"{cidr}","allow_users":["{user}"]}}]}}"#
    );
    let mut f = std::fs::File::create(&path).expect("create users.conf");
    f.write_all(body.as_bytes()).expect("write users.conf");
    f.flush().expect("flush users.conf");
    path
}

// ---------------------------------------------------------------------------
// Daemon fixture
// ---------------------------------------------------------------------------

struct Daemon {
    socket: PathBuf,
    #[allow(dead_code)]
    base_dir: PathBuf,
    proc: Option<Child>,
    _tmp: TempDir,
}

impl Daemon {
    /// Spawn the daemon binary against a tempdir. Returns once the
    /// socket is observable on disk. `pool_cidr` lets each test pick
    /// its own /24 so parallel runs don't collide.
    fn spawn(pool_cidr: &str) -> Self {
        Self::spawn_with_env(pool_cidr, &[])
    }

    /// As [`spawn`], but threads extra `(key, value)` env vars into
    /// the daemon's process environment. Used by the gateway- and
    /// lite-image tag-override tests to point the daemon at a
    /// guaranteed-absent tag without depending on the host's docker
    /// image inventory.
    fn spawn_with_env(pool_cidr: &str, extra_env: &[(&str, &str)]) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let user = current_username();
        let socket = tmp.path().join("sandboxd.sock");
        let base_dir = tmp.path().join("state");
        std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");
        let users_conf = write_users_conf(tmp.path(), &user, pool_cidr);

        let stdout_log = tmp.path().join("sandboxd.stdout.log");
        let stderr_log = tmp.path().join("sandboxd.stderr.log");
        let stdout_fh = std::fs::File::create(&stdout_log).expect("create stdout log");
        let stderr_fh = std::fs::File::create(&stderr_log).expect("create stderr log");

        let mut cmd = Command::new(sandboxd_bin());
        cmd.arg("--socket")
            .arg(&socket)
            .arg("--base-dir")
            .arg(&base_dir)
            .env("XDG_DATA_HOME", tmp.path())
            .env("XDG_RUNTIME_DIR", tmp.path())
            .env("SANDBOX_USERS_CONF", &users_conf)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(stdout_fh))
            .stderr(Stdio::from(stderr_fh));
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let proc = cmd.spawn().expect("spawn sandboxd");
        let daemon = Self {
            socket,
            base_dir,
            proc: Some(proc),
            _tmp: tmp,
        };
        daemon.wait_for_socket(Duration::from_secs(30));
        daemon
    }

    fn wait_for_socket(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if self.socket.exists() {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "sandboxd socket did not appear at {} within {:?}",
                    self.socket.display(),
                    timeout,
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut proc) = self.proc.take() {
            let _ = proc.kill();
            let _ = proc.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP-over-unix client
// ---------------------------------------------------------------------------

async fn http_get(
    socket_path: &Path,
    path: &str,
    timeout: Duration,
) -> (hyper::StatusCode, Vec<u8>) {
    let socket_str = socket_path.to_string_lossy().into_owned();
    tokio::time::timeout(timeout, async move {
        let stream = UnixStream::connect(&socket_str)
            .await
            .unwrap_or_else(|e| panic!("connect {socket_str}: {e}"));
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .expect("hyper handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header("host", "localhost")
            .body(Empty::<hyper::body::Bytes>::new())
            .expect("build request");
        let resp = sender.send_request(req).await.expect("send_request");
        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        (status, body.to_vec())
    })
    .await
    .unwrap_or_else(|_| panic!("HTTP request timed out after {timeout:?}"))
}

// ---------------------------------------------------------------------------
// Test 1 — startup subdir mode correction
// ---------------------------------------------------------------------------

/// Pre-create `<base_dir>/sessions/` with mode `0755`; start the
/// daemon; assert it corrects the mode to `0700` (the
/// `ensure_base_dir_layout` contract). This integration test exercises
/// the behavior end-to-end against
/// the real daemon binary so a regression that quietly removed the
/// chmod call (or moved it past a startup error) would surface.
#[test]
fn integration_subdir_mode_correction_at_startup() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let user = current_username();
    let socket = tmp.path().join("sandboxd.sock");
    let base_dir = tmp.path().join("state");
    std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");

    // Pre-create sessions/ with the wrong mode. The startup-hardening
    // contract is "warn + correct" — the daemon must end up with
    // mode 0700 even though we wrote 0755.
    let sessions_dir = base_dir.join("sessions");
    std::fs::create_dir(&sessions_dir).expect("create sessions/");
    std::fs::set_permissions(&sessions_dir, std::fs::Permissions::from_mode(0o755))
        .expect("set sessions/ to 0755");

    let users_conf = write_users_conf(tmp.path(), &user, "10.231.0.0/24");
    let stdout_log = tmp.path().join("sandboxd.stdout.log");
    let stderr_log = tmp.path().join("sandboxd.stderr.log");
    let stdout_fh = std::fs::File::create(&stdout_log).expect("create stdout log");
    let stderr_fh = std::fs::File::create(&stderr_log).expect("create stderr log");

    let mut cmd = Command::new(sandboxd_bin());
    cmd.arg("--socket")
        .arg(&socket)
        .arg("--base-dir")
        .arg(&base_dir)
        .env("XDG_DATA_HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", tmp.path())
        .env("SANDBOX_USERS_CONF", &users_conf)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::from(stdout_fh))
        .stderr(Stdio::from(stderr_fh));
    let mut proc = cmd.spawn().expect("spawn sandboxd");

    // Wait for the socket to appear (signals the layout pass has
    // completed and the listener is up).
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if socket.exists() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = proc.kill();
            let _ = proc.wait();
            let stderr = std::fs::read_to_string(&stderr_log).unwrap_or_default();
            panic!("sandboxd did not bring up socket; stderr={stderr}");
        }
        thread::sleep(Duration::from_millis(50));
    }

    // The chmod runs synchronously during startup, before the socket
    // exists; by the time we observe the socket the mode is already
    // correct. Read the mode directly off the filesystem.
    let mode = std::fs::metadata(&sessions_dir)
        .expect("stat sessions/")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o700,
        "startup must correct sessions/ from 0755 to 0700; got {mode:04o}"
    );

    let _ = proc.kill();
    let _ = proc.wait();
}

// ---------------------------------------------------------------------------
// Test 2 — doctor exits 1 when gateway image is missing
// ---------------------------------------------------------------------------

/// Spawn a daemon pointed at a guaranteed-absent gateway-image tag
/// (timestamp-suffixed, so concurrent test runs and any pre-built
/// `sandbox-gateway:<version>` on the host don't collide) and run
/// `sandbox doctor --verbose`. The tag-override env var is honored
/// only when `sandbox-core` is built with the `test-env-override`
/// feature (production builds ignore it — see Cargo.toml). The test
/// asserts unconditionally:
///
/// - exit code is `1` (C7 hard-failed),
/// - C7 row renders the `✗` glyph and names the gateway-image check,
/// - the row carries the remediation hint substring.5
///   mandates (`sandbox update` and/or `make gateway-image`).
///
/// We additionally probe `GET /diagnostics` to pin the wire-level
/// answer the doctor's C7 check trips on: `gateway_image_present`
/// must be `false`.
///
/// The unique-tag isolation pattern mirrors
/// `integration_gateway_image_pinned_to_daemon_version` (suffixing
/// the tag with `SystemTime::now().duration_since(UNIX_EPOCH).as_nanos()`)
/// so a passing run never depends on the host's docker inventory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_doctor_hard_fails_on_missing_gateway_image() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // No `docker tag` step — the tag is *only* probed via `docker
    // image inspect` (which returns "no such image"), never built or
    // run. Leak-proof by construction.
    let absent_tag = format!("sandbox-gateway:doctor-itest-absent-{nanos}");
    let daemon = Daemon::spawn_with_env(
        "10.232.0.0/24",
        &[("SANDBOX_GATEWAY_TAG_OVERRIDE", &absent_tag)],
    );

    let (status, body) = http_get(&daemon.socket, "/diagnostics", Duration::from_secs(10)).await;
    assert_eq!(status, hyper::StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("body parses as JSON");
    let gateway_present = parsed
        .get("gateway_image_present")
        .and_then(|v| v.as_bool())
        .expect("gateway_image_present is bool");
    assert!(
        !gateway_present,
        "daemon must report gateway_image_present=false when its override \
         tag points at an absent image; got true. body={parsed}. \
         (If this fires, the `test-env-override` feature is likely off — \
         confirm `--features sandbox-route-helper/test-env-override` is on \
         the cargo invocation, which transitively enables `sandbox-core/test-env-override`.)"
    );

    // Run `sandbox doctor` against the daemon. Doctor connects with
    // the version-handshake bypass so it reaches the daemon despite
    // any skew.
    let output = std::process::Command::new(sandbox_cli_bin())
        .arg("--socket")
        .arg(&daemon.socket)
        .arg("doctor")
        .arg("--verbose")
        .output()
        .expect("spawn sandbox doctor");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let exit_code = output.status.code().expect("exited normally");

    // ;
    // doctor's process exit code flips to 1.
    assert_eq!(
        exit_code, 1,
        "doctor must exit 1 when gateway image is missing; got {exit_code}, stdout={stdout}"
    );
    assert!(
        stdout.contains("gateway image present"),
        "C7 row must always render; got: {stdout}"
    );
    assert!(
        stdout.contains("\u{2717}"),
        "missing gateway image must render the ✗ glyph on the C7 row; got: {stdout}"
    );
    assert!(
        stdout.contains("sandbox update") || stdout.contains("make gateway-image"),
        "C7 fail hint must point at the remediation (`sandbox update` or `make gateway-image`); \
         got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — doctor stays informational when only the lite image is missing
// ---------------------------------------------------------------------------

/// Spawn a daemon pointed at a guaranteed-absent lite-image tag
/// (timestamp-suffixed unique tag, mirroring the gateway test's
/// isolation pattern). Run `sandbox doctor --verbose`. The lite
/// image is informational only — missing it
/// must NOT trip the C8 row to `✗`. The test asserts unconditionally:
///
/// - `/diagnostics` reports `lite_image_present: false`,
/// - C8 row renders with the `SKIPPED` / `not built yet` annotation,
/// - doctor's exit code is `0` or `1` (never `2` — doctor-itself-broken).
///
/// The tag-override env var (`SANDBOX_LITE_TAG_OVERRIDE`) is honored
/// only when `sandbox-core` is built with the `test-env-override`
/// feature; production builds ignore it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_doctor_informational_on_missing_lite_image() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let absent_tag = format!("sandboxd-lite:doctor-itest-absent-{nanos}");
    let daemon = Daemon::spawn_with_env(
        "10.233.0.0/24",
        &[("SANDBOX_LITE_TAG_OVERRIDE", &absent_tag)],
    );

    let (status, body) = http_get(&daemon.socket, "/diagnostics", Duration::from_secs(10)).await;
    assert_eq!(status, hyper::StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("body parses as JSON");
    let lite_present = parsed
        .get("lite_image_present")
        .and_then(|v| v.as_bool())
        .expect("lite_image_present is bool");
    assert!(
        !lite_present,
        "daemon must report lite_image_present=false when its override \
         tag points at an absent image; got true. body={parsed}. \
         (If this fires, the `test-env-override` feature is likely off — \
         confirm `--features sandbox-route-helper/test-env-override` is on \
         the cargo invocation.)"
    );

    let output = std::process::Command::new(sandbox_cli_bin())
        .arg("--socket")
        .arg(&daemon.socket)
        .arg("doctor")
        .arg("--verbose")
        .output()
        .expect("spawn sandbox doctor");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let exit_code = output.status.code().expect("exited normally");

    // C8 must render — and as Skip (not Fail). The SKIPPED token is
    // the load-bearing assertion; missing-lite alone does not raise
    // doctor's exit code to `1`.
    assert!(
        stdout.contains("lite image present"),
        "C8 row must always appear in verbose mode; got: {stdout}"
    );
    assert!(
        stdout.contains("SKIPPED") || stdout.contains("not built yet"),
        "missing lite image must render as SKIPPED / `not built yet` (informational); \
         got: {stdout}"
    );
    // Exit code must not be raised because of C8 alone. Other
    // checks (e.g. C7, C9) may still trip exit code 1 on a CI host
    // lacking the gateway image or the cap'd route helper, so we
    // assert the more falsifiable "exit code is 0 OR 1 — never 2".
    assert!(
        exit_code == 0 || exit_code == 1,
        "doctor exit code must be 0 or 1 (never 2 — doctor-itself-broken); got {exit_code}"
    );
}

// ---------------------------------------------------------------------------
// Test 4 — doctor full happy-path against a running daemon
// ---------------------------------------------------------------------------

/// Spawn a daemon and run `sandbox doctor --verbose`. Assert:
///
/// - the summary line is always present, with three integer counts;
/// - the header line ("sandbox doctor — checking deployment") leads;
/// - the C1, C2, C3 rows all appear in verbose mode (regardless of
///   their individual pass/fail outcomes).
///
/// We do not assert exit code `0` here because the daemon's host may
/// be missing the gateway image; that case is covered by the
/// dedicated test above. The contract pinned here is "doctor runs to
/// completion against a real daemon and emits the design-shaped
/// output".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_doctor_full_pass_against_running_daemon() {
    let daemon = Daemon::spawn("10.234.0.0/24");

    let output = std::process::Command::new(sandbox_cli_bin())
        .arg("--socket")
        .arg(&daemon.socket)
        .arg("doctor")
        .arg("--verbose")
        .output()
        .expect("spawn sandbox doctor");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let exit_code = output.status.code().expect("exited normally");

    // Header line — load-bearing token from.3.
    assert!(
        stdout.contains("sandbox doctor \u{2014} checking deployment"),
        "header line must match.3; got: {stdout}"
    );

    // The first three rows all show up in verbose mode regardless
    // of their outcome.
    assert!(
        stdout.contains("daemon process running"),
        "C1 row must render; got: {stdout}"
    );
    assert!(
        stdout.contains("daemon reachable"),
        "C2 row must render; got: {stdout}"
    );
    assert!(
        stdout.contains("CLI \u{2194} daemon version match"),
        "C3 row must render; got: {stdout}"
    );

    // Summary line shape: "N checks passed, M failed, K skipped".
    assert!(
        stdout.contains("checks passed,"),
        "summary line must contain `checks passed,`; got: {stdout}"
    );
    assert!(
        stdout.contains(" failed,") && stdout.contains(" skipped"),
        "summary line must contain `failed,` and `skipped`; got: {stdout}"
    );

    // Exit code must be 0 or 1 — never 2 (doctor-itself-broken).
    assert!(
        exit_code == 0 || exit_code == 1,
        "doctor exit code must be 0 or 1 against a running daemon; got {exit_code}"
    );
}

// ---------------------------------------------------------------------------
// Test 5 — KVM check surfaces through /diagnostics
// ---------------------------------------------------------------------------

/// `GET /diagnostics` must include `kvm_readable` and `kvm_writable`
/// fields evaluated daemon-side. The doctor's C6 check reads these
/// to determine whether the daemon's uid can access `/dev/kvm` —
/// the operative question for whether the daemon can run Lima VMs.
/// The CLI's own uid is irrelevant to this check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_kvm_check_via_daemon_diagnostics() {
    let daemon = Daemon::spawn("10.235.0.0/24");

    let (status, body) = http_get(&daemon.socket, "/diagnostics", Duration::from_secs(10)).await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "GET /diagnostics must return 200 OK; got {status}, body={:?}",
        String::from_utf8_lossy(&body)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("body parses as JSON");

    // Both fields must be present and boolean — even if /dev/kvm
    // is absent on the test host (CI containers), the daemon
    // returns `false`/`false` rather than omitting the fields.
    let readable = parsed.get("kvm_readable").and_then(|v| v.as_bool());
    let writable = parsed.get("kvm_writable").and_then(|v| v.as_bool());
    assert!(
        readable.is_some(),
        "kvm_readable must be present + boolean; body={parsed}"
    );
    assert!(
        writable.is_some(),
        "kvm_writable must be present + boolean; body={parsed}"
    );

    // `GET /diagnostics` returns these keys. Pin them here so a
    // regression that renames or drops one fails this test loudly.
    // The `*_probe_failed` / `*_probe_error` companions were added
    // to the contract so doctor C7/C8 can
    // `probe_failed` variant must also appear so doctor C7/C8 can
    // distinguish "image absent" from "probe could not run".
    for key in [
        "daemon_uid",
        "daemon_user",
        "kvm_readable",
        "kvm_writable",
        "gateway_image_present",
        "lite_image_present",
        "gateway_image_probe_failed",
        "lite_image_probe_failed",
        "gateway_image_probe_error",
        "lite_image_probe_error",
        "users_conf_pool",
        "guest_version_drift",
        "substrate_orphans",
    ] {
        assert!(
            parsed.get(key).is_some(),
            "`{key}` must appear in /diagnostics body; body={parsed}"
        );
    }
}
