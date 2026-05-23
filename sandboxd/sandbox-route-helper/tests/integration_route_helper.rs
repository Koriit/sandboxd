//! Deny-branch integration tests for `sandbox-route-helper`.
//!
//! All three tests follow the same outer shape:
//!
//! 1. Locate the installed helper binary at the canonical test
//!    install path `/usr/local/libexec/sandboxd-test/sandbox-route-helper`
//!    (FHS § 4.7-aligned; `sandboxd-test` is a sibling of the
//!    production `sandboxd/` libexec directory so test installs do
//!    not clobber a real production binary).
//! 2. Verify that the installed binary (a) exists, (b) carries
//!    `cap_sys_admin+ep`, and (c) has a SHA-256 checksum equal to the
//!    cargo-built binary at `CARGO_BIN_EXE_sandbox-route-helper`. A
//!    checksum mismatch panics with a pointer at the make target so
//!    the operator knows how to refresh the install.
//! 3. Drop a tempfile users.conf into place; point the helper at it
//!    via the `SANDBOX_USERS_CONF` env var. The installed test
//!    binary is built with the `test-env-override` Cargo feature
//!    (see `make install-route-helper-test-cap`), which is the only
//!    build of the route helper that consults the env var — default
//!    production builds ignore it (privilege boundary).
//! 4. Run the helper, capture exit status + stderr, assert on the
//!    expected substring.
//!
//! The third test (`netns_ip_outside_caller_subnet`) additionally
//! spins up a real Docker container in an isolated bridge network so
//! it can give the helper a live `pidfd_open` target whose netns IPs
//! are *outside* the caller's `users.conf` subnet. Cleanup is RAII
//! per the `TestContainer` pattern in `sandbox-core/tests/validators.rs`.
//!
//! ## Why no per-test setcap
//!
//! Pre-S9 each test copied the cargo-built binary to `/tmp` and
//! `sudo setcap`'d the copy. That worked but:
//!
//!  - Required `sudo` per test (slow; flaky on systems with NOPASSWD
//!    timing).
//!  - Race-prone: parallel test execution under nextest could blow
//!    away another test's tempfile path.
//!  - Hid the install path / cap requirements from the operator —
//!    the tests carried their own `setcap` invocation that did not
//!    match the production install runbook.
//!
//! Cap installation lives in a make target
//! (`install-route-helper-test-cap`) that is run once before
//! `make test-integration`. The tests verify the install is fresh
//! (checksum match) and bail with an actionable error if it is
//! stale, but do not invoke `sudo` themselves.
//!
//! ## Profile selection
//!
//! Each test name is prefixed `integration_route_helper_` so the
//! `integration` nextest profile (`sandboxd/.config/nextest.toml`)
//! picks them up via its `test(/^integration_/)` filter, and the
//! default profile filters them out. No `#[ignore]`, no env gate —
//! membership is self-describing at the call site.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Path to the freshly-built helper binary. Cargo populates this env
/// var for every integration test in this crate; the binary is
/// (re)built before the test runs. We use it for the checksum side of
/// the freshness check below — the cargo binary is NEVER executed
/// directly by the integration tests (it is uncap'd, would fail at
/// `setns(2)` with EPERM), only checksummed.
fn cargo_bin_helper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandbox-route-helper"))
}

/// Canonical test install path (`make install-route-helper-test-cap`
/// installs here). `sandboxd-test` is deliberately a separate libexec
/// directory from production `sandboxd/` so a `make
/// install-route-helper-prod-cap` run does not silently overwrite the
/// test binary (which carries the `test-env-override` feature) with
/// a production build (which does not).
const INSTALLED_TEST_HELPER_PATH: &str = "/usr/local/libexec/sandboxd-test/sandbox-route-helper";

/// Compute SHA-256 of a file. Used to verify the installed binary is
/// in sync with the cargo-built one — a mismatch means the operator
/// rebuilt the workspace but forgot to re-run
/// `make install-route-helper-test-cap`, and we'd otherwise be
/// running an outdated cap'd binary.
fn sha256_file(path: &Path) -> [u8; 32] {
    use ring::digest::{Context, SHA256};
    let mut f = std::fs::File::open(path)
        .unwrap_or_else(|e| panic!("open {} for checksum: {e}", path.display()));
    let mut ctx = Context::new(&SHA256);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .unwrap_or_else(|e| panic!("read {} for checksum: {e}", path.display()));
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let digest = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Verify the installed test helper exists, has caps, and matches the
/// cargo build. Returns the verified path on success; panics with an
/// actionable message otherwise. Called once at the top of each test.
///
/// The three checks lined up:
///  - Existence: `/usr/local/libexec/sandboxd-test/sandbox-route-helper`
///    must be a regular file. Missing → `make install-route-helper-test-cap`.
///  - Capability: `getcap` output must contain `cap_sys_admin=ep`.
///    Present-but-no-cap → setcap was not run after install.
///  - Checksum: SHA-256 must equal the cargo-built binary's SHA-256.
///    Mismatch → operator rebuilt without re-installing.
fn verify_installed_test_helper() -> PathBuf {
    let installed = PathBuf::from(INSTALLED_TEST_HELPER_PATH);
    if !installed.is_file() {
        panic!(
            "installed test route helper not found at {}\n\
             run: make install-route-helper-test-cap",
            installed.display()
        );
    }

    // Cap check via `getcap`. We could read security.capability via
    // libc::getxattr ourselves (the daemon's resolver does that for
    // production), but `getcap` is universally present on Linux test
    // hosts and produces a self-explanatory line that we can show in
    // the panic message verbatim.
    let getcap = Command::new("getcap")
        .arg(&installed)
        .output()
        .unwrap_or_else(|e| panic!("invoking getcap on {}: {e}", installed.display()));
    let cap_output = String::from_utf8_lossy(&getcap.stdout);
    if !cap_output.contains("cap_sys_admin") || !cap_output.contains("cap_net_admin") {
        panic!(
            "installed test route helper at {} lacks cap_sys_admin and/or cap_net_admin \
             (getcap stdout: {:?})\n\
             run: make install-route-helper-test-cap",
            installed.display(),
            cap_output,
        );
    }

    let installed_hash = sha256_file(&installed);
    let cargo_hash = sha256_file(&cargo_bin_helper_path());
    if installed_hash != cargo_hash {
        panic!(
            "installed route helper is stale; run: make install-route-helper-test-cap\n\
             installed: {} (sha256={})\n\
             cargo:     {} (sha256={})",
            installed.display(),
            hex(&installed_hash),
            cargo_bin_helper_path().display(),
            hex(&cargo_hash),
        );
    }

    installed
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Resolve the test runner's username. Used to populate `allow_users`
/// in the fixtures where the test wants the auth check to *pass* (so
/// it can fall through to a later step).
fn runner_username() -> String {
    let output = Command::new("id")
        .arg("-un")
        .output()
        .expect("`id -un` should succeed");
    assert!(output.status.success(), "`id -un` exit non-zero");
    String::from_utf8(output.stdout)
        .expect("`id -un` output is utf-8")
        .trim()
        .to_string()
}

/// Resolve the test runner's numeric uid as a string. Used by the
/// fault-injection tests where the caller-uid lookup is forced to fail
/// and the helper records `uid:<n>` as the placeholder `caller`.
fn runner_uid_string() -> String {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .expect("`id -u` should succeed");
    assert!(output.status.success(), "`id -u` exit non-zero");
    String::from_utf8(output.stdout)
        .expect("`id -u` output is utf-8")
        .trim()
        .to_string()
}

/// Write `contents` to a tempfile and return it. The tempfile owns
/// the on-disk path and removes it on drop.
fn write_users_conf(contents: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tempfile");
    f.write_all(contents.as_bytes()).expect("write users.conf");
    f.flush().expect("flush users.conf");
    f
}

/// Run the cap'd installed helper with the given argv, pointing at
/// the given users.conf tempfile via `SANDBOX_USERS_CONF`. The
/// helper is the test-feature build (made by
/// `install-route-helper-test-cap`), so it consults the env var.
///
/// This variant additionally redirects the audit log to a per-test
/// tempdir so concurrent test runs (and the host's persistent
/// `$XDG_RUNTIME_DIR/sandboxd/route-helper-audit.log`) do not
/// interfere. Callers that don't care about the audit-log content can
/// ignore the returned tempdir; it cleans up on drop. Callers that
/// want to inspect the audit record use [`run_helper_with_audit`].
fn run_helper(helper: &Path, users_conf: &NamedTempFile, args: &[&str]) -> Output {
    let (_audit_dir, audit_path) = make_audit_log_path();
    Command::new(helper)
        .args(args)
        .env("SANDBOX_USERS_CONF", users_conf.path())
        .env("SANDBOX_ROUTE_HELPER_AUDIT_LOG", &audit_path)
        .output()
        .expect("invoking helper should succeed")
}

/// Run the cap'd installed helper with an audit-log tempfile path
/// injected via `SANDBOX_ROUTE_HELPER_AUDIT_LOG`. The helper test build
/// (`test-env-override`) honors that env var — production builds
/// ignore it (same privilege story as `SANDBOX_USERS_CONF`).
///
/// Returns `(Output, audit_lines)` where `audit_lines` is the parsed
/// JSON-Lines content of the audit-log file after the helper exits.
/// The caller asserts on both surfaces (subprocess exit code + audit
/// records).
fn run_helper_with_audit(
    helper: &Path,
    users_conf: &NamedTempFile,
    audit_log_path: &Path,
    args: &[&str],
) -> (Output, Vec<serde_json::Value>) {
    let output = Command::new(helper)
        .args(args)
        .env("SANDBOX_USERS_CONF", users_conf.path())
        .env("SANDBOX_ROUTE_HELPER_AUDIT_LOG", audit_log_path)
        .output()
        .expect("invoking helper should succeed");
    let audit_lines = read_audit_log_lines(audit_log_path);
    (output, audit_lines)
}

/// Which `User::*` call the fault-injection env var targets. Mirrors
/// the helper-side `InjectionSite` enum.
enum InjectionSite {
    CallerUid,
    ForUser,
}

impl InjectionSite {
    fn as_str(&self) -> &'static str {
        match self {
            InjectionSite::CallerUid => "caller_uid",
            InjectionSite::ForUser => "for_user",
        }
    }
}

/// Run the cap'd installed helper with both an audit-log tempfile and
/// a `SANDBOX_ROUTE_HELPER_TEST_INJECT_USER_RESOLUTION_ERROR=<site>:<errno>`
/// injection. The test-feature build honors that env var by failing
/// the targeted `User::from_uid` / `User::from_name` call with the
/// given errno, letting the integration tests exercise the
/// `caller-uid-resolution-error` and `for-user-resolution-error`
/// audit branches deterministically. Production builds ignore the
/// var (same privilege story as the other test-only env vars).
fn run_helper_with_user_resolution_error_injected(
    helper: &Path,
    users_conf: &NamedTempFile,
    audit_log_path: &Path,
    site: InjectionSite,
    inject_errno: i32,
    args: &[&str],
) -> (Output, Vec<serde_json::Value>) {
    let injection = format!("{}:{}", site.as_str(), inject_errno);
    let output = Command::new(helper)
        .args(args)
        .env("SANDBOX_USERS_CONF", users_conf.path())
        .env("SANDBOX_ROUTE_HELPER_AUDIT_LOG", audit_log_path)
        .env(
            "SANDBOX_ROUTE_HELPER_TEST_INJECT_USER_RESOLUTION_ERROR",
            injection,
        )
        .output()
        .expect("invoking helper should succeed");
    let audit_lines = read_audit_log_lines(audit_log_path);
    (output, audit_lines)
}

/// Parse the audit-log file (JSON-Lines) and return one `Value` per
/// non-empty line. Returns an empty Vec if the file does not yet exist
/// (the helper denied so early it could not write a record) — callers
/// distinguish "audit log empty" from "audit log absent" via this Vec's
/// length.
fn read_audit_log_lines(path: &Path) -> Vec<serde_json::Value> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("audit-log line is not JSON: {line:?} err={e}"))
        })
        .collect()
}

/// Path to an audit-log file under a fresh tempdir. Returns the tempdir
/// (kept alive by the caller so it is not removed mid-test) and the
/// audit-log path inside it. Each integration test owns its own
/// tempdir so parallel runs do not collide on a shared file.
fn make_audit_log_path() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("audit-log tempdir");
    let path = dir.path().join("route-helper-audit.log");
    (dir, path)
}

// ---------------------------------------------------------------------------
// Test 1 — gateway IP outside all configured subnets (denies at step 3)
// ---------------------------------------------------------------------------

/// Verifies the step-3 deny branch: the helper denies before any
/// netns operation when the gateway IP is not contained by any
/// `subnets[].cidr` in users.conf. The pid value is irrelevant — the
/// helper exits before reaching `pidfd_open`.
#[test]
fn integration_route_helper_denies_when_gateway_ip_outside_all_subnets() {
    let helper = verify_installed_test_helper();
    let user = runner_username();

    let users_conf = write_users_conf(&format!(
        r#"{{
            "subnets": [
                {{ "cidr": "10.209.0.0/20", "allow_users": ["{user}"] }}
            ]
        }}"#
    ));

    // Gateway IP 198.18.0.5 is outside the only configured subnet
    // (10.209.0.0/20). RFC 2544 benchmark-reserved range chosen so
    // it cannot collide with any real subnet on the host. Pid 1 (init)
    // — irrelevant; helper denies at step 3 before pidfd_open runs.
    let output = run_helper(&helper, &users_conf, &["1", "198.18.0.5"]);

    assert!(
        !output.status.success(),
        "helper must deny; got exit success. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not in any subnet"),
        "stderr must contain 'not in any subnet'; got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — caller uid not in subnet's allow_users (denies at pair-check)
// ---------------------------------------------------------------------------

/// Verifies the pair-check deny branch: the gateway IP IS inside a
/// configured subnet, but that subnet's `allow_users` does not contain
/// any name that resolves to the caller's uid (nor the implicit
/// `--for-user=<caller>`). Helper denies before any netns operation
/// with the stderr substring `pair-check failed` naming both
/// identities.
#[test]
fn integration_route_helper_denies_when_caller_not_in_allow_users() {
    let helper = verify_installed_test_helper();

    // allow_users intentionally lists a username that does not exist
    // on the host (the same sentinel name the loader's unit tests use,
    // for the same reason — `getpwnam_r` returns Ok(None) and the
    // name is treated as a non-match).
    let users_conf = write_users_conf(
        r#"{
            "_schema_version": 1,
            "subnets": [
                {
                    "cidr": "10.209.0.0/20",
                    "allow_users": ["definitely-not-a-real-user-9c3f"]
                }
            ]
        }"#,
    );

    // Gateway IP 10.209.0.2 IS inside the subnet — gateway-lookup
    // passes — but neither the caller's uid nor the implicit
    // `--for-user=<caller>` matches the bogus allow_users entry.
    let output = run_helper(&helper, &users_conf, &["1", "10.209.0.2"]);

    assert!(
        !output.status.success(),
        "helper must deny; got exit success. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let runner = runner_username();
    assert!(
        stderr.contains("pair-check failed"),
        "stderr must contain 'pair-check failed'; got: {stderr}"
    );
    //
    // for forensic clarity.
    assert!(
        stderr.contains(&format!("caller={runner}")),
        "stderr must include caller={runner}; got: {stderr}"
    );
    assert!(
        stderr.contains(&format!("for-user={runner}")),
        "stderr must include for-user={runner} (defaulted from caller); got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — netns address outside caller subnet (denies at step 6)
// ---------------------------------------------------------------------------

/// Bridge-network + container fixture for the step-6 deny test.
///
/// Spins up a Docker bridge network with a known subnet outside the
/// users.conf range, runs a long-sleeping container on it, and
/// exposes the container's host-namespace pid + name for the test
/// body. RAII Drop runs `docker stop` + `docker rm -f` + `docker
/// network rm` in order — each best-effort, swallowing errors so a
/// stop on an already-exited container does not panic.
///
/// Network name carries a `<nanos>` suffix so concurrent test
/// invocations on the same host (cargo nextest's parallel runner)
/// cannot collide.
struct TestNetnsContainer {
    container_name: String,
    network_name: String,
    container_pid: i32,
}

impl TestNetnsContainer {
    /// Spin up a bridge network with `subnet` (e.g. `"198.18.0.0/24"`)
    /// and a container attached to it running `sleep 60`. Panics on
    /// any setup failure — Drop will still tear down whatever was
    /// successfully created.
    fn spawn(subnet: &str) -> Self {
        // Make sure busybox:latest is available. `docker pull` is a
        // no-op if the image is already cached, so we always run it
        // — much more robust than image-presence detection logic.
        let pull = Command::new("docker")
            .args(["pull", "busybox:latest"])
            .output()
            .expect("docker pull should be invokable");
        assert!(
            pull.status.success(),
            "docker pull busybox:latest failed: stderr={}",
            String::from_utf8_lossy(&pull.stderr)
        );

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let network_name = format!("sb-routehelper-test-{nanos}");
        let container_name = format!("sb-routehelper-ctr-{nanos}");

        // Bridge network with the requested subnet — IPAM puts the
        // container at .2 (gateway is .1). We don't care which IP the
        // container gets so long as it lives in `subnet`.
        let net = Command::new("docker")
            .args([
                "network",
                "create",
                "--driver",
                "bridge",
                "--subnet",
                subnet,
                &network_name,
            ])
            .output()
            .expect("docker network create should be invokable");
        assert!(
            net.status.success(),
            "docker network create failed: stderr={}",
            String::from_utf8_lossy(&net.stderr)
        );

        // Construct the container; --rm so it self-deletes on stop.
        // sleep 60 gives the test plenty of time even on a slow box.
        //
        // `--user <uid>:<gid>` makes the container's task credentials
        // match the test runner's. Under rootful Docker, the helper's
        // `setns(pidfd, CLONE_NEWNET)` is gated by
        // `ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)`,
        // which checks both real uid AND real gid: a uid match alone
        // is not enough — gid must also match (or the caller must
        // hold `CAP_SYS_PTRACE`, which we deliberately do not grant).
        // Passing only `--user <uid>` leaves gid at the busybox
        // image default (root, 0), so the gid check fails and setns
        // returns EPERM. Production containers spawned by sandboxd
        // already pass `--user 1000:1000` (matching the daemon's
        // uid:gid), which is why the production path works.
        let uid = nix::unistd::Uid::current().as_raw();
        let gid = nix::unistd::Gid::current().as_raw();
        let user_arg = format!("{uid}:{gid}");
        let run = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &container_name,
                "--network",
                &network_name,
                "--user",
                &user_arg,
                "busybox:latest",
                "sleep",
                "60",
            ])
            .output()
            .expect("docker run should be invokable");
        if !run.status.success() {
            // Network was created but container failed — clean up the
            // network manually before bailing, since Self isn't built
            // yet so Drop won't run.
            let _ = Command::new("docker")
                .args(["network", "rm", &network_name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            panic!(
                "docker run failed: stderr={}",
                String::from_utf8_lossy(&run.stderr)
            );
        }

        // Read the host-namespace pid for the helper to pidfd_open.
        let inspect = Command::new("docker")
            .args(["inspect", "-f", "{{.State.Pid}}", &container_name])
            .output()
            .expect("docker inspect should be invokable");
        assert!(
            inspect.status.success(),
            "docker inspect failed: stderr={}",
            String::from_utf8_lossy(&inspect.stderr)
        );
        let pid_str = String::from_utf8_lossy(&inspect.stdout);
        let container_pid: i32 = pid_str
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("docker inspect returned non-integer pid: {pid_str:?}"));

        Self {
            container_name,
            network_name,
            container_pid,
        }
    }
}

impl Drop for TestNetnsContainer {
    fn drop(&mut self) {
        // Best-effort, ordered teardown. Drop must not panic.
        let _ = Command::new("docker")
            .args(["stop", "-t", "1", &self.container_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        // Network removal must come after the container is gone —
        // docker refuses to remove a network with attached endpoints.
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Verifies the step-6 deny branch: the caller is authorized (steps
/// 3 + 4 pass) and the helper successfully enters the netns (step 5),
/// but the netns has at least one IPv4 address outside the caller's
/// subnet, so the helper denies before installing the route.
///
/// Also verifies that the container's default route was NOT modified
/// — the docker-managed default (`via 198.18.0.1`) must still be in
/// place.
///
/// # Why 198.18.0.0/24
///
/// RFC 2544 reserves `198.18.0.0/15` for inter-network device
/// benchmarking. It is structurally guaranteed not to be used as a
/// production subnet (the IETF carved it out specifically to be
/// uninteresting for routing), so it cannot collide with the
/// daemon's allocator pool (default `10.209.0.0/24`) or with any
/// other test's subnet, even if they run in parallel on the same
/// host. The previous shape used `10.250.0.0/24`, which is private
/// space but only conventionally — an operator who happens to use
/// `10.250.0.0/16` for a real network would see this test interfere.
#[test]
fn integration_route_helper_denies_when_netns_ip_outside_caller_subnet() {
    let helper = verify_installed_test_helper();
    let user = runner_username();

    // Container lives on 198.18.0.0/24. users.conf authorizes the
    // caller for 10.209.0.0/20 — well outside the container's bridge
    // — so step 6 will see `eth0` carrying 198.18.0.2 and deny.
    let fixture = TestNetnsContainer::spawn("198.18.0.0/24");

    let users_conf = write_users_conf(&format!(
        r#"{{
            "subnets": [
                {{ "cidr": "10.209.0.0/20", "allow_users": ["{user}"] }}
            ]
        }}"#
    ));

    // Gateway IP inside the caller's subnet, so steps 3 + 4 pass.
    // Container pid is the live pid we just inspected.
    let pid_str = fixture.container_pid.to_string();
    let output = run_helper(&helper, &users_conf, &[&pid_str, "10.209.0.2"]);

    assert!(
        !output.status.success(),
        "helper must deny; got exit success. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("outside caller subnet"),
        "stderr must contain 'outside caller subnet'; got: {stderr}"
    );

    // Verify the container's default route was NOT modified — the
    // docker-installed default via 198.18.0.1 must still be the
    // active default route. If the helper had erroneously installed
    // `default via 10.209.0.2`, that string would appear in the
    // route table.
    let route = Command::new("docker")
        .args([
            "exec",
            &fixture.container_name,
            "ip",
            "route",
            "show",
            "default",
        ])
        .output()
        .expect("docker exec ip route should succeed");
    assert!(
        route.status.success(),
        "docker exec ip route show default failed: stderr={}",
        String::from_utf8_lossy(&route.stderr)
    );
    let route_text = String::from_utf8_lossy(&route.stdout);
    assert!(
        !route_text.contains("10.209.0.2"),
        "container default route was modified by the helper; \
         expected no '10.209.0.2', got: {route_text}"
    );
    assert!(
        route_text.contains("198.18.0.1"),
        "container should still have the docker-installed default \
         via 198.18.0.1; got: {route_text}"
    );
}

// ---------------------------------------------------------------------------
// Pair-check + audit log tests —.4
// ---------------------------------------------------------------------------

/// Spin up a Docker container on a bridge whose subnet matches the
/// `users.conf` pool, returning the container fixture, the bridge
/// CIDR (matching the users.conf pool), and the gateway IP. Used by
/// the "allow path" pair-check tests below to drive the helper
/// through to a successful route install.
///
/// Each test should pass a distinct `subnet` so cargo-nextest's
/// parallel execution does not collide on the bridge's IPAM pool
/// (Docker refuses to create a network whose subnet overlaps an
/// existing one). The pool used by the calling test must allow the
/// runner for that subnet.
fn spawn_allow_path_container(subnet: &str) -> TestNetnsContainer {
    TestNetnsContainer::spawn(subnet)
}

/// Render a users.conf with a single subnet at `cidr` whose
/// `allow_users` is the supplied slice. The `_schema_version` field is
/// present so the fixture exercises the post-V001 schema shape; this
/// also pins the requirement that the route helper continues to parse
/// post-V001 files.
fn users_conf_for_pool(cidr: &str, allow_users: &[&str]) -> NamedTempFile {
    let names: Vec<String> = allow_users.iter().map(|n| format!("\"{n}\"")).collect();
    write_users_conf(&format!(
        r#"{{
            "_schema_version": 1,
            "subnets": [
                {{ "cidr": "{cidr}", "allow_users": [{}] }}
            ]
        }}"#,
        names.join(", ")
    ))
}

/// Find the (expected single) audit-log record in `lines` and assert
/// the audit-record field schema: `decision`, `caller`, `for_user`,
/// `gateway_ip`, `pid` always present; `pool` present iff
/// gateway-ip-in-subnet (left to the caller to assert); `reason`
/// present iff `decision == "denied"`; `ts` parseable as RFC 3339 UTC.
fn assert_audit_record_shape(
    lines: &[serde_json::Value],
    expected_decision: &str,
    expected_caller: &str,
    expected_for_user: &str,
    expected_pid: i32,
) -> serde_json::Value {
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one audit-log line; got {} lines: {:?}",
        lines.len(),
        lines
    );
    let r = &lines[0];
    let ts = r["ts"]
        .as_str()
        .unwrap_or_else(|| panic!("audit record missing `ts`: {r}"));
    // RFC 3339 parse (chrono accepts both `Z` and `+00:00` suffixes).
    chrono::DateTime::parse_from_rfc3339(ts)
        .unwrap_or_else(|e| panic!("audit `ts` not RFC 3339: {ts:?} err={e}"));
    assert_eq!(
        r["decision"].as_str(),
        Some(expected_decision),
        "audit record decision mismatch: {r}"
    );
    assert_eq!(
        r["caller"].as_str(),
        Some(expected_caller),
        "audit record caller mismatch: {r}"
    );
    assert_eq!(
        r["for_user"].as_str(),
        Some(expected_for_user),
        "audit record for_user mismatch: {r}"
    );
    assert_eq!(
        r["pid"].as_i64(),
        Some(expected_pid as i64),
        "audit record pid mismatch: {r}"
    );
    // `reason` field presence is decision-conditional per.5.
    match expected_decision {
        "allowed" => assert!(
            r.get("reason").is_none(),
            "allowed audit record must NOT carry `reason`; got: {r}"
        ),
        "denied" => assert!(
            r.get("reason").and_then(|v| v.as_str()).is_some(),
            "denied audit record must carry `reason`; got: {r}"
        ),
        other => panic!("unexpected expected_decision: {other}"),
    }
    r.clone()
}

// ---------------------------------------------------------------------------
// Allow path — `--for-user=<runner>`, matching caller
// ---------------------------------------------------------------------------

/// Helper runs end-to-end with an explicit `--for-user=<runner>` that
/// matches the caller's runtime uid; pool contains the runner; expect
/// exit 0, allowed audit-log line, route installed inside the
/// container's netns.
#[test]
fn integration_route_helper_accepts_for_user_matching_caller() {
    let helper = verify_installed_test_helper();
    let runner = runner_username();
    // RFC 2544 benchmarking range — guaranteed not to overlap other
    // tests' bridges. Each allow-path test uses a distinct /24 so
    // parallel runs cannot collide on Docker's IPAM.
    let subnet = "198.19.10.0/24";
    let gateway_ip = "198.19.10.1";
    let fixture = spawn_allow_path_container(subnet);
    let users_conf = users_conf_for_pool(subnet, &[runner.as_str()]);
    let (audit_dir, audit_path) = make_audit_log_path();
    // `audit_dir` must outlive the helper invocation; bind so it isn't
    // dropped on the same line.
    let _audit_keep = audit_dir;

    let pid_str = fixture.container_pid.to_string();
    let (output, audit_lines) = run_helper_with_audit(
        &helper,
        &users_conf,
        &audit_path,
        &["--for-user", &runner, &pid_str, gateway_ip],
    );

    assert!(
        output.status.success(),
        "helper must allow; got exit failure. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let record = assert_audit_record_shape(
        &audit_lines,
        "allowed",
        &runner,
        &runner,
        fixture.container_pid,
    );
    assert_eq!(
        record["pool"].as_str(),
        Some(subnet),
        "audit pool field mismatch: {record}"
    );
    assert_eq!(
        record["gateway_ip"].as_str(),
        Some(gateway_ip),
        "audit gateway_ip field mismatch: {record}"
    );

    // Verify the route landed: container default route now points at
    // the helper-installed gateway. The pre-test default (docker's own
    // `10.209.0.1`) coincidentally matches our gateway; to confirm the
    // helper actually ran a `replace`, we read the stdout which the
    // helper emits on success (step 8).
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("route installed"),
        "helper stdout must confirm route install; got: {stdout}"
    );

    let route = Command::new("docker")
        .args([
            "exec",
            &fixture.container_name,
            "ip",
            "route",
            "show",
            "default",
        ])
        .output()
        .expect("docker exec ip route should succeed");
    let route_text = String::from_utf8_lossy(&route.stdout);
    assert!(
        route_text.contains(gateway_ip),
        "container default route must point at the helper-installed gateway {gateway_ip}; got: {route_text}"
    );
}

// ---------------------------------------------------------------------------
// Deny path — `--for-user=<other>` mismatches the runner
// ---------------------------------------------------------------------------

/// Helper runs with `--for-user` set to a name OTHER than the runner;
/// pool contains ONLY the runner. Pair-check denies because for-user
/// is not in `allow_users`. The deny path also exercises the
/// stderr substring (`pair-check failed`) and the audit-record
/// `decision="denied"` + `reason` field.
#[test]
fn integration_route_helper_denies_for_user_mismatch() {
    let helper = verify_installed_test_helper();
    let runner = runner_username();
    // `root` always resolves (uid 0) on every supported host, so
    // `for_user_uid` lookup succeeds — the deny happens at pair-check,
    // not at name-resolution. We deliberately pick a name that is
    // never the runner to keep the test stable regardless of who runs
    // it. (If a test host happens to log in as `root`, the test fails
    // its precondition assertion below before invoking the helper.)
    let other = "root";
    assert_ne!(
        runner, other,
        "test precondition: runner must not be `root` for the mismatch case"
    );
    // This deny test never creates a Docker bridge — the helper exits
    // at pair-check long before pidfd_open. The CIDR here matches
    // only the users.conf pool naming for the audit record's `pool`
    // field; the gateway IP `10.209.0.2` must lie inside it.
    let users_conf = users_conf_for_pool("10.209.0.0/24", &[runner.as_str()]);
    let (audit_dir, audit_path) = make_audit_log_path();
    let _audit_keep = audit_dir;

    let (output, audit_lines) = run_helper_with_audit(
        &helper,
        &users_conf,
        &audit_path,
        // Pid 1 / gateway 10.209.0.2 — pid is irrelevant because the
        // pair-check exits before reaching pidfd_open.
        &["--for-user", other, "1", "10.209.0.2"],
    );

    assert!(
        !output.status.success(),
        "helper must deny; got exit success. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("pair-check failed"),
        "stderr must contain 'pair-check failed'; got: {stderr}"
    );
    assert!(
        stderr.contains(&format!("caller={runner}")),
        "stderr must name caller={runner}; got: {stderr}"
    );
    assert!(
        stderr.contains(&format!("for-user={other}")),
        "stderr must name for-user={other}; got: {stderr}"
    );

    let record = assert_audit_record_shape(&audit_lines, "denied", &runner, other, 1);
    assert_eq!(
        record["reason"].as_str(),
        Some("pair-check failed"),
        "audit `reason` must be 'pair-check failed'; got: {record}"
    );
    assert_eq!(
        record["pool"].as_str(),
        Some("10.209.0.0/24"),
        "audit `pool` must name the chosen subnet on pair-check deny; got: {record}"
    );
}

// ---------------------------------------------------------------------------
// Default `--for-user` path — omitting the flag
// ---------------------------------------------------------------------------

/// Helper runs WITHOUT `--for-user`; the flag defaults to the caller's
/// name per.1, so pair-check is `(runner, runner)` against
/// `[runner]` and succeeds. Otherwise identical to the explicit-flag
/// allow-path test.
#[test]
fn integration_route_helper_defaults_for_user_to_caller_when_omitted() {
    let helper = verify_installed_test_helper();
    let runner = runner_username();
    // Distinct /24 from the other allow-path tests to avoid Docker IPAM
    // pool-overlap when nextest runs them in parallel.
    let subnet = "198.19.11.0/24";
    let gateway_ip = "198.19.11.1";
    let fixture = spawn_allow_path_container(subnet);
    let users_conf = users_conf_for_pool(subnet, &[runner.as_str()]);
    let (audit_dir, audit_path) = make_audit_log_path();
    let _audit_keep = audit_dir;

    let pid_str = fixture.container_pid.to_string();
    let (output, audit_lines) = run_helper_with_audit(
        &helper,
        &users_conf,
        &audit_path,
        // Note: no --for-user flag here.
        &[&pid_str, gateway_ip],
    );

    assert!(
        output.status.success(),
        "helper must allow; got exit failure. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Both `caller` and `for_user` are the runner — pair-check sees
    // the same uid twice.
    assert_audit_record_shape(
        &audit_lines,
        "allowed",
        &runner,
        &runner,
        fixture.container_pid,
    );
}

// ---------------------------------------------------------------------------
// Caller not in pool — even with a valid `--for-user`
// ---------------------------------------------------------------------------

/// Pool contains a name OTHER than the runner; `--for-user` matches
/// that other name. Pair-check still denies because the caller is not
/// in the pool. Demonstrates that an attacker who controls argv (e.g.
/// a compromised daemon) cannot bypass isolation by
/// asserting a victim's identity — the caller's own identity must
/// also be in the pool.
#[test]
fn integration_route_helper_denies_when_caller_not_in_pool_even_with_valid_for_user() {
    let helper = verify_installed_test_helper();
    // Pool authorizes only `root` (uid 0). The runner is not root
    // (asserted), so the pair-check denies even though `for_user`
    // resolves cleanly and is in the pool.
    let runner = runner_username();
    assert_ne!(
        runner, "root",
        "test precondition: runner must not be `root` for this caller-not-in-pool case"
    );
    let users_conf = users_conf_for_pool("10.209.0.0/24", &["root"]);
    let (audit_dir, audit_path) = make_audit_log_path();
    let _audit_keep = audit_dir;

    let (output, audit_lines) = run_helper_with_audit(
        &helper,
        &users_conf,
        &audit_path,
        &["--for-user", "root", "1", "10.209.0.2"],
    );

    assert!(
        !output.status.success(),
        "helper must deny; got exit success. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("pair-check failed"),
        "stderr must contain 'pair-check failed'; got: {stderr}"
    );
    let record = assert_audit_record_shape(&audit_lines, "denied", &runner, "root", 1);
    assert_eq!(
        record["reason"].as_str(),
        Some("pair-check failed"),
        "audit `reason` must be 'pair-check failed'; got: {record}"
    );
}

// ---------------------------------------------------------------------------
// Unresolvable `--for-user`
// ---------------------------------------------------------------------------

/// `--for-user` is a sentinel name that does not exist on the host.
/// Per.4 this is a strict deny path — the helper denies
/// before reaching pair-check (it cannot even establish the
/// for-user's numeric uid).
#[test]
fn integration_route_helper_denies_when_username_unresolvable() {
    let helper = verify_installed_test_helper();
    let runner = runner_username();
    let users_conf = users_conf_for_pool("10.209.0.0/24", &[runner.as_str()]);
    let (audit_dir, audit_path) = make_audit_log_path();
    let _audit_keep = audit_dir;

    // Sentinel name reused from `sandbox-core/src/users_conf.rs` —
    // every host's `getpwnam_r` returns `Ok(None)` for it.
    let bogus = "definitely-not-a-real-user-9c3f";
    let (output, audit_lines) = run_helper_with_audit(
        &helper,
        &users_conf,
        &audit_path,
        &["--for-user", bogus, "1", "10.209.0.2"],
    );

    assert!(
        !output.status.success(),
        "helper must deny; got exit success. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not resolve to a uid"),
        "stderr must contain 'does not resolve to a uid'; got: {stderr}"
    );

    let record = assert_audit_record_shape(&audit_lines, "denied", &runner, bogus, 1);
    assert_eq!(
        record["reason"].as_str(),
        Some("for-user-unresolvable"),
        "audit `reason` must be 'for-user-unresolvable'; got: {record}"
    );
    // Pool field is absent — the deny happened before the users.conf
    // subnet lookup ran.
    assert!(
        record.get("pool").is_none(),
        "audit `pool` must be absent on for-user-unresolvable deny; got: {record}"
    );
}

// ---------------------------------------------------------------------------
// Non-ENOENT errno on user resolution
// ---------------------------------------------------------------------------
//
// `getpwuid_r` / `getpwnam_r` can return errnos other than `ENOENT` (the
// "no such user" path covered above) — EIO from a downed NSS service,
// ENOMEM under memory pressure, EINTR mid-syscall, etc. None of those
// are reachable deterministically from a hermetic test, so the
// `test-env-override` build of the helper exposes a fault-injection
// seam (`SANDBOX_ROUTE_HELPER_TEST_INJECT_USER_RESOLUTION_ERROR=<site>:<errno>`)
// that forces the targeted `User::from_uid` / `User::from_name` call
// to return `Err(Errno::from_raw(<errno>))`. The `<site>` selector
// (`caller_uid` or `for_user`) lets the two arms be exercised
// independently — without it, the caller-uid lookup (which fires
// first) would mask the for-user arm. Production builds ignore the
// env var (same privilege story as `SANDBOX_USERS_CONF`).

/// Injected `EIO` on the caller-uid `User::from_uid` lookup forces the
/// `caller-uid-resolution-error` audit branch. `EIO` is deliberately
/// not `ENOENT` (5 vs. 2) — `ENOENT` would be collapsed into the
/// `caller-uid-unresolvable` arm by the libc-version fix.
#[test]
fn integration_route_helper_denies_when_caller_uid_resolution_errors() {
    let helper = verify_installed_test_helper();
    let runner = runner_username();
    let users_conf = users_conf_for_pool("10.209.0.0/24", &[runner.as_str()]);
    let (audit_dir, audit_path) = make_audit_log_path();
    let _audit_keep = audit_dir;

    // libc::EIO == 5 on Linux. Using the raw integer keeps the test
    // free of a libc dependency just to name the constant.
    let eio: i32 = 5;
    let (output, audit_lines) = run_helper_with_user_resolution_error_injected(
        &helper,
        &users_conf,
        &audit_path,
        InjectionSite::CallerUid,
        eio,
        &["--for-user", &runner, "1", "10.209.0.2"],
    );

    assert!(
        !output.status.success(),
        "helper must deny; got exit success. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("username resolution failed for uid"),
        "stderr must contain 'username resolution failed for uid'; got: {stderr}"
    );

    // The audit record's `caller` field is the `uid:<n>` placeholder
    // (we couldn't resolve a name); `for_user` is whatever was on the
    // CLI. Pid is the literal `1` argv we passed.
    let placeholder = format!("uid:{}", runner_uid_string());
    let record = assert_audit_record_shape(&audit_lines, "denied", &placeholder, &runner, 1);
    assert_eq!(
        record["reason"].as_str(),
        Some("caller-uid-resolution-error"),
        "audit `reason` must be 'caller-uid-resolution-error'; got: {record}"
    );
    assert!(
        record.get("pool").is_none(),
        "audit `pool` must be absent on caller-uid-resolution-error deny; got: {record}"
    );
}

/// Injected `EIO` on the `--for-user` `User::from_name` lookup forces
/// the `for-user-resolution-error` audit branch. The site selector
/// (`for_user`) makes this independent of the caller-uid lookup, which
/// is allowed to succeed naturally so the helper reaches the
/// for-user-name resolution step.
#[test]
fn integration_route_helper_denies_when_for_user_resolution_errors() {
    let helper = verify_installed_test_helper();
    let runner = runner_username();
    let users_conf = users_conf_for_pool("10.209.0.0/24", &[runner.as_str()]);
    let (audit_dir, audit_path) = make_audit_log_path();
    let _audit_keep = audit_dir;

    let eio: i32 = 5;
    let (output, audit_lines) = run_helper_with_user_resolution_error_injected(
        &helper,
        &users_conf,
        &audit_path,
        InjectionSite::ForUser,
        eio,
        &["--for-user", &runner, "1", "10.209.0.2"],
    );

    assert!(
        !output.status.success(),
        "helper must deny; got exit success. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("username resolution failed for"),
        "stderr must contain 'username resolution failed for'; got: {stderr}"
    );

    // Caller-uid lookup succeeded naturally, so audit `caller` is the
    // runner's name (not the `uid:<n>` placeholder).
    let record = assert_audit_record_shape(&audit_lines, "denied", &runner, &runner, 1);
    assert_eq!(
        record["reason"].as_str(),
        Some("for-user-resolution-error"),
        "audit `reason` must be 'for-user-resolution-error'; got: {record}"
    );
    assert!(
        record.get("pool").is_none(),
        "audit `pool` must be absent on for-user-resolution-error deny; got: {record}"
    );
}

// ---------------------------------------------------------------------------
// Audit-log on allowed decision
// ---------------------------------------------------------------------------

/// Independent of any specific decision branch: assert the precise
/// JSON-Lines shape of an allowed-decision audit record. The allow
/// path also drives a real Docker container so the helper actually
/// completes step 8 (route installed), which is the production shape
/// of the field set.
#[test]
fn integration_route_helper_writes_audit_log_on_allowed() {
    let helper = verify_installed_test_helper();
    let runner = runner_username();
    // Distinct /24 from the other allow-path tests to avoid Docker IPAM
    // pool-overlap when nextest runs them in parallel.
    let subnet = "198.19.12.0/24";
    let gateway_ip = "198.19.12.1";
    let fixture = spawn_allow_path_container(subnet);
    let users_conf = users_conf_for_pool(subnet, &[runner.as_str()]);
    let (audit_dir, audit_path) = make_audit_log_path();
    let _audit_keep = audit_dir;

    let pid_str = fixture.container_pid.to_string();
    let (output, audit_lines) = run_helper_with_audit(
        &helper,
        &users_conf,
        &audit_path,
        &["--for-user", &runner, &pid_str, gateway_ip],
    );

    assert!(
        output.status.success(),
        "helper must allow; got exit failure. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let record = assert_audit_record_shape(
        &audit_lines,
        "allowed",
        &runner,
        &runner,
        fixture.container_pid,
    );
    // All.5 fields present on the allowed record (sans
    // `reason`, asserted absent inside assert_audit_record_shape).
    assert_eq!(record["pool"].as_str(), Some(subnet));
    assert_eq!(record["gateway_ip"].as_str(), Some(gateway_ip));
}

// ---------------------------------------------------------------------------
// Audit-log on denied decision
// ---------------------------------------------------------------------------

/// Independent of stderr substring: assert the precise JSON-Lines
/// shape of a denied-decision audit record. The for-user mismatch is
/// the most representative deny because it exercises the pool-naming
/// field (`pool`) which an unresolvable-for-user record cannot.
#[test]
fn integration_route_helper_writes_audit_log_on_denied() {
    let helper = verify_installed_test_helper();
    let runner = runner_username();
    let other = "root";
    assert_ne!(runner, other, "test precondition: runner must not be root");
    let users_conf = users_conf_for_pool("10.209.0.0/24", &[runner.as_str()]);
    let (audit_dir, audit_path) = make_audit_log_path();
    let _audit_keep = audit_dir;

    let (output, audit_lines) = run_helper_with_audit(
        &helper,
        &users_conf,
        &audit_path,
        &["--for-user", other, "1", "10.209.0.2"],
    );

    assert!(
        !output.status.success(),
        "helper must deny; got exit success. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let record = assert_audit_record_shape(&audit_lines, "denied", &runner, other, 1);
    assert_eq!(
        record["reason"].as_str(),
        Some("pair-check failed"),
        "denied audit `reason` must be 'pair-check failed': {record}"
    );
    assert_eq!(
        record["pool"].as_str(),
        Some("10.209.0.0/24"),
        "denied audit `pool` must name the chosen subnet: {record}"
    );
    assert_eq!(
        record["gateway_ip"].as_str(),
        Some("10.209.0.2"),
        "denied audit `gateway_ip` must echo the argv value: {record}"
    );
}

// ---------------------------------------------------------------------------
// Audit-log write failure on deny still denies
// ---------------------------------------------------------------------------

/// , the
/// helper still exits `DENY_EXIT` AND escalates to stderr — the deny
/// itself is unconditional and the forensic-record-availability
/// invariant gains explicit escalation.
///
/// We force the write to fail by pointing
/// `SANDBOX_ROUTE_HELPER_AUDIT_LOG` at a path under a parent that is
/// itself a regular file (not a directory). `OpenOptions::open` then
/// fails with ENOTDIR, the helper logs the stderr escalation line, and
/// the process exits with `DENY_EXIT` despite no audit record having
/// been written.
#[test]
fn integration_route_helper_audit_log_write_failure_on_deny_still_denies() {
    let helper = verify_installed_test_helper();
    let runner = runner_username();
    let other = "root";
    assert_ne!(runner, other, "test precondition: runner must not be root");

    let users_conf = users_conf_for_pool("10.209.0.0/24", &[runner.as_str()]);

    // Build a path whose parent is a regular file — `create_dir_all`
    // and `open` both fail on this shape, so the audit writer returns
    // `WriteFailed` regardless of the helper's level of effort.
    let block_file =
        NamedTempFile::new().expect("tempfile for audit-log path-blocker should succeed");
    let audit_path = block_file.path().join("nested/route-helper-audit.log");
    assert!(
        !audit_path.exists(),
        "test setup invariant: nested path must not yet exist"
    );

    let output = Command::new(&helper)
        .args(["--for-user", other, "1", "10.209.0.2"])
        .env("SANDBOX_USERS_CONF", users_conf.path())
        .env("SANDBOX_ROUTE_HELPER_AUDIT_LOG", &audit_path)
        .output()
        .expect("invoking helper should succeed");

    assert!(
        !output.status.success(),
        "helper must deny even when audit-log write fails; got exit success. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The deny reason itself surfaces.
    assert!(
        stderr.contains("pair-check failed"),
        "stderr must contain 'pair-check failed' (deny still happens): {stderr}"
    );
    // The audit-write escalation surfaces too.
    assert!(
        stderr.contains("audit log write failed"),
        "stderr must contain 'audit log write failed' escalation: {stderr}"
    );
    // The audit log file was never created (the helper could not
    // open it).
    assert!(
        !audit_path.exists(),
        "audit log file must not exist after a forced write failure: {}",
        audit_path.display()
    );
}

// ---------------------------------------------------------------------------
// Audit-log write failure on allow still allows
// ---------------------------------------------------------------------------

///
/// failure across the two decision paths:
///
/// - **Allow path** — log to stderr, return — the privilege has
///   already been granted; an audit-log infrastructure failure (disk
///   full, ENOSPC, missing parent dir) must not be a denial of service
///   to session creation. Routing-path availability wins.
/// - **Deny path** — log to stderr **and** exit `DENY_EXIT` (covered
///   by `integration_route_helper_audit_log_write_failure_on_deny_still_denies`
///   above).
///
/// This test pins the allow-side half of that asymmetry. We force the
/// audit write to fail by pointing `SANDBOX_ROUTE_HELPER_AUDIT_LOG` at
/// a path under a parent that is itself a regular file (so
/// `create_dir_all` returns ENOTDIR). The helper still proceeds through
/// the routing install — exit `0`, `"route installed"` on stdout, the
/// container's default route updated — but stderr must carry the
/// `"audit log write failed"` escalation line so an operator notices
/// the missing forensic record.
///
/// The fault-injection shape is identical to the deny-path test: a
/// `NamedTempFile`-rooted nested path that cannot be created. The
/// difference is in the helper's argv (allow-path: `for-user` matches
/// pool entry) and the expected exit code.
#[test]
fn integration_route_helper_audit_log_write_failure_on_allow_still_allows() {
    let helper = verify_installed_test_helper();
    let runner = runner_username();
    // Distinct /24 from the other allow-path tests to avoid Docker IPAM
    // pool-overlap when nextest runs them in parallel.
    let subnet = "198.19.13.0/24";
    let gateway_ip = "198.19.13.1";
    let fixture = spawn_allow_path_container(subnet);
    let users_conf = users_conf_for_pool(subnet, &[runner.as_str()]);

    // Build a path whose parent is a regular file — `create_dir_all`
    // fails with ENOTDIR, so the audit writer returns `WriteFailed`
    // regardless of the helper's level of effort. Same shape as the
    // deny-path test above.
    let block_file =
        NamedTempFile::new().expect("tempfile for audit-log path-blocker should succeed");
    let audit_path = block_file.path().join("nested/route-helper-audit.log");
    assert!(
        !audit_path.exists(),
        "test setup invariant: nested audit path must not yet exist"
    );

    let pid_str = fixture.container_pid.to_string();
    let output = Command::new(&helper)
        .args(["--for-user", &runner, &pid_str, gateway_ip])
        .env("SANDBOX_USERS_CONF", users_conf.path())
        .env("SANDBOX_ROUTE_HELPER_AUDIT_LOG", &audit_path)
        .output()
        .expect("invoking helper should succeed");

    // Allow honored: exit 0 despite the audit-log failure — routing
    // availability wins on the allow side.
    assert!(
        output.status.success(),
        "helper must still allow when audit-log write fails on the allow path; \
         got exit failure. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The step-8 success line still surfaces.
    assert!(
        stdout.contains("route installed"),
        "helper stdout must confirm route install on the allow path; got: {stdout}"
    );

    // The audit-write escalation must surface on stderr — the
    // forensic-record-availability invariant gains an operator-visible
    // signal even though the deny code path does not fire.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit log write failed"),
        "stderr must contain 'audit log write failed' escalation on allow-path; \
         got: {stderr}"
    );

    // The audit log file was never created (the helper could not
    // open it).
    assert!(
        !audit_path.exists(),
        "audit log file must not exist after a forced write failure: {}",
        audit_path.display()
    );

    // Sanity: the route actually landed inside the container despite
    // the audit-log failure. The route helper must never short-circuit
    // an allow on an audit-write failure; routing availability wins on
    // the allow side. Assert the post-install state directly to catch
    // any future regression that conflates the two paths' fault handling.
    let route = Command::new("docker")
        .args([
            "exec",
            &fixture.container_name,
            "ip",
            "route",
            "show",
            "default",
        ])
        .output()
        .expect("docker exec ip route should succeed");
    let route_text = String::from_utf8_lossy(&route.stdout);
    assert!(
        route_text.contains(gateway_ip),
        "container default route must point at the helper-installed gateway {gateway_ip} \
         even when the allow-path audit-log write failed; got: {route_text}"
    );
}
