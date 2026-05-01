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
    if !cap_output.contains("cap_sys_admin") {
        panic!(
            "installed test route helper at {} lacks cap_sys_admin (getcap stdout: {:?})\n\
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
fn run_helper(helper: &Path, users_conf: &NamedTempFile, args: &[&str]) -> Output {
    Command::new(helper)
        .args(args)
        .env("SANDBOX_USERS_CONF", users_conf.path())
        .output()
        .expect("invoking helper should succeed")
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
// Test 2 — caller uid not in subnet's allow_users (denies at step 4)
// ---------------------------------------------------------------------------

/// Verifies the step-4 deny branch: the gateway IP IS inside a
/// configured subnet, but that subnet's `allow_users` does not contain
/// any name that resolves to the caller's uid. Helper denies before
/// any netns operation.
#[test]
fn integration_route_helper_denies_when_caller_not_in_allow_users() {
    let helper = verify_installed_test_helper();

    // allow_users intentionally lists a username that does not exist
    // on the host (the same sentinel name the loader's unit tests use,
    // for the same reason — `getpwnam_r` returns Ok(None) and the
    // name is treated as a non-match).
    let users_conf = write_users_conf(
        r#"{
            "subnets": [
                {
                    "cidr": "10.209.0.0/20",
                    "allow_users": ["definitely-not-a-real-user-9c3f"]
                }
            ]
        }"#,
    );

    // Gateway IP 10.209.0.2 IS inside the subnet — step 3 passes —
    // but the caller's uid won't match the bogus allow_users entry.
    let output = run_helper(&helper, &users_conf, &["1", "10.209.0.2"]);

    assert!(
        !output.status.success(),
        "helper must deny; got exit success. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not in allow_users"),
        "stderr must contain 'not in allow_users'; got: {stderr}"
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
        let run = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &container_name,
                "--network",
                &network_name,
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
