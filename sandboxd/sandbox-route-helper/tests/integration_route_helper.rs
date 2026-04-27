//! Deny-branch integration tests for `sandbox-route-helper`.
//!
//! All three tests follow the same outer shape:
//!
//! 1. Locate the freshly-built helper binary via the
//!    `CARGO_BIN_EXE_sandbox-route-helper` env var that cargo sets for
//!    every integration test in this crate.
//! 2. Copy the helper binary to a per-test path under `/tmp` (an ext4
//!    filesystem that backs `security.capability` xattrs — the cargo
//!    `target/` directory may live on a 9p / virtio-fs mount that
//!    does not, in which case `setcap` returns `Operation not
//!    supported`). `sudo setcap cap_sys_admin+ep <copy>` applies the
//!    capability the helper relies on at runtime. RAII removes the
//!    copy on test teardown — see [`CappedHelper`].
//! 3. Drop a tempfile users.conf into place; point the helper at it
//!    via the `SANDBOX_USERS_CONF` env var (test-only seam exposed by
//!    the loader in `sandbox-core`).
//! 4. Run the helper, capture exit status + stderr, assert on the
//!    expected substring.
//!
//! The third test (`netns_ip_outside_caller_subnet`) additionally
//! spins up a real Docker container in an isolated bridge network so
//! it can give the helper a live `pidfd_open` target whose netns IPs
//! are *outside* the caller's `users.conf` subnet. Cleanup is RAII
//! per the `TestContainer` pattern in `sandbox-core/tests/validators.rs`.
//!
//! ## Profile selection
//!
//! Each test name is prefixed `integration_route_helper_` so the
//! `integration` nextest profile (`sandboxd/.config/nextest.toml`)
//! picks them up via its `test(/^integration_/)` filter, and the
//! default profile filters them out. No `#[ignore]`, no env gate —
//! membership is self-describing at the call site.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Path to the freshly-built helper binary. Cargo populates this env
/// var for every integration test in this crate; the binary is
/// (re)built before the test runs.
fn helper_binary() -> &'static str {
    env!("CARGO_BIN_EXE_sandbox-route-helper")
}

/// A copy of the helper binary on a filesystem that supports file
/// capabilities, with `cap_sys_admin+ep` applied. RAII removes the
/// copy on drop.
///
/// Why a copy and not the cargo-built binary directly:
/// `target/debug/sandbox-route-helper` may live on a 9p / virtio-fs /
/// other mount that does not back `security.capability` xattrs (Lima's
/// host-share mount being the canonical example). `setcap` on such a
/// mount fails with `Operation not supported`. Copying to a host-side
/// path that supports xattrs (`/tmp` on the standard ext4 root) and
/// setcap'ing the copy sidesteps this.
struct CappedHelper {
    path: PathBuf,
}

impl CappedHelper {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // Use /tmp explicitly rather than std::env::temp_dir() — the
        // latter honours $TMPDIR which a caller might point at the
        // 9p-mounted source tree, defeating the workaround.
        let path = PathBuf::from(format!("/tmp/sb-route-helper-test-{nanos}"));
        std::fs::copy(helper_binary(), &path)
            .unwrap_or_else(|e| panic!("copying helper binary to {} failed: {e}", path.display()));
        // setcap the copy. Idempotent in the sense that re-applying
        // the same capability set is a no-op; we run it once per test
        // because each test gets its own copy.
        let output = Command::new("sudo")
            .args([
                "-n",
                "setcap",
                "cap_sys_admin+ep",
                path.to_str().expect("tempfile path is utf-8"),
            ])
            .output()
            .expect("invoking sudo setcap should succeed");
        assert!(
            output.status.success(),
            "sudo setcap failed on {}: stderr={}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CappedHelper {
    fn drop(&mut self) {
        // Best-effort cleanup. Drop must not panic.
        let _ = std::fs::remove_file(&self.path);
    }
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

/// Run the cap'd helper copy with the given argv, pointing at the
/// given users.conf tempfile via `SANDBOX_USERS_CONF`. Captures
/// stdout + stderr.
fn run_helper(helper: &CappedHelper, users_conf: &NamedTempFile, args: &[&str]) -> Output {
    Command::new(helper.path())
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
    let helper = CappedHelper::new();
    let user = runner_username();

    let users_conf = write_users_conf(&format!(
        r#"{{
            "subnets": [
                {{ "cidr": "10.209.0.0/20", "allow_users": ["{user}"] }}
            ]
        }}"#
    ));

    // Gateway IP 10.250.0.5 is outside the only configured subnet
    // (10.209.0.0/20). Pid 1 (init) — irrelevant; helper denies at
    // step 3 before pidfd_open runs.
    let output = run_helper(&helper, &users_conf, &["1", "10.250.0.5"]);

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
    let helper = CappedHelper::new();

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
    /// Spin up a bridge network with `subnet` (e.g. `"10.250.0.0/24"`)
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
/// — the docker-managed default (`via 10.250.0.1`) must still be in
/// place.
#[test]
fn integration_route_helper_denies_when_netns_ip_outside_caller_subnet() {
    let helper = CappedHelper::new();
    let user = runner_username();

    // Container lives on 10.250.0.0/24. users.conf authorizes the
    // caller for 10.209.0.0/20 — well outside the container's bridge
    // — so step 6 will see `eth0` carrying 10.250.0.2 and deny.
    let fixture = TestNetnsContainer::spawn("10.250.0.0/24");

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
    // docker-installed default via 10.250.0.1 must still be the
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
        route_text.contains("10.250.0.1"),
        "container should still have the docker-installed default \
         via 10.250.0.1; got: {route_text}"
    );
}
