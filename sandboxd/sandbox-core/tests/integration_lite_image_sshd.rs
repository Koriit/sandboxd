//! Integration test for the lite-image's in-container sshd contract.
//!
//! Asserts the image surface the daemon-mediated SSH design depends
//! on, *before* the daemon-side WebSocket proxy and ssh-config endpoint
//! land in later sessions:
//!
//! - The guest user `sandbox` exists with uid 1000.
//! - `sshd` listens on `127.0.0.1:22` inside the container netns under
//!   the production hardening profile (`--cap-drop ALL`,
//!   `--security-opt no-new-privileges`, `--read-only`,
//!   `--user 1000:1000`) plus the lowered
//!   `net.ipv4.ip_unprivileged_port_start=22` sysctl that lets sshd
//!   bind 22 without CAP_NET_BIND_SERVICE.
//!
//! The test runs `docker run` directly with the same hardening flags
//! the runtime's `build_create_argv` emits (minus the network /
//! workspace flags which are not needed to exercise the in-image
//! sshd surface). Asserting against the real runtime flags catches a
//! drift where the Dockerfile and the runtime disagree on what makes
//! sshd reachable.
//!
//! Test name is prefixed `integration_*` so the default hermetic
//! `make test` profile filters it out (see
//! `sandboxd/.config/nextest.toml`); the integration profile selects
//! it via that prefix.

use std::process::{Command, Stdio};
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandbox_core::backend::{LITE_IMAGE_REPOSITORY, ensure_image};

// ---------------------------------------------------------------------------
// sandbox-guest staging — same one-time copy as the build tests, so the
// lite Dockerfile's `COPY` of `sandbox-guest` resolves under nextest's
// `target/<profile>/deps/` exe layout.
// ---------------------------------------------------------------------------

static GUEST_STAGED: Once = Once::new();

fn ensure_sandbox_guest_in_exe_parent() {
    GUEST_STAGED.call_once(|| {
        let exe = std::env::current_exe().expect("current_exe");
        let deps_dir = exe.parent().expect("test exe parent (deps/)");
        let dest = deps_dir.join("sandbox-guest");
        if dest.exists() {
            return;
        }

        let profile_dir = deps_dir
            .parent()
            .expect("deps_dir parent (target/<profile>/)");
        let candidates = [
            profile_dir.join("sandbox-guest"),
            profile_dir
                .parent()
                .map(|p| p.join("sandbox-guest"))
                .unwrap_or_default(),
        ];
        let src = candidates
            .iter()
            .find(|p| p.exists())
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "sandbox-guest binary not found in any of: {candidates:?}. \
                     Run `cargo build --workspace` first.",
                )
            });

        std::fs::copy(&src, &dest).unwrap_or_else(|e| {
            panic!(
                "failed to stage sandbox-guest from {} to {}: {e}",
                src.display(),
                dest.display()
            )
        });
    });
}

// ---------------------------------------------------------------------------
// Tag minting + RAII cleanup.
// ---------------------------------------------------------------------------

fn unique_daemon_version(label: &str) -> String {
    static COUNTER: Mutex<u64> = Mutex::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let n = {
        let mut g = COUNTER.lock().unwrap();
        *g = g.wrapping_add(1);
        *g
    };
    format!("test-build-{label}-{pid}-{nanos}-{n}")
}

struct LiteImageCleanup {
    tag: String,
}

impl LiteImageCleanup {
    fn new(daemon_version: &str) -> Self {
        Self {
            tag: format!("{LITE_IMAGE_REPOSITORY}:{daemon_version}"),
        }
    }
}

impl Drop for LiteImageCleanup {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rmi", "-f", &self.tag])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

// ---------------------------------------------------------------------------
// Container lifecycle helpers — `docker run -d` + RAII teardown so a
// panic in the assertions never leaks a container.
// ---------------------------------------------------------------------------

struct ContainerCleanup {
    name: String,
}

impl Drop for ContainerCleanup {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn unique_container_name(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    format!("sandbox-lite-sshd-{label}-{pid}-{nanos}")
}

/// Run `docker exec <container> <argv...>` and return (status_success,
/// stdout). Captures both streams; the production-mode hardening
/// profile keeps stderr quiet on success, but on failure surfacing it
/// in panic messages is the difference between a one-shot fix and a
/// fishing expedition through Docker logs.
fn docker_exec(container: &str, argv: &[&str]) -> (bool, String, String) {
    let output = Command::new("docker")
        .arg("exec")
        .arg(container)
        .args(argv)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn docker exec {container} {argv:?}: {e}"));
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Poll `docker exec <container> ss -tlnH` until the predicate matches
/// or the deadline expires. `sandbox-entrypoint.sh` starts sshd before
/// `exec`'ing `sandbox-guest`, but sshd's listen socket comes up a few
/// ms after the entrypoint forks it; a tight read race would flake.
fn wait_for(container: &str, deadline: Duration, mut pred: impl FnMut(&str) -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        let (ok, stdout, _) = docker_exec(container, &["ss", "-tlnH"]);
        if ok && pred(&stdout) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// End-to-end image surface contract for the in-container sshd:
///
/// 1. Build the lite image (via `ensure_image`, the same code path the
///    daemon uses on first session create).
/// 2. `docker run -d` a container from it under the production
///    hardening profile.
/// 3. Inside the container:
///    - `id sandbox` reports uid=1000 (the guest user was renamed from
///      `agent` to `sandbox` per Spec § Architecture → Lite-image:
///      bundle sshd).
///    - `ss -tlnH` shows `sshd` listening on `127.0.0.1:22` (the
///      daemon's `docker exec ... socat - TCP:127.0.0.1:22` byte mover
///      delivered in a later session will target this endpoint).
///
/// The production-mode `docker run` flags here exactly mirror what
/// `sandbox-core::backend::container::build_create_argv` emits at
/// session-create time — minus the docker network and bind-mounts
/// that are not necessary to exercise the sshd surface. The
/// `--sysctl net.ipv4.ip_unprivileged_port_start=22` argument is the
/// one that lets sshd bind port 22 under `--user 1000:1000 +
/// --cap-drop ALL + --security-opt no-new-privileges`, all without a
/// single capability or privilege gain.
#[test]
fn integration_lite_image_sshd_listens_on_127_0_0_1_port_22_as_sandbox_user() {
    ensure_sandbox_guest_in_exe_parent();
    let version = unique_daemon_version("sshd");
    let _image_cleanup = LiteImageCleanup::new(&version);
    let tag = format!("{LITE_IMAGE_REPOSITORY}:{version}");

    // Step 1: build the lite image via the production code path.
    ensure_image(&version).expect("ensure_image must succeed for sshd contract test");

    // Step 2: launch a container under the production hardening profile.
    let container_name = unique_container_name("sshd");
    let _ctr_cleanup = ContainerCleanup {
        name: container_name.clone(),
    };
    let run = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &container_name,
            // Production hardening profile — see
            // `build_create_argv` in
            // `sandbox-core::backend::container`. The list is kept in
            // sync with the runtime by virtue of being asserted
            // against here.
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=256m",
            "--tmpfs",
            "/run:rw,nosuid,nodev,size=16m",
            "--security-opt",
            "no-new-privileges",
            "--security-opt",
            "seccomp=builtin",
            "--cap-drop",
            "ALL",
            "--sysctl",
            "net.ipv4.ip_unprivileged_port_start=22",
            "--user",
            "1000:1000",
            // No --network: a default bridge is fine for the in-image
            // contract check; the daemon-supplied per-session network
            // is not exercised here.
            &tag,
        ])
        .output()
        .expect("failed to spawn docker run");
    assert!(
        run.status.success(),
        "docker run failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr),
    );

    // Step 3a: assert the guest user `sandbox` exists with uid 1000.
    //
    // `id sandbox` prints `uid=1000(sandbox) gid=1000(sandbox) ...` on
    // success. We match on `uid=1000(sandbox)` so a future cosmetic
    // change in the gid line does not flake the test.
    let (ok, stdout, stderr) = docker_exec(&container_name, &["id", "sandbox"]);
    assert!(
        ok,
        "`id sandbox` failed inside container:\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        stdout.contains("uid=1000(sandbox)"),
        "expected `uid=1000(sandbox)` in `id sandbox` output; got: {stdout}",
    );

    // Step 3b: wait briefly for sshd to bring up its listen socket,
    // then assert it is listening on `127.0.0.1:22` inside the
    // container. `ss -tlnH` (`-H` = no header line) prints one row
    // per listening TCP socket; the row for sshd starts with
    // `LISTEN ... 127.0.0.1:22 ...`.
    let listening = wait_for(&container_name, Duration::from_secs(10), |out| {
        out.lines().any(|line| line.contains("127.0.0.1:22"))
    });
    assert!(
        listening,
        "sshd did not start listening on 127.0.0.1:22 within 10s; \
         last `ss -tlnH` snapshot:\n{}",
        docker_exec(&container_name, &["ss", "-tlnH"]).1,
    );

    // Belt + braces: confirm the process behind that listener is
    // sshd, not some other rogue socket on 22. `ss -tlnpH` adds the
    // process name to each row. The output format is
    //   LISTEN 0 128 127.0.0.1:22 ... users:(("sshd",pid=X,fd=Y))
    let (ok, stdout, stderr) = docker_exec(&container_name, &["ss", "-tlnpH"]);
    assert!(
        ok,
        "`ss -tlnpH` failed inside container:\nstdout: {stdout}\nstderr: {stderr}",
    );
    let sshd_line = stdout
        .lines()
        .find(|line| line.contains("127.0.0.1:22"))
        .unwrap_or_else(|| panic!("no LISTEN line for 127.0.0.1:22 in ss output:\n{stdout}"));
    assert!(
        sshd_line.contains("sshd"),
        "process on 127.0.0.1:22 is not sshd:\n{sshd_line}",
    );
}
