//! Integration tests for [`sandbox_core::backend::ContainerRuntime`].
//!
//! Each test exercises the real Docker daemon (no `bollard`, just the
//! `docker` CLI under the runtime's hood) and mirrors the integration
//! conventions used by `lima_integration.rs` / `validators.rs`:
//!
//! - Test names are prefixed `integration_*` so they are picked up only
//!   by the `integration` nextest profile (see
//!   `sandboxd/.config/nextest.toml`); the default hermetic
//!   `make test` run filters them out.
//! - Per-test RAII guards (`TestNetwork`, `TestContainerImage`) ensure
//!   the docker artefacts are torn down even if a test panics, so
//!   parallel runs (`cargo nextest -j`) and partial failures cannot
//!   leak state.
//!
//! Phase 3A scope (handoff
//! `.tasks/handoffs/20260427-200000-implementer-m11-s3-phase3a-container-runtime.md`):
//! these tests do **not** exercise the route helper (Phase 3D) and do
//! **not** depend on `users.conf`. They use a tiny inline-built test
//! image (`sandboxd-test-sleep:latest` — ENTRYPOINT `sleep 3600`) since
//! the production lite image is built in Phase 3B.

use std::process::{Command, Stdio};
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_core::backend::{ContainerNetwork, ContainerRuntime, RuntimeStatus, SessionRuntime};
use sandbox_core::session::SessionId;
use sandbox_core::{BackendKind, BackendSpecific, RuntimeHandle, SessionSpec};

// ---------------------------------------------------------------------------
// Test image — a minimal alpine wrapper with `sleep 3600` as ENTRYPOINT
// ---------------------------------------------------------------------------

const TEST_IMAGE_TAG: &str = "sandboxd-test-sleep:latest";

/// Dockerfile used to build [`TEST_IMAGE_TAG`]. The lite production
/// image (Phase 3B) will embed `sandboxd-guest`; here we just need
/// PID 1 to stay alive long enough for the lifecycle assertions.
const TEST_DOCKERFILE: &str =
    "FROM alpine:latest\nENTRYPOINT [\"sh\", \"-c\", \"exec sleep 3600\"]\n";

/// `Once` so concurrent tests in the same process do not race the
/// build. Cross-process races are benign — `docker build` is
/// idempotent on identical content.
static IMAGE_BUILD: Once = Once::new();

fn ensure_test_image() {
    IMAGE_BUILD.call_once(|| {
        let mut child = Command::new("docker")
            .args(["build", "-t", TEST_IMAGE_TAG, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("docker build should be invokable; ensure Docker daemon is running");
        {
            use std::io::Write;
            let stdin = child.stdin.as_mut().expect("docker build stdin");
            stdin
                .write_all(TEST_DOCKERFILE.as_bytes())
                .expect("write Dockerfile to docker build");
        }
        let output = child.wait_with_output().expect("docker build should exit");
        assert!(
            output.status.success(),
            "docker build {TEST_IMAGE_TAG} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    });
}

// ---------------------------------------------------------------------------
// Per-test RAII helpers
// ---------------------------------------------------------------------------

/// Unique-per-test docker network owning one /28 from a private range
/// outside the daemon's actual session allocations. RAII tear-down
/// removes the network on Drop. The IP block is deliberately picked in
/// `10.99.x.0/28` chunks and randomised to avoid collisions across
/// concurrent test runs on the same host.
struct TestNetwork {
    name: String,
    subnet: String,
    container_ip: String,
    gateway_ip: String,
}

impl TestNetwork {
    fn create(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // `nanos as u8` gives us a per-test 0..=255 third octet, kept
        // inside the private 10.99.0.0/16 RFC1918 block. `*16` then
        // gives us a /28 boundary so each test owns a fresh subnet.
        let third = (nanos as u8).wrapping_mul(1);
        let fourth_base = (nanos.wrapping_shr(8) as u8).wrapping_mul(16);
        let subnet = format!("10.99.{third}.{fourth_base}/28");
        let gateway_ip = format!("10.99.{third}.{}", fourth_base.wrapping_add(2));
        let container_ip = format!("10.99.{third}.{}", fourth_base.wrapping_add(3));
        let name = format!("sandbox-net-test-{label}-{nanos}");

        let output = Command::new("docker")
            .args(["network", "create", "--subnet", &subnet, &name])
            .output()
            .expect("docker network create should be invokable");
        assert!(
            output.status.success(),
            "docker network create failed for {name} ({subnet}): {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Self {
            name,
            subnet,
            container_ip,
            gateway_ip,
        }
    }

    fn to_container_network(&self) -> ContainerNetwork {
        ContainerNetwork {
            docker_network: self.name.clone(),
            container_ip: self.container_ip.parse().unwrap(),
            gateway_ip: self.gateway_ip.parse().unwrap(),
            workspace_bind: None,
            // No route helper: integration tests deliberately exercise
            // the lifecycle without depending on /etc/sandboxd/users.conf
            // (Phase 3D wires the helper).
            route_helper_path: None,
            // Integration tests don't exercise the L3-MITM CA trust
            // path; the daemon-level test
            // `integration_create_session_container_*` exercises the
            // CA-mount wiring end-to-end via `create_session`.
            ca_host_path: None,
            // SSH staging is wired by the daemon-level integration
            // tests against a real `create_session` call site; the
            // runtime-level integration tests stay on the existing
            // best-effort sshd path documented in the lite-image
            // launch wrapper.
            ssh_host_dir: None,
        }
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        // Best-effort teardown; Drop must not panic and a leaked
        // network from a prior partial failure would already be
        // surfaced by `docker network create`.
        let _ = Command::new("docker")
            .args(["network", "rm", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// RAII guard that `docker rm -f`s the container by name and `docker
/// volume rm`s the per-session home volume on Drop. Insurance against
/// a panic between `create()` and the explicit `delete()` step.
struct ContainerCleanup {
    container_name: String,
    home_volume: String,
}

impl ContainerCleanup {
    fn new(session_id: &SessionId) -> Self {
        Self {
            container_name: format!("sandbox-{session_id}"),
            home_volume: format!("sandbox-home-{session_id}"),
        }
    }
}

impl Drop for ContainerCleanup {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("docker")
            .args(["volume", "rm", &self.home_volume])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn container_spec() -> SessionSpec {
    SessionSpec {
        backend_specific: BackendSpecific::Container {
            memory_mb: 256,
            cpus: 1.0,
        },
        workspace_mode: None,
        repo: None,
        boot_cmd: None,
        template: None,
        disk_gb: None,
        no_cache: None,
    }
}

/// Resolve a stable host path for the bind-mount source the runtime
/// passes as `guest_bind_source`. The path must exist before
/// `docker create` runs (otherwise dockerd errors on the mount source),
/// so we drop a small placeholder file in a process-global tempdir
/// and reuse the same path across every integration test in this
/// file. Tests in this module are not exercising refresh — they just
/// need the bind-mount source to be a real, executable host file so
/// the create/start lifecycle assertions hold.
fn guest_bind_source_for_tests() -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::OnceLock;
    static GUEST_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();
    GUEST_PATH
        .get_or_init(|| {
            // System-tempdir path that lives for the test process's
            // lifetime; the underlying file is not unlinked because
            // every test in this file reuses the same path and racing
            // `docker create` against an unlinked source would flake.
            let dir = std::env::temp_dir().join("sandboxd-test-guest-bind-source");
            std::fs::create_dir_all(&dir).expect("create test guest-bind-source dir");
            let path = dir.join("sandbox-guest");
            std::fs::write(&path, b"placeholder-sandbox-guest-for-integration-tests\n")
                .expect("write placeholder guest binary");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod 0755 on placeholder guest binary");
            path
        })
        .clone()
}

fn make_runtime() -> std::sync::Arc<ContainerRuntime> {
    ContainerRuntime::new(
        TEST_IMAGE_TAG,
        256,
        1.0,
        1000,
        1000,
        guest_bind_source_for_tests(),
    )
}

fn docker_inspect(container: &str, format: &str) -> String {
    let output = Command::new("docker")
        .args(["inspect", "-f", format, container])
        .output()
        .expect("docker inspect should be invokable");
    assert!(
        output.status.success(),
        "docker inspect {container} {format} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Phase 3A handoff Task 4 / test 1 — full container lifecycle.
/// Asserts the runtime walks `created -> running -> stopped` and the
/// container is gone after `delete()`. The route helper is not
/// exercised (no `route_helper_path` registered) so this test runs
/// without `/etc/sandboxd/users.conf`.
#[tokio::test]
async fn integration_container_runtime_create_start_stop_delete_round_trip() {
    ensure_test_image();
    let net = TestNetwork::create("lifecycle");
    let runtime = make_runtime();
    let session_id = SessionId::generate();
    let _cleanup = ContainerCleanup::new(&session_id);

    runtime.register_session(session_id, net.to_container_network());

    let handle = runtime
        .create(&session_id, &container_spec())
        .await
        .expect("ContainerRuntime::create should succeed");
    assert_eq!(handle.as_str(), format!("sandbox-{session_id}"));

    // Pre-start, docker reports `created`.
    let status = runtime.status(&handle).await.unwrap();
    assert_eq!(
        status,
        RuntimeStatus::Stopped,
        "freshly-created container maps to RuntimeStatus::Stopped"
    );

    runtime
        .start(&handle, &Default::default())
        .await
        .expect("ContainerRuntime::start should succeed");

    // Post-start, docker reports `running`.
    let status = runtime.status(&handle).await.unwrap();
    assert_eq!(status, RuntimeStatus::Running);

    runtime
        .stop(&handle)
        .await
        .expect("ContainerRuntime::stop should succeed");

    // Post-stop, docker reports `exited` → Stopped.
    let status = runtime.status(&handle).await.unwrap();
    assert_eq!(status, RuntimeStatus::Stopped);

    runtime
        .delete(&handle)
        .await
        .expect("ContainerRuntime::delete should succeed");

    // Post-delete, the container is gone — status maps the
    // "No such container" stderr to Stopped.
    let status = runtime.status(&handle).await.unwrap();
    assert_eq!(status, RuntimeStatus::Stopped);
}

/// Phase 3A handoff Task 4 / test 2 — every the documented contract flag is
/// reflected in `docker inspect` HostConfig output. Pinned per flag so
/// a silent regression in `create()` (e.g. a typo'd flag, a re-ordered
/// arg slice that drops one) fails this test rather than silently
/// shipping a softer container.
#[tokio::test]
async fn integration_container_runtime_hardening_flags_match_spec() {
    ensure_test_image();
    let net = TestNetwork::create("hardening");
    let runtime = make_runtime();
    let session_id = SessionId::generate();
    let _cleanup = ContainerCleanup::new(&session_id);

    runtime.register_session(session_id, net.to_container_network());

    let handle = runtime
        .create(&session_id, &container_spec())
        .await
        .expect("ContainerRuntime::create");
    runtime
        .start(&handle, &Default::default())
        .await
        .expect("ContainerRuntime::start");

    let container = handle.as_str();

    // --read-only
    assert_eq!(
        docker_inspect(container, "{{.HostConfig.ReadonlyRootfs}}"),
        "true",
        "rootfs must be read-only (--read-only)"
    );

    // --cap-drop ALL
    let cap_drop = docker_inspect(container, "{{.HostConfig.CapDrop}}");
    assert!(
        cap_drop.contains("ALL"),
        "CapDrop must include ALL, got: {cap_drop}"
    );

    // --security-opt no-new-privileges + seccomp=builtin
    let sec_opts = docker_inspect(container, "{{.HostConfig.SecurityOpt}}");
    assert!(
        sec_opts.contains("no-new-privileges"),
        "SecurityOpt must include no-new-privileges, got: {sec_opts}"
    );
    assert!(
        sec_opts.contains("seccomp=builtin"),
        "SecurityOpt must include Docker's default seccomp profile (seccomp=builtin), got: {sec_opts}"
    );

    // --memory 256m → 256 * 1024 * 1024 = 268_435_456
    assert_eq!(
        docker_inspect(container, "{{.HostConfig.Memory}}"),
        "268435456",
        "Memory must reflect --memory 256m"
    );

    // --cpus 1.0 → 1_000_000_000 nanocpus
    assert_eq!(
        docker_inspect(container, "{{.HostConfig.NanoCpus}}"),
        "1000000000",
        "NanoCpus must reflect --cpus 1.0"
    );

    // --pids-limit 512
    assert_eq!(
        docker_inspect(container, "{{.HostConfig.PidsLimit}}"),
        "512",
        "PidsLimit must reflect --pids-limit 512"
    );

    // --restart no
    assert_eq!(
        docker_inspect(container, "{{.HostConfig.RestartPolicy.Name}}"),
        "no",
        "RestartPolicy.Name must reflect --restart no"
    );

    // --user 1000:1000
    assert_eq!(
        docker_inspect(container, "{{.Config.User}}"),
        "1000:1000",
        "User must reflect --user 1000:1000"
    );

    // --tmpfs /tmp + /run
    let tmpfs = docker_inspect(container, "{{.HostConfig.Tmpfs}}");
    assert!(
        tmpfs.contains("/tmp:"),
        "Tmpfs must include /tmp, got: {tmpfs}"
    );
    assert!(
        tmpfs.contains("/run:"),
        "Tmpfs must include /run, got: {tmpfs}"
    );
    assert!(
        tmpfs.contains("size=256m"),
        "Tmpfs /tmp must declare size=256m, got: {tmpfs}"
    );
    assert!(
        tmpfs.contains("size=16m"),
        "Tmpfs /run must declare size=16m, got: {tmpfs}"
    );
    assert!(
        tmpfs.contains("nosuid") && tmpfs.contains("nodev"),
        "Tmpfs flags must include nosuid,nodev, got: {tmpfs}"
    );

    // --label sandbox.session_id=<sid>
    let label = docker_inspect(container, "{{index .Config.Labels \"sandbox.session_id\"}}");
    assert_eq!(label, session_id.to_string(), "session_id label missing");

    runtime
        .delete(&handle)
        .await
        .expect("ContainerRuntime::delete");

    // Drop the net subnet usage off the assertion list — it's
    // exercised by `create_start_stop_delete_round_trip` already.
    drop(net);
}

/// Phase 3A handoff Task 4 / test 3 — `runtime.status()` reflects the
/// container's actual state, even when state changes happen out-of-band
/// (e.g. an operator runs `docker stop` directly).
#[tokio::test]
async fn integration_container_runtime_status_reflects_docker_state() {
    ensure_test_image();
    let net = TestNetwork::create("status");
    let runtime = make_runtime();
    let session_id = SessionId::generate();
    let _cleanup = ContainerCleanup::new(&session_id);

    runtime.register_session(session_id, net.to_container_network());

    let handle = runtime
        .create(&session_id, &container_spec())
        .await
        .expect("ContainerRuntime::create");
    runtime
        .start(&handle, &Default::default())
        .await
        .expect("ContainerRuntime::start");

    assert_eq!(
        runtime.status(&handle).await.unwrap(),
        RuntimeStatus::Running,
        "post-start must be Running"
    );

    // Stop the container directly via the docker CLI, simulating an
    // operator out-of-band action — the runtime's status() must catch
    // up rather than reflecting cached state.
    let stop_output = Command::new("docker")
        .args(["stop", "-t", "5", handle.as_str()])
        .output()
        .expect("docker stop should be invokable");
    assert!(
        stop_output.status.success(),
        "docker stop failed: {}",
        String::from_utf8_lossy(&stop_output.stderr)
    );

    assert_eq!(
        runtime.status(&handle).await.unwrap(),
        RuntimeStatus::Stopped,
        "out-of-band docker stop must surface as RuntimeStatus::Stopped"
    );

    runtime
        .delete(&handle)
        .await
        .expect("ContainerRuntime::delete");

    drop(net);
}

/// Phase 3A handoff Task 4 / test 4 — `delete()` is idempotent.
/// Calling it on a session that has already been deleted (and whose
/// home volume has already been removed) must succeed quietly.
#[tokio::test]
async fn integration_container_runtime_delete_is_idempotent() {
    ensure_test_image();
    let net = TestNetwork::create("idempotent");
    let runtime = make_runtime();
    let session_id = SessionId::generate();
    let _cleanup = ContainerCleanup::new(&session_id);

    runtime.register_session(session_id, net.to_container_network());

    let handle = runtime
        .create(&session_id, &container_spec())
        .await
        .expect("ContainerRuntime::create");

    runtime
        .delete(&handle)
        .await
        .expect("first ContainerRuntime::delete should succeed");

    // Second delete — the container and the home volume are both
    // gone; the runtime must translate "No such container" /
    // "No such volume" stderr into Ok(()).
    runtime
        .delete(&handle)
        .await
        .expect("second ContainerRuntime::delete must be idempotent");

    // Third delete via a freshly-derived handle (covers the path
    // where a recovery flow re-derives the handle from the session
    // id rather than reusing the one returned by create()).
    runtime
        .delete(&RuntimeHandle::from_session_id(&session_id))
        .await
        .expect("delete via re-derived handle must be idempotent");

    drop(net);
}

/// Sanity smoke — the static descriptor exposed via `kind()` /
/// `capabilities()` matches what `GET /backends` (Phase 3C) is going
/// to publish. Lives in the integration suite alongside the lifecycle
/// tests so a regression here surfaces in the same Docker-required
/// run that exercises `create()`, rather than only in the unit-test
/// path.
#[test]
fn integration_container_runtime_static_descriptor() {
    let runtime = make_runtime();
    assert_eq!(runtime.kind(), BackendKind::Container);
    let caps = runtime.capabilities();
    assert_eq!(caps.kind, BackendKind::Container);
    assert!(!caps.nested_virt);
    assert!(!caps.privileged_ops);
    assert!(!caps.raw_network);
    assert!(!caps.hardening_flag);

    // Subnet field is informational on the helper struct; pinned here
    // so a refactor that reorders TestNetwork's fields would surface
    // a compile error rather than silently stop populating it.
    let net = TestNetwork::create("smoke");
    assert!(net.subnet.starts_with("10.99."));
    drop(net);
}
