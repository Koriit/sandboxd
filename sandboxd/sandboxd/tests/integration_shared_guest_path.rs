//! S1-deferred integration tests for `WorkspaceMode::Shared`'s
//! operator-supplied guest path (M17 breaking default).
//!
//! These tests pin the wiring contract that
//! `WorkspaceMode::Shared { host_path, guest_path, .. }` carries the
//! guest path through to the backend's bind-mount step:
//! `ContainerRuntime` translates the pair into a `docker create
//! --mount type=bind,src=<host>,dst=<guest>` flag, and the resulting
//! container sees the host directory at exactly `<guest_path>`.
//!
//! ## Why container-only at the runtime layer
//!
//! Spec § 11.4 lists both
//! `integration_shared_guest_path_lima` and
//! `integration_shared_guest_path_container`. The Lima half requires
//! booting a real VM (the 9p mount is materialised at boot time, not
//! at template-render time); the existing
//! `sandbox-core/tests/lima_integration.rs` convention is
//! "inert-VM tests only" because runtime-level VM boot would need
//! `NetworkManager` plumbing from `AppState` that is out of scope at
//! this layer. The Lima coverage is therefore handled at the E2E
//! layer (`tests/e2e/test_workspace_shared_guest_path.py`).
//!
//! ## What's pinned here
//!
//! - `integration_shared_guest_path_container` — the M17-S1
//!   breaking-default guest path (`shared:<host>:<guest>`) lands the
//!   host directory at `<guest>` inside the container, host-side
//!   writes are visible in the guest, and guest-side writes are
//!   visible on the host (round-trip).

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_core::backend::{
    ContainerNetwork, ContainerRuntime, RuntimeStartArgs, SessionRuntime, WorkspaceBind,
};
use sandbox_core::session::SessionId;
use sandbox_core::{BackendSpecific, SessionSpec};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Test image: alpine sleep (no rsync needed; the bind-mount path is
// what we exercise, not a host→guest sync).
// ---------------------------------------------------------------------------

const SHARED_GUEST_PATH_IMAGE_TAG: &str = "sandboxd-shared-guest-path-test-sleep:latest";
const SHARED_GUEST_PATH_DOCKERFILE: &str =
    "FROM alpine:latest\nENTRYPOINT [\"sh\", \"-c\", \"exec sleep 3600\"]\n";

static SHARED_GUEST_PATH_IMAGE_BUILD: Once = Once::new();

fn ensure_shared_guest_path_image() {
    SHARED_GUEST_PATH_IMAGE_BUILD.call_once(|| {
        let mut child = Command::new("docker")
            .args(["build", "-t", SHARED_GUEST_PATH_IMAGE_TAG, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("docker build invokable");
        {
            let stdin = child.stdin.as_mut().expect("docker build stdin");
            stdin
                .write_all(SHARED_GUEST_PATH_DOCKERFILE.as_bytes())
                .expect("write Dockerfile");
        }
        let output = child.wait_with_output().expect("docker build exit");
        assert!(
            output.status.success(),
            "docker build {SHARED_GUEST_PATH_IMAGE_TAG} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    });
}

// ---------------------------------------------------------------------------
// Per-test network + container cleanup
// ---------------------------------------------------------------------------

struct TestNetwork {
    name: String,
    container_ip: String,
    gateway_ip: String,
}

impl TestNetwork {
    fn create(session_id: &SessionId) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let third = (nanos as u8).wrapping_mul(1);
        let fourth_base = (nanos.wrapping_shr(8) as u8).wrapping_mul(16);
        let subnet = format!("10.96.{third}.{fourth_base}/28");
        let gateway_ip = format!("10.96.{third}.{}", fourth_base.wrapping_add(2));
        let container_ip = format!("10.96.{third}.{}", fourth_base.wrapping_add(3));
        let name = format!("sandbox-net-{session_id}");

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
            container_ip,
            gateway_ip,
        }
    }

    fn to_container_network(&self, workspace_bind: Option<WorkspaceBind>) -> ContainerNetwork {
        ContainerNetwork {
            docker_network: self.name.clone(),
            container_ip: self.container_ip.parse().unwrap(),
            gateway_ip: self.gateway_ip.parse().unwrap(),
            workspace_bind,
            route_helper_path: None,
            ca_host_path: None,
        }
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["network", "rm", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

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

/// Placeholder `sandbox-guest` host file for the runtime's read-only
/// bind-mount at `/usr/local/bin/sandbox-guest`. The fixture
/// container's entrypoint never execs the guest binary; the bind
/// still has to resolve to a real host path or `docker run` errors.
fn guest_bind_source_for_tests() -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::OnceLock;
    static GUEST_PATH: OnceLock<PathBuf> = OnceLock::new();
    GUEST_PATH
        .get_or_init(|| {
            let dir = std::env::temp_dir().join("sandboxd-shared-guest-path-bind-source");
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

fn container_spec() -> SessionSpec {
    SessionSpec {
        backend_specific: BackendSpecific::Container {
            memory_mb: 256,
            cpus: 1.0,
        },
        // The workspace_mode field on the SessionSpec is informational
        // at the runtime layer; the actual bind comes from
        // `ContainerNetwork.workspace_bind`. We leave it as None here
        // so the runtime takes the same code path the daemon does
        // (the daemon stamps `workspace_mode` into `SessionConfig` for
        // persistence; the runtime reads only `ContainerNetwork`).
        workspace_mode: None,
        repo: None,
        boot_cmd: None,
        template: None,
        disk_gb: None,
        no_cache: None,
    }
}

fn docker_exec_capture(container_name: &str, argv: &[&str]) -> String {
    let mut cmd = Command::new("docker");
    cmd.arg("exec").arg(container_name);
    for a in argv {
        cmd.arg(a);
    }
    let output = cmd.output().expect("docker exec should be invokable");
    assert!(
        output.status.success(),
        "docker exec {container_name} {argv:?} failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

// ---------------------------------------------------------------------------
// Test: container backend honours operator-supplied `:<guest_path>`
// ---------------------------------------------------------------------------

/// Spec § 11.4 — `integration_shared_guest_path_container`.
///
/// Create a host tempdir with known contents. Boot a container with
/// `ContainerNetwork.workspace_bind = Some(WorkspaceBind { host_path:
/// <tempdir>, guest_path: /home/agent/work })`. Verify:
///
/// 1. The host file is visible inside the guest at `/home/agent/work/`
///    (the operator-supplied guest path, not the default
///    `/home/agent/workspace/` from earlier milestones).
/// 2. A file written from the host appears inside the guest at the
///    same relative path.
/// 3. A file written from the guest is visible on the host at the
///    bind source — pins the bidirectional mount semantics the
///    operator-facing docs guarantee.
///
/// The guest path `/home/agent/work` is chosen because the alpine
/// fixture writable area extends across the rootfs (no read-only
/// mount). The production lite image is `--read-only` with writable
/// areas at `/home/agent/`, `/tmp/`, and `/run/`; the spec's
/// constraint that the container backend requires the guest path
/// live inside a writable area is honoured by picking a `/home/agent/`
/// child path here.
#[tokio::test]
async fn integration_shared_guest_path_container() {
    let host_dir = TempDir::new().expect("host tempdir");
    let host_root = host_dir.path();
    // Seed a single file so the host-visible bind is unambiguously
    // populated before the container starts.
    std::fs::write(host_root.join("from_host.txt"), b"host-bytes\n").expect("write from_host.txt");

    ensure_shared_guest_path_image();
    let runtime = ContainerRuntime::new(
        SHARED_GUEST_PATH_IMAGE_TAG,
        256,
        1.0,
        1000,
        1000,
        guest_bind_source_for_tests(),
    );
    let session_id = SessionId::generate();
    let container_name = format!("sandbox-{session_id}");
    let net = TestNetwork::create(&session_id);
    let _cleanup = ContainerCleanup::new(&session_id);

    let workspace_bind = WorkspaceBind {
        host_path: host_root.to_path_buf(),
        guest_path: PathBuf::from("/home/agent/work"),
    };
    runtime.register_session(session_id, net.to_container_network(Some(workspace_bind)));

    let handle = runtime
        .create(&session_id, &container_spec())
        .await
        .expect("runtime.create");
    runtime
        .start(&handle, &RuntimeStartArgs::default())
        .await
        .expect("runtime.start");

    // (1) Host file is visible at the operator-supplied guest path.
    let body = docker_exec_capture(&container_name, &["cat", "/home/agent/work/from_host.txt"]);
    assert_eq!(
        body, "host-bytes",
        "the operator-supplied :<guest_path> must mount the host \
         directory at that exact path inside the container; \
         expected to read 'host-bytes' from /home/agent/work/from_host.txt"
    );

    // (2) Host writes after start are visible to the guest (mount is
    // live, not a snapshot).
    std::fs::write(host_root.join("late.txt"), b"appeared-after-start\n")
        .expect("write late.txt host-side");
    let late = docker_exec_capture(&container_name, &["cat", "/home/agent/work/late.txt"]);
    assert_eq!(
        late, "appeared-after-start",
        "host-side writes after container start must be visible in \
         the guest — the bind-mount must be live, not a snapshot"
    );

    // (3) Guest writes are visible to the host (round-trip).
    // Use docker exec with `sh -c` so the redirection happens
    // inside the container.
    let write_status = Command::new("docker")
        .args([
            "exec",
            &container_name,
            "sh",
            "-c",
            "echo 'guest-bytes' > /home/agent/work/from_guest.txt",
        ])
        .status()
        .expect("docker exec for guest write");
    assert!(
        write_status.success(),
        "guest-side write into the bind target must succeed"
    );

    let host_bytes =
        std::fs::read_to_string(host_root.join("from_guest.txt")).expect("read from_guest.txt");
    assert_eq!(
        host_bytes.trim(),
        "guest-bytes",
        "guest-side writes must appear on the host at the bind source — \
         a bind-mount is bidirectional by definition"
    );

    // Tear the container down explicitly so the assertion failures
    // above don't leave a stray container that the next test in the
    // suite might race against. The ContainerCleanup Drop covers the
    // panic path; this is the happy-path tidy-up.
    runtime.delete(&handle).await.expect("runtime.delete");
}
