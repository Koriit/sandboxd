//! Integration tests for `WorkspaceMode::Shared`'s operator-supplied
//! guest path (the breaking default that replaces the historical
//! fixed `/home/agent/workspace` mount).
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
//!
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
//! - `integration_shared_guest_path_container` — the breaking-default
//!   guest path (`shared:<host>:<guest>`) lands the host directory at
//!   `<guest>` inside the container, host-side writes are visible in
//!   the guest, and guest-side writes are visible on the host
//!   (round-trip).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Once;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use sandbox_core::backend::{
    ContainerNetwork, ContainerRuntime, RuntimeStartArgs, SessionRuntime, WorkspaceBind,
};
use sandbox_core::session::SessionId;
use sandbox_core::{BackendSpecific, SessionSpec};
use tempfile::TempDir;
use tokio::net::UnixStream;

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
            ssh_host_dir: None,
            operator_identity: None,
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
        // The workspace_mode field on the SessionSpecis informational
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
        operator_identity: None,
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

/// .
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
/// areas at `/home/agent/`, `/tmp/`, and `/run/`; the
/// constraint that the container backend requires the guest path
/// live inside a writable area is honoured by picking a `/home/agent/`
/// child path here.
#[tokio::test]
async fn integration_shared_guest_path_container() {
    let host_dir = TempDir::new().expect("host tempdir");
    let host_root = host_dir.path();
    // Make the bind-mount source world-writable so the container user
    // (UID 1000) can write into it regardless of the host UID that owns
    // the tempdir (on CI the runner is typically UID 1001, not 1000).
    // TempDir::new() creates with mode 0o700; the container runs as
    // 1000:1000 and would get EACCES on the write step without this.
    std::fs::set_permissions(
        host_root,
        std::os::unix::fs::PermissionsExt::from_mode(0o777),
    )
    .expect("chmod 0o777 on host bind-mount dir");
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

// ---------------------------------------------------------------------------
// Daemon-spawn fixture for the security_model rejection HTTP test.
//
// The runtime-direct tests above pin the bind-mount wiring; the
// rejection contract for `:<security_model>` against the container
// backend is daemon-side (the mapper at `sandboxd/src/main.rs::create_session`
// refuses the request before it can stamp the `ContainerNetwork`).
// Driving it through the HTTP boundary catches a regression that
// drops the gate without breaking the runtime-direct tests.
//
// Pattern mirrors `integration_local_workspace.rs` and
// `integration_session_create_refused_on_missing_gateway_image.rs` —
// real `sandboxd` binary, real `users.conf`, real Unix socket. The
// fixture is local to this file because the daemon-spawn helpers
// are deliberately not crate-public (each test crate composes its
// own to keep wiring drift visible at the call site).
// ---------------------------------------------------------------------------

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

struct Daemon {
    socket: PathBuf,
    proc: Option<Child>,
    #[allow(dead_code)]
    tmp: TempDir,
}

impl Daemon {
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
            proc: Some(proc),
            tmp,
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
                    "sandboxd socket did not appear at {} within {:?}; check {}/sandboxd.stderr.log",
                    self.socket.display(),
                    timeout,
                    self.tmp.path().display(),
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

async fn http_post_json(
    socket_path: &Path,
    path: &str,
    body: String,
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
            .method("POST")
            .uri(path)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("content-length", body.len().to_string())
            .body(body)
            .expect("build POST request");
        let resp = sender.send_request(req).await.expect("send_request");
        let status = resp.status();
        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        (status, body_bytes.to_vec())
    })
    .await
    .unwrap_or_else(|_| panic!("HTTP request timed out after {timeout:?}"))
}

/// HTTP-boundary pin for the container backend shared bind-mount
/// rejection: the container backend has no 9p layer, so
/// any operator-supplied `:<security_model>` token (e.g.
/// `shared:/tmp:none`) must be refused with 400 +
/// `SandboxError::InvalidArgument`. The mapper at
/// `sandboxd/src/main.rs::create_session` enforces this; a regression
/// that drops the gate would let the request reach
/// `runtime.register_session` with an inert `security_model` value,
/// silently degrading the operator's request rather than failing
/// loudly.
///
/// Body shape mirrors `integration_create_session_rejects_no_gitignore_with_non_local_workspace`
/// — minimum valid container request plus the offending
/// `workspace: "shared:/tmp:none"` field. The host's already-loaded
/// production gateway image satisfies the pre-flight probe at
/// `sandboxd/src/main.rs:1372-1394`, the parser at `:1399` accepts
/// `shared:/tmp:none` (`Shared { host_path: "/tmp", guest_path: "/tmp",
/// security_model: Some(NoneMapping) }`), and the request then
/// proceeds through CA + network allocation before the container
/// branch's rejection fires at `:1908`. The `cleanup_net_ca_and_return!`
/// macro on that branch tears down the per-session network + CA the
/// daemon allocated, so the test leaks no resources on success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_container_rejects_security_model() {
    // Distinct /24 from other integration tests (10.97.x — local
    // workspace runtime fixtures; 10.98.x — create-session-container;
    // 10.219.x — owner peercred; 10.234.x — missing gateway refuse;
    // 10.235.x — local-workspace HTTP). 10.236.x is unused.
    let daemon = Daemon::spawn_with_env("10.236.0.0/24", &[]);

    let body =
        r#"{"backend":"container","workspace":"shared:/tmp:none","cpus":1.0,"memory_mb":256}"#
            .to_string();
    let (status, body_bytes) =
        http_post_json(&daemon.socket, "/sessions", body, Duration::from_secs(30)).await;

    assert_eq!(
        status,
        hyper::StatusCode::BAD_REQUEST,
        "container backend must refuse a request carrying a 9p :<security_model> \
         token (the bind-mount has no 9p layer); expected 400, got {status}. \
         body={}",
        String::from_utf8_lossy(&body_bytes)
    );

    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes)
        .expect("rejection body must be valid JSON for the error envelope");
    let error_msg = parsed
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            panic!("rejection body must have a top-level `error` string; got: {parsed}")
        });

    //  — the rejection
    // message must name the offending field so the operator can map
    // the error back to their `--workspace shared:…:<model>` invocation.
    assert!(
        error_msg.contains("security_model"),
        "rejection body must contain the literal field name `security_model`; got: {error_msg}"
    );
}
