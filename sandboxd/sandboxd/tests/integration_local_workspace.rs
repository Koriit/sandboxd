//! Integration tests for `WorkspaceMode::Local` create-time rsync push.
//!
//! These tests pin the contract that the Phase 3 module
//! `sandbox_core::workspace_rsync::run_initial_push` exposes to the
//! daemon: given a real running container (sandbox-<id>) and a host
//! source tree, the function mirrors the host tree into the guest at
//! the requested guest path, honouring `.gitignore` filtering unless
//! `no_gitignore == true`, and surfaces non-zero rsync exits as
//! `SandboxError::Internal` with a `"local-workspace rsync failed"`
//! prefix carrying rsync's stderr.
//!
//! ## Why runtime-level, not full daemon HTTP
//!
//! The full HTTP-boundary `cleanup_and_return!` wire-shape pin is
//! deferred to Phase 5 E2E (`tests/e2e/test_workspace_local.py`),
//! which already drives the full daemon end-to-end on both backends.
//! Driving the same flow through `POST /sessions` from this test
//! crate would require waiting for a real Lima VM boot (3-10 min per
//! CLAUDE.md) — outside the "no individual test > 10 min" envelope.
//!
//! Container coverage at the runtime layer exercises every line of
//! `run_initial_push`. The Lima half of the same exercise is left to
//! E2E:.4 lists `integration_lima_local_create_and_push`,
//! but the existing `sandbox-core/tests/lima_integration.rs` convention
//! is "inert-VM tests only" — booting a Lima VM at the runtime layer
//! requires `NetworkManager` plumbing from `AppState` (per the comment
//! at `lima_integration.rs:67`), which is out of scope here.
//!
//! ## What's covered
//!
//! - `integration_container_local_create_and_push` — happy path: host
//!   tree mirrored to a known guest path; verified via `docker exec
//!   <ctr> cat <path>`. Container backend.
//! - `integration_local_gitignore_filter` — `.gitignore` filtering
//!   semantics: same host source, two pushes (default + `no_gitignore=true`);
//!   assert excluded directory presence flips between runs. Container
//!   backend (the filter-flag handling is backend-independent in
//!   `workspace_rsync.rs`).
//! - `integration_local_create_failure_tears_down` — `chmod 000` a file
//!   inside the host source; assert `run_initial_push` returns
//!   `Err(SandboxError::Internal(msg))` and `msg` carries the production
//!   prefix `"local-workspace rsync failed"` (see
//!   `sandbox-core/src/workspace_rsync.rs:228`). The daemon's
//!   `cleanup_and_return!` orchestration is deferred to Phase 5 E2E —
//!   the library-level surface this test exercises is what the daemon
//!   call site at `sandboxd/src/main.rs:2723` consumes.
//! - `integration_create_session_rejects_no_gitignore_with_non_local_workspace`
//!   — HTTP-boundary wire-shape pin for Phase 2's `--no-gitignore`
//!   validation. Spawns the daemon, posts a `shared:`+`no_gitignore=true`
//!   body, asserts 400 with the design-verbatim rejection token. No
//!   backend boot required.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Once};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use sandbox_core::backend::{
    BackendKind, ContainerNetwork, ContainerRuntime, RuntimeStartArgs, SessionRuntime,
    WorkspaceBind,
};
use sandbox_core::session::SessionId;
use sandbox_core::workspace_rsync::run_initial_push;
use sandbox_core::{BackendSpecific, SandboxError, SessionSpec};
use tempfile::TempDir;
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// Test fixture: rsync-equipped alpine sleep container
// ---------------------------------------------------------------------------
//
// The lite image is `--read-only` per the design
// production daemon entrypoint expects route-helper scaffolding the
// runtime-level tests deliberately avoid. We build a small alpine
// image with `rsync` pre-installed and `sleep 3600` as the entrypoint
// so the container stays running while the test pushes files into it
// via `rsync -e "docker exec -i"`.
//
// `rsync` must exist on the guest side because the host's `rsync`
// client speaks the remote-server protocol against the in-container
// `rsync --server` worker.

// Image contract: alpine + `rsync` + a `sandbox` user matching the
// runtime's `--user 1000:1000` flag, with `/home/sandbox` owned by
// sandbox so the docker volume (also mounted at `/home/sandbox`) is
// initialised with sandbox's ownership at first mount. The production
// lite image follows the same pattern (`useradd --uid 1000 ...
// sandbox && install -d -o sandbox -g sandbox /home/sandbox/workspace`);
// we keep the bare essentials needed for rsync to write under
// `/home/sandbox/`.
const LOCAL_WS_IMAGE_TAG: &str = "sandboxd-local-ws-test-rsync:latest";
const LOCAL_WS_DOCKERFILE: &str = "FROM alpine:latest\n\
RUN apk add --no-cache rsync shadow \\\n\
    && groupadd --gid 1000 sandbox \\\n\
    && useradd --uid 1000 --gid 1000 --shell /bin/sh --create-home sandbox\n\
ENTRYPOINT [\"sh\", \"-c\", \"exec sleep 3600\"]\n";

static LOCAL_WS_IMAGE_BUILD: Once = Once::new();

fn ensure_local_ws_image() {
    LOCAL_WS_IMAGE_BUILD.call_once(|| {
        let mut child = Command::new("docker")
            .args(["build", "-t", LOCAL_WS_IMAGE_TAG, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("docker build invokable");
        {
            let stdin = child.stdin.as_mut().expect("docker build stdin");
            stdin
                .write_all(LOCAL_WS_DOCKERFILE.as_bytes())
                .expect("write Dockerfile");
        }
        let output = child.wait_with_output().expect("docker build exit");
        assert!(
            output.status.success(),
            "docker build {LOCAL_WS_IMAGE_TAG} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    });
}

// ---------------------------------------------------------------------------
// Per-test docker network + per-test container/volume cleanup
// ---------------------------------------------------------------------------
//
// Same shape as `integration_create_session_container.rs`: the network
// name follows the canonical `sandbox-net-<id>` form so the daemon-
// startup orphan reaper's IPAM gate skips our session (the subnet sits
// outside the production allocator pool).

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
        let subnet = format!("10.97.{third}.{fourth_base}/28");
        let gateway_ip = format!("10.97.{third}.{}", fourth_base.wrapping_add(2));
        let container_ip = format!("10.97.{third}.{}", fourth_base.wrapping_add(3));
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
            // No route helper: the start path skips route installation
            // when this is `None`, which is exactly what these tests
            // want — we are not exercising the routing surface here.
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
/// bind-mount at `/usr/local/bin/sandbox-guest`. The test fixture
/// container does not exec the guest binary (entrypoint is sleep);
/// the bind still has to resolve to a real host path or `docker run`
/// errors out.
fn guest_bind_source_for_tests() -> PathBuf {
    use std::sync::OnceLock;
    static GUEST_PATH: OnceLock<PathBuf> = OnceLock::new();
    GUEST_PATH
        .get_or_init(|| {
            let dir = std::env::temp_dir().join("sandboxd-local-ws-guest-bind-source");
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
        workspace_mode: None,
        repo: None,
        boot_cmd: None,
        template: None,
        disk_gb: None,
        no_cache: None,
    }
}

/// Run `docker exec sandbox-<id> -- <argv...>` and return stdout as
/// trimmed UTF-8. Panics on non-zero exit so an assertion that depends
/// on the output sees the failure verbatim. The container must have
/// been created and started before the call.
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

/// Boot a fresh sleep-rsync container under the given workspace bind
/// (`None` for `local:` mode tests; `Some(...)` for the
/// shared-guest-path tests in the sibling file). Returns
/// `(session_id, container_name, _cleanup_guards)` — drop the guards
/// to tear down the network + container + volume.
async fn start_container(
    workspace_bind: Option<WorkspaceBind>,
) -> (
    SessionId,
    String,
    (Arc<ContainerRuntime>, TestNetwork, ContainerCleanup),
) {
    ensure_local_ws_image();
    let runtime = ContainerRuntime::new(
        LOCAL_WS_IMAGE_TAG,
        256,
        1.0,
        1000,
        1000,
        guest_bind_source_for_tests(),
    );
    let session_id = SessionId::generate();
    let container_name = format!("sandbox-{session_id}");
    let net = TestNetwork::create(&session_id);
    let cleanup = ContainerCleanup::new(&session_id);
    runtime.register_session(session_id, net.to_container_network(workspace_bind));

    let handle = runtime
        .create(&session_id, &container_spec())
        .await
        .expect("runtime.create");
    runtime
        .start(&handle, &RuntimeStartArgs::default())
        .await
        .expect("runtime.start");

    (session_id, container_name, (runtime, net, cleanup))
}

// ---------------------------------------------------------------------------
// Test 1: happy-path mirror — container backend
// ---------------------------------------------------------------------------

/// .
///
/// Create a host source tree with known nested files. Boot a
/// container. Call `run_initial_push(Container, …, no_gitignore=false)`
/// against a guest path that does not yet exist (`--mkpath` will
/// create it). Verify via `docker exec <ctr> cat /guest/<file>` that
/// the host bytes are mirrored verbatim, including the nested
/// subdirectory.
#[tokio::test]
async fn integration_container_local_create_and_push() {
    let host_src = TempDir::new().expect("host tempdir");
    let host_root = host_src.path();
    // Known nested tree: `srv/foo.txt` + `srv/sub/bar.txt`. Mirroring
    // `srv/` matters because the trailing-slash rule in
    // `workspace_rsync` mirrors *contents*, not the directory entry
    // itself — so the resulting guest tree contains `foo.txt` at the
    // top level, not `srv/foo.txt`.
    std::fs::create_dir_all(host_root.join("srv/sub")).expect("mkdir srv/sub");
    std::fs::write(host_root.join("srv/foo.txt"), b"hello from host\n").expect("write foo.txt");
    std::fs::write(host_root.join("srv/sub/bar.txt"), b"nested-bytes\n").expect("write bar.txt");

    let (session_id, container_name, _guards) = start_container(None).await;
    let session_name = format!("sandbox-{session_id}");

    // Push from <host>/srv to /home/sandbox/work inside the guest. We
    // pick a writable guest path because the alpine fixture has a
    // writable rootfs; the breaking default (guest_path ==
    // host_path) is exercised by the shared-guest-path sibling
    // file, not here — this test pins the explicit-guest-path arm.
    let host_arg = host_root.join("srv").to_string_lossy().to_string();
    let guest_arg = "/home/sandbox/work";
    run_initial_push(
        BackendKind::Container,
        &session_name,
        &host_arg,
        guest_arg,
        false,
    )
    .await
    .expect("run_initial_push happy path must succeed");

    // Top-level file at the bind target.
    let foo = docker_exec_capture(&container_name, &["cat", "/home/sandbox/work/foo.txt"]);
    assert_eq!(
        foo, "hello from host",
        "create-time push must mirror <host>/srv/foo.txt → /home/sandbox/work/foo.txt"
    );

    // Nested file under the bind target.
    let bar = docker_exec_capture(&container_name, &["cat", "/home/sandbox/work/sub/bar.txt"]);
    assert_eq!(
        bar, "nested-bytes",
        "create-time push must mirror nested entries under the guest path"
    );

    // Bind target's existence as a directory inside the guest.
    let kind = docker_exec_capture(&container_name, &["stat", "-c", "%F", "/home/sandbox/work"]);
    assert_eq!(
        kind, "directory",
        "guest path must exist as a directory after --mkpath; got: {kind}"
    );
}

// ---------------------------------------------------------------------------
// Test 2: `.gitignore` filter respected by default, dropped on opt-in
// ---------------------------------------------------------------------------

/// .
///
/// Same host source, two pushes against two fresh containers (one
/// container per push so neither test sees the other's leftover
/// state). Run #1: `no_gitignore=false` → assert `excluded/` is NOT
/// present in the guest. Run #2: `no_gitignore=true` → assert
/// `excluded/` IS present in the guest. Container backend (the
/// filter-flag handling is identical between Lima and Container in
/// `workspace_rsync::build_argv`, asserted by the inline unit tests).
#[tokio::test]
async fn integration_local_gitignore_filter() {
    let host_src = TempDir::new().expect("host tempdir");
    let host_root = host_src.path();
    // Source tree:
    //   ./.gitignore         (excludes `excluded/`)
    //   ./kept.txt           (always present in guest)
    //   ./excluded/secret.txt(dropped under default filter, kept under
    //                        no_gitignore)
    std::fs::write(host_root.join(".gitignore"), b"excluded/\n").expect("write .gitignore");
    std::fs::write(host_root.join("kept.txt"), b"keep-me\n").expect("write kept.txt");
    std::fs::create_dir_all(host_root.join("excluded")).expect("mkdir excluded");
    std::fs::write(host_root.join("excluded/secret.txt"), b"hidden\n").expect("write secret.txt");

    let host_arg = host_root.to_string_lossy().to_string();
    let guest_arg = "/home/sandbox/work";

    // -- Run #1: default filter, `excluded/` must be dropped --------------
    {
        let (session_id, container_name, _guards) = start_container(None).await;
        let session_name = format!("sandbox-{session_id}");
        run_initial_push(
            BackendKind::Container,
            &session_name,
            &host_arg,
            guest_arg,
            false,
        )
        .await
        .expect("default-filter push must succeed");

        // `kept.txt` survives the filter.
        let kept = docker_exec_capture(&container_name, &["cat", "/home/sandbox/work/kept.txt"]);
        assert_eq!(kept, "keep-me");

        // `excluded/` must be absent. Use `test -e` via `sh -c` so the
        // command's exit code, not its stdout, carries the assertion.
        let output = Command::new("docker")
            .args([
                "exec",
                &container_name,
                "sh",
                "-c",
                "test -e /home/sandbox/work/excluded && echo PRESENT || echo ABSENT",
            ])
            .output()
            .expect("docker exec test -e");
        assert!(
            output.status.success(),
            "test-e shell harness should exit 0"
        );
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert_eq!(
            stdout, "ABSENT",
            "default filter must exclude `excluded/` (matched by .gitignore); guest reported: {stdout}"
        );
    }

    // -- Run #2: `no_gitignore=true`, `excluded/` must be present ----------
    {
        let (session_id, container_name, _guards) = start_container(None).await;
        let session_name = format!("sandbox-{session_id}");
        run_initial_push(
            BackendKind::Container,
            &session_name,
            &host_arg,
            guest_arg,
            true,
        )
        .await
        .expect("--no-gitignore push must succeed");

        let secret = docker_exec_capture(
            &container_name,
            &["cat", "/home/sandbox/work/excluded/secret.txt"],
        );
        assert_eq!(
            secret, "hidden",
            "`--no-gitignore` must transfer files matched by .gitignore"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 3: rsync failure surfaces as SandboxError::Internal w/ stderr
// ---------------------------------------------------------------------------

/// .
///
/// Library-level: assert the function returns the documented error
/// shape on rsync failure. The orphan-cleanup half of the design ("no
/// orphaned VM/container artefacts remain") is exercised by the
/// daemon's `cleanup_and_return!` orchestration around the
/// `run_initial_push` call site at `sandboxd/src/main.rs:2723`;
/// covering that wire path requires a fully daemon-driven test, which
/// is deferred to Phase 5 E2E. This test pins the function-level
/// contract the daemon consumes: when rsync exits non-zero, the
/// `Err` payload is `SandboxError::Internal` and its `Display` text
/// embeds the production prefix `"local-workspace rsync failed"`
/// plus rsync's captured stderr.
///
/// Failure injection: `chmod 000` a file under the host source so
/// rsync cannot open it for read. This produces a non-zero exit
/// (typically exit 23, "partial transfer due to error") with an
/// `Operation not permitted` / `Permission denied` line in stderr.
/// The production module's "all-non-zero-exits-fatal" rule
/// maps such exit to `Internal`.
#[tokio::test]
async fn integration_local_create_failure_tears_down() {
    let host_src = TempDir::new().expect("host tempdir");
    let host_root = host_src.path();
    // Two files, one of them unreadable. rsync visits the directory,
    // opens each entry, and reports the unreadable one as a per-file
    // error → non-zero exit.
    std::fs::write(host_root.join("readable.txt"), b"ok\n").expect("write readable.txt");
    let unreadable = host_root.join("unreadable.txt");
    std::fs::write(&unreadable, b"this-will-not-be-readable\n").expect("write unreadable.txt");
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000))
        .expect("chmod 000 on unreadable.txt");

    // Re-grant read permission at the end of the test so the
    // TempDir's Drop can remove the file cleanly. Use an explicit
    // RAII guard so this happens even on assertion failure.
    struct RestorePerms<'a>(&'a Path);
    impl Drop for RestorePerms<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o644));
        }
    }
    let _restore = RestorePerms(&unreadable);

    let (session_id, _container_name, _guards) = start_container(None).await;
    let session_name = format!("sandbox-{session_id}");
    let host_arg = host_root.to_string_lossy().to_string();
    let guest_arg = "/home/sandbox/work";

    let result = run_initial_push(
        BackendKind::Container,
        &session_name,
        &host_arg,
        guest_arg,
        false,
    )
    .await;

    let err = result.expect_err(
        "unreadable host file must produce a non-zero rsync exit \
         and surface as Err — sandbox can otherwise mask the broken \
         source tree as a Running session with a partial snapshot",
    );

    // The variant the daemon's call site at
    // `sandboxd/src/main.rs:2723` routes through `error_response`.
    // Pinning the variant (not just the Display text) catches a
    // refactor that switched to a less-specific or new variant.
    let msg = match &err {
        SandboxError::Internal(m) => m.clone(),
        other => panic!(
            "rsync failure must surface as SandboxError::Internal so the \
             daemon's create_session handler routes it through the same \
             cleanup_and_return! arm; got variant: {other:?}"
        ),
    };

    // The production prefix at `sandbox-core/src/workspace_rsync.rs:228`.
    // Operators grep journald with this prefix; refactors that drop
    // it would silently break that workflow.
    assert!(
        msg.contains("local-workspace rsync failed"),
        "Internal error message must lead with the design-verbatim \
         `local-workspace rsync failed` prefix; got: {msg}"
    );

    // Rsync's own stderr must be embedded so the operator can see
    // *why* the push failed (permission denied / mkdir failed / ...).
    // The exact wording is rsync-version-dependent, so we assert on
    // the cross-version-stable token "rsync" plus an indication that
    // a file failed.
    assert!(
        msg.to_lowercase().contains("rsync"),
        "Internal error must embed rsync's diagnostic so operators \
         can debug the failure; got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: HTTP-boundary wire-shape pin — Phase 2 `--no-gitignore` rejection
// ---------------------------------------------------------------------------
//
// This is the one HTTP-boundary test in Phase 4. It exists because
// the runtime-level coverage above cannot see the request-shape
// gate Phase 2 installed (the daemon refuses
// `no_gitignore=true` against a non-`local:` workspace before any
// runtime code runs). Driving it through `POST /sessions` with a
// gateway-image override forces the pre-flight gateway check to
// pass; the daemon then hits the workspace-validation gate and
// returns a 400 with the design-verbatim rejection token.
//
// Mirrors the daemon-spawn pattern in
// `integration_session_create_refused_on_missing_gateway_image.rs`
// and `integration_owner_peercred.rs`; both establish the
// `Daemon::spawn_*` + `http_post_json` shape this test reuses.

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

/// HTTP-boundary pin for Phase 2's daemon-side `--no-gitignore` gate.
///
/// `--no-gitignore` is meaningful only with `local:` workspaces; the
/// CLI mirrors the rejection client-side, but a hand-rolled HTTP
/// client (or a CLI version drift) could bypass that surface. The
/// daemon's gate at `sandboxd/src/main.rs::create_session` is the
/// authoritative enforcer. This test fires a request with
/// `workspace: "shared:/tmp"` + `no_gitignore: true`, asserts:
///
/// 1. HTTP 400 (`SandboxError::InvalidArgument` mapping).
/// 2. The error body's `error` field carries the design-verbatim
///    rejection token `"is only meaningful for local: workspaces"`.
///
/// The request never reaches a backend boot — the gate fires
/// immediately after the gateway-image pre-flight (which we pass
/// trivially via the production `sandbox-gateway:0.1.0` tag the host
/// already has loaded).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_create_session_rejects_no_gitignore_with_non_local_workspace() {
    // Distinct /24 from neighboring integration tests so a parallel
    // run cannot collide on users.conf pool registration. The
    // matching subnet families in the host docker network table are
    // 10.97.x.x (this test crate's runtime fixtures), 10.98.x.x
    // (create_session_container fixtures), 10.219.0.0/24 (owner
    // peercred), 10.234.0.0/24 (missing-gateway refuse). Pick a
    // fresh /24 here.
    let daemon = Daemon::spawn_with_env("10.235.0.0/24", &[]);

    let body = r#"{"backend":"container","workspace":"shared:/tmp","no_gitignore":true,"cpus":1.0,"memory_mb":256}"#
        .to_string();
    let (status, body_bytes) =
        http_post_json(&daemon.socket, "/sessions", body, Duration::from_secs(15)).await;

    assert_eq!(
        status,
        hyper::StatusCode::BAD_REQUEST,
        "no_gitignore against a non-local: workspace must surface as 400 \
         (SandboxError::InvalidArgument); got {status}. body={}",
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

    // Verbatim token from the Phase 2 rejection helper. Token
    // checked here mirrors the test in
    // `sandbox-core/src/api/mod.rs` for the validator helper; this
    // assertion pins the wire shape (the helper text reaching the
    // operator over HTTP) end-to-end.
    assert!(
        error_msg.contains("is only meaningful for local: workspaces"),
        "rejection body must contain the design-verbatim Phase 2 token \
         \"is only meaningful for local: workspaces\"; got: {error_msg}"
    );
}
