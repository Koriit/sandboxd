//! Daemon-driven HTTP-boundary integration coverage for the workspace
//! lock surface (`POST` / `DELETE /sessions/{id}/workspace-lock`) plus
//! the lifecycle 409 path on `stop` / `remove`, and a single
//! container-backend pull happy-path that mirrors the
//! `integration_container_local_create_and_push` shape.
//!
//! ## Lima coverage deferred to E2E
//!
//! The Lima half of the local-pull exercise
//! (`integration_lima_local_pull`) is deferred to E2E with the same
//! rationale as `integration_local_workspace.rs`: booting a real Lima
//! VM at the runtime layer requires `NetworkManager` plumbing from
//! `AppState` that is out of scope here, and the per-test runtime
//! would blow past the project's per-test budget.
//!
//! ## What's covered
//!
//! - `integration_container_local_pull` — Container backend, real
//!   alpine+rsync fixture container. Seed contents inside the guest via
//!   `docker exec`, run a hand-rolled `rsync` pull from host
//!   (`docker exec -i` transport), assert the host tempdir mirrors the
//!   guest tree. Runtime-level — no daemon — mirroring the push
//!   shape inverted.
//!
//! - `integration_workspace_lock_push_blocks_pull` — Daemon HTTP path:
//!   acquire `op=push` → 200 with token; acquire `op=pull` → 409 with
//!   the design-pinned `"active push operation"` token; release with the
//!   first token → 200; re-acquire `op=pull` → 200.
//!
//! - `integration_workspace_lock_blocks_stop` — Daemon HTTP path:
//!   acquire `op=push`; `POST /sessions/<id>/stop` → 409 carrying the
//!   `sandbox workspace unlock` recovery hint; release; re-`POST stop`
//!   → 200. Pins the atomicity contract for stop.
//!
//! - `integration_workspace_lock_blocks_delete` — Daemon HTTP path:
//!   acquire `op=push`; `DELETE /sessions/<id>` → 409; release;
//!   re-`DELETE` → 200. Pins the atomicity contract for delete.
//!
//! - `integration_workspace_lock_force_release` — Daemon HTTP path:
//!   acquire `push` (token T1); release with a different token +
//!   `force=true` → 200; re-acquire `pull` → 200 (lock genuinely
//!   cleared).
//!
//! - `integration_workspace_lock_idempotent_release` — Daemon HTTP
//!   path: release on Unlocked is idempotent for both `force=false`
//!   and `force=true`; release with wrong token + `force=false` on
//!   Locked → 409; release with wrong token + `force=true` on Locked
//!   → 200.
//!
//! - `integration_workspace_lock_acquire_rejected_when_not_running` —
//!   Daemon HTTP path: seed a session in `Creating` state (not
//!   `Running`); acquire → 400 with the design-verbatim wording
//!   `"session is in state ...; workspace operations require Running"`.
//!   Pins the state-gate.
//!
//! ## Workspace-mode choice for tests 2-7
//!
//! The acquire handler's only precondition is `state == Running`, not workspace
//! mode, so tests 2-7 seed a session row directly into `SessionStore`
//! with the default `SessionConfig` (no workspace mode) and
//! force-transition it to `Running` via
//! `SessionStore::update_state_reconcile`. There is no real container
//! backing the session — the lock subsystem is entirely a daemon-side
//! state machine, gated only on the persisted session state, so
//! standing up a docker container for tests 2-7 would only slow them
//! down without exercising additional contract surface.
//!
//! Test 1 (`integration_container_local_pull`) DOES require a real
//! container because it exercises the actual rsync transport against a
//! live `docker exec -i` shell. It uses the same alpine+rsync fixture
//! image as the push test.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Once};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::TokioIo;
use sandbox_core::backend::{
    BackendKind, ContainerNetwork, ContainerRuntime, RuntimeStartArgs, SessionRuntime,
};
use sandbox_core::session::SessionId;
use sandbox_core::{BackendSpecific, SessionConfig, SessionSpec, SessionState, SessionStore};
use tempfile::TempDir;
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// Binary resolution + username helper
// ---------------------------------------------------------------------------

fn sandboxd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandboxd"))
}

/// Resolve the current process's username via `getpwuid_r` — the same
/// route `PeerCredListener::accept` walks for every incoming
/// connection. Matching the daemon's resolution function makes the
/// fixture and the assertion run through identical code.
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

// ---------------------------------------------------------------------------
// Daemon fixture — spawn the real `sandboxd` binary against an isolated
// tempdir + pre-seeded SessionStore.
// ---------------------------------------------------------------------------

struct Daemon {
    socket: PathBuf,
    proc: Option<Child>,
    tmp: TempDir,
}

impl Daemon {
    /// Spawn against the given pre-seeded `base_dir`. The directory
    /// must already contain whatever DB rows the test wants the daemon
    /// to surface — seeding happens BEFORE the spawn so the test can
    /// drop the seed `SessionStore` handle (SQLite cooperates with one
    /// writer at a time).
    fn spawn_with_base_dir(tmp: TempDir, base_dir: PathBuf, pool_cidr: &str) -> Self {
        let user = current_username();
        let socket = tmp.path().join("sandboxd.sock");
        let users_conf = write_users_conf(tmp.path(), &user, pool_cidr);
        std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");

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
            // The daemon resolves and cap-checks `sandbox-lima-helper` at
            // startup (a fatal prerequisite since the cross-user Lima model
            // landed). Point it at the `test-env-override` helper that
            // `make install-lima-helper-test-cap` installs so the daemon can
            // bind its socket on hosts without the production helper.
            .env(
                "SANDBOX_LIMA_HELPER_PATH",
                "/usr/local/libexec/sandboxd-test/sandbox-lima-helper",
            )
            .stdout(Stdio::from(stdout_fh))
            .stderr(Stdio::from(stderr_fh));
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

/// Seed one container-backed session row, transition it to `Running`
/// via the per-caller-filtered `update_state` write, and return its
/// `SessionId` for use in test URLs. The session has no associated
/// container, network, or `network_info` row — the workspace-lock
/// subsystem only cares about `session.state`, and lifecycle paths
/// (`stop`, `remove`) tolerate missing containers via their "No such
/// container" idempotent arms.
///
/// Two reasons we seed via the API rather than firing a `POST /sessions`:
///
/// 1. Speed — no `docker create`, no network allocation, no real
///    container boot.
/// 2. Determinism — `POST /sessions` against a seeded daemon would
///    take the create code path and try to actually allocate a network
///    + container. We just need a row the daemon can resolve.
///
/// The owner_username must match `current_username()` so the daemon's
/// per-caller storage filter surfaces the row to the test process.
///
/// The transition goes through `SessionStore::update_state` (not the
/// reconcile-bypass variant). `update_state` is a normal request-path
/// API — the per-caller filter matches the caller we pass here against
/// the row's `owner_username`, and the `Creating -> Running` step is a
/// valid forward transition under `SessionState::can_transition_to`.
/// Going through this path keeps the test out of the static-analysis
/// allow-list (`sandbox-core/tests/update_state_reconcile_allow_list.rs`)
/// for the reconcile-only API.
fn seed_running_container_session(base_dir: &Path) -> SessionId {
    let (store, _orphans) =
        SessionStore::new(base_dir.to_path_buf()).expect("open store for seeding");
    let store = Arc::new(store);
    let owner = current_username();
    let session = store
        .create_session_with_backend(
            SessionConfig::default(),
            None,
            BackendKind::Container,
            &owner,
            0,
            "",
            None,
            None,
        )
        .expect("seed session row");
    // Transition Creating -> Running through the owner-filtered API.
    // The acquire handler's `session_state != Running` gate is the only
    // precondition we need a Running row to satisfy.
    store
        .update_state(&session.id, &owner, SessionState::Running)
        .expect("transition seeded row to Running");
    session.id
}

/// Same as [`seed_running_container_session`] but leaves the row at
/// `Creating` — used by the not-Running rejection test.
fn seed_creating_container_session(base_dir: &Path) -> SessionId {
    let (store, _orphans) =
        SessionStore::new(base_dir.to_path_buf()).expect("open store for seeding");
    let store = Arc::new(store);
    let session = store
        .create_session_with_backend(
            SessionConfig::default(),
            None,
            BackendKind::Container,
            &current_username(),
            0,
            "",
            None,
            None,
        )
        .expect("seed session row");
    session.id
}

// ---------------------------------------------------------------------------
// HTTP-over-unix client
// ---------------------------------------------------------------------------

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

async fn http_delete_json(
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
            .method("DELETE")
            .uri(path)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("content-length", body.len().to_string())
            .body(body)
            .expect("build DELETE request");
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

/// `DELETE` with an empty body — `remove_session` does not deserialise
/// a request body; sending the empty marker `Empty<Bytes>` matches the
/// shape `sandbox-cli` uses.
async fn http_delete_empty(
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
            .method("DELETE")
            .uri(path)
            .header("host", "localhost")
            .body(Empty::<hyper::body::Bytes>::new())
            .expect("build DELETE request");
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

/// Wire-level acquire helper: POST to the workspace-lock endpoint and
/// return `(status, body_bytes)`. Tests parse the body themselves so
/// they can assert on both the success-shape (`lock_token`) and the
/// conflict-shape (`error`) without ambiguity.
async fn acquire_lock(
    socket: &Path,
    session_id: &SessionId,
    op: &str,
) -> (hyper::StatusCode, Vec<u8>) {
    let url = format!("/sessions/{session_id}/workspace-lock");
    let body = format!(r#"{{"op":"{op}"}}"#);
    http_post_json(socket, &url, body, Duration::from_secs(15)).await
}

/// Wire-level release helper. The token is sent as a raw string so the
/// test can deliberately exercise the unparseable-token sentinel path
/// (empty string, garbage) when needed.
async fn release_lock(
    socket: &Path,
    session_id: &SessionId,
    token: &str,
    force: bool,
) -> (hyper::StatusCode, Vec<u8>) {
    let url = format!("/sessions/{session_id}/workspace-lock");
    let body = format!(r#"{{"lock_token":"{token}","force":{force}}}"#);
    http_delete_json(socket, &url, body, Duration::from_secs(15)).await
}

/// Parse the `error` field out of an error envelope. Panics if the
/// body is not the expected JSON shape so an assertion failure surfaces
/// the raw bytes verbatim.
fn parse_error_field(body: &[u8]) -> String {
    let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or_else(|e| {
        panic!(
            "rejection body must be valid JSON; parse error: {e}; body={}",
            String::from_utf8_lossy(body)
        )
    });
    parsed
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("error body must have a top-level `error` string; got: {parsed}"))
        .to_string()
}

/// Parse the `lock_token` field out of an acquire success response.
fn parse_lock_token(body: &[u8]) -> String {
    let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or_else(|e| {
        panic!(
            "acquire success body must be valid JSON; parse error: {e}; body={}",
            String::from_utf8_lossy(body)
        )
    });
    parsed
        .get("lock_token")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            panic!("acquire success body must have a top-level `lock_token` string; got: {parsed}")
        })
        .to_string()
}

// ===========================================================================
// Test 1 — Container backend `local:` pull round-trip (runtime-level,
// no daemon).
// ===========================================================================
//
// Mirrors `integration_local_workspace.rs::integration_container_local_create_and_push`
// but with the rsync direction inverted. Uses the same alpine+rsync
// fixture image so the in-container rsync server can speak the
// remote-server protocol against the host's rsync client over the
// `docker exec -i` transport.

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

struct TestNetwork {
    name: String,
    container_ip: String,
    gateway_ip: String,
}

impl TestNetwork {
    fn create(session_id: &SessionId) -> Self {
        // Distinct /28 base from neighbouring integration test crates
        // (create_and_push uses 10.97.x.y, shared-guest-path uses
        // 10.96.x.y, container-runtime fixtures use 10.98.x.y). Use
        // 10.95.x.y here.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let third = (nanos as u8).wrapping_mul(1);
        let fourth_base = (nanos.wrapping_shr(8) as u8).wrapping_mul(16);
        let subnet = format!("10.95.{third}.{fourth_base}/28");
        let gateway_ip = format!("10.95.{third}.{}", fourth_base.wrapping_add(2));
        let container_ip = format!("10.95.{third}.{}", fourth_base.wrapping_add(3));
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

    fn to_container_network(&self) -> ContainerNetwork {
        ContainerNetwork {
            docker_network: self.name.clone(),
            container_ip: self.container_ip.parse().unwrap(),
            gateway_ip: self.gateway_ip.parse().unwrap(),
            workspace_bind: None,
            route_helper_path: None,
            ca_host_path: None,
            ssh_host_dir: None,
            operator_identity: None,
            owner_pool: None,
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

fn guest_bind_source_for_tests() -> PathBuf {
    use std::sync::OnceLock;
    static GUEST_PATH: OnceLock<PathBuf> = OnceLock::new();
    GUEST_PATH
        .get_or_init(|| {
            let dir = std::env::temp_dir().join("sandboxd-workspace-lock-guest-bind-source");
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
        operator_identity: None,
    }
}

/// .
///
/// Seed contents inside the guest by `docker exec`-ing `mkdir` +
/// `tee`. Then invoke the host-side `rsync` client against
/// `sandbox-<id>:/guest/path/` with the `-e "docker exec -i"`
/// transport (the same shell-transport string `plan_workspace_sync_argv`
/// emits for the container backend, and the same string the daemon-side
/// `workspace_rsync::run_initial_push` uses for the push direction).
/// Verify the host tempdir mirrors the guest tree.
///
/// Container backend only — the Lima half is deferred to E2E.
#[tokio::test]
async fn integration_container_local_pull() {
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
    let _cleanup = ContainerCleanup::new(&session_id);
    runtime.register_session(session_id, net.to_container_network());

    let handle = runtime
        .create(&session_id, &container_spec())
        .await
        .expect("runtime.create");
    runtime
        .start(&handle, &RuntimeStartArgs::default())
        .await
        .expect("runtime.start");

    // Seed a known nested tree inside the guest. /home/sandbox is the
    // writable area on the alpine fixture (mirroring the production
    // lite image's writable mount).
    let seed_status = Command::new("docker")
        .args([
            "exec",
            &container_name,
            "sh",
            "-c",
            "mkdir -p /home/sandbox/work/sub \
             && printf 'pulled-from-guest\\n' > /home/sandbox/work/foo.txt \
             && printf 'nested-from-guest\\n' > /home/sandbox/work/sub/bar.txt",
        ])
        .status()
        .expect("docker exec for guest seed");
    assert!(
        seed_status.success(),
        "guest-side seed of /home/sandbox/work/{{foo.txt,sub/bar.txt}} must succeed"
    );

    // Host destination — a fresh empty tempdir. The pull should
    // populate it with the guest tree.
    let host_dst = TempDir::new().expect("host dst tempdir");
    let host_dst_path = host_dst.path().to_path_buf();

    // Hand-rolled rsync argv mirroring `plan_workspace_sync_argv`'s
    // output for a pull on the container backend:
    //   rsync -aL --delete --filter=':- .gitignore'
    //         -e "docker exec -i"
    //         sandbox-<id>:/home/sandbox/work/  <host_dst>/
    //
    // Trailing slashes on both ends are load-bearing: rsync mirrors
    // the *contents* of the directory, not the directory entry itself.
    let remote = format!("{container_name}:/home/sandbox/work/");
    let host_arg = format!("{}/", host_dst_path.display());
    let pull_output = Command::new("rsync")
        .args([
            "-aL",
            "--delete",
            "--filter=:- .gitignore",
            "-e",
            "docker exec -i",
            &remote,
            &host_arg,
        ])
        .output()
        .expect("rsync invokable");
    assert!(
        pull_output.status.success(),
        "rsync pull (guest → host) must succeed; stderr: {}",
        String::from_utf8_lossy(&pull_output.stderr)
    );

    // Top-level file pulled to the host.
    let foo = std::fs::read_to_string(host_dst_path.join("foo.txt")).expect("read host foo.txt");
    assert_eq!(
        foo.trim(),
        "pulled-from-guest",
        "host destination must carry the guest's /home/sandbox/work/foo.txt verbatim"
    );

    // Nested file pulled to the host.
    let bar =
        std::fs::read_to_string(host_dst_path.join("sub/bar.txt")).expect("read host sub/bar.txt");
    assert_eq!(
        bar.trim(),
        "nested-from-guest",
        "host destination must carry the nested guest entry verbatim"
    );

    // Tear the container down explicitly so a stray container does not
    // race the next test's namespace.
    runtime.delete(&handle, 0).await.expect("runtime.delete");
}

// ===========================================================================
// Tests 2-7 — Daemon HTTP path against a seeded `Running` session.
// ===========================================================================
//
// Each test stands up its own daemon against its own tempdir +
// users.conf pool /24 so parallel-run isolation holds even if nextest's
// `docker-sandbox-namespace` serialisation is loosened in the future.
// The pool CIDR is unique per test (10.236..10.241) — outside the /24s
// the existing daemon-spawning tests claim (see comment block on the
// other integration_local_workspace test in this crate).

/// .
///
/// 1. Acquire `op=push` against the seeded `Running` session → 200,
///    body carries a `lock_token`.
/// 2. Acquire `op=pull` while the push lock is held → 409 with body
///    `error` containing the design-pinned `"active push operation"`
///    token.
/// 3. Release with the original token + `force=false` → 200.
/// 4. Re-acquire `op=pull` → 200 (lock genuinely cleared).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_workspace_lock_push_blocks_pull() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir = tmp.path().join("state");
    std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");
    let session_id = seed_running_container_session(&base_dir);

    let daemon = Daemon::spawn_with_base_dir(tmp, base_dir, "10.236.0.0/24");

    // (1) push acquire — 200 + lock_token
    let (status, body) = acquire_lock(&daemon.socket, &session_id, "push").await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "first acquire (op=push) on Unlocked must return 200; got {status}, body: {}",
        String::from_utf8_lossy(&body)
    );
    let push_token = parse_lock_token(&body);
    assert!(
        !push_token.is_empty(),
        "lock_token must be a non-empty string; got {push_token:?}"
    );

    // (2) pull acquire while push is held — 409, "active push operation"
    let (status, body) = acquire_lock(&daemon.socket, &session_id, "pull").await;
    assert_eq!(
        status,
        hyper::StatusCode::CONFLICT,
        "second acquire (op=pull) while push is held must return 409; got {status}, body: {}",
        String::from_utf8_lossy(&body)
    );
    let err = parse_error_field(&body);
    assert!(
        err.contains("active push operation"),
        "conflict body must contain the design-pinned `active push operation` token; got: {err}"
    );

    // (3) release with the original token — 200
    let (status, body) = release_lock(&daemon.socket, &session_id, &push_token, false).await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "release with matching token must return 200; got {status}, body: {}",
        String::from_utf8_lossy(&body)
    );

    // (4) re-acquire pull — 200
    let (status, body) = acquire_lock(&daemon.socket, &session_id, "pull").await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "pull acquire after clean release must return 200; got {status}, body: {}",
        String::from_utf8_lossy(&body)
    );
    let pull_token = parse_lock_token(&body);
    assert_ne!(
        pull_token, push_token,
        "the second acquire must mint a fresh token, not reuse the first"
    );
}

/// .
///
/// Phase 4 atomicity contract: while a workspace operation holds the
/// lock, `POST /sessions/<id>/stop` must refuse with HTTP 409 and the
/// `sandbox workspace unlock` recovery hint. After the lock is
/// released, the stop must proceed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_workspace_lock_blocks_stop() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir = tmp.path().join("state");
    std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");
    let session_id = seed_running_container_session(&base_dir);

    let daemon = Daemon::spawn_with_base_dir(tmp, base_dir, "10.237.0.0/24");

    // Acquire push.
    let (status, body) = acquire_lock(&daemon.socket, &session_id, "push").await;
    assert_eq!(status, hyper::StatusCode::OK, "push acquire must succeed");
    let token = parse_lock_token(&body);

    // POST /sessions/<id>/stop → 409 with the recovery hint.
    let stop_url = format!("/sessions/{session_id}/stop");
    let (status, body) = http_post_json(
        &daemon.socket,
        &stop_url,
        String::new(),
        Duration::from_secs(15),
    )
    .await;
    assert_eq!(
        status,
        hyper::StatusCode::CONFLICT,
        "stop must refuse with 409 while a workspace op is in flight; got {status}, body: {}",
        String::from_utf8_lossy(&body)
    );
    let err = parse_error_field(&body);
    assert!(
        err.contains("active push operation"),
        "stop refusal must name the active op; got: {err}"
    );
    assert!(
        err.contains("sandbox workspace unlock"),
        "stop refusal must carry the `sandbox workspace unlock` recovery hint; got: {err}"
    );

    // Release the lock cleanly.
    let (status, _body) = release_lock(&daemon.socket, &session_id, &token, false).await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "clean release after the stop-409 must succeed"
    );

    // Re-POST stop — must proceed. The session row is still Running
    // (we never transitioned away from it), so stop runs through its
    // happy path. The runtime layer is idempotent on missing
    // containers ("No such container" → Ok); the gateway / network
    // teardown is best-effort (every step is `let _ = ...`); and the
    // DB transition Running → Stopped is the only durable step we
    // care about.
    let (status, body) = http_post_json(
        &daemon.socket,
        &stop_url,
        String::new(),
        Duration::from_secs(30),
    )
    .await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "stop after release must succeed; got {status}, body: {}",
        String::from_utf8_lossy(&body)
    );
}

/// .
///
/// Phase 4 atomicity contract mirror for the remove path. While a
/// workspace operation holds the lock, `DELETE /sessions/<id>` must
/// refuse with HTTP 409. After release, the delete must proceed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_workspace_lock_blocks_delete() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir = tmp.path().join("state");
    std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");
    let session_id = seed_running_container_session(&base_dir);

    let daemon = Daemon::spawn_with_base_dir(tmp, base_dir, "10.238.0.0/24");

    // Acquire push.
    let (status, body) = acquire_lock(&daemon.socket, &session_id, "push").await;
    assert_eq!(status, hyper::StatusCode::OK, "push acquire must succeed");
    let token = parse_lock_token(&body);

    // DELETE /sessions/<id> → 409.
    let url = format!("/sessions/{session_id}");
    let (status, body) = http_delete_empty(&daemon.socket, &url, Duration::from_secs(15)).await;
    assert_eq!(
        status,
        hyper::StatusCode::CONFLICT,
        "delete must refuse with 409 while a workspace op is in flight; got {status}, body: {}",
        String::from_utf8_lossy(&body)
    );
    let err = parse_error_field(&body);
    assert!(
        err.contains("active push operation"),
        "delete refusal must name the active op; got: {err}"
    );
    assert!(
        err.contains("sandbox workspace unlock"),
        "delete refusal must carry the `sandbox workspace unlock` recovery hint; got: {err}"
    );

    // Release.
    let (status, _body) = release_lock(&daemon.socket, &session_id, &token, false).await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "release after the delete-409 must succeed"
    );

    // Re-DELETE — must succeed (idempotent runtime teardown on a
    // missing container, DB row deletion). The handler returns
    // `204 NO_CONTENT` on the success path; accept either 2xx success
    // code (a future shift to `200 + body` would still satisfy the
    // "delete succeeded" contract this test pins).
    let (status, body) = http_delete_empty(&daemon.socket, &url, Duration::from_secs(30)).await;
    assert!(
        status.is_success(),
        "delete after release must return a 2xx status; got {status}, body: {}",
        String::from_utf8_lossy(&body)
    );
}

/// .
///
/// Operator escape hatch: `force=true` skips the token-match check.
/// Acquire push (token T1), release with a deliberately different
/// token + `force=true` → 200, re-acquire pull → 200 (the lock was
/// genuinely cleared, not just made invisible).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_workspace_lock_force_release() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir = tmp.path().join("state");
    std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");
    let session_id = seed_running_container_session(&base_dir);

    let daemon = Daemon::spawn_with_base_dir(tmp, base_dir, "10.239.0.0/24");

    // Acquire push — token T1.
    let (status, body) = acquire_lock(&daemon.socket, &session_id, "push").await;
    assert_eq!(status, hyper::StatusCode::OK);
    let t1 = parse_lock_token(&body);

    // Different, syntactically valid token — guaranteed not to match T1.
    let unrelated = uuid::Uuid::new_v4().to_string();
    assert_ne!(
        unrelated, t1,
        "test wiring: unrelated token must differ from T1"
    );

    // Force-release with the unrelated token.
    let (status, _body) = release_lock(&daemon.socket, &session_id, &unrelated, true).await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "force-release with a non-matching token must succeed"
    );

    // Re-acquire pull — lock must be Unlocked, so this returns 200.
    let (status, body) = acquire_lock(&daemon.socket, &session_id, "pull").await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "pull acquire after force-release must succeed; lock must be genuinely cleared; got {status}, body: {}",
        String::from_utf8_lossy(&body)
    );
    let _ = parse_lock_token(&body);
}

/// .
///
/// Two contracts:
///
/// 1. **Release on Unlocked is idempotent** for both `force=false`
///    and `force=true` — re-issuing `unlock` against an already-clean
///    session is a no-op success (so a CLI that lost track of its own
///    state can self-recover without surfacing a spurious 409).
///
/// 2. **Release with a wrong token on Locked** distinguishes `force`:
///    `force=false` → 409; `force=true` → 200. This is the same
///    adjudication the unit tests cover, pinned end-to-end through
///    the HTTP boundary (the daemon's handler maps unparseable input
///    to the `LockToken::nil` sentinel before delegating to
///    `LockState::release`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_workspace_lock_idempotent_release() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir = tmp.path().join("state");
    std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");
    let session_id = seed_running_container_session(&base_dir);

    let daemon = Daemon::spawn_with_base_dir(tmp, base_dir, "10.240.0.0/24");

    // (1a) Release on Unlocked with the empty-string sentinel +
    //      force=false. The daemon maps the unparseable token to nil
    //      and delegates to `LockState::release(nil, false)`. The
    //      Unlocked-state branch returns Ok unconditionally, so the
    //      handler responds 200 regardless of the token shape.
    let (status, _body) = release_lock(&daemon.socket, &session_id, "", false).await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "release on Unlocked (force=false) must be idempotent; got {status}"
    );

    // (1b) Same, with force=true.
    let (status, _body) = release_lock(&daemon.socket, &session_id, "", true).await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "release on Unlocked (force=true) must be idempotent; got {status}"
    );

    // Now acquire push to set up the wrong-token cases.
    let (status, body) = acquire_lock(&daemon.socket, &session_id, "push").await;
    assert_eq!(status, hyper::StatusCode::OK);
    let _held = parse_lock_token(&body);

    // (2a) Release on Locked with wrong token + force=false → 409.
    let wrong = uuid::Uuid::new_v4().to_string();
    let (status, body) = release_lock(&daemon.socket, &session_id, &wrong, false).await;
    assert_eq!(
        status,
        hyper::StatusCode::CONFLICT,
        "release with wrong token (force=false) must return 409; got {status}, body: {}",
        String::from_utf8_lossy(&body)
    );
    let err = parse_error_field(&body);
    assert!(
        err.contains("lock_token mismatch"),
        "wrong-token release must surface the `lock_token mismatch` token; got: {err}"
    );
    assert!(
        err.contains("force=true"),
        "wrong-token release must point at the force=true escape hatch; got: {err}"
    );

    // (2b) Same wrong token + force=true → 200.
    let (status, _body) = release_lock(&daemon.socket, &session_id, &wrong, true).await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "release with wrong token + force=true must succeed; the lock subsystem's escape hatch"
    );
}

///
/// `integration_workspace_lock_acquire_rejected_when_not_running`.
///
/// Phase 3 state-gate: the acquire handler refuses with HTTP 400 when
/// the session is not in `Running` state. The error wording is
/// pinned by the workspace-lock API contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_workspace_lock_acquire_rejected_when_not_running() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir = tmp.path().join("state");
    std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");
    // Seed but DON'T transition to Running — leaves the row at
    // `Creating`. The acquire's state-gate must fire.
    let session_id = seed_creating_container_session(&base_dir);

    let daemon = Daemon::spawn_with_base_dir(tmp, base_dir, "10.241.0.0/24");

    let (status, body) = acquire_lock(&daemon.socket, &session_id, "push").await;
    assert_eq!(
        status,
        hyper::StatusCode::BAD_REQUEST,
        "acquire on a non-Running session must return 400; got {status}, body: {}",
        String::from_utf8_lossy(&body)
    );
    let err = parse_error_field(&body);
    // Verbatim wording from Phase 3's handler
    // (`acquire_workspace_lock_inner` in `sandboxd/src/main.rs`).
    assert!(
        err.contains("workspace operations require Running"),
        "rejection must carry the design-verbatim `workspace operations require Running` token; got: {err}"
    );
    assert!(
        err.contains("session is in state"),
        "rejection must lead with the design-verbatim `session is in state` prefix; got: {err}"
    );
}
