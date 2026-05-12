//! End-to-end coverage for the `SO_PEERCRED` → `OperatorIdentity` →
//! storage-boundary-filter pipeline (api-session-isolation spec § 7.5).
//!
//! Three contracts are pinned here, all driven through the real
//! `PeerCredListener` acceptor on a freshly-spawned daemon binary:
//!
//! 1. `integration_create_stamps_owner_from_peercred` — a single
//!    `POST /sessions` over the unix socket yields a persisted row
//!    whose `owner_username` matches the test runner's `whoami`. Pins
//!    the daemon's `unix(2) accept → peer_cred() → resolve_uid_to_name()
//!    → Extension<OperatorIdentity> → store.create_session_with_backend(
//!    .., &operator.name, ..)` chain — a refactor that drops any link
//!    in the chain fails this test before reaching the wire shape.
//!
//! 2. `integration_synthetic_foreign_owner_returns_404` — seed a row
//!    with `owner_username = "synthetic-other"` directly via
//!    `SessionStore` (the same internal API the daemon uses); spawn
//!    the daemon against the same DB; issue `GET /sessions/<id>` as
//!    the test runner; assert `404`. The synthetic-name approach
//!    bypasses the (impractical-on-a-single-uid host) "really run as
//!    bob" requirement while still exercising the full HTTP pipeline
//!    with a real peer-cred extension; the multi-uid path lives in
//!    the Lima E2E harness (spec § 7.5).
//!
//! 3. `integration_list_returns_only_callers_sessions` — same fixture
//!    shape: one synthetic-foreign row + one runner-owned row;
//!    `GET /sessions` returns exactly the runner-owned entry.
//!
//! # Why spawn the daemon binary, not an in-process router
//!
//! The unit tests in `sandbox-core::store::tests` and the in-process
//! router tests in `policy_http.rs` / `events_http_*.rs` synthesise an
//! `OperatorIdentity` via `Extension::layer(OperatorIdentity::new(...))`
//! — fast, hermetic, but they skip every byte of the `PeerCredListener`
//! path. A refactor that drops `Extension::insert` between accept and
//! handler dispatch would pass every existing test. These three tests
//! are the canary on that ridge.
//!
//! Both heavy lifts (POST /sessions for #1, GET /sessions for #2/#3)
//! travel through `hyper::client::conn::http1::handshake` against a
//! `tokio::net::UnixStream` — the same shape `sandbox-cli`'s
//! `send_request_with_timeout` uses (`sandbox-cli/src/main.rs:1114`).
//! No docker, no Lima boot, no route-helper invocation: test #1's
//! `POST /sessions` requests the Lima backend and is expected to fail
//! at network-create or VM-create time (depending on whether docker
//! is even present on the host); the row is persisted *before* either
//! call, so the `owner_username` stamp survives the failure. Tests
//! #2 and #3 never hit the create path — they seed rows pre-spawn and
//! read them back via HTTP.
//!
//! # users.conf fixture
//!
//! The daemon refuses to start without a `users.conf` whose
//! `allow_users` resolves to its own uid. The fixture writes one
//! that names the test-runner's resolved username (same shape
//! `integration_rootless_docker.rs` uses).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::TokioIo;
use rusqlite::Connection;
use sandbox_core::backend::BackendKind;
use sandbox_core::{SessionConfig, SessionStore};
use tempfile::TempDir;
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// Binary resolution
// ---------------------------------------------------------------------------

fn sandboxd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandboxd"))
}

// ---------------------------------------------------------------------------
// users.conf fixture
// ---------------------------------------------------------------------------

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

/// Materialise a `users.conf` whose single subnet's `allow_users`
/// resolves to the test process's own uid so the daemon starts up.
/// The subnet itself is irrelevant here — these tests never allocate
/// per-session networks all the way through (#1 may try once and
/// roll back, #2/#3 never hit the create path).
fn write_users_conf(dir: &Path, user: &str) -> PathBuf {
    let path = dir.join("users.conf");
    let body = format!(r#"{{"subnets":[{{"cidr":"10.219.0.0/24","allow_users":["{user}"]}}]}}"#);
    let mut f = std::fs::File::create(&path).expect("create users.conf");
    f.write_all(body.as_bytes()).expect("write users.conf");
    f.flush().expect("flush users.conf");
    path
}

// ---------------------------------------------------------------------------
// Daemon fixture
// ---------------------------------------------------------------------------

/// Live `sandboxd` child plus the tempdir holding its socket, base
/// dir, log files, and `users.conf`. Drops to SIGKILL + cleanup.
struct Daemon {
    socket: PathBuf,
    base_dir: PathBuf,
    proc: Option<Child>,
    tmp: TempDir,
}

impl Daemon {
    /// Spawn the daemon against the given pre-seeded base directory.
    /// `base_dir` must already contain whatever DB rows the test wants
    /// the daemon to see (tests #2 and #3 seed rows pre-spawn; #1
    /// passes a fresh dir).
    fn spawn_with_base_dir(tmp: TempDir, base_dir: PathBuf) -> Self {
        let user = current_username();
        let socket = tmp.path().join("sandboxd.sock");
        let users_conf = write_users_conf(tmp.path(), &user);
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
            // `info` is enough to debug a stuck startup without
            // flooding the log file with per-poll chatter.
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(stdout_fh))
            .stderr(Stdio::from(stderr_fh));
        let proc = cmd.spawn().expect("spawn sandboxd");
        let daemon = Self {
            socket,
            base_dir,
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

// ---------------------------------------------------------------------------
// HTTP-over-unix client
// ---------------------------------------------------------------------------

/// Issue a single HTTP/1.1 request against `socket_path` and return
/// `(status, body_bytes)`. Mirrors the shape `sandbox-cli`'s
/// `send_request_with_timeout` uses (`sandbox-cli/src/main.rs:1114`);
/// the connection driver is spawned and the request is bounded by an
/// overall timeout.
async fn http_request(
    socket_path: &Path,
    req: Request<String>,
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
            // Connection close after request completion is expected
            // for a single-shot request; ignore the resulting error.
            let _ = conn.await;
        });
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

async fn http_request_empty(
    socket_path: &Path,
    method: &str,
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
            .method(method)
            .uri(path)
            // Authority is meaningless for a unix-socket connection;
            // any value works as long as the request line parses.
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
// Test 1 — peer-cred ownership stamp on create
// ---------------------------------------------------------------------------

/// `POST /sessions` over the real unix socket stamps the persisted
/// row's `owner_username` with the SO_PEERCRED-resolved name. The
/// downstream Lima/Docker session-create steps may fail (depending on
/// host state), but the row is persisted *before* any of them — so
/// the stamp survives every failure mode.
#[tokio::test]
async fn integration_create_stamps_owner_from_peercred() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir = tmp.path().join("state");
    let daemon = Daemon::spawn_with_base_dir(tmp, base_dir.clone());

    // Request a Lima session so the (always-built-into-the-daemon)
    // capability matrix accepts the spec without requiring docker
    // probe responses. The persisted row's `owner_username` stamp
    // happens *before* `create_network` or `LimaManager::start_vm` —
    // see `create_session` handler in `sandboxd/src/main.rs`, where
    // `store.create_session_with_backend(.., &operator.name, ..)`
    // fires immediately after spec validation. So the test only needs
    // the request to *reach* the handler; whether it then succeeds
    // (on a fully-provisioned Lima/QEMU host) or fails fast (no docker)
    // or runs long (Lima present, VM boot in progress) is irrelevant
    // to the assertion.
    let body = r#"{"backend":"lima","cpus":1,"memory_mb":1024}"#.to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/sessions")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("content-length", body.len().to_string())
        .body(body)
        .expect("build POST /sessions");

    // Fire-and-forget the request in a background task. On hosts
    // with Lima installed, the handler blocks for minutes on VM
    // boot — we cannot wait for it. The row stamp happens in the
    // first ~100ms of the handler (well before the VM boot starts),
    // so we poll the DB for the stamped row and proceed as soon as
    // it appears. The Daemon's Drop kills the child so any in-flight
    // Lima boot is aborted along with it.
    let socket = daemon.socket.clone();
    let request_task = tokio::spawn(async move {
        // Long inner timeout: we do not depend on the response, but
        // a too-short value would race the row-write on slow CI.
        let _ = http_request(&socket, req, Duration::from_secs(120)).await;
    });

    // Poll for the row to appear. The `create_session_with_backend`
    // call happens within the first ~100ms of the handler; allow
    // generous slack for CI variance.
    let db_path = daemon.base_dir.join("sessions.db");
    let expected = current_username();
    let poll_deadline = Instant::now() + Duration::from_secs(30);
    let (owner, session_id) = loop {
        let conn = Connection::open(&db_path).expect("open sessions.db");
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT owner_username, id FROM sessions LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();
        drop(conn);
        if let Some((owner, id)) = row {
            break (Some(owner), Some(id));
        }
        if Instant::now() >= poll_deadline {
            request_task.abort();
            panic!(
                "no session row appeared in {} within 30s; check {}/sandboxd.stderr.log",
                db_path.display(),
                daemon.tmp.path().display(),
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    request_task.abort();

    // Best-effort docker cleanup BEFORE the assertion fires: the
    // daemon may have allocated a `sandbox-net-<id>` network between
    // the row stamp and the SIGKILL on Drop. Reap it now so a failed
    // assertion does not also leak a docker network. Idempotent on
    // hosts without docker (silent stderr).
    if let Some(id) = &session_id {
        let _ = Command::new("docker")
            .args(["network", "rm", &format!("sandbox-net-{id}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    assert_eq!(
        owner.as_deref(),
        Some(expected.as_str()),
        "POST /sessions must stamp the persisted row's owner_username with the \
         SO_PEERCRED-resolved username; expected {expected:?}, got {owner:?}.\n\
         If the value is empty or differs, the handler may have bypassed the \
         `Extension<OperatorIdentity>` extractor (regression on the \
         `PeerCredListener` → `operator_identity_layer` wiring). \
         Check {}/sandboxd.stderr.log.",
        daemon.tmp.path().display(),
    );
}

// ---------------------------------------------------------------------------
// Test 2 — synthetic foreign-owner row is invisible via GET
// ---------------------------------------------------------------------------

/// Seed a row whose `owner_username` is `"synthetic-other"` (i.e. not
/// the test runner) directly via `SessionStore`; spawn the daemon
/// against the same DB; issue `GET /sessions/<id>` as the runner; the
/// daemon must return `404`.
///
/// The spec text names `GET /sessions/<id>` as the focal endpoint;
/// the same filter wraps every per-id endpoint (H3, H5..H12), so the
/// per-endpoint matrix is the unit-tested concern and this test pins
/// the wiring at the storage boundary through one real HTTP path.
#[tokio::test]
async fn integration_synthetic_foreign_owner_returns_404() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir = tmp.path().join("state");
    std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");

    // Seed the foreign-owner row pre-spawn. Drop the store before
    // spawning the daemon so the SQLite handle is closed (the daemon
    // opens its own).
    let foreign_id_str;
    {
        let (store, _orphans) = SessionStore::new(base_dir.clone()).expect("open store for seed");
        let store = Arc::new(store);
        let session = store
            .create_session_with_backend(
                SessionConfig::default(),
                Some("seeded-foreign".into()),
                BackendKind::Lima,
                "synthetic-other",
                0,
                "",
            )
            .expect("seed foreign-owner row");
        foreign_id_str = session.id.as_str().to_string();
    }

    let daemon = Daemon::spawn_with_base_dir(tmp, base_dir);

    let uri = format!("/sessions/{foreign_id_str}");
    let (status, _body) =
        http_request_empty(&daemon.socket, "GET", &uri, Duration::from_secs(15)).await;
    assert_eq!(
        status,
        hyper::StatusCode::NOT_FOUND,
        "foreign-owner row must be invisible to the runner via the storage-boundary \
         filter; expected 404 NOT FOUND, got {status}",
    );
}

// ---------------------------------------------------------------------------
// Test 3 — list returns only the caller's sessions
// ---------------------------------------------------------------------------

/// Seed two rows — one foreign-owner, one runner-owned — and assert
/// `GET /sessions` returns exactly one entry (the runner-owned one).
#[tokio::test]
async fn integration_list_returns_only_callers_sessions() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir = tmp.path().join("state");
    std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");

    let runner = current_username();
    let runner_id_str;
    let foreign_id_str;
    {
        let (store, _orphans) = SessionStore::new(base_dir.clone()).expect("open store for seed");
        let store = Arc::new(store);
        let foreign = store
            .create_session_with_backend(
                SessionConfig::default(),
                Some("seeded-foreign".into()),
                BackendKind::Lima,
                "synthetic-other",
                0,
                "",
            )
            .expect("seed foreign-owner row");
        foreign_id_str = foreign.id.as_str().to_string();
        let owned = store
            .create_session_with_backend(
                SessionConfig::default(),
                Some("seeded-runner".into()),
                BackendKind::Lima,
                &runner,
                0,
                "",
            )
            .expect("seed runner-owner row");
        runner_id_str = owned.id.as_str().to_string();
    }

    let daemon = Daemon::spawn_with_base_dir(tmp, base_dir);

    let (status, body) =
        http_request_empty(&daemon.socket, "GET", "/sessions", Duration::from_secs(15)).await;
    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "GET /sessions must succeed for the runner; got {status}, body: {}",
        String::from_utf8_lossy(&body),
    );
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("parse /sessions body");
    let arr = parsed.as_array().expect("/sessions returns a JSON array");
    let ids: Vec<&str> = arr
        .iter()
        .filter_map(|v| v.get("id").and_then(serde_json::Value::as_str))
        .collect();
    assert!(
        ids.contains(&runner_id_str.as_str()),
        "GET /sessions must surface the runner-owned row {runner_id_str}; got ids={ids:?}",
    );
    assert!(
        !ids.contains(&foreign_id_str.as_str()),
        "GET /sessions must NOT surface the synthetic-other-owned row {foreign_id_str}; \
         got ids={ids:?}",
    );
    assert_eq!(
        ids.len(),
        1,
        "GET /sessions must return exactly the runner-owned row; got {} entries: {ids:?}",
        ids.len(),
    );
}
