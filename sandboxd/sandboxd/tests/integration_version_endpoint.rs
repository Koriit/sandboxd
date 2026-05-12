//! End-to-end coverage for the `GET /version` daemon endpoint
//! (spec § 7.2, § 11.6 — `integration_version_endpoint_real_socket`).
//!
//! Spins up the daemon binary against a freshly-provisioned tempdir,
//! issues `GET /version` over its real unix socket (no in-process
//! router shortcut), and asserts:
//!
//! 1. status is `200 OK`,
//! 2. `Content-Type: application/json`,
//! 3. body parses as `{"version": "<env!(CARGO_PKG_VERSION)>"}`,
//!    with the daemon's `CARGO_PKG_VERSION` matching the workspace's
//!    own value (the workspace ships sandboxd and sandbox-cli with the
//!    same version field, so the test process's
//!    `env!("CARGO_PKG_VERSION")` is the right reference).
//!
//! The wire shape is the contract the CLI's `send_request_with_timeout`
//! handshake depends on. This integration test pins the bytes the
//! daemon actually emits over the socket — the unit tests in
//! `src/main.rs::tests` pin the handler's `IntoResponse` output, but
//! they cannot catch a route-declaration regression (e.g. someone
//! drops the `.route("/version", get(version_handler))` line). This
//! test does.
//!
//! # users.conf fixture
//!
//! The daemon refuses to start without a `users.conf` whose
//! `allow_users` resolves to its own uid; the fixture writes one
//! naming the test-runner's resolved username (same shape
//! `integration_owner_peercred.rs` uses).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::TokioIo;
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

/// Resolve the current process's username via `getpwuid_r` — same
/// route the daemon's startup-validation walks. Matching helps the
/// test fixture and the daemon agree on which user counts.
fn current_username() -> String {
    let uid = nix::unistd::Uid::current();
    nix::unistd::User::from_uid(uid)
        .expect("getpwuid_r succeeded")
        .expect("uid maps to a passwd entry")
        .name
}

/// Materialise a `users.conf` whose single subnet's `allow_users`
/// resolves to the test process's own uid so the daemon starts up.
/// The subnet itself is irrelevant — this test never creates sessions.
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

struct Daemon {
    socket: PathBuf,
    proc: Option<Child>,
    tmp: TempDir,
}

impl Daemon {
    fn spawn(tmp: TempDir) -> Self {
        let user = current_username();
        let socket = tmp.path().join("sandboxd.sock");
        let base_dir = tmp.path().join("state");
        std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");
        let users_conf = write_users_conf(tmp.path(), &user);

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

// ---------------------------------------------------------------------------
// HTTP-over-unix client (single-shot GET)
// ---------------------------------------------------------------------------

/// Issue `GET <path>` over the unix socket at `socket_path` and return
/// `(status, content_type, body_bytes)`. Mirrors the shape the CLI's
/// `send_request_with_timeout` uses; the connection driver is spawned
/// and the request is bounded by an overall timeout.
async fn http_get(
    socket_path: &Path,
    path: &str,
    timeout: Duration,
) -> (hyper::StatusCode, Option<String>, Vec<u8>) {
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
            .method("GET")
            .uri(path)
            .header("host", "localhost")
            .body(Empty::<hyper::body::Bytes>::new())
            .expect("build request");
        let resp = sender.send_request(req).await.expect("send_request");
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        (status, content_type, body.to_vec())
    })
    .await
    .unwrap_or_else(|_| panic!("HTTP request timed out after {timeout:?}"))
}

// ---------------------------------------------------------------------------
// Test — `GET /version` over the real socket
// ---------------------------------------------------------------------------

/// `GET /version` over the unix socket returns
/// `200 OK + application/json + {"version": "<CARGO_PKG_VERSION>"}`.
///
/// Pins the route declaration (`.route("/version", get(version_handler))`)
/// and the auth policy (none required — the CLI fetches this on every
/// connection before any other request, including before any operator
/// identity is consulted). A regression that hides the route behind
/// authentication would break the entire CLI fleet's strict-equality
/// handshake; this test fails the moment that happens.
#[tokio::test]
async fn integration_version_endpoint_real_socket() {
    let tmp = TempDir::new().expect("tempdir");
    let daemon = Daemon::spawn(tmp);

    let (status, content_type, body) =
        http_get(&daemon.socket, "/version", Duration::from_secs(10)).await;

    assert_eq!(
        status,
        hyper::StatusCode::OK,
        "spec § 7.2: `GET /version` is always 200 OK; \
         got {status:?}, body = {:?}",
        String::from_utf8_lossy(&body)
    );

    let ct = content_type.expect("daemon must emit Content-Type for /version");
    assert!(
        ct.starts_with("application/json"),
        "spec § 7.2: /version body is JSON; got Content-Type = {ct:?}"
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&body).expect("response body must be valid JSON");
    assert_eq!(
        parsed,
        serde_json::json!({ "version": env!("CARGO_PKG_VERSION") }),
        "spec § 7.2 pins the body to exactly \
         `{{\"version\": \"<CARGO_PKG_VERSION>\"}}`; got {parsed}"
    );
}
