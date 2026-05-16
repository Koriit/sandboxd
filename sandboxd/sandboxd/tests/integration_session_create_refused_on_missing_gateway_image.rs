//! HTTP-level coverage for the missing-gateway-image refusal on
//! `POST /sessions`.
//!
//! Spec 3 § 11.6 lists `integration_session_create_refused_on_missing_gateway_image`
//! as the wire-shape complement to the primitive-level
//! `integration_session_create_image_contracts.rs` test in
//! `sandbox-core/tests/`. The primitive test pins the daemon-side
//! helpers (`gateway_image_present` returns `Ok(false)` for the
//! absent tag; `missing_gateway_image_hint` renders the correct
//! substrings); this file drives the same contract through the real
//! daemon binary and a real `POST /sessions` request, so the wire
//! shape on the refusal path is pinned end-to-end.
//!
//! ## Why both
//!
//! The primitive layer is fast (~ms) and runs without spawning the
//! daemon, but it does not exercise the pre-flight gate in
//! `create_session` (`sandboxd/src/main.rs:1262-1294`). A regression
//! that moved the gate after `create_network` or that dropped the
//! `error_response` mapping would pass the primitive test but break
//! the wire shape. This file fires a real HTTP request through the
//! real `PeerCredListener` to catch that.
//!
//! ## Fault injection
//!
//! The daemon ships with a `test-env-override` Cargo feature that
//! makes `gateway_image_tag_for_daemon` consult
//! `SANDBOX_GATEWAY_TAG_OVERRIDE` (`sandbox-core/src/gateway.rs:163`).
//! We spawn the daemon with that env var pointing at a unique
//! `nanos`-suffixed tag we never `docker tag` into existence — the
//! probe sees "no such image" deterministically, regardless of what
//! gateway images the host happens to have built. Same isolation
//! pattern as `integration_doctor_hard_fails_on_missing_gateway_image`.
//!
//! ## Profile selection
//!
//! Each test name is prefixed `integration_` so the `integration`
//! nextest profile picks it up via its `test(/^integration_/)` filter,
//! and the default profile filters it out.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tempfile::TempDir;
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// Binary resolution — sibling to the daemon test crate's binary.
// ---------------------------------------------------------------------------

fn sandboxd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandboxd"))
}

// ---------------------------------------------------------------------------
// users.conf fixture — mirrors `integration_doctor_diagnostics.rs`.
// ---------------------------------------------------------------------------

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
// Daemon fixture.
// ---------------------------------------------------------------------------

struct Daemon {
    socket: PathBuf,
    proc: Option<Child>,
    tmp: TempDir,
}

impl Daemon {
    /// Spawn the daemon binary against a tempdir with the supplied
    /// env-var overlay so the gateway-tag override can be threaded
    /// in. Returns once the socket is observable on disk. The fixture
    /// uses a unique `/24` per test to avoid IP-pool collisions when
    /// nextest runs multiple integration tests on the same host.
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

// ---------------------------------------------------------------------------
// HTTP-over-unix POST helper.
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

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// Spec 3 § 11.6 — `integration_session_create_refused_on_missing_gateway_image`.
///
/// Spawn the daemon with `SANDBOX_GATEWAY_TAG_OVERRIDE` set to a
/// guaranteed-absent tag (timestamp-suffixed so this run never depends
/// on host docker inventory). Fire `POST /sessions`. Assert:
///
/// 1. The response status maps to `SandboxError::Gateway` —
///    `500 INTERNAL_SERVER_ERROR` per the `error_response` table
///    (`sandboxd/sandboxd/src/main.rs:7929-7933`). The status is the
///    same shape regardless of whether the daemon backs the request
///    with the container or Lima backend; the pre-flight gate fires
///    before the backend dispatch.
///
/// 2. The response body is the `{"error": "<hint>"}` JSON shape, where
///    `<hint>` is `missing_gateway_image_hint(tag)`:
///       - contains the missing tag verbatim,
///       - contains the substring `sandbox update`,
///       - contains the leading `gateway image missing` phrase.
///    Pins the same operator-visible contract the primitive-level
///    `integration_session_create_refused_on_missing_gateway_image`
///    test in `sandbox-core/tests/integration_session_create_image_contracts.rs`
///    checks against the helper directly. The primitive test cannot
///    catch a regression that drops the wire mapping; this test can.
///
/// 3. No session row was persisted. The pre-flight gate exits the
///    handler before `store.create_session_with_backend` runs, so the
///    DB must remain empty after the refused request.
///
/// Belt-and-suspenders against three failure modes a refactor could
/// silently introduce: (a) gate moved past `create_network` (e.g.
/// during a future allocation-order rewrite), (b) error mapping
/// dropped from `error_response`, (c) session row persisted before the
/// gate fires.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_session_create_refused_on_missing_gateway_image() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // No `docker tag` step — the tag is only ever probed via
    // `docker image inspect`, which returns `no such image` for any
    // tag that was never built. Leak-proof by construction; same
    // isolation pattern as `integration_doctor_hard_fails_on_missing_gateway_image`.
    let absent_tag = format!("sandbox-gateway:create-itest-absent-{nanos}");

    let daemon = Daemon::spawn_with_env(
        // Distinct /24 from the doctor-diagnostics tests so a parallel
        // run cannot collide on users.conf pool registration.
        "10.234.0.0/24",
        &[("SANDBOX_GATEWAY_TAG_OVERRIDE", &absent_tag)],
    );

    // POST a minimal valid session-create body. Backend choice does
    // not matter for this test — both Lima and Container reach the
    // same pre-flight gate before any backend code runs.
    let body = r#"{"backend":"container","cpus":1.0,"memory_mb":256}"#.to_string();
    let (status, body_bytes) = http_post_json(
        &daemon.socket,
        "/sessions",
        body,
        Duration::from_secs(15),
    )
    .await;

    // Spec § 11.6: refusal status maps via `error_response` to 500.
    assert_eq!(
        status,
        hyper::StatusCode::INTERNAL_SERVER_ERROR,
        "missing-gateway-image refusal must surface as 500 \
         (the `SandboxError::Gateway` mapping); got {status}. \
         body={}",
        String::from_utf8_lossy(&body_bytes)
    );

    // Body must be the documented `{"error": "<hint>"}` shape with all
    // three substrings the operator-facing hint carries.
    let parsed: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("refusal body must be valid JSON");
    let error_msg = parsed
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            panic!(
                "refusal body must have a top-level `error` string; got: {parsed}"
            )
        });

    assert!(
        error_msg.contains(&absent_tag),
        "refusal body's error must name the missing tag verbatim ({absent_tag}); got: {error_msg}"
    );
    assert!(
        error_msg.contains("sandbox update"),
        "refusal body's error must point the operator at `sandbox update`; got: {error_msg}"
    );
    assert!(
        error_msg.contains("gateway image missing"),
        "refusal body's error must lead with `gateway image missing` so an operator \
         can grep journald correlations; got: {error_msg}"
    );

    // No session row persisted. The pre-flight gate exits the handler
    // before `store.create_session_with_backend` runs; the DB lives
    // under `<base_dir>/sessions.db` and must be either absent (gate
    // exits before the store is even opened on this request) or
    // contain zero rows.
    let db_path = daemon.tmp.path().join("state").join("sessions.db");
    if db_path.exists() {
        let conn = rusqlite::Connection::open(&db_path).expect("open sessions.db");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
            .unwrap_or(0);
        assert_eq!(
            count, 0,
            "refused session-create must not persist a row; sessions.db has {count} row(s)"
        );
    }
}
