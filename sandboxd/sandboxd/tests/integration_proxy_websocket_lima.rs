//! Integration coverage for the Lima branch of
//! `GET /sessions/{id}/proxy` — the daemon's `pump_lima` byte mover.
//!
//! The cross-user CLI access spec § Phase 2 step 4 calls for
//! `integration_*` round-trip coverage of the proxy endpoint per
//! backend. The container half is covered by
//! [`integration_proxy_websocket_round_trip_container_backend`]; this
//! file is the Lima half. It exercises every Lima-shaped step the
//! handler takes — `limactl list --json` parsing, `sshLocalPort`
//! discovery, `TcpStream` dial to the host-side forward port,
//! bidirectional byte ferry between the WebSocket and the TCP
//! stream — without requiring a Lima VM or QEMU on the test host.
//!
//! ## Faking Lima
//!
//! After the helper pivot, `sandbox-lima-helper list-json --op-uid N`
//! is what resolves `sshLocalPort` — not a direct `limactl` call.  The
//! helper resolves `limactl` via the `SANDBOX_LIMA_HELPER_TEST_LIMACTL_PATH`
//! env-var override (compiled in under the `test-env-override` feature) when
//! that var is set.
//!
//! The test stages a fake shell-script under the per-test `TempDir`, then
//! passes its path to `Daemon::spawn` which forwards it to the helper via
//! `SANDBOX_LIMA_HELPER_TEST_LIMACTL_PATH`. The operator's real
//! `~/.local/bin/limactl` (if any) is never touched. Additionally, the
//! daemon is configured with the test-cap'd helper (`SANDBOX_LIMA_HELPER_PATH`)
//! and the `test-env-override` seams (`SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER`,
//! `SANDBOX_LIMA_HELPER_TEST_SANDBOX_GROUP`) so the helper accepts the
//! test runner uid as the "sandbox" caller, and the session row carries
//! `operator_uid = test_runner_uid`.
//!
//! Bytes flow:
//!
//! ```text
//! WebSocket client (tokio-tungstenite)
//!   → daemon's /sessions/{id}/proxy handler
//!   → pump_lima: spawn_blocking → ssh_local_port_for_session
//!   → sandbox-lima-helper list-json --op-uid N
//!   → helper execs <tempdir>/limactl list --json (fake script, via env-var override)
//!   → pump_lima: TcpStream::connect("127.0.0.1", <port>)
//!   → test's TcpListener
//!   → fake sshd substitute (writes the SSH-2.0- banner)
//! ```
//!
//! The fake-sshd substitute is a single-shot accept that writes
//! `SSH-2.0-sandbox-stub\r\n` and waits for the connection to close
//! — same shape the container test uses, just over a plain TCP
//! socket instead of `docker exec socat`. Observing the banner on
//! the WebSocket client side proves every Lima-shaped invariant the
//! handler owns.
//!
//! ## Why this test should ship even on hosts where Lima is broken
//!
//! Spec § Phase-1 diff-the-outcomes documents that issue #217
//! (daemon-spawned QEMU exit-1) prevents real Lima VMs from
//! starting on the current dev host. This test does not need a
//! real Lima VM — it shorts out the limactl binary itself — so it
//! runs cleanly even where #217 still blocks the e2e suite. In CI
//! environments where Lima does work, the test catches the same
//! daemon-side regressions, just without exercising real QEMU.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use hyper::Request;
use sandbox_core::backend::BackendKind;
use sandbox_core::{SessionConfig, SessionStore};
use tempfile::TempDir;

use axum::http::HeaderName;
use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::Message as ClientMessage;

// ---------------------------------------------------------------------------
// Binary resolution & users.conf fixture (mirrors
// integration_owner_peercred.rs / integration_ssh_config_endpoint.rs).
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

fn write_users_conf(dir: &Path, user: &str) -> PathBuf {
    let path = dir.join("users.conf");
    let body = format!(
        r#"{{"_schema_version":1,"subnets":[{{"cidr":"10.221.0.0/24","allow_users":["{user}"]}}]}}"#
    );
    let mut f = std::fs::File::create(&path).expect("create users.conf");
    f.write_all(body.as_bytes()).expect("write users.conf");
    f.flush().expect("flush users.conf");
    path
}

/// Stage a fake `limactl` shell script under `dir` and return its path.
///
/// The script responds to `list --json` (the form `sandbox-lima-helper`
/// passes after `execvpe`) with a single sandbox VM entry whose
/// `sshLocalPort` is `port`.  All other verbs exit zero with empty output.
///
/// The caller passes the returned path to `Daemon::spawn` which sets
/// `SANDBOX_LIMA_HELPER_TEST_LIMACTL_PATH` in the daemon's env so the
/// helper resolves the override instead of probing the operator's real
/// `~/.local/bin/limactl`.  Cleanup is handled by the caller's `TempDir`.
fn stage_fake_limactl(dir: &Path, vm_name: &str, port: u16) -> PathBuf {
    let script_path = dir.join("limactl");

    // The helper passes `list --json --tty=false` to limactl (from
    // build_limactl_argv / Subcommand::ListJson).  Accept that exact
    // form and also the bare `list --json` variant for robustness.
    let body = format!(
        r#"#!/bin/sh
case "$1" in
  list)
    printf '%s\n' '{{"name":"{vm_name}","status":"Running","sshLocalPort":{port}}}'
    ;;
  *)
    ;;
esac
exit 0
"#,
    );
    let mut f = std::fs::File::create(&script_path).expect("create fake limactl");
    f.write_all(body.as_bytes()).expect("write fake limactl");
    f.flush().expect("flush fake limactl");
    let mut perm = std::fs::metadata(&script_path)
        .expect("stat fake limactl")
        .permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&script_path, perm).expect("chmod fake limactl");

    script_path
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
    /// Spawn the daemon configured to use the test-cap'd `sandbox-lima-helper`
    /// with the `test-env-override` feature seams set to accept the test user
    /// as the "sandbox" user.  This lets `sandbox-lima-helper list-json`
    /// succeed under the test runner uid so the Lima proxy path works.
    ///
    /// `fake_limactl` must be the path to an executable shell script that the
    /// helper should use in place of the operator's real `limactl`.  It is
    /// forwarded to the helper via `SANDBOX_LIMA_HELPER_TEST_LIMACTL_PATH`
    /// so the helper's env-var override fires instead of probing the three
    /// hardcoded candidate paths.
    fn spawn(tmp: TempDir, base_dir: PathBuf, fake_limactl: &Path) -> Self {
        let user = current_username();
        let socket = tmp.path().join("sandboxd.sock");
        let users_conf = write_users_conf(tmp.path(), &user);
        std::fs::create_dir_all(&base_dir).expect("mkdir base_dir");

        // Resolve the test user's primary group name so the helper's
        // op-uid sandbox-group check passes.
        let gid = nix::unistd::Gid::current();
        let group_name = nix::unistd::Group::from_gid(gid)
            .expect("getgrgid succeeded")
            .expect("gid maps to a group entry")
            .name;

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
            // Point the daemon at the test-cap'd helper (built with
            // test-env-override so it honours the next three env vars).
            .env(
                "SANDBOX_LIMA_HELPER_PATH",
                "/usr/local/libexec/sandboxd-test/sandbox-lima-helper",
            )
            // Override the sandbox-user/group name to the test user so
            // the helper's identity check (step 1) and the op-uid
            // group-membership check (step 3) both pass.
            .env("SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER", &user)
            .env("SANDBOX_LIMA_HELPER_TEST_SANDBOX_GROUP", &group_name)
            // Direct the helper at the per-test fake limactl script so
            // it never touches the operator's real ~/.local/bin/limactl.
            .env("SANDBOX_LIMA_HELPER_TEST_LIMACTL_PATH", fake_limactl)
            // Redirect the per-operator LIMA_HOME state root into the test
            // tempdir so the daemon provisions `<root>/<uid>/lima` somewhere
            // the test runner can write, instead of the production
            // `/var/lib/sandboxd` (which needs root/dev-env setup to exist).
            .env("SANDBOX_LIMA_HELPER_TEST_STATE_ROOT", tmp.path())
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
// Fake sshd stub — single-shot TCP banner writer
// ---------------------------------------------------------------------------

/// Start a TCP listener on 127.0.0.1 and return its bound port. The
/// background task accepts a single connection, writes the SSH-2.0
/// banner, then waits for the peer to close. Drops on returned
/// handle when test ends.
async fn spawn_fake_sshd() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake sshd listener");
    let port = listener.local_addr().expect("local_addr").port();
    let handle = tokio::spawn(async move {
        if let Ok((mut conn, _)) = listener.accept().await {
            use tokio::io::AsyncWriteExt;
            let _ = conn.write_all(b"SSH-2.0-sandbox-stub\r\n").await;
            // Hold the connection open until the peer closes. The
            // daemon's `pump_lima` will close once the WebSocket
            // side terminates; this `read_to_end` returns then.
            use tokio::io::AsyncReadExt;
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf).await;
        }
    });
    (port, handle)
}

// ---------------------------------------------------------------------------
// WebSocket client over unix-socket transport
// ---------------------------------------------------------------------------

/// Perform a hand-rolled HTTP/1.1 → WebSocket upgrade against the
/// daemon's unix socket, then return the established `WebSocketStream`
/// ready for binary-frame reads.
///
/// We use the same handshake shape the CLI's `sandbox-cli::proxy`
/// module uses — hyper over a `UnixStream`, then handing the
/// upgraded socket to `tokio-tungstenite::WebSocketStream::from_raw_socket`.
async fn open_ws_via_unix_socket(
    socket_path: &Path,
    request_path: &str,
) -> tokio_tungstenite::WebSocketStream<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>> {
    use http_body_util::BodyExt;
    use hyper::body::Body;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;
    use tokio_tungstenite::tungstenite::handshake::client::generate_key;

    let stream = UnixStream::connect(socket_path)
        .await
        .unwrap_or_else(|e| panic!("connect daemon socket: {e}"));
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, String>(io)
        .await
        .expect("hyper handshake");
    let conn_with_upgrades = conn.with_upgrades();
    let conn_task = tokio::spawn(async move {
        let _ = conn_with_upgrades.await;
    });

    let ws_key = generate_key();
    let req = Request::builder()
        .method("GET")
        .uri(request_path)
        .header(HeaderName::from_static("host"), "localhost")
        .header(HeaderName::from_static("connection"), "upgrade")
        .header(HeaderName::from_static("upgrade"), "websocket")
        .header(HeaderName::from_static("sec-websocket-version"), "13")
        .header(HeaderName::from_static("sec-websocket-key"), ws_key)
        .body(String::new())
        .expect("build upgrade request");
    let resp = sender
        .send_request(req)
        .await
        .expect("send upgrade request");

    let status = resp.status();
    if status != hyper::StatusCode::SWITCHING_PROTOCOLS {
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        panic!(
            "daemon did not switch protocols; status={status} body={:?}",
            String::from_utf8_lossy(&body)
        );
    }
    let _ = resp.body().size_hint(); // suppress unused-import warning on debug-only builds
    let upgraded = hyper::upgrade::on(resp).await.expect("hyper upgrade");
    drop(conn_task);
    let upgraded_io = TokioIo::new(upgraded);
    tokio_tungstenite::WebSocketStream::from_raw_socket(
        upgraded_io,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await
}

/// Search for `needle` in `haystack`; return true if `haystack`
/// contains the byte sequence.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// The Lima proxy round-trip test
// ---------------------------------------------------------------------------

/// Stand up a fake sshd substitute on `127.0.0.1:<port>`, point a
/// fake `limactl list --json` at that port, spawn the daemon, open
/// a WebSocket to `GET /sessions/<id>/proxy`, and read the
/// SSH-2.0 banner back. Pins every Lima-shaped invariant in
/// `proxy_http::pump_lima`:
///
/// - `LimaManager::ssh_local_port_for_session` parses the JSON entry
///   the fake script emits.
/// - `TcpStream::connect("127.0.0.1", port)` succeeds against the
///   fake sshd listener.
/// - `bidirectional_ferry` carries bytes from the TCP read half to
///   the WebSocket binary-frame sink.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_proxy_websocket_round_trip_lima_backend() {
    let tmp = TempDir::new().expect("tempdir");
    let base_dir = tmp.path().join("state");

    // Step 1: stand up the fake sshd substitute.
    let (port, _sshd_task) = spawn_fake_sshd().await;

    // Step 2: seed a Lima-backed session row pre-spawn so the daemon
    // picks it up at open. We set operator_uid to the test runner's uid
    // so the Lima proxy path can resolve it through the helper.
    let owner = current_username();
    let op_uid = nix::unistd::Uid::current().as_raw();
    let op_gid = nix::unistd::Gid::current().as_raw();
    let session_id_str = {
        let (store, _orphans) = SessionStore::new(base_dir.clone()).expect("open store pre-spawn");
        let session = store
            .create_session_with_backend(
                SessionConfig::default(),
                Some("proxy-lima".to_string()),
                BackendKind::Lima,
                &owner,
                0,
                "",
                Some(op_uid),
                Some(op_gid),
            )
            .expect("create lima session row");
        session.id.to_string()
    };

    // Step 3: stage the fake `limactl` under the per-test tempdir.  The
    // path is passed to `Daemon::spawn` which forwards it to the helper
    // via `SANDBOX_LIMA_HELPER_TEST_LIMACTL_PATH`.  The operator's real
    // `~/.local/bin/limactl` (if any) is never touched.
    let vm_name = format!("sandbox-{session_id_str}");
    let fake_limactl_path = stage_fake_limactl(tmp.path(), &vm_name, port);

    // Step 4: spawn the daemon with the test-cap'd lima helper configured
    // to accept the test user as the "sandbox" user, pointing it at the
    // isolated per-test fake limactl.
    let daemon = Daemon::spawn(tmp, base_dir, &fake_limactl_path);
    let socket = daemon.socket.clone();

    // Step 5: open the WebSocket and read until we see the SSH banner.
    // Bounded by a generous deadline so a stuck daemon fails loudly.
    let request_path = format!("/sessions/{session_id_str}/proxy");
    let banner_deadline = Duration::from_secs(15);

    let banner = tokio::time::timeout(banner_deadline, async {
        let mut ws = open_ws_via_unix_socket(&socket, &request_path).await;
        let mut acc: Vec<u8> = Vec::new();
        while let Some(msg) = ws.next().await {
            match msg.expect("ws recv") {
                ClientMessage::Binary(bytes) => {
                    acc.extend_from_slice(&bytes);
                    if contains_subsequence(&acc, b"SSH-2.0-") && acc.contains(&b'\n') {
                        return acc;
                    }
                }
                ClientMessage::Close(_) => return acc,
                _ => {}
            }
        }
        acc
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "did not receive SSH-2.0- banner within {banner_deadline:?}. \
             daemon stderr: {}",
            std::fs::read_to_string(daemon.tmp.path().join("sandboxd.stderr.log"))
                .unwrap_or_default(),
        );
    });

    let banner_str = String::from_utf8_lossy(&banner);
    assert!(
        banner_str.contains("SSH-2.0-"),
        "expected SSH-2.0- banner in proxy output; got: {banner_str:?}\n\
         === daemon stdout ===\n{}\n=== daemon stderr ===\n{}",
        std::fs::read_to_string(daemon.tmp.path().join("sandboxd.stdout.log")).unwrap_or_default(),
        std::fs::read_to_string(daemon.tmp.path().join("sandboxd.stderr.log")).unwrap_or_default(),
    );
}
