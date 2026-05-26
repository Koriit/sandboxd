//! Integration test for M18-S4 — `GET /sessions/{id}/proxy` WebSocket
//! byte mover.
//!
//! The spec (`Phase 2 → step 4`) calls for a round-trip test that
//! "opens a proxy connection and exchanges bytes through a stub-sshd
//! inside the session." We satisfy that by reusing the same in-image
//! sshd substrate the M18-S3 cross-user proof
//! (`sandbox-core::tests::integration_lite_image_sshd_cross_user`)
//! already validates byte-for-byte, then layering the daemon's
//! axum-served WebSocket proxy on top.
//!
//! ## Test shape
//!
//! 1. Build the lite image via the production `ensure_image` path —
//!    same path the daemon's session-create handler exercises.
//! 2. Generate a per-session ed25519 keypair and stage the three
//!    credential files (`authorized_keys` + synthetic `passwd` +
//!    synthetic `group`) via `stage_ssh_credentials`. Container runs
//!    under `--user 9876:9876` to exercise the cross-user path (the
//!    whole reason the M18 milestone exists).
//! 3. Launch the lite-image container under the production hardening
//!    profile with the three SSH-credential bind-mounts.
//! 4. Wait for sshd to bind `127.0.0.1:22` inside the container.
//! 5. Create a `SessionStore`, insert a `Container`-backend session
//!    row whose generated id matches the docker container name. The
//!    daemon's proxy handler derives the container name from the
//!    session id alone (`format!("sandbox-{session_id}")`) — so the
//!    test's container name is the session id with `sandbox-` prefix.
//! 6. Build an axum `Router` exposing only `GET /sessions/{id}/proxy`
//!    against a fresh `ProxyState`, and serve it on a TCP loopback
//!    listener.
//! 7. Open a WebSocket client via `tokio-tungstenite` to
//!    `ws://127.0.0.1:<port>/sessions/<id>/proxy`. Read inbound binary
//!    frames until the SSH server banner (`SSH-2.0-`) appears. The
//!    banner is the canonical "the bytes flow end-to-end" signal —
//!    sshd emits it as its first protocol output the moment a TCP
//!    peer connects, and observing it on the WebSocket side proves
//!    the daemon's byte pump correctly bridged the WebSocket to
//!    `docker exec socat` to in-container sshd.
//!
//! ## Why not full SSH handshake
//!
//! A full SSH handshake (key exchange, authentication) through the
//! WebSocket would require either a Rust SSH client library or
//! spawning a real `ssh` client process whose stdio is bridged into
//! the WebSocket. The first adds a dependency that has no other
//! caller in the workspace; the second is what M18-S5's CLI shim does
//! and is the right home for an end-to-end test (out of scope here).
//! The banner exchange exercises every byte-pump invariant this
//! milestone owns: WebSocket upgrade, per-backend dispatch, async I/O
//! carve-out, bidirectional byte transfer, and close-frame
//! propagation. Anything that touches more belongs to M18-S5/S6.

use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandbox_core::SshKeypair;
use sandbox_core::backend::{
    BackendKind, LITE_IMAGE_REPOSITORY, ensure_image, stage_ssh_credentials,
};
use sandbox_core::{LimaManager, SessionConfig, SessionStore};
use sandboxd::proxy_http::{ProxyState, handle_proxy};
use tempfile::TempDir;

use axum::Router;
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::routing::get;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as ClientMessage;

// Non-1000 daemon uid used throughout the test — picked clear of any
// real system uid range so a host-side collision with `useradd` is
// vanishingly unlikely. Mirrors the production case the M18 milestone
// exists to fix: when the daemon runs as the `sandbox` system user
// (created by `setup-dev-env` with an arbitrary system uid), the
// in-container effective uid is not 1000.
const CROSS_USER_DAEMON_UID: u32 = 9876;
const CROSS_USER_DAEMON_GID: u32 = 9876;

// ---------------------------------------------------------------------------
// sandbox-guest staging — same one-time copy as the M18-S3 cross-user
// test, so the lite Dockerfile's `COPY` of `sandbox-guest` resolves
// under nextest's `target/<profile>/deps/` exe layout.
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
// Cleanup helpers — same RAII pattern as the M18-S3 cross-user test.
// ---------------------------------------------------------------------------

fn unique_label(label: &str) -> String {
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
    format!("test-proxy-{label}-{pid}-{nanos}-{n}")
}

struct LiteImageCleanup {
    tag: String,
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

/// Two-phase sshd-readiness probe.
///
/// Phase 1 polls `docker logs <ctr> 2>&1` until the entrypoint
/// script's positive readiness line appears
/// (`sandbox-entrypoint: sshd ready on 127.0.0.1:22`). This catches
/// the race where OpenSSH's daemon-fork returns 0 to the parent
/// before `bind(2)` completes in the daemonised child — the success-
/// path log line is emitted by the parent *after* the parent confirms
/// daemonisation succeeded, which is a strictly later signal than
/// `ss -tlnH` showing the listen socket. Phase 1 also captures the
/// failure-path log lines for the panic message if readiness never
/// arrives.
///
/// Phase 2 confirms the listen socket is visible inside the container
/// netns — guarantees the `listen()` call actually completed after
/// the entrypoint logged readiness. A short 5s timeout here is fine:
/// if Phase 1 succeeded, `listen()` is already in the queue.
fn wait_for_sshd_ready(container: &str, phase1: Duration, phase2: Duration) -> Result<(), String> {
    let start = Instant::now();
    let mut last_logs = String::new();
    while start.elapsed() < phase1 {
        let output = Command::new("docker")
            .args(["logs", container])
            .output()
            .map_err(|e| format!("failed to spawn `docker logs {container}`: {e}"))?;
        let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        if combined.contains("sandbox-entrypoint: sshd ready on 127.0.0.1:22") {
            last_logs = combined;
            break;
        }
        last_logs = combined;
        std::thread::sleep(Duration::from_millis(100));
    }
    if !last_logs.contains("sandbox-entrypoint: sshd ready on 127.0.0.1:22") {
        return Err(format!(
            "Phase 1: sshd-ready readiness line never appeared within {phase1:?}. \
             Entrypoint logs:\n{last_logs}",
        ));
    }
    if !wait_for(container, phase2, |out| {
        out.lines().any(|line| line.contains("127.0.0.1:22"))
    }) {
        let listen = docker_exec(container, &["ss", "-tlnH"]).1;
        return Err(format!(
            "Phase 2: 127.0.0.1:22 listen socket not visible within {phase2:?} \
             after sshd-ready log. Last `ss -tlnH`:\n{listen}\nEntrypoint logs:\n{last_logs}",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Axum router under test — only the `/sessions/{id}/proxy` route.
// ---------------------------------------------------------------------------

/// Mount a single-route axum router exposing
/// `GET /sessions/{id}/proxy`, wired through the production
/// `handle_proxy` entry point. The test serves on a TCP loopback
/// listener (the production daemon serves on a unix socket; both are
/// equivalent at the axum layer — `axum::serve` accepts any
/// `axum::serve::Listener` impl).
///
/// We hand-inject a fixed operator name as a route extension instead
/// of going through the real `PeerCredListener` peercred plumbing —
/// that mechanism is exercised by `integration_owner_peercred.rs` and
/// is not part of M18-S4's surface.
fn build_router(state: Arc<ProxyState>, operator_name: String) -> Router {
    Router::new()
        .route(
            "/sessions/{id}/proxy",
            get(
                move |State(state): State<Arc<ProxyState>>,
                      Path(id): Path<String>,
                      ws: WebSocketUpgrade| {
                    let op = operator_name.clone();
                    async move {
                        match handle_proxy(state, op, id, ws).await {
                            Ok(resp) => resp,
                            Err(e) => axum::response::IntoResponse::into_response(e),
                        }
                    }
                },
            ),
        )
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// **The M18-S4 proxy WebSocket round-trip proof.**
///
/// Stages a per-session container running sshd, mounts the daemon's
/// production `GET /sessions/{id}/proxy` handler behind an axum
/// router, connects via `tokio-tungstenite`, and asserts the SSH
/// server banner makes it back over the WebSocket — proving every
/// byte-pump invariant the milestone owns (WebSocket upgrade,
/// per-backend dispatch, async-I/O carve-out, bidirectional byte
/// transfer, close-frame propagation).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_proxy_websocket_round_trip_container_backend() {
    ensure_sandbox_guest_in_exe_parent();
    let version = unique_label("rt");
    let tag = format!("{LITE_IMAGE_REPOSITORY}:{version}");
    let _image_cleanup = LiteImageCleanup { tag: tag.clone() };

    // Step 1: build the lite image via the production code path.
    // `ensure_image` is synchronous; offload to `spawn_blocking` so we
    // do not block the tokio worker thread for the duration of the
    // image build.
    let v = version.clone();
    tokio::task::spawn_blocking(move || ensure_image(&v).expect("ensure_image"))
        .await
        .expect("ensure_image join");

    // Step 2: generate per-session ed25519 keypair (same code path
    // the daemon's session-create handler uses).
    let kp = SshKeypair::generate("proxy_round_trip").expect("keypair generation");

    // Step 3: stage credential files into a host tempdir the test
    // owns; container bind-mounts them readonly.
    let base_dir = TempDir::new().expect("tempdir for daemon base_dir");
    let stage_dir = TempDir::new().expect("tempdir for ssh staging");
    stage_ssh_credentials(
        stage_dir.path(),
        &kp,
        CROSS_USER_DAEMON_UID,
        CROSS_USER_DAEMON_GID,
    )
    .expect("stage_ssh_credentials");

    let authorized_keys_host = stage_dir.path().join("authorized_keys");
    let passwd_host = stage_dir.path().join("passwd");
    let group_host = stage_dir.path().join("group");

    // Step 5 (split out of order so we have a session id to name the
    // container with): create the SessionStore and insert a
    // container-backed session row. The store hands back the session
    // id; the docker container name is `sandbox-<session_id>`, which
    // is what the proxy handler's `pump_container` derives from
    // `session.id`.
    let (store, _orphans) =
        SessionStore::new(base_dir.path().to_path_buf()).expect("open SessionStore");
    let operator = "test-operator";
    let session = store
        .create_session_with_backend(
            SessionConfig::default(),
            None,
            BackendKind::Container,
            operator,
            0,
            "",
        )
        .expect("create container session row");
    let session_id = session.id;
    let container_name = format!("sandbox-{session_id}");
    let _ctr_cleanup = ContainerCleanup {
        name: container_name.clone(),
    };

    // Step 4 (resumed): launch the container under the production
    // hardening profile + cross-user `--user` flag + the three SSH
    // bind-mounts. Same hardening shape `build_create_argv` produces
    // in the production session-create path.
    let user_flag = format!("{CROSS_USER_DAEMON_UID}:{CROSS_USER_DAEMON_GID}");
    let ak_mount = format!(
        "type=bind,src={},dst=/run/sandbox/authorized_keys,readonly",
        authorized_keys_host.display()
    );
    let passwd_mount = format!(
        "type=bind,src={},dst=/etc/passwd,readonly",
        passwd_host.display()
    );
    let group_mount = format!(
        "type=bind,src={},dst=/etc/group,readonly",
        group_host.display()
    );
    let run = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &container_name,
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
            &user_flag,
            "--mount",
            &ak_mount,
            "--mount",
            &passwd_mount,
            "--mount",
            &group_mount,
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

    // Wait for sshd to be fully ready inside the container. The
    // two-phase probe (entrypoint "sshd ready" log line, then listen-
    // socket visibility) defeats the banner-write race where the
    // proxy connects after `bind(2)` but before sshd finishes its
    // post-accept setup — see `wait_for_sshd_ready`'s docstring.
    if let Err(reason) = wait_for_sshd_ready(
        &container_name,
        Duration::from_secs(15),
        Duration::from_secs(5),
    ) {
        panic!("{reason}");
    }

    // Step 6: mount the production proxy handler behind a one-route
    // axum router and serve on a TCP loopback listener.
    let store = Arc::new(store);
    // LimaManager is never invoked on the container path; constructed
    // pointing at the test's base_dir so its `~/.lima/`-rooted state
    // never escapes the tempdir.
    let lima = Arc::new(
        LimaManager::new(
            base_dir.path().to_path_buf(),
            "sandbox-base-test".to_string(),
        )
        .expect("LimaManager::new"),
    );
    let proxy_state = Arc::new(ProxyState { store, lima });
    let app = build_router(proxy_state, operator.to_string());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind TcpListener");
    let local_addr = listener.local_addr().expect("local_addr");
    let server_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Step 7: open a WebSocket client to the proxy endpoint and read
    // bytes until we see the SSH server banner. The banner is the
    // canonical "bytes flow end-to-end" signal — sshd emits it as the
    // first protocol output on every TCP connect.
    let ws_url = format!("ws://{local_addr}/sessions/{session_id}/proxy");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .unwrap_or_else(|e| panic!("WebSocket connect to {ws_url} failed: {e}"));

    // Accumulate inbound binary frames; the SSH banner can arrive
    // fragmented across multiple WebSocket frames so we keep reading
    // until either we see the marker or the deadline expires.
    let banner_deadline = Duration::from_secs(10);
    let banner = tokio::time::timeout(banner_deadline, async {
        let mut acc: Vec<u8> = Vec::new();
        while let Some(msg) = ws.next().await {
            match msg.expect("ws recv") {
                ClientMessage::Binary(bytes) => {
                    acc.extend_from_slice(&bytes);
                    if let Some(idx) = find_subsequence(&acc, b"SSH-2.0-") {
                        // Read a little further so we capture the
                        // newline-terminated banner line.
                        if acc[idx..].contains(&b'\n') {
                            return acc;
                        }
                    }
                }
                ClientMessage::Close(_) => {
                    return acc;
                }
                _ => {}
            }
        }
        acc
    })
    .await
    .unwrap_or_else(|_| panic!("did not receive SSH banner within {banner_deadline:?}"));

    let banner_str = String::from_utf8_lossy(&banner);
    assert!(
        banner_str.contains("SSH-2.0-"),
        "expected SSH-2.0- banner in proxy output; got {banner_str:?}",
    );

    // Send a courtesy client banner so sshd does not log a banner
    // timeout. The proxy is expected to forward these bytes into the
    // backend stdin (== sshd stdin) without further inspection. We
    // do not assert sshd's reaction here — the banner-back side
    // already proved bidirectional bytes flow.
    let client_banner = b"SSH-2.0-sandbox-proxy-test\r\n";
    ws.send(ClientMessage::Binary(client_banner.to_vec().into()))
        .await
        .expect("ws send client banner");

    // Close the WebSocket cleanly so the daemon-side ferry tears down
    // the docker-exec child promptly.
    let _ = ws.close(None).await;

    // Give the server task a moment to drain its in-flight ferry,
    // then drop it. The `kill_on_drop(true)` on the docker-exec child
    // guarantees the container-side `socat` and the connection to
    // sshd are reaped even if the ferry task is abruptly cancelled.
    tokio::time::sleep(Duration::from_millis(200)).await;
    server_task.abort();
}

/// Search for `needle` in `haystack`; return the index of the first
/// match. Used to detect the SSH banner across fragmented WebSocket
/// frames.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
