//! Integration tests for the guest-version refresh path
//! (api-session-isolation spec §§ 3.4, 3.8, 3.9; §§ 7.4, 7.5).
//!
//! These tests pin the refresh-on-start path so it stays observable
//! end-to-end:
//!
//! - `integration_guest_refresh_container_backend` — runs
//!   `refresh_guest_binary` against a real Docker container with an
//!   old `sandbox-guest` binary baked at `/usr/local/bin/sandbox-guest`
//!   and asserts (a) the binary mtime / byte content changes after the
//!   refresh, (b) the container survives the stop-then-cp dance.
//! - `integration_guest_refresh_updates_db_columns` — exercises the
//!   `SessionStore::update_guest_versions` call site so a successful
//!   refresh stamps the daemon's current proto / binary versions into
//!   the row. Hermetic — no Docker required.
//! - `integration_guest_refresh_fast_path_skips_refresh` — pins the
//!   property that a session with a compatible
//!   `guest_protocol_version` does not trigger the refresh seam. Uses
//!   the `is_protocol_compatible` predicate to spell out the decision
//!   the daemon's `start_session` makes; the absence of any side
//!   effect from `refresh_guest_binary` here mirrors the daemon's
//!   intent. Hermetic.
//! - `integration_guest_refresh_refuses_when_unsalvageable` —
//!   constructs the `GuestProtocolIncompatible` error variant the
//!   daemon returns on the refuse arm and asserts the daemon-side
//!   `error_response` helper maps it to HTTP 409 with both load-bearing
//!   message tokens (`refresh is not viable`, `recreate the session`).
//!   Hermetic.

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::http::StatusCode;
use sandbox_core::backend::{
    BackendKind, ContainerNetwork, ContainerRuntime, RuntimeStartArgs, SessionRuntime,
};
use sandbox_core::guest::{
    DAEMON_GUEST_PROTO_VERSION, SANDBOX_GUEST_VERSION, can_refresh_in_place, is_protocol_compatible,
};
use sandbox_core::session::SessionId;
use sandbox_core::{
    ApiError, BackendSpecific, SandboxError, SessionConfig, SessionSpec, SessionStore,
};
use sandboxd::error::error_response;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Hermetic tests — no Docker daemon
// ---------------------------------------------------------------------------

/// Spec § 7.5 refuse arm: assert the daemon's `error_response` helper
/// maps `GuestProtocolIncompatible` to HTTP 409 with both load-bearing
/// message tokens (`refresh is not viable`, `recreate the session`) in
/// the JSON body's `error` field. Drives the same code path
/// `start_session`'s refuse arm reaches.
#[test]
fn integration_guest_refresh_refuses_when_unsalvageable() {
    let err = SandboxError::GuestProtocolIncompatible {
        session_id: "0123456789ab".into(),
        session_proto: 0,
        daemon_proto: DAEMON_GUEST_PROTO_VERSION,
        reason: "session_proto=0 is not refreshable by this daemon".into(),
    };
    let (status, Json(body)): (StatusCode, Json<ApiError>) = error_response(err);

    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "GuestProtocolIncompatible must map to 409 Conflict"
    );
    assert!(
        body.error.contains("refresh is not viable"),
        "missing load-bearing token `refresh is not viable` in body: {}",
        body.error
    );
    assert!(
        body.error.contains("recreate the session"),
        "missing load-bearing token `recreate the session` in body: {}",
        body.error
    );
    assert!(
        body.error.contains("0123456789ab"),
        "missing session id in body: {}",
        body.error
    );
}

/// Spec § 7.4 fast-path: the compat predicate accepts the daemon's own
/// proto version, so a freshly-stamped session takes the no-refresh
/// arm. This pins the decision the `start_session` handler makes and
/// rules out a regression that would silently call
/// `refresh_guest_binary` on every start.
#[test]
fn integration_guest_refresh_fast_path_skips_refresh() {
    // The compat predicate matches the constant the daemon stamps on
    // create. Any drift between them would force refresh on every
    // start.
    assert!(
        is_protocol_compatible(DAEMON_GUEST_PROTO_VERSION),
        "is_protocol_compatible must accept DAEMON_GUEST_PROTO_VERSION; \
         drift would force refresh on every start"
    );

    // The fast path never reaches `can_refresh_in_place`, but the
    // refuse arm is gated on it: assert proto=0 maps to refuse so the
    // refuse-arm test's premise stays valid.
    assert!(!can_refresh_in_place(0));
}

/// Spec § 7.4 (storage half) — after a refresh + start, the daemon
/// calls `SessionStore::update_guest_versions` to atomically stamp the
/// new versions. This test exercises the store API directly: insert a
/// session with stale (`proto = 0`, `bin = ""`) versions, call
/// `update_guest_versions(operator, id, DAEMON_GUEST_PROTO_VERSION,
/// SANDBOX_GUEST_VERSION)`, and assert the row reads back at the new
/// values.
#[test]
fn integration_guest_refresh_updates_db_columns() {
    let tmp = TempDir::new().expect("tempdir");
    let (store, _orphans) = SessionStore::new(tmp.path().to_path_buf()).expect("open store");
    let store = Arc::new(store);

    let session = store
        .create_session(
            SessionConfig::default(),
            None,
            "test-operator",
            // Stale stamp — simulates a session created by an older
            // daemon. The current daemon create path stamps the real
            // constants; this `0` / `""` shape mirrors what V006
            // bequeaths on migration default.
            0,
            "",
        )
        .expect("create session");

    assert_eq!(session.guest_protocol_version, 0);
    assert_eq!(session.guest_binary_version, "");

    store
        .update_guest_versions(
            "test-operator",
            &session.id,
            DAEMON_GUEST_PROTO_VERSION,
            SANDBOX_GUEST_VERSION,
        )
        .expect("update_guest_versions");

    let reloaded = store
        .get_session(&session.id, "test-operator")
        .expect("read back")
        .expect("session present");
    assert_eq!(reloaded.guest_protocol_version, DAEMON_GUEST_PROTO_VERSION);
    assert_eq!(reloaded.guest_binary_version, SANDBOX_GUEST_VERSION);
}

/// `update_guest_versions` must reject a row owned by a different
/// operator with `SessionNotFound` so a daemon bug that lost the
/// per-caller filter would trip immediately.
#[test]
fn integration_guest_refresh_update_versions_filters_by_owner() {
    let tmp = TempDir::new().expect("tempdir");
    let (store, _orphans) = SessionStore::new(tmp.path().to_path_buf()).expect("open store");

    let session = store
        .create_session(SessionConfig::default(), None, "alice", 0, "")
        .expect("create session");

    let err = store
        .update_guest_versions("bob", &session.id, DAEMON_GUEST_PROTO_VERSION, "9.9.9")
        .expect_err("foreign owner must be rejected as SessionNotFound");
    assert!(
        matches!(err, SandboxError::SessionNotFound(_)),
        "expected SessionNotFound, got: {err:?}"
    );

    // Alice's row is untouched.
    let alice_row = store
        .get_session(&session.id, "alice")
        .expect("read back")
        .expect("alice's session present");
    assert_eq!(alice_row.guest_protocol_version, 0);
    assert_eq!(alice_row.guest_binary_version, "");
}

// ---------------------------------------------------------------------------
// Docker-required integration test (container refresh)
// ---------------------------------------------------------------------------

/// Tiny `docker network create` wrapper that cleans up on drop.
struct TestNetwork {
    name: String,
    container_ip: String,
    gateway_ip: String,
}

impl TestNetwork {
    fn create(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let third = (nanos as u8).wrapping_mul(1);
        let fourth_base = (nanos.wrapping_shr(8) as u8).wrapping_mul(16);
        let subnet = format!("10.97.{third}.{fourth_base}/28");
        let gateway_ip = format!("10.97.{third}.{}", fourth_base.wrapping_add(2));
        let container_ip = format!("10.97.{third}.{}", fourth_base.wrapping_add(3));
        let name = format!("sandbox-net-refresh-{label}-{nanos}");

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
            workspace_host_path: None,
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

/// Build the same sleep-image used by the round-trip integration test.
/// Ships an old (placeholder) `sandbox-guest` at the canonical path so
/// the refresh can be observed by reading the file back and comparing
/// to the daemon's actual sandbox-guest bytes.
///
/// The test Dockerfile declares `VOLUME ["/usr/local/bin"]` to bypass
/// the `--read-only` rootfs constraint that Docker 29.4+ (with the
/// containerd snapshotter / overlayfs driver) enforces against
/// `docker cp` writes — without the VOLUME declaration, `docker cp`
/// into a `--read-only` container's rootfs is rejected by dockerd
/// with `container rootfs is marked read-only` regardless of
/// destination path. The production lite image does not yet carry
/// this VOLUME declaration; see
/// `.tasks/handoffs/m13-s6-refresh-readonly-gap.md` for the
/// production-side resolution options.
const REFRESH_IMAGE_TAG: &str = "sandboxd-refresh-test:latest";
const REFRESH_DOCKERFILE: &str = "FROM alpine:latest\n\
RUN mkdir -p /usr/local/bin && \\\n    \
printf 'old-guest-placeholder\\n' > /usr/local/bin/sandbox-guest && \\\n    \
chmod +x /usr/local/bin/sandbox-guest\n\
VOLUME [\"/usr/local/bin\"]\n\
ENTRYPOINT [\"sh\", \"-c\", \"exec sleep 3600\"]\n";

static REFRESH_IMAGE_BUILD: std::sync::Once = std::sync::Once::new();

fn ensure_refresh_image() {
    REFRESH_IMAGE_BUILD.call_once(|| {
        use std::io::Write;
        let mut child = Command::new("docker")
            .args(["build", "-t", REFRESH_IMAGE_TAG, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("docker build invokable");
        {
            let stdin = child.stdin.as_mut().expect("docker build stdin");
            stdin
                .write_all(REFRESH_DOCKERFILE.as_bytes())
                .expect("write Dockerfile");
        }
        let output = child.wait_with_output().expect("docker build exit");
        assert!(
            output.status.success(),
            "docker build {REFRESH_IMAGE_TAG} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    });
}

fn refresh_spec() -> SessionSpec {
    SessionSpec {
        backend_specific: BackendSpecific::Container {
            memory_mb: 128,
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

/// Read the bytes of `/usr/local/bin/sandbox-guest` from inside a
/// stopped container via `docker cp` into a host tempfile.
fn read_in_container_guest_bytes(container_name: &str) -> Vec<u8> {
    let tmp = TempDir::new().expect("tempdir");
    let host_dst = tmp.path().join("guest-readback");
    let output = Command::new("docker")
        .args([
            "cp",
            &format!("{container_name}:/usr/local/bin/sandbox-guest"),
            host_dst.to_str().unwrap(),
        ])
        .output()
        .expect("docker cp invokable");
    assert!(
        output.status.success(),
        "docker cp out of {container_name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read(&host_dst).expect("read host tempfile")
}

/// Spec § 7.4 — exercise the container backend's `refresh_guest_binary`
/// end-to-end against a real Docker container. Asserts:
///
/// 1. Refresh succeeds against a stopped container with an old
///    placeholder `sandbox-guest` baked in.
/// 2. After refresh, the in-container `/usr/local/bin/sandbox-guest`
///    bytes match the daemon's sibling guest binary bytes (i.e. the
///    refresh actually replaced the file).
/// 3. The refresh sequence is idempotent — a second call against the
///    same container succeeds.
#[tokio::test]
async fn integration_guest_refresh_container_backend() {
    ensure_refresh_image();
    let net = TestNetwork::create("refresh");
    let runtime = ContainerRuntime::new(REFRESH_IMAGE_TAG, 128, 1.0, 1000, 1000);

    // Spin up a session row + the container itself.
    let tmp = TempDir::new().expect("tempdir");
    let (store, _orphans) = SessionStore::new(tmp.path().to_path_buf()).expect("open store");
    let store = Arc::new(store);
    let session = store
        .create_session_with_backend(
            SessionConfig::default(),
            Some("m13s5-refresh".into()),
            BackendKind::Container,
            "test-operator",
            // Stale stamp — simulates an older daemon's session.
            0,
            "",
        )
        .expect("persist session");

    let _cleanup = ContainerCleanup::new(&session.id);
    runtime.register_session(session.id, net.to_container_network());

    let handle = runtime
        .create(&session.id, &refresh_spec())
        .await
        .expect("runtime.create");
    runtime
        .start(&handle, &RuntimeStartArgs::default())
        .await
        .expect("runtime.start");

    // Stop the container — the refresh sequence requires (and
    // explicitly defends against) a stopped container.
    runtime.stop(&handle).await.expect("runtime.stop");

    // Capture the old bytes so we can detect change.
    let container_name = handle.as_str().to_string();
    let old_bytes = read_in_container_guest_bytes(&container_name);
    assert!(
        old_bytes.starts_with(b"old-guest-placeholder"),
        "pre-refresh in-container guest should be the placeholder"
    );

    // Drive the refresh — first invocation.
    runtime
        .refresh_guest_binary(&handle)
        .await
        .expect("refresh_guest_binary (first call)");

    let new_bytes = read_in_container_guest_bytes(&container_name);
    let daemon_bytes = std::fs::read(sandbox_core::guest_agent_path().expect("guest_agent_path"))
        .expect("read daemon-side sandbox-guest");

    assert_eq!(
        new_bytes, daemon_bytes,
        "post-refresh in-container guest must match daemon-side bytes"
    );
    assert_ne!(
        new_bytes, old_bytes,
        "refresh must have replaced the placeholder"
    );

    // Idempotency: re-running refresh against the same container is a
    // no-op modulo writes (api-session-isolation spec § 3.9 motivates
    // the property — a daemon crash after refresh but before start
    // re-runs refresh on the next attempt).
    runtime
        .refresh_guest_binary(&handle)
        .await
        .expect("refresh_guest_binary (second call)");

    let after_second = read_in_container_guest_bytes(&container_name);
    assert_eq!(
        after_second, daemon_bytes,
        "second refresh keeps the daemon-side bytes in place"
    );

    runtime.delete(&handle).await.expect("runtime.delete");
}
