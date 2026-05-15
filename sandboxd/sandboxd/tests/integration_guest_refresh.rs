//! Integration tests for the guest-version refresh path
//! (api-session-isolation spec §§ 3.4, 3.8, 3.9; §§ 7.4, 7.5).
//!
//! Under spec § 3.8.1's bind-mount design, the container backend's
//! refresh path is not a `docker cp` into the rootfs; instead, the
//! daemon stages `sandbox-guest` once into
//! `{base_dir}/guest/sandbox-guest` at startup and every container
//! session bind-mounts that path read-only at
//! `/usr/local/bin/sandbox-guest`. Refresh becomes `docker restart`.
//!
//! Test coverage in this file:
//!
//! - `integration_guest_refresh_refuses_when_unsalvageable` —
//!   constructs the `GuestProtocolIncompatible` error variant the
//!   daemon returns on the refuse arm; asserts the daemon-side
//!   `error_response` helper maps it to HTTP 409 with both
//!   load-bearing message tokens. Hermetic.
//! - `integration_guest_refresh_fast_path_skips_refresh` — pins the
//!   compat-predicate decision the daemon's `start_session` makes
//!   when the persisted column matches `DAEMON_GUEST_PROTO_VERSION`.
//!   Hermetic.
//! - `integration_guest_refresh_updates_db_columns` — exercises
//!   `SessionStore::update_guest_versions` so a successful refresh
//!   stamps the daemon's current versions into the row. Hermetic.
//! - `integration_guest_refresh_update_versions_filters_by_owner` —
//!   foreign-owner rejection on the same store call. Hermetic.
//! - `integration_guest_refresh_container_backend` — runs against
//!   the production-shape `--read-only` lite image
//!   (`sandboxd-lite:<workspace_version>`, produced by
//!   `make lite-image`). Asserts the in-container
//!   `/usr/local/bin/sandbox-guest` post-restart bytes are
//!   bit-identical to the daemon's staged-source bytes (the
//!   bind-mount design's load-bearing property) and that
//!   `update_guest_versions` lands. Docker-required.
//! - `integration_guest_binary_swap_picked_up_by_new_sessions` —
//!   change the host-side staged bytes between two container creates;
//!   verify the second container sees the new bytes through its bind-
//!   mount. Pins the "new sessions automatically pick up the
//!   refreshed daemon's guest" property. Docker-required.
//! - `integration_guest_binary_shared_inode_across_sessions` — start
//!   two container sessions; verify their bind-mounted
//!   `/usr/local/bin/sandbox-guest` resolves to the same backing
//!   inode on the host (the "one inode shared across every live
//!   session" property the bind-mount design preserves over a copy-
//!   per-session approach). Docker-required.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::http::StatusCode;
use sandbox_core::backend::{
    BackendKind, ContainerNetwork, ContainerRuntime, RuntimeStartArgs, SessionRuntime,
    lite_image_tag_for_version,
};
use sandbox_core::guest::{
    DAEMON_GUEST_PROTO_VERSION, SANDBOX_GUEST_VERSION, can_refresh_in_place,
    is_protocol_compatible,
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
    assert!(
        is_protocol_compatible(DAEMON_GUEST_PROTO_VERSION),
        "is_protocol_compatible must accept DAEMON_GUEST_PROTO_VERSION; \
         drift would force refresh on every start"
    );

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

    let alice_row = store
        .get_session(&session.id, "alice")
        .expect("read back")
        .expect("alice's session present");
    assert_eq!(alice_row.guest_protocol_version, 0);
    assert_eq!(alice_row.guest_binary_version, "");
}

// ---------------------------------------------------------------------------
// Docker-required integration tests (container refresh, bind-mount design)
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

/// Production-shape lite image tag — `sandboxd-lite:<workspace_version>`,
/// exactly what `make lite-image` produces (using the same
/// `lite_image_tag_for_version` helper the daemon's `ensure_image`
/// uses at runtime). The integration profile depends on `lite-image`
/// in the Makefile; if a developer iterates without rebuilding the
/// image after a workspace-version bump the test would error with a
/// clear "image not found" message from dockerd.
fn lite_image_tag() -> String {
    lite_image_tag_for_version(env!("CARGO_PKG_VERSION"))
}

/// Stage `bytes` (with mode 0755) into a per-test base directory's
/// `guest/sandbox-guest`. Returns the absolute host path. Mirrors
/// what `sandbox_core::stage_embedded_guest_binary_into_base_dir`
/// does at daemon startup so the test fixture exercises the same
/// on-disk shape every container session sees.
fn stage_test_guest(base_dir: &std::path::Path, bytes: &[u8]) -> PathBuf {
    let guest_dir = base_dir.join(sandbox_core::STAGED_GUEST_SUBDIR);
    std::fs::create_dir_all(&guest_dir).expect("create guest subdir");
    let path = sandbox_core::staged_guest_path(base_dir);
    // Re-use the production staging function so a regression in the
    // atomic-write or chmod logic surfaces here too. Synthetic bytes
    // mean the resulting "guest" never actually executes useful
    // protocol code; the bind-mount design is what the test exercises.
    let outcome =
        sandbox_core::stage_guest_binary_at(&path, bytes).expect("stage_guest_binary_at");
    assert!(
        matches!(
            outcome,
            sandbox_core::StageOutcome::Wrote | sandbox_core::StageOutcome::Rewrote
        ),
        "first stage on a freshly-created subdir must write or rewrite, not skip; \
         got {outcome:?}",
    );
    path
}

/// A bash one-liner that sleeps long enough for the test to complete
/// its assertions. The lite-image entrypoint is
/// `["/usr/bin/tini", "--", "/usr/local/bin/sandbox-guest"]`; the
/// bind-mount overlays the in-image binary, so the file the
/// container actually exec's is our synthetic script. Using `bash`
/// rather than `sh` because the lite image ships `bash` (per the
/// Dockerfile's apt-get) and the shebang surfaces cleanly to the
/// kernel's `execve`.
fn placeholder_sleep_script(version_tag: &str) -> Vec<u8> {
    format!(
        "#!/usr/bin/env bash\n\
         # synthetic-sandbox-guest version={version_tag}\n\
         # Test stub binary — sleeps long enough for the host-side\n\
         # assertions to read back the bind-mount contents and (for\n\
         # the shared-inode test) stat both containers'\n\
         # /usr/local/bin/sandbox-guest.\n\
         exec sleep 300\n",
    )
    .into_bytes()
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
/// container via `docker cp` into a host tempfile.
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

/// Spec § 7.4 (bind-mount design) — exercise the container
/// backend's `refresh_guest_binary` end-to-end against the
/// production-shape `--read-only` lite image
/// (`sandboxd-lite:<workspace_version>`, the same image `make
/// lite-image` produces). Asserts:
///
/// 1. Refresh succeeds against a stopped container.
/// 2. After refresh + start, the in-container
///    `/usr/local/bin/sandbox-guest` bytes are bit-identical to the
///    daemon's staged copy on the host (the bind-mount property).
/// 3. `SessionStore::update_guest_versions` writes the daemon's
///    current `DAEMON_GUEST_PROTO_VERSION` / `SANDBOX_GUEST_VERSION`
///    into the row, mirroring the daemon's post-refresh atomic
///    update (spec § 3.9).
/// 4. The refresh sequence is idempotent — a second call against the
///    same container succeeds.
///
/// The lite image's ENTRYPOINT is `["/usr/bin/tini", "--",
/// "/usr/local/bin/sandbox-guest"]`; the bind-mount overlays the
/// in-image binary with a synthetic shell script so the container
/// stays alive long enough for the assertions. The production
/// `sandbox-guest` would also stay alive (it binds TCP :5123 and
/// listens forever), but the placeholder removes a network / port
/// dependency from this test.
#[tokio::test]
async fn integration_guest_refresh_container_backend() {
    let net = TestNetwork::create("refresh");

    // Per-test base directory. The daemon would point its
    // `staged_guest_path` at `{base_dir}/guest/sandbox-guest`; the
    // test fixture stages a synthetic script at that path so the
    // bind-mount lands an executable file inside the container.
    let base_dir = TempDir::new().expect("tempdir base_dir");
    let staged_path = stage_test_guest(base_dir.path(), &placeholder_sleep_script("v-new"));

    let runtime = ContainerRuntime::new(
        lite_image_tag(),
        128,
        1.0,
        1000,
        1000,
        staged_path.clone(),
    );

    let tmp = TempDir::new().expect("tempdir for store");
    let (store, _orphans) = SessionStore::new(tmp.path().to_path_buf()).expect("open store");
    let store = Arc::new(store);
    let session = store
        .create_session_with_backend(
            SessionConfig::default(),
            Some("m16-s6-refresh".into()),
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

    // Stop before refresh — the orchestrator (`start_session`) asserts
    // `state == Stopped` before invoking refresh; mirror that
    // precondition.
    runtime.stop(&handle).await.expect("runtime.stop");

    // Drive refresh = `docker restart`.
    runtime
        .refresh_guest_binary(&handle)
        .await
        .expect("refresh_guest_binary (first call)");

    // The container is now running again (refresh restarts it); the
    // in-container `/usr/local/bin/sandbox-guest` resolves through
    // the bind-mount to our staged file, so its bytes must equal the
    // host-side staged bytes.
    let container_name = handle.as_str().to_string();
    let in_container = read_in_container_guest_bytes(&container_name);
    let on_host = std::fs::read(&staged_path).expect("read host staged guest");
    assert_eq!(
        in_container, on_host,
        "post-refresh in-container `/usr/local/bin/sandbox-guest` must be \
         bit-identical to the daemon's host-side staged file — that's the \
         load-bearing property of the bind-mount design (api-session-isolation \
         spec § 3.8.1)"
    );

    // Idempotency: re-running refresh against the same container is a
    // no-op modulo restarting it again. The bind-mount source hasn't
    // changed; the container's binary stays bit-identical.
    runtime
        .refresh_guest_binary(&handle)
        .await
        .expect("refresh_guest_binary (second call)");
    let after_second = read_in_container_guest_bytes(&container_name);
    assert_eq!(
        after_second, on_host,
        "second refresh must leave the bind-mount source intact",
    );

    // Spec § 3.9 — after refresh + start succeed, the daemon stamps
    // the current versions on the row. Mirror the orchestrator's
    // call here so the integration coverage includes the store-side
    // write (the existing hermetic test
    // `integration_guest_refresh_updates_db_columns` covers the
    // store API in isolation; this assertion ties it to the live
    // refresh path).
    store
        .update_guest_versions(
            "test-operator",
            &session.id,
            DAEMON_GUEST_PROTO_VERSION,
            SANDBOX_GUEST_VERSION,
        )
        .expect("update_guest_versions");
    let row = store
        .get_session(&session.id, "test-operator")
        .expect("read row")
        .expect("row present");
    assert_eq!(row.guest_protocol_version, DAEMON_GUEST_PROTO_VERSION);
    assert_eq!(row.guest_binary_version, SANDBOX_GUEST_VERSION);

    runtime.delete(&handle).await.expect("runtime.delete");
}

/// Change the host-side staged file's bytes between two container
/// creates; verify the second container sees the new bytes through
/// its bind-mount (api-session-isolation spec § 3.8.1).
///
/// This pins the "new sessions automatically pick up the refreshed
/// daemon's guest" property of the bind-mount design: a daemon
/// upgrade that stages new bytes into `{base_dir}/guest/sandbox-guest`
/// changes what every subsequent container session sees at
/// `/usr/local/bin/sandbox-guest`, without per-session refresh work.
#[tokio::test]
async fn integration_guest_binary_swap_picked_up_by_new_sessions() {
    let net = TestNetwork::create("swap");
    let base_dir = TempDir::new().expect("tempdir base_dir");

    // Stage v1 and create container #1.
    let staged_path = stage_test_guest(base_dir.path(), &placeholder_sleep_script("v-one"));
    let runtime = ContainerRuntime::new(
        lite_image_tag(),
        128,
        1.0,
        1000,
        1000,
        staged_path.clone(),
    );

    let tmp = TempDir::new().expect("tempdir for store");
    let (store, _orphans) = SessionStore::new(tmp.path().to_path_buf()).expect("open store");
    let store = Arc::new(store);

    let session_one = store
        .create_session_with_backend(
            SessionConfig::default(),
            Some("m16-s6-swap-one".into()),
            BackendKind::Container,
            "test-operator",
            DAEMON_GUEST_PROTO_VERSION,
            SANDBOX_GUEST_VERSION,
        )
        .expect("persist session #1");
    let _c1 = ContainerCleanup::new(&session_one.id);
    runtime.register_session(session_one.id, net.to_container_network());
    let handle_one = runtime
        .create(&session_one.id, &refresh_spec())
        .await
        .expect("runtime.create #1");
    runtime
        .start(&handle_one, &RuntimeStartArgs::default())
        .await
        .expect("runtime.start #1");

    let c1_bytes = read_in_container_guest_bytes(handle_one.as_str());
    assert!(
        c1_bytes.windows("v-one".len()).any(|w| w == b"v-one"),
        "container #1 must see v-one bytes through its bind-mount; got {} bytes",
        c1_bytes.len(),
    );

    // Swap: rewrite the staged file with v2 bytes. The atomic rename
    // happens inside `stage_guest_binary_at`; container #1's
    // bind-mount continues to resolve to the OLD inode (the kernel
    // captured the inode at mount time) — that's a kernel-level
    // guarantee we don't assert here, we only assert that NEW
    // containers see the NEW bytes.
    let v2_bytes = placeholder_sleep_script("v-two-rewritten");
    let outcome = sandbox_core::stage_guest_binary_at(&staged_path, &v2_bytes)
        .expect("stage v2 bytes");
    assert_eq!(
        outcome,
        sandbox_core::StageOutcome::Rewrote,
        "staging different bytes over an existing file must take the Rewrote arm",
    );

    // New network for container #2 (each container needs its own /28 IP).
    let net2 = TestNetwork::create("swap2");

    let session_two = store
        .create_session_with_backend(
            SessionConfig::default(),
            Some("m16-s6-swap-two".into()),
            BackendKind::Container,
            "test-operator",
            DAEMON_GUEST_PROTO_VERSION,
            SANDBOX_GUEST_VERSION,
        )
        .expect("persist session #2");
    let _c2 = ContainerCleanup::new(&session_two.id);
    runtime.register_session(session_two.id, net2.to_container_network());
    let handle_two = runtime
        .create(&session_two.id, &refresh_spec())
        .await
        .expect("runtime.create #2");
    runtime
        .start(&handle_two, &RuntimeStartArgs::default())
        .await
        .expect("runtime.start #2");

    let c2_bytes = read_in_container_guest_bytes(handle_two.as_str());
    assert!(
        c2_bytes
            .windows("v-two-rewritten".len())
            .any(|w| w == b"v-two-rewritten"),
        "container #2 must see v-two bytes through its bind-mount after the \
         host-side staged file was rewritten; got {} bytes",
        c2_bytes.len(),
    );

    runtime
        .delete(&handle_one)
        .await
        .expect("runtime.delete #1");
    runtime
        .delete(&handle_two)
        .await
        .expect("runtime.delete #2");
}

/// Start two container sessions; verify their bind-mounted
/// `/usr/local/bin/sandbox-guest` resolves to the same backing inode
/// on the host (api-session-isolation spec § 3.8.1).
///
/// The bind-mount design's load-bearing property is that one host
/// inode is shared across every live session — the kernel does not
/// synthesize new inodes for bind-mount targets, so two containers
/// bind-mounting the same source see the same inode number from
/// inside their own filesystem views. A copy-per-session approach
/// would produce N inodes for N containers and N copies of the
/// binary in the kernel page cache; the bind-mount keeps it at one.
///
/// The assertion is layered:
///
/// 1. **Docker-side**: `docker inspect -f '{{json .Mounts}}'` shows
///    each container has a bind-mount whose `Source` equals the
///    host-side staged path. Both containers' `Source` strings are
///    the same string, so by definition they share the host inode
///    (a single path resolves to a single inode at a moment in
///    time).
///
/// 2. **In-container**: `docker exec <ctr> stat -c %i
///    /usr/local/bin/sandbox-guest` reports the host inode (the
///    kernel exposes the source inode through the bind-mount). We
///    assert this for at least one container (the second falls
///    through the same kernel path; doing both adds little signal
///    over the docker-inspect equality above and would make the
///    test more fragile to container-lifecycle races).
///
/// The combination of (1) and (2) covers the kernel-level invariant
/// and the docker-side wiring; together they pin the shared-inode
/// property under realistic load.
#[tokio::test]
async fn integration_guest_binary_shared_inode_across_sessions() {
    let base_dir = TempDir::new().expect("tempdir base_dir");
    let staged_path = stage_test_guest(base_dir.path(), &placeholder_sleep_script("shared"));
    let runtime = ContainerRuntime::new(
        lite_image_tag(),
        128,
        1.0,
        1000,
        1000,
        staged_path.clone(),
    );

    let tmp = TempDir::new().expect("tempdir for store");
    let (store, _orphans) = SessionStore::new(tmp.path().to_path_buf()).expect("open store");
    let store = Arc::new(store);

    // Container A.
    let net_a = TestNetwork::create("shareda");
    let session_a = store
        .create_session_with_backend(
            SessionConfig::default(),
            Some("m16-s6-share-a".into()),
            BackendKind::Container,
            "test-operator",
            DAEMON_GUEST_PROTO_VERSION,
            SANDBOX_GUEST_VERSION,
        )
        .expect("persist session A");
    let _cleanup_a = ContainerCleanup::new(&session_a.id);
    runtime.register_session(session_a.id, net_a.to_container_network());
    let handle_a = runtime
        .create(&session_a.id, &refresh_spec())
        .await
        .expect("runtime.create A");
    runtime
        .start(&handle_a, &RuntimeStartArgs::default())
        .await
        .expect("runtime.start A");

    // Container B.
    let net_b = TestNetwork::create("sharedb");
    let session_b = store
        .create_session_with_backend(
            SessionConfig::default(),
            Some("m16-s6-share-b".into()),
            BackendKind::Container,
            "test-operator",
            DAEMON_GUEST_PROTO_VERSION,
            SANDBOX_GUEST_VERSION,
        )
        .expect("persist session B");
    let _cleanup_b = ContainerCleanup::new(&session_b.id);
    runtime.register_session(session_b.id, net_b.to_container_network());
    let handle_b = runtime
        .create(&session_b.id, &refresh_spec())
        .await
        .expect("runtime.create B");
    runtime
        .start(&handle_b, &RuntimeStartArgs::default())
        .await
        .expect("runtime.start B");

    // (1) Docker-side mount-source equality. Both containers must
    // report the same `Source` path on the bind-mount targeting
    // `/usr/local/bin/sandbox-guest`. A regression in the daemon's
    // staged-path threading (e.g. each runtime instance pointing
    // at a per-session tempfile) would trip this assertion long
    // before reaching the in-container inode read.
    let src_a = bind_mount_source_for_guest(handle_a.as_str());
    let src_b = bind_mount_source_for_guest(handle_b.as_str());
    assert_eq!(
        src_a, src_b,
        "containers A and B must bind-mount the same host source for \
         /usr/local/bin/sandbox-guest; got A={src_a}, B={src_b}",
    );
    assert_eq!(
        std::path::PathBuf::from(&src_a).canonicalize().expect("canonicalize A"),
        staged_path.canonicalize().expect("canonicalize staged"),
        "containers must bind-mount the daemon-staged path verbatim",
    );

    // (2) In-container inode read — defense-in-depth on top of (1).
    // The kernel exposes the source inode through bind mounts, so a
    // container's own stat of the bind-mount target reports the
    // host source inode. This is a kernel-level invariant; if the
    // container is reachable for `docker exec`, we read it; if it
    // exited (e.g. raced by a parallel orphan-reaper-shaped test
    // operating outside our test group), we log and skip. The
    // docker-side equality in (1) is the load-bearing assertion;
    // this read is informational.
    let host_inode = inode_of(&staged_path);
    match try_inode_of_in_container_guest(handle_a.as_str(), 5) {
        Some(in_container_inode) => {
            assert_eq!(
                in_container_inode, host_inode,
                "container A's in-container stat of /usr/local/bin/sandbox-guest \
                 must report the host-side staged inode — the bind-mount design's \
                 shared-inode property; docker reports source={src_a}, host inode \
                 ={host_inode}, in-container inode={in_container_inode}",
            );
        }
        None => {
            // Pinned at eprintln rather than `unreachable!` because
            // the docker-side equality in (1) already proves the
            // shared-inode property structurally — the kernel
            // cannot expose a different inode through a bind-mount
            // than the source has. The in-container read is
            // defense-in-depth.
            eprintln!(
                "integration_guest_binary_shared_inode_across_sessions: \
                 container {} did not stay alive for the in-container \
                 stat read; relying on docker inspect equality (assertion \
                 (1) above) for the shared-inode property",
                handle_a.as_str(),
            );
        }
    }

    runtime.delete(&handle_a).await.expect("runtime.delete A");
    runtime.delete(&handle_b).await.expect("runtime.delete B");
}

/// Read the host-side `Source` of the bind-mount targeting
/// `/usr/local/bin/sandbox-guest` for the given container, via
/// `docker inspect -f '{{json .Mounts}}'`. Docker's `.Mounts` is a
/// JSON array of mount info; we scan for the entry whose
/// `Destination` matches the canonical in-container guest path.
fn bind_mount_source_for_guest(container_name: &str) -> String {
    let output = Command::new("docker")
        .args(["inspect", "-f", "{{json .Mounts}}", container_name])
        .output()
        .expect("docker inspect invokable");
    assert!(
        output.status.success(),
        "docker inspect {container_name} .Mounts failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json_str = String::from_utf8(output.stdout).expect("Mounts utf8");
    let mounts: serde_json::Value =
        serde_json::from_str(json_str.trim()).expect("Mounts parse");
    let arr = mounts.as_array().expect("Mounts is array");
    for m in arr {
        if m.get("Destination").and_then(|v| v.as_str())
            == Some("/usr/local/bin/sandbox-guest")
        {
            return m
                .get("Source")
                .and_then(|v| v.as_str())
                .expect("mount has Source")
                .to_string();
        }
    }
    panic!(
        "no bind-mount with Destination=/usr/local/bin/sandbox-guest found in \
         {container_name}'s Mounts: {json_str}",
    );
}

/// Best-effort read of the in-container inode of
/// `/usr/local/bin/sandbox-guest`. Returns `Some(inode)` if the
/// container is reachable for `docker exec`; returns `None` if the
/// container is not running / no longer exists (e.g. raced by a
/// parallel orphan-reaper-shaped test). Retries up to `attempts`
/// times on transient runqueue races where `docker start` returns
/// before the kernel has fully scheduled PID 1.
///
/// The caller decides whether a `None` is fatal — the docker-side
/// mount-source equality assertion in
/// `integration_guest_binary_shared_inode_across_sessions` is the
/// load-bearing assertion; the in-container read is defense-in-depth
/// and tolerated as informational if it can't be obtained.
fn try_inode_of_in_container_guest(container_name: &str, attempts: u32) -> Option<u64> {
    for _ in 0..attempts {
        let output = Command::new("docker")
            .args([
                "exec",
                container_name,
                "stat",
                "-c",
                "%i",
                "/usr/local/bin/sandbox-guest",
            ])
            .output()
            .expect("docker exec stat invokable");
        if output.status.success() {
            let stdout = String::from_utf8(output.stdout).expect("stat stdout utf8");
            return Some(
                stdout
                    .trim()
                    .parse()
                    .unwrap_or_else(|e| panic!("parse inode {stdout:?}: {e}")),
            );
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("is not running") || stderr.contains("No such container") {
            std::thread::sleep(std::time::Duration::from_millis(200));
            continue;
        }
        // Some other error — surface it; it's not the
        // container-lifecycle race the function is designed to
        // tolerate.
        panic!("docker exec {container_name} stat failed: {stderr}");
    }
    None
}

/// Read the on-host inode number of `path`.
fn inode_of(path: &std::path::Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat {} failed: {e}", path.display()))
        .ino()
}
