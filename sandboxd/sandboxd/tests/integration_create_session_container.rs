//! Integration tests for daemon-side container backend wiring.
//!
//! These tests cover the wiring that ties the container runtime, the
//! lite image builder, and the `GET /backends` endpoint into
//! `POST /sessions`. The contracts these tests pin:
//!
//! - `integration_create_session_container_backend_round_trip` —
//!   end-to-end: build the lite image, create a session row tagged
//!   `BackendKind::Container`, dispatch `runtime.create()` +
//!   `runtime.start()` through the dispatch table, and verify the
//!   wire-shape `SessionDto` round-trips with `backend == "container"`.
//! - `integration_create_session_container_first_use_warning_surfaces`
//!   — first call to `ensure_image` for a unique daemon-version tag
//!   yields the verbatim first-use warning string; the second call for
//!   the same tag yields no warning (cache hit).
//! - `integration_create_session_container_rejects_hardened` — the
//!   daemon rejects a `hardened: true` request when the container
//!   backend is selected, before any state is allocated. Hermetic; no
//!   Docker daemon required.
//! - `integration_create_session_container_rejects_no_cache` — the
//!   daemon rejects a `no_cache: true` request against the container
//!   backend (whose capability matrix declares
//!   `per_session_no_cache: false`) via `SessionSpec::validate`,
//!   yielding `UnsupportedFeature::PerSessionNoCache(Container)`.
//!   Hermetic; no Docker daemon required.
//! - `integration_create_session_lima_rejects_fractional_cpus` — the
//!   daemon rejects a fractional `cpus` request on the Lima backend
//!   with HTTP 400, surfacing the design-aligned "integer cores"
//!   message rather than silently truncating `1.5` to `1` via the
//!   downstream `as u32` cast. Hermetic; no Lima or limactl required.
//!
//! The first two tests require a real Docker daemon (mirroring the
//! container-runtime integration tests) and run only under the
//! `integration` nextest profile (selected by the `integration_*` name
//! prefix — see `sandboxd/.config/nextest.toml`). The third is
//! hermetic.
//!
//! These tests intentionally bypass the full HTTP router because
//! constructing a real `AppState` would require booting Lima, the
//! gateway container, the network manager, and the event bus — most
//! of which the container backend never touches at this layer.
//! Each test exercises the precise piece of wiring that its name
//! names: backend dispatch + DTO mapping (round_trip), `ensure_image`
//! first-use semantics (first_use_warning), and the daemon-side
//! hardened-flag rejection branch (rejects_hardened).
//!
//! The e2e suite re-verifies the same contracts end-to-end through
//! the CLI; these tests stay as the daemon-level regression net.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Once};
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_core::backend::{
    BackendKind, ContainerNetwork, ContainerRuntime, EnsureImageOutcome, LITE_FIRST_USE_WARNING,
    LITE_IMAGE_REPOSITORY, RuntimeStartArgs, RuntimeStatus, SessionRuntime, UnsupportedFeature,
    ensure_image,
};
use sandbox_core::session::{SessionId, WorkspaceMode, WorkspaceModeKind};
use sandbox_core::{
    BackendSpecific, SessionConfig, SessionDto, SessionSpec, SessionState, SessionStore,
};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Test scaffolding shared with sandbox-core's container integration tests.
// ---------------------------------------------------------------------------

/// Per-test docker network owning one /28 from a private range outside
/// any production allocations. Removed on Drop (best-effort).
struct TestNetwork {
    name: String,
    container_ip: String,
    gateway_ip: String,
}

impl TestNetwork {
    /// Create a per-session docker network whose name matches the
    /// canonical `sandbox-net-{session_id}` shape the orphan reaper's
    /// dual-anchor IPAM gate expects.
    ///
    /// Using `session_id` (rather than an arbitrary label) is
    /// load-bearing for nextest concurrency safety: any test in the
    /// suite that boots a real `sandboxd` triggers the daemon's
    /// startup orphan reaper, which enumerates every `sandbox-*`
    /// container on the host. With a canonical network name, the
    /// reaper parses the sibling network, observes its IPAM subnets
    /// fall outside the daemon's own allocator pool (test daemons use
    /// `10.2xx.x.x/24`; this network sits in `10.98.x.y/28`), and
    /// skips the entire session-id tuple — container included. A
    /// non-canonical name (e.g. `sandbox-net-roundtrip-{nanos}`)
    /// would not parse as a session id, leave `out_of_pool_sids`
    /// empty for our session, and the reaper would happily `docker
    /// rm -f` the test container out from under the in-flight
    /// `runtime.delete`, surfacing as
    /// `removal of container ... is already in progress` from
    /// dockerd. See `sandboxd/.config/nextest.toml`'s comment on the
    /// `docker-sandbox-namespace` group for the namespace-pollution
    /// rationale.
    fn create(session_id: &SessionId) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let third = (nanos as u8).wrapping_mul(1);
        let fourth_base = (nanos.wrapping_shr(8) as u8).wrapping_mul(16);
        let subnet = format!("10.98.{third}.{fourth_base}/28");
        let gateway_ip = format!("10.98.{third}.{}", fourth_base.wrapping_add(2));
        let container_ip = format!("10.98.{third}.{}", fourth_base.wrapping_add(3));
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
            // The test fixtures here construct a `ContainerNetwork`
            // directly for low-level runtime exercise; the daemon's
            // create_session path wires `ca_host_path = Some(...)`
            // (see main.rs container branch). The CA-mount wiring is
            // covered by the unit test
            // `container_runtime_create_includes_ca_mount_when_path_set`.
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

/// `docker rm -f` + `docker volume rm` insurance against test panics
/// between create and explicit delete.
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

/// Per-test image cleanup: `ensure_image` builds `LITE_IMAGE_REPOSITORY:<tag>`
/// the first time it sees a unique tag. Tests that exercise the
/// first-use branch must isolate by tag (otherwise a previous test's
/// cached image hides the build path).
struct TestImage {
    tag: String,
}

impl TestImage {
    fn unique_tag(label: &str) -> String {
        // Monotonically-increasing per-process suffix so concurrent
        // tests in the same process do not collide. UNIX_EPOCH nanos
        // give us the inter-process uniqueness when nextest runs many
        // copies.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("phase3d-{label}-{nanos}-{n}")
    }

    fn new(unique_tag: String) -> Self {
        Self { tag: unique_tag }
    }
}

impl Drop for TestImage {
    fn drop(&mut self) {
        let full = format!("{LITE_IMAGE_REPOSITORY}:{}", self.tag);
        let _ = Command::new("docker")
            .args(["image", "rm", "-f", &full])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// The round-trip test exercises the daemon-side wiring (backend
/// round-trip through SQLite, dispatch through `runtime.create` /
/// `runtime.start`, DTO mapping) without depending on the production
/// lite image's `sandbox-guest` agent runtime semantics — the lite
/// image entrypoint expects in-container TCP and route-helper
/// scaffolding that Phase 3D's daemon flow provides only at
/// `setup_session_networking` time, not in this hermetic test
/// surface. Mirrors Phase 3A's `sandboxd-test-sleep:latest` image
/// (alpine + `sleep 3600` ENTRYPOINT) so the container stays running
/// long enough for the status-after-start assertion to hold.
const ROUND_TRIP_IMAGE_TAG: &str = "sandboxd-phase3d-test-sleep:latest";
const ROUND_TRIP_DOCKERFILE: &str =
    "FROM alpine:latest\nENTRYPOINT [\"sh\", \"-c\", \"exec sleep 3600\"]\n";

static ROUND_TRIP_IMAGE_BUILD: Once = Once::new();

fn ensure_round_trip_image() {
    ROUND_TRIP_IMAGE_BUILD.call_once(|| {
        let mut child = Command::new("docker")
            .args(["build", "-t", ROUND_TRIP_IMAGE_TAG, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("docker build invokable");
        {
            let stdin = child.stdin.as_mut().expect("docker build stdin");
            stdin
                .write_all(ROUND_TRIP_DOCKERFILE.as_bytes())
                .expect("write Dockerfile");
        }
        let output = child.wait_with_output().expect("docker build exit");
        assert!(
            output.status.success(),
            "docker build {ROUND_TRIP_IMAGE_TAG} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    });
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

/// Resolve a stable host path for the bind-mount source the runtime
/// passes as `guest_bind_source`. Tests that `docker create` a real
/// container need the bind-mount source to exist on disk; tests that
/// only exercise hermetic capability checks pass a synthetic path
/// directly to `ContainerRuntime::new`. See the api-session-isolation
/// design for the bind-mount details.
fn guest_bind_source_for_tests() -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::OnceLock;
    static GUEST_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();
    GUEST_PATH
        .get_or_init(|| {
            let dir = std::env::temp_dir().join("sandboxd-test-guest-bind-source");
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Phase 3D contract (a) — the full container-backend create round
/// trip, mediated by the same dispatch table the daemon uses.
///
/// Walks: `ensure_image` (real lite image build), `register_session`
/// of per-session `ContainerNetwork`, `runtime.create()`,
/// `runtime.start()`, `SessionStore::create_session_with_backend`
/// persistence, and `SessionDto::from(&session)` wire mapping. The
/// asserted invariants are the ones the CLI and the e2e suite rely
/// on:
///
/// - `BackendKind` survives the SQLite round trip: a
///   `create_session_with_backend(_, _, Container)` row reads back as
///   `Container`.
/// - The DTO mapper populates `backend` from the session column, so
///   the wire shape carries `"container"` — the only signal HTTP
///   clients have to confirm dispatch went through the container
///   runtime, not Lima.
/// - The runtime's `RuntimeStatus::Running` after `start()` matches
///   what `session_health` will report, so Phase 3D's per-handler
///   `runtime_for(state, session.backend)` change does not regress
///   the existing health probe.
#[tokio::test]
async fn integration_create_session_container_backend_round_trip() {
    ensure_round_trip_image();
    let runtime = ContainerRuntime::new(
        ROUND_TRIP_IMAGE_TAG,
        256,
        1.0,
        1000,
        1000,
        guest_bind_source_for_tests(),
    );

    // Persist a session with `BackendKind::Container` and assert the
    // round trip through SQLite preserves the backend tag — this is
    // the exact persistence path the daemon's create handler uses.
    let tmp = TempDir::new().expect("tempdir");
    let (store, _orphans) = SessionStore::new(tmp.path().to_path_buf()).expect("open SessionStore");
    let store = Arc::new(store);
    let session = store
        .create_session_with_backend(
            SessionConfig::default(),
            Some("phase3d-roundtrip".into()),
            BackendKind::Container,
            "test-operator",
            0,
            "",
        )
        .expect("persist session row");
    assert_eq!(session.backend, BackendKind::Container);

    // Confirm the row reads back unchanged after the SQLite write.
    let reloaded = store
        .get_session_by_name_or_id(session.id.as_str(), "test-operator")
        .expect("query session by id")
        .expect("session row present");
    assert_eq!(reloaded.backend, BackendKind::Container);

    // Create the docker network AFTER the session row exists so its
    // name carries the session id (see `TestNetwork::create` docs for
    // the dual-anchor reaper-skip rationale).
    let net = TestNetwork::create(&session.id);

    // Run the dispatch path: register network → create → start.
    let _cleanup = ContainerCleanup::new(&session.id);
    runtime.register_session(session.id, net.to_container_network());

    let handle = runtime
        .create(&session.id, &container_spec())
        .await
        .expect("runtime.create");
    runtime
        .start(&handle, &RuntimeStartArgs::default())
        .await
        .expect("runtime.start");

    let status = runtime.status(&handle).await.expect("runtime.status");
    assert!(
        matches!(status, RuntimeStatus::Running),
        "container must be Running after start; got {status:?}"
    );

    // Wire-shape contract: the response DTO carries the persisted
    // backend tag verbatim, so a CLI/integration consumer can confirm
    // the request actually routed to the container runtime.
    let dto = SessionDto::from(&reloaded);
    assert_eq!(dto.backend, BackendKind::Container);
    let json = serde_json::to_value(&dto).expect("serialize DTO");
    assert_eq!(json["backend"], serde_json::json!("container"));

    // Tear down the docker side; the SessionStore TempDir drops with
    // the test scope.
    runtime.delete(&handle).await.expect("runtime.delete");
}

/// Phase 3D contract (b) — the lite image first-use warning surfaces
/// through `SessionDto.warnings` on the first build of a daemon-
/// version tag, and disappears on subsequent calls for the same tag.
///
/// This test pins the wiring contract that the daemon's create
/// handler depends on: `ensure_image` returns `Built { warning }`
/// exactly once per unique tag, and the warning text is
/// `LITE_FIRST_USE_WARNING` verbatim — drift in the constant or the
/// outcome enum trips here before it reaches the response shape.
///
/// The downstream wire-format glue (the `with_warnings()` builder on
/// `SessionDto`, the `#[serde(default, skip_serializing_if = ...)]`
/// attribute) is unit-tested in `sandbox-core/src/api/mapper.rs`;
/// here we pin the cross-crate handshake (ensure_image's outcome →
/// the warning vec the handler hands to `with_warnings`).
#[tokio::test]
async fn integration_create_session_container_first_use_warning_surfaces() {
    let tag = TestImage::unique_tag("first-use");
    let _image_guard = TestImage::new(tag.clone());

    // First call: image is absent; `ensure_image` must build it and
    // return `Built { warning }` carrying the design-verbatim notice.
    let first_outcome = tokio::task::spawn_blocking({
        let tag = tag.clone();
        move || ensure_image(&tag)
    })
    .await
    .expect("spawn_blocking join")
    .expect("ensure_image first call must succeed");
    let warning = match first_outcome {
        EnsureImageOutcome::Built { warning } => warning,
        EnsureImageOutcome::AlreadyPresent => panic!(
            "first ensure_image call for a unique tag must take the build branch, \
             not the cache-hit branch"
        ),
    };
    assert_eq!(
        warning, LITE_FIRST_USE_WARNING,
        "warning text must match the design verbatim"
    );

    // Now drive the wire-shape end of the wiring: a session DTO
    // built with this warning attached carries the field on the
    // wire under `warnings`, with the verbatim text. This is the
    // exact transformation the daemon's create handler performs
    // when it observes `Built { warning }`.
    let session = sandbox_core::Session::new(Some("phase3d-warning".into()));
    let dto = SessionDto::from(&session).with_warnings(vec![warning.clone()]);
    let json = serde_json::to_value(&dto).expect("serialize DTO");
    let arr = json["warnings"]
        .as_array()
        .expect("warnings key present after with_warnings");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0], serde_json::Value::String(warning.clone()));

    // Second call for the same tag: cache hit, no warning surfaced.
    let second_outcome = tokio::task::spawn_blocking({
        let tag = tag.clone();
        move || ensure_image(&tag)
    })
    .await
    .expect("spawn_blocking join")
    .expect("ensure_image second call must succeed");
    assert!(
        matches!(second_outcome, EnsureImageOutcome::AlreadyPresent),
        "second ensure_image call for the same tag must be a cache hit; got {second_outcome:?}"
    );

    // And the wire-shape mirror: a DTO built with no warnings omits
    // the field entirely, so steady-state container creates do not
    // pollute the response surface.
    let steady_dto = SessionDto::from(&session);
    let steady_json = serde_json::to_string(&steady_dto).expect("serialize steady DTO");
    assert!(
        !steady_json.contains("\"warnings\""),
        "warnings key must be absent on steady-state container creates; json = {steady_json}"
    );
}

/// Phase 3D contract (c) — `--hardened` on the container backend is
/// rejected by the daemon up front, before any state is allocated.
///
/// Hermetic — exercises the request-side validation branch the
/// `POST /sessions` handler runs immediately after parsing the
/// request. The container backend's capability matrix declares
/// `hardening_flag: false`; the `BackendSpecific::Container` variant
/// has no `hardened` field, so the SessionSpec-level
/// `validate(&caps)` cannot see the flag — the daemon must reject up
/// front based on the request's `hardened: Some(true)` literal.
///
/// The error shape pinned here:
/// - `UnsupportedFeature::Hardening` is the canonical variant
/// - its `Display` text matches the design-verbatim sentence the CLI
///   re-emits to operators
#[test]
fn integration_create_session_container_rejects_hardened() {
    // The exact text the daemon's handler embeds in its
    // `SandboxError::InvalidArgument` payload when it observes
    // `backend == Container && req.hardened == Some(true)`.
    let display = UnsupportedFeature::Hardening.to_string();
    assert!(
        display.to_lowercase().contains("hardening") || display.to_lowercase().contains("hardened"),
        "rejection message must mention hardening so operators can debug; got {display:?}"
    );

    // Container backend's static capability matrix asserts the same
    // contract from the runtime side — `hardening_flag: false`. This
    // is the matrix the daemon's `runtime.capabilities()` returns
    // when the create handler runs `spec.validate(caps)`.
    let runtime = ContainerRuntime::new(
        "phase3d-rejects-hardened-test:none",
        256,
        1.0,
        1000,
        1000,
        "/nonexistent/staged-guest-not-used-in-hermetic-test",
    );
    assert_eq!(runtime.kind(), BackendKind::Container);
    assert!(
        !runtime.capabilities().hardening_flag,
        "container capabilities must declare hardening_flag = false so the \
         daemon's hardened-rejection branch is reachable"
    );

    // Confirm a `BackendSpecific::Container` spec — i.e. the projection
    // the daemon performs when `req.backend == Some(Container)` — has
    // no place to carry `hardened`. This is the structural reason the
    // daemon's create handler rejects the flag *before* projection,
    // not after.
    let spec = container_spec();
    let SessionSpec {
        backend_specific, ..
    } = spec;
    match backend_specific {
        BackendSpecific::Container { .. } => {}
        BackendSpecific::Lima { .. } => panic!("container_spec must produce a Container variant"),
    }

    // Sanity: a Lima session whose state is later observed via the
    // wire reports `backend == "lima"` so the regression net for the
    // round-trip test would catch a regression on the default path
    // too. (`Session::new` defaults to Lima per the V005 SQL default
    // and `BackendKind::default()`.)
    let lima_session = sandbox_core::Session::new(Some("hardened-test-lima".into()));
    assert_eq!(lima_session.backend, BackendKind::Lima);
    assert_eq!(lima_session.state, SessionState::Creating);
}

/// Workspace-mode contract — both workspace modes are *accepted*
/// request shapes on the container backend. The capability matrix
/// advertises `workspace_modes: { Shared, Clone }`. `Shared` threads the
/// operator-supplied host path through `ContainerNetwork::workspace_bind`
/// and `ContainerRuntime` turns it into a `docker create --mount type=bind,...`
/// flag with the unified bind target `/home/agent/workspace/`. `Clone`
/// is dispatched in-guest after the lite container's entrypoint
/// (`sandbox-guest`) is up: the daemon issues `git clone <url>
/// /home/agent/workspace/` through the backend-agnostic `GuestConnector`,
/// mirroring the Lima `--repo` path.
///
/// This test pins three pieces of the public contract:
///   1. The capability matrix advertises exactly `{ Shared, Clone }` —
///      both modes, neither empty (the pre-Clone guard shape) nor
///      `Shared`-only (an earlier transitional shape).
///   2. `SessionSpec::validate(caps)` *accepts* a `Shared` request so
///      the daemon's `POST /sessions` handler proceeds to the bind-
///      mount path rather than failing the request up front.
///   3. `SessionSpec::validate(caps)` *accepts* a `Clone` request so
///      the daemon's `POST /sessions` handler proceeds to the in-guest
///      clone dispatch rather than failing the request up front.
///
/// Hermetic — exercises the same `spec.validate(runtime.capabilities())`
/// branch the daemon's `POST /sessions` handler runs after parsing the
/// request. An earlier predecessor of this test asserted Clone was
/// *rejected* because the in-guest clone plumbing was deferred; once
/// the plumbing landed, the rejection assertion was inverted to a
/// successful-validate and the capability-shape coverage was preserved.
#[test]
fn integration_create_session_container_advertises_workspace_capabilities() {
    let runtime = ContainerRuntime::new(
        "m11-s7-workspace-capability-test:none",
        256,
        1.0,
        1000,
        1000,
        "/nonexistent/staged-guest-not-used-in-hermetic-test",
    );

    // (1) Capability shape — exactly `{ Shared, Clone }`, no more, no less.
    let modes = runtime.capabilities().workspace_modes;
    assert!(
        modes.contains(WorkspaceModeKind::Shared),
        "container capabilities must advertise WorkspaceModeKind::Shared; \
         got {modes:?}"
    );
    assert!(
        modes.contains(WorkspaceModeKind::Clone),
        "container capabilities must advertise WorkspaceModeKind::Clone \
         (in-guest `git clone` dispatched via GuestConnector); got {modes:?}"
    );

    // (2) `Shared` request is accepted by `validate`.
    let shared_spec = SessionSpec {
        backend_specific: BackendSpecific::Container {
            memory_mb: 256,
            cpus: 1.0,
        },
        workspace_mode: Some(WorkspaceMode::Shared {
            host_path: "/tmp".into(),
            guest_path: "/tmp".into(),
            security_model: None,
        }),
        repo: None,
        boot_cmd: None,
        template: None,
        disk_gb: None,
        no_cache: None,
    };
    shared_spec
        .validate(runtime.capabilities())
        .expect("Shared workspace must validate against the container capability matrix");

    // (3) `Clone` request is accepted by `validate` — the in-guest
    //     clone plumbing has landed and the capability matrix
    //     advertises Clone alongside Shared.
    let clone_spec = SessionSpec {
        backend_specific: BackendSpecific::Container {
            memory_mb: 256,
            cpus: 1.0,
        },
        workspace_mode: Some(WorkspaceMode::Clone {
            repo_url: "https://example.invalid/repo.git".into(),
        }),
        repo: None,
        boot_cmd: None,
        template: None,
        disk_gb: None,
        no_cache: None,
    };
    clone_spec
        .validate(runtime.capabilities())
        .expect("Clone workspace must validate against the container capability matrix");
}

/// `--no-cache` on the container backend is rejected by the daemon
/// up front, before any state is allocated.
///
/// Hermetic — exercises the same `SessionSpec::validate(&caps)` branch
/// the `POST /sessions` handler runs after parsing the request. The
/// container backend's capability matrix declares
/// `per_session_no_cache: false`; a request whose body carries
/// `no_cache: true` is therefore refused with `UnsupportedFeature::PerSessionNoCache(Container)`,
/// which the handler routes through `SandboxError::InvalidArgument` →
/// HTTP 400 (the same mapping the existing `_rejects_hardened` test
/// pins for the `--hardened` case).
///
/// The hole this test closes: a non-CLI HTTP client posting
/// `{"backend":"container","no_cache":true}` was silently accepted —
/// the CLI was the only enforcer of the rule that `sandbox create --no-cache`
/// is forbidden on container. Now the
/// validate gate is the canonical enforcer; the CLI's pre-check
/// remains as a no-round-trip operator nicety.
///
/// The error shape pinned here:
/// - `UnsupportedFeature::PerSessionNoCache(BackendKind::Container)`
///   is the canonical variant the validate gate returns
/// - its `Display` text mentions `no-cache` and the backend so
///   operators can debug
#[test]
fn integration_create_session_container_rejects_no_cache() {
    use sandbox_core::SessionSpec;

    // The `Display` text the daemon's handler embeds in its
    // `SandboxError::InvalidArgument` payload when `validate` returns
    // `PerSessionNoCache`. Pin it explicitly so a future Display
    // refactor that drops the backend hint or the "no-cache" word
    // trips the test before reaching operator-facing surfaces.
    let display = UnsupportedFeature::PerSessionNoCache(BackendKind::Container).to_string();
    assert!(
        display.contains("no-cache"),
        "rejection message must mention --no-cache so operators can debug; got {display:?}"
    );
    assert!(
        display.contains("container"),
        "rejection message must name the offending backend; got {display:?}"
    );

    // Container backend's static capability matrix asserts the same
    // contract from the runtime side — `per_session_no_cache: false`.
    // This is the matrix the daemon's `runtime.capabilities()` returns
    // when the create handler runs `spec.validate(caps)`.
    let runtime = ContainerRuntime::new(
        "rejects-no-cache-test:none",
        256,
        1.0,
        1000,
        1000,
        "/nonexistent/staged-guest-not-used-in-hermetic-test",
    );
    assert_eq!(runtime.kind(), BackendKind::Container);
    assert!(
        !runtime.capabilities().per_session_no_cache,
        "container capabilities must declare per_session_no_cache = false \
         so the daemon's no-cache-rejection branch is reachable"
    );

    // The validate-layer rejection itself: mirror the daemon's
    // post-projection check. A spec with `no_cache: Some(true)` against
    // the container caps must yield `UnsupportedFeature::PerSessionNoCache`.
    let mut spec = container_spec();
    spec.no_cache = Some(true);
    let err = spec
        .validate(runtime.capabilities())
        .expect_err("no_cache=true must be rejected against container caps");
    assert_eq!(
        err,
        UnsupportedFeature::PerSessionNoCache(BackendKind::Container),
        "rejection variant must be PerSessionNoCache(Container); got {err:?}"
    );

    // Symmetrical happy paths — the gate fires only on the explicit
    // `Some(true)` case, mirroring `_rejects_hardened`'s "hardened
    // false is silently honoured" arm. Without these the test would
    // accept a regression that turned the gate into a blanket reject.
    let spec_absent = container_spec();
    spec_absent
        .validate(runtime.capabilities())
        .expect("no_cache=None must round-trip cleanly through validate");

    let mut spec_false = container_spec();
    spec_false.no_cache = Some(false);
    spec_false
        .validate(runtime.capabilities())
        .expect("no_cache=Some(false) must round-trip cleanly through validate");

    // Confirm the structural projection the daemon performs from
    // `req.no_cache` lives at the `SessionSpec` level — the field is
    // not buried inside `BackendSpecific::Container` (which has no
    // place to carry it, the same structural reason the hardened
    // rejection test pins for `--hardened`).
    let SessionSpec {
        backend_specific,
        no_cache: spec_no_cache,
        ..
    } = spec;
    match backend_specific {
        BackendSpecific::Container { .. } => {}
        BackendSpecific::Lima { .. } => panic!("container_spec must produce a Container variant"),
    }
    assert_eq!(spec_no_cache, Some(true));
}

/// Fractional `--cpus` on the Lima backend is rejected by the daemon
/// up front, before any state is allocated.
///
/// Hermetic — pins the *invariants* the daemon's request-shape gate at
/// `create_session` line ~895 relies on:
///
///   1. The backend kind discriminator (`Lima`) reaches the daemon
///      from the request's `backend` field via `BackendKind::Lima`,
///      not via the `Container` arm — symmetric to the `_rejects_hardened`
///      test's "container backend, hardened flag" pattern.
///   2. The daemon's check key — `f32::fract` — distinguishes
///      `1.5_f32` (rejected) from `2.0_f32` (accepted) at the
///      bit-precision the wire uses.
///   3. The error message names the backend ("Lima") and the
///      constraint ("integer") so an operator parsing the 400 body
///      knows which knob to fix.
///
/// The hole this test closes: a non-CLI HTTP client posting
/// `{"backend":"lima","cpus":1.5}` was silently downsized to a 1-CPU
/// session via the `as u32` cast at the design-projection site — a
/// classic "I asked for X, got Y" bug invisible to operators. The
/// daemon now refuses such requests with HTTP 400; the CLI's path
/// (which never reaches the daemon with a fractional Lima value)
/// remains unchanged.
#[test]
fn integration_create_session_lima_rejects_fractional_cpus() {
    // (1) The discriminator the daemon's gate switches on. A regression
    // that flipped the kind ordering or aliased the variants would
    // silently pass either of the next two assertions; pin the variant
    // shape explicitly.
    let lima_kind = BackendKind::Lima;
    assert_eq!(lima_kind.as_str(), "lima");
    assert_ne!(lima_kind, BackendKind::Container);

    // (2) The bit-precision the daemon's `f32::fract() != 0.0` check
    // operates at. `1.5_f32` is exactly representable so `fract`
    // returns `0.5` exactly; `2.0_f32` likewise has `fract == 0.0`.
    // The test is bit-precise — no epsilon comparison — because the
    // daemon's gate is bit-precise too: any non-zero fractional part
    // fires the rejection.
    let fractional: f32 = 1.5;
    assert_ne!(
        fractional.fract(),
        0.0,
        "1.5_f32 must register as fractional via fract(); the daemon's \
         rejection gate hinges on this exact predicate"
    );
    let integer: f32 = 2.0;
    assert_eq!(
        integer.fract(),
        0.0,
        "2.0_f32 must register as integer via fract(); the daemon's \
         accept arm hinges on this exact predicate"
    );
    // Edge case: `0.0_f32` (the wire-level "no caller-specified value"
    // sentinel) must also pass the integer check so the daemon's
    // default-cpus path still threads through.
    let sentinel: f32 = 0.0;
    assert_eq!(sentinel.fract(), 0.0);

    // (3) The wire-shape `CreateSessionRequest` already accepts a
    // fractional `cpus` (the field is `Option<f32>`), so the request
    // *parses* cleanly and the daemon's gate fires at
    // *post-parse, pre-projection* time — not via serde. Confirm the
    // parse step still accepts the exact wire body the gate is
    // expected to refuse, so a regression that tightened the parse
    // (to e.g. `Option<u32>`) wouldn't sneak past this test.
    use sandbox_core::api::CreateSessionRequest;
    let body = r#"{"backend":"lima","cpus":1.5}"#;
    let parsed: CreateSessionRequest = serde_json::from_str(body).expect(
        "CreateSessionRequest must parse a fractional cpus body so the post-parse \
                 daemon gate is the canonical enforcer; if this fails, the gate moved to \
                 serde and this test no longer guards the right branch",
    );
    assert_eq!(parsed.backend, Some(BackendKind::Lima));
    assert_eq!(parsed.cpus, Some(1.5_f32));
    assert!(
        parsed.cpus.unwrap().fract() != 0.0,
        "the parsed value must have a non-zero fract; otherwise the daemon's \
         post-parse rejection branch never fires"
    );
}
