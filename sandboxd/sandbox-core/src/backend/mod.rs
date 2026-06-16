//! Backend abstraction for sandbox session runtimes.
//!
//! Two traits — [`SessionRuntime`] and [`GuestTransport`] — describe the
//! contract every backend (Lima and container) must satisfy. The
//! daemon dispatches by the persisted `sessions.backend` column
//! (see V005 migration) into a `HashMap<BackendKind, Arc<dyn SessionRuntime>>`
//! held on `AppState`.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::SandboxError;
use crate::session::{SessionConfig, SessionId};

pub mod capabilities;
pub mod container;
/// Rootless-Docker probe used by the container backend's
/// session-create path. Public so the daemon's create handler can
/// call it; structurally placed alongside [`container`] so Lima code
/// paths cannot reach it. See the module docs for the caching and
/// error-handling contract.
pub mod container_rootless_probe;
pub mod lima;
pub mod orphan_reaper;
pub mod spec;

pub use capabilities::{BackendKind, Capabilities, IsolationLevel, UnsupportedFeature};

/// Wire-shape entry returned by the daemon's `GET /backends` endpoint.
///
/// One element per backend the daemon has registered in its dispatch
/// table, paired with the static [`Capabilities`] value the runtime
/// reports. Defined in `sandbox-core` (rather than the daemon binary)
/// because the CLI deserializes this same type when fetching the
/// capability matrix to drive client-side validation and the
/// `sandbox inspect -v` capability table.
///
/// The wire format is fixed at `[{"kind": "...", "capabilities": {...}}]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendInfo {
    pub kind: BackendKind,
    pub capabilities: Capabilities,
}
pub use container::{
    ContainerNetwork, ContainerRuntime, ContainerTransport, DEFAULT_LITE_IMAGE_TAG,
    EnsureImageOutcome, LITE_FIRST_USE_WARNING, LITE_IMAGE_REPOSITORY, LITE_TAG_OVERRIDE_ENV,
    SANDBOX_CA_CONTAINER_PATH, WorkspaceBind, compute_default_resource_limits, ensure_image,
    home_volume_name, lite_image_tag_for_daemon_probe, lite_image_tag_for_version,
    map_container_uid_gid, rebuild_lite_image, stage_ssh_credentials,
};
pub use lima::{LimaRuntime, LimaTransport};
pub use orphan_reaper::{CliDockerOps, DockerOps, ReaperReport, reap_orphans};
pub use spec::{BackendSpecific, SessionSpec};

/// Backend-specific arguments to [`SessionRuntime::start`].
///
/// The original `start(handle)` boot signature was deliberately
/// minimal — the daemon-side networking bringup (docker bridge name,
/// deterministic VM MAC) and the persisted [`SessionConfig`] all
/// stayed in `AppState`, with the trait implementation falling back
/// to [`SessionConfig::default()`]. The current surface widens that
/// so the daemon can plumb the real per-session values down to the
/// runtime without leaking Lima-specific call sites into handlers.
///
/// Today the struct carries only Lima-shaped fields; the container
/// backend will land its own `container_*` siblings here, keyed by
/// which backend the [`SessionRuntime`] dispatched to. New fields
/// land as `Option<T>` (and via `#[serde(default)]` if the type ever
/// becomes serialisable) so the wire shape and forward-compat
/// guarantees of CLAUDE.md "On-disk compatibility" stay applicable
/// when persistence comes for these values.
#[derive(Debug, Clone, Default)]
pub struct RuntimeStartArgs {
    /// Lima: docker bridge name attached as the VM's `eth1` interface
    /// (TAP, via `qemu-bridge-helper`). When `None`, the runtime starts
    /// without a bridge NIC — same fallback behavior the daemon used to
    /// log via `warn!` on `ensure_network` failure.
    pub lima_bridge: Option<String>,
    /// Lima: deterministic MAC address for the bridge NIC, derived from
    /// the session id (`mac_from_session_id`). Mirrors `lima_bridge` —
    /// `None` means start without bridge networking.
    pub lima_mac: Option<String>,
    /// Lima: the persisted [`SessionConfig`] for this session. Phase 1B
    /// fell back to `SessionConfig::default()` inside `LimaRuntime::start`
    /// because the trait did not yet carry the config; 1C plumbs the
    /// real value through so resource fields (`cpus`, `memory_mb`,
    /// `disk_gb`, `hardened`) reach `LimaManager::start_vm`. When `None`,
    /// the runtime keeps the Phase 1B default-config behavior with a
    /// `warn!` so test paths that omit the config remain explicit
    /// rather than silent.
    pub lima_config: Option<SessionConfig>,
    /// Operator identity to pass to `sandbox-route-helper` via `--for-user`.
    ///
    /// `Some(<operator_name>)` for all backends when the daemon has resolved
    /// the connecting client's identity via `SO_PEERCRED`. The value is
    /// **only consumed** by `ContainerRuntime::start` today —
    /// `LimaRuntime::start` does not invoke the route-helper and ignores
    /// this field. It is threaded through `RuntimeStartArgs` on the Lima
    /// call sites for forward-compatibility: if Lima networking ever
    /// routes through `sandbox-route-helper` in a future spec, the caller
    /// identity is already present without an API break. `None` means no
    /// operator identity is available (test paths that omit the
    /// extractor); the container runtime errors if `None` when a helper
    /// path is configured (programming error — a handler reached
    /// `runtime.start` without the operator extension).
    ///
    /// The route helper enforces pair-membership: BOTH the caller's uid
    /// (the daemon, via `getuid`) AND the `--for-user` name must appear
    /// in the chosen pool's `allow_users`. The daemon is **the operator
    /// acting on behalf of** — the helper independently verifies that
    /// assertion against `users.conf`, so a compromised daemon cannot
    /// invent operators not already paired with the daemon's runtime uid.
    pub for_user: Option<String>,
    /// Operator's `(uid, gid)` pair captured from the connecting socket's
    /// `SO_PEERCRED`, threaded into the runtime so it can align the
    /// in-VM/in-container effective identity with the operator on the
    /// host.
    ///
    /// `Some((uid, gid))` is set by the daemon's session-create handler
    /// for every backend whenever the operator identity has been
    /// resolved (post-V008). The container runtime uses it for
    /// `docker create --user <uid>:<gid>`; the Lima runtime uses it to
    /// interpolate the operator's uid/gid into the per-session cloud-init
    /// `usermod` provision step. All Lima limactl operations are dispatched
    /// through the per-operator `LimaManager` (keyed by uid), so uid
    /// alignment for `limactl start` is implicit.
    ///
    /// `None` means the operator identity is unavailable — either a
    /// pre-V008 record where the daemon didn't yet capture peercred, or
    /// a fixture-test row that omits it.
    pub operator_identity: Option<(u32, u32)>,
    /// Lima: allow the management slirp NIC to stay unrestricted for this
    /// start. Used only for first-boot `limactl create` sessions whose
    /// cloud-init provisioning still needs guest-initiated network access
    /// before the sandbox gateway is configured. Callers must restart the VM
    /// without this flag before exposing the session as ready.
    pub lima_unrestricted_slirp_for_provisioning: bool,
}

/// Opaque per-backend handle to a created session, returned by
/// [`SessionRuntime::create`] and re-used by the lifecycle methods.
///
/// Both backends derive their handle from the session id by
/// convention: the Lima instance is named `sandbox-{session_id}`, and
/// the container is named the same. Daemon code never inspects the
/// inner string — each backend's impl dereferences the handle through
/// its own discovery primitive (`limactl list` / `docker inspect`).
///
/// This is the structural convention shared by both backends.
/// `RuntimeHandle` is **not** persisted — the daemon rehydrates it on
/// startup from the session id alone.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuntimeHandle {
    name: String,
}

impl RuntimeHandle {
    /// Construct a runtime handle from the structural session-id
    /// naming convention `sandbox-{session_id}`. Callers in Phase 1B+
    /// use this to rehydrate a handle on daemon startup without
    /// touching backend-specific state.
    pub fn from_session_id(session_id: &SessionId) -> Self {
        Self {
            name: format!("sandbox-{session_id}"),
        }
    }

    /// Construct a runtime handle from an explicit name. Used by
    /// backend impls that recover a handle from their own discovery
    /// surface (`limactl list`, `docker inspect`) when the persisted
    /// session id is the source of truth but the resolved name has
    /// already been re-derived.
    pub fn from_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Borrow the inner backend-specific name. Used only by the
    /// backend impls themselves; callers should treat the value as
    /// opaque.
    pub fn as_str(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Display for RuntimeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

/// State of a backend session, as observed by [`SessionRuntime::status`].
///
/// Mirrors [`crate::lima::VmStatus`] so the existing call sites can map
/// over without semantic loss; `Unknown` carries the backend-specific
/// status string for diagnostic display.
///
/// The runtime impls (Phase
/// 1B+) are responsible for normalising backend output into one of
/// these variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeStatus {
    /// The session is being created (image pull, VM provision, etc.).
    Creating,
    /// The session is running.
    Running,
    /// The session is stopped but not deleted.
    Stopped,
    /// The session terminated with an error.
    Error,
    /// Any backend-specific status not handled by the variants above.
    Unknown(String),
}

/// Convenience trait combining [`AsyncRead`] and [`AsyncWrite`] for
/// the bidirectional stream returned by [`GuestTransport::connect`].
///
/// Defined here so trait objects (`Box<dyn AsyncReadWrite + Send +
/// Unpin>`) can be returned without leaking the auto-impl into every
/// backend module.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}

/// Bidirectional transport to the in-session `sandbox-guest` agent.
///
/// The agent listens on TCP `127.0.0.1:5123` inside every session,
/// regardless of backend. Lima's transport wraps `limactl shell <vm>
/// -- socat - TCP:127.0.0.1:5123`; the container backend wraps
/// `docker exec <ctr> socat - TCP:127.0.0.1:5123`. The payload is
/// sandboxd's structured JSON guest protocol (`ping`, `exec`,
/// `file upload`, `status`).
#[async_trait]
pub trait GuestTransport: Send + Sync {
    /// Open a fresh connection to the in-session agent. Each call
    /// returns an independent stream; backends are responsible for
    /// any pooling/serialisation if their underlying transport
    /// requires it.
    async fn connect(&self) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>, SandboxError>;
}

/// A backend that creates and manages sandbox sessions.
///
/// One trait object lives per [`BackendKind`]; the daemon dispatches
/// by the session row's `backend` column (V005) into a registry held
/// on `AppState`. Implementations are stateless over [`RuntimeHandle`]
/// — a single instance per kind is shared across all sessions of that
/// kind.
#[async_trait]
pub trait SessionRuntime: Send + Sync {
    /// Which backend this runtime represents. Used by the daemon's
    /// dispatch table and surfaced on `GET /backends`.
    fn kind(&self) -> BackendKind;

    /// Static capability descriptor for this backend; consulted by
    /// [`SessionSpec::validate`] and surfaced on `GET /backends`.
    fn capabilities(&self) -> &Capabilities;

    /// Create a new session matching `spec` and return its opaque
    /// handle. Implementations are responsible for any image
    /// preparation (Lima golden image, container image build), VM /
    /// container provisioning, and per-session artefact staging.
    /// Networking, gateway, and policy work happen outside the
    /// runtime.
    ///
    /// The session id is assigned by the daemon before dispatch and passed
    /// explicitly here, mirroring `LimaManager::create_vm` and the
    /// deterministic-handle convention: handles are not persisted by the
    /// backend.
    async fn create(
        &self,
        session_id: &SessionId,
        spec: &SessionSpec,
    ) -> Result<RuntimeHandle, SandboxError>;

    /// Boot a previously-created session.
    ///
    /// `args` carries backend-specific knobs the runtime cannot derive
    /// from the handle alone — for Lima today, the docker bridge name,
    /// VM MAC, and the persisted [`SessionConfig`]. See
    /// [`RuntimeStartArgs`] for the field-by-field contract.
    async fn start(
        &self,
        handle: &RuntimeHandle,
        args: &RuntimeStartArgs,
    ) -> Result<(), SandboxError>;

    /// Gracefully stop a running session. Idempotent: stopping a
    /// stopped session must not error.
    ///
    /// `operator_uid` is the numeric uid of the operator that owns the
    /// session. The Lima runtime dispatches through `sandbox-lima-helper
    /// stop --op-uid`; the container runtime accepts and ignores it.
    async fn stop(&self, handle: &RuntimeHandle, operator_uid: u32) -> Result<(), SandboxError>;

    /// Delete a stopped session and its artefacts. Idempotent.
    ///
    /// `operator_uid` is the numeric uid of the operator that owns the
    /// session. The Lima runtime dispatches through `sandbox-lima-helper
    /// delete --op-uid`; the container runtime accepts and ignores it.
    async fn delete(&self, handle: &RuntimeHandle, operator_uid: u32) -> Result<(), SandboxError>;

    /// Query the current state of a session.
    ///
    /// `operator_uid` is the numeric uid of the operator that owns the
    /// session. The Lima runtime dispatches through `sandbox-lima-helper
    /// list-json --op-uid`; the container runtime accepts and ignores it.
    async fn status(
        &self,
        handle: &RuntimeHandle,
        operator_uid: u32,
    ) -> Result<RuntimeStatus, SandboxError>;

    /// Return a guest-agent transport bound to this session's
    /// handle. The returned transport is cheap to clone and is
    /// expected to be reusable across many `connect()` calls.
    ///
    /// `operator_uid` is the numeric uid of the operator that owns the session.
    /// The Lima runtime uses it to pivot to the operator's uid via
    /// `sandbox-lima-helper guest-socat`; the container runtime accepts
    /// and ignores it (Docker's `--user` mediation handles cross-user
    /// isolation there).
    fn guest_transport(&self, handle: &RuntimeHandle, operator_uid: u32)
    -> Arc<dyn GuestTransport>;

    /// Push the daemon's embedded `sandbox-guest` binary into the
    /// session addressed by `handle` so that the next
    /// `runtime.start` exec picks up the new binary.
    ///
    /// `operator_uid` is the numeric uid of the operator that owns the
    /// session. The Lima runtime dispatches through `sandbox-lima-helper`
    /// (`start` → `install-guest-agent` → `stop`); the container runtime
    /// accepts and ignores it (Docker handles cross-user isolation).
    ///
    /// Implementations are responsible for the order of operations
    /// within their own substrate (start the runtime if it was stopped,
    /// push the binary, restart the guest service, return the runtime
    /// to its previous state if it wasn't already started for this
    /// call) and for atomicity within that substrate. The daemon
    /// orchestrator (per-caller isolation) only resumes
    /// the normal start path after `Ok(())`.
    ///
    /// Idempotent — repeated invocations of this method on the same
    /// session must observe the same outcome as a single invocation,
    /// so crash-recovery flows can re-run refresh without harm.
    async fn refresh_guest_binary(
        &self,
        handle: &RuntimeHandle,
        operator_uid: u32,
    ) -> Result<(), SandboxError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `RuntimeHandle` derived from a session id matches the
    /// `sandbox-{session_id}` convention shared by both backends.
    #[test]
    fn runtime_handle_from_session_id() {
        let sid = SessionId::parse("0123456789ab").unwrap();
        let handle = RuntimeHandle::from_session_id(&sid);
        assert_eq!(handle.as_str(), "sandbox-0123456789ab");
        assert_eq!(handle.to_string(), "sandbox-0123456789ab");
    }

    #[test]
    fn runtime_handle_from_name() {
        let handle = RuntimeHandle::from_name("sandbox-deadbeef0000");
        assert_eq!(handle.as_str(), "sandbox-deadbeef0000");
    }

    /// `RuntimeStartArgs::default()` zero-fills every field — every
    /// runtime impl must tolerate `None` on all knobs. The Phase 1C
    /// `LimaRuntime::start` falls back to `SessionConfig::default()`
    /// when `lima_config` is `None` and starts without a bridge NIC
    /// when both `lima_bridge` and `lima_mac` are `None`; this test
    /// pins the Default shape so that contract stays visible.
    #[test]
    fn runtime_start_args_default_is_all_none() {
        let args = RuntimeStartArgs::default();
        assert!(args.lima_bridge.is_none());
        assert!(args.lima_mac.is_none());
        assert!(args.lima_config.is_none());
        assert!(args.for_user.is_none());
        assert!(
            !args.lima_unrestricted_slirp_for_provisioning,
            "lima_unrestricted_slirp_for_provisioning must default to false — \
             sessions must never start with slirp unrestricted"
        );
    }

    /// `RuntimeStartArgs` is `Clone` so handlers can capture it before
    /// moving into a `tokio::spawn`/`spawn_blocking` task; pinned here
    /// because adding a non-`Clone` field later would silently break
    /// every call site that captures the args by value.
    #[test]
    fn runtime_start_args_is_clone() {
        fn _assert_clone<T: Clone>() {}
        _assert_clone::<RuntimeStartArgs>();
    }

    // exit_code_success_only_for_zero test removed — ExitCode removed with
    // exec_interactive.

    /// `dyn SessionRuntime` and `dyn GuestTransport` are object-safe
    /// so the daemon can hold them as trait objects in `AppState`.
    /// This is a compile-only check; if either trait stops being
    /// object-safe, this test fails to build.
    #[test]
    fn traits_are_object_safe() {
        fn _assert_object_safe(_runtime: &dyn SessionRuntime, _transport: &dyn GuestTransport) {}
    }

    /// `BackendInfo` serializes to the `{"kind": "...", "capabilities": {...}}`
    /// shape mandated by the design for `GET /backends`. Pinned here so a
    /// silent rename of either field (or a stray `#[serde(rename)]`)
    /// breaks compile-time rather than reaching CLI consumers.
    #[test]
    fn backend_info_serializes_to_spec_wire_shape() {
        let info = BackendInfo {
            kind: BackendKind::Lima,
            capabilities: Capabilities::for_lima(),
        };
        let value = serde_json::to_value(&info).expect("serialize");
        assert_eq!(value["kind"], serde_json::json!("lima"));
        assert!(value["capabilities"].is_object(), "capabilities object");
        assert_eq!(value["capabilities"]["kind"], serde_json::json!("lima"));
        assert_eq!(value["capabilities"]["isolation"], serde_json::json!("vm"));
    }
}
