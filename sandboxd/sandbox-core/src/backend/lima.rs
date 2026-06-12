//! Lima/QEMU backend implementation of [`super::SessionRuntime`] and
//! [`super::GuestTransport`].
//!
//! Holds a [`LimaManagerRegistry`] that vends per-operator
//! [`LimaManager`] instances on demand. Every limactl operation is
//! dispatched through `sandbox-lima-helper` pivoted to the operator's
//! uid; the daemon never invokes `limactl` directly.
//!
//! - [`LimaRuntime::create`] dispatches to `LimaManager::create_vm`
//!   (or `create_vm_with_custom_template` when the design carries a
//!   template).
//! - [`LimaRuntime::start`] consumes [`RuntimeStartArgs`] for
//!   docker bridge / MAC / `SessionConfig` populated by the daemon
//!   from `NetworkInfo`.
//! - [`LimaRuntime::stop`] / `delete` / `status` carry `operator_uid`
//!   so the right per-operator manager is selected from the registry.

use std::process::Stdio;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::Command;
use tracing::debug;

use crate::backend::capabilities::{BackendKind, Capabilities};
use crate::backend::spec::{BackendSpecific, SessionSpec};
use crate::backend::{
    AsyncReadWrite, GuestTransport, RuntimeHandle, RuntimeStartArgs, RuntimeStatus, SessionRuntime,
};
use crate::error::SandboxError;
use crate::lima::{self, LimaManager, LimaManagerRegistry, VmStatus};
use crate::session::{SessionConfig, SessionId};

// ---------------------------------------------------------------------------
// Timeout constants for refresh_lima_guest_binary_via_helper
// ---------------------------------------------------------------------------

/// Wall-clock budget for `limactl start` during a guest-binary refresh.
const REFRESH_START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(330);
/// Wall-clock budget for `install-guest-agent` (6 steps + 4 probes).
const REFRESH_INSTALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(360);
/// Wall-clock budget for `limactl stop` after a guest-binary refresh.
const REFRESH_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

// ---------------------------------------------------------------------------
// VmStatus -> RuntimeStatus
// ---------------------------------------------------------------------------

impl From<VmStatus> for RuntimeStatus {
    /// Map [`VmStatus`] (Lima-specific) onto [`RuntimeStatus`] (the
    /// backend-agnostic shape returned by [`SessionRuntime::status`]).
    ///
    /// `Running` and `Stopped` map straight through; everything Lima
    /// reports as `Unknown(s)` is forwarded with the original status
    /// string preserved for diagnostic display. Lima today does not
    /// surface explicit `Creating` / `Error` states — those variants
    /// exist on `RuntimeStatus` for the container backend and are
    /// populated by it directly.
    fn from(status: VmStatus) -> Self {
        match status {
            VmStatus::Running => RuntimeStatus::Running,
            VmStatus::Stopped => RuntimeStatus::Stopped,
            VmStatus::Unknown(s) => RuntimeStatus::Unknown(s),
        }
    }
}

// ---------------------------------------------------------------------------
// LimaRuntime
// ---------------------------------------------------------------------------

/// Lima/QEMU backend runtime.
///
/// One instance is shared across every Lima-backed session — the trait
/// is stateless over [`RuntimeHandle`] (see the trait doc on
/// [`SessionRuntime`]). Holds a [`LimaManagerRegistry`] that vends
/// per-operator [`LimaManager`] instances on demand; every limactl
/// operation is dispatched through `sandbox-lima-helper` pivoted to the
/// operator's uid. The daemon never invokes `limactl` directly.
pub struct LimaRuntime {
    registry: Arc<LimaManagerRegistry>,
    capabilities: Capabilities,
}

impl LimaRuntime {
    /// Construct a [`LimaRuntime`] backed by the given registry.
    /// Returns an `Arc` so the daemon can drop it into
    /// `AppState.runtimes` without an extra allocation at dispatch time.
    ///
    /// `registry` holds per-operator [`LimaManager`] instances; every
    /// session-context limactl call obtains the operator's manager from
    /// the registry and dispatches through `sandbox-lima-helper`.
    pub fn new(registry: Arc<LimaManagerRegistry>) -> Arc<Self> {
        Arc::new(Self {
            registry,
            capabilities: Capabilities::for_lima(),
        })
    }

    /// Access the per-operator manager for Lima-specific operations
    /// not on the trait surface — base-image build, template
    /// generation, base-image hash check, etc.
    ///
    /// Returns an error if per-operator LIMA_HOME provisioning fails
    /// on first use (e.g. `setfacl` absent or state-root unwritable).
    pub fn manager_for(&self, op_uid: u32) -> Result<Arc<LimaManager>, SandboxError> {
        self.registry.get_or_create(op_uid)
    }

    /// Access the registry directly. Used by `reconcile` and startup
    /// orphan scan to iterate per-operator managers.
    pub fn registry(&self) -> &Arc<LimaManagerRegistry> {
        &self.registry
    }

    /// Convert a [`SessionSpec`] into the resource-shaped
    /// [`SessionConfig`] that `LimaManager` consumes.
    ///
    /// Returns an error if the spec targets a non-Lima backend. The
    /// daemon is expected to have already validated `spec.backend() ==
    /// BackendKind::Lima` before dispatching to this runtime; this
    /// guard is defense in depth.
    fn spec_to_config(spec: &SessionSpec) -> Result<SessionConfig, SandboxError> {
        match &spec.backend_specific {
            BackendSpecific::Lima {
                hardened,
                memory_mb,
                cpus,
            } => Ok(SessionConfig {
                cpus: *cpus,
                memory_mb: *memory_mb,
                // `disk_gb` is carried at the SessionSpec level (see
                // `backend::spec::SessionSpec`); fall back to SessionConfig::default
                // if the request did not specify a size.
                disk_gb: spec
                    .disk_gb
                    .unwrap_or_else(|| SessionConfig::default().disk_gb),
                workspace_mode: spec.workspace_mode.clone(),
                hardened: *hardened,
                repo: spec.repo.clone(),
                boot_cmd: spec.boot_cmd.clone(),
                template: spec.template.clone(),
                // Lima's `BackendSpecific::Lima` carries integer `cpus`
                // (not the decimal form). `cpus_decimal` only applies to
                // container sessions; `None` keeps the persisted shape
                // consistent with the historical Lima record.
                cpus_decimal: None,
                // Rootless-Docker probe is gated to the container
                // backend. Lima sessions
                // never construct this state — the `None` keeps the
                // persisted shape consistent with Lima records that
                // predate the probe.
                rootless_docker: None,
            }),
            BackendSpecific::Container { .. } => Err(SandboxError::InvalidArgument(format!(
                "LimaRuntime received a container-shaped SessionSpec (got backend={})",
                spec.backend()
            ))),
        }
    }

    /// Resolve a [`RuntimeHandle`] back into the underlying
    /// [`SessionId`] by stripping the canonical `sandbox-` prefix.
    ///
    /// Returns an error if the handle does not match the convention —
    /// any caller hitting this is using a non-Lima handle against the
    /// Lima runtime, which is a daemon-level dispatch bug.
    fn session_id_from_handle(handle: &RuntimeHandle) -> Result<SessionId, SandboxError> {
        lima::parse_session_id_from_name(handle.as_str()).ok_or_else(|| {
            SandboxError::InvalidArgument(format!(
                "LimaRuntime received a non-Lima runtime handle: {}",
                handle.as_str()
            ))
        })
    }
}

#[async_trait]
impl SessionRuntime for LimaRuntime {
    fn kind(&self) -> BackendKind {
        BackendKind::Lima
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// Create the inert VM entity for `spec`.
    ///
    /// Writes the per-session Lima template and invokes
    /// `sandbox-lima-helper create` to run `limactl create` as the
    /// operator uid. The VM is **not** booted and the guest agent is
    /// **not** installed — those steps happen in `AppState`.
    ///
    /// When [`SessionSpec::template`] is `Some`, delegates to
    /// [`LimaManager::create_vm_with_custom_template`]; otherwise
    /// generates the template via [`LimaManager::create_vm`].
    async fn create(
        &self,
        session_id: &SessionId,
        spec: &SessionSpec,
    ) -> Result<RuntimeHandle, SandboxError> {
        let config = Self::spec_to_config(spec)?;
        let op_uid = spec.operator_identity.map(|(u, _)| u).ok_or_else(|| {
            SandboxError::Internal(
                "LimaRuntime::create called without operator_identity; \
                 post-V009 sessions must carry operator_uid"
                    .into(),
            )
        })?;
        let manager = self.registry.get_or_create(op_uid)?;
        let session_id_owned = *session_id;
        let template = spec.template.clone();
        let operator_identity = spec.operator_identity;
        tokio::task::spawn_blocking(move || {
            if let Some(template_path) = &template {
                manager.create_vm_with_custom_template(
                    &session_id_owned,
                    std::path::Path::new(template_path),
                )
            } else {
                manager.create_vm(&session_id_owned, &config, operator_identity)
            }
        })
        .await
        .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))??;

        Ok(RuntimeHandle::from_session_id(session_id))
    }

    /// Boot the VM with the bridge / MAC / config carried by `args`.
    ///
    /// Dispatches through `sandbox-lima-helper start` with all QEMU
    /// resource flags as typed arguments. The per-operator `LimaManager`
    /// is looked up from the registry using `args.operator_identity`.
    async fn start(
        &self,
        handle: &RuntimeHandle,
        args: &RuntimeStartArgs,
    ) -> Result<(), SandboxError> {
        let session_id = Self::session_id_from_handle(handle)?;
        let op_uid = args.operator_identity.map(|(u, _)| u).ok_or_else(|| {
            SandboxError::Internal(
                "LimaRuntime::start called without operator_identity; \
                 post-V009 sessions must carry operator_uid"
                    .into(),
            )
        })?;
        let manager = self.registry.get_or_create(op_uid)?;
        let bridge = args.lima_bridge.clone();
        let mac = args.lima_mac.clone();
        let config = match &args.lima_config {
            Some(cfg) => cfg.clone(),
            None => {
                tracing::warn!(
                    handle = %handle,
                    "LimaRuntime::start called without lima_config; \
                     falling back to SessionConfig::default()"
                );
                SessionConfig::default()
            }
        };

        tokio::task::spawn_blocking(move || {
            manager.start_vm(&session_id, &config, bridge.as_deref(), mac.as_deref())
        })
        .await
        .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))??;
        Ok(())
    }

    async fn stop(&self, handle: &RuntimeHandle, operator_uid: u32) -> Result<(), SandboxError> {
        let session_id = Self::session_id_from_handle(handle)?;
        let manager = self.registry.get_or_create(operator_uid)?;

        tokio::task::spawn_blocking(move || manager.stop_vm(&session_id))
            .await
            .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))??;
        Ok(())
    }

    async fn delete(&self, handle: &RuntimeHandle, operator_uid: u32) -> Result<(), SandboxError> {
        let session_id = Self::session_id_from_handle(handle)?;
        let manager = self.registry.get_or_create(operator_uid)?;

        tokio::task::spawn_blocking(move || manager.delete_vm(&session_id))
            .await
            .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))??;
        Ok(())
    }

    async fn status(
        &self,
        handle: &RuntimeHandle,
        operator_uid: u32,
    ) -> Result<RuntimeStatus, SandboxError> {
        let session_id = Self::session_id_from_handle(handle)?;
        let manager = self.registry.get_or_create(operator_uid)?;

        let vm_status = tokio::task::spawn_blocking(move || manager.vm_status(&session_id))
            .await
            .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))??;
        Ok(vm_status.into())
    }

    fn guest_transport(
        &self,
        handle: &RuntimeHandle,
        operator_uid: u32,
    ) -> Arc<dyn GuestTransport> {
        // Resolving the session id can fail for malformed handles, but
        // `guest_transport` is non-fallible by trait contract. We
        // construct the transport with whichever name the handle
        // carries — `LimaTransport::connect` will surface the failure
        // when the helper rejects the unknown VM name.
        Arc::new(LimaTransport {
            manager: self.registry.get_or_create(operator_uid),
            vm_name: handle.as_str().to_string(),
            operator_uid,
        })
    }

    /// Refresh the guest binary inside a Lima VM by routing through
    /// `sandbox-lima-helper`.
    ///
    /// Composed from existing helper subcommands:
    ///
    /// 1. `helper start --op-uid N --vm V ...` — ensure the VM is running
    ///    (idempotent: no-op on a running VM, boots a stopped one). The
    ///    qemu-wrapper, hardened flag, memory/cpu, and timeout are all required
    ///    by the helper; they are sourced from the session config stored on the
    ///    manager. Since refresh happens before `runtime.start` re-runs with
    ///    the real config, we use the manager's per-operator LIMA_HOME and the
    ///    defaults (hardened=1, 4096 MiB, 4 CPUs) to boot the VM.
    /// 2. `helper install-guest-agent --op-uid N --vm V` — copy, install, and
    ///    restart the guest-agent service (the subcommand already encapsulates
    ///    copy → mv → chmod → systemd unit write → daemon-reload → enable
    ///    --now, all idempotent). The tool probes at the end are a no-op on a
    ///    correctly provisioned base image.
    /// 3. `helper stop --op-uid N --vm V` — return the VM to Stopped baseline
    ///    so the orchestrator's subsequent `runtime.start` controls the
    ///    lifecycle cleanly and `Session.state` stays in lockstep.
    async fn refresh_guest_binary(
        &self,
        handle: &RuntimeHandle,
        operator_uid: u32,
    ) -> Result<(), SandboxError> {
        let vm_name = handle.as_str().to_string();
        let manager = self.registry.get_or_create(operator_uid)?;

        tokio::task::spawn_blocking(move || {
            refresh_lima_guest_binary_via_helper(&manager, &vm_name)
        })
        .await
        .map_err(|e| {
            SandboxError::Internal(format!(
                "spawn_blocking join failed during Lima guest refresh: {e}"
            ))
        })?
    }
}

/// Synchronous body of [`LimaRuntime::refresh_guest_binary`]. Lives as
/// a free function so the async wrapper can hand it to
/// `tokio::task::spawn_blocking` without capturing the trait's `&self`
/// across the boundary.
///
/// Composes `sandbox-lima-helper` subcommands:
///   1. `start` — ensure the VM is running (idempotent).
///   2. `install-guest-agent` — copy + install + restart the agent.
///   3. `stop` — return VM to Stopped baseline.
///
/// This eliminates every direct `limactl` invocation from this path.
fn refresh_lima_guest_binary_via_helper(
    manager: &LimaManager,
    vm_name: &str,
) -> Result<(), SandboxError> {
    // `start` requires qemu-wrapper, hardened, memory-mb, cpus,
    // start-timeout-s. For the refresh path we use conservative defaults:
    // hardened=1, 4096 MiB, 4 CPUs, 300s Lima-internal SSH wait. The
    // real per-session config is applied on the subsequent `runtime.start`
    // by the orchestrator; the refresh boot is just to reach Running.
    let qemu_wrapper = manager.ensure_qemu_wrapper_for_test()?;
    let qemu_wrapper_str = qemu_wrapper.to_string_lossy().to_string();

    tracing::debug!(vm = %vm_name, "refresh_guest_binary: ensuring VM running via helper");
    let output = manager.run_helper(
        "start",
        &[
            "--vm",
            vm_name,
            "--qemu-wrapper",
            &qemu_wrapper_str,
            "--hardened",
            "1",
            "--memory-mb",
            "4096",
            "--cpus",
            "4",
            "--start-timeout-s",
            "300",
        ],
        REFRESH_START_TIMEOUT,
        "sandbox-lima-helper start (guest refresh)",
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Lima(format!(
            "refresh: failed to start VM {vm_name}: {stderr}"
        )));
    }

    tracing::debug!(vm = %vm_name, "refresh_guest_binary: running install-guest-agent via helper");
    let output = manager.run_helper(
        "install-guest-agent",
        &["--vm", vm_name],
        REFRESH_INSTALL_TIMEOUT,
        "sandbox-lima-helper install-guest-agent (guest refresh)",
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Lima(format!(
            "refresh: install-guest-agent failed for {vm_name}: {stderr}"
        )));
    }

    tracing::debug!(vm = %vm_name, "refresh_guest_binary: stopping VM via helper");
    let output = manager.run_helper(
        "stop",
        &["--vm", vm_name],
        REFRESH_STOP_TIMEOUT,
        "sandbox-lima-helper stop (guest refresh)",
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Lima(format!(
            "refresh: failed to stop VM {vm_name} after refresh: {stderr}"
        )));
    }

    tracing::info!(vm = %vm_name, "guest binary refreshed via helper");
    Ok(())
}

// ---------------------------------------------------------------------------
// LimaTransport
// ---------------------------------------------------------------------------

/// [`GuestTransport`] over `sandbox-lima-helper guest-socat --op-uid
/// <uid> --vm <vm>`, which exec's `limactl shell <vm> -- socat -
/// TCP:127.0.0.1:5123` as the operator uid. Each [`Self::connect`] call
/// spawns a fresh helper child whose stdio is wired to the in-VM TCP
/// socket the guest agent listens on; the returned bidirectional stream
/// owns the child handle and tears it down on drop (`kill_on_drop(true)`).
///
/// # Async-I/O carve-out
///
/// This is the long-lived async-I/O carve-out documented in `CLAUDE.md`.
/// The helper is spawned via `tokio::process::Command` with async stdio
/// (NOT `spawn_blocking`): a blocking-task-slot capture for the full
/// SSH session duration (potentially hours under VS Code Remote-SSH or
/// JetBrains Gateway) would deadlock the executor under load.
pub struct LimaTransport {
    /// The per-operator manager, or the error from LIMA_HOME provisioning
    /// if `get_or_create` failed. Deferred to `connect()` so that
    /// `guest_transport` (a non-fallible trait method) can return without
    /// erroring — the error surfaces when the transport is actually used.
    ///
    /// **Sticky-error note:** the cached `Err` is fixed for the lifetime of
    /// this transport. A second `connect()` call after a provisioning error
    /// will return the same error. This is intentional: `LimaTransport` is
    /// per-session, so a new session (fresh `guest_transport` call) creates
    /// a fresh transport with a fresh registry lookup. Session-management
    /// code must not reuse a `LimaTransport` across reconcile cycles.
    manager: Result<Arc<LimaManager>, SandboxError>,
    /// VM name (`sandbox-{session_id}`), captured at transport
    /// construction so [`SessionRuntime::guest_transport`] can return
    /// without resolving fallible handle parsing here.
    vm_name: String,
    /// Operator uid for the `--op-uid` flag passed to the helper.
    operator_uid: u32,
}

#[async_trait]
impl GuestTransport for LimaTransport {
    async fn connect(&self) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>, SandboxError> {
        // Async-I/O carve-out: spawn via tokio::process::Command (NOT
        // spawn_blocking). See LimaTransport doc-comment and CLAUDE.md
        // "Async-I/O carve-out for long-lived child processes."
        let manager = match &self.manager {
            Ok(m) => m,
            Err(e) => {
                return Err(SandboxError::Internal(format!(
                    "LimaTransport: LIMA_HOME provisioning failed for operator {}: {e}",
                    self.operator_uid
                )));
            }
        };
        debug!(
            vm = %self.vm_name,
            op_uid = self.operator_uid,
            "opening sandbox-lima-helper guest-socat transport"
        );

        let mut command = Command::new(manager.helper_path());
        command
            .args([
                "guest-socat",
                "--op-uid",
                &self.operator_uid.to_string(),
                "--vm",
                &self.vm_name,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn().map_err(|e| {
            SandboxError::Lima(format!(
                "failed to spawn sandbox-lima-helper guest-socat for {}: {e}",
                self.vm_name
            ))
        })?;

        let stdin = child.stdin.take().ok_or_else(|| {
            SandboxError::Internal("failed to capture stdin of limactl shell socat".into())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            SandboxError::Internal("failed to capture stdout of limactl shell socat".into())
        })?;

        Ok(Box::new(LimaTransportStream {
            stdin,
            stdout,
            _child: child,
        }))
    }
}

/// Bidirectional duplex stream backed by a `limactl shell ... socat`
/// child. Owns the child handle so dropping the stream
/// (`kill_on_drop(true)`) tears the process down — no zombie left
/// behind even on caller-side panic.
struct LimaTransportStream {
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    _child: tokio::process::Child,
}

impl AsyncRead for LimaTransportStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for LimaTransportStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stdin).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use enumset::EnumSet;
    use std::path::PathBuf;

    use crate::backend::IsolationLevel;
    use crate::session::WorkspaceModeKind;

    /// Construct a hermetic `LimaRuntime` for unit tests. Uses
    /// `LimaManager::with_helper_path` (gated `#[cfg(test)]` in
    /// `lima.rs`) so no helper binary must be present on the host.
    fn test_runtime() -> Arc<LimaRuntime> {
        let registry = Arc::new(crate::lima::LimaManagerRegistry::new(
            crate::lima::DEFAULT_BASE_VM_NAME.to_string(),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            "test-pool".to_string(),
        ));
        LimaRuntime::new(registry)
    }

    /// `LimaRuntime::kind()` is the `BackendKind::Lima` constant —
    /// the Phase 1A trait dispatch table keys on this value.
    #[test]
    fn lima_runtime_kind_is_lima() {
        let rt = test_runtime();
        assert_eq!(rt.kind(), BackendKind::Lima);
    }

    /// `LimaRuntime::capabilities()` exposes the Lima-specific
    /// capability surface. Each field is asserted explicitly so a
    /// silent drift surfaces as a diff in this test rather than at a
    /// runtime call site months later.
    #[test]
    fn lima_runtime_capabilities_are_populated() {
        let rt = test_runtime();
        let caps = rt.capabilities();
        assert_eq!(caps.kind, BackendKind::Lima);
        assert_eq!(caps.isolation, IsolationLevel::Vm);
        assert!(caps.nested_virt, "Lima exposes KVM");
        assert!(caps.privileged_ops, "VM has full kernel surface");
        assert!(caps.raw_network, "Lima sessions get a real QEMU NIC");
        assert!(caps.hardening_flag, "Lima honours --hardened");
        assert!(caps.per_session_no_cache, "Lima supports --no-cache");
        assert_eq!(
            caps.workspace_modes,
            EnumSet::all(),
            "Lima supports every workspace mode kind"
        );
        assert!(caps.workspace_modes.contains(WorkspaceModeKind::Shared));
        assert!(caps.workspace_modes.contains(WorkspaceModeKind::Clone));
        assert!(caps.workspace_modes.contains(WorkspaceModeKind::Local));
    }

    /// Golden test for `Capabilities::for_lima()` — pins each field
    /// independently. This is the canonical regression guard called
    /// out in the Phase 1B handoff (Task 5 / Verification 9): if any
    /// field flips, a future maintainer must consciously update the
    /// expectations here and update the capabilities model design doc
    /// at the same time.
    #[test]
    fn capabilities_for_lima_returns_expected_values() {
        let caps = Capabilities::for_lima();
        assert_eq!(caps.kind, BackendKind::Lima);
        assert_eq!(caps.isolation, IsolationLevel::Vm);
        assert!(caps.nested_virt);
        assert!(caps.privileged_ops);
        assert!(caps.raw_network);
        assert!(caps.hardening_flag);
        assert!(caps.per_session_no_cache);
        assert_eq!(caps.workspace_modes, EnumSet::all());
    }

    /// `RuntimeHandle::from_session_id` follows the
    /// `sandbox-{session_id}` shape on which `LimaRuntime`'s entire
    /// dispatch path depends — `session_id_from_handle` round-trips
    /// against the same convention.
    #[test]
    fn runtime_handle_from_session_id_matches_lima_vm_name() {
        let sid = SessionId::parse("0123456789ab").unwrap();
        let handle = RuntimeHandle::from_session_id(&sid);
        assert_eq!(handle.as_str(), "sandbox-0123456789ab");
        // The Lima inverse parse hits the same shape:
        let parsed = LimaRuntime::session_id_from_handle(&handle).expect("handle is well-formed");
        assert_eq!(parsed, sid);
    }

    /// `From<VmStatus> for RuntimeStatus` covers every `VmStatus`
    /// variant currently in use. `Unknown(s)` preserves the original
    /// status string — diagnostic display in the daemon API depends
    /// on it.
    #[test]
    fn vm_status_to_runtime_status_covers_all_variants() {
        assert_eq!(
            RuntimeStatus::from(VmStatus::Running),
            RuntimeStatus::Running
        );
        assert_eq!(
            RuntimeStatus::from(VmStatus::Stopped),
            RuntimeStatus::Stopped
        );
        assert_eq!(
            RuntimeStatus::from(VmStatus::Unknown("Broken".to_string())),
            RuntimeStatus::Unknown("Broken".to_string()),
        );
        assert_eq!(
            RuntimeStatus::from(VmStatus::Unknown(String::new())),
            RuntimeStatus::Unknown(String::new()),
        );
    }

    /// Defensive: `LimaRuntime::create` rejects a container-shaped
    /// spec without ever touching `limactl`. The HTTP layer (Phase
    /// 1C) is expected to dispatch by `BackendKind` and never pass
    /// the wrong shape down, but this guard prevents a
    /// silent-empty-VM bug if the dispatch ever regresses.
    #[tokio::test]
    async fn create_rejects_container_spec() {
        let rt = test_runtime();
        let sid = SessionId::generate();
        let spec = SessionSpec {
            backend_specific: BackendSpecific::Container {
                memory_mb: 1024,
                cpus: 1.0,
            },
            workspace_mode: None,
            repo: None,
            boot_cmd: None,
            template: None,
            disk_gb: None,
            no_cache: None,
            operator_identity: None,
        };

        let err = rt
            .create(&sid, &spec)
            .await
            .expect_err("container spec must be rejected");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(msg.contains("container"), "got: {msg}");
            }
            other => panic!("expected InvalidArgument, got: {other:?}"),
        }
    }

    /// Defensive: `LimaRuntime::session_id_from_handle` rejects a
    /// handle that does not match the `sandbox-{12-hex-id}` shape.
    /// Daemon-level dispatch is responsible for routing handles to
    /// the right backend; this guard catches bugs early.
    #[test]
    fn session_id_from_handle_rejects_non_lima_handle() {
        let bogus = RuntimeHandle::from_name("docker-deadbeef0000");
        let err =
            LimaRuntime::session_id_from_handle(&bogus).expect_err("bogus handle must be rejected");
        assert!(matches!(err, SandboxError::InvalidArgument(_)));
    }

    /// `LimaRuntime::new` accepts a `LimaManagerRegistry` and exposes it
    /// via `registry()`. The registry is the source of per-operator
    /// `LimaManager` instances; this pins the constructor wiring.
    #[test]
    fn registry_round_trips_through_constructor() {
        let helper = PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper");
        let registry = Arc::new(crate::lima::LimaManagerRegistry::new(
            crate::lima::DEFAULT_BASE_VM_NAME.to_string(),
            helper.clone(),
            "test-pool".to_string(),
        ));
        let rt = LimaRuntime::new(Arc::clone(&registry));
        assert!(
            Arc::ptr_eq(rt.registry(), &registry),
            "constructor must thread the registry through to the getter"
        );
    }
}
