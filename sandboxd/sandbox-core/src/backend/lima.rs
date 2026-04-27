//! Lima/QEMU backend implementation of [`super::SessionRuntime`] and
//! [`super::GuestTransport`].
//!
//! Wraps the existing [`crate::lima::LimaManager`] behind the
//! `SessionRuntime` trait so HTTP handlers dispatch through
//! `Arc<dyn SessionRuntime>`. Lima-specific orchestration that does
//! not generalize to the container backend (clone, base-image
//! lifecycle, guest-agent install, list/reconcile) remains accessible
//! via [`LimaRuntime::manager`].
//!
//! - [`LimaRuntime::create`] dispatches to `LimaManager::create_vm`
//!   (or `create_vm_with_custom_template` when the spec carries a
//!   template).
//! - [`LimaRuntime::start`] consumes [`RuntimeStartArgs`] for
//!   docker bridge / MAC / `SessionConfig` populated by the daemon
//!   from `NetworkInfo`.
//! - [`LimaRuntime::ip`] shells out to `limactl shell ... ip -4 addr
//!   show eth1` and parses the dotted-quad. Future polish: source
//!   the IP from the daemon's per-session `NetworkInfo.vm_ip` map
//!   (one less round-trip; works pre-boot).

use std::net::IpAddr;
use std::process::Stdio;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tracing::debug;

use crate::backend::capabilities::{BackendKind, Capabilities};
use crate::backend::spec::{BackendSpecific, SessionSpec};
use crate::backend::{
    AsyncReadWrite, ExitCode, GuestTransport, RuntimeHandle, RuntimeStartArgs, RuntimeStatus,
    SessionRuntime,
};
use crate::error::SandboxError;
use crate::guest::GUEST_AGENT_PORT;
use crate::lima::{self, LimaManager, VmStatus};
use crate::session::{SessionConfig, SessionId};

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
    /// exist on `RuntimeStatus` for the container backend (M11-S2) and
    /// are populated by it directly.
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
/// [`SessionRuntime`]). Wraps [`crate::lima::LimaManager`] as a private
/// inner field; folding the manager content into this module and
/// narrowing the [`Self::manager`] accessor is deferred until M11-S2,
/// when the trait surface widens enough to cover daemon-startup
/// orchestration without an escape hatch.
pub struct LimaRuntime {
    manager: Arc<LimaManager>,
    capabilities: Capabilities,
}

impl LimaRuntime {
    /// Construct a [`LimaRuntime`] wrapping an existing
    /// [`LimaManager`]. Returns an `Arc` so the daemon can drop it
    /// into `AppState.runtimes: HashMap<BackendKind, Arc<dyn
    /// SessionRuntime>>` (Phase 1C) without an extra allocation at
    /// dispatch time.
    pub fn new(manager: Arc<LimaManager>) -> Arc<Self> {
        Arc::new(Self {
            manager,
            capabilities: Capabilities::for_lima(),
        })
    }

    /// Access the inner [`LimaManager`] for Lima-specific operations
    /// not on the trait surface — base-image build, template
    /// generation, base-image hash check, etc. Future polish: deferred
    /// until M11-S2 grows the trait enough to cover the daemon-startup
    /// flow without escape hatches.
    pub fn manager(&self) -> &Arc<LimaManager> {
        &self.manager
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
                // `backend::spec`); fall back to SessionConfig::default
                // if the request did not specify a size.
                disk_gb: spec
                    .disk_gb
                    .unwrap_or_else(|| SessionConfig::default().disk_gb),
                workspace_mode: spec.workspace_mode.clone(),
                hardened: *hardened,
                repo: spec.repo.clone(),
                boot_cmd: spec.boot_cmd.clone(),
                template: spec.template.clone(),
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
    /// Mirrors today's daemon "slow path" (`use_cache == false`): writes
    /// the per-session Lima template and shells out to `limactl create`.
    /// The VM is **not** booted, **not** cloned from the golden image,
    /// and the guest agent is **not** installed — those orchestration
    /// steps remain in `AppState` (clone path lives behind
    /// [`Self::manager`] until M11-S2 generalises them).
    ///
    /// When [`SessionSpec::template`] is `Some`, the runtime delegates to
    /// [`LimaManager::create_vm_with_custom_template`]; otherwise it
    /// generates the template inline via
    /// [`LimaManager::create_vm`]. This branch was previously open-coded
    /// in the daemon handler (see Phase 1C handoff §5).
    async fn create(
        &self,
        session_id: &SessionId,
        spec: &SessionSpec,
    ) -> Result<RuntimeHandle, SandboxError> {
        let config = Self::spec_to_config(spec)?;
        let manager = Arc::clone(&self.manager);
        let session_id_owned = *session_id;
        let template = spec.template.clone();

        // CLAUDE.md: every `std::process::Command` call in async
        // contexts is wrapped in `spawn_blocking`. Both
        // `LimaManager::create_vm` and `create_vm_with_custom_template`
        // shell out via `process::run_with_timeout`.
        tokio::task::spawn_blocking(move || {
            if let Some(template_path) = &template {
                manager.create_vm_with_custom_template(
                    &session_id_owned,
                    std::path::Path::new(template_path),
                )
            } else {
                manager.create_vm(&session_id_owned, &config)
            }
        })
        .await
        .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))??;

        Ok(RuntimeHandle::from_session_id(session_id))
    }

    /// Boot the VM with the bridge / MAC / config carried by `args`.
    ///
    /// Phase 1C plumbs the persisted [`SessionConfig`] and per-session
    /// docker-bridge / MAC through [`RuntimeStartArgs`]; the daemon
    /// (`AppState`) is the source of truth for these values and passes
    /// them in unchanged from what it allocates / persists per session.
    /// `args.lima_config == None` falls back to
    /// [`SessionConfig::default()`] for test paths that omit a config —
    /// the runtime emits a `warn!` so the silent-default behavior is
    /// audible rather than hidden, matching the Phase 1B trade-off.
    async fn start(
        &self,
        handle: &RuntimeHandle,
        args: &RuntimeStartArgs,
    ) -> Result<(), SandboxError> {
        let session_id = Self::session_id_from_handle(handle)?;
        let manager = Arc::clone(&self.manager);
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

    async fn stop(&self, handle: &RuntimeHandle) -> Result<(), SandboxError> {
        let session_id = Self::session_id_from_handle(handle)?;
        let manager = Arc::clone(&self.manager);

        tokio::task::spawn_blocking(move || manager.stop_vm(&session_id))
            .await
            .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))??;
        Ok(())
    }

    async fn delete(&self, handle: &RuntimeHandle) -> Result<(), SandboxError> {
        let session_id = Self::session_id_from_handle(handle)?;
        let manager = Arc::clone(&self.manager);

        tokio::task::spawn_blocking(move || manager.delete_vm(&session_id))
            .await
            .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))??;
        Ok(())
    }

    async fn status(&self, handle: &RuntimeHandle) -> Result<RuntimeStatus, SandboxError> {
        let session_id = Self::session_id_from_handle(handle)?;
        let manager = Arc::clone(&self.manager);

        let vm_status = tokio::task::spawn_blocking(move || manager.vm_status(&session_id))
            .await
            .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))??;
        Ok(vm_status.into())
    }

    /// Phase 1B approximation of `ip(handle)` (per the handoff Issue
    /// 2): shells out via `limactl shell <vm> -- ip -4 addr show eth1`
    /// and parses the resulting `inet 10.x.y.z/...` line. The IP
    /// authoritatively lives on the daemon's `NetworkInfo.vm_ip`
    /// blob; this shell-out is a stop-gap until Phase 1C plumbs the
    /// daemon's per-session map into the runtime so we can return it
    /// without an extra round trip to the VM.
    ///
    // TODO(M11-S1 Phase 1C): wire IP attribution properly via the
    // daemon's persisted `NetworkInfo.vm_ip` rather than an in-VM
    // shell-out. The current implementation requires the VM to be
    // running and `eth1` to exist — neither holds during create /
    // post-stop windows.
    async fn ip(&self, handle: &RuntimeHandle) -> Result<IpAddr, SandboxError> {
        let manager = Arc::clone(&self.manager);
        let vm_name = handle.as_str().to_string();

        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(manager.limactl_path())
                .args([
                    "shell", &vm_name, "--", "ip", "-4", "-o", "addr", "show", "dev", "eth1",
                ])
                .output()
                .map_err(|e| {
                    SandboxError::Lima(format!("failed to spawn limactl shell ... ip: {e}"))
                })
        })
        .await
        .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))??;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "limactl shell ... ip -4 addr show eth1 failed: {stderr}"
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_eth1_ipv4(&stdout).ok_or_else(|| {
            SandboxError::Lima(format!("could not parse eth1 IPv4 address from: {stdout}"))
        })
    }

    fn guest_transport(&self, handle: &RuntimeHandle) -> Arc<dyn GuestTransport> {
        // Resolving the session id can fail for malformed handles, but
        // `guest_transport` is non-fallible by trait contract. We
        // construct the transport with whichever name the handle
        // carries — `LimaTransport::connect` will surface the failure
        // when `limactl shell` rejects the unknown VM name.
        Arc::new(LimaTransport {
            manager: Arc::clone(&self.manager),
            vm_name: handle.as_str().to_string(),
        })
    }

    /// Run a command inside the VM with stdio streamed through the
    /// caller-supplied byte sinks. Mirrors today's `sandbox ssh` /
    /// `sandbox exec` flow (`limactl shell <vm> -- <cmd>`) but with
    /// the streams under the daemon's control rather than inheriting
    /// from the CLI process.
    async fn exec_interactive(
        &self,
        handle: &RuntimeHandle,
        cmd: Vec<String>,
        mut stdin: Box<dyn AsyncRead + Unpin + Send>,
        mut stdout: Box<dyn AsyncWrite + Unpin + Send>,
        mut stderr: Box<dyn AsyncWrite + Unpin + Send>,
    ) -> Result<ExitCode, SandboxError> {
        let vm_name = handle.as_str().to_string();

        let mut command = Command::new(self.manager.limactl_path());
        command
            .arg("shell")
            .arg(&vm_name)
            .arg("--")
            .args(&cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn().map_err(|e| {
            SandboxError::Lima(format!("failed to spawn limactl shell for {vm_name}: {e}"))
        })?;

        let mut child_stdin = child.stdin.take().ok_or_else(|| {
            SandboxError::Internal("failed to capture stdin of limactl shell".into())
        })?;
        let mut child_stdout = child.stdout.take().ok_or_else(|| {
            SandboxError::Internal("failed to capture stdout of limactl shell".into())
        })?;
        let mut child_stderr = child.stderr.take().ok_or_else(|| {
            SandboxError::Internal("failed to capture stderr of limactl shell".into())
        })?;

        // Pump caller stdin -> child stdin, child stdout -> caller
        // stdout, child stderr -> caller stderr concurrently. Each
        // direction ends naturally on EOF; we drop child_stdin first
        // so the child sees EOF on its end too.
        let stdin_task = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut stdin, &mut child_stdin).await;
            // Closing child_stdin tells the remote process EOF.
            let _ = child_stdin.shutdown().await;
        });
        let stdout_task = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut child_stdout, &mut stdout).await;
        });
        let stderr_task = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut child_stderr, &mut stderr).await;
        });

        let status = child.wait().await.map_err(|e| {
            SandboxError::Lima(format!(
                "failed to wait for limactl shell exit ({vm_name}): {e}"
            ))
        })?;

        // Best-effort: let the pipe pumpers drain anything still in
        // flight before returning.
        let _ = stdin_task.await;
        let _ = stdout_task.await;
        let _ = stderr_task.await;

        Ok(ExitCode(status.code().unwrap_or(-1)))
    }
}

// ---------------------------------------------------------------------------
// LimaTransport
// ---------------------------------------------------------------------------

/// [`GuestTransport`] over `limactl shell <vm> -- socat -
/// TCP:127.0.0.1:5123`. Each [`Self::connect`] call spawns a fresh
/// `limactl shell` child whose stdio is wired to the in-VM TCP socket
/// the guest agent listens on; the returned bidirectional stream owns
/// the child handle and tears it down on drop (`kill_on_drop(true)`).
///
/// Mirrors the inline construct used by [`crate::guest::GuestConnector`]
/// today (which Phase 1B does not refactor — see the handoff Task 4).
pub struct LimaTransport {
    manager: Arc<LimaManager>,
    /// VM name (`sandbox-{session_id}`), captured at transport
    /// construction so [`SessionRuntime::guest_transport`] can return
    /// without resolving fallible handle parsing here.
    vm_name: String,
}

#[async_trait]
impl GuestTransport for LimaTransport {
    async fn connect(&self) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>, SandboxError> {
        debug!(vm = %self.vm_name, "opening limactl shell socat transport");

        let mut command = Command::new(self.manager.limactl_path());
        command
            .args([
                "shell",
                &self.vm_name,
                "--",
                "socat",
                "-",
                &format!("TCP:127.0.0.1:{GUEST_AGENT_PORT}"),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn().map_err(|e| {
            SandboxError::Lima(format!(
                "failed to spawn limactl shell socat for {}: {e}",
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
// Helpers
// ---------------------------------------------------------------------------

/// Parse the dotted-quad IPv4 address out of `ip -4 -o addr show dev
/// eth1` output. Lima's `ip(8)` formatting (`-o`) puts the `inet
/// <addr>/<prefix>` token on a single line; we split on whitespace,
/// find `inet`, and return the address minus its prefix.
fn parse_eth1_ipv4(stdout: &str) -> Option<IpAddr> {
    for line in stdout.lines() {
        let mut tokens = line.split_whitespace();
        // Tokens: "<idx>:" "<iface>" "inet" "<addr>/<prefix>" ...
        while let Some(token) = tokens.next() {
            if token == "inet" {
                if let Some(cidr) = tokens.next() {
                    let addr = cidr.split('/').next().unwrap_or(cidr);
                    if let Ok(ip) = addr.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
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
    /// `LimaManager::with_limactl_path` (gated `#[cfg(test)]` in
    /// `lima.rs`) so no `limactl` binary must be present on `$PATH`.
    fn test_runtime() -> Arc<LimaRuntime> {
        let manager = Arc::new(LimaManager::with_limactl_path(
            PathBuf::from("/tmp/sandbox-test"),
            PathBuf::from("limactl"),
        ));
        LimaRuntime::new(manager)
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
    }

    /// Golden test for `Capabilities::for_lima()` — pins each field
    /// independently. This is the canonical regression guard called
    /// out in the Phase 1B handoff (Task 5 / Verification 9): if any
    /// field flips, a future maintainer must consciously update the
    /// expectations here and update the spec § "Capabilities model"
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

    /// `parse_eth1_ipv4` extracts the dotted-quad IPv4 address from
    /// `ip -4 -o addr show dev eth1`-shaped output. Tightly scoped
    /// helper test — the real `ip(handle)` round-trip is exercised
    /// in `integration_lima_runtime_lifecycle`.
    #[test]
    fn parse_eth1_ipv4_extracts_dotted_quad() {
        let output = "3: eth1    inet 10.209.0.3/28 brd 10.209.0.15 scope global eth1\\       valid_lft forever preferred_lft forever\n";
        let ip = parse_eth1_ipv4(output).expect("parse succeeded");
        assert_eq!(ip.to_string(), "10.209.0.3");
    }

    /// `parse_eth1_ipv4` returns `None` on output without an `inet`
    /// token (e.g. when `ip` reports only `inet6` because the link is
    /// down).
    #[test]
    fn parse_eth1_ipv4_returns_none_when_absent() {
        assert!(parse_eth1_ipv4("").is_none());
        assert!(parse_eth1_ipv4("3: eth1    inet6 fe80::1/64 scope link").is_none());
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
                cpus: 1,
            },
            workspace_mode: None,
            repo: None,
            boot_cmd: None,
            template: None,
            disk_gb: None,
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
}
