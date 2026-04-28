//! Docker container ("lite") backend implementation of
//! [`super::SessionRuntime`] and [`super::GuestTransport`].
//!
//! Subprocess-based: every Docker interaction is a `std::process::Command`
//! invocation against the `docker` CLI, mirroring the pattern used by
//! [`crate::gateway::GatewayManager`]. No `bollard` dependency.
//!
//! # Phase 3A scope
//!
//! This module implements the `SessionRuntime` trait surface and the
//! container-side `GuestTransport`. It does **not** build the lite
//! image (Phase 3B), expose `GET /backends` (Phase 3C), or wire into
//! `AppState.runtimes` (Phase 3D). The image tag is accepted via
//! [`ContainerRuntime::new`] and the per-session networking parameters
//! (bridge name, IP, gateway IP, DNS, workspace mount, home volume) are
//! accepted via [`ContainerRuntime::register_session`] which the daemon
//! (Phase 3D) and integration tests call before [`SessionRuntime::create`].
//!
//! Going through `register_session` rather than extending
//! [`super::RuntimeStartArgs`] keeps the trait signature stable through
//! 3A (Lima continues to ignore container fields) while letting the
//! container backend carry the per-session network state it needs at
//! `docker create` time.
//!
//! # Hardening defaults
//!
//! Per spec § "Hardening" — every flag in the table is applied at
//! `docker create` time and is not relaxable by callers:
//!
//! - `--read-only` — rootfs immutable.
//! - `--tmpfs /tmp` (`rw,nosuid,nodev,size=256m`) — scratch space.
//! - `--tmpfs /run` (`rw,nosuid,nodev,size=16m`) — process-runtime state.
//! - `--security-opt no-new-privileges` — prevents setuid escalation.
//! - `--security-opt seccomp=builtin` — Docker's default seccomp profile.
//!   Spec § "Hardening" prints this as `seccomp=default`, which is not a
//!   valid Docker CLI argument (Docker reads `default` as a filename and
//!   exits non-zero). The operator-intent reading is "Docker's default
//!   seccomp profile" — `builtin` is Docker's documented spelling for
//!   that and produces the same effective profile.
//! - `--cap-drop ALL` — no Linux capabilities; route helper installs
//!   the default route from the host so `CAP_NET_ADMIN` is never inside
//!   the container.
//! - `--user <uid>:<gid>` — non-root; calling uid/gid when the host uid
//!   is not 1000 so workspace bind-mount writes are owned by the
//!   operator.
//! - `--pids-limit 512` — fork-bomb ceiling.
//! - `--memory <mb>`, `--cpus <n>` — resource ceilings (from constructor).
//! - `--restart no` — daemon owns restart semantics.
//!
//! # Lifecycle
//!
//! - [`SessionRuntime::create`]: validates the spec, looks up the
//!   per-session network info registered via
//!   [`ContainerRuntime::register_session`], then `docker create`s the
//!   container with the hardening flags + network attachment + DNS
//!   pointer + named home volume + optional workspace bind.
//! - [`SessionRuntime::start`]: `docker start <name>`. Reading the
//!   container PID and invoking `sandbox-route-helper` is wired here:
//!   when the network info has a non-`None` `route_helper_path` and
//!   `gateway_ip`, the runtime spawns the helper between `docker start`
//!   and returning. Per spec § "Networking → Timing invariant", the
//!   agent does no outbound I/O before this point so the window is
//!   benign even though the default route still points at `.1`.
//! - [`SessionRuntime::stop`]: `docker stop -t 10 <name>`. Idempotent —
//!   stopping a non-running / nonexistent container returns `Ok(())`.
//! - [`SessionRuntime::delete`]: `docker rm -f <name>` then
//!   `docker volume rm sandbox-home-{session_id}`. Idempotent.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::process::Command as TokioCommand;
use tracing::{debug, info, warn};

use crate::backend::capabilities::{BackendKind, Capabilities, IsolationLevel};
use crate::backend::spec::{BackendSpecific, SessionSpec};
use crate::backend::{
    AsyncReadWrite, ExitCode, GuestTransport, RuntimeHandle, RuntimeStartArgs, RuntimeStatus,
    SessionRuntime,
};
use crate::error::SandboxError;
use crate::guest::GUEST_AGENT_PORT;
use crate::lima::guest_agent_path;
use crate::process::run_with_timeout;
use crate::session::SessionId;
use enumset::EnumSet;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Stop timeout passed to `docker stop -t`. Matches the spec's "bounded
/// timeout" requirement and gives in-container processes a reasonable
/// window to flush before SIGKILL.
const DOCKER_STOP_GRACE_SECS: u64 = 10;

/// Wall-clock timeout for individual `docker` subprocess invocations.
/// Sized to absorb a busy Docker daemon without leaving the runtime
/// blocked indefinitely on a hung CLI.
const DOCKER_CMD_TIMEOUT: Duration = Duration::from_secs(60);

/// Test-fixture tag for the lite image. Production builds construct
/// the runtime with `format!("{LITE_IMAGE_REPOSITORY}:{daemon_version}")`
/// so the tag matches what [`ensure_image`] actually builds; this `:latest`
/// constant is retained only for unit-test fixtures that point at any
/// pre-built image and never reach [`ensure_image`].
pub const DEFAULT_LITE_IMAGE_TAG: &str = "sandboxd-lite:latest";

/// Repository name for the lite image; the daemon-version tag is
/// appended at [`ensure_image`] time to produce the full
/// `sandboxd-lite:<daemon-version>` tag.
pub const LITE_IMAGE_REPOSITORY: &str = "sandboxd-lite";

/// Compose the full `sandboxd-lite:<daemon_version>` image tag from a
/// daemon version string. Pinned to this single helper so the daemon's
/// `ContainerRuntime` construction site, [`ensure_image`], and
/// [`rebuild_lite_image`] all agree on the same tag without duplicating
/// the format string. Drift here was the M11-S4 Phase 4D-pre gap #1
/// regression that broke `sandbox create --lite` end-to-end.
pub fn lite_image_tag_for_version(daemon_version: &str) -> String {
    format!("{LITE_IMAGE_REPOSITORY}:{daemon_version}")
}

/// Verbatim warning emitted on first-use rebuild of the lite image.
///
/// Spec § "Image building / First-use warning" pins this exact byte
/// sequence (note the en-dash `—` between "version" and "building"); the
/// CLI surface (M11-S4) and integration tests both rely on string
/// equality.
pub const LITE_FIRST_USE_WARNING: &str =
    "lite: first use on this daemon version — building lite image";

/// Dockerfile baked into `sandboxd` and written to the build-context
/// staging directory at [`ensure_image`] time. Spec § "Image building /
/// Dockerfile shape" — bumping the Dockerfile invalidates the daemon
/// version (callers are expected to bump `CARGO_PKG_VERSION` when this
/// content changes; the version is part of the tag, so an old image
/// stays addressable until a session referencing it is deleted).
const LITE_DOCKERFILE: &str = include_str!("../../../images/lite/Dockerfile");

/// Wall-clock timeout for `docker build`. Sized to absorb a slow Ubuntu
/// `apt-get install` over a constrained network without leaving the
/// runtime blocked indefinitely. Distinct from [`DOCKER_CMD_TIMEOUT`] —
/// `docker build` is the one Docker invocation routinely measured in
/// minutes rather than seconds.
const DOCKER_BUILD_TIMEOUT: Duration = Duration::from_secs(600);

/// Tmpfs flag values shared by the `/tmp` and `/run` mounts —
/// `rw,nosuid,nodev` plus per-mount size. Centralised so the spec
/// audit trail (§ "Hardening") stays grep-able from one place.
const TMPFS_TMP_FLAGS: &str = "rw,nosuid,nodev,size=256m";
const TMPFS_RUN_FLAGS: &str = "rw,nosuid,nodev,size=16m";

/// Pids-limit ceiling (§ "Hardening" — fork-bomb mitigation).
const PIDS_LIMIT: u32 = 512;

// ---------------------------------------------------------------------------
// Per-session network info (populated by daemon / tests via register_session)
// ---------------------------------------------------------------------------

/// Per-session network and bind-mount knobs the daemon allocates on
/// the host side and passes down to the container backend at
/// [`SessionRuntime::create`] time.
///
/// The runtime cannot derive these from the [`SessionId`] alone — the
/// docker network name, gateway container IP, and per-session bridge
/// IP are owned by `NetworkManager` (see `crate::network`). Phase 3D
/// will plumb these through `AppState.runtimes` registration; in 3A
/// integration tests construct them directly.
#[derive(Debug, Clone)]
pub struct ContainerNetwork {
    /// Docker network name to attach the container to (`sandbox-net-{session_id}`).
    pub docker_network: String,
    /// Bridge IP to assign the container, the per-session `.3` allocated
    /// by `NetworkManager` from the /28 block.
    pub container_ip: IpAddr,
    /// Gateway container IP, the `.2` of the per-session /28. Used for
    /// `--dns` and (Phase 3A) handed to the route helper at start time.
    pub gateway_ip: IpAddr,
    /// Optional host path bound into `/home/agent/workspace/` inside
    /// the container. `None` means no workspace bind. Aligned with the
    /// spec's [`WorkspaceMode::Shared`] semantics — the bind target is
    /// unified with Lima's workspace mount across both backends
    /// (M11-S7), so an operator's `--workspace shared:<path>` lands at
    /// the same in-guest path regardless of the backend they chose.
    pub workspace_host_path: Option<PathBuf>,
    /// Path to the `sandbox-route-helper` binary. When `None`, the
    /// runtime skips the route-installation step at `start` — useful
    /// for hardening tests that exercise lifecycle without requiring
    /// the helper to be installed (the 3A integration tests). Phase
    /// 3D wires this from a daemon configuration value.
    pub route_helper_path: Option<PathBuf>,
    /// Optional host path to the per-session CA certificate
    /// (`<base_dir>/sessions/<sid>/ca/cert.pem`). When `Some`, the
    /// runtime bind-mounts the file read-only into the container at
    /// `/etc/ssl/certs/sandbox-ca.pem` and exports the standard
    /// HTTPS-client trust env vars (`CURL_CA_BUNDLE`, `SSL_CERT_FILE`,
    /// `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`) pointing at it. This
    /// is the container-backend analogue of Lima's `inject_ca_into_vm`
    /// path: the per-session sandbox CA must be trusted inside the
    /// container so HTTPS traffic transparently rewritten by mitmproxy
    /// (L3-HTTP policy MITM) verifies cleanly. The Lima approach
    /// (`update-ca-certificates` over a writable rootfs) is unavailable
    /// here because the spec § Hardening mandates `--read-only`; the
    /// bind-mount + env-var path achieves the same effect without
    /// touching the rootfs. `None` means no CA injection.
    pub ca_host_path: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// ContainerRuntime
// ---------------------------------------------------------------------------

/// Docker container backend runtime.
///
/// One instance is shared across every container-backed session — the
/// trait is stateless over [`RuntimeHandle`]. Per-session networking
/// state is populated via [`Self::register_session`] before
/// [`SessionRuntime::create`].
pub struct ContainerRuntime {
    capabilities: Capabilities,
    image_tag: String,
    /// Default memory ceiling in megabytes. Spec § "Resource defaults"
    /// — `host_ram × 0.8` rounded down — is computed once at daemon
    /// startup (Phase 3D) and threaded in here.
    default_memory_mb: u32,
    /// Default CPU ceiling. Spec § "Resource defaults" — `host_cpus × 0.8`
    /// rounded to one decimal place.
    default_cpus: f64,
    /// Linux uid the container runs as. Spec § "Hardening" specifies
    /// `1000:1000` unless the host uid differs from 1000 (for workspace
    /// bind-mount uid alignment), in which case the calling uid/gid are
    /// used.
    user_uid: u32,
    user_gid: u32,
    /// Per-session network info, populated by the daemon (3D) or by
    /// tests before [`SessionRuntime::create`]. Keyed on the session id
    /// so a single runtime instance handles every session.
    sessions: Mutex<HashMap<SessionId, ContainerNetwork>>,
}

impl ContainerRuntime {
    /// Construct a container runtime with the given image tag, default
    /// resource ceilings, and container-process uid/gid.
    ///
    /// `image_tag` is the docker image used for `docker create`. Phase 3B
    /// computes this from the daemon version (`sandboxd-lite:<ver>`); 3A
    /// tests pass any image they have available.
    ///
    /// `default_memory_mb` / `default_cpus` are applied when the
    /// [`SessionSpec`] does not override them. Phase 3D computes the
    /// 80%-of-host defaults; 3A tests pass arbitrary values.
    ///
    /// `user_uid` / `user_gid` are the in-container runtime identity.
    /// Spec § "Hardening" mandates non-root; spec § "Workspace" mandates
    /// alignment with the host operator's uid when the host uid is not
    /// 1000.
    pub fn new(
        image_tag: impl Into<String>,
        default_memory_mb: u32,
        default_cpus: f64,
        user_uid: u32,
        user_gid: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            capabilities: capabilities_for_container(),
            image_tag: image_tag.into(),
            default_memory_mb,
            default_cpus,
            user_uid,
            user_gid,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    /// Image tag this runtime uses on `docker create` / `docker build`.
    /// Exposed so the daemon can pass the same tag to `ensure_image`
    /// before calling [`SessionRuntime::create`] without re-deriving
    /// the daemon version → tag mapping at the call site.
    pub fn image_tag(&self) -> &str {
        &self.image_tag
    }

    /// Register the per-session network info this runtime needs at
    /// `docker create` time. The daemon (Phase 3D) calls this after
    /// `NetworkManager::ensure_network` and before dispatching to
    /// [`SessionRuntime::create`].
    ///
    /// Subsequent `register_session` calls for the same session id
    /// replace the previous entry — useful for test reuse but also for
    /// recovery flows that re-derive network info.
    pub fn register_session(&self, session_id: SessionId, network: ContainerNetwork) {
        let mut guard = self.sessions.lock().expect("sessions mutex poisoned");
        guard.insert(session_id, network);
    }

    /// Best-effort lookup; the corresponding `SessionRuntime` method
    /// returns `Err` when the session is unregistered.
    fn lookup_session(&self, session_id: &SessionId) -> Result<ContainerNetwork, SandboxError> {
        let guard = self.sessions.lock().expect("sessions mutex poisoned");
        guard.get(session_id).cloned().ok_or_else(|| {
            SandboxError::InvalidArgument(format!(
                "ContainerRuntime: session {session_id} has no registered network info"
            ))
        })
    }

    /// Drop the per-session entry. Called from `delete` so a re-create
    /// of the same session id with fresh network info does not pick up
    /// stale state.
    fn forget_session(&self, session_id: &SessionId) {
        let mut guard = self.sessions.lock().expect("sessions mutex poisoned");
        guard.remove(session_id);
    }

    /// Resolve a runtime handle back to a [`SessionId`] by stripping
    /// the canonical `sandbox-` prefix. Container handles share Lima's
    /// naming convention (spec § "Persistence / Handle persistence").
    fn session_id_from_handle(handle: &RuntimeHandle) -> Result<SessionId, SandboxError> {
        crate::lima::parse_session_id_from_name(handle.as_str()).ok_or_else(|| {
            SandboxError::InvalidArgument(format!(
                "ContainerRuntime received a non-container runtime handle: {}",
                handle.as_str()
            ))
        })
    }

    /// Resolve container memory/cpus from the spec, falling back to
    /// the runtime's defaults when the spec carries `0` (treated as
    /// "unset" — the request-boundary handler in `sandboxd` stamps
    /// `0`/`0.0` whenever the operator omitted `--cpus`/`--memory`,
    /// and this is where we substitute the daemon's host-80% defaults).
    ///
    /// Returns `(memory_mb, cpus)` with `cpus` widened to `f64` for
    /// the consumer (`format_cpus` formats with `{:.1}`). Pre-todo-#67
    /// the `cpus` input was `u32` and the widening was a `as f64` on
    /// every call; the f32 source eliminates the truncation that
    /// previously dropped fractional values like `1.5` to `1`.
    fn resource_ceilings(&self, spec: &SessionSpec) -> Result<(u32, f64), SandboxError> {
        let (memory_mb, cpus) = match &spec.backend_specific {
            BackendSpecific::Container { memory_mb, cpus } => (*memory_mb, *cpus),
            BackendSpecific::Lima { .. } => {
                return Err(SandboxError::InvalidArgument(format!(
                    "ContainerRuntime received a Lima-shaped SessionSpec (got backend={})",
                    spec.backend()
                )));
            }
        };
        let memory_mb = if memory_mb == 0 {
            self.default_memory_mb
        } else {
            memory_mb
        };
        // `0.0` is the request-boundary "unset" sentinel (operator did
        // not pass `--cpus`); substitute the daemon's host-80% default.
        // Any other value is passed through after a lossless f32→f64
        // widening so `format_cpus` sees the exact same one-decimal
        // value the operator supplied.
        let cpus = if cpus == 0.0 {
            self.default_cpus
        } else {
            cpus as f64
        };
        Ok((memory_mb, cpus))
    }
}

/// Static [`Capabilities`] for the container backend. Mirrors
/// [`Capabilities::for_lima`] in placement intent — pinned source of
/// truth for the discovery endpoint (Phase 3C). Spec §"Capabilities
/// model" + §"What this breaks" justifies each field.
fn capabilities_for_container() -> Capabilities {
    Capabilities {
        kind: BackendKind::Container,
        // Spec §"Architecture / Two implementations" — container is
        // namespace + cgroup isolation only.
        isolation: IsolationLevel::Container,
        // Spec §"What this breaks" — kernel modules / KVM not
        // exposed in default-seccomp container.
        nested_virt: false,
        // Spec §"What this breaks" — `cap-drop=ALL` and read-only
        // rootfs forbid `mount`, raw `iptables`, etc.
        privileged_ops: false,
        // Spec §"What this breaks" — `CAP_NET_RAW` dropped; raw sockets
        // (and therefore `ping`) do not work.
        raw_network: false,
        // Spec §"Capabilities model" — `--hardened` is QEMU-only.
        hardening_flag: false,
        // Spec §"CLI & UX / `sandbox create --no-cache`" — no
        // per-session slow path; rebuild-image is the operator surface.
        per_session_no_cache: false,
        // Spec §"Workspace" — both workspace modes are supported on the
        // container backend (M11-S7): `Shared` advertises a Docker
        // bind-mount (the daemon threads `workspace_host_path` from the
        // request through `ContainerNetwork`, and `docker create --mount`
        // lights up at create time); `Clone` advertises the same in-guest
        // `git clone <url> /home/agent/workspace/` flow Lima uses — the
        // daemon dispatches it via the backend-agnostic `GuestConnector`
        // after the lite container's entrypoint (`sandbox-guest`) is up,
        // mirroring the Lima `--repo` path.
        workspace_modes: EnumSet::all(),
    }
}

// ---------------------------------------------------------------------------
// SessionRuntime impl
// ---------------------------------------------------------------------------

#[async_trait]
impl SessionRuntime for ContainerRuntime {
    fn kind(&self) -> BackendKind {
        BackendKind::Container
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// `docker create` the container with hardening flags, network
    /// attachment, DNS pointer, named home volume, and the optional
    /// workspace bind mount.
    async fn create(
        &self,
        session_id: &SessionId,
        spec: &SessionSpec,
    ) -> Result<RuntimeHandle, SandboxError> {
        spec.validate(&self.capabilities)
            .map_err(|e| SandboxError::InvalidArgument(e.to_string()))?;

        let network = self.lookup_session(session_id)?;
        let (memory_mb, cpus) = self.resource_ceilings(spec)?;
        let container_name = format!("sandbox-{session_id}");
        let home_volume = home_volume_name(session_id);
        let user_arg = format!("{}:{}", self.user_uid, self.user_gid);
        let memory_arg = format!("{memory_mb}m");
        let cpus_arg = format_cpus(cpus);
        let pids_arg = PIDS_LIMIT.to_string();
        let dns_arg = network.gateway_ip.to_string();
        let ip_arg = network.container_ip.to_string();
        let label_arg = format!("sandbox.session_id={session_id}");
        let home_mount = format!("type=volume,src={home_volume},dst=/home/agent");
        let workspace_mount = network.workspace_host_path.as_ref().map(|p| {
            // Spec § "Workspace" — bind target unified with Lima at
            // `/home/agent/workspace/` (M11-S7). The home volume mounts
            // at `/home/agent`; this bind shadows the volume's content
            // at the workspace subdirectory, which is the intended
            // semantics (operator-supplied workspace files take
            // precedence over the volume's empty `workspace/`).
            format!(
                "type=bind,src={},dst=/home/agent/workspace/",
                p.to_string_lossy().into_owned()
            )
        });
        let ca_args = build_ca_mount_args(&network);
        // M11-S7 — `WorkspaceMode::Clone` is now part of the container
        // backend's capability matrix; the daemon dispatches the in-guest
        // `git clone` step after `runtime.start` completes, exactly like
        // the Lima `--repo` path. `runtime.create` only owns the
        // `docker create` arguments, which are identical for `Empty`,
        // `Clone`, and `Shared` (the bind mount is the only knob, and
        // `Clone` does not bind a host path).

        let mut args: Vec<String> = vec![
            "create".to_string(),
            "--name".to_string(),
            container_name.clone(),
            "--hostname".to_string(),
            session_id.to_string(),
            "--network".to_string(),
            network.docker_network.clone(),
            "--ip".to_string(),
            ip_arg,
            "--dns".to_string(),
            dns_arg,
            // Hardening — every flag in spec § "Hardening" applied
            // verbatim, in table order.
            "--read-only".to_string(),
            "--tmpfs".to_string(),
            format!("/tmp:{TMPFS_TMP_FLAGS}"),
            "--tmpfs".to_string(),
            format!("/run:{TMPFS_RUN_FLAGS}"),
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
            "--security-opt".to_string(),
            "seccomp=builtin".to_string(),
            "--cap-drop".to_string(),
            "ALL".to_string(),
            "--user".to_string(),
            user_arg,
            "--pids-limit".to_string(),
            pids_arg,
            "--memory".to_string(),
            memory_arg,
            "--cpus".to_string(),
            cpus_arg,
            "--restart".to_string(),
            "no".to_string(),
            "--label".to_string(),
            label_arg,
            "--mount".to_string(),
            home_mount,
        ];

        if let Some(mount) = workspace_mount {
            args.push("--mount".to_string());
            args.push(mount);
        }

        args.extend(ca_args);

        // Trailing positional: image tag — must come last so subsequent
        // entrypoint args (none here) line up with the docker CLI grammar.
        args.push(self.image_tag.clone());

        debug!(
            session_id = %session_id,
            container = %container_name,
            image = %self.image_tag,
            "ContainerRuntime: docker create"
        );

        run_docker(&args, "docker create (container runtime)").await?;
        Ok(RuntimeHandle::from_session_id(session_id))
    }

    /// `docker start <name>`, then optionally invoke
    /// `sandbox-route-helper <pid> <gateway-ip>` if a helper path was
    /// registered. Spec § "Lifecycle" — the helper runs between
    /// `docker start` and the agent-ready wait. Idempotent retries on
    /// already-running containers are safe (Docker's start command is
    /// idempotent for running containers).
    async fn start(
        &self,
        handle: &RuntimeHandle,
        _args: &RuntimeStartArgs,
    ) -> Result<(), SandboxError> {
        let session_id = Self::session_id_from_handle(handle)?;
        let network = self.lookup_session(&session_id)?;
        let container_name = handle.as_str().to_string();

        run_docker(
            &["start".to_string(), container_name.clone()],
            "docker start (container runtime)",
        )
        .await?;

        if let Some(helper) = network.route_helper_path.as_ref() {
            let pid = inspect_container_pid(&container_name).await?;
            invoke_route_helper(helper, pid, network.gateway_ip).await?;
        } else {
            debug!(
                session_id = %session_id,
                container = %container_name,
                "ContainerRuntime::start: no route_helper_path registered; \
                 container will route to the bridge; route-helper integration \
                 scheduled for M11-S4/S5."
            );
        }

        Ok(())
    }

    /// `docker stop -t 10 <name>`. Idempotent: a `docker stop` against
    /// a stopped or nonexistent container exits non-zero with a
    /// recognisable "is not running" / "No such container" stderr.
    /// Both shapes map to `Ok(())` so callers do not need to special-
    /// case the redundant-stop path.
    async fn stop(&self, handle: &RuntimeHandle) -> Result<(), SandboxError> {
        let container_name = handle.as_str().to_string();
        let args = [
            "stop".to_string(),
            "-t".to_string(),
            DOCKER_STOP_GRACE_SECS.to_string(),
            container_name,
        ];

        match run_docker(&args, "docker stop (container runtime)").await {
            Ok(_) => Ok(()),
            Err(SandboxError::Gateway(msg))
                if msg.contains("is not running") || msg.contains("No such container") =>
            {
                Ok(())
            }
            Err(other) => Err(other),
        }
    }

    /// `docker rm -f <name>` then `docker volume rm
    /// sandbox-home-{session_id}`. Idempotent: `docker rm -f` against a
    /// nonexistent container, and `docker volume rm` against a
    /// nonexistent volume, both surface as "No such ..." in stderr —
    /// translated to `Ok(())`.
    async fn delete(&self, handle: &RuntimeHandle) -> Result<(), SandboxError> {
        let session_id = Self::session_id_from_handle(handle)?;
        let container_name = handle.as_str().to_string();

        let rm_args = ["rm".to_string(), "-f".to_string(), container_name.clone()];
        match run_docker(&rm_args, "docker rm (container runtime)").await {
            Ok(_) => {}
            Err(SandboxError::Gateway(msg)) if msg.contains("No such container") => {}
            Err(other) => return Err(other),
        }

        let volume = home_volume_name(&session_id);
        let vol_args = ["volume".to_string(), "rm".to_string(), volume];
        match run_docker(&vol_args, "docker volume rm (container runtime)").await {
            Ok(_) => {}
            Err(SandboxError::Gateway(msg))
                if msg.contains("No such volume") || msg.contains("no such volume") => {}
            Err(other) => return Err(other),
        }

        self.forget_session(&session_id);
        Ok(())
    }

    async fn status(&self, handle: &RuntimeHandle) -> Result<RuntimeStatus, SandboxError> {
        let container_name = handle.as_str().to_string();
        let args = [
            "inspect".to_string(),
            "-f".to_string(),
            "{{.State.Status}}".to_string(),
            container_name,
        ];

        match run_docker(&args, "docker inspect (container status)").await {
            Ok(stdout) => Ok(parse_docker_state_status(&stdout)),
            // `docker inspect` emits "no such object" (lowercase) while
            // `docker rm/stop` emit "No such container" (mixed case).
            // Both shapes mean the container is gone; surface as Stopped.
            Err(SandboxError::Gateway(msg))
                if msg.contains("No such container") || msg.contains("no such object") =>
            {
                Ok(RuntimeStatus::Stopped)
            }
            Err(other) => Err(other),
        }
    }

    /// Return the container's bridge IP. Returns the IP recorded at
    /// `register_session` time rather than `docker inspect`-ing — the
    /// daemon is the authoritative source (network manager allocated
    /// it), and the inspect path costs a subprocess for no new
    /// information.
    async fn ip(&self, handle: &RuntimeHandle) -> Result<IpAddr, SandboxError> {
        let session_id = Self::session_id_from_handle(handle)?;
        let network = self.lookup_session(&session_id)?;
        Ok(network.container_ip)
    }

    fn guest_transport(&self, handle: &RuntimeHandle) -> Arc<dyn GuestTransport> {
        Arc::new(ContainerTransport {
            container_name: handle.as_str().to_string(),
        })
    }

    async fn exec_interactive(
        &self,
        handle: &RuntimeHandle,
        cmd: Vec<String>,
        mut stdin: Box<dyn AsyncRead + Unpin + Send>,
        mut stdout: Box<dyn AsyncWrite + Unpin + Send>,
        mut stderr: Box<dyn AsyncWrite + Unpin + Send>,
    ) -> Result<ExitCode, SandboxError> {
        let container_name = handle.as_str().to_string();

        let mut command = TokioCommand::new("docker");
        command
            .arg("exec")
            .arg("-i")
            .arg(&container_name)
            .args(&cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn().map_err(|e| {
            SandboxError::Gateway(format!(
                "failed to spawn docker exec for {container_name}: {e}"
            ))
        })?;

        let mut child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| SandboxError::Internal("failed to capture docker exec stdin".into()))?;
        let mut child_stdout = child
            .stdout
            .take()
            .ok_or_else(|| SandboxError::Internal("failed to capture docker exec stdout".into()))?;
        let mut child_stderr = child
            .stderr
            .take()
            .ok_or_else(|| SandboxError::Internal("failed to capture docker exec stderr".into()))?;

        let stdin_task = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut stdin, &mut child_stdin).await;
            let _ = child_stdin.shutdown().await;
        });
        let stdout_task = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut child_stdout, &mut stdout).await;
        });
        let stderr_task = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut child_stderr, &mut stderr).await;
        });

        let status = child.wait().await.map_err(|e| {
            SandboxError::Gateway(format!(
                "failed to wait for docker exec exit ({container_name}): {e}"
            ))
        })?;

        let _ = stdin_task.await;
        let _ = stdout_task.await;
        let _ = stderr_task.await;

        Ok(ExitCode(status.code().unwrap_or(-1)))
    }
}

// ---------------------------------------------------------------------------
// ContainerTransport
// ---------------------------------------------------------------------------

/// [`GuestTransport`] over `docker exec <container> socat -
/// TCP:127.0.0.1:5123` — the spec § "Architecture / Two implementations"
/// pattern that mirrors Lima's `limactl shell <vm> -- socat -
/// TCP:127.0.0.1:5123` exactly. The `sandbox-guest` agent binds TCP on
/// `127.0.0.1:5123` inside the container; reaching it via `docker exec`
/// is the dual of Lima reaching it via `limactl shell` and works
/// regardless of the container's external network configuration.
pub struct ContainerTransport {
    container_name: String,
}

#[async_trait]
impl GuestTransport for ContainerTransport {
    async fn connect(&self) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>, SandboxError> {
        debug!(container = %self.container_name, "opening docker exec socat transport");

        let mut command = TokioCommand::new("docker");
        command
            .args([
                "exec",
                "-i",
                &self.container_name,
                "socat",
                "-",
                &format!("TCP:127.0.0.1:{GUEST_AGENT_PORT}"),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn().map_err(|e| {
            SandboxError::Gateway(format!(
                "failed to spawn docker exec socat for {}: {e}",
                self.container_name
            ))
        })?;

        let stdin = child.stdin.take().ok_or_else(|| {
            SandboxError::Internal("failed to capture stdin of docker exec socat".into())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            SandboxError::Internal("failed to capture stdout of docker exec socat".into())
        })?;

        Ok(Box::new(ContainerTransportStream {
            stdin,
            stdout,
            _child: child,
        }))
    }
}

struct ContainerTransportStream {
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    _child: tokio::process::Child,
}

impl AsyncRead for ContainerTransportStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ContainerTransportStream {
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

/// Canonical home-volume name (spec § "Per-session home volume").
fn home_volume_name(session_id: &SessionId) -> String {
    format!("sandbox-home-{session_id}")
}

/// Format the cpus knob as a one-decimal string (`2.0`, `0.5`) since
/// the docker CLI accepts decimals and spec § "Resource defaults"
/// pins one-decimal precision.
fn format_cpus(cpus: f64) -> String {
    format!("{cpus:.1}")
}

/// Stable in-container path of the per-session sandbox CA. Bind-mounted
/// from the host's `<base_dir>/sessions/<id>/ca/cert.pem` and pointed at
/// by the four standard HTTPS-client trust env vars. Pinned here so the
/// daemon-side wiring and the unit test that pins the contract share
/// the same source of truth.
const SANDBOX_CA_CONTAINER_PATH: &str = "/etc/ssl/certs/sandbox-ca.pem";

/// HTTPS-client trust env var names that must point at the per-session
/// CA file inside the container. Listed in the order `create()` emits
/// them so the unit-test pin can assert positional ordering. The
/// rationale for picking these four is documented on
/// [`ContainerNetwork::ca_host_path`].
const SANDBOX_CA_ENV_VARS: &[&str] = &[
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
];

/// Render the `--mount` + `--env` arg slice that `create()` appends
/// when a per-session CA bind-mount is wired. Returns an empty vec when
/// `ca_host_path` is `None` so the caller can `args.extend(...)`
/// unconditionally. Extracted as a pure helper so the unit test
/// `container_runtime_create_includes_ca_mount_when_path_set` can pin
/// the bind-mount string and env-var ordering without exec'ing
/// `docker create`.
///
/// Per-session sandbox CA: bind-mounted read-only at a stable path
/// inside the container, and surfaced through the four standard
/// HTTPS-client trust env vars. See the field doc on
/// [`ContainerNetwork::ca_host_path`] for the rationale (Lima's
/// `update-ca-certificates`-based path is incompatible with the
/// spec-mandated `--read-only` rootfs).
///
/// `CURL_CA_BUNDLE` / `SSL_CERT_FILE` override the system bundle, which
/// is the desired behaviour here: every request inside the container is
/// intercepted by mitmproxy through Envoy, and the synthesized server
/// cert is signed by the per-session CA. The system Ubuntu bundle is
/// never the right answer for that traffic.
fn build_ca_mount_args(network: &ContainerNetwork) -> Vec<String> {
    let Some(ca_path) = network.ca_host_path.as_ref() else {
        return Vec::new();
    };
    let mount = format!(
        "type=bind,src={},dst={SANDBOX_CA_CONTAINER_PATH},readonly",
        ca_path.to_string_lossy().into_owned()
    );
    let mut out = Vec::with_capacity(2 + SANDBOX_CA_ENV_VARS.len() * 2);
    out.push("--mount".to_string());
    out.push(mount);
    for var in SANDBOX_CA_ENV_VARS {
        out.push("--env".to_string());
        out.push(format!("{var}={SANDBOX_CA_CONTAINER_PATH}"));
    }
    out
}

/// Map the trimmed stdout of `docker inspect -f '{{.State.Status}}' <name>`
/// onto a [`RuntimeStatus`].
///
/// Docker's status vocabulary covers `created`, `running`, `paused`,
/// `restarting`, `removing`, `exited`, `dead`. The mapping favours
/// what the daemon's recovery loop cares about: `running` → Running,
/// `created` (post-create / pre-start) → Stopped, `exited` (clean stop
/// or crash) → Stopped, `dead` → Error, `paused` / `restarting` /
/// `removing` → Unknown(s) (preserved verbatim for diagnostic display).
fn parse_docker_state_status(raw: &str) -> RuntimeStatus {
    match raw.trim() {
        "running" => RuntimeStatus::Running,
        "created" | "exited" => RuntimeStatus::Stopped,
        "dead" => RuntimeStatus::Error,
        other => RuntimeStatus::Unknown(other.to_string()),
    }
}

/// Run `docker <args>` with [`run_with_timeout`] inside a
/// `spawn_blocking` task (CLAUDE.md `spawn_blocking` discipline).
///
/// On success returns the trimmed stdout — most callers want a
/// trivial value (status line, container id) and trimming once here
/// is cheaper than re-trimming at every call site.
async fn run_docker(args: &[String], operation: &'static str) -> Result<String, SandboxError> {
    let owned: Vec<String> = args.to_vec();
    let op = operation.to_string();
    tokio::task::spawn_blocking(move || {
        let mut cmd = std::process::Command::new("docker");
        for arg in &owned {
            cmd.arg(arg);
        }
        let output = run_with_timeout(&mut cmd, DOCKER_CMD_TIMEOUT, &op).map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                SandboxError::Gateway(format!("failed to run {op}: {msg}"))
            }
            other => other,
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            return Err(SandboxError::Gateway(format!("{op} failed: {stderr}")));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    })
    .await
    .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))?
}

/// `docker inspect -f '{{.State.Pid}}' <name>` → host-namespace pid.
/// Returns the parsed integer; 0 (a stopped container's reported pid)
/// surfaces as an error since spawning the helper against pid 0 makes
/// no sense.
async fn inspect_container_pid(container_name: &str) -> Result<i32, SandboxError> {
    let args = [
        "inspect".to_string(),
        "-f".to_string(),
        "{{.State.Pid}}".to_string(),
        container_name.to_string(),
    ];
    let stdout = run_docker(&args, "docker inspect (container pid)").await?;
    let pid: i32 = stdout.parse().map_err(|_| {
        SandboxError::Gateway(format!(
            "docker inspect returned non-integer pid for {container_name}: {stdout:?}"
        ))
    })?;
    if pid <= 0 {
        return Err(SandboxError::Gateway(format!(
            "docker inspect returned non-positive pid for {container_name}: {pid}"
        )));
    }
    Ok(pid)
}

/// Spawn `sandbox-route-helper <pid> <gateway_ip>` and wait for
/// completion. Per the route-helper contract (spec § "Networking →
/// Helper authorization flow"), exit 0 is success and any non-zero
/// exit is a deny — stderr carries the load-bearing reason which we
/// surface to the caller verbatim.
async fn invoke_route_helper(
    helper: &Path,
    pid: i32,
    gateway_ip: IpAddr,
) -> Result<(), SandboxError> {
    let helper = helper.to_path_buf();
    let pid_arg = pid.to_string();
    let gw_arg = gateway_ip.to_string();
    tokio::task::spawn_blocking(move || {
        let mut cmd = std::process::Command::new(&helper);
        cmd.arg(&pid_arg).arg(&gw_arg);
        let output = run_with_timeout(&mut cmd, DOCKER_CMD_TIMEOUT, "sandbox-route-helper")
            .map_err(|e| match e {
                SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                    SandboxError::Network(format!(
                        "failed to spawn sandbox-route-helper at {}: {msg}",
                        helper.display()
                    ))
                }
                other => other,
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            return Err(SandboxError::Network(format!(
                "sandbox-route-helper denied (exit {}): {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            )));
        }
        Ok(())
    })
    .await
    .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))?
}

// ---------------------------------------------------------------------------
// Resource defaults (Phase 3D)
// ---------------------------------------------------------------------------

/// Compute the daemon-wide default container memory/CPU ceilings from
/// the host's resources, per spec § "Resource defaults — container only".
///
/// Returns `(memory_mb, cpus)`:
/// - `memory_mb` = `host_ram_mb × 0.8`, floored to whole MB.
/// - `cpus` = `host_cpus × 0.8`, rounded to one decimal place.
///
/// Computed once at daemon startup (callers cache the result on
/// `ContainerRuntime::new`); host RAM/CPU changes between daemon
/// restarts pick up new defaults on the next boot.
///
/// Internal type for the cpu default is `f64` so the spec's one-decimal
/// precision survives all the way to docker's `--cpus <n>` flag (see
/// [`format_cpus`]). M11-S7 todo #67 widened the wire-level
/// [`BackendSpecific::Container`] field from `u32` to `f32`, so an
/// explicit operator-supplied fractional value (e.g. `--cpus 1.5`) now
/// reaches `format_cpus` without truncation. The implicit-default path
/// (operator omits `--cpus`, request boundary stamps `0.0`) still
/// resolves to this function's return value via
/// [`ContainerRuntime::resource_ceilings`]'s `0.0 → default_cpus` arm.
///
/// Best-effort fallbacks keep the daemon bootable even on hosts where
/// /proc/meminfo or `available_parallelism` is unavailable: a 4096 MB
/// memory ceiling and a 2.0 CPU ceiling. A `tracing::warn!` is emitted
/// via the called helpers when either fallback fires so operators can
/// see the substitution at startup.
pub fn compute_default_resource_limits() -> (u32, f64) {
    let host_ram_mb = read_host_ram_mb_or_default();
    let host_cpus = read_host_cpus_or_default();

    let memory_mb = ((host_ram_mb as f64) * 0.8).floor() as u32;
    // Round to one decimal place so the value matches Docker's `--cpus`
    // grammar (`format_cpus` formats with `{:.1}`); rounding here keeps
    // the stored field stable across calls and avoids surfacing
    // floating-point noise (`1.6000000000001`) on the `GET /backends` /
    // log lines that show this default.
    let cpus = ((host_cpus * 0.8) * 10.0).round() / 10.0;

    (memory_mb, cpus)
}

/// Best-effort `MemTotal` read from `/proc/meminfo` in megabytes.
/// Falls back to 4096 MB when the file cannot be read or the line is
/// missing — keeps the daemon bootable on a non-Linux dev host (the
/// production target is Linux per spec § "Architecture").
fn read_host_ram_mb_or_default() -> u64 {
    const FALLBACK_MB: u64 = 4096;
    let raw = match std::fs::read_to_string("/proc/meminfo") {
        Ok(s) => s,
        Err(e) => {
            warn!(
                error = %e,
                "container backend: /proc/meminfo unreadable; \
                 using fallback host RAM 4096 MB"
            );
            return FALLBACK_MB;
        }
    };
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            // Format: "MemTotal:        16329048 kB"
            let mut parts = rest.split_whitespace();
            if let (Some(num_str), Some(unit)) = (parts.next(), parts.next())
                && unit.eq_ignore_ascii_case("kB")
                && let Ok(kb) = num_str.parse::<u64>()
            {
                return kb / 1024;
            }
        }
    }
    warn!(
        "container backend: /proc/meminfo missing MemTotal entry; \
         using fallback host RAM 4096 MB"
    );
    FALLBACK_MB
}

/// Map a host (uid, gid) onto the in-container `--user <uid>:<gid>`
/// pair per spec § Hardening line 544 + § Workspace lines 568-571.
///
/// Branch logic:
/// - `daemon_uid == 0` → `(1000, 1000)`. Spec mandates non-root
///   (line 281); root degrades to the spec floor 1000:1000 so a
///   `sudo sandboxd` / `User=root` systemd unit cannot leak root into
///   the container or root-own bind-mounted writes.
/// - `daemon_uid == 1000` → `(1000, 1000)`. Spec primary branch; uid
///   alignment is already trivial.
/// - otherwise → `(daemon_uid, daemon_gid)`. Spec § Workspace's
///   "calling uid/gid when host uid ≠ 1000" so workspace bind-mount
///   writes are owned by the operator on the host.
pub fn map_container_uid_gid(daemon_uid: u32, daemon_gid: u32) -> (u32, u32) {
    match daemon_uid {
        0 | 1000 => (1000, 1000),
        _ => (daemon_uid, daemon_gid),
    }
}

/// Best-effort host CPU count. Falls back to 2.0 when
/// `available_parallelism` errors (e.g. cgroup v1 oddities). Returned as
/// `f64` because the spec's `× 0.8` multiplier produces a fractional
/// value that flows directly into the `--cpus` ceiling.
fn read_host_cpus_or_default() -> f64 {
    match std::thread::available_parallelism() {
        Ok(n) => n.get() as f64,
        Err(e) => {
            warn!(
                error = %e,
                "container backend: available_parallelism failed; \
                 using fallback host CPUs 2.0"
            );
            2.0
        }
    }
}

// ---------------------------------------------------------------------------
// Image ensure (Phase 3B)
// ---------------------------------------------------------------------------

/// Outcome of an [`ensure_image`] call.
///
/// `AlreadyPresent` carries no payload — the image existed already and
/// the caller has no operator-facing news. `Built` carries the
/// first-use warning text, surfaced verbatim to the create-session
/// caller (Phase 3D plumbs it into the HTTP response so the CLI can
/// echo it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsureImageOutcome {
    /// `docker image inspect <tag>` succeeded; no build performed.
    AlreadyPresent,
    /// Image was missing and a `docker build` was just performed.
    /// `warning` is [`LITE_FIRST_USE_WARNING`] verbatim.
    Built { warning: String },
}

/// Process-global lock serialising lite-image builds.
///
/// Two concurrent session creates targeting the same daemon version
/// must not both invoke `docker build` — the image namespace is shared
/// across the host's docker daemon, and a duplicated build wastes
/// minutes without producing a different result. Every [`ensure_image`]
/// invocation acquires this lock before the inspect-then-maybe-build
/// sequence, so the second caller always observes
/// [`EnsureImageOutcome::AlreadyPresent`] after the first releases.
///
/// `OnceLock<Mutex<()>>` rather than a static `Mutex::new(())` because
/// `Mutex::new` is not `const` on all supported toolchains; lazy init
/// matches the pattern most cleanly while staying allocation-free
/// after the first call.
fn container_image_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Build the `sandboxd-lite:<daemon_version>` image if it is missing.
///
/// Synchronous (`fn`, not `async fn`) so callers from sync contexts
/// (tests, daemon startup) can invoke it directly. Async callers must
/// wrap in `tokio::task::spawn_blocking` (CLAUDE.md `spawn_blocking`
/// discipline) — this function does Docker subprocess work, file I/O,
/// and lock acquisition that must not block a tokio worker.
///
/// Invariants:
/// - `daemon_version` flows verbatim into the tag suffix; callers
///   typically pass `env!("CARGO_PKG_VERSION")`. Tests use unique
///   version-shaped strings (`test-build-<rand>`) to avoid colliding
///   with co-running tests.
/// - The image-namespace lock is held across the inspect-then-build
///   sequence; concurrent calls with the same tag observe exactly one
///   `Built` outcome and `AlreadyPresent` for the rest.
/// - Build context: a fresh `tempfile::TempDir` populated with the
///   embedded [`LITE_DOCKERFILE`] and the `sandbox-guest` binary
///   located via [`guest_agent_path`]. The spec mentions
///   `{runtime_dir}/images/lite/` — using a tempdir is functionally
///   equivalent (the staging surface has no purpose beyond the
///   `docker build` invocation) and removes a runtime-dir dependency
///   that 3B does not need.
pub fn ensure_image(daemon_version: &str) -> Result<EnsureImageOutcome, SandboxError> {
    let tag = lite_image_tag_for_version(daemon_version);

    let _guard = container_image_lock()
        .lock()
        .map_err(|_| SandboxError::Internal("container_image_lock poisoned".into()))?;

    if image_present(&tag)? {
        return Ok(EnsureImageOutcome::AlreadyPresent);
    }

    info!(tag = %tag, "lite image missing for daemon version; building");
    // First-use build: caches enabled (no_cache=false) — the image is
    // missing, so there is nothing to cache-bust against; the
    // operator-driven `rebuild_lite_image` path is the place that
    // honors `--no-cache`.
    build_lite_image(&tag, false)?;
    Ok(EnsureImageOutcome::Built {
        warning: LITE_FIRST_USE_WARNING.to_string(),
    })
}

/// `docker image inspect <tag>`: exit 0 → present, exit 1 with stderr
/// matching "no such image" → absent. Any other failure surfaces as
/// [`SandboxError::Gateway`] so callers can distinguish a missing
/// image (proceed to build) from a docker-daemon problem (abort).
fn image_present(tag: &str) -> Result<bool, SandboxError> {
    let mut cmd = std::process::Command::new("docker");
    cmd.args(["image", "inspect", tag]);
    let output = run_with_timeout(&mut cmd, DOCKER_CMD_TIMEOUT, "docker image inspect (lite)")
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                SandboxError::Gateway(format!("failed to spawn docker image inspect: {msg}"))
            }
            other => other,
        })?;

    if output.status.success() {
        return Ok(true);
    }

    let stderr_lower = String::from_utf8_lossy(&output.stderr).to_lowercase();
    if stderr_lower.contains("no such image")
        || stderr_lower.contains("no such object")
        || stderr_lower.contains("error: no such image")
    {
        return Ok(false);
    }
    Err(SandboxError::Gateway(format!(
        "docker image inspect {tag} failed unexpectedly: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// Stage the build context (Dockerfile + sandbox-guest binary) into a
/// fresh tempdir and run `docker build -t <tag> <ctx>`.
///
/// `no_cache` is wired through to `docker build --no-cache` for the
/// rebuild path (M11-S4 Phase 4C). `false` keeps the historical fast
/// path (incremental cache enabled) for the missing-image build flow
/// `ensure_image` uses.
fn build_lite_image(tag: &str, no_cache: bool) -> Result<(), SandboxError> {
    let agent_src = guest_agent_path()?;
    if !agent_src.exists() {
        return Err(SandboxError::Internal(format!(
            "sandbox-guest binary not found at {} (cannot build lite image)",
            agent_src.display()
        )));
    }

    let staging = tempfile::tempdir().map_err(|e| {
        SandboxError::Internal(format!("failed to create lite-image staging tempdir: {e}"))
    })?;

    let dockerfile_path = staging.path().join("Dockerfile");
    std::fs::write(&dockerfile_path, LITE_DOCKERFILE).map_err(|e| {
        SandboxError::Internal(format!(
            "failed to write Dockerfile to {}: {e}",
            dockerfile_path.display()
        ))
    })?;

    let agent_dst = staging.path().join("sandbox-guest");
    std::fs::copy(&agent_src, &agent_dst).map_err(|e| {
        SandboxError::Internal(format!(
            "failed to copy sandbox-guest from {} to {}: {e}",
            agent_src.display(),
            agent_dst.display()
        ))
    })?;

    let mut cmd = std::process::Command::new("docker");
    cmd.arg("build");
    if no_cache {
        cmd.arg("--no-cache");
    }
    cmd.arg("-t").arg(tag).arg(staging.path());
    let output = run_with_timeout(&mut cmd, DOCKER_BUILD_TIMEOUT, "docker build (lite image)")
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                SandboxError::Gateway(format!(
                    "failed to spawn docker build for lite image: {msg}"
                ))
            }
            other => other,
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return Err(SandboxError::Gateway(format!(
            "docker build for {tag} failed: {stderr}"
        )));
    }
    Ok(())
}

/// Rebuild the lite image unconditionally — the operator-driven
/// counterpart to [`ensure_image`].
///
/// `ensure_image` short-circuits when the image is already present;
/// `rebuild_lite_image` always runs `docker build`, which is what
/// `sandbox rebuild-image --backend container` asks for. `no_cache:
/// true` adds `docker build --no-cache` (spec § "rebuild-image"),
/// otherwise the build runs with cache enabled — fast path for
/// incremental rebuilds when the operator just wants to pick up
/// `sandbox-guest` changes without rebuilding every Dockerfile layer.
///
/// Reuses the same `container_image_lock()` mutex as [`ensure_image`]
/// so concurrent ensure-and-rebuild paths cannot race; the lock is
/// container-scoped and independent of Lima's `base_image_lock`, so
/// concurrent `rebuild --backend lima` and `rebuild --backend
/// container` still run in parallel (spec Phase 4C: per-backend lock
/// model).
///
/// Synchronous: callers from async contexts must wrap in
/// `tokio::task::spawn_blocking` (CLAUDE.md `spawn_blocking`
/// discipline) — this function shells out to `docker build` and may
/// block for minutes.
pub fn rebuild_lite_image(daemon_version: &str, no_cache: bool) -> Result<(), SandboxError> {
    let tag = lite_image_tag_for_version(daemon_version);

    let _guard = container_image_lock()
        .lock()
        .map_err(|_| SandboxError::Internal("container_image_lock poisoned".into()))?;

    info!(tag = %tag, no_cache, "rebuilding lite image (operator-requested)");
    build_lite_image(&tag, no_cache)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use enumset::EnumSet;

    use crate::backend::IsolationLevel;
    use crate::session::WorkspaceModeKind;

    fn test_runtime() -> Arc<ContainerRuntime> {
        ContainerRuntime::new(DEFAULT_LITE_IMAGE_TAG, 2048, 2.0, 1000, 1000)
    }

    /// `kind()` reports the static `BackendKind::Container` constant —
    /// the trait dispatch table in `AppState.runtimes` keys on this.
    #[test]
    fn container_runtime_kind_is_container() {
        let rt = test_runtime();
        assert_eq!(rt.kind(), BackendKind::Container);
    }

    /// `capabilities()` mirrors what `GET /backends` (Phase 3C) will
    /// expose for the container backend. Each field is asserted
    /// explicitly so a silent drift surfaces here rather than at a
    /// distant call site.
    #[test]
    fn container_runtime_capabilities_match_spec() {
        let rt = test_runtime();
        let caps = rt.capabilities();
        assert_eq!(caps.kind, BackendKind::Container);
        assert_eq!(caps.isolation, IsolationLevel::Container);
        assert!(!caps.nested_virt, "container forbids nested virt");
        assert!(!caps.privileged_ops, "cap-drop=ALL forbids privileged ops");
        assert!(!caps.raw_network, "CAP_NET_RAW dropped");
        assert!(
            !caps.hardening_flag,
            "--hardened is QEMU-only; container has its own hardening defaults"
        );
        assert!(
            !caps.per_session_no_cache,
            "container has no per-session no-cache slow path"
        );
        assert_eq!(
            caps.workspace_modes,
            EnumSet::all(),
            "M11-S7 advertises both workspace modes — `Shared` (Docker \
             bind-mount via ContainerNetwork.workspace_host_path) and \
             `Clone` (in-guest `git clone` dispatched through GuestConnector \
             after the lite container's entrypoint comes up)",
        );
        assert!(caps.workspace_modes.contains(WorkspaceModeKind::Shared));
        assert!(caps.workspace_modes.contains(WorkspaceModeKind::Clone));
    }

    /// Round-trip the `register_session` / `lookup_session` /
    /// `forget_session` private API — `delete()` relies on the forget
    /// step so a re-create with new network info does not pick up
    /// stale state.
    #[test]
    fn register_session_then_forget() {
        let rt = test_runtime();
        let sid = SessionId::generate();
        let net = ContainerNetwork {
            docker_network: "sandbox-net-x".into(),
            container_ip: "10.0.0.3".parse().unwrap(),
            gateway_ip: "10.0.0.2".parse().unwrap(),
            workspace_host_path: None,
            route_helper_path: None,
            ca_host_path: None,
        };
        rt.register_session(sid, net.clone());
        let got = rt.lookup_session(&sid).expect("registered");
        assert_eq!(got.docker_network, net.docker_network);
        rt.forget_session(&sid);
        assert!(rt.lookup_session(&sid).is_err());
    }

    /// M11-S5 gap #68 contract: the daemon resolves
    /// `WorkspaceMode::Shared { host_path }` into a
    /// `ContainerNetwork.workspace_host_path = Some(<path>)`, and that
    /// value round-trips through `register_session` /
    /// `lookup_session` unchanged so `create()` can render it as a
    /// `docker create --mount type=bind,source=<host_path>,...` flag.
    /// Pinning the round-trip here catches silent drift in the
    /// registry — e.g. accidentally storing a stale clone, or
    /// dropping the optional path on the way back out.
    #[test]
    fn register_session_round_trips_workspace_host_path() {
        let rt = test_runtime();
        let sid = SessionId::generate();
        let host_path = std::path::PathBuf::from("/tmp/workspace-fixture");
        let net = ContainerNetwork {
            docker_network: "sandbox-net-x".into(),
            container_ip: "10.0.0.3".parse().unwrap(),
            gateway_ip: "10.0.0.2".parse().unwrap(),
            workspace_host_path: Some(host_path.clone()),
            // Bare name resolved via $PATH at start time; mirrors how
            // the daemon actually wires it (see main.rs container
            // branch).
            route_helper_path: Some(std::path::PathBuf::from("sandbox-route-helper")),
            ca_host_path: None,
        };
        rt.register_session(sid, net);
        let got = rt.lookup_session(&sid).expect("registered");
        assert_eq!(
            got.workspace_host_path,
            Some(host_path),
            "Shared workspace host path must round-trip through the registry verbatim",
        );
        assert_eq!(
            got.route_helper_path,
            Some(std::path::PathBuf::from("sandbox-route-helper")),
            "route helper path must round-trip so start() can invoke it",
        );
        rt.forget_session(&sid);
    }

    /// `lookup_session` for an unregistered id surfaces an
    /// `InvalidArgument` error pointing at the missing registration —
    /// the daemon-level dispatch bug this guards against.
    #[test]
    fn lookup_session_unregistered_is_invalid_argument() {
        let rt = test_runtime();
        let sid = SessionId::generate();
        let err = rt.lookup_session(&sid).expect_err("must reject");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(msg.contains(&sid.to_string()), "got: {msg}");
                assert!(msg.contains("ContainerRuntime"), "got: {msg}");
            }
            other => panic!("expected InvalidArgument, got: {other:?}"),
        }
    }

    /// M11-S6 follow-up — the per-session sandbox CA is bind-mounted
    /// read-only at `/etc/ssl/certs/sandbox-ca.pem` and surfaced through
    /// the four standard HTTPS-client trust env vars when
    /// `ContainerNetwork.ca_host_path = Some(<host_path>)`.
    ///
    /// Pinned per-arg because the L3 MITM test cluster
    /// (`test_level3_*[container]`, the npm/cargo/github preset tests)
    /// fails with `curl: (60) SSL certificate problem` if any of these
    /// flags drift — the lite container's `--read-only` rootfs makes
    /// Lima's `update-ca-certificates`-based injection impossible, so
    /// the bind-mount + env-var combo is the only trust path the
    /// container has. A regression in the mount string or the env-var
    /// list would silently break HTTPS through the gateway without a
    /// cargo-level signal; this test is that signal.
    ///
    /// Symmetric `None` arm pinned alongside so the no-CA branch
    /// continues to render zero CA-related args (used by the
    /// integration test fixture in
    /// `sandbox-core/tests/integration_container_runtime.rs`, which
    /// deliberately exercises the lifecycle without the CA wiring).
    #[test]
    fn container_runtime_create_includes_ca_mount_when_path_set() {
        let host_path = std::path::PathBuf::from("/var/lib/sandboxd/sessions/abc/ca/cert.pem");
        let net = ContainerNetwork {
            docker_network: "sandbox-net-x".into(),
            container_ip: "10.0.0.3".parse().unwrap(),
            gateway_ip: "10.0.0.2".parse().unwrap(),
            workspace_host_path: None,
            route_helper_path: None,
            ca_host_path: Some(host_path.clone()),
        };

        let args = build_ca_mount_args(&net);

        // Expected literal — pinned in full so any drift in the mount
        // shape (path, dst, readonly flag), env-var name, or env-var
        // ordering surfaces as a diff against this fixture.
        let expected = vec![
            "--mount".to_string(),
            format!(
                "type=bind,src={},dst=/etc/ssl/certs/sandbox-ca.pem,readonly",
                host_path.display()
            ),
            "--env".to_string(),
            "CURL_CA_BUNDLE=/etc/ssl/certs/sandbox-ca.pem".to_string(),
            "--env".to_string(),
            "SSL_CERT_FILE=/etc/ssl/certs/sandbox-ca.pem".to_string(),
            "--env".to_string(),
            "REQUESTS_CA_BUNDLE=/etc/ssl/certs/sandbox-ca.pem".to_string(),
            "--env".to_string(),
            "NODE_EXTRA_CA_CERTS=/etc/ssl/certs/sandbox-ca.pem".to_string(),
        ];
        assert_eq!(
            args, expected,
            "CA bind-mount + env vars must render verbatim — drift here breaks the L3 MITM \
             trust path inside the container",
        );

        // Round-trip the path through the registry so `create()` picks
        // it up via `lookup_session` exactly the way the daemon-side
        // wiring delivers it.
        let rt = test_runtime();
        let sid = SessionId::generate();
        rt.register_session(sid, net);
        let got = rt.lookup_session(&sid).expect("registered");
        assert_eq!(
            got.ca_host_path,
            Some(host_path),
            "ca_host_path must round-trip through the registry verbatim so create() \
             can see what setup_session_networking_lite wrote",
        );
        rt.forget_session(&sid);

        // No-CA arm — the integration fixture and any future Lima-
        // pinned dispatch path that bypasses the CA wiring depends on
        // this returning an empty arg slice (so `args.extend(...)` in
        // `create()` is a no-op).
        let no_ca = ContainerNetwork {
            docker_network: "sandbox-net-y".into(),
            container_ip: "10.0.0.4".parse().unwrap(),
            gateway_ip: "10.0.0.2".parse().unwrap(),
            workspace_host_path: None,
            route_helper_path: None,
            ca_host_path: None,
        };
        assert!(
            build_ca_mount_args(&no_ca).is_empty(),
            "build_ca_mount_args must be a no-op when ca_host_path is None",
        );
    }

    /// `parse_docker_state_status` covers Docker's documented status
    /// vocabulary, mapping to the `RuntimeStatus` variants the daemon
    /// reasons about.
    #[test]
    fn parse_docker_state_status_covers_documented_statuses() {
        assert_eq!(parse_docker_state_status("running"), RuntimeStatus::Running);
        assert_eq!(
            parse_docker_state_status("running\n"),
            RuntimeStatus::Running
        );
        assert_eq!(parse_docker_state_status("created"), RuntimeStatus::Stopped);
        assert_eq!(parse_docker_state_status("exited"), RuntimeStatus::Stopped);
        assert_eq!(parse_docker_state_status("dead"), RuntimeStatus::Error);
        assert_eq!(
            parse_docker_state_status("paused"),
            RuntimeStatus::Unknown("paused".to_string()),
        );
        assert_eq!(
            parse_docker_state_status("restarting"),
            RuntimeStatus::Unknown("restarting".to_string()),
        );
    }

    /// `home_volume_name` follows the spec's `sandbox-home-{session_id}`
    /// shape — pinned because `delete()` constructs the volume name from
    /// the session id and a drift would orphan the volume.
    #[test]
    fn home_volume_name_format() {
        let sid = SessionId::parse("0123456789ab").unwrap();
        assert_eq!(home_volume_name(&sid), "sandbox-home-0123456789ab");
    }

    /// `format_cpus` pins one-decimal precision (spec § "Resource
    /// defaults") so `--cpus 0.8` renders unambiguously.
    #[test]
    fn format_cpus_one_decimal() {
        assert_eq!(format_cpus(2.0), "2.0");
        assert_eq!(format_cpus(0.8), "0.8");
        assert_eq!(format_cpus(1.5), "1.5");
        assert_eq!(format_cpus(1.0 / 3.0), "0.3");
    }

    /// `session_id_from_handle` round-trips against the canonical
    /// `sandbox-{session_id}` shape shared with Lima.
    #[test]
    fn session_id_from_handle_round_trip() {
        let sid = SessionId::parse("0123456789ab").unwrap();
        let handle = RuntimeHandle::from_session_id(&sid);
        assert_eq!(
            ContainerRuntime::session_id_from_handle(&handle).unwrap(),
            sid
        );
    }

    /// Defensive: `session_id_from_handle` rejects a non-`sandbox-`
    /// prefixed handle. Daemon dispatch is responsible for routing
    /// handles to the right backend; this guard catches bugs early.
    #[test]
    fn session_id_from_handle_rejects_non_container_handle() {
        let bogus = RuntimeHandle::from_name("limactl-xyz");
        let err = ContainerRuntime::session_id_from_handle(&bogus)
            .expect_err("bogus handle must be rejected");
        assert!(matches!(err, SandboxError::InvalidArgument(_)));
    }

    /// Defensive: `create()` rejects a Lima-shaped `SessionSpec`
    /// without ever touching `docker`. The HTTP layer (Phase 3D) is
    /// expected to dispatch by `BackendKind` and never pass the wrong
    /// shape down, but this guard prevents a silent-empty-container
    /// bug if the dispatch ever regresses.
    #[tokio::test]
    async fn create_rejects_lima_spec() {
        let rt = test_runtime();
        let sid = SessionId::generate();
        // Register a network entry so we get past the session lookup
        // before reaching the spec-shape check; otherwise the test
        // would conflate two failure modes.
        rt.register_session(
            sid,
            ContainerNetwork {
                docker_network: "sandbox-net-x".into(),
                container_ip: "10.0.0.3".parse().unwrap(),
                gateway_ip: "10.0.0.2".parse().unwrap(),
                workspace_host_path: None,
                route_helper_path: None,
                ca_host_path: None,
            },
        );
        // `hardened: false` so we move past `SessionSpec::validate` (which
        // would reject `hardened: true` against `hardening_flag: false`)
        // and exercise the explicit shape check inside `resource_ceilings`.
        // This pins the dispatch-bug guard, not the validate-layer error.
        let spec = SessionSpec {
            backend_specific: BackendSpecific::Lima {
                hardened: false,
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
            .expect_err("Lima spec must be rejected");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(msg.contains("Lima") || msg.contains("lima"), "got: {msg}");
            }
            other => panic!("expected InvalidArgument, got: {other:?}"),
        }
    }

    /// `resource_ceilings` falls back to the runtime's defaults when
    /// the spec carries `0`/`0.0`; passes through non-zero values
    /// unchanged with f32→f64 lossless widening (M11-S7 todo #67).
    ///
    /// The pre-todo-#67 shape was `cpus: u32` with `as f64` widening
    /// inside the function, which silently truncated `1.5` to `1`.
    /// The fractional case is now pinned below.
    #[test]
    fn resource_ceilings_zero_falls_back_to_defaults() {
        let rt = test_runtime();
        let spec_zero = SessionSpec {
            backend_specific: BackendSpecific::Container {
                memory_mb: 0,
                cpus: 0.0,
            },
            workspace_mode: None,
            repo: None,
            boot_cmd: None,
            template: None,
            disk_gb: None,
        };
        let (mem, cpus) = rt.resource_ceilings(&spec_zero).unwrap();
        assert_eq!(mem, 2048, "0 → default_memory_mb");
        assert!((cpus - 2.0).abs() < f64::EPSILON, "0.0 → default_cpus");

        let spec_explicit = SessionSpec {
            backend_specific: BackendSpecific::Container {
                memory_mb: 4096,
                cpus: 4.0,
            },
            workspace_mode: None,
            repo: None,
            boot_cmd: None,
            template: None,
            disk_gb: None,
        };
        let (mem, cpus) = rt.resource_ceilings(&spec_explicit).unwrap();
        assert_eq!(mem, 4096);
        assert!((cpus - 4.0).abs() < f64::EPSILON);

        // Fractional value: pre-todo-#67 the `as f64` widening lost
        // precision because the source was `u32`. With `f32` source
        // the widening is exact, and `format_cpus` will render `1.5`
        // verbatim into the `--cpus` flag.
        let spec_fractional = SessionSpec {
            backend_specific: BackendSpecific::Container {
                memory_mb: 4096,
                cpus: 1.5,
            },
            workspace_mode: None,
            repo: None,
            boot_cmd: None,
            template: None,
            disk_gb: None,
        };
        let (_mem, cpus) = rt.resource_ceilings(&spec_fractional).unwrap();
        assert!(
            (cpus - 1.5).abs() < f64::EPSILON,
            "fractional cpus must survive f32→f64 widening; got {cpus}"
        );
    }

    /// `capabilities_for_container` is the one source of truth for the
    /// container backend's capability surface — pinned with explicit
    /// asserts so any silent drift fails the test rather than only
    /// surfacing in `GET /backends` integration coverage (3C).
    #[test]
    fn capabilities_for_container_returns_expected_values() {
        let caps = capabilities_for_container();
        assert_eq!(caps.kind, BackendKind::Container);
        assert_eq!(caps.isolation, IsolationLevel::Container);
        assert!(!caps.nested_virt);
        assert!(!caps.privileged_ops);
        assert!(!caps.raw_network);
        assert!(!caps.hardening_flag);
        assert!(!caps.per_session_no_cache);
        assert_eq!(caps.workspace_modes, EnumSet::all());
    }

    /// Smoke test for [`compute_default_resource_limits`]: the function
    /// must always return a usable `(memory_mb, cpus)` pair on the host
    /// that runs the test, even when /proc/meminfo or
    /// `available_parallelism` misbehave (they fall back to 4096 / 2.0).
    /// We can't pin the exact value because it depends on the host the
    /// test runs on, but we can pin invariants: memory ≥ floor(0.8 ×
    /// fallback) and cpus ≥ 0.8 × fallback, both rounded to spec.
    #[test]
    fn compute_default_resource_limits_returns_sane_pair() {
        let (mem, cpus) = compute_default_resource_limits();
        // Lower bound: even on the fallback path the result is
        // floor(4096 × 0.8) = 3276 MB and 0.8 × 2.0 = 1.6 CPUs. On a
        // real host both are at least that high, so this is a strict
        // lower bound that catches accidental sign flips / bad math.
        assert!(
            mem >= 3276,
            "memory_mb must be at least floor(4096 × 0.8) = 3276, got {mem}"
        );
        assert!(
            cpus >= 1.5,
            "cpus must be at least 0.8 × 2.0 = 1.6 (allowing rounding slack), got {cpus}"
        );
        // CPU value must be on the one-decimal grid: multiplying by 10
        // and rounding must yield the same integer as the rounded
        // representation. Any fp noise (e.g. 1.6000000000000001) fails
        // here.
        let scaled = (cpus * 10.0).round();
        assert!(
            (cpus * 10.0 - scaled).abs() < 1e-9,
            "cpus must be exactly on the one-decimal grid, got {cpus}"
        );
    }

    /// `read_host_ram_mb_or_default` parses `/proc/meminfo` on Linux. On
    /// the test host (Linux per spec) we expect a non-fallback value;
    /// at minimum it must exceed the 4096 MB fallback floor so we can
    /// distinguish "real read" from "fallback fired".
    ///
    /// Skipped silently on non-Linux dev hosts: on those the function
    /// is allowed to return the fallback, and the assertion would
    /// flake. Production target is Linux per spec § "Architecture".
    #[test]
    fn read_host_ram_mb_or_default_reads_meminfo_on_linux() {
        if !cfg!(target_os = "linux") {
            return;
        }
        let mb = read_host_ram_mb_or_default();
        // CI runners and dev VMs always have at least 1 GB; if we got
        // exactly the fallback the parser is broken or /proc/meminfo
        // was unreadable, both worth surfacing.
        assert!(
            mb >= 512,
            "expected /proc/meminfo to yield ≥ 512 MB on Linux host, got {mb}"
        );
    }

    /// `read_host_cpus_or_default` returns a positive count. We don't
    /// pin the exact count because it varies across hosts, but it must
    /// be at least 1.0 (single-core fallback floor doesn't apply on
    /// standard nextest hosts).
    #[test]
    fn read_host_cpus_or_default_returns_positive_count() {
        let cpus = read_host_cpus_or_default();
        assert!(cpus >= 1.0, "expected at least 1 CPU, got {cpus}");
    }

    /// `map_container_uid_gid` enforces spec § Hardening line 544 +
    /// § Workspace lines 568-571: root degrades to the 1000:1000 floor,
    /// uid 1000 stays put, and any other uid/gid pass through verbatim
    /// for workspace bind-mount alignment.
    #[test]
    fn map_container_uid_gid_branches_match_spec() {
        assert_eq!(map_container_uid_gid(0, 0), (1000, 1000));
        assert_eq!(map_container_uid_gid(1000, 1000), (1000, 1000));
        assert_eq!(map_container_uid_gid(1500, 1500), (1500, 1500));
        assert_eq!(map_container_uid_gid(1500, 2000), (1500, 2000));
    }
}
