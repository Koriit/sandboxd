use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use ring::digest;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::backend::AsyncReadWrite;
use crate::backend::BackendKind;
use crate::error::SandboxError;
use crate::process::run_with_timeout;
use crate::session::{SessionConfig, SessionId, WorkspaceMode};

// ---------------------------------------------------------------------------
// Timeout constants
// ---------------------------------------------------------------------------

/// Timeout for `limactl create`.
const CREATE_VM_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for `limactl start` (VM boot is slow).
const START_VM_TIMEOUT: Duration = Duration::from_secs(300);

/// Timeout for `limactl stop`.
const STOP_VM_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for `limactl delete`.
const DELETE_VM_TIMEOUT: Duration = Duration::from_secs(60);

// INSTALL_GUEST_AGENT_STEP_TIMEOUT was removed: the install
// sequence now runs inside sandbox-lima-helper (install-guest-agent subcommand)
// with its own per-step budget. The total wall-clock is INSTALL_TOTAL_TIMEOUT
// inside install_guest_agent().

/// Timeout for `limactl list`.
const LIST_VMS_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for the `read-owner-marker` helper subcommand. This is a simple
/// file read — no limactl invocation, no network, no long-running process.
const READ_OWNER_MARKER_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for `limactl create` when building the base image. The base
/// image build path downloads the Ubuntu 24.04 cloud-image qcow2
/// (`ubuntu-24.04-server-cloudimg-amd64.img`, ~580 MiB) on first use.
/// Observed effective throughput from `cloud-images.ubuntu.com` varies
/// wildly — a fast mirror finishes in 60-120 s, but slow-network hosts
/// see floors as low as ~1.3 MB/s, which makes the full download take
/// ~7-8 minutes. The 1200 s budget here clears that observed floor
/// with ample headroom for the post-download `limactl create` work
/// (qcow2 cloning, cloud-config generation) and any one-off network
/// jitter.
///
/// This bound is daemon-side and does not directly bound any e2e test:
/// the harness's session-scoped pre-warm fixture (`_ensure_base_image`
/// in `tests/e2e/conftest.py`) runs the rebuild *outside* any per-test
/// pytest-timeout window. The fixture itself caps the rebuild
/// subprocess at 1800 s, so 1200 s here leaves room without papering
/// over a genuinely-stalled download.
///
/// This is a one-time cost amortized over every subsequent session
/// against the cached base image — the harness's
/// `_reset_sandbox_state_dir` deliberately preserves the Lima
/// download cache and the golden base VM across pytest sessions so
/// the freshness check short-circuits the rebuild after the first
/// successful pre-warm.
const BASE_CREATE_TIMEOUT: Duration = Duration::from_secs(1200);

/// Timeout for `limactl start` when booting the base image (cloud-init
/// provisioning runs on first boot: installs socat, git, Docker via
/// apt, guest agent). 600 s budget — the cloud-init scripts use
/// HTTPS apt sources with a 5 s Acquire::http::Timeout + ForceIPv4
/// (see the base template's `/etc/apt/apt.conf.d/99sandbox` stanza)
/// so a warm-network provision completes in ~60-120 s. If the build
/// exceeds this budget, investigate the provisioning steps rather than
/// raising this constant.
const BASE_START_TIMEOUT: Duration = Duration::from_secs(600);

/// Graceful budget for `limactl stop` of the base image. Healthy
/// guests under normal disk I/O finish well under this; under
/// contention we fall back to `-f`. See `build_base_image_inner`.
const BASE_STOP_GRACEFUL_BUDGET: Duration = Duration::from_secs(60);

/// Force-stop (-f) budget for the fallback path. Issues SIGTERM to
/// QEMU directly; qcow2 flushes via QEMU's own exit handler.
const BASE_STOP_FORCE_BUDGET: Duration = Duration::from_secs(60);

/// Timeout for `limactl clone`.
const CLONE_VM_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Golden image constants
// ---------------------------------------------------------------------------

/// Default VM name for the pre-provisioned golden base image.
///
/// Callers that don't need to pin a specific name (typically tests) can
/// pass this into [`LimaManager::new`] or [`LimaManager::with_helper_path`].
/// The daemon resolves the actual name from the `SANDBOX_BASE_VM_NAME`
/// environment variable at startup so production and test daemons don't
/// collide on a single user-global Lima instance.
pub const DEFAULT_BASE_VM_NAME: &str = "sandbox-base";

/// Maximum age (in days) before the base image is considered stale and
/// should be rebuilt.
const BASE_IMAGE_MAX_AGE_DAYS: u64 = 10;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Status of a Lima-managed virtual machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmStatus {
    Running,
    Stopped,
    /// Any status string not explicitly handled.
    Unknown(String),
}

/// Summary information for a sandbox VM discovered via `limactl list`.
#[derive(Debug, Clone)]
pub struct VmInfo {
    pub name: String,
    pub status: VmStatus,
    /// Session ID parsed from the `sandbox-{id}` naming convention.
    pub session_id: Option<SessionId>,
}

/// Metadata for the golden base image, persisted as JSON alongside the VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseImageMeta {
    /// When the base image was built.
    pub built_at: chrono::DateTime<chrono::Utc>,
    /// SHA256 hash of the inputs (template content + guest agent binary)
    /// that produced this image.
    pub content_hash: String,
}

/// Status of the pre-provisioned golden base image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseImageStatus {
    /// No base image VM exists.
    Missing,
    /// The base image is up-to-date and ready for cloning.
    Fresh,
    /// The base image exists but should be rebuilt.
    Stale {
        /// Age of the base image in days.
        age_days: u64,
        /// Whether the content hash differs from the current inputs.
        hash_mismatch: bool,
    },
}

// ---------------------------------------------------------------------------
// Per-operator LIMA_HOME
// ---------------------------------------------------------------------------

/// Root directory for per-operator Lima state.
///
/// Each daemon uid gets its own subtree; within it each operator gets an
/// isolated LIMA_HOME at `/var/lib/sandboxd/<daemon_uid>/<op_uid>/lima/`.
/// The directory is owned `sandbox:sandbox 0750` with POSIX ACLs granting
/// the operator rwx on the directory itself.
///
/// Installed at startup by `make setup-dev-env` and provisioned on first
/// use by [`ensure_operator_lima_home`].
pub const SANDBOXD_STATE_ROOT: &str = "/var/lib/sandboxd";

/// Env-var name that `test-env-override` builds consult to redirect the
/// sandboxd state root away from `/var/lib/sandboxd`. Integration tests
/// set this to a tempdir so `operator_lima_home` and
/// `ensure_operator_lima_home` resolve inside the test sandbox rather than
/// touching the production state root.
///
/// This constant is also used by `sandbox-lima-helper` (as
/// `SANDBOX_LIMA_HELPER_TEST_STATE_ROOT`) to redirect `read-user-key`'s
/// key-file path. Both sides must agree on the env var name.
pub const STATE_ROOT_OVERRIDE_ENV: &str = "SANDBOX_LIMA_HELPER_TEST_STATE_ROOT";

/// Pure path-construction kernel for the per-operator LIMA_HOME.
///
/// Separated from [`operator_lima_home`] so tests can assert the 3-level path
/// scheme (`{root}/{daemon_uid}/{op_uid}/lima`) without depending on the live
/// process uid.
///
/// - `root`       — state-root prefix (production: [`SANDBOXD_STATE_ROOT`];
///   tests: a caller-supplied tempdir path).
/// - `daemon_uid` — uid the daemon process itself runs as; the first variable
///   segment, isolating per-daemon state trees on the same host.
/// - `op_uid`     — the human operator's uid; the second variable segment,
///   isolating per-operator Lima state within one daemon's tree.
pub(crate) fn operator_lima_home_inner(root: &str, daemon_uid: u32, op_uid: u32) -> PathBuf {
    PathBuf::from(format!("{root}/{daemon_uid}/{op_uid}/lima"))
}

/// Maximum length of a Unix-domain socket address on macOS, **including** the
/// NUL terminator (`sizeof(sockaddr_un.sun_path)`).
///
/// Linux allows 108; the tighter macOS bound is the one every path scheme in
/// this tree has to clear, so it is the one stated here and the one asserted
/// against.
pub const MACOS_UNIX_PATH_MAX: usize = 104;

/// Path of the SSH control socket Lima binds for an instance.
///
/// Lima binds `<instance-dir>/ssh.sock` and **resolves symlinks before
/// binding**, so a shorter path spelled with a symlink does not shorten the
/// address that reaches the kernel. Exceed [`MACOS_UNIX_PATH_MAX`] and the VM
/// fails to start with an error that does not name path length as the cause.
///
/// Three things consume the headroom: a longer state root, another level of
/// nesting under it, and a longer instance-name scheme. Do not add one without
/// recomputing — [`instance_socket_path_fits`] is the computation.
pub fn instance_ssh_socket_path(lima_home: &Path, instance: &str) -> PathBuf {
    lima_home.join(instance).join("ssh.sock")
}

/// Whether an instance's SSH socket address fits in `sun_path`.
///
/// Strictly less than the bound: [`MACOS_UNIX_PATH_MAX`] counts the NUL
/// terminator, so a path of exactly that many bytes does not fit.
pub fn instance_socket_path_fits(lima_home: &Path, instance: &str) -> bool {
    instance_ssh_socket_path(lima_home, instance)
        .as_os_str()
        .len()
        < MACOS_UNIX_PATH_MAX
}

/// Return the LIMA_HOME path for the given operator uid.
///
/// Path scheme: `{state_root}/{daemon_uid}/{op_uid}/lima`
///
/// - `daemon_uid` is derived from `getuid()` (kernel-provided, not
///   caller-supplied) so each daemon uid produces an isolated subtree.
/// - `op_uid` is the human operator's uid (unchanged from the caller's
///   `--op-uid` argument).
///
/// In `test-env-override` builds, the `SANDBOX_LIMA_HELPER_TEST_STATE_ROOT`
/// env var can redirect the state root to a tempdir so integration tests
/// do not touch `/var/lib/sandboxd/`.  The daemon-uid segment is still
/// inserted even when the override is active.
pub fn operator_lima_home(op_uid: u32) -> PathBuf {
    let daemon_uid = nix::unistd::Uid::current().as_raw();
    #[cfg(feature = "test-env-override")]
    if let Ok(root) = std::env::var(STATE_ROOT_OVERRIDE_ENV)
        && !root.is_empty()
    {
        return operator_lima_home_inner(&root, daemon_uid, op_uid);
    }
    operator_lima_home_inner(SANDBOXD_STATE_ROOT, daemon_uid, op_uid)
}

/// Resolve the per-daemon root directory for Lima state:
/// `{state_root}/{daemon_uid}/`.
///
/// The daemon (uid `sandbox`) owns this directory and can enumerate its
/// immediate subdirectories to discover operator uids. This is the root
/// that `enumerate_operator_uids_from_fs` scans.
///
/// Respects the `test-env-override` state root redirect.
fn daemon_lima_root() -> PathBuf {
    let daemon_uid = nix::unistd::Uid::current().as_raw();
    let state_root = {
        #[cfg(feature = "test-env-override")]
        if let Ok(root) = std::env::var(STATE_ROOT_OVERRIDE_ENV)
            && !root.is_empty()
        {
            root
        } else {
            SANDBOXD_STATE_ROOT.to_string()
        }
        #[cfg(not(feature = "test-env-override"))]
        SANDBOXD_STATE_ROOT.to_string()
    };
    PathBuf::from(format!("{state_root}/{daemon_uid}"))
}

/// Enumerate operator uids by scanning the daemon-owned filesystem tree.
///
/// The daemon (uid `sandbox`) can `readdir` the tree it owns:
/// `{state_root}/{daemon_uid}/` — any immediate numeric subdir that also
/// contains a `lima/` child is an operator uid.
///
/// This is the resolution for a gap in `reconcile()`: `reconcile`
/// only enumerates op_uids from session rows, missing operators whose sessions
/// have all been deleted. This function discovers op_uids from the filesystem
/// regardless of session-row state, closing the orphan-VM leak.
///
/// Non-numeric subdirs and subdirs without a `lima/` child are silently
/// skipped. Read errors log at `warn!` and return an empty list.
pub fn enumerate_operator_uids_from_fs() -> Vec<u32> {
    let root = daemon_lima_root();
    let mut result = Vec::new();

    let rd = match std::fs::read_dir(&root) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // State root not yet created — no operators exist yet.
            return result;
        }
        Err(e) => {
            tracing::warn!(
                path = %root.display(),
                error = %e,
                "enumerate_operator_uids_from_fs: failed to read daemon root; \
                 skipping Lima orphan scan"
            );
            return result;
        }
    };

    for entry in rd.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        // Parse as a u32 uid.
        let Ok(uid) = name_str.parse::<u32>() else {
            continue;
        };
        // Skip root op-uid (would be rejected by the helper anyway).
        if uid == 0 {
            continue;
        }
        // Verify the `lima/` sub-directory exists — without it there are
        // no VMs to enumerate, and `get_or_create` would provision an empty
        // LIMA_HOME unnecessarily.
        let lima_child = entry.path().join("lima");
        if lima_child.is_dir() {
            result.push(uid);
        }
    }

    result
}

/// Tally of VMs reaped by a single [`reap_lima_orphans`] pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LimaReaperReport {
    pub vms_reaped: u32,
    pub vms_skipped_foreign: u32,
    pub vms_skipped_live: u32,
    pub op_uids_scanned: u32,
}

/// Decision produced by [`decide_lima_vm`] for a single VM entry.
///
/// Extracted into its own type so the classification logic can be unit-tested
/// independently of the I/O that executes the decision (delete_vm, logging).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimaVmDecision {
    /// VM should be reaped: orphaned (not in live set) and owned by this daemon.
    Reap,
    /// VM is in the live set — skip unconditionally.
    SkipLive,
    /// VM has no parseable session id (e.g. base image `sandbox-base`) — skip.
    SkipNoSessionId,
    /// VM's owner marker belongs to a different daemon pool — skip to avoid
    /// cross-daemon reaping in a shared-LIMA_HOME edge case.
    SkipForeignMarker { marker_pool: String },
}

/// Classify a single Lima VM for the orphan reaper.
///
/// Pure function over `(session_id, marker, live, my_pool)` with no I/O.
/// Extracted from [`reap_lima_orphans`] so the classification logic can be
/// tested without a real Lima helper, real VMs, or real registry.
///
/// Decision rules (in priority order):
/// 1. `session_id` is `None` → [`LimaVmDecision::SkipNoSessionId`]
///    (base image VMs whose names don't parse as 12-hex).
/// 2. `session_id` is in `live` → [`LimaVmDecision::SkipLive`].
/// 3. `marker` is `Some(pool)` and `pool != my_pool` →
///    [`LimaVmDecision::SkipForeignMarker`]
///    (shared-LIMA_HOME defense: a VM belonging to another daemon).
/// 4. Otherwise (marker matches my_pool, or marker is absent for a legacy VM
///    within the daemon's own LIMA_HOME tree) → [`LimaVmDecision::Reap`].
///
/// These rules are not the whole of what survives a reap pass. The gateway VM
/// is excluded by name in [`reap_lima_orphans_inner`], before this function is
/// consulted, because it is not a session VM and has no session id to classify
/// by. Reading the rules above as the complete account would put a
/// `Reap` in front of the one VM every running session's egress depends on.
pub fn decide_lima_vm(
    session_id: Option<&crate::session::SessionId>,
    marker: Option<&str>,
    live: &std::collections::HashSet<crate::session::SessionId>,
    my_pool: &str,
) -> LimaVmDecision {
    let Some(sid) = session_id else {
        return LimaVmDecision::SkipNoSessionId;
    };
    if live.contains(sid) {
        return LimaVmDecision::SkipLive;
    }
    if let Some(pool) = marker {
        if pool != my_pool {
            return LimaVmDecision::SkipForeignMarker {
                marker_pool: pool.to_string(),
            };
        }
    }
    LimaVmDecision::Reap
}

/// Per-operator Lima I/O operations the reaper needs. Extracted as a trait
/// so the `reap_lima_orphans` core loop can be tested over fakes without a
/// real `LimaManager`, real helper binary, or real VMs.
///
/// Production wiring uses [`RegistryLimaReaperOps`]; tests inject a
/// [`crate::lima::FakeLimaReaperOps`] (cfg(test)).
pub trait LimaReaperOps {
    /// List sandbox-prefixed VMs for an operator uid. Returns `None` on any
    /// error so the caller skips the uid and continues.
    fn list_vms(&self, op_uid: u32) -> Option<Vec<VmInfo>>;

    /// Read the owner marker for a VM. Returns `None` when absent or on error.
    fn read_marker(&self, op_uid: u32, session_id: &crate::session::SessionId) -> Option<String>;

    /// Delete a VM. Returns `Err` on failure; the caller logs and continues.
    fn delete_vm(
        &self,
        op_uid: u32,
        session_id: &crate::session::SessionId,
    ) -> Result<(), SandboxError>;
}

/// Production [`LimaReaperOps`] backed by the real [`LimaManagerRegistry`].
pub struct RegistryLimaReaperOps<'a> {
    registry: &'a LimaManagerRegistry,
}

impl<'a> RegistryLimaReaperOps<'a> {
    fn new(registry: &'a LimaManagerRegistry) -> Self {
        Self { registry }
    }
}

impl LimaReaperOps for RegistryLimaReaperOps<'_> {
    fn list_vms(&self, op_uid: u32) -> Option<Vec<VmInfo>> {
        // `get_or_create` runs `ensure_operator_lima_home` (mkdir + ACL
        // shell-out, ~10 s timeout) on the first call for this uid. The mkdir
        // runs before anything looks the uid up, so a uid found on disk but no
        // longer in passwd still gets its directory: macOS then fails here
        // resolving the username `chmod +a` needs, while the Linux branch
        // resolves nothing — its ACL spec is numeric — so on that path the
        // uid is refused by the helper on the `list_vms` call below, not
        // here. Either way the operator is warned about and skipped.
        let mgr = match self.registry.get_or_create(op_uid) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    op_uid,
                    error = %e,
                    "lima orphan reaper: failed to get/create manager for operator; skipping"
                );
                return None;
            }
        };
        match mgr.list_vms() {
            Ok(vms) => Some(vms),
            Err(e) => {
                tracing::warn!(
                    op_uid,
                    error = %e,
                    "lima orphan reaper: failed to list VMs for operator; skipping"
                );
                None
            }
        }
    }

    fn read_marker(&self, op_uid: u32, session_id: &crate::session::SessionId) -> Option<String> {
        let mgr = self.registry.get_or_create(op_uid).ok()?;
        mgr.read_owner_marker(session_id)
    }

    fn delete_vm(
        &self,
        op_uid: u32,
        session_id: &crate::session::SessionId,
    ) -> Result<(), SandboxError> {
        let mgr = self.registry.get_or_create(op_uid).map_err(|e| {
            SandboxError::Internal(format!(
                "lima orphan reaper: failed to get manager for op {op_uid}: {e}"
            ))
        })?;
        mgr.delete_vm(session_id)
    }
}

/// Whether a Lima instance name belongs to a gateway VM.
///
/// The reaper is platform-neutral and the gateway VM is not: it exists only on
/// macOS, where the gateway runs inside a Lima instance instead of a container
/// on the host. So the question is answered by the module that owns the name
/// where there is one to own, and answered `false` where no gateway instance
/// can exist. That `false` is a statement about the platform, not a default —
/// a Linux host has no gateway Lima instance for this to be wrong about.
#[cfg(target_os = "macos")]
fn is_gateway_instance(name: &str) -> bool {
    crate::gateway_lima::is_gateway_instance_name(name)
}

/// See the macOS definition above; there is no gateway Lima instance here.
#[cfg(not(target_os = "macos"))]
fn is_gateway_instance(_name: &str) -> bool {
    false
}

/// Core loop of the Lima orphan reaper, parametrised over injected I/O ops.
///
/// Takes an explicit `op_uids` slice (the caller decides how to enumerate
/// them — production passes the FS-scanned set; tests inject a fixed list).
/// All per-VM I/O is dispatched through `ops` so the loop is hermetically
/// testable without a real helper or VMs.
pub fn reap_lima_orphans_inner(
    op_uids: &[u32],
    ops: &dyn LimaReaperOps,
    live: &std::collections::HashSet<crate::session::SessionId>,
    my_pool: &str,
) -> LimaReaperReport {
    let mut report = LimaReaperReport::default();

    for &op_uid in op_uids {
        report.op_uids_scanned += 1;
        let vms = match ops.list_vms(op_uid) {
            Some(v) => v,
            None => continue,
        };

        for vm in &vms {
            // The gateway VM is not a candidate. It is daemon infrastructure
            // rather than a session VM: it carries no owner marker (nothing
            // stamps one) and no session id (its name is not a session name),
            // so every input `decide_lima_vm` classifies by is absent for it.
            // Deleting it takes egress away from every running session on the
            // host, so it is excluded here, by name, ahead of the classifier —
            // not left to be protected by the shape of a name it happens not
            // to have.
            if is_gateway_instance(&vm.name) {
                continue;
            }

            // Only read the owner marker when we have a session_id.
            let marker = vm
                .session_id
                .as_ref()
                .and_then(|sid| ops.read_marker(op_uid, sid));
            let decision = decide_lima_vm(vm.session_id.as_ref(), marker.as_deref(), live, my_pool);

            match decision {
                LimaVmDecision::SkipNoSessionId => {}
                LimaVmDecision::SkipLive => {
                    report.vms_skipped_live += 1;
                }
                LimaVmDecision::SkipForeignMarker { ref marker_pool } => {
                    tracing::info!(
                        op_uid,
                        vm = %vm.name,
                        marker_pool = %marker_pool,
                        "lima orphan reaper: VM marker belongs to a different daemon pool; skipping"
                    );
                    report.vms_skipped_foreign += 1;
                }
                LimaVmDecision::Reap => {
                    let sid = vm
                        .session_id
                        .expect("Reap decision requires Some(session_id)");
                    match ops.delete_vm(op_uid, &sid) {
                        Ok(()) => {
                            tracing::info!(
                                op_uid,
                                vm = %vm.name,
                                session_id = %sid,
                                "lima orphan reaper: removed VM with no owning session"
                            );
                            report.vms_reaped += 1;
                        }
                        Err(e) => {
                            tracing::warn!(
                                op_uid,
                                vm = %vm.name,
                                session_id = %sid,
                                error = %e,
                                "lima orphan reaper: failed to delete VM; continuing"
                            );
                        }
                    }
                }
            }
        }
    }

    tracing::info!(
        vms_reaped = report.vms_reaped,
        vms_skipped_foreign = report.vms_skipped_foreign,
        vms_skipped_live = report.vms_skipped_live,
        op_uids_scanned = report.op_uids_scanned,
        "lima orphan reaper: pass complete"
    );

    report
}

/// Enumerate and reap orphaned Lima VMs at daemon startup.
///
/// This runs AFTER `reconcile()` (which is state-only) and parallel to
/// `reap_orphans` (the Docker reaper). It closes the gap `reconcile` leaves
/// open: `reconcile` only enumerates op_uids from session rows, so operators
/// whose last session was deleted never have their VMs cleaned up.
///
/// Algorithm:
/// 1. Enumerate op_uids from the daemon-owned FS tree (not from session rows).
/// 2. For each op_uid: dispatch via [`RegistryLimaReaperOps`] to list/reap.
/// 3. For each VM: classify via [`decide_lima_vm`], then execute the decision.
/// 4. Best-effort and idempotent: per-VM and per-operator errors log at `warn!`
///    and continue.
pub fn reap_lima_orphans(
    registry: &LimaManagerRegistry,
    live: &std::collections::HashSet<crate::session::SessionId>,
    my_pool: &str,
) -> LimaReaperReport {
    let op_uids = enumerate_operator_uids_from_fs();
    let ops = RegistryLimaReaperOps::new(registry);
    reap_lima_orphans_inner(&op_uids, &ops, live, my_pool)
}

/// [`reap_lima_orphans`], restricted to operators the daemon can currently act
/// as.
///
/// Identical classification; the only difference is which operators are
/// scanned. The filesystem scan still decides which per-operator LIMA_HOMEs
/// exist and `reachable` decides which of those this pass opens, so an
/// operator named in `reachable` who has no LIMA_HOME is not scanned and does
/// not get one: `get_or_create` provisions the directory as a side effect of
/// being asked for it, and a reaper has no business creating the tree it is
/// auditing.
///
/// # Why a reaper has to be told who is reachable
///
/// Every `limactl` call for an operator is made *as* that operator — on Linux
/// by `sandbox-lima-helper` pivoting to their uid, on macOS by their own
/// LaunchAgent over the broker. The macOS half answers only while that agent
/// is checked in; with no agent the call fails, so
/// [`reap_lima_orphans_inner`] logs a warning and moves on. Naming the
/// reachable set turns an attempt that could not have succeeded into one that
/// was never made. The same VMs are deleted either way — this narrows the
/// scan, it does not widen it.
///
/// # Why this is macOS-only
///
/// That premise is, so this is. `reachable` is the daemon's own uid plus the
/// operators whose agent is checked in, and only the macOS path has an agent
/// to check in. Check-in is not the only condition on that set: the broker's
/// `classify_peer_uid` rejects uid 0, rejects uids below the system floor, and
/// requires sandbox-group membership via `getgrouplist(3)` before the registry
/// records the uid. So the macOS set is host configuration *and* liveness, and
/// `sandbox-lima-helper` gates on the same configuration — the uid it is asked
/// to become must be non-zero, must resolve via `getpwuid_r`, and must be in
/// the sandbox group, all three checked before its single `setresuid`.
///
/// It is the liveness half Linux has no analogue for. Whether the helper will
/// pivot to a given uid turns on passwd and group state the daemon keeps no
/// registry of; to predict it the daemon would have to repeat the helper's own
/// lookups. Attempting instead ends in a denial the reaper already handles —
/// `RegistryLimaReaperOps::list_vms` logs a `warn!` naming the operator and the
/// pass moves on — which is why nothing on Linux computes such a set.
///
/// Naming a set is free only when the operators it leaves out could not have
/// been acted for at all; that is what the section above argues, and it is the
/// whole of the licence. Leave out an operator who could have been acted for
/// and the pass stops collecting their orphans, with nothing in the log to say
/// so. Linux wants [`reap_lima_orphans`], which scans the whole tree. The
/// Docker counterpart, `backend::reap_orphans_per_gateway_owner`, is gated for
/// the same reason.
///
/// # `live` stays the global union
///
/// `reachable` narrows *whose VMs are examined* and must never narrow the set
/// of sessions considered live. A VM is reaped when its session id is absent
/// from `live`, so a `live` filtered to one operator would classify every
/// other operator's running session as an orphan and delete its VM. Recovery
/// narrows its session list, for reasons that belong to recovery; the reaper
/// must not, and the two land together looking symmetric. They are not: the
/// asymmetry is the difference between a session's VM surviving and being
/// deleted.
#[cfg(target_os = "macos")]
pub fn reap_lima_orphans_for_operators(
    registry: &LimaManagerRegistry,
    reachable: &[u32],
    live: &std::collections::HashSet<crate::session::SessionId>,
    my_pool: &str,
) -> LimaReaperReport {
    let op_uids = scan_scoped_to_reachable(enumerate_operator_uids_from_fs(), reachable);
    let ops = RegistryLimaReaperOps::new(registry);
    reap_lima_orphans_inner(&op_uids, &ops, live, my_pool)
}

/// The operator uids a scoped reap pass scans: those with a LIMA_HOME on disk
/// *and* named as reachable.
///
/// Both conditions are necessary and neither implies the other. An operator
/// with VMs on disk who is not reachable cannot be listed; a reachable
/// operator with nothing on disk has nothing to list.
#[cfg(target_os = "macos")]
fn scan_scoped_to_reachable(on_disk: Vec<u32>, reachable: &[u32]) -> Vec<u32> {
    on_disk
        .into_iter()
        .filter(|uid| reachable.contains(uid))
        .collect()
}

/// Ensure `/var/lib/sandboxd/<daemon_uid>/<op_uid>/lima/` exists and carries
/// the correct POSIX ACL so helper-pivoted `limactl` (running as `op_uid`)
/// can write into it.
///
/// Concrete steps:
///
/// 1. `mkdir -p /var/lib/sandboxd/<daemon_uid>/<op_uid>/lima/`
/// 2. `setfacl -m u:<op_uid>:rwx,d:g::---,d:o::--- <dir>`
///
/// Idempotent: safe to call on every session-create.  The directory
/// creation uses `std::fs::create_dir_all`, which is a no-op if the
/// directory already exists.  `setfacl` is idempotent by spec.
///
/// Returns the path of the provisioned LIMA_HOME directory.
pub fn ensure_operator_lima_home(op_uid: u32) -> Result<PathBuf, SandboxError> {
    let lima_home = operator_lima_home(op_uid);

    // Step 1: mkdir -p
    std::fs::create_dir_all(&lima_home).map_err(|e| {
        SandboxError::Internal(format!(
            "failed to create per-operator LIMA_HOME {}: {e}",
            lima_home.display()
        ))
    })?;

    // macOS: cross-uid setup mirroring the Linux setfacl grant.
    //
    // macOS is cross-uid just like Linux: the daemon runs as its own uid
    // (_sandboxd) while limactl runs as the operator uid.  `setfacl` is a
    // Linux POSIX-ACL tool and does not exist on macOS.  Instead we use
    // `chmod +a` (macOS NFSv4/Darwin ACL) to grant the operator read/write/
    // traverse access to the LIMA_HOME directory.
    //
    // Two steps:
    //
    // 1. `chmod 0700` — daemon owns the dir, no group/other access.
    //
    // 2. `chmod +a "user:<username> allow list,search,add_file,
    //     add_subdirectory,delete_child,readattr,writeattr,
    //     readextattr,writeextattr,readsecurity"` — grant the operator ACE
    //     on the directory itself ONLY.
    //
    //    CRITICAL — no `file_inherit` / `directory_inherit` in the ACE.
    //    Inheritance would propagate into every child, including
    //    `_config/user` (Lima's SSH private key).  OpenSSH StrictKeyfileMode
    //    calls stat(2) and rejects any key with a non-empty ACL (the `+` bit
    //    in `ls -le` output) whose effective mode & 077 ≠ 0.  Without
    //    inheritance the SSH key is a plain 0600 file with no ACL.
    //    The operator runs limactl via the helper post-setresuid, so it owns
    //    every file it creates and accesses them via owner bits — no
    //    propagation needed.
    //
    // `chmod +a` on macOS requires a username, not a numeric uid (the kernel
    // resolves it to a UUID via Directory Services; a bare numeric uid fails
    // "Unable to translate to a UUID").  We resolve op_uid → name via the
    // `nix` crate (NSS lookup, same as the kernel would do).
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lima_home, std::fs::Permissions::from_mode(0o700)).map_err(
            |e| {
                SandboxError::Internal(format!(
                    "failed to chmod 0700 per-operator LIMA_HOME {}: {e}",
                    lima_home.display()
                ))
            },
        )?;

        // Resolve op_uid to a username for chmod +a.
        let username = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(op_uid))
            .map_err(|e| {
                SandboxError::Internal(format!("failed to look up username for uid {op_uid}: {e}"))
            })?
            .ok_or_else(|| SandboxError::Internal(format!("no passwd entry for uid {op_uid}")))?
            .name;

        // Grant the operator ACE on the directory. No file_inherit or
        // directory_inherit — ACE must not propagate to children so the SSH
        // key stays a plain 0600 file.
        let ace = format!(
            "user:{username} allow \
             list,search,add_file,add_subdirectory,delete_child,\
             readattr,writeattr,readextattr,writeextattr,readsecurity"
        );
        let output = run_with_timeout(
            Command::new("chmod").arg("+a").arg(&ace).arg(&lima_home),
            std::time::Duration::from_secs(10),
            "chmod +a",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Internal(format!(
                "chmod +a on {} failed: {stderr}",
                lima_home.display()
            )));
        }

        info!(
            op_uid,
            path = %lima_home.display(),
            "per-operator LIMA_HOME provisioned (macOS, chmod +a)"
        );
        return Ok(lima_home);
    }

    // Linux only: apply POSIX ACLs via setfacl. On macOS the early return
    // above handles LIMA_HOME provisioning without setfacl.
    //
    // setfacl -m u:<op_uid>:rwx,d:g::---,d:o::--- <dir>
    //
    //   - `u:<op_uid>:rwx` — access ACL on the top dir only: operator can
    //                         traverse, read, and write the LIMA_HOME root
    //                         (e.g. the operator-uid limactl creates the
    //                         per-instance subdirs and writes `_config/user`
    //                         there). Daemon-written inputs the operator must
    //                         read (base template, QEMU wrapper) live in the
    //                         sibling state root, not here — see
    //                         `write_operator_readable_template`.
    //
    //   - NO `d:u:<op_uid>:rwx` — intentionally omitted. A default
    //                         named-user ACL would propagate into every
    //                         child (including `_config/user`, Lima's SSH
    //                         private key). Linux's ACL mask rule forces
    //                         st_mode group bits ≥ the mask whenever a
    //                         named-user entry exists. OpenSSH does NOT
    //                         understand POSIX ACLs: it calls stat(2) and
    //                         rejects any key whose st_mode & 077 ≠ 0
    //                         ("bad permissions"). With a default named-user
    //                         entry, `_config/user` always shows up as
    //                         0640 or 0644 to stat, causing the hostagent
    //                         to loop "bad permissions" for the full 600 s
    //                         start timeout and never reach SSH.
    //                         The operator runs limactl via the helper
    //                         post-setresuid, so it OWNS every file it
    //                         creates and accesses them via owner bits —
    //                         no named-user ACL propagation is needed.
    //
    //   - `d:g::---`       — default group: suppress group read on all
    //                         children (belt-and-suspenders for the mask).
    //   - `d:o::---`       — default other: suppress world read on all
    //                         children.
    //
    // Numeric uid form avoids an NSS round-trip and matches the spec
    // prescription exactly.
    #[cfg(not(target_os = "macos"))]
    {
        let acl_spec = format!("u:{op_uid}:rwx,d:g::---,d:o::---");
        let output = run_with_timeout(
            Command::new("setfacl")
                .arg("-m")
                .arg(&acl_spec)
                .arg(&lima_home),
            std::time::Duration::from_secs(10),
            "setfacl",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Internal(format!(
                "setfacl on {} failed: {stderr}",
                lima_home.display()
            )));
        }

        info!(
            op_uid,
            path = %lima_home.display(),
            "per-operator LIMA_HOME provisioned"
        );
        return Ok(lima_home);
    }

    // Unreachable on Linux (the cfg(not(macos)) block above returns); on macOS
    // the cfg(macos) block above also returns. The trailing Ok satisfies the
    // type-checker when both cfg blocks are absent (e.g., a hypothetical third
    // OS).
    #[allow(unreachable_code)]
    Ok(lima_home)
}

// ---------------------------------------------------------------------------
// LimaExecutor trait — operator-execution seam
// ---------------------------------------------------------------------------

/// A one-shot Lima helper operation, represented as a typed value.
///
/// Each variant corresponds to one subcommand of `sandbox-lima-helper`.
/// The closed-enum shape ensures the set of operations is statically
/// known and no arbitrary argv can be constructed from outside this
/// module.  The Linux [`SetuidHelperExecutor`] flattens each variant
/// back to the exact argv the helper expects; a future macOS executor
/// (added in a later session) will match on these variants to translate
/// them into broker-protocol messages without touching call sites.
///
/// `RunRsync` is included here because it also goes through the helper
/// binary (the only op that is not Lima-specific: the same helper
/// subcommand serves both Lima and container initial-push transports,
/// distinguished by the `backend` field).  `GuestSocat` is intentionally
/// absent: the streaming socat transport uses
/// [`LimaExecutor::guest_socat`] rather than `run` because it is
/// long-lived and must not run inside `spawn_blocking`.
///
/// `Stop` carries `force: bool` because the base-image build path may
/// fall back to `--force` after a graceful stop timeout; this is the
/// only flag whose presence changes the helper's argv beyond the
/// subcommand-level dispatch.
#[derive(Debug)]
pub enum LimaOp<'a> {
    /// `sandbox-lima-helper create --vm <vm> --yaml <yaml_path> --owner <owner>`
    Create {
        vm: &'a str,
        yaml_path: &'a std::path::Path,
        owner: &'a str,
        /// True when creating a real session VM (which must have a socket_vmnet
        /// NIC). False for the transient base-image build VM, which uses
        /// Lima's slirp NIC only and therefore has no `networks:` key.
        is_hardened_session: bool,
    },
    /// `sandbox-lima-helper start --vm <vm> --qemu-wrapper <path>
    ///   --hardened <0|1> --memory-mb <n> --cpus <n> --start-timeout-s <n>
    ///   [--bridge-name <b> --vm-mac <m>
    ///    [--unrestricted-slirp-for-provisioning]]`
    Start {
        vm: &'a str,
        qemu_wrapper: &'a std::path::Path,
        hardened: bool,
        memory_mb: u32,
        cpus: u32,
        start_timeout_s: u32,
        /// Bridge name and VM MAC, supplied together or not at all.
        bridge: Option<(&'a str, &'a str)>,
        unrestricted_slirp_for_provisioning: bool,
    },
    /// `sandbox-lima-helper stop --vm <vm> [--force]`
    Stop { vm: &'a str, force: bool },
    /// `sandbox-lima-helper delete --vm <vm>`
    Delete { vm: &'a str },
    /// `sandbox-lima-helper clone --base <base> --vm <vm>
    ///   --cpus <n> --memory <gib> --disk <gb> --owner <owner>`
    Clone {
        base: &'a str,
        vm: &'a str,
        cpus: u32,
        memory_gib: u32,
        disk_gb: u32,
        owner: &'a str,
    },
    /// `sandbox-lima-helper list-json`
    ListJson,
    /// `sandbox-lima-helper install-guest-agent --vm <vm>`
    InstallGuestAgent { vm: &'a str },
    /// `sandbox-lima-helper read-user-key`
    ReadUserKey,
    /// `sandbox-lima-helper run-rsync --op-uid <n> --backend <backend>
    ///   --session-name <name> --host-path <p> --guest-path <p> [--no-gitignore]`
    RunRsync {
        backend: BackendKind,
        session_name: &'a str,
        host_path: &'a str,
        guest_path: &'a str,
        no_gitignore: bool,
    },
    /// `sandbox-lima-helper read-owner-marker --vm <vm>`
    ReadOwnerMarker { vm: &'a str },
    /// Post-boot `restrict=on` verification.
    ///
    /// On **macOS** this is routed to the `AgentBrokerExecutor`, which sends
    /// `BrokerOp::RestrictOnVerify` to the operator's agent. The agent reads
    /// the QMP socket (`{lima_home}/{vm}/qmp.sock`) — preferred — falling back
    /// to the wrapper marker file (`{lima_home}/{vm}/sandboxd-restrict-marker`).
    ///
    /// On **Linux** the `SetuidHelperExecutor` reads the wrapper marker file
    /// directly from the LIMA_HOME filesystem (the QMP socket is under the same
    /// uid that called `spawn_blocking`, no broker indirection needed).
    ///
    /// In both cases a successful verification returns `Output { status: 0 }`
    /// with the confirmed token in `stdout`; failure returns `status: 1`.
    RestrictOnVerify { vm: &'a str },
}

/// Operator-execution seam — the platform-independent interface for running
/// `limactl` operations as a given operator uid.
///
/// The daemon never calls `limactl` directly; every operation goes through
/// this trait. The platform determines which implementation is used:
///
/// - **Linux** ([`SetuidHelperExecutor`]): invokes `sandbox-lima-helper` with
///   `cap_setuid+ep`. The helper validates the caller, `setresuid`-pivots to
///   the operator uid, and `exec`s `limactl` with a sanitised env. No
///   privilege is granted to the daemon itself — the narrow helper is the
///   only setcap binary in the Lima execution path.
///
/// - **macOS** (`AgentBrokerExecutor`, defined in the daemon crate): routes
///   each operation to the operator's checked-in `sandbox-agent` LaunchAgent
///   over the broker channel. The agent already runs as the operator, so no
///   setuid or capability is involved. The daemon's own uid (`_sandboxd`, or
///   the operator in single-uid foreground-dev mode) is special-cased to run
///   `limactl` directly rather than routing through the broker.
///
/// The trait separates two concerns:
///
/// - One-shot operations ([`Self::run`]): the caller blocks (via
///   `spawn_blocking`) until the operation completes and returns a
///   fully-buffered `std::process::Output`. Timeout and error-label semantics
///   match the existing [`run_with_timeout`] convention.
///
/// - The streaming operation ([`Self::guest_socat`]): opens a long-lived
///   bidirectional byte pump for the duration of an SSH session. This path
///   MUST NOT use `spawn_blocking` (see the async-I/O carve-out in
///   `CLAUDE.md`); `guest_socat` is therefore `async`.
///
/// The same split exists on the Docker side, and the streams there are the
/// other three in the carve-out: [`crate::docker::DockerExecutor::run`] is
/// one-shot and blocking, [`crate::docker::DockerExecutor::open_stream`] is
/// long-lived and async. This one stays `limactl`-shaped because its
/// transport is `limactl shell`, not `docker exec`.
#[async_trait]
pub trait LimaExecutor: Send + Sync {
    /// Run a one-shot helper operation and return the captured output.
    ///
    /// - `op_uid`: the operator uid passed as `--op-uid <n>`.
    /// - `op`: the typed operation; [`SetuidHelperExecutor`] flattens this to
    ///   the exact argv the helper expects.
    /// - `timeout`: wall-clock budget passed to [`run_with_timeout`].
    /// - `label`: diagnostic string for error and timeout messages.
    fn run(
        &self,
        op_uid: u32,
        op: LimaOp<'_>,
        timeout: Duration,
        label: &str,
    ) -> Result<std::process::Output, SandboxError>;

    /// Open a long-lived bidirectional stream to the in-VM guest agent.
    ///
    /// Spawns `sandbox-lima-helper guest-socat --op-uid <op_uid> --vm <vm>`
    /// with async stdio and `kill_on_drop(true)`.  The returned stream owns
    /// the child handle; dropping it tears down the process.
    ///
    /// This is the async-I/O carve-out: it MUST NOT be wrapped in
    /// `spawn_blocking`.  Holding a blocking-task slot for the full SSH
    /// session lifetime (potentially hours) deadlocks the executor under load.
    async fn guest_socat(
        &self,
        op_uid: u32,
        vm: &str,
    ) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>, SandboxError>;
}

// ---------------------------------------------------------------------------
// SetuidHelperExecutor — Linux implementation
// ---------------------------------------------------------------------------

/// Helper child stdout + stdin owned by the returned stream so
/// `kill_on_drop(true)` tears the process down when the stream is dropped.
struct LimaHelperSocatStream {
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    _child: tokio::process::Child,
}

impl tokio::io::AsyncRead for LimaHelperSocatStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for LimaHelperSocatStream {
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

/// Linux [`LimaExecutor`] implementation that invokes `sandbox-lima-helper`
/// directly.
///
/// Holds the absolute path to the helper binary, resolved once at daemon
/// startup by `resolve_lima_helper_path()`.  Each [`LimaOp`] variant is
/// mapped to the exact argv the helper expects; no subcommand string or
/// extra-arg array escapes from the executor interface.
pub struct SetuidHelperExecutor {
    helper_path: PathBuf,
}

impl SetuidHelperExecutor {
    /// Construct an executor for the helper binary at `helper_path`.
    ///
    /// `helper_path` must be the absolute path returned by
    /// `resolve_lima_helper_path()`.  Callers should treat construction
    /// as fatal on missing (the daemon already enforces this).
    pub fn new(helper_path: PathBuf) -> Self {
        Self { helper_path }
    }

    /// Return the path to the helper binary held by this executor.
    pub fn helper_path(&self) -> &std::path::Path {
        &self.helper_path
    }
}

#[async_trait]
impl LimaExecutor for SetuidHelperExecutor {
    fn run(
        &self,
        op_uid: u32,
        op: LimaOp<'_>,
        timeout: Duration,
        label: &str,
    ) -> Result<std::process::Output, SandboxError> {
        let mut cmd = Command::new(&self.helper_path);
        // Every subcommand receives --op-uid as the second argument; the
        // helper enforces this before dispatching.  RunRsync embeds op_uid
        // via the same flag — the helper's arg parser unifies them.
        match op {
            LimaOp::Create {
                vm,
                yaml_path,
                owner,
                is_hardened_session: _,
            } => {
                cmd.arg("create")
                    .arg("--op-uid")
                    .arg(op_uid.to_string())
                    .arg("--vm")
                    .arg(vm)
                    .arg("--yaml")
                    .arg(yaml_path)
                    .arg("--owner")
                    .arg(owner);
            }
            LimaOp::Start {
                vm,
                qemu_wrapper,
                hardened,
                memory_mb,
                cpus,
                start_timeout_s,
                bridge,
                unrestricted_slirp_for_provisioning,
            } => {
                cmd.arg("start")
                    .arg("--op-uid")
                    .arg(op_uid.to_string())
                    .arg("--vm")
                    .arg(vm)
                    .arg("--qemu-wrapper")
                    .arg(qemu_wrapper)
                    .arg("--hardened")
                    .arg(if hardened { "1" } else { "0" })
                    .arg("--memory-mb")
                    .arg(memory_mb.to_string())
                    .arg("--cpus")
                    .arg(cpus.to_string())
                    .arg("--start-timeout-s")
                    .arg(start_timeout_s.to_string());
                if let Some((bridge_name, mac)) = bridge {
                    cmd.arg("--bridge-name")
                        .arg(bridge_name)
                        .arg("--vm-mac")
                        .arg(mac);
                    if unrestricted_slirp_for_provisioning {
                        cmd.arg("--unrestricted-slirp-for-provisioning");
                    }
                }
            }
            LimaOp::Stop { vm, force } => {
                cmd.arg("stop")
                    .arg("--op-uid")
                    .arg(op_uid.to_string())
                    .arg("--vm")
                    .arg(vm);
                if force {
                    cmd.arg("--force");
                }
            }
            LimaOp::Delete { vm } => {
                cmd.arg("delete")
                    .arg("--op-uid")
                    .arg(op_uid.to_string())
                    .arg("--vm")
                    .arg(vm);
            }
            LimaOp::Clone {
                base,
                vm,
                cpus,
                memory_gib,
                disk_gb,
                owner,
            } => {
                cmd.arg("clone")
                    .arg("--op-uid")
                    .arg(op_uid.to_string())
                    .arg("--base")
                    .arg(base)
                    .arg("--vm")
                    .arg(vm)
                    .arg("--cpus")
                    .arg(cpus.to_string())
                    .arg("--memory")
                    .arg(memory_gib.to_string())
                    .arg("--disk")
                    .arg(disk_gb.to_string())
                    .arg("--owner")
                    .arg(owner);
            }
            LimaOp::ListJson => {
                cmd.arg("list-json").arg("--op-uid").arg(op_uid.to_string());
            }
            LimaOp::InstallGuestAgent { vm } => {
                cmd.arg("install-guest-agent")
                    .arg("--op-uid")
                    .arg(op_uid.to_string())
                    .arg("--vm")
                    .arg(vm);
            }
            LimaOp::ReadUserKey => {
                cmd.arg("read-user-key")
                    .arg("--op-uid")
                    .arg(op_uid.to_string());
            }
            LimaOp::RunRsync {
                backend,
                session_name,
                host_path,
                guest_path,
                no_gitignore,
            } => {
                let backend_str = match backend {
                    BackendKind::Lima => "lima",
                    BackendKind::Container => "container",
                };
                cmd.arg("run-rsync")
                    .arg("--op-uid")
                    .arg(op_uid.to_string())
                    .arg("--backend")
                    .arg(backend_str)
                    .arg("--session-name")
                    .arg(session_name)
                    .arg("--host-path")
                    .arg(host_path)
                    .arg("--guest-path")
                    .arg(guest_path);
                if no_gitignore {
                    cmd.arg("--no-gitignore");
                }
            }
            LimaOp::ReadOwnerMarker { vm } => {
                cmd.arg("read-owner-marker")
                    .arg("--op-uid")
                    .arg(op_uid.to_string())
                    .arg("--vm")
                    .arg(vm);
            }
            LimaOp::RestrictOnVerify { vm } => {
                // Linux: read the wrapper marker file directly. There is no
                // `sandbox-lima-helper` subcommand for this op — on Linux the
                // QEMU process and its files are accessible from the daemon
                // process (same uid or root-readable), so no broker indirection
                // is needed. On macOS this branch is unreachable: the
                // `AgentBrokerExecutor` handles `RestrictOnVerify` by routing
                // to the agent's `handle_restrict_on_verify`, which performs
                // the QMP-preferred / marker-fallback check.
                let lima_home = operator_lima_home(op_uid);
                let marker_path = lima_home.join(vm).join("sandboxd-restrict-marker");
                let contents = match std::fs::read_to_string(&marker_path) {
                    Ok(c) => c,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Err(SandboxError::Internal(format!(
                            "{label}: restrict marker not found at {}; \
                             the qemu-wrapper may not have run",
                            marker_path.display()
                        )));
                    }
                    Err(e) => {
                        return Err(SandboxError::Internal(format!(
                            "{label}: failed to read restrict marker at {}: {e}",
                            marker_path.display()
                        )));
                    }
                };
                if contents.contains("restrict=on") {
                    use std::os::unix::process::ExitStatusExt;
                    return Ok(std::process::Output {
                        status: std::process::ExitStatus::from_raw(0),
                        stdout: contents.trim().as_bytes().to_vec(),
                        stderr: Vec::new(),
                    });
                }
                return Err(SandboxError::Internal(format!(
                    "{label}: restrict marker at {} does not contain 'restrict=on'; \
                     contents: {contents:?}",
                    marker_path.display()
                )));
            }
        }
        run_with_timeout(&mut cmd, timeout, label).map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => SandboxError::Lima(
                format!("{label}: sandbox-lima-helper not found or not executable: {msg}"),
            ),
            other => other,
        })
    }

    async fn guest_socat(
        &self,
        op_uid: u32,
        vm: &str,
    ) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>, SandboxError> {
        // Async-I/O carve-out: spawn via tokio::process::Command (NOT
        // spawn_blocking). See CLAUDE.md "Async-I/O carve-out for long-lived
        // child processes."
        use std::process::Stdio;
        let mut command = tokio::process::Command::new(&self.helper_path);
        command
            .args(["guest-socat", "--op-uid", &op_uid.to_string(), "--vm", vm])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn().map_err(|e| {
            SandboxError::Lima(format!(
                "failed to spawn sandbox-lima-helper guest-socat for {vm}: {e}"
            ))
        })?;

        let stdin = child.stdin.take().ok_or_else(|| {
            SandboxError::Internal("failed to capture stdin of limactl shell socat".into())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            SandboxError::Internal("failed to capture stdout of limactl shell socat".into())
        })?;

        Ok(Box::new(LimaHelperSocatStream {
            stdin,
            stdout,
            _child: child,
        }))
    }
}

// ---------------------------------------------------------------------------
// Per-operator LimaManager registry
// ---------------------------------------------------------------------------

/// Registry of per-operator [`LimaManager`] instances.
///
/// One `LimaManager` per operator uid, held for the daemon's lifetime
/// (no eviction this milestone).  The registry serialises concurrent
/// same-operator base-image builds via the `build_lock` mutex inside each
/// [`LimaManager`] — acquired in `build_base_image_inner` for the full
/// duration of the build.  Distinct operators hold separate `LimaManager`
/// instances with separate locks, so they build in parallel.
///
/// # Lifetime
///
/// Wrap in an `Arc` and pass it wherever the daemon today holds a single
/// `Arc<LimaManager>`.  On the first `LimaManager`-needing call for a
/// given operator the registry creates a per-operator entry; all
/// subsequent calls for the same operator reuse it.
///
/// # Concurrency
///
/// The outer `Mutex` guards the `HashMap` of operator → manager entries;
/// it is held only for the duration of a `HashMap` lookup or insert
/// (never across `ensure_operator_lima_home` / `setfacl` I/O).
/// Long-running operations (base-image builds) run on the per-operator
/// `LimaManager` after the outer lock is released, so distinct operators
/// never contend on the registry mutex.
pub struct LimaManagerRegistry {
    /// Per-operator manager map.  Keyed by operator uid.
    ///
    /// Invariant: every entry has been fully constructed and is ready for
    /// use.  Entries are never removed; the registry grows monotonically
    /// as new operators create sessions.
    managers: Mutex<HashMap<u32, Arc<LimaManager>>>,
    /// Operator-execution seam for all `sandbox-lima-helper` invocations.
    /// Shared across all per-operator managers; each manager holds a clone
    /// of this `Arc`.  The Linux implementation is [`SetuidHelperExecutor`];
    /// a macOS implementation (added in a later session) slots in here.
    executor: Arc<dyn LimaExecutor>,
    /// Golden-image base VM name shared across all per-operator managers.
    base_vm_name: String,
    /// Canonical pool CIDR string (`<base>/<prefix>`) stamped as
    /// `sandboxd.owner=<pool>` via the `--owner` flag on `create`/`clone`
    /// helper calls. The marker is written into each VM's instance dir so
    /// the Lima orphan reaper can attribute VMs to this daemon. Shared
    /// across all per-operator managers (same daemon = same pool).
    owner_pool: String,
    /// Whether this registry is running on macOS.  Propagated to every
    /// [`LimaManager`] created by [`get_or_create`] so template generation
    /// and wrapper selection use the correct platform paths.
    is_macos: bool,
    /// Provisioning function: creates the per-operator LIMA_HOME directory
    /// and applies the POSIX ACL.  Production wiring uses
    /// `ensure_operator_lima_home`; tests inject a closure that provisions
    /// into a caller-owned tmpdir instead of `/var/lib/sandboxd/`.
    ///
    /// This construction-time seam eliminates any `#[cfg(test)]` divergence
    /// from the production code path: the function is a plain field, so the
    /// struct layout is identical in all builds.
    provision_lima_home: Box<dyn Fn(u32) -> Result<PathBuf, SandboxError> + Send + Sync>,
}

impl LimaManagerRegistry {
    /// Construct a registry backed by the production
    /// `ensure_operator_lima_home` provisioning function.
    ///
    /// `executor` is the operator-execution seam for all helper invocations,
    /// constructed once at daemon startup.  The Linux implementation is
    /// [`SetuidHelperExecutor`], built from the path returned by
    /// `resolve_lima_helper_path()`.
    ///
    /// `base_vm_name` is the Lima instance name for the golden base image.
    ///
    /// `owner_pool` is the canonical pool CIDR string stamped via `--owner`
    /// on every `create`/`clone` helper call.
    pub fn new(
        base_vm_name: String,
        executor: Arc<dyn LimaExecutor>,
        owner_pool: String,
        is_macos: bool,
    ) -> Self {
        Self {
            managers: Mutex::new(HashMap::new()),
            executor,
            base_vm_name,
            owner_pool,
            is_macos,
            provision_lima_home: Box::new(ensure_operator_lima_home),
        }
    }

    /// Construct a registry with an injected provisioning function.
    ///
    /// The `provision` closure is called with the operator uid on the first
    /// `get_or_create` for that operator; it must return the absolute path
    /// to the operator's LIMA_HOME or an error.
    ///
    /// Production code uses [`Self::new`].  Tests inject a closure that
    /// provisions into a caller-owned tmpdir so registry unit tests remain
    /// hermetic and do not touch `/var/lib/sandboxd/`.
    pub fn new_with_provisioner<F>(
        base_vm_name: String,
        executor: Arc<dyn LimaExecutor>,
        owner_pool: String,
        is_macos: bool,
        provision: F,
    ) -> Self
    where
        F: Fn(u32) -> Result<PathBuf, SandboxError> + Send + Sync + 'static,
    {
        Self {
            managers: Mutex::new(HashMap::new()),
            executor,
            base_vm_name,
            owner_pool,
            is_macos,
            provision_lima_home: Box::new(provision),
        }
    }

    /// Return the `Arc<LimaManager>` for `op_uid`, creating one if this
    /// is the first call for that operator.
    ///
    /// On the first call for a given operator uid, this also provisions
    /// the per-operator LIMA_HOME directory
    /// (`/var/lib/sandboxd/<daemon_uid>/<op_uid>/lima/`)
    /// and applies the POSIX ACL that grants the operator uid write access.
    /// Without the ACL, limactl (which runs pivoted to the operator uid via
    /// `sandbox-lima-helper`) cannot create VM directories inside LIMA_HOME.
    ///
    /// Returns an error if LIMA_HOME provisioning fails (e.g. `setfacl` is
    /// missing or the daemon lacks permission to write the state root).
    ///
    /// The returned `Arc` is reference-counted; callers can hold it across
    /// slow operations without blocking other operators.
    ///
    /// # Concurrency
    ///
    /// Uses a double-checked insert pattern so `self.managers` is NOT held
    /// across the `ensure_operator_lima_home` / `setfacl` shell-out (up to
    /// 10 s under `run_with_timeout`).  The outer lock is held only for the
    /// fast `HashMap` lookup and the final `entry().or_insert_with` insert.
    pub fn get_or_create(&self, op_uid: u32) -> Result<Arc<LimaManager>, SandboxError> {
        // Fast path: check under a short-lived lock.
        {
            let map = self.managers.lock().map_err(|e| {
                SandboxError::Internal(format!("LimaManagerRegistry mutex poisoned: {e}"))
            })?;
            if let Some(mgr) = map.get(&op_uid) {
                return Ok(Arc::clone(mgr));
            }
        } // lock released before the slow provisioning step

        // Provision the LIMA_HOME directory and apply the operator's ACL
        // outside the lock. This is idempotent: `setfacl` is safe to run
        // more than once for the same operator.  A concurrent winner for
        // the same op_uid runs the same idempotent provisioning and the
        // `entry().or_insert_with` below retains whichever manager was
        // inserted first.
        let lima_home = (self.provision_lima_home)(op_uid)?;

        let mgr = Arc::new(LimaManager::new(
            lima_home,
            Arc::clone(&self.executor),
            op_uid,
            self.base_vm_name.clone(),
            self.owner_pool.clone(),
            self.is_macos,
        ));

        // Re-lock and insert, using entry().or_insert_with so that a
        // concurrent winner's manager is kept and ours is discarded.
        let mut map = self.managers.lock().map_err(|e| {
            SandboxError::Internal(format!("LimaManagerRegistry mutex poisoned: {e}"))
        })?;
        let inserted = map.entry(op_uid).or_insert_with(|| Arc::clone(&mgr));
        Ok(Arc::clone(inserted))
    }

    /// Return the executor held by this registry.
    ///
    /// Used by call sites that need to invoke the helper outside the
    /// per-operator [`LimaManager`] world — currently the workspace rsync
    /// pivot ([`crate::workspace_rsync::run_initial_push_via_helper`]).
    pub fn executor(&self) -> &Arc<dyn LimaExecutor> {
        &self.executor
    }

    /// Return the number of operator entries currently in the registry.
    /// Exposed for tests.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.managers
            .lock()
            .map_err(|e| panic!("LimaManagerRegistry mutex poisoned in test: {e}"))
            .unwrap()
            .len()
    }

    /// Return `true` if the registry has no entries.
    /// Paired with [`len`](Self::len) to satisfy the `len_without_is_empty` lint.
    /// Exposed for tests.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// LimaManager
// ---------------------------------------------------------------------------

/// Systemd unit file for the sandbox guest agent service.
/// Retained in daemon-side `lima.rs` for unit test assertions that verify
/// the constant matches the helper's copy. Production installs go through
/// `sandbox-lima-helper install-guest-agent` which embeds its own copy.
#[cfg(test)]
const GUEST_AGENT_SERVICE_UNIT: &str = "\
[Unit]
Description=Sandbox Guest Agent
After=network.target

[Service]
Type=simple
User=sandbox
Group=sandbox
ExecStart=/usr/local/bin/sandbox-guest
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target";

// ---------------------------------------------------------------------------
// Shared Ubuntu cloud-image URL constants
// ---------------------------------------------------------------------------

/// Canonical Ubuntu 24.04 (Noble) cloud-image for x86_64.
///
/// Used by the Linux base template and the Linux session template. Centralised
/// here so a URL change (new release, mirror move) is a single-location edit
/// rather than a silently-diverging copy across multiple format strings.
const UBUNTU_IMAGE_AMD64: &str =
    "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img";

/// Canonical Ubuntu 24.04 (Noble) cloud-image for arm64 (Apple Silicon + Linux arm64).
///
/// Used by the Linux base template, the Linux session template, and the macOS
/// session template. Centralised alongside [`UBUNTU_IMAGE_AMD64`] — the two
/// constants form the complete cross-arch image set for all templates.
const UBUNTU_IMAGE_ARM64: &str =
    "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img";

/// QEMU wrapper script that injects PCIe root-port, bridge networking,
/// device lockdown, and optional cgroup resource limits via `systemd-run`.
///
/// Extracted as a constant so tests can verify the content without writing
/// to the filesystem.
const QEMU_WRAPPER_SCRIPT: &str = r#"#!/bin/sh
# QEMU wrapper injected by sandboxd.
#
# Always:
# 1. Adds a PCIe root-port so that NIC hot-add via QMP works on q35 machines.
# When SANDBOX_DOCKER_BRIDGE is set:
# 2. Restricts Lima's management slirp NIC to host-initiated forwards only.
# 3. Adds a second NIC connected to the Docker bridge via qemu-bridge-helper.
#
# When SANDBOX_QEMU_HARDENED=1:
# 4. Disables unnecessary devices (USB, sound, display, floppy, HPET, etc.)
#    and adds virtio-rng for guest entropy.
#
# When SANDBOX_QEMU_MEMORY_MB and SANDBOX_QEMU_CPUS are set:
# 5. Applies cgroup resource limits via systemd-run.

# Find the real QEMU binary, excluding this wrapper's directory to prevent
# infinite recursion if Lima prepends it to PATH.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_QEMU=""
IFS=:
for dir in $PATH; do
    [ "$dir" = "$SCRIPT_DIR" ] && continue
    if [ -x "$dir/qemu-system-x86_64" ]; then
        REAL_QEMU="$dir/qemu-system-x86_64"
        break
    fi
done
unset IFS
[ -z "$REAL_QEMU" ] && { echo "qemu-system-x86_64 not found on PATH (excluding wrapper dir $SCRIPT_DIR)" >&2; exit 1; }

# Lima runs probe commands (-machine help, -cpu help, -accel help, --version,
# etc.) through the wrapper.  Pass these straight to QEMU without extra flags.
for arg in "$@"; do
    case "$arg" in
        help|--version|--help|-help)
            exec "$REAL_QEMU" "$@" ;;
    esac
done

# PCIe root-port is always needed for NIC hot-add.
EXTRA_ARGS="-device pcie-root-port,id=pcie-hotplug-port,bus=pcie.0,chassis=1"

# Bridge networking: if SANDBOX_DOCKER_BRIDGE is set, add a second NIC
# connected to the Docker bridge via qemu-bridge-helper.
# QEMU resolves the helper via its compile-time libexecdir default
# (different on Ubuntu/Debian (/usr/lib/qemu/) vs RHEL/Fedora
# (/usr/libexec/)); sandboxd does not pin the path.
# Lima's mandatory management NIC is QEMU user-mode/slirp.  It is needed
# for host-initiated SSH/readiness forwards, but guest-initiated traffic
# through it would bypass the sandbox gateway when bridge networking is
# active.  In that mode, normalize every `-netdev user,...` backend to
# `restrict=on` before QEMU sees the argv.  Base-image builds have no
# sandbox bridge yet and intentionally keep unrestricted slirp for package
# installation during provisioning.
if [ -n "$SANDBOX_DOCKER_BRIDGE" ]; then
    if [ "$SANDBOX_UNRESTRICTED_SLIRP_FOR_PROVISIONING" != "1" ]; then
        remaining=$#
        while [ "$remaining" -gt 0 ]; do
            arg="$1"
            shift
            remaining=$((remaining - 1))

            if [ "$arg" = "-netdev" ] && [ "$remaining" -gt 0 ]; then
                netdev="$1"
                shift
                remaining=$((remaining - 1))

                case "$netdev" in
                    user|user,*)
                        IFS=,
                        restricted_netdev=""
                        for field in $netdev; do
                            case "$field" in
                                restrict=*) continue ;;
                            esac
                            if [ -z "$restricted_netdev" ]; then
                                restricted_netdev="$field"
                            else
                                restricted_netdev="$restricted_netdev,$field"
                            fi
                        done
                        unset IFS
                        netdev="$restricted_netdev,restrict=on"
                        ;;
                esac

                set -- "$@" "$arg" "$netdev"
            else
                set -- "$@" "$arg"
            fi
        done
    fi

    EXTRA_ARGS="$EXTRA_ARGS \
        -netdev bridge,id=net_sandbox,br=$SANDBOX_DOCKER_BRIDGE \
        -device virtio-net-pci,netdev=net_sandbox,mac=$SANDBOX_VM_MAC,bus=pcie-hotplug-port"
fi

# Hardened mode: device lockdown.
if [ "$SANDBOX_QEMU_HARDENED" = "1" ]; then
    # Note: QEMU seccomp (-sandbox) is NOT used because it requires
    # PR_SET_NO_NEW_PRIVS, which strips setuid from qemu-bridge-helper
    # and breaks bridge networking.  Defence-in-depth still comes from
    # device lockdown, cgroup limits, and KVM hardware isolation.
    EXTRA_ARGS="$EXTRA_ARGS \
        -no-user-config \
        -display none \
        -vga none \
        -device virtio-rng-pci"
fi

# If resource limit env vars are set and the user-systemd instance is
# reachable, wrap QEMU in a transient systemd scope with memory and CPU
# limits.
#
# The `systemctl --user show-environment` probe is load-bearing: a system
# user (e.g. `sandbox`, when the daemon runs as a hardened systemd unit
# without `loginctl enable-linger sandbox`) has `systemd-run` *installed*
# but no user-bus, so `systemd-run --user --scope` aborts immediately with
# `Failed to connect to bus: No medium found` (exit 1). Lima sees QEMU
# exit with status 1 before it ever opens its QMP socket and reports
# `Driver stopped due to error: "exit status 1"` with no actionable
# detail. The earlier `command -v systemd-run` gate alone is insufficient
# because it answers "is the binary on PATH?" rather than "can we
# actually use --user?". When the probe fails, fall back to running QEMU
# directly: cgroup hardening is downgraded for that session, but the VM
# boots — operators who want the cgroup limits restored should run
# `loginctl enable-linger <daemon-user>` to make the user bus persist.
if [ -n "$SANDBOX_QEMU_MEMORY_MB" ] && [ -n "$SANDBOX_QEMU_CPUS" ] \
        && command -v systemd-run >/dev/null 2>&1 \
        && systemctl --user show-environment >/dev/null 2>&1; then
    exec systemd-run --user --scope --slice=sandbox.slice \
        -p MemoryMax="$((SANDBOX_QEMU_MEMORY_MB + 512))M" \
        -p "CPUQuota=${SANDBOX_QEMU_CPUS}00%" \
        -p TasksMax=256 \
        "$REAL_QEMU" $EXTRA_ARGS "$@"
else
    # Cgroup limits are NOT applied to this session.
    # Either systemd-run is absent or the user-systemd bus is
    # unreachable (no active login session and loginctl enable-linger
    # not enabled for the operator).
    # To enable cgroup enforcement: run
    #   loginctl enable-linger <operator-user>
    # so the user manager persists across logouts, then restart the
    # daemon.  Without an active user manager or enable-linger, every
    # session VM boots without MemoryMax/CPUQuota/TasksMax limits.
    echo "WARNING: sandboxd qemu-wrapper: user-systemd bus unreachable or systemd-run absent -- cgroup limits (MemoryMax/CPUQuota/TasksMax) are NOT applied to this VM. Run: loginctl enable-linger <operator-user>" >&2
    exec "$REAL_QEMU" $EXTRA_ARGS "$@"
fi
"#;

/// macOS QEMU wrapper script that injects `restrict=on` into Lima's mandatory
/// slirp management NIC (`eth0`) for each sandbox VM.
///
/// This wrapper is the egress-enforcement surface for macOS sandbox VMs.
/// It must be fail-closed: if it cannot find exactly one `-netdev user,...`
/// token, it aborts the launch rather than starting a VM with an unrestricted
/// management NIC.
///
/// Genuine macOS deltas from the Linux wrapper:
///
/// 1. **Binary name** — `qemu-system-aarch64` (Apple Silicon only).
/// 2. **Firmware path** — Lima derives the edk2 firmware search path from the
///    qemu binary's directory (`../share/qemu/edk2-aarch64-code.fd`).  The
///    wrapper's directory must contain a `share/qemu` symlink pointing to the
///    Homebrew firmware directory so Lima can resolve the firmware.  The symlink
///    is created by `ensure_qemu_wrapper_macos()` alongside the script.
/// 3. **HVF via exec** — the wrapper `exec`s the real Homebrew-signed QEMU
///    (`com.apple.security.hypervisor` entitlement is re-acquired on `exec`).
/// 4. **No bridge NIC** — socket_vmnet is the gateway-facing NIC; the wrapper
///    never appends a second NIC.  The bridge-networking block is absent.
/// 5. **No systemd-run / cgroup limits** — cgroups don't exist on macOS.
/// 6. **Marker file** — the wrapper records the final rewritten `-netdev`
///    token to `$SANDBOX_RESTRICT_MARKER` (an absolute path in the instance
///    dir, set by the daemon before the limactl start invocation). The
///    broker-mediated post-boot verification reads this as fallback evidence,
///    used only when a live QMP `query-netdev` against the instance is
///    unavailable.
///
/// The rewrite algorithm (identical to the Linux wrapper):
/// Scan argv for every `-netdev user,...` token (both split and single-arg
/// forms), strip any existing `restrict=` field, splice `,restrict=on`, and
/// confirm exactly one such token was found. Zero or more than one → abort.
///
/// `SANDBOX_UNRESTRICTED_SLIRP_FOR_PROVISIONING=1` skips the rewrite (base
/// image builds need unrestricted slirp for apt package installation).
#[cfg(target_os = "macos")]
const QEMU_WRAPPER_MACOS_SCRIPT: &str = r#"#!/bin/sh
# macOS QEMU wrapper injected by sandboxd (sandbox VMs only).
#
# Injects restrict=on into Lima's mandatory slirp management NIC (eth0) so
# the guest cannot egress except through the gateway.  Fail-closed: aborts
# if it cannot find exactly one -netdev user,... token.
#
# Does NOT apply cgroup limits (Linux-only feature) or bridge networking.
# Socket_vmnet is the gateway-facing NIC — this wrapper never touches it.

# Find the real qemu-system-aarch64, excluding this wrapper's directory
# (which Lima prepends to PATH) to prevent infinite recursion.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_QEMU=""
IFS=:
for dir in $PATH; do
    [ "$dir" = "$SCRIPT_DIR" ] && continue
    if [ -x "$dir/qemu-system-aarch64" ]; then
        REAL_QEMU="$dir/qemu-system-aarch64"
        break
    fi
done
unset IFS
[ -z "$REAL_QEMU" ] && { echo "sandboxd qemu-wrapper: qemu-system-aarch64 not found on PATH (excluding wrapper dir $SCRIPT_DIR)" >&2; exit 1; }

# Lima runs probe commands (-machine help, -cpu help, -accel help, --version,
# etc.) through the wrapper.  Pass these straight to QEMU without extra flags.
for arg in "$@"; do
    case "$arg" in
        help|--version|--help|-help)
            exec "$REAL_QEMU" "$@" ;;
    esac
done

# Restrict=on rewrite: splice restrict=on into Lima's management slirp netdev.
# Skipped for base-image provisioning builds (unrestricted slirp needed for apt).
if [ "$SANDBOX_UNRESTRICTED_SLIRP_FOR_PROVISIONING" != "1" ]; then
    user_netdev_count=0
    rewritten_netdev=""

    remaining=$#
    while [ "$remaining" -gt 0 ]; do
        arg="$1"
        shift
        remaining=$((remaining - 1))

        if [ "$arg" = "-netdev" ] && [ "$remaining" -gt 0 ]; then
            netdev="$1"
            shift
            remaining=$((remaining - 1))

            case "$netdev" in
                user|user,*)
                    user_netdev_count=$((user_netdev_count + 1))
                    # Strip any existing restrict= field, then splice restrict=on.
                    IFS=,
                    restricted_netdev=""
                    for field in $netdev; do
                        case "$field" in
                            restrict=*) continue ;;
                        esac
                        if [ -z "$restricted_netdev" ]; then
                            restricted_netdev="$field"
                        else
                            restricted_netdev="$restricted_netdev,$field"
                        fi
                    done
                    unset IFS
                    netdev="$restricted_netdev,restrict=on"
                    rewritten_netdev="$netdev"
                    ;;
            esac

            set -- "$@" "$arg" "$netdev"
        else
            set -- "$@" "$arg"
        fi
    done

    # Fail closed: exactly one user netdev required.
    if [ "$user_netdev_count" -eq 0 ]; then
        echo "sandboxd qemu-wrapper: no -netdev user,... token found in QEMU argv — Lima version incompatibility? Aborting to prevent unrestricted slirp egress." >&2
        exit 1
    fi
    if [ "$user_netdev_count" -gt 1 ]; then
        echo "sandboxd qemu-wrapper: found $user_netdev_count -netdev user,... tokens (expected exactly 1) — Aborting." >&2
        exit 1
    fi

    # Belt-and-suspenders: confirm restrict=on is present in the rewritten token.
    case "$rewritten_netdev" in
        *restrict=on*)
            ;;
        *)
            echo "sandboxd qemu-wrapper: restrict=on not present in rewritten netdev '$rewritten_netdev' — Aborting." >&2
            exit 1
            ;;
    esac

    # Record the rewritten netdev token to the marker file (if requested).
    # The broker-mediated post-boot verification reads this as fallback evidence.
    if [ -n "$SANDBOX_RESTRICT_MARKER" ]; then
        printf '%s\n' "$rewritten_netdev" > "$SANDBOX_RESTRICT_MARKER" 2>/dev/null || true
    fi
fi

exec "$REAL_QEMU" "$@"
"#;

/// Manages Lima virtual machines that back sandbox sessions.
///
/// All VMs are named `sandbox-{session_id}` so they can be distinguished from
/// user-created Lima instances.  Per-session Lima templates are staged as
/// world-readable files under the operator state root
/// (`{base_dir}/../sandbox-tmpl-{id}.yaml`) so that `sandbox-lima-helper
/// create` (running as the operator uid after setresuid) can open them.
/// Files are cleaned up immediately after `limactl create` returns.
///
/// Each `LimaManager` instance is bound to a single operator uid. Every
/// `limactl` operation is dispatched through `sandbox-lima-helper` with
/// `--op-uid <self.op_uid>` so the helper pivots to the operator's uid before
/// exec'ing `limactl`. The daemon never invokes `limactl` directly.
pub struct LimaManager {
    base_dir: PathBuf,
    /// Operator-execution seam for all helper invocations bound to this
    /// operator.  Every limactl call goes through the executor — limactl is
    /// never exec'd directly by the daemon.
    executor: Arc<dyn LimaExecutor>,
    /// Operator uid this manager is bound to. Passed as `--op-uid <N>` on
    /// every helper invocation. The helper rejects `--op-uid 0`.
    op_uid: u32,
    /// Name of the singleton golden-image VM this manager owns. The daemon
    /// resolves this from `SANDBOX_BASE_VM_NAME` at startup; the test
    /// daemon picks a distinct name (`sandbox-test-base`) so production
    /// and test daemons don't collide on a single user-global Lima
    /// instance.
    base_vm_name: String,
    /// Canonical pool CIDR string (`<base>/<prefix>`) passed as `--owner`
    /// to every `create` and `clone` helper invocation so the helper writes
    /// `{lima_home}{vm}/sandboxd-owner` after a successful limactl run.
    /// The Lima orphan reaper reads this marker to attribute VMs to this
    /// daemon without relying on LIMA_HOME isolation alone.
    owner_pool: String,
    /// Whether this manager is running on macOS. Controls template generation
    /// (socket_vmnet NIC instead of bridge, no Linux seccomp/cgroup wrapper,
    /// aarch64-only image) and wrapper selection
    /// (`ensure_qemu_wrapper_macos` vs `ensure_qemu_wrapper`).
    is_macos: bool,
    /// Serialises concurrent `build_base_image` calls for this operator.
    /// A single `Arc<LimaManager>` is shared across all callers for the
    /// same operator (vended by `LimaManagerRegistry`), so two concurrent
    /// `create_session` requests for the same operator will both call
    /// `build_base_image` if the golden image is absent — without this
    /// lock the second `limactl create` would clash with the first.
    /// Different operators hold separate `LimaManager` instances and
    /// therefore separate locks, so they build independently in parallel.
    build_lock: std::sync::Mutex<()>,
}

impl LimaManager {
    /// Create a new manager for the given operator, rooted at the per-operator
    /// LIMA_HOME directory.
    ///
    /// `executor` is the operator-execution seam for all helper invocations,
    /// shared with all other managers in the same registry.
    ///
    /// `op_uid` is the numeric uid of the operator that owns this manager.
    /// The helper rejects `--op-uid 0`; callers must never pass 0.
    ///
    /// `base_vm_name` is the Lima instance name for the golden base image
    /// this manager owns. Production callers pass the validated value of
    /// `SANDBOX_BASE_VM_NAME`; tests typically pass [`DEFAULT_BASE_VM_NAME`].
    pub fn new(
        base_dir: PathBuf,
        executor: Arc<dyn LimaExecutor>,
        op_uid: u32,
        base_vm_name: String,
        owner_pool: String,
        is_macos: bool,
    ) -> Self {
        Self {
            base_dir,
            executor,
            op_uid,
            base_vm_name,
            owner_pool,
            is_macos,
            build_lock: std::sync::Mutex::new(()),
        }
    }

    /// Create a manager with a caller-supplied helper path and operator uid,
    /// wrapping the path in a [`SetuidHelperExecutor`]. Useful for tests.
    #[cfg(test)]
    pub fn with_helper_path(
        base_dir: PathBuf,
        helper_path: PathBuf,
        op_uid: u32,
        base_vm_name: String,
    ) -> Self {
        Self {
            base_dir,
            executor: Arc::new(SetuidHelperExecutor::new(helper_path)),
            op_uid,
            base_vm_name,
            owner_pool: "test-pool".to_string(),
            is_macos: false,
            build_lock: std::sync::Mutex::new(()),
        }
    }

    /// Test constructor with explicit `is_macos` flag, for macOS template tests.
    #[cfg(test)]
    pub fn with_helper_path_and_platform(
        base_dir: PathBuf,
        helper_path: PathBuf,
        op_uid: u32,
        base_vm_name: String,
        is_macos: bool,
    ) -> Self {
        Self {
            base_dir,
            executor: Arc::new(SetuidHelperExecutor::new(helper_path)),
            op_uid,
            base_vm_name,
            owner_pool: "test-pool".to_string(),
            is_macos,
            build_lock: std::sync::Mutex::new(()),
        }
    }

    /// Return the base directory (LIMA_HOME root) this manager is rooted at.
    pub fn base_dir(&self) -> &std::path::Path {
        &self.base_dir
    }

    /// Return the operator uid this manager is bound to.
    pub fn op_uid(&self) -> u32 {
        self.op_uid
    }

    /// Return the executor held by this manager.
    pub fn executor(&self) -> &Arc<dyn LimaExecutor> {
        &self.executor
    }

    /// Return the VM name this manager uses for the golden base image.
    pub fn base_vm_name(&self) -> &str {
        &self.base_vm_name
    }

    /// Run a typed [`LimaOp`] through the executor, binding `self.op_uid`.
    ///
    /// All one-shot helper calls in this manager go through this method so
    /// the executor seam is the single point through which operations are
    /// dispatched.  The `timeout` and `label` parameters are forwarded
    /// verbatim to [`LimaExecutor::run`].
    pub(crate) fn run_helper(
        &self,
        op: LimaOp<'_>,
        timeout: Duration,
        label: &str,
    ) -> Result<std::process::Output, SandboxError> {
        self.executor.run(self.op_uid, op, timeout, label)
    }

    // -- public API ---------------------------------------------------------

    /// Create a new VM for the given session.
    ///
    /// Generates a Lima YAML template, writes it to the session directory, and
    /// invokes `sandbox-lima-helper create` to run `limactl create` as the
    /// operator uid (so `_config/user` is written as the operator, satisfying
    /// OpenSSH `StrictKeyfileMode`).
    /// Write `content` to a world-readable (`0o644`) tempfile under the
    /// operator state root (`{LIMA_HOME}/../`) and return its path.
    ///
    /// # Why a tempfile outside LIMA_HOME
    ///
    /// `sandbox-lima-helper create` runs as the operator uid (post-`setresuid`)
    /// and calls `limactl create --yaml <path>`. `limactl` must be able to
    /// `open()` the template before creating the VM.
    ///
    /// Placing the template inside LIMA_HOME is problematic for two reasons:
    ///
    /// 1. **No operator read access on LIMA_HOME subdirs.** The per-operator
    ///    LIMA_HOME is provisioned with `u:<op_uid>:rwx` on the root directory
    ///    only, deliberately without a `d:u:<op_uid>:rwx` *default* ACL so
    ///    that the SSH private key (`_config/user`) remains a plain 0600 file
    ///    with no ACL mask. Any subdirectory the daemon creates inside
    ///    LIMA_HOME inherits the default `d:g::---,d:o::---` ACEs, meaning
    ///    the operator cannot enter them and gets EACCES.
    ///
    /// 2. **Lima instance enumeration.** Lima enumerates every directory
    ///    entry under LIMA_HOME when building its instance list. Any
    ///    daemon-created subdirectory visible to the operator would cause Lima
    ///    to attempt `open(<dir>/lima.yaml)`, which either produces a fatal
    ///    "no such file" error (if the dir is readable) or is silently skipped
    ///    (if the dir is inaccessible). Placing the template *outside*
    ///    LIMA_HOME sidesteps this entirely — Lima never looks outside its own
    ///    home directory.
    ///
    /// The operator state root (`/var/lib/sandboxd/<daemon_uid>/<op_uid>/`) is
    /// a sibling of LIMA_HOME and is not scanned by Lima. A `0o644` tempfile there is
    /// readable by everyone (the template contains non-sensitive Lima YAML
    /// config — no keys, no secrets). The file is removed on success and on
    /// all error paths inside the callers (`create_vm`,
    /// `create_vm_with_custom_template`).
    fn write_operator_readable_template(
        &self,
        session_id: &SessionId,
        content: &[u8],
    ) -> Result<std::path::PathBuf, SandboxError> {
        // Place the file under the operator state root (parent of LIMA_HOME)
        // so Lima never enumerates it.
        let state_root = self.base_dir.parent().ok_or_else(|| {
            SandboxError::Internal(format!(
                "base_dir {} has no parent — cannot derive operator state root for template",
                self.base_dir.display()
            ))
        })?;
        let path = state_root.join(format!("sandbox-tmpl-{}.yaml", session_id.as_str()));
        std::fs::write(&path, content).map_err(|e| {
            SandboxError::Internal(format!(
                "failed to write session template to {}: {e}",
                path.display()
            ))
        })?;
        // World-readable: the template is non-sensitive Lima YAML config
        // (no keys, no secrets). The operator-uid limactl process must be
        // able to open it, and the simplest cross-uid mechanism is 0o644.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).map_err(
                |e| {
                    SandboxError::Internal(format!(
                        "failed to chmod 0644 template {}: {e}",
                        path.display()
                    ))
                },
            )?;
        }
        Ok(path)
    }

    pub fn create_vm(
        &self,
        session_id: &SessionId,
        config: &SessionConfig,
        operator_identity: Option<(u32, u32)>,
        vmnet_slot: Option<u16>,
    ) -> Result<(), SandboxError> {
        let template = self.generate_template(session_id, config, operator_identity, vmnet_slot);
        // Write the template to a world-readable tempfile outside LIMA_HOME
        // so the operator-uid `limactl create` can open it without touching
        // the LIMA_HOME subdirectory tree (which Lima enumerates for instances).
        let template_path =
            self.write_operator_readable_template(session_id, template.as_bytes())?;

        let vm_name = vm_name(session_id);

        info!(
            session_id = %session_id,
            vm = %vm_name,
            cpus = config.cpus,
            memory_mb = config.memory_mb,
            disk_gb = config.disk_gb,
            hardened = config.hardened,
            "creating VM"
        );

        let result = self.run_helper(
            LimaOp::Create {
                vm: &vm_name,
                yaml_path: &template_path,
                owner: &self.owner_pool,
                is_hardened_session: true,
            },
            CREATE_VM_TIMEOUT,
            "sandbox-lima-helper create",
        );
        // Best-effort cleanup of the tempfile on both success and failure.
        // Errors here are swallowed — the primary result takes precedence.
        let _ = std::fs::remove_file(&template_path);

        let output = result?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("create", &stderr));
        }

        info!(session_id = %session_id, vm = %vm_name, "VM created");
        Ok(())
    }

    /// Create a new VM using a custom Lima template file.
    ///
    /// The template is copied to a world-readable tempfile outside LIMA_HOME
    /// before invoking `sandbox-lima-helper create`.
    pub fn create_vm_with_custom_template(
        &self,
        session_id: &SessionId,
        template_path: &std::path::Path,
    ) -> Result<(), SandboxError> {
        // Read the caller-supplied template and re-stage it as a
        // world-readable tempfile outside LIMA_HOME so the operator-uid
        // limactl process can open it. See write_operator_readable_template
        // for the full rationale.
        let content = std::fs::read(template_path).map_err(|e| {
            SandboxError::Internal(format!(
                "failed to read custom template {}: {e}",
                template_path.display()
            ))
        })?;
        let staged = self.write_operator_readable_template(session_id, &content)?;

        let vm_name = vm_name(session_id);

        info!(
            session_id = %session_id,
            vm = %vm_name,
            template = %template_path.display(),
            "creating VM with custom template"
        );

        let result = self.run_helper(
            LimaOp::Create {
                vm: &vm_name,
                yaml_path: &staged,
                owner: &self.owner_pool,
                is_hardened_session: true,
            },
            CREATE_VM_TIMEOUT,
            "sandbox-lima-helper create (custom template)",
        );
        // Best-effort cleanup on both success and failure.
        let _ = std::fs::remove_file(&staged);

        let output = result?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("create", &stderr));
        }

        info!(session_id = %session_id, vm = %vm_name, "VM created with custom template");
        Ok(())
    }

    /// Start an existing (stopped) VM.
    ///
    /// Dispatches `sandbox-lima-helper start` with all QEMU resource flags as
    /// typed arguments. The helper sets the appropriate environment variables
    /// (`QEMU_SYSTEM_X86_64`, `SANDBOX_QEMU_*`) after setresuid to the
    /// operator uid, satisfying OpenSSH `StrictKeyfileMode` for `_config/user`.
    ///
    /// The `config` parameter controls hardening and propagates resource limits.
    /// When `bridge_name` and `vm_mac` are provided (both must be Some together),
    /// the QEMU wrapper adds a second NIC via `qemu-bridge-helper`.
    pub fn start_vm(
        &self,
        session_id: &SessionId,
        config: &SessionConfig,
        bridge_name: Option<&str>,
        vm_mac: Option<&str>,
        unrestricted_slirp_for_provisioning: bool,
    ) -> Result<(), SandboxError> {
        let vm_name = vm_name(session_id);
        let qemu_wrapper = self.resolve_qemu_wrapper()?;

        info!(
            session_id = %session_id,
            vm = %vm_name,
            hardened = config.hardened,
            bridge = bridge_name.unwrap_or("none"),
            op_uid = self.op_uid,
            "starting VM"
        );

        // Bridge/MAC must be supplied together (enforced by the caller).
        let bridge = match (bridge_name, vm_mac) {
            (Some(b), Some(m)) => Some((b, m)),
            _ => None,
        };

        let output = self.run_helper(
            LimaOp::Start {
                vm: &vm_name,
                qemu_wrapper: &qemu_wrapper,
                hardened: config.hardened,
                memory_mb: config.memory_mb,
                cpus: config.cpus,
                // Cast is safe: START_VM_TIMEOUT is 300 s, well within u32.
                start_timeout_s: START_VM_TIMEOUT.as_secs() as u32,
                bridge,
                unrestricted_slirp_for_provisioning,
            },
            // Host-side wall-clock kill: slightly longer than Lima's own
            // --timeout so Lima can report its own error instead of being
            // killed. This is distinct from `start_timeout_s` (above)
            // which is Lima's internal SSH-reachability wait.
            START_VM_TIMEOUT + Duration::from_secs(30),
            "sandbox-lima-helper start",
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("start", &stderr));
        }

        info!(session_id = %session_id, vm = %vm_name, "VM started");
        Ok(())
    }

    /// Stop a running VM.
    pub fn stop_vm(&self, session_id: &SessionId) -> Result<(), SandboxError> {
        let vm_name = vm_name(session_id);

        info!(session_id = %session_id, vm = %vm_name, "stopping VM");

        let output = self.run_helper(
            LimaOp::Stop {
                vm: &vm_name,
                force: false,
            },
            STOP_VM_TIMEOUT,
            "sandbox-lima-helper stop",
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("stop", &stderr));
        }

        info!(session_id = %session_id, vm = %vm_name, "VM stopped");
        Ok(())
    }

    /// Rewrite the sandbox VM's Lima YAML to use a new socket_vmnet slot.
    ///
    /// Called during `start` (resume) on macOS, where slots are non-sticky:
    /// the session was stopped on slot N and is being resumed on slot M.
    /// Lima's `networks: [{socket: ...}]` entry in `lima.yaml` must be
    /// updated to the new slot's socket path before `limactl start`.
    ///
    /// The YAML rewrite is a targeted string replacement: the old
    /// `socket: /var/run/sandbox/vmnet/slot-<N>.sock` line is replaced with
    /// the new slot's path. This is intentionally narrow (not a full YAML
    /// parse/rewrite) to avoid disturbing other fields Lima may have written
    /// into the file (e.g. `status`, `sshLocalPort`).
    ///
    /// The file lives at `{base_dir}/{vm}/lima.yaml`, owned by the operator.
    /// This method runs as the operator uid (via the helper seam) — but since
    /// `run_limactl_direct` / the agent both use the operator's LIMA_HOME, the
    /// file is directly readable/writable here. In single-uid (dev) mode and
    /// in the full agent path, the agent owns the file and writes it.
    ///
    /// On the degenerate-executor (dev) path, the daemon runs as the operator
    /// so it can write the file directly. In the full agent path, this write
    /// happens daemon-side before the brokered `Start` op is sent (the daemon
    /// authors the YAML; the agent validates and re-uses it verbatim).
    #[cfg(target_os = "macos")]
    pub fn rewrite_vm_network_slot(
        &self,
        session_id: &SessionId,
        new_slot: u16,
    ) -> Result<(), SandboxError> {
        use crate::network::{VMNET_SOCKET_DIR, vmnet_slot_socket_path};

        let vm = vm_name(session_id);
        let yaml_path = self.base_dir.join(&vm).join("lima.yaml");

        let contents = std::fs::read_to_string(&yaml_path).map_err(|e| {
            SandboxError::Internal(format!(
                "rewrite_vm_network_slot: failed to read {}: {e}",
                yaml_path.display()
            ))
        })?;

        // Replace any existing slot-N.sock line with the new slot path.
        // Pattern: `  socket: /var/run/sandbox/vmnet/slot-<N>.sock`
        let new_socket = vmnet_slot_socket_path(new_slot);
        let socket_dir = VMNET_SOCKET_DIR;
        let new_contents = {
            let mut out = String::with_capacity(contents.len());
            for line in contents.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("socket:") && trimmed.contains(socket_dir) {
                    // Replace the socket path on this line.
                    let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                    out.push_str(&format!("{indent}socket: {new_socket}\n"));
                } else {
                    out.push_str(line);
                    out.push('\n');
                }
            }
            out
        };

        if new_contents == contents {
            // No socket line found — the YAML may be from before slot support
            // or may have a different format. Log a warning but do not fail:
            // limactl start will use whatever socket is in the file.
            tracing::warn!(
                session_id = %session_id,
                vm = %vm,
                new_slot,
                "rewrite_vm_network_slot: no slot socket line found in lima.yaml; \
                 starting with existing YAML"
            );
        }

        std::fs::write(&yaml_path, new_contents.as_bytes()).map_err(|e| {
            SandboxError::Internal(format!(
                "rewrite_vm_network_slot: failed to write {}: {e}",
                yaml_path.display()
            ))
        })?;

        info!(
            session_id = %session_id,
            vm = %vm,
            new_slot,
            socket = %new_socket,
            "VM Lima YAML rewritten with new slot socket path"
        );
        Ok(())
    }

    /// Force-delete a VM and its Lima data.
    pub fn delete_vm(&self, session_id: &SessionId) -> Result<(), SandboxError> {
        let vm_name = vm_name(session_id);

        info!(session_id = %session_id, vm = %vm_name, "deleting VM");

        let output = self.run_helper(
            LimaOp::Delete { vm: &vm_name },
            DELETE_VM_TIMEOUT,
            "sandbox-lima-helper delete",
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("delete", &stderr));
        }

        info!(session_id = %session_id, vm = %vm_name, "VM deleted");
        Ok(())
    }

    /// Read the owner marker for a VM and return the pool CIDR string, or
    /// `None` if the marker is absent (legacy VM created before this feature).
    ///
    /// The marker file (`{lima_home}{vm}/sandboxd-owner`) lives inside the
    /// operator-owned 0700 instance directory. The daemon cannot read it
    /// directly — this method goes through the helper's `read-owner-marker`
    /// subcommand, which runs post-pivot as the operator uid.
    ///
    /// Returns `None` on non-zero exit (absent marker or I/O error) or empty
    /// stdout. The Lima orphan reaper treats `None` as "legacy, fall back to
    /// name + live-set scoping within this daemon's own LIMA_HOME."
    pub fn read_owner_marker(&self, session_id: &SessionId) -> Option<String> {
        let vm_name = vm_name(session_id);
        let output = match self.run_helper(
            LimaOp::ReadOwnerMarker { vm: &vm_name },
            READ_OWNER_MARKER_TIMEOUT,
            "sandbox-lima-helper read-owner-marker",
        ) {
            Ok(o) => o,
            Err(e) => {
                tracing::debug!(
                    session_id = %session_id,
                    vm = %vm_name,
                    error = %e,
                    "read_owner_marker: helper invocation failed"
                );
                return None;
            }
        };
        if !output.status.success() {
            // Non-zero exit: absent marker (expected for legacy VMs).
            return None;
        }
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }

    /// Best-effort cleanup of a partial Lima instance directory.
    ///
    /// `sandbox-lima-helper clone` is non-atomic: a failure mid-clone can leave
    /// behind `disk` and `cidata.iso` without a `lima.yaml`. From that
    /// point on every subsequent `limactl` invocation host-wide fatals
    /// while enumerating instances ("open lima.yaml: no such file or
    /// directory"), poisoning all other Lima operations until the
    /// orphan dir is removed manually.
    ///
    /// We try the clean path first (`sandbox-lima-helper delete`) and fall
    /// back to a direct `rm -rf <LIMA_HOME>/<vm>` when limactl refuses
    /// to operate on a corrupted instance. Errors are swallowed — this
    /// runs from the error path of another operation, and the caller
    /// already has a primary failure to report.
    fn cleanup_partial_lima_instance(&self, vm: &str) {
        let delete_attempt = self.run_helper(
            LimaOp::Delete { vm },
            DELETE_VM_TIMEOUT,
            "sandbox-lima-helper delete (partial-clone cleanup)",
        );
        match delete_attempt {
            Ok(out) if out.status.success() => {
                debug!(vm, "partial Lima instance removed via helper delete");
                return;
            }
            Ok(out) => {
                debug!(
                    vm,
                    stderr = %String::from_utf8_lossy(&out.stderr),
                    "helper delete on partial clone failed; falling back to fs cleanup"
                );
            }
            Err(e) => {
                debug!(
                    vm, error = %e,
                    "helper delete on partial clone errored; falling back to fs cleanup"
                );
            }
        }

        // Fallback: rm -rf the dir directly under the per-operator LIMA_HOME.
        let target = self.base_dir.join(vm);
        if target.exists() {
            if let Err(e) = std::fs::remove_dir_all(&target) {
                warn!(
                    vm,
                    path = %target.display(),
                    error = %e,
                    "failed to rm -rf partial Lima instance dir (manual cleanup may be required)"
                );
            } else {
                debug!(vm, path = %target.display(), "removed partial Lima instance dir");
            }
        }
    }

    /// Copy the sandbox-guest binary into a running VM and start it as a
    /// systemd service.
    ///
    /// Delegates to `sandbox-lima-helper install-guest-agent`, which performs
    /// the full six-step sequence (copy, mv, chmod, write unit, daemon-reload,
    /// enable --now) followed by four `command -v` probes
    /// (socat/git/rsync/docker). The helper runs as `self.op_uid` post-setresuid.
    ///
    /// This should be called after the VM has booted (i.e. after `start_vm`
    /// or `create_vm` + start). On failure the helper exits non-zero; partial
    /// cleanup is the caller's responsibility (per spec: `cleanup_partial_lima_instance`
    /// is the closest pattern; `build_base_image`'s cleanup path already handles
    /// the base-image case).
    pub fn install_guest_agent(&self, vm_name: &str) -> Result<(), SandboxError> {
        // Wall-clock budget: 6 steps × 30s each + 4 probes × 30s + headroom.
        const INSTALL_TOTAL_TIMEOUT: Duration = Duration::from_secs(360);

        info!(vm = %vm_name, op_uid = self.op_uid, "installing guest agent via helper");

        let output = self.run_helper(
            LimaOp::InstallGuestAgent { vm: vm_name },
            INSTALL_TOTAL_TIMEOUT,
            "sandbox-lima-helper install-guest-agent",
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Lima(format!(
                "sandbox-lima-helper install-guest-agent failed for {vm_name}: {stderr}"
            )));
        }

        info!(vm = %vm_name, "guest agent installed and started");
        Ok(())
    }

    /// Verify that the sandbox VM's management NIC was locked to `restrict=on`
    /// by the qemu-wrapper.
    ///
    /// This is the authoritative post-boot check that the daemon MUST call
    /// before marking a session `Running`. On macOS, the check is brokered
    /// through the operator's agent (which can read the QMP socket and marker
    /// file that live under the operator-owned LIMA_HOME). On Linux, the
    /// wrapper marker file is read directly from `self.base_dir` (the manager's
    /// LIMA_HOME) — no helper invocation is needed because the QEMU process
    /// runs under the same uid as the daemon.
    ///
    /// Returns `Ok(())` when `restrict=on` is confirmed. Returns
    /// `Err(SandboxError::Internal(...))` when verification fails — the caller
    /// MUST tear down the VM, gateway container, and any claimed slot before
    /// returning an error to the API client.
    ///
    /// The wall-clock budget is kept short: the marker/QMP is available as
    /// soon as the QEMU process has processed its argv, which happens during
    /// early boot — well before the VM is considered "Running".
    pub fn verify_restrict_on(&self, session_id: &SessionId) -> Result<(), SandboxError> {
        let vm = vm_name(session_id);

        // macOS: broker the check through the operator's agent so the QMP
        // socket (operator-owned) can be queried. The agent uses QMP
        // query-netdev as authoritative evidence, falling back to the marker.
        #[cfg(target_os = "macos")]
        {
            const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);
            let output = self.run_helper(
                LimaOp::RestrictOnVerify { vm: &vm },
                VERIFY_TIMEOUT,
                "restrict-on-verify",
            )?;
            if output.status.success() {
                info!(
                    session_id = %session_id,
                    vm = %vm,
                    token = %String::from_utf8_lossy(&output.stdout).trim(),
                    "restrict=on confirmed via broker"
                );
                return Ok(());
            }
            let reason = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout_msg = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if reason.is_empty() {
                stdout_msg
            } else {
                reason
            };
            return Err(SandboxError::Internal(format!(
                "restrict-verify failed for session {session_id}: {detail}"
            )));
        }

        // Linux: read the wrapper marker file directly from self.base_dir.
        // The QEMU process and its files are accessible from the daemon
        // (same uid or root-readable), so no broker indirection is needed.
        #[allow(unreachable_code)]
        {
            let marker_path = self.base_dir.join(&vm).join("sandboxd-restrict-marker");
            let contents = match std::fs::read_to_string(&marker_path) {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(SandboxError::Internal(format!(
                        "restrict-verify failed for session {session_id}: \
                         marker not found at {} (qemu-wrapper may not have run)",
                        marker_path.display()
                    )));
                }
                Err(e) => {
                    return Err(SandboxError::Internal(format!(
                        "restrict-verify failed for session {session_id}: \
                         failed to read marker at {}: {e}",
                        marker_path.display()
                    )));
                }
            };
            if contents.contains("restrict=on") {
                info!(
                    session_id = %session_id,
                    vm = %vm,
                    token = %contents.trim(),
                    "restrict=on confirmed via wrapper marker"
                );
                return Ok(());
            }
            Err(SandboxError::Internal(format!(
                "restrict-verify failed for session {session_id}: \
                 marker at {} does not contain 'restrict=on'; contents: {contents:?}",
                marker_path.display()
            )))
        }
    }

    /// Query the status of a single VM.
    pub fn vm_status(&self, session_id: &SessionId) -> Result<VmStatus, SandboxError> {
        let vms = self.list_vms_raw()?;
        let vm_name = vm_name(session_id);
        for entry in &vms {
            if entry.name.as_deref() == Some(vm_name.as_str()) {
                return Ok(parse_status_field(entry.status.as_deref().unwrap_or("")));
            }
        }
        Err(SandboxError::Lima(format!(
            "VM {vm_name} not found in limactl list"
        )))
    }

    /// Resolve a session's per-VM SSH port via `limactl list --json`.
    ///
    /// Reads the `sshLocalPort` field on the entry matching
    /// `sandbox-{session_id}` — the host-side TCP port Lima forwards to
    /// the in-VM sshd's port 22. Used by the daemon's
    /// `GET /sessions/{id}/proxy` handler to dial `127.0.0.1:<port>`
    /// for byte-forwarding to the in-VM sshd.
    ///
    /// Returns `None` if the entry exists but Lima has not assigned a
    /// port yet (typical for VMs in `Stopped` status). Returns an error
    /// if the VM is not registered at all.
    ///
    /// Synchronous shell-out per the project convention: this is a
    /// short one-shot probe and is invoked from `spawn_blocking` on the
    /// async side. The long-lived byte pumps in the proxy handler
    /// follow a different convention (see the async-I/O carve-out in
    /// the cross-user CLI access spec § Architecture → Async I/O note).
    pub fn ssh_local_port_for_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<u16>, SandboxError> {
        let vms = self.list_vms_raw()?;
        let target = vm_name(session_id);
        for entry in vms {
            if entry.name.as_deref() == Some(target.as_str()) {
                return Ok(entry.ssh_local_port);
            }
        }
        Err(SandboxError::Lima(format!(
            "VM {target} not found in limactl list"
        )))
    }

    /// List all sandbox-prefixed VMs known to Lima.
    pub fn list_vms(&self) -> Result<Vec<VmInfo>, SandboxError> {
        let entries = self.list_vms_raw()?;
        Ok(entries
            .into_iter()
            .filter_map(|e| {
                let name = e.name?;
                if !name.starts_with(VM_NAME_PREFIX) {
                    return None;
                }
                let status = parse_status_field(e.status.as_deref().unwrap_or(""));
                let session_id = parse_session_id_from_name(&name);
                Some(VmInfo {
                    name,
                    status,
                    session_id,
                })
            })
            .collect())
    }

    // -- golden image -------------------------------------------------------

    /// Compute a SHA256 content hash of the golden image inputs.
    ///
    /// The hash covers:
    /// 1. The base template YAML content (from `generate_base_template()`)
    /// 2. The guest agent binary bytes (at the path from `guest_agent_path()`)
    ///
    /// If the guest agent binary does not exist, this is treated as a hard
    /// error because the base image cannot be built without it.
    pub fn compute_base_image_hash(&self) -> Result<String, SandboxError> {
        let template = self.generate_base_template();
        let agent_path = guest_agent_path()?;

        if !agent_path.exists() {
            return Err(SandboxError::Internal(format!(
                "guest agent binary not found at {}",
                agent_path.display()
            )));
        }

        let agent_bytes = std::fs::read(&agent_path).map_err(|e| {
            SandboxError::Internal(format!(
                "failed to read guest agent binary at {}: {e}",
                agent_path.display()
            ))
        })?;

        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(template.as_bytes());
        ctx.update(&agent_bytes);
        let hash = ctx.finish();

        Ok(hex_encode(hash.as_ref()))
    }

    /// Check the status of the golden base image.
    ///
    /// Returns `Missing` if the VM does not exist, `Fresh` if it is
    /// up-to-date, or `Stale` if it should be rebuilt.
    pub fn check_base_image(&self) -> Result<BaseImageStatus, SandboxError> {
        // Check if the VM exists.
        let vms = self.list_vms_raw()?;
        let vm_exists = vms
            .iter()
            .any(|e| e.name.as_deref() == Some(self.base_vm_name.as_str()));

        if !vm_exists {
            return Ok(BaseImageStatus::Missing);
        }

        // Read metadata file.
        let meta_path = self.base_dir.join("base-image-meta.json");
        let meta = match std::fs::read_to_string(&meta_path) {
            Ok(content) => match serde_json::from_str::<BaseImageMeta>(&content) {
                Ok(meta) => meta,
                Err(_) => {
                    return Ok(BaseImageStatus::Stale {
                        age_days: 0,
                        hash_mismatch: true,
                    });
                }
            },
            Err(_) => {
                return Ok(BaseImageStatus::Stale {
                    age_days: 0,
                    hash_mismatch: true,
                });
            }
        };

        // Check content hash.
        let current_hash = self.compute_base_image_hash()?;
        if meta.content_hash != current_hash {
            let age_days = age_in_days(&meta.built_at);
            return Ok(BaseImageStatus::Stale {
                age_days,
                hash_mismatch: true,
            });
        }

        // Check age.
        let age_days = age_in_days(&meta.built_at);
        if age_days > BASE_IMAGE_MAX_AGE_DAYS {
            return Ok(BaseImageStatus::Stale {
                age_days,
                hash_mismatch: false,
            });
        }

        Ok(BaseImageStatus::Fresh)
    }

    /// Build the golden base image from scratch.
    ///
    /// Creates a new Lima VM named after `self.base_vm_name`, boots it,
    /// installs the guest agent (via `sandbox-lima-helper install-guest-agent`,
    /// which also runs the four `command -v` tool probes that replace the old
    /// `validate_base_provisioning` step), then stops it. The resulting VM
    /// serves as a template that can be cloned for each new session.
    ///
    /// All `limactl` operations run as `self.op_uid` via the helper, so
    /// `_config/user` is written as the operator uid.
    pub fn build_base_image(&self) -> Result<(), SandboxError> {
        info!(op_uid = self.op_uid, "building golden base image");

        // 1. Generate and write the base template.
        //
        // Write it OUTSIDE LIMA_HOME (under the operator state root, the
        // parent of base_dir) and world-readable. `limactl create --yaml`
        // runs as the operator uid via the helper and must open() this file;
        // a template written inside LIMA_HOME would be unreadable by the
        // operator (the per-operator LIMA_HOME's default ACL denies
        // group/other and omits the named-user entry) and would be
        // enumerated by Lima as a malformed instance. Mirrors
        // write_operator_readable_template and ensure_qemu_wrapper. The
        // template is non-sensitive Lima YAML (no keys, no secrets).
        let template = self.generate_base_template();
        std::fs::create_dir_all(&self.base_dir)?;
        let state_root = self.base_dir.parent().ok_or_else(|| {
            SandboxError::Internal(format!(
                "base_dir {} has no parent — cannot derive operator state root \
                 for base template",
                self.base_dir.display()
            ))
        })?;
        let template_path = state_root.join("base-template.yaml");
        std::fs::write(&template_path, &template)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&template_path, std::fs::Permissions::from_mode(0o644))?;
        }
        info!(path = %template_path.display(), "wrote base template");

        // 2. Create the VM via helper.
        info!("creating base VM");
        let output = self.run_helper(
            LimaOp::Create {
                vm: &self.base_vm_name,
                yaml_path: &template_path,
                owner: &self.owner_pool,
                // The base-image build VM uses Lima's slirp NIC only — there is no
                // socket_vmnet NIC, so the agent must not require a networks: entry.
                is_hardened_session: false,
            },
            BASE_CREATE_TIMEOUT,
            "sandbox-lima-helper create (base image)",
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("create (base image)", &stderr));
        }
        info!("base VM created");

        // Steps 3-6 are wrapped so that a failure cleans up the partially-
        // built VM. Without this, a broken base VM is left in Lima's
        // inventory and subsequent `create` calls try to clone from it,
        // producing non-functional VMs.
        match self.build_base_image_inner() {
            Ok(()) => {
                info!("golden base image build complete");
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, "base image build failed, cleaning up partial VM");
                // Best-effort cleanup — errors here are swallowed.
                let _ = self.run_helper(
                    LimaOp::Delete {
                        vm: &self.base_vm_name,
                    },
                    Duration::from_secs(60),
                    "sandbox-lima-helper delete (base image cleanup)",
                );
                Err(e)
            }
        }
    }

    /// Inner build steps (start, install agent, stop, write metadata).
    /// Separated from `build_base_image` so the caller can clean up on error.
    ///
    /// Acquires `self.build_lock` for its duration so that concurrent
    /// same-operator `build_base_image` calls serialise here. Different
    /// operators hold separate `LimaManager` instances and separate locks,
    /// so they proceed in parallel.
    fn build_base_image_inner(&self) -> Result<(), SandboxError> {
        let _build_guard = self
            .build_lock
            .lock()
            .map_err(|e| SandboxError::Internal(format!("LimaManager build_lock poisoned: {e}")))?;
        // 3. Start the VM with QEMU wrapper for hardening.
        info!("starting base VM (this may take several minutes for cloud-init)");
        let qemu_wrapper = self.resolve_qemu_wrapper()?;

        let output = self.run_helper(
            LimaOp::Start {
                vm: &self.base_vm_name,
                qemu_wrapper: &qemu_wrapper,
                hardened: true,
                memory_mb: 4096,
                cpus: 4,
                // Cast is safe: BASE_START_TIMEOUT is 600 s, well within u32.
                start_timeout_s: BASE_START_TIMEOUT.as_secs() as u32,
                bridge: None,
                // On macOS the only NIC is Lima's slirp eth0; the macOS QEMU
                // wrapper applies restrict=on unless this flag is true. The base
                // VM must reach the internet over eth0 during cloud-init to
                // install socat/git/rsync/docker.io. On Linux the restrict
                // rewrite is gated on SANDBOX_DOCKER_BRIDGE being set, so base
                // builds keep unrestricted slirp as a side effect of having no
                // bridge — the flag is not needed there and stays false.
                unrestricted_slirp_for_provisioning: cfg!(target_os = "macos"),
            },
            // Host-side wall-clock kill: slightly longer than Lima's own
            // --timeout so Lima can report its own error message.
            BASE_START_TIMEOUT + Duration::from_secs(30),
            "sandbox-lima-helper start (base image)",
        )?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(parse_limactl_error("start (base image)", &stderr));
        }
        info!("base VM started");

        // 4. Install the guest agent (helper also runs the four
        //    `command -v {socat,git,rsync,docker}` probes, which replace
        //    the old `validate_base_provisioning` step).
        info!("installing guest agent into base VM");
        self.install_guest_agent(&self.base_vm_name)?;
        info!("guest agent installed in base VM");

        // 5. Stop the VM. Try graceful first; fall back to --force on timeout.
        // The warn! on fallback is the diagnostic signal.
        info!("stopping base VM");
        let graceful = self.run_helper(
            LimaOp::Stop {
                vm: &self.base_vm_name,
                force: false,
            },
            BASE_STOP_GRACEFUL_BUDGET,
            "sandbox-lima-helper stop (base image)",
        );
        match graceful {
            Ok(output) if output.status.success() => {
                info!("base VM stopped (graceful)");
            }
            other => {
                warn!(
                    outcome = ?other,
                    vm = %self.base_vm_name,
                    "graceful stop did not complete in {}s; \
                     falling back to --force. Usually indicates host I/O \
                     contention.",
                    BASE_STOP_GRACEFUL_BUDGET.as_secs(),
                );
                let force = self.run_helper(
                    LimaOp::Stop {
                        vm: &self.base_vm_name,
                        force: true,
                    },
                    BASE_STOP_FORCE_BUDGET,
                    "sandbox-lima-helper stop --force (base image fallback)",
                )?;
                if !force.status.success() {
                    let stderr = String::from_utf8_lossy(&force.stderr);
                    return Err(parse_limactl_error("stop --force (base image)", &stderr));
                }
                info!("base VM stopped (force, after graceful timeout)");
            }
        }

        // 6. Write metadata.
        let content_hash = self.compute_base_image_hash()?;
        let meta = BaseImageMeta {
            built_at: chrono::Utc::now(),
            content_hash,
        };
        let meta_path = self.base_dir.join("base-image-meta.json");
        let meta_json = serde_json::to_string_pretty(&meta).map_err(|e| {
            SandboxError::Internal(format!("failed to serialize base image metadata: {e}"))
        })?;
        std::fs::write(&meta_path, &meta_json)?;
        info!(path = %meta_path.display(), "wrote base image metadata");

        Ok(())
    }

    // validate_base_provisioning was removed; its tool probes now run inside the helper's install-guest-agent step.
    // The four `command -v {socat,git,rsync,docker}` probes are now
    // performed by `sandbox-lima-helper install-guest-agent` as its built-in
    // final validation phase (REQUIRED_BASE_TOOLS in the helper crate).
    // install_guest_agent() returns an error if any probe fails, so the
    // "stamp golden only after tools verified" invariant is preserved.

    /// Delete and rebuild the golden base image.
    pub fn rebuild_base_image(&self) -> Result<(), SandboxError> {
        info!(op_uid = self.op_uid, "rebuilding golden base image");

        // Delete the existing VM (ignore errors if it doesn't exist).
        let output = self.run_helper(
            LimaOp::Delete {
                vm: &self.base_vm_name,
            },
            DELETE_VM_TIMEOUT,
            "sandbox-lima-helper delete (base image)",
        );

        match output {
            Ok(o) if !o.status.success() => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                debug!(stderr = %stderr, "base VM delete returned non-zero (may not exist)");
            }
            Err(e) => {
                debug!(error = %e, "base VM delete failed (may not exist)");
            }
            Ok(_) => {
                info!("deleted existing base VM");
            }
        }

        // Delete the metadata file (ignore errors).
        let meta_path = self.base_dir.join("base-image-meta.json");
        if meta_path.exists() {
            let _ = std::fs::remove_file(&meta_path);
        }

        self.build_base_image()
    }

    /// Clone the golden base image into a new VM for a session.
    ///
    /// The cloned VM gets the specified resource limits. The base image
    /// must exist and be stopped (call `build_base_image()` first).
    ///
    /// Uses `sandbox-lima-helper clone` so the cloned VM is written under
    /// the per-operator LIMA_HOME and `_config/user` is owned by `self.op_uid`.
    pub fn clone_vm(
        &self,
        session_id: SessionId,
        cpus: u32,
        memory_mb: u32,
        disk_gb: u32,
    ) -> Result<(), SandboxError> {
        let target = vm_name(&session_id);
        let memory_gib = mib_to_ceil_gib(memory_mb);

        info!(
            session_id = %session_id,
            vm = %target,
            cpus,
            memory_mb,
            disk_gb,
            op_uid = self.op_uid,
            "cloning base image"
        );

        let output = self
            .run_helper(
                LimaOp::Clone {
                    base: &self.base_vm_name,
                    vm: &target,
                    cpus,
                    memory_gib,
                    disk_gb,
                    owner: &self.owner_pool,
                },
                CLONE_VM_TIMEOUT,
                "sandbox-lima-helper clone",
            )
            .inspect_err(|_| {
                // A timeout or spawn error may have left a half-written instance
                // dir behind. Best-effort cleanup.
                self.cleanup_partial_lima_instance(&target);
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            self.cleanup_partial_lima_instance(&target);
            return Err(parse_limactl_error("clone", &stderr));
        }

        info!(session_id = %session_id, vm = %target, "VM cloned from base image");
        Ok(())
    }

    // -- template generation ------------------------------------------------

    /// Generate a minimal Lima YAML template for the golden base image.
    ///
    /// Unlike `generate_template()`, this template uses fixed minimal
    /// resources (1 CPU, 1024 MB, 10 GB), has no mounts, and includes no
    /// per-session customization.  It carries the same cloud-init
    /// provisioning scripts (user creation, socat/git, Docker install).
    pub fn generate_base_template(&self) -> String {
        let base_vm_name = &self.base_vm_name;
        let ubuntu_amd64 = UBUNTU_IMAGE_AMD64;
        let ubuntu_arm64 = UBUNTU_IMAGE_ARM64;
        format!(
            r#"# Auto-generated Lima template for golden base image
minimumLimaVersion: "2.0.0"

vmType: "qemu"

images:
- location: "{ubuntu_amd64}"
  arch: "x86_64"
- location: "{ubuntu_arm64}"
  arch: "aarch64"

cpus: 4
memory: "4GiB"
disk: "10GiB"

mounts: []
portForwards: []

video:
  display: "none"
audio:
  device: "none"

containerd:
  system: false
  user: false

user:
  name: "sandbox"
  home: "/home/sandbox"

provision:
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=hostname start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    hostnamectl set-hostname {base_vm_name}
    if ! grep -q '{base_vm_name}' /etc/hosts; then
      echo "127.0.1.1 {base_vm_name}" >> /etc/hosts
    fi
    echo "[sandbox-provision] step=hostname done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=user start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Create the in-VM `sandbox` user (uid 1000) with passwordless sudo.
    # Home is /home/sandbox, unified with the container backend — both
    # backends now use the same user name and home directory path.
    if ! id sandbox &>/dev/null; then
      useradd -m -d /home/sandbox -s /bin/bash sandbox
    fi
    echo 'sandbox ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sandbox
    chmod 0440 /etc/sudoers.d/sandbox
    echo "[sandbox-provision] step=user done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=net-tune start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Workaround for libslirp PMTU-propagation gap.
    # libslirp doesn't relay the host's learned PMTU into the guest's
    # TCP state. On host paths with PMTU < 1500 (PPPoE, WiFi, VPN,
    # cellular, NAT64), the guest's full-MTU TCP segments get
    # blackholed — apt-update against Canonical mirrors hangs forever
    # and the e2e base-image build times out at BASE_START_TIMEOUT.
    #
    # Clip eth0 (the SLIRP NIC) to 1280 bytes — the IPv6 minimum
    # (RFC 8200 §5). Every IPv6-capable hop must forward this size,
    # so it's the universal safe floor used by Cloudflare WARP,
    # Tailscale, etc. Throughput cost is negligible for our workload
    # (small apt fetches, package downloads). Session runtime egress
    # uses eth1/the gateway bridge with its own MTU, so agent
    # workloads inside session VMs are unaffected.
    install -m 0600 /dev/stdin /etc/netplan/99-sandbox-mtu.yaml <<'NETPLAN_EOF'
    network:
      version: 2
      ethernets:
        eth0:
          mtu: 1280
    NETPLAN_EOF
    netplan apply
    echo "[sandbox-provision] step=net-tune done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=apt-config start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Switch apt sources to HTTPS and configure fast timeouts
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources
    cat > /etc/apt/apt.conf.d/99sandbox <<'APTEOF'
    Acquire::http::Timeout "5";
    Acquire::https::Timeout "5";
    Acquire::Retries "5";
    Acquire::ForceIPv4 "true";
    Acquire::Queue-Mode "access";
    Acquire::http::Pipeline-Depth "0";
    Acquire::https::Pipeline-Depth "0";
    APTEOF
    echo "[sandbox-provision] step=apt-config done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    export DEBIAN_FRONTEND=noninteractive
    echo "[sandbox-provision] step=apt-baseline start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Baseline packages required by sandboxd's session contract:
    #   - socat: host-guest communication bridge for the guest agent
    #   - git: required by `--repo`, the git remote helper, and
    #     in-session source workflows
    #   - rsync: required by `sandbox sync`, which dispatches
    #     `rsync -e 'limactl shell' …`. The remote side has to
    #     find an rsync binary on PATH or the operator gets a
    #     "command not found" from the remote shell. The host-side
    #     rsync must be present too, but that is the operator's
    #     concern.
    #   - docker.io: provides the in-VM `docker` CLI without adding
    #     Docker Inc.'s external apt repository to sandbox sessions.
    #
    # Wrapped in a retry loop because Lima's user-mode networking
    # (SLIRP) can drop packets under concurrent fetches and apt
    # surfaces those as "Could not wait for server fd - select
    # (11: Resource temporarily unavailable)". Without retry, a
    # single transient flake stamps a baseline-less golden image
    # (cloud-init's per_boot doesn't abort on script failure).
    if ! command -v socat &>/dev/null \
        || ! command -v git &>/dev/null \
        || ! command -v rsync &>/dev/null \
        || ! command -v docker &>/dev/null; then
      attempt=1
      max_attempts=3
      until apt-get update -qq && apt-get install -y socat git rsync docker.io; do
        if [ "$attempt" -ge "$max_attempts" ]; then
          echo "[sandbox-provision] apt-baseline failed after $max_attempts attempts" >&2
          exit 1
        fi
        echo "[sandbox-provision] apt-baseline attempt=$attempt failed, retrying" >&2
        attempt=$((attempt + 1))
        sleep 10
      done
      echo "[sandbox-provision] apt-baseline succeeded after $attempt attempt(s)"
    fi
    # Ensure the workspace directory exists for repo cloning (owned by sandbox, not root)
    mkdir -p /home/sandbox/workspace
    chown sandbox:sandbox /home/sandbox/workspace
    echo "[sandbox-provision] step=apt-baseline done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=docker start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Docker itself is installed by the apt-baseline step via Ubuntu's
    # `docker.io` package. Keep this separate step for the membership
    # side effect and idempotent repair on older base images.
    if command -v docker &>/dev/null; then
      usermod -aG docker sandbox
    fi
    echo "[sandbox-provision] step=docker done=$(date -u +%Y-%m-%dT%H:%M:%S)"
"#,
        )
    }

    /// Generate the Lima YAML template for a session.
    ///
    /// On macOS (`self.is_macos == true`) the template uses:
    /// - A single `aarch64` image (Apple Silicon only).
    /// - A `networks: [{socket: /var/run/sandbox/vmnet/slot-<n>.sock}]` entry
    ///   for the socket_vmnet slot allocated to this session
    ///   (`vmnet_slot` must be `Some` on macOS).
    /// - No Linux seccomp/cgroup wrapper (`SANDBOX_DOCKER_BRIDGE`, etc.).
    /// - Same cloud-init provisioning, `mountType: 9p`, and operator-uid
    ///   alignment as Linux.
    ///
    /// On Linux (`self.is_macos == false`) the template is the same as before:
    /// both `amd64` and `aarch64` images, no `networks:` section (the bridge
    /// NIC is added by the QEMU wrapper at runtime via `SANDBOX_DOCKER_BRIDGE`).
    ///
    /// # Panics
    ///
    /// Panics (via `sanitize_yaml_path`) if a shared-workspace `host_path`
    /// contains characters that are unsafe for YAML interpolation.  In
    /// practice this cannot happen because `WorkspaceMode::parse_flag`
    /// validates the path before it reaches this point, but the check here
    /// acts as defense-in-depth.
    ///
    /// Also panics if `self.is_macos && vmnet_slot.is_none()` (a macOS
    /// template requires a slot index).
    pub fn generate_template(
        &self,
        session_id: &SessionId,
        config: &SessionConfig,
        operator_identity: Option<(u32, u32)>,
        vmnet_slot: Option<u16>,
    ) -> String {
        if self.is_macos {
            return self.generate_template_macos(
                session_id,
                config,
                operator_identity,
                vmnet_slot.expect("generate_template on macOS requires a vmnet_slot"),
            );
        }
        // Hostname includes the full 12-hex session id. At 20 chars it is
        // well under the POSIX HOST_NAME_MAX of 64.
        let hostname = format!("sandbox-{session_id}");

        // Lima expects memory as a string like "4GiB" and disk as "20GiB".
        let memory_gib = format!("{}GiB", mib_to_gib_string(config.memory_mb));
        let disk_gib = format!("{}GiB", config.disk_gb);

        // Build the mounts section: empty by default, populated for shared
        // workspace mode.  We use `9p` (built into QEMU) rather than
        // `virtiofs` because virtiofs requires virtiofsd + shared memory
        // (memfd) which adds complexity and an additional process.
        // 9p runs inside the QEMU process itself.
        //
        // SECURITY NOTE: 9p adds a virtio-9p device to the VM, which
        // expands the attack surface compared to a fully isolated VM.  The
        // host directory is writable by the guest.  This is a documented
        // trade-off — see the "9p shared mounts" section of
        // docs/guides/hardening.md.
        let mounts_section = match &config.workspace_mode {
            Some(WorkspaceMode::Shared {
                host_path,
                guest_path,
                security_model,
            }) => {
                // Validate both paths contain only characters safe for
                // YAML string interpolation.  This prevents injection of
                // arbitrary YAML via crafted directory names containing
                // quotes, newlines, or other YAML-special characters.
                // The same sanitization story applies symmetrically to
                // the operator-supplied `guest_path`.
                let safe_host = sanitize_yaml_path(host_path);
                let safe_guest = sanitize_yaml_path(guest_path);
                // `securityModel` defaults to `mapped-xattr` when the
                // operator did not pick one (`None`); an explicit
                // `Some(_)` is honoured verbatim.
                let model = security_model.unwrap_or_default().as_yaml();
                format!(
                    "\
mountType: \"9p\"
mounts:
- location: \"{safe_host}\"
  mountPoint: \"{safe_guest}\"
  writable: true
  9p:
    securityModel: {model}
    cache: mmap"
                )
            }
            // `Local` is an explicit-sync host snapshot — the daemon
            // populates `guest_path` via rsync after the VM reaches
            // Running, with no 9p device involved. Emit no `mounts:`
            // block so the Lima fast-path cache stays eligible.
            Some(WorkspaceMode::Local { .. }) => "mounts: []".to_string(),
            // `Clone` performs an in-guest `git clone` after boot — no
            // mount surface needed.
            Some(WorkspaceMode::Clone { .. }) => "mounts: []".to_string(),
            None => "mounts: []".to_string(),
        };

        // When hardened, tell Lima to disable video and audio devices.  Lima
        // translates these into the appropriate QEMU flags at VM creation
        // time, ensuring no display or sound device is attached.
        let hardened_section = if config.hardened {
            "\nvideo:\n  display: \"none\"\naudio:\n  device: \"none\""
        } else {
            ""
        };

        // Optional cloud-init step that re-aligns the in-VM `sandbox`
        // user's uid/gid with the operator's host-side identity.
        //
        // The base image bakes `sandbox` at uid 1000 / gid 1000 (the
        // common case). When the operator on the host happens to also
        // be uid 1000 / gid 1000 (single-user dev box, the typical
        // Linux desktop), this step is a no-op and we elide it to keep
        // cloud-init runs quick. When the operator is a different uid
        // (multi-user host, NFS-backed home dir at uid 5xxx, CI box at
        // uid 2000), we run `usermod` + `groupmod` + a recursive
        // chown on `/home/sandbox` so:
        //
        //   - the in-VM `sandbox` user owns its home dir
        //   - 9p `mapped-xattr` shared workspaces don't trip the
        //     ownership-mismatch check on bind-mount writes
        //   - the QEMU process spawned via `sandbox-lima-helper` (uid
        //     = operator's, after setresuid) can `setuid(sandbox)` on
        //     the in-VM side and end up with the expected uid
        //
        // The chown is recursive because the base image populated the dir
        // tree (e.g. `.bash_profile`, sshd authorized_keys staging)
        // before this step runs. Both Lima and container backends now
        // share `/home/sandbox` as the in-VM user home.
        let usermod_section = match operator_identity {
            Some((uid, gid)) if uid != 1000 || gid != 1000 => format!(
                "- mode: system\n  \
                 script: |\n    \
                 #!/bin/bash\n    \
                 set -eux -o pipefail\n    \
                 echo \"[sandbox-provision] step=operator-uid start=$(date -u +%Y-%m-%dT%H:%M:%S)\"\n    \
                 # Re-align the in-VM `sandbox` account's uid/gid with the\n    \
                 # operator's host-side identity ({uid}:{gid}). The base\n    \
                 # image bakes uid/gid 1000; this step bumps them to the\n    \
                 # operator's values so 9p mapped-xattr shared workspaces\n    \
                 # and synthetic /etc/passwd consistency hold.\n    \
                 if id sandbox &>/dev/null; then\n    \
                   current_uid=$(id -u sandbox)\n    \
                   current_gid=$(id -g sandbox)\n    \
                   if [ \"$current_uid\" != \"{uid}\" ] || [ \"$current_gid\" != \"{gid}\" ]; then\n    \
                     # `groupmod` first because `usermod -u` validates\n    \
                     # the primary group still exists at the new gid.\n    \
                     groupmod -g {gid} sandbox\n    \
                     usermod -u {uid} -g {gid} sandbox\n    \
                     chown -R {uid}:{gid} /home/sandbox\n    \
                   fi\n    \
                 fi\n    \
                 echo \"[sandbox-provision] step=operator-uid done=$(date -u +%Y-%m-%dT%H:%M:%S)\"\n"
            ),
            _ => String::new(),
        };

        format!(
            r#"# Auto-generated Lima template for sandbox session {session_id}
minimumLimaVersion: "2.0.0"

vmType: "qemu"

images:
- location: "{ubuntu_amd64}"
  arch: "x86_64"
- location: "{ubuntu_arm64}"
  arch: "aarch64"

cpus: {cpus}
memory: "{memory_gib}"
disk: "{disk_gib}"

{mounts_section}
portForwards: []
{hardened_section}
containerd:
  system: false
  user: false

user:
  name: "sandbox"
  home: "/home/sandbox"

provision:
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=hostname start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    hostnamectl set-hostname {hostname}
    # Add hostname to /etc/hosts so 'sudo' and other tools that resolve
    # the local hostname do not emit "unable to resolve host" warnings.
    if ! grep -q '{hostname}' /etc/hosts; then
      echo "127.0.1.1 {hostname}" >> /etc/hosts
    fi
    echo "[sandbox-provision] step=hostname done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=user start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Create the in-VM `sandbox` user (uid 1000) with passwordless sudo.
    # Home is /home/sandbox, unified with the container backend — both
    # backends now use the same user name and home directory path.
    if ! id sandbox &>/dev/null; then
      useradd -m -d /home/sandbox -s /bin/bash sandbox
    fi
    echo 'sandbox ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sandbox
    chmod 0440 /etc/sudoers.d/sandbox
    echo "[sandbox-provision] step=user done=$(date -u +%Y-%m-%dT%H:%M:%S)"
{usermod_section}- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=net-tune start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Workaround for libslirp PMTU-propagation gap.
    # libslirp doesn't relay the host's learned PMTU into the guest's
    # TCP state. On host paths with PMTU < 1500 (PPPoE, WiFi, VPN,
    # cellular, NAT64), the guest's full-MTU TCP segments get
    # blackholed — apt-update against Canonical mirrors hangs forever
    # and the e2e base-image build times out at BASE_START_TIMEOUT.
    #
    # Clip eth0 (the SLIRP NIC) to 1280 bytes — the IPv6 minimum
    # (RFC 8200 §5). Every IPv6-capable hop must forward this size,
    # so it's the universal safe floor used by Cloudflare WARP,
    # Tailscale, etc. Throughput cost is negligible for our workload
    # (small apt fetches, package downloads). Session runtime egress
    # uses eth1/the gateway bridge with its own MTU, so agent
    # workloads inside session VMs are unaffected.
    install -m 0600 /dev/stdin /etc/netplan/99-sandbox-mtu.yaml <<'NETPLAN_EOF'
    network:
      version: 2
      ethernets:
        eth0:
          mtu: 1280
    NETPLAN_EOF
    netplan apply
    echo "[sandbox-provision] step=net-tune done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=apt-config start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Switch apt sources to HTTPS and configure fast timeouts
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources
    cat > /etc/apt/apt.conf.d/99sandbox <<'APTEOF'
    Acquire::http::Timeout "5";
    Acquire::https::Timeout "5";
    Acquire::Retries "5";
    Acquire::ForceIPv4 "true";
    Acquire::Queue-Mode "access";
    Acquire::http::Pipeline-Depth "0";
    Acquire::https::Pipeline-Depth "0";
    APTEOF
    echo "[sandbox-provision] step=apt-config done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    export DEBIAN_FRONTEND=noninteractive
    echo "[sandbox-provision] step=apt-baseline start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Baseline packages required by sandboxd's session contract:
    # socat (guest-agent bridge), git (`--repo` + remote helper),
    # rsync (`sandbox sync`), docker.io (in-VM `docker` CLI). The base
    # image already installs these — this block is a defence-in-depth
    # no-op when the VM was cloned from an up-to-date base, and a
    # recovery path when it wasn't. See base template for retry
    # rationale.
    if ! command -v socat &>/dev/null \
        || ! command -v git &>/dev/null \
        || ! command -v rsync &>/dev/null \
        || ! command -v docker &>/dev/null; then
      attempt=1
      max_attempts=3
      until apt-get update -qq && apt-get install -y socat git rsync docker.io; do
        if [ "$attempt" -ge "$max_attempts" ]; then
          echo "[sandbox-provision] apt-baseline failed after $max_attempts attempts" >&2
          exit 1
        fi
        echo "[sandbox-provision] apt-baseline attempt=$attempt failed, retrying" >&2
        attempt=$((attempt + 1))
        sleep 10
      done
      echo "[sandbox-provision] apt-baseline succeeded after $attempt attempt(s)"
    fi
    # Ensure the workspace directory exists for repo cloning (owned by sandbox, not root)
    mkdir -p /home/sandbox/workspace
    chown sandbox:sandbox /home/sandbox/workspace
    echo "[sandbox-provision] step=apt-baseline done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=docker start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Docker itself is installed by the apt-baseline step via Ubuntu's
    # `docker.io` package. Keep this separate step for the membership
    # side effect and idempotent repair on older base images.
    if command -v docker &>/dev/null; then
      usermod -aG docker sandbox
    fi
    echo "[sandbox-provision] step=docker done=$(date -u +%Y-%m-%dT%H:%M:%S)"
"#,
            session_id = session_id,
            cpus = config.cpus,
            memory_gib = memory_gib,
            disk_gib = disk_gib,
            mounts_section = mounts_section,
            hardened_section = hardened_section,
            usermod_section = usermod_section,
            hostname = hostname,
            ubuntu_amd64 = UBUNTU_IMAGE_AMD64,
            ubuntu_arm64 = UBUNTU_IMAGE_ARM64,
        )
    }

    /// Generate the macOS-specific Lima YAML template for a sandbox session VM.
    ///
    /// Key differences from the Linux template:
    /// - **Single `aarch64` image** (Apple Silicon only; no `amd64` entry).
    /// - **`networks: [{socket: ...}]`** socket_vmnet NIC for the allocated
    ///   vmnet slot.  Lima adds its mandatory slirp management NIC automatically.
    /// - **Explicit `vmType: "qemu"`** — Lima on macOS defaults to VZ
    ///   (Virtualization.framework) when `vmType` is unset, and VZ cannot attach
    ///   socket_vmnet NICs.  A VM booting under VZ would use vzNAT and bypass
    ///   the gateway entirely, voiding egress control.  The template always
    ///   emits `vmType: "qemu"` explicitly; the agent's
    ///   `validate_lima_yaml_shape` now requires it.
    /// - **No Linux process-isolation wrapper** — `systemd-run`, cgroups,
    ///   namespace flags, and QEMU `-sandbox` seccomp are Linux-only features.
    /// - **Static IP cloud-init** — the socket_vmnet segment has no DHCP.
    ///   The sandbox VM's gateway NIC (`lima0`) is configured with a static
    ///   `B+4` address and default route pointing to the gateway container
    ///   (`B+3`), where `B` is the /29 base for slot `n`.
    ///   (`10.209.128.0 + 8*n` per the subnet allocation table.)
    /// - Everything else (cloud-init provisioning, operator-uid alignment,
    ///   9p mounts, hardened video/audio) is identical to Linux.
    ///
    /// Called by [`generate_template`] when `self.is_macos == true`.
    fn generate_template_macos(
        &self,
        session_id: &SessionId,
        config: &SessionConfig,
        operator_identity: Option<(u32, u32)>,
        vmnet_slot: u16,
    ) -> String {
        let hostname = format!("sandbox-{session_id}");
        let memory_gib = format!("{}GiB", mib_to_gib_string(config.memory_mb));
        let disk_gib = format!("{}GiB", config.disk_gb);

        // Compute the /29 base for this slot: 10.209.128.0 + 8*n
        // Address roles per § Subnet allocation:
        //   B+3 = gateway container IP (the VM's default route)
        //   B+4 = sandbox VM IP (assigned statically via cloud-init)
        let slot = vmnet_slot as u32;
        let base_u32: u32 = (10 << 24) | (209 << 16) | (128 << 8) | (slot * 8);
        let gateway_ip = format!(
            "{}.{}.{}.{}",
            (base_u32 >> 24) & 0xff,
            (base_u32 >> 16) & 0xff,
            (base_u32 >> 8) & 0xff,
            (base_u32 & 0xff) + 3,
        );
        let vm_ip = format!(
            "{}.{}.{}.{}",
            (base_u32 >> 24) & 0xff,
            (base_u32 >> 16) & 0xff,
            (base_u32 >> 8) & 0xff,
            (base_u32 & 0xff) + 4,
        );
        let socket_path = format!("/var/run/sandbox/vmnet/slot-{vmnet_slot}.sock");

        // Mounts section — identical logic to the Linux path.
        let mounts_section = match &config.workspace_mode {
            Some(WorkspaceMode::Shared {
                host_path,
                guest_path,
                security_model,
            }) => {
                let safe_host = sanitize_yaml_path(host_path);
                let safe_guest = sanitize_yaml_path(guest_path);
                let model = security_model.unwrap_or_default().as_yaml();
                format!(
                    "\
mountType: \"9p\"
mounts:
- location: \"{safe_host}\"
  mountPoint: \"{safe_guest}\"
  writable: true
  9p:
    securityModel: {model}
    cache: mmap"
                )
            }
            _ => "mounts: []".to_string(),
        };

        let hardened_section = if config.hardened {
            "\nvideo:\n  display: \"none\"\naudio:\n  device: \"none\""
        } else {
            ""
        };

        // Operator-uid alignment cloud-init — identical to Linux.
        let usermod_section = match operator_identity {
            Some((uid, gid)) if uid != 1000 || gid != 1000 => format!(
                "- mode: system\n  \
                 script: |\n    \
                 #!/bin/bash\n    \
                 set -eux -o pipefail\n    \
                 echo \"[sandbox-provision] step=operator-uid start=$(date -u +%Y-%m-%dT%H:%M:%S)\"\n    \
                 # Re-align the in-VM `sandbox` account's uid/gid with the\n    \
                 # operator's host-side identity ({uid}:{gid}). The base\n    \
                 # image bakes uid/gid 1000; this step bumps them to the\n    \
                 # operator's values so 9p mapped-xattr shared workspaces\n    \
                 # and synthetic /etc/passwd consistency hold.\n    \
                 if id sandbox &>/dev/null; then\n    \
                   current_uid=$(id -u sandbox)\n    \
                   current_gid=$(id -g sandbox)\n    \
                   if [ \"$current_uid\" != \"{uid}\" ] || [ \"$current_gid\" != \"{gid}\" ]; then\n    \
                     # `groupmod` first because `usermod -u` validates\n    \
                     # the primary group still exists at the new gid.\n    \
                     groupmod -g {gid} sandbox\n    \
                     usermod -u {uid} -g {gid} sandbox\n    \
                     chown -R {uid}:{gid} /home/sandbox\n    \
                   fi\n    \
                 fi\n    \
                 echo \"[sandbox-provision] step=operator-uid done=$(date -u +%Y-%m-%dT%H:%M:%S)\"\n"
            ),
            _ => String::new(),
        };

        format!(
            r#"# Auto-generated Lima template for macOS sandbox session {session_id}
minimumLimaVersion: "2.0.0"

vmType: "qemu"

images:
- location: "{ubuntu_arm64}"
  arch: "aarch64"

cpus: {cpus}
memory: "{memory_gib}"
disk: "{disk_gib}"

networks:
- socket: {socket_path}

{mounts_section}
portForwards: []
{hardened_section}
containerd:
  system: false
  user: false

user:
  name: "sandbox"
  home: "/home/sandbox"

provision:
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=hostname start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    hostnamectl set-hostname {hostname}
    if ! grep -q '{hostname}' /etc/hosts; then
      echo "127.0.1.1 {hostname}" >> /etc/hosts
    fi
    echo "[sandbox-provision] step=hostname done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=user start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    if ! id sandbox &>/dev/null; then
      useradd -m -d /home/sandbox -s /bin/bash sandbox
    fi
    echo 'sandbox ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sandbox
    chmod 0440 /etc/sudoers.d/sandbox
    echo "[sandbox-provision] step=user done=$(date -u +%Y-%m-%dT%H:%M:%S)"
{usermod_section}- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=net-tune start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Clamp eth0 (the slirp/Lima management NIC) MTU to 1280.
    # libslirp doesn't relay host PMTU into the guest; 1280 is the
    # IPv6 minimum — safe on all paths.
    install -m 0600 /dev/stdin /etc/netplan/99-sandbox-mtu.yaml <<'NETPLAN_EOF'
    network:
      version: 2
      ethernets:
        eth0:
          optional: true
          mtu: 1280
    NETPLAN_EOF
    netplan apply
    echo "[sandbox-provision] step=net-tune done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=net-vmnet start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # Configure lima0 (socket_vmnet NIC) with a static IP.
    # The socket_vmnet segment has no DHCP; addresses are assigned statically.
    # B+4 = sandbox VM IP; B+3 = gateway container (default route).
    # Without this, systemd-networkd stalls at boot waiting for DHCP
    # that never arrives on the network-identifier segment.
    install -m 0600 /dev/stdin /etc/netplan/99-sandbox-vmnet.yaml <<'NETPLAN_EOF'
    network:
      version: 2
      ethernets:
        lima0:
          optional: true
          dhcp4: no
          addresses:
            - {vm_ip}/29
          routes:
            - to: default
              via: {gateway_ip}
          nameservers:
            addresses:
              - {gateway_ip}
    NETPLAN_EOF
    netplan apply
    echo "[sandbox-provision] step=net-vmnet done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=wait-online start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    # systemd-networkd-wait-online drop-in: pass --any so the service
    # reports online as soon as at least one interface is configured,
    # rather than waiting for ALL interfaces. On macOS sandbox VMs the
    # lima0 (socket_vmnet) interface is configured statically by the
    # net-vmnet step above, but if the socket_vmnet segment is not yet
    # bridged (e.g. during the very first create before the gateway
    # container is fully up), networkd may briefly mark lima0 as
    # "configuring" and wait-online blocks indefinitely — exceeding the
    # 300 s START_VM_TIMEOUT and causing `create` to roll back with a
    # confusing timeout. The --any flag makes eth0 (the SLIRP management
    # NIC, always up) sufficient to satisfy the wait. Note: netplan
    # `optional: true` on lima0 was intended to exempt it from the wait,
    # but that only affects networkd's per-link RequiredForOnline state;
    # the service-level --any override is the reliable guard.
    # NEEDS_LIVE_E2E: effectiveness against the dead-segment hang
    # requires a live macOS full-backend test (tracked as #249).
    mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d
    cat > /etc/systemd/system/systemd-networkd-wait-online.service.d/sandbox-any.conf <<'DROPIN_EOF'
    [Service]
    ExecStart=
    ExecStart=/lib/systemd/systemd-networkd-wait-online --any
    DROPIN_EOF
    systemctl daemon-reload
    echo "[sandbox-provision] step=wait-online done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=apt-config start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources
    cat > /etc/apt/apt.conf.d/99sandbox <<'APTEOF'
    Acquire::http::Timeout "5";
    Acquire::https::Timeout "5";
    Acquire::Retries "5";
    Acquire::ForceIPv4 "true";
    Acquire::Queue-Mode "access";
    Acquire::http::Pipeline-Depth "0";
    Acquire::https::Pipeline-Depth "0";
    APTEOF
    echo "[sandbox-provision] step=apt-config done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    export DEBIAN_FRONTEND=noninteractive
    echo "[sandbox-provision] step=apt-baseline start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    if ! command -v socat &>/dev/null \
        || ! command -v git &>/dev/null \
        || ! command -v rsync &>/dev/null \
        || ! command -v docker &>/dev/null; then
      attempt=1
      max_attempts=3
      until apt-get update -qq && apt-get install -y socat git rsync docker.io; do
        if [ "$attempt" -ge "$max_attempts" ]; then
          echo "[sandbox-provision] apt-baseline failed after $max_attempts attempts" >&2
          exit 1
        fi
        echo "[sandbox-provision] apt-baseline attempt=$attempt failed, retrying" >&2
        attempt=$((attempt + 1))
        sleep 10
      done
      echo "[sandbox-provision] apt-baseline succeeded after $attempt attempt(s)"
    fi
    mkdir -p /home/sandbox/workspace
    chown sandbox:sandbox /home/sandbox/workspace
    echo "[sandbox-provision] step=apt-baseline done=$(date -u +%Y-%m-%dT%H:%M:%S)"
- mode: system
  script: |
    #!/bin/bash
    set -eux -o pipefail
    echo "[sandbox-provision] step=docker start=$(date -u +%Y-%m-%dT%H:%M:%S)"
    if command -v docker &>/dev/null; then
      usermod -aG docker sandbox
    fi
    echo "[sandbox-provision] step=docker done=$(date -u +%Y-%m-%dT%H:%M:%S)"
"#,
            session_id = session_id,
            cpus = config.cpus,
            memory_gib = memory_gib,
            disk_gib = disk_gib,
            socket_path = socket_path,
            mounts_section = mounts_section,
            hardened_section = hardened_section,
            usermod_section = usermod_section,
            hostname = hostname,
            vm_ip = vm_ip,
            gateway_ip = gateway_ip,
            ubuntu_arm64 = UBUNTU_IMAGE_ARM64,
        )
    }

    // -- helpers ------------------------------------------------------------

    /// Return the appropriate QEMU wrapper path for this platform.
    ///
    /// On macOS (`self.is_macos`) delegates to `ensure_qemu_wrapper_macos`;
    /// on Linux delegates to `ensure_qemu_wrapper`.
    fn resolve_qemu_wrapper(&self) -> Result<PathBuf, SandboxError> {
        if self.is_macos {
            #[cfg(target_os = "macos")]
            {
                self.ensure_qemu_wrapper_macos()
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err(SandboxError::Internal(
                    "resolve_qemu_wrapper: is_macos=true but cfg(target_os) is not macos"
                        .to_string(),
                ))
            }
        } else {
            self.ensure_qemu_wrapper()
        }
    }

    /// Create a QEMU wrapper script that injects process hardening.
    ///
    /// The wrapper does three things:
    ///
    /// 1. **PCIe root-port** — The q35 machine type does not include any PCIe
    ///    root-port by default, which means no PCIe device (including
    ///    virtio-net-pci) can be hot-added via QMP.
    ///
    /// 2. **Device lockdown** — Disables unnecessary QEMU devices (USB, sound,
    ///    display, floppy, HPET) and adds virtio-rng for guest entropy.
    ///
    /// 3. **Cgroup limits** — When `SANDBOX_QEMU_MEMORY_MB` and
    ///    `SANDBOX_QEMU_CPUS` environment variables are set (propagated from
    ///    [`SessionConfig`] in [`start_vm`]), the wrapper uses `systemd-run` to
    ///    place the QEMU process in a scoped cgroup with memory and CPU limits.
    ///    If `systemd-run` is absent **or** the operator's user-systemd bus is
    ///    not reachable (no active login session and `loginctl enable-linger
    ///    <operator>` not enabled), the wrapper falls back to running QEMU
    ///    without cgroup limits and emits a warning to stderr. See
    ///    `docs/guides/hardening.md` § "Prerequisite: `loginctl enable-linger`".
    ///
    /// Lima does not expose a way to pass extra QEMU arguments, so we
    /// interpose a shell wrapper that Lima invokes via the
    /// `QEMU_SYSTEM_X86_64` environment variable.
    ///
    /// # Layout
    ///
    /// The wrapper is written to the operator **state root** — the parent of
    /// LIMA_HOME — not inside LIMA_HOME itself.  Lima enumerates every
    /// subdirectory of LIMA_HOME as a potential instance and fatals when it
    /// finds one without a `lima.yaml`; placing `libexec/` inside LIMA_HOME
    /// triggers exactly that fatal.  The production path is:
    ///
    /// ```text
    /// /var/lib/sandboxd/<daemon_uid>/<op_uid>/   ← operator state root
    ///   lima/                                    ← LIMA_HOME  (base_dir)
    ///     <vm-name>/                             ← Lima instance dirs
    ///   libexec/                                 ← wrapper dir  (base_dir/../libexec)
    ///     qemu-system-x86_64                    ← this wrapper, mode 0755
    /// ```
    ///
    /// The wrapper and its directory are world-readable and world-executable
    /// (`0755`).  The script contains no secrets; world-exec is required so
    /// the operator-uid QEMU process (which runs after the helper's
    /// `setresuid`) can execute the wrapper regardless of which uid owns the
    /// parent state-root directory.
    pub(crate) fn ensure_qemu_wrapper(&self) -> Result<PathBuf, SandboxError> {
        // Place the wrapper OUTSIDE LIMA_HOME so limactl never enumerates it
        // as a malformed instance.  base_dir == LIMA_HOME, so its parent is
        // the operator state root (/var/lib/sandboxd/<daemon_uid>/<op_uid>/).
        let state_root = self.base_dir.parent().ok_or_else(|| {
            SandboxError::Internal(format!(
                "base_dir {} has no parent — cannot derive operator state root for QEMU wrapper",
                self.base_dir.display()
            ))
        })?;
        let wrapper_dir = state_root.join("libexec");
        std::fs::create_dir_all(&wrapper_dir)?;

        // Ensure the directory itself is world-executable so the
        // operator-uid QEMU process can enter it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&wrapper_dir, std::fs::Permissions::from_mode(0o755))?;
        }

        let wrapper_path = wrapper_dir.join("qemu-system-x86_64");

        // The wrapper script is idempotent — overwrite if the content changed.
        let script = QEMU_WRAPPER_SCRIPT;
        std::fs::write(&wrapper_path, script)?;

        // chmod +x
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755))?;
        }

        debug!(path = %wrapper_path.display(), "QEMU wrapper script ready");
        Ok(wrapper_path)
    }

    /// Test-only escape hatch: write the QEMU wrapper script to disk and
    /// return its path.  The wrapper lands at `base_dir/../libexec/` (the
    /// operator state root sibling of LIMA_HOME), mirroring the production
    /// layout where LIMA_HOME == `base_dir`.
    ///
    /// Used by the workspace's integration tests to drive the wrapper
    /// against a stub QEMU and capture its composed argv. Production
    /// callers go through [`LimaManager::start_vm`], which invokes
    /// the private [`Self::ensure_qemu_wrapper`] internally.
    #[doc(hidden)]
    pub fn ensure_qemu_wrapper_for_test(&self) -> Result<PathBuf, SandboxError> {
        self.ensure_qemu_wrapper()
    }

    /// Create the macOS `restrict=on` qemu-wrapper and its firmware symlink.
    ///
    /// # Wrapper binary
    ///
    /// The wrapper script is written to `{operator_state_root}/libexec/` as
    /// `qemu-system-aarch64` (mode 0755, world-executable).  Lima passes the
    /// wrapper dir via `--qemu-binary-path` (which it derives from
    /// `--qemu-wrapper`) to resolve firmware paths, so the binary name must
    /// match Lima's probing logic (`qemu-system-aarch64`).
    ///
    /// # Firmware symlink
    ///
    /// Lima derives the edk2 firmware search path from the qemu binary's
    /// directory: `<wrapper_dir>/../share/qemu/edk2-aarch64-code.fd`.  The
    /// wrapper's parent directory must therefore expose `share/qemu/` pointing
    /// at the Homebrew firmware dir so Lima can resolve the firmware.  This
    /// function creates:
    ///
    /// ```text
    /// {operator_state_root}/
    ///   libexec/
    ///     qemu-system-aarch64   ← wrapper script (mode 0755)
    ///   share -> /opt/homebrew/share  ← symlink for firmware resolution
    /// ```
    ///
    /// If the Homebrew share dir (`/opt/homebrew/share`) does not exist
    /// (non-macOS build, or Homebrew not installed), the symlink creation is
    /// silently skipped — Lima will emit a firmware warning on first use, but
    /// the wrapper itself is still functional.
    ///
    /// # Returns
    ///
    /// The absolute path to the wrapper script.
    #[cfg(target_os = "macos")]
    pub(crate) fn ensure_qemu_wrapper_macos(&self) -> Result<PathBuf, SandboxError> {
        let state_root = self.base_dir.parent().ok_or_else(|| {
            SandboxError::Internal(format!(
                "base_dir {} has no parent — cannot derive operator state root for macOS QEMU wrapper",
                self.base_dir.display()
            ))
        })?;
        let wrapper_dir = state_root.join("libexec");
        std::fs::create_dir_all(&wrapper_dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&wrapper_dir, std::fs::Permissions::from_mode(0o755))?;
        }

        // Write the wrapper script as `qemu-system-aarch64` (aarch64 only on macOS).
        let wrapper_path = wrapper_dir.join("qemu-system-aarch64");
        let script = QEMU_WRAPPER_MACOS_SCRIPT;
        std::fs::write(&wrapper_path, script)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&wrapper_path, std::fs::Permissions::from_mode(0o755))?;
        }

        // Create a `share` symlink in the state root pointing at the Homebrew
        // share directory so Lima can find the edk2 firmware.  Lima resolves:
        //   <wrapper_dir>/../share/qemu/edk2-aarch64-code.fd
        // which expands to:
        //   {state_root}/share/qemu/edk2-aarch64-code.fd → Homebrew firmware.
        let share_link = state_root.join("share");
        let homebrew_share = std::path::Path::new("/opt/homebrew/share");
        if homebrew_share.exists() && !share_link.exists() {
            #[cfg(unix)]
            {
                if let Err(e) = std::os::unix::fs::symlink(homebrew_share, &share_link) {
                    // Non-fatal: Lima will warn about missing firmware but the wrapper works.
                    debug!(
                        link = %share_link.display(),
                        target = %homebrew_share.display(),
                        error = %e,
                        "macOS QEMU wrapper: could not create firmware symlink (non-fatal)"
                    );
                }
            }
        }

        debug!(path = %wrapper_path.display(), "macOS QEMU wrapper script ready");
        Ok(wrapper_path)
    }

    /// Test-only escape hatch for the macOS wrapper.
    #[cfg(all(test, target_os = "macos"))]
    pub fn ensure_qemu_wrapper_macos_for_test(&self) -> Result<PathBuf, SandboxError> {
        self.ensure_qemu_wrapper_macos()
    }

    /// Read the operator's Lima SSH private key by invoking
    /// `sandbox-lima-helper read-user-key --op-uid <N>`.
    ///
    /// The helper pivots to the operator uid via `setresuid` before reading
    /// `$LIMA_HOME/_config/user` (mode 0600, owned by the operator). The
    /// daemon (uid 999) cannot read that file directly; the helper is the
    /// correct cross-user pivot, parallel to how `list-json` and
    /// `guest-socat` already operate.
    ///
    /// Returns the key bytes as a `String` (verbatim PEM/OpenSSH format).
    /// The daemon serves this through `GET /sessions/{id}/ssh-config` so
    /// the CLI can authenticate to the operator's VM without reading the
    /// key file directly.
    pub fn read_user_key(&self) -> Result<String, SandboxError> {
        let output = self.run_helper(
            LimaOp::ReadUserKey,
            Duration::from_secs(10),
            "sandbox-lima-helper read-user-key",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Internal(format!(
                "sandbox-lima-helper read-user-key failed for op_uid={}: {stderr}",
                self.op_uid
            )));
        }
        let key = String::from_utf8(output.stdout).map_err(|e| {
            SandboxError::Internal(format!(
                "Lima user key for op_uid={} is not valid UTF-8: {e}",
                self.op_uid
            ))
        })?;
        if key.is_empty() {
            return Err(SandboxError::Internal(format!(
                "Lima user key for op_uid={} is empty; VM may not have been provisioned yet",
                self.op_uid
            )));
        }
        Ok(key)
    }

    /// Run `sandbox-lima-helper list-json` and deserialize the raw entries.
    ///
    /// The helper execvp's `limactl list --json --tty=false` as `self.op_uid`
    /// with `LIMA_HOME` set to the per-operator path.
    fn list_vms_raw(&self) -> Result<Vec<LimactlListEntry>, SandboxError> {
        let output = self.run_helper(
            LimaOp::ListJson,
            LIST_VMS_TIMEOUT,
            "sandbox-lima-helper list-json",
        )?;

        // Lima writes a warning to stderr and returns empty stdout when no
        // instances exist.  Treat empty stdout as an empty list.
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            return Ok(Vec::new());
        }

        parse_limactl_list_output(&stdout)
    }
}

// ---------------------------------------------------------------------------
// VM naming helpers (public for tests)
// ---------------------------------------------------------------------------

/// Production install path for the `sandbox-guest` helper binary.
///
/// The helper is a daemon-internal artifact (not operator-facing), so
/// it lives under `/usr/local/libexec/sandboxd/` per FHS § 4.7 — the
/// same directory the cap'd `sandbox-route-helper` is installed to.
/// `scripts/install.sh` lays it down here, `scripts/uninstall.sh`
/// removes it, and the daemon's startup-staging path (and Lima VM
/// provisioning) reads it from this location.
pub const PRODUCTION_GUEST_BINARY_PATH: &str = "/usr/local/libexec/sandboxd/sandbox-guest";

/// Env-var name a `test-env-override` build of the daemon consults to
/// redirect [`guest_agent_path`] at an alternate `sandbox-guest`
/// binary. Production builds ignore this variable; the integration-
/// test harness sets it so a test-local cargo build can drive the
/// staging path without installing into `/usr/local/libexec/`.
pub const GUEST_BINARY_PATH_OVERRIDE_ENV: &str = "SANDBOXD_GUEST_BINARY_PATH";

/// Resolve the path to the `sandbox-guest` binary.
///
/// `sandbox-guest` is a daemon-internal helper, not an operator-
/// facing tool. In production it is installed by `scripts/install.sh`
/// to [`PRODUCTION_GUEST_BINARY_PATH`]. In `cargo` / `cargo nextest`
/// dev workflows the workspace build writes it to
/// `target/{debug,release}/sandbox-guest`, which is either a sibling
/// of `sandboxd` (release / `cargo run`) or a grandparent of the
/// nextest test binary (`target/debug/deps/<hash>/<test>`).
///
/// Resolution order — first existing path wins:
///
/// 1. **`test-env-override`-only**: the value of
///    `SANDBOXD_GUEST_BINARY_PATH` if set (the integration-test
///    harness's dev loop pins this so a freshly `cargo build`'d guest
///    binary can be staged without polluting `/usr/local/libexec/`).
///    Production builds skip this branch entirely; the env var is
///    untrusted on a daemon that may have CAP_NET_ADMIN / read access
///    to private state.
/// 2. **Production install path** [`PRODUCTION_GUEST_BINARY_PATH`].
/// 3. **`test-env-override`-only — dev sibling**:
///    `current_exe().parent() / "sandbox-guest"` — catches `cargo run
///    -p sandboxd` where both binaries live in `target/{debug,release}/`.
/// 4. **`test-env-override`-only — dev grandparent**:
///    `current_exe().parent().parent() / "sandbox-guest"` — catches
///    `cargo nextest run`, where the test binary lives in
///    `target/debug/deps/<hash>` while `cargo build --bin sandbox-guest`
///    writes to `target/debug/sandbox-guest`.
///
/// **A production daemon resolves the guest from the canonical install
/// path ONLY** (branch 2): the `current_exe`-relative dev fallbacks are
/// compiled out of default-feature builds, mirroring the lima-helper's
/// canonical-only guest resolution. A privileged daemon should not resolve
/// a binary it copies into sessions from a path derived from its own
/// executable location.
///
/// On miss, returns an error naming every path tried so the operator
/// log surfaces exactly which locations the daemon checked.
pub fn guest_agent_path() -> Result<PathBuf, SandboxError> {
    let mut tried: Vec<PathBuf> = Vec::new();

    // 1. test-env-override.
    #[cfg(feature = "test-env-override")]
    if let Ok(p) = std::env::var(GUEST_BINARY_PATH_OVERRIDE_ENV)
        && !p.is_empty()
    {
        let candidate = PathBuf::from(p);
        if candidate.exists() {
            return Ok(candidate);
        }
        tried.push(candidate);
    }

    // 2. Production install path.
    let production = PathBuf::from(PRODUCTION_GUEST_BINARY_PATH);
    if production.exists() {
        return Ok(production);
    }
    tried.push(production);

    // 3-4. Dev fallbacks (sibling and grandparent of current_exe). Compiled in
    // ONLY for `test-env-override` builds — a production daemon must not
    // resolve the guest binary from a `current_exe`-relative path; it uses the
    // canonical install path only (branch 2 above), mirroring the lima-helper.
    // The integration suite builds with this feature (via
    // `sandbox-route-helper/test-env-override` → `sandbox-core/test-env-override`),
    // so `cargo nextest` still finds `target/debug/sandbox-guest` here.
    #[cfg(feature = "test-env-override")]
    {
        let exe = std::env::current_exe().map_err(|e| {
            SandboxError::Internal(format!("failed to determine current executable path: {e}"))
        })?;
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("sandbox-guest");
            if sibling.exists() {
                return Ok(sibling);
            }
            tried.push(sibling);
            if let Some(parent) = dir.parent() {
                let grandparent_sibling = parent.join("sandbox-guest");
                if grandparent_sibling.exists() {
                    return Ok(grandparent_sibling);
                }
                tried.push(grandparent_sibling);
            }
        }
    }

    let tried_list = tried
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(SandboxError::Internal(format!(
        "sandbox-guest binary not found; tried: [{tried_list}]. \
         Install the release tarball (which places it at {PRODUCTION_GUEST_BINARY_PATH}) \
         or run `cargo build --workspace` so a dev-build sibling is available."
    )))
}

/// Prefix applied to all sandbox VM names.
pub const VM_NAME_PREFIX: &str = "sandbox-";

/// Canonical VM name for a session.
pub fn vm_name(session_id: &SessionId) -> String {
    format!("{VM_NAME_PREFIX}{session_id}")
}

/// Try to extract a session ID from a VM name of the form `sandbox-{id}`.
pub fn parse_session_id_from_name(name: &str) -> Option<SessionId> {
    name.strip_prefix(VM_NAME_PREFIX)
        .and_then(|s| SessionId::parse(s).ok())
}

// ---------------------------------------------------------------------------
// Lima JSON parsing
// ---------------------------------------------------------------------------

/// Minimal representation of a single entry in `limactl list --json` output.
///
/// Lima outputs one JSON object per line (NDJSON), not a JSON array.
#[derive(Debug, Deserialize)]
struct LimactlListEntry {
    #[serde(rename = "name", alias = "Name")]
    name: Option<String>,
    #[serde(rename = "status", alias = "Status")]
    status: Option<String>,
    /// Host-side TCP port Lima forwards to the VM's port 22 — Lima's
    /// documented machine-readable surface (`sshLocalPort`). Stable
    /// across Lima minor versions per the cross-user CLI access spec's
    /// proxy endpoint design. Optional because the field is absent when
    /// the VM is `Stopped`; the daemon's proxy handler dials
    /// `127.0.0.1:<port>` only on running VMs.
    #[serde(rename = "sshLocalPort", alias = "SSHLocalPort", default)]
    ssh_local_port: Option<u16>,
}

/// Parse the NDJSON output of `limactl list --json`.
///
/// Each line is a self-contained JSON object.
fn parse_limactl_list_output(output: &str) -> Result<Vec<LimactlListEntry>, SandboxError> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: LimactlListEntry = serde_json::from_str(trimmed)
            .map_err(|e| SandboxError::Lima(format!("failed to parse limactl JSON: {e}")))?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Map a Lima status string to our `VmStatus` enum.
fn parse_status_field(s: &str) -> VmStatus {
    match s {
        "Running" => VmStatus::Running,
        "Stopped" => VmStatus::Stopped,
        other => VmStatus::Unknown(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

/// Produce an error from limactl stderr (surfaced via the helper), always
/// preserving the raw output.
fn parse_limactl_error(subcommand: &str, stderr: &str) -> SandboxError {
    let stderr = stderr.trim();
    SandboxError::Lima(format!("limactl {subcommand} failed: {stderr}"))
}

/// Sanitise a filesystem path for safe interpolation into a YAML
/// double-quoted string.
///
/// YAML double-quoted strings interpret backslash escapes and treat `"`
/// as the string terminator.  A malicious directory name such as
/// `foo"\nnewkey: injected` could therefore inject arbitrary YAML when
/// interpolated with `format!("location: \"{path}\"")`.
///
/// This function validates that every character in the path is in the
/// known-safe set defined by [`crate::session::is_workspace_path_char`].
/// The set lives there rather than here because the same operator-supplied
/// path is also interpolated into the container backend's Docker `--mount`
/// option list; two copies of the list would be two things to keep in step.
///
/// If any other character is found the function panics.
///
/// # What guarantees the precondition, stated precisely
///
/// It holds **because of today's call graph, not because the types make it
/// impossible to violate.** The distinction matters, because a doc comment
/// on this function previously asserted the precondition outright while
/// nothing enforced it, and a wire request carrying `"` reached this panic.
///
/// What is actually true: `WorkspaceMode::parse_flag` rejects these
/// characters, and it is the sole route from the wire format to a
/// `WorkspaceMode` on both the CLI and the daemon. Every `SessionConfig`
/// that reaches this function came through `create_vm`, whose config comes
/// from the session-create path, which parses the wire `workspace` string
/// with that parser. So no operator input can produce a panic here.
///
/// What is *not* true, and is the reason this is a call-graph fact rather
/// than a structural one:
///
/// - `WorkspaceMode` is a `pub` enum whose variant fields are public, so any
///   caller can build `WorkspaceMode::Shared { host_path, .. }` directly and
///   never meet the parser. Serde can construct one too.
/// - [`LimaManager::generate_template`] is `pub`, so this path is reachable
///   from outside this module without a wire request at all.
///
/// A panic here therefore means a `SessionConfig` was built in-process
/// without going through the parser. That is a programming error today, but
/// it is one the type system permits: adding a second caller that assembles
/// a `WorkspaceMode` itself turns operator input into a panicking daemon
/// again. If that caller is ever added, validate at it or make this return
/// `Result` — do not rely on this comment having stayed true.
fn sanitize_yaml_path(path: &str) -> &str {
    for (i, ch) in path.char_indices() {
        if !crate::session::is_workspace_path_char(ch) {
            panic!(
                "host_path contains unsafe character {ch:?} at index {i} — \
                 refusing to interpolate into YAML template: {path:?}",
            );
        }
    }
    path
}

/// Convert MiB to GiB as a human-friendly string.
///
/// If the value divides evenly into GiB, returns a whole number (e.g. "4").
/// Otherwise returns a decimal (e.g. "1.5").
fn mib_to_gib_string(mib: u32) -> String {
    if mib % 1024 == 0 {
        format!("{}", mib / 1024)
    } else {
        format!("{:.1}", mib as f64 / 1024.0)
    }
}

/// Convert MiB to a whole GiB count for Lima CLI flags.
fn mib_to_ceil_gib(mib: u32) -> u32 {
    mib.div_ceil(1024)
}

/// Encode a byte slice as a lowercase hexadecimal string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compute the age of a timestamp in whole days from now.
fn age_in_days(built_at: &chrono::DateTime<chrono::Utc>) -> u64 {
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(built_at);
    duration.num_days().max(0) as u64
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- VM naming ----------------------------------------------------------
    // Note: tests in this module may use `nix::unistd::Uid::current()` to
    // obtain the running process's uid without requiring privilege.

    #[test]
    fn test_vm_name_format() {
        let id = SessionId::parse("550e8400e29b").unwrap();
        let name = vm_name(&id);
        assert_eq!(name, "sandbox-550e8400e29b");
        assert!(name.starts_with(VM_NAME_PREFIX));
    }

    #[test]
    fn test_parse_session_id_from_name() {
        let id = SessionId::parse("550e8400e29b").unwrap();
        let name = vm_name(&id);
        assert_eq!(parse_session_id_from_name(&name), Some(id));
    }

    #[test]
    fn test_parse_session_id_non_sandbox_name() {
        assert_eq!(parse_session_id_from_name("default"), None);
        assert_eq!(parse_session_id_from_name("my-vm"), None);
    }

    #[test]
    fn test_parse_session_id_bad_id() {
        assert_eq!(parse_session_id_from_name("sandbox-not-a-sessionid"), None);
        // Old-style full UUID is no longer accepted.
        assert_eq!(
            parse_session_id_from_name("sandbox-550e8400-e29b-41d4-a716-446655440000"),
            None
        );
    }

    // -- Template generation ------------------------------------------------

    #[test]
    fn test_generate_template() {
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default(); // 2 CPU, 4096 MB, 20 GB

        let template = mgr.generate_template(&id, &config, None, None);

        // Parse as YAML via serde_json (Lima YAML is a superset; we
        // just verify key fields are present via string inspection and
        // basic serde_json::Value parsing of the YAML-as-key-value).

        // Verify essential fields are present
        assert!(
            template.contains("vmType: \"qemu\""),
            "template should specify qemu vmType"
        );
        assert!(template.contains("cpus: 2"), "template should have cpus: 2");
        assert!(
            template.contains("memory: \"4GiB\""),
            "template should have memory: 4GiB"
        );
        assert!(
            template.contains("disk: \"20GiB\""),
            "template should have disk: 20GiB"
        );
        assert!(
            template.contains("mounts: []"),
            "template should disable mounts"
        );
        assert!(
            template.contains("portForwards: []"),
            "template should disable port forwards"
        );
        assert!(
            template.contains("ubuntu-24.04-server-cloudimg-amd64.img"),
            "template should reference Ubuntu 24.04 image"
        );
        assert!(
            template.contains("sandbox-550e8400e29b"),
            "template should set hostname including the full session id"
        );
        assert!(
            template.contains("name: \"sandbox\""),
            "template should configure the sandbox user"
        );
        assert!(
            template.contains("home: \"/home/sandbox\""),
            "template should set the sandbox user's home at /home/sandbox, \
             unified with the container backend"
        );

        // Verify provision scripts
        assert!(
            template.contains("hostnamectl set-hostname"),
            "template should set hostname"
        );
        assert!(
            template.contains("useradd -m -d /home/sandbox -s /bin/bash sandbox"),
            "template should create the sandbox user with home at /home/sandbox"
        );
        assert!(
            template.contains("NOPASSWD"),
            "template should grant passwordless sudo"
        );
        assert!(
            template.contains("apt-get")
                && template.contains("install -y socat git rsync docker.io"),
            "template should install the socat / git / rsync / docker baseline"
        );
        assert!(
            !template.contains("get.docker.com"),
            "template must not install Docker from get.docker.com"
        );
        assert!(
            template.contains("usermod -aG docker sandbox"),
            "template should add the sandbox user to the docker group"
        );
        assert!(
            template.contains("step=net-tune"),
            "template should include the net-tune provision step"
        );
        assert!(
            template.contains("mtu: 1280"),
            "template should clamp eth0 MTU to 1280 (libslirp PMTU workaround)"
        );
    }

    #[test]
    fn test_generate_template_custom_config() {
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );
        let id = SessionId::parse("a1b2c3d4e5f6").unwrap();
        let config = SessionConfig {
            cpus: 8,
            memory_mb: 16384,
            disk_gb: 100,
            workspace_mode: None,
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };

        let template = mgr.generate_template(&id, &config, None, None);

        assert!(
            template.contains("cpus: 8"),
            "template should reflect custom cpus"
        );
        assert!(
            template.contains("memory: \"16GiB\""),
            "template should reflect 16384 MiB as 16GiB"
        );
        assert!(
            template.contains("disk: \"100GiB\""),
            "template should reflect custom disk"
        );
        assert!(
            template.contains("sandbox-a1b2c3d4e5f6"),
            "hostname should include the full 12-hex session id"
        );
        assert!(
            template.contains("step=net-tune"),
            "template should include the net-tune provision step"
        );
        assert!(
            template.contains("mtu: 1280"),
            "template should clamp eth0 MTU to 1280 (libslirp PMTU workaround)"
        );
    }

    #[test]
    fn test_generate_template_fractional_memory() {
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );
        let id = SessionId::generate();
        let config = SessionConfig {
            cpus: 1,
            memory_mb: 1536, // 1.5 GiB
            disk_gb: 10,
            workspace_mode: None,
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };

        let template = mgr.generate_template(&id, &config, None, None);
        assert!(
            template.contains("memory: \"1.5GiB\""),
            "template should handle fractional GiB"
        );
        assert!(
            template.contains("step=net-tune"),
            "template should include the net-tune provision step"
        );
        assert!(
            template.contains("mtu: 1280"),
            "template should clamp eth0 MTU to 1280 (libslirp PMTU workaround)"
        );
    }

    #[test]
    fn test_generate_template_shared_workspace() {
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: Some(WorkspaceMode::Shared {
                host_path: "/home/user/project".into(),
                // Default: `guest_path` equals `host_path` when the
                // operator did not pick one.
                guest_path: "/home/user/project".into(),
                security_model: None,
            }),
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };

        let template = mgr.generate_template(&id, &config, None, None);

        // Should NOT contain the empty mounts placeholder.
        assert!(
            !template.contains("mounts: []"),
            "shared workspace template must not have empty mounts"
        );

        // Should contain 9p mount type.
        assert!(
            template.contains("mountType: \"9p\""),
            "template should specify 9p mount type"
        );

        // Should mount the host path at the operator-resolved guest
        // path. The guest path defaults to the host path when the
        // operator does not supply an explicit value — so this
        // fixture lands the workspace at `/home/user/project` inside
        // the guest too.
        assert!(
            template.contains("location: \"/home/user/project\""),
            "template should reference the host path"
        );
        assert!(
            template.contains("mountPoint: \"/home/user/project\""),
            "template should mount to the resolved guest path \
             (default: equal to host path)"
        );
        assert!(
            template.contains("writable: true"),
            "template should make mount writable"
        );
        // Default branch: `security_model: None` resolves to the Lima
        // backend default of `mapped-xattr` in the rendered template.
        assert!(
            template.contains("securityModel: mapped-xattr"),
            "default (None) security model should render as mapped-xattr"
        );
        assert!(
            template.contains("step=net-tune"),
            "template should include the net-tune provision step"
        );
        assert!(
            template.contains("mtu: 1280"),
            "template should clamp eth0 MTU to 1280 (libslirp PMTU workaround)"
        );
    }

    #[test]
    fn test_generate_template_shared_workspace_with_mapped_xattr() {
        use crate::session::WorkspaceSecurityModel;

        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: Some(WorkspaceMode::Shared {
                host_path: "/home/user/project".into(),
                guest_path: "/home/user/project".into(),
                security_model: Some(WorkspaceSecurityModel::MappedXattr),
            }),
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };

        let template = mgr.generate_template(&id, &config, None, None);

        // SF-17 round-trip: an explicit `Some(MappedXattr)` should
        // serialize to the same `securityModel: mapped-xattr` line as
        // the default (None) branch — preserving operator intent.
        assert!(
            template.contains("securityModel: mapped-xattr"),
            "explicit Some(MappedXattr) should render as mapped-xattr"
        );
    }

    #[test]
    fn test_generate_template_shared_workspace_with_none_mapping() {
        use crate::session::WorkspaceSecurityModel;

        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: Some(WorkspaceMode::Shared {
                host_path: "/home/user/project".into(),
                guest_path: "/home/user/project".into(),
                security_model: Some(WorkspaceSecurityModel::NoneMapping),
            }),
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };

        let template = mgr.generate_template(&id, &config, None, None);

        // SF-17 round-trip: an explicit `Some(NoneMapping)` should
        // serialize to `securityModel: none` (the YAML wire form).
        assert!(
            template.contains("securityModel: none"),
            "explicit Some(NoneMapping) should render as none"
        );
    }

    #[test]
    fn test_generate_template_clone_workspace_no_mount() {
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );
        let id = SessionId::generate();
        let config = SessionConfig {
            cpus: 1,
            memory_mb: 1024,
            disk_gb: 10,
            workspace_mode: Some(WorkspaceMode::Clone {
                repo_url: "https://github.com/example/repo.git".into(),
            }),
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };

        let template = mgr.generate_template(&id, &config, None, None);

        // Clone mode should NOT add mounts — cloning is handled post-boot.
        assert!(
            template.contains("mounts: []"),
            "clone workspace should not produce mounts"
        );
        assert!(
            !template.contains("9p:"),
            "clone workspace should not reference 9p mount config"
        );
        assert!(
            template.contains("step=net-tune"),
            "template should include the net-tune provision step"
        );
        assert!(
            template.contains("mtu: 1280"),
            "template should clamp eth0 MTU to 1280 (libslirp PMTU workaround)"
        );
    }

    /// `local:` is an explicit-sync host snapshot — the daemon
    /// orchestrates an initial rsync push after boot. The Lima
    /// template MUST emit no 9p mount block so the fast-path cache
    /// stays eligible (a 9p block would invalidate the cache key).
    #[test]
    fn test_generate_template_local_workspace_no_mount() {
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );
        let id = SessionId::generate();
        let config = SessionConfig {
            cpus: 1,
            memory_mb: 1024,
            disk_gb: 10,
            workspace_mode: Some(WorkspaceMode::Local {
                host_path: "/tmp/sbx-local-host".into(),
                guest_path: "/srv/work".into(),
            }),
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };

        let template = mgr.generate_template(&id, &config, None, None);

        assert!(
            template.contains("mounts: []"),
            "local workspace should not produce mounts (no 9p, no bind), got:\n{template}"
        );
        assert!(
            !template.contains("9p:"),
            "local workspace must not reference 9p mount config, got:\n{template}"
        );
        // The host path must not appear anywhere in the template —
        // the daemon-side rsync wields it separately; baking it into
        // the YAML would expose host-path-shaped data to the cached
        // VM image.
        assert!(
            !template.contains("/tmp/sbx-local-host"),
            "host_path must not leak into the Lima template for local: mode, got:\n{template}"
        );
        assert!(
            !template.contains("/srv/work"),
            "guest_path must not leak into the Lima template for local: mode, got:\n{template}"
        );
    }

    // -- YAML path sanitization -----------------------------------------------

    #[test]
    fn test_sanitize_yaml_path_normal_paths() {
        // Normal filesystem paths should pass through unchanged.
        assert_eq!(
            sanitize_yaml_path("/home/user/project"),
            "/home/user/project"
        );
        assert_eq!(sanitize_yaml_path("/tmp/my-dir_v2"), "/tmp/my-dir_v2");
        assert_eq!(
            sanitize_yaml_path("/home/user/My Project"),
            "/home/user/My Project"
        );
        assert_eq!(
            sanitize_yaml_path("/home/user/.config/app"),
            "/home/user/.config/app"
        );
    }

    #[test]
    #[should_panic(expected = "unsafe character")]
    fn test_sanitize_yaml_path_rejects_double_quote() {
        sanitize_yaml_path("/home/user/project\"injected");
    }

    #[test]
    #[should_panic(expected = "unsafe character")]
    fn test_sanitize_yaml_path_rejects_newline() {
        sanitize_yaml_path("/home/user/project\nnewkey: injected");
    }

    #[test]
    #[should_panic(expected = "unsafe character")]
    fn test_sanitize_yaml_path_rejects_backslash() {
        sanitize_yaml_path("/home/user/project\\evil");
    }

    #[test]
    #[should_panic(expected = "unsafe character")]
    fn test_sanitize_yaml_path_rejects_backtick() {
        sanitize_yaml_path("/home/user/`command`");
    }

    #[test]
    #[should_panic(expected = "unsafe character")]
    fn test_sanitize_yaml_path_rejects_dollar() {
        sanitize_yaml_path("/home/user/$HOME");
    }

    // -- QEMU hardening / device lockdown ------------------------------------

    #[test]
    fn test_qemu_wrapper_contains_device_lockdown_args() {
        // The wrapper script should contain device lockdown args gated on
        // the SANDBOX_QEMU_HARDENED env var.
        let script = QEMU_WRAPPER_SCRIPT;

        // Always present: PCIe root-port
        assert!(
            script.contains("pcie-root-port"),
            "wrapper should always add PCIe root-port"
        );

        // Hardened-only args
        assert!(
            !script.contains("-nodefaults"),
            "wrapper must NOT use -nodefaults (it strips serial console and 9p filesystem backend)"
        );
        assert!(
            script.contains("-no-user-config"),
            "wrapper should disable user config when hardened"
        );
        assert!(
            script.contains("-display none"),
            "wrapper should disable display when hardened"
        );
        assert!(
            script.contains("-vga none"),
            "wrapper should disable VGA when hardened"
        );
        assert!(
            script.contains("virtio-rng-pci"),
            "wrapper should add virtio-rng for entropy when hardened"
        );

        // Verify these are gated on the env var
        assert!(
            script.contains("SANDBOX_QEMU_HARDENED"),
            "wrapper should check SANDBOX_QEMU_HARDENED env var"
        );
    }

    #[test]
    fn test_qemu_wrapper_hardened_conditional() {
        // Verify the device lockdown args are inside the hardened conditional,
        // not unconditionally applied. The script should have -no-user-config
        // only within the if-block checking SANDBOX_QEMU_HARDENED.
        let script = QEMU_WRAPPER_SCRIPT;

        // Find the position of the hardened check and the -no-user-config arg.
        let hardened_check_pos = script.find("SANDBOX_QEMU_HARDENED").unwrap();
        let no_user_config_pos = script.find("-no-user-config").unwrap();

        assert!(
            no_user_config_pos > hardened_check_pos,
            "-no-user-config should come after the SANDBOX_QEMU_HARDENED check"
        );
    }

    #[test]
    fn test_generate_template_hardened_video_audio() {
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );
        let id = SessionId::generate();
        let config = SessionConfig {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };

        let template = mgr.generate_template(&id, &config, None, None);

        assert!(
            template.contains("display: \"none\""),
            "hardened template should disable video display"
        );
        assert!(
            template.contains("device: \"none\""),
            "hardened template should disable audio device"
        );
        assert!(
            template.contains("step=net-tune"),
            "template should include the net-tune provision step"
        );
        assert!(
            template.contains("mtu: 1280"),
            "template should clamp eth0 MTU to 1280 (libslirp PMTU workaround)"
        );
    }

    #[test]
    fn test_generate_template_not_hardened_no_video_audio() {
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );
        let id = SessionId::generate();
        let config = SessionConfig {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: false,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };

        let template = mgr.generate_template(&id, &config, None, None);

        assert!(
            !template.contains("display: \"none\""),
            "non-hardened template should not disable video display"
        );
        assert!(
            !template.contains("device: \"none\""),
            "non-hardened template should not disable audio device"
        );
        assert!(
            template.contains("step=net-tune"),
            "template should include the net-tune provision step"
        );
        assert!(
            template.contains("mtu: 1280"),
            "template should clamp eth0 MTU to 1280 (libslirp PMTU workaround)"
        );
    }

    /// `generate_template` is the source of truth for the per-session
    /// Lima YAML. When the daemon stamps `operator_identity = None`
    /// (pre-V008 records, fixture-test rows that did not capture
    /// peercred), the resulting YAML must NOT carry the operator-uid
    /// cloud-init step — the legacy "in-VM sandbox stays at uid 1000"
    /// path applies. This pins the omit-on-None invariant.
    #[test]
    fn generate_template_omits_operator_uid_step_when_identity_is_none() {
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default();
        let template = mgr.generate_template(&id, &config, None, None);
        assert!(
            !template.contains("step=operator-uid"),
            "operator_identity=None must NOT emit the operator-uid \
             cloud-init step (got template excerpt: {})",
            &template[..template.len().min(800)]
        );
    }

    /// When the operator pair happens to coincide with the base
    /// image's baked uid/gid (1000:1000), the cloud-init step would
    /// be a no-op. Elide it entirely so cloud-init runs stay quick
    /// and the YAML diff is empty for the common-case dev install.
    #[test]
    fn generate_template_omits_operator_uid_step_when_identity_is_1000_1000() {
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default();
        let template = mgr.generate_template(&id, &config, Some((1000, 1000)), None);
        assert!(
            !template.contains("step=operator-uid"),
            "operator_identity=Some((1000, 1000)) coincides with the \
             baked uid/gid; the cloud-init step must be elided"
        );
    }

    /// `generate_template` interpolates the operator pair into a
    /// system-mode cloud-init step that re-aligns the in-VM `sandbox`
    /// user's uid/gid. The step must:
    ///
    ///   - be `mode: system` (root-equivalent inside the VM)
    ///   - call `groupmod -g <gid>` BEFORE `usermod -u <uid>` so the
    ///     primary group still resolves after the renumbering
    ///   - chown `/home/sandbox` recursively at the operator's uid:gid
    ///
    /// All three are structural invariants of the cross-user
    /// supervisor-fork pattern and regressing any of them silently
    /// would break 9p mapped-xattr workspaces. Pin all three here.
    #[test]
    fn generate_template_emits_operator_uid_step_with_correct_shape() {
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default();
        let template = mgr.generate_template(&id, &config, Some((5001, 5001)), None);
        // Step header.
        assert!(
            template.contains("step=operator-uid start="),
            "template must emit step=operator-uid start banner; got: {template}"
        );
        // mode: system precedes the step (sibling of the step=user
        // block). We don't pin the exact YAML formatting, just that
        // the script body lives under a `mode: system` clause.
        assert!(
            template.contains("step=operator-uid"),
            "template must emit the operator-uid step"
        );
        // groupmod-before-usermod ordering.
        let groupmod_idx = template
            .find("groupmod -g 5001 sandbox")
            .expect("template must call groupmod -g <gid> sandbox");
        let usermod_idx = template
            .find("usermod -u 5001 -g 5001 sandbox")
            .expect("template must call usermod -u <uid> -g <gid> sandbox");
        assert!(
            groupmod_idx < usermod_idx,
            "groupmod must precede usermod so the primary group is in \
             place before the usermod call validates it; groupmod={groupmod_idx} \
             usermod={usermod_idx}"
        );
        // Recursive chown on /home/sandbox (both backends share this home path).
        assert!(
            template.contains("chown -R 5001:5001 /home/sandbox"),
            "template must chown /home/sandbox recursively to the \
             operator pair; got: {template}"
        );
    }
    #[test]
    fn test_ensure_qemu_wrapper_creates_file() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        // base_dir must be a subdirectory of the TempDir (mirroring the
        // production layout where base_dir == LIMA_HOME and its parent is
        // the operator state root).  The wrapper lands at base_dir/../libexec/
        // which resolves to dir.path()/libexec/ — still inside the TempDir.
        let lima_home = dir.path().join("lima");
        std::fs::create_dir_all(&lima_home).expect("create lima_home");
        let mgr = LimaManager::with_helper_path(
            lima_home,
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );

        let wrapper = mgr.ensure_qemu_wrapper().unwrap();

        assert!(wrapper.exists(), "wrapper script should exist");

        let content = std::fs::read_to_string(&wrapper).unwrap();
        assert!(
            content.contains("pcie-root-port"),
            "wrapper should contain PCIe root-port"
        );
        assert!(
            content.contains("SANDBOX_QEMU_HARDENED"),
            "wrapper should reference SANDBOX_QEMU_HARDENED"
        );
        assert!(
            content.contains("-no-user-config"),
            "wrapper should contain device lockdown args"
        );
    }

    // -- Lima JSON parsing --------------------------------------------------

    #[test]
    fn test_parse_vm_status() {
        assert_eq!(parse_status_field("Running"), VmStatus::Running);
        assert_eq!(parse_status_field("Stopped"), VmStatus::Stopped);
        assert_eq!(
            parse_status_field("Broken"),
            VmStatus::Unknown("Broken".to_string())
        );
        assert_eq!(parse_status_field(""), VmStatus::Unknown(String::new()));
    }

    #[test]
    fn test_parse_vm_list() {
        // Simulated NDJSON output from `limactl list --json`
        let output = r#"{"name":"sandbox-550e8400e29b","status":"Running","arch":"x86_64","cpus":2,"memory":4294967296,"disk":21474836480,"dir":"/home/user/.lima/sandbox-550e8400e29b"}
{"name":"sandbox-a1b2c3d4e5f6","status":"Stopped","arch":"x86_64","cpus":4,"memory":8589934592,"disk":107374182400,"dir":"/home/user/.lima/sandbox-a1b2c3d4e5f6"}
{"name":"default","status":"Running","arch":"x86_64","cpus":4,"memory":4294967296,"disk":107374182400,"dir":"/home/user/.lima/default"}
"#;

        let entries = parse_limactl_list_output(output).unwrap();
        assert_eq!(entries.len(), 3);

        // Simulate the filtering that list_vms does
        let vms: Vec<VmInfo> = entries
            .into_iter()
            .filter_map(|e| {
                let name = e.name?;
                if !name.starts_with(VM_NAME_PREFIX) {
                    return None;
                }
                let status = parse_status_field(e.status.as_deref().unwrap_or(""));
                let session_id = parse_session_id_from_name(&name);
                Some(VmInfo {
                    name,
                    status,
                    session_id,
                })
            })
            .collect();

        assert_eq!(vms.len(), 2, "should filter out non-sandbox VMs");

        assert_eq!(vms[0].name, "sandbox-550e8400e29b");
        assert_eq!(vms[0].status, VmStatus::Running);
        assert_eq!(
            vms[0].session_id,
            Some(SessionId::parse("550e8400e29b").unwrap())
        );

        assert_eq!(vms[1].name, "sandbox-a1b2c3d4e5f6");
        assert_eq!(vms[1].status, VmStatus::Stopped);
        assert_eq!(
            vms[1].session_id,
            Some(SessionId::parse("a1b2c3d4e5f6").unwrap())
        );
    }

    #[test]
    fn test_parse_empty_list() {
        let entries = parse_limactl_list_output("").unwrap();
        assert!(entries.is_empty());

        let entries = parse_limactl_list_output("  \n  \n").unwrap();
        assert!(entries.is_empty());
    }

    /// `sshLocalPort` is the host-side TCP port Lima forwards to the
    /// in-VM sshd's port 22. The cross-user CLI access proxy handler
    /// dials `127.0.0.1:<sshLocalPort>` to byte-forward into the
    /// session's sshd, so the parser must capture the field reliably.
    /// Lima omits the field on `Stopped` VMs — the parser must accept
    /// that case as `None` rather than failing.
    #[test]
    fn test_parse_ssh_local_port() {
        let output = r#"{"name":"sandbox-aaaabbbbccc1","status":"Running","sshLocalPort":60022}
{"name":"sandbox-aaaabbbbccc2","status":"Stopped"}
"#;
        let entries = parse_limactl_list_output(output).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ssh_local_port, Some(60022));
        assert_eq!(entries[1].ssh_local_port, None);
    }

    #[test]
    fn test_parse_limactl_error_preserves_stderr() {
        let err = parse_limactl_error(
            "start",
            "FATA[0000] Instance \"sandbox-abc\" does not exist",
        );
        match err {
            SandboxError::Lima(msg) => {
                assert!(msg.contains("limactl start failed:"));
                assert!(msg.contains("does not exist"));
            }
            _ => panic!("expected Lima error variant"),
        }
    }

    #[test]
    fn test_mib_to_gib_string() {
        assert_eq!(mib_to_gib_string(1024), "1");
        assert_eq!(mib_to_gib_string(4096), "4");
        assert_eq!(mib_to_gib_string(16384), "16");
        assert_eq!(mib_to_gib_string(1536), "1.5");
        assert_eq!(mib_to_gib_string(2560), "2.5");
    }

    #[test]
    fn test_mib_to_ceil_gib() {
        assert_eq!(mib_to_ceil_gib(1024), 1);
        assert_eq!(mib_to_ceil_gib(4096), 4);
        assert_eq!(mib_to_ceil_gib(10000), 10);
        assert_eq!(mib_to_ceil_gib(1536), 2);
    }

    // -- Guest agent service unit tests --------------------------------------

    #[test]
    fn test_guest_agent_service_unit() {
        assert!(
            GUEST_AGENT_SERVICE_UNIT.contains("[Unit]"),
            "service unit should have [Unit] section"
        );
        assert!(
            GUEST_AGENT_SERVICE_UNIT.contains("ExecStart=/usr/local/bin/sandbox-guest"),
            "service unit should run sandbox-guest"
        );
        assert!(
            GUEST_AGENT_SERVICE_UNIT.contains("Restart=always"),
            "service should restart on failure"
        );
        assert!(
            GUEST_AGENT_SERVICE_UNIT.contains("[Install]"),
            "service unit should have [Install] section"
        );
        // Pin that the unit runs as the `sandbox` user (not the legacy
        // `agent` username). The daemon-emitted SSH config block carries
        // `User sandbox`, and the in-VM sshd must accept that username,
        // so every in-VM process the daemon manages — including this
        // guest-agent service — runs under the same identity.
        assert!(
            GUEST_AGENT_SERVICE_UNIT.contains("User=sandbox"),
            "service unit should run as the sandbox user"
        );
        assert!(
            GUEST_AGENT_SERVICE_UNIT.contains("Group=sandbox"),
            "service unit should run as the sandbox group"
        );
    }

    // test_install_guest_agent_missing_binary was removed; the install now runs in the helper.
    // The guest-agent binary path is now a compile-time constant inside
    // sandbox-lima-helper (SANDBOX_GUEST_HOST_PATH), not resolved by the daemon.
    // Integration coverage of the install-guest-agent path lives in the
    // helper's own integration tests (against the setcap-installed binary).

    // -- QEMU wrapper script tests ------------------------------------------

    #[test]
    fn test_qemu_wrapper_includes_pcie_root_port() {
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("pcie-root-port,id=pcie-hotplug-port"),
            "wrapper must inject PCIe root-port for NIC hot-add"
        );
    }

    #[test]
    fn test_qemu_wrapper_includes_bridge_networking() {
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("SANDBOX_DOCKER_BRIDGE"),
            "wrapper must check SANDBOX_DOCKER_BRIDGE env var"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("qemu-bridge-helper"),
            "wrapper must reference qemu-bridge-helper"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("-netdev bridge,id=net_sandbox"),
            "wrapper must add bridge netdev when SANDBOX_DOCKER_BRIDGE is set"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("SANDBOX_VM_MAC"),
            "wrapper must use SANDBOX_VM_MAC for the NIC MAC address"
        );
    }

    #[test]
    fn test_qemu_wrapper_restricts_slirp_netdev() {
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("user|user,*)"),
            "wrapper must inspect QEMU -netdev user backends"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("netdev=\"$restricted_netdev,restrict=on\""),
            "wrapper must add restrict=on to Lima's slirp management NIC"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("SANDBOX_UNRESTRICTED_SLIRP_FOR_PROVISIONING"),
            "wrapper must support a first-boot provisioning escape hatch"
        );
    }

    #[test]
    fn test_qemu_wrapper_no_seccomp_sandbox() {
        // QEMU seccomp sandbox requires PR_SET_NO_NEW_PRIVS which strips
        // the setuid bit from qemu-bridge-helper, breaking bridge networking.
        assert!(
            !QEMU_WRAPPER_SCRIPT.contains("-sandbox on"),
            "wrapper must NOT use -sandbox on (incompatible with qemu-bridge-helper setuid)"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("PR_SET_NO_NEW_PRIVS"),
            "wrapper should document why seccomp is not used"
        );
    }

    #[test]
    fn test_qemu_wrapper_includes_cgroup_limits() {
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("systemd-run --user --scope --slice=sandbox.slice"),
            "wrapper must use systemd-run for cgroup limits"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("MemoryMax="),
            "wrapper must set MemoryMax cgroup limit"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("CPUQuota="),
            "wrapper must set CPUQuota cgroup limit"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("TasksMax=256"),
            "wrapper must set TasksMax cgroup limit"
        );
    }

    // ---------------------------------------------------------------
    // Regression: `helper=` and rootless-Docker removal.
    //
    // QEMU's `-netdev bridge,...` accepts an optional `helper=<path>`;
    // when omitted, QEMU resolves the helper via its compile-time
    // `libexecdir` (different on Ubuntu/Debian vs RHEL/Fedora).
    // Sandboxd no longer pins the helper path nor carries a
    // rootless-Docker code path; the tests below pin the post-removal
    // shape so a future contributor cannot silently reintroduce the
    // hardcoded path or the rootless wrapper.
    //
    // Design reference: daemon-productionization (QEMU wrapper + image pinning).
    // ---------------------------------------------------------------

    /// The `-netdev bridge,…` line emits no `helper=` parameter. The
    /// surrounding substring (`br=$SANDBOX_DOCKER_BRIDGE \\\n`) is
    /// load-bearing: it terminates the netdev token without a comma,
    /// proving no `,helper=` follows.
    #[test]
    fn qemu_wrapper_emits_netdev_without_helper_param() {
        assert!(
            QEMU_WRAPPER_SCRIPT
                .contains("-netdev bridge,id=net_sandbox,br=$SANDBOX_DOCKER_BRIDGE \\\n"),
            "wrapper must emit `-netdev bridge,id=net_sandbox,br=$SANDBOX_DOCKER_BRIDGE \\` \
             with NO `,helper=` segment; full script:\n{QEMU_WRAPPER_SCRIPT}"
        );
        assert!(
            !QEMU_WRAPPER_SCRIPT.contains(",helper="),
            "wrapper must NOT carry a `,helper=` segment anywhere (QEMU resolves the helper via \
             its compile-time libexecdir); full script:\n{QEMU_WRAPPER_SCRIPT}"
        );
    }

    /// The `BRIDGE_HELPER` shell variable is gone — both the
    /// assignment site (`BRIDGE_HELPER=…`) and any later
    /// dereference. Anchored on the assignment-form token so a stray
    /// comment containing the word "helper" does not flag a false
    /// positive.
    #[test]
    fn qemu_wrapper_has_no_bridge_helper_variable() {
        assert!(
            !QEMU_WRAPPER_SCRIPT.contains("BRIDGE_HELPER="),
            "wrapper must NOT carry a `BRIDGE_HELPER=` shell variable; full script:\n\
             {QEMU_WRAPPER_SCRIPT}"
        );
    }

    /// None of the rootless-Docker artefacts that the previous
    /// rootless branch introduced may survive in the wrapper. Each
    /// token is named explicitly so the failure pinpoints which
    /// artefact slipped back in.
    #[test]
    fn qemu_wrapper_has_no_rootlesskit_artefacts() {
        for token in [
            "dockerd-rootless",
            "rootlesskit",
            "nsenter",
            "RLKIT_PID",
            "NSHELPER",
            "bridge-helper-ns",
            "SANDBOX_REAL_BRIDGE_HELPER",
        ] {
            assert!(
                !QEMU_WRAPPER_SCRIPT.contains(token),
                "wrapper must NOT carry rootless-Docker artefact `{token}`; \
                 full script:\n{QEMU_WRAPPER_SCRIPT}"
            );
        }
    }

    /// The literal string `qemu-bridge-helper` is still present —
    /// the surviving comments in the bridge-networking block and the
    /// `PR_SET_NO_NEW_PRIVS` block reference it by name. Pinning this
    /// keeps the existing `test_qemu_wrapper_includes_bridge_networking`
    /// assertion green and forecloses an over-zealous future edit
    /// that strips even the descriptive comment.
    #[test]
    fn qemu_wrapper_still_references_qemu_bridge_helper_in_comments() {
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("qemu-bridge-helper"),
            "wrapper must keep the descriptive `qemu-bridge-helper` references \
             in its comments so operators can grep for the integration; \
             full script:\n{QEMU_WRAPPER_SCRIPT}"
        );
    }

    #[test]
    fn test_qemu_wrapper_cgroup_gated_on_env_vars() {
        // Cgroup limits should only apply when both env vars are present.
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("SANDBOX_QEMU_MEMORY_MB"),
            "wrapper must check SANDBOX_QEMU_MEMORY_MB env var"
        );
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("SANDBOX_QEMU_CPUS"),
            "wrapper must check SANDBOX_QEMU_CPUS env var"
        );
    }

    #[test]
    fn test_qemu_wrapper_cgroup_fallback_without_systemd_run() {
        // When systemd-run is not available, wrapper should fall back to
        // running QEMU directly (without cgroup limits).
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("command -v systemd-run"),
            "wrapper must check for systemd-run availability"
        );
        // The else branch should exec QEMU directly.
        let lines: Vec<&str> = QEMU_WRAPPER_SCRIPT.lines().collect();
        let has_else_exec = lines.iter().any(|line| {
            let trimmed = line.trim();
            trimmed == r#"exec "$REAL_QEMU" $EXTRA_ARGS "$@""#
        });
        assert!(
            has_else_exec,
            "wrapper must have a fallback exec without systemd-run"
        );
    }

    /// Regression: the systemd-run guard must also probe the user-bus.
    ///
    /// When the daemon runs as a system user (`User=sandbox` in the
    /// production systemd unit) without `loginctl enable-linger`, the
    /// `systemd-run` binary is present on PATH but `--user` cannot reach
    /// any user-bus and aborts with exit 1. The wrapper would `exec`
    /// straight into that failure and Lima would surface a generic QEMU
    /// `"exit status 1"` with no QMP socket and no actionable stderr.
    /// Asserting the `systemctl --user show-environment` probe is part of
    /// the guard pins the resolution so a future contributor cannot
    /// silently re-introduce the regression.
    #[test]
    fn test_qemu_wrapper_cgroup_gated_on_user_bus_reachability() {
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("systemctl --user show-environment >/dev/null 2>&1"),
            "wrapper must probe `systemctl --user show-environment` before \
             invoking `systemd-run --user --scope` — otherwise a daemon \
             running as a system user without an active user-bus exits \
             with status 1 the moment the wrapper exec's systemd-run; \
             full script:\n{QEMU_WRAPPER_SCRIPT}"
        );
    }

    #[test]
    fn test_qemu_wrapper_probe_passthrough() {
        // Lima runs probe commands (-machine help, -cpu help, --version, etc.)
        // through the wrapper.  The wrapper must detect these and exec the
        // real QEMU without adding extra flags or cgroup wrapping.

        // Must detect "help" as a probe trigger (covers -machine help,
        // -accel help, -cpu help, -netdev help).
        assert!(
            QEMU_WRAPPER_SCRIPT.contains("help|--version"),
            "wrapper must detect help and --version as probe triggers"
        );
        // When a probe is detected, wrapper must exec without extra args.
        let lines: Vec<&str> = QEMU_WRAPPER_SCRIPT.lines().collect();
        let has_probe_exec = lines
            .iter()
            .any(|line| line.trim().starts_with("exec \"$REAL_QEMU\" \"$@\""));
        assert!(
            has_probe_exec,
            "wrapper must pass probe invocations through without extra args"
        );
    }

    #[test]
    fn test_qemu_wrapper_written_to_filesystem() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        // base_dir == lima_home (subdirectory), so wrapper lands at
        // dir.path()/libexec/ — still inside the TempDir.
        let lima_home = dir.path().join("lima");
        std::fs::create_dir_all(&lima_home).expect("create lima_home");
        let mgr = LimaManager::with_helper_path(
            lima_home,
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );

        let wrapper_path = mgr
            .ensure_qemu_wrapper()
            .expect("ensure_qemu_wrapper should succeed");

        // Verify the file exists and is executable.
        assert!(wrapper_path.exists(), "wrapper script must exist");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&wrapper_path)
                .expect("metadata")
                .permissions();
            assert_eq!(
                perms.mode() & 0o755,
                0o755,
                "wrapper script must be executable"
            );
        }

        // Verify content matches the constant.
        let content = std::fs::read_to_string(&wrapper_path).expect("read wrapper");
        assert_eq!(
            content, QEMU_WRAPPER_SCRIPT,
            "written content must match constant"
        );
    }

    // -- Golden base image --------------------------------------------------

    #[test]
    fn test_generate_base_template_valid_yaml_fields() {
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );

        let template = mgr.generate_base_template();

        // Resource configuration: fixed values for base image build.
        assert!(
            template.contains("cpus: 4"),
            "base template should have 4 CPUs"
        );
        assert!(
            template.contains("memory: \"4GiB\""),
            "base template should have 4GiB memory"
        );
        assert!(
            template.contains("disk: \"10GiB\""),
            "base template should have 10GiB disk"
        );

        // No mounts (no workspace).
        assert!(
            template.contains("mounts: []"),
            "base template should have empty mounts"
        );

        // Same Ubuntu cloud images as per-session template.
        assert!(
            template.contains("ubuntu-24.04-server-cloudimg-amd64.img"),
            "base template should reference Ubuntu 24.04 amd64 image"
        );
        assert!(
            template.contains("ubuntu-24.04-server-cloudimg-arm64.img"),
            "base template should reference Ubuntu 24.04 arm64 image"
        );

        // Uses the base VM name as hostname.
        assert!(
            template.contains(&format!("hostnamectl set-hostname {DEFAULT_BASE_VM_NAME}")),
            "base template should set hostname to base VM name"
        );

        // Cloud-init provisioning scripts.
        assert!(
            template.contains("name: \"sandbox\""),
            "base template should configure the sandbox user"
        );
        assert!(
            template.contains("home: \"/home/sandbox\""),
            "base template should set the sandbox user's home at /home/sandbox"
        );
        assert!(
            template.contains("useradd -m -d /home/sandbox -s /bin/bash sandbox"),
            "base template should create the sandbox user with home at /home/sandbox"
        );
        assert!(
            template.contains("NOPASSWD"),
            "base template should grant passwordless sudo"
        );
        assert!(
            template.contains("apt-get")
                && template.contains("install -y socat git rsync docker.io"),
            "base template should install the socat / git / rsync / docker baseline"
        );
        assert!(
            !template.contains("get.docker.com"),
            "base template must not install Docker from get.docker.com"
        );
        assert!(
            template.contains("usermod -aG docker sandbox"),
            "base template should add the sandbox user to the docker group"
        );

        // Hardened by default (video/audio disabled).
        assert!(
            template.contains("display: \"none\""),
            "base template should disable video display"
        );
        assert!(
            template.contains("device: \"none\""),
            "base template should disable audio device"
        );

        // Port forwards should be empty.
        assert!(
            template.contains("portForwards: []"),
            "base template should have empty port forwards"
        );

        // vmType specification.
        assert!(
            template.contains("vmType: \"qemu\""),
            "base template should specify qemu vmType"
        );

        // libslirp PMTU workaround: eth0 MTU clamped to 1280.
        assert!(
            template.contains("step=net-tune"),
            "base template should include the net-tune provision step"
        );
        assert!(
            template.contains("mtu: 1280"),
            "base template should clamp eth0 MTU to 1280 (libslirp PMTU workaround)"
        );
    }

    #[test]
    fn test_generate_base_template_deterministic() {
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
        );

        let t1 = mgr.generate_base_template();
        let t2 = mgr.generate_base_template();
        assert_eq!(t1, t2, "base template should be deterministic");
    }

    #[test]
    fn test_compute_base_image_hash_deterministic() {
        // Create a temporary directory with a fake guest agent binary at
        // the path that `guest_agent_path()` will resolve.
        //
        // `guest_agent_path()` uses `std::env::current_exe()` which in
        // test context points to the test binary.  We can't control that
        // path, so we test the underlying hash logic directly with
        // `ring::digest`.
        let template = "some template content";
        let agent_bytes = b"fake agent binary";

        let mut ctx1 = digest::Context::new(&digest::SHA256);
        ctx1.update(template.as_bytes());
        ctx1.update(agent_bytes);
        let hash1 = hex_encode(ctx1.finish().as_ref());

        let mut ctx2 = digest::Context::new(&digest::SHA256);
        ctx2.update(template.as_bytes());
        ctx2.update(agent_bytes);
        let hash2 = hex_encode(ctx2.finish().as_ref());

        assert_eq!(hash1, hash2, "hash should be deterministic");
        assert_eq!(hash1.len(), 64, "SHA256 hex digest should be 64 chars");
    }

    #[test]
    fn test_compute_base_image_hash_changes_with_input() {
        let agent_bytes = b"fake agent binary";

        let mut ctx1 = digest::Context::new(&digest::SHA256);
        ctx1.update(b"template version 1");
        ctx1.update(agent_bytes);
        let hash1 = hex_encode(ctx1.finish().as_ref());

        let mut ctx2 = digest::Context::new(&digest::SHA256);
        ctx2.update(b"template version 2");
        ctx2.update(agent_bytes);
        let hash2 = hex_encode(ctx2.finish().as_ref());

        assert_ne!(hash1, hash2, "hash should change when inputs change");
    }

    #[test]
    fn test_check_base_image_missing_when_no_vms() {
        // check_base_image relies on list_vms_raw() which shells out to
        // limactl.  We test the logic by directly verifying the metadata
        // parsing and status evaluation.  When the VM list is empty, the
        // result should be Missing.
        let entries: Vec<LimactlListEntry> = vec![];
        let vm_exists = entries
            .iter()
            .any(|e| e.name.as_deref() == Some(DEFAULT_BASE_VM_NAME));
        assert!(!vm_exists);
        // This corresponds to BaseImageStatus::Missing
    }

    #[test]
    fn test_check_base_image_stale_when_meta_missing() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let meta_path = dir.path().join("base-image-meta.json");

        // Metadata file does not exist.
        assert!(!meta_path.exists());

        // Simulate: VM exists but no metadata -> Stale(hash_mismatch=true)
        let result = std::fs::read_to_string(&meta_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_base_image_stale_when_meta_corrupt() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let meta_path = dir.path().join("base-image-meta.json");
        std::fs::write(&meta_path, "not valid json").unwrap();

        let content = std::fs::read_to_string(&meta_path).unwrap();
        let parse_result = serde_json::from_str::<BaseImageMeta>(&content);
        assert!(
            parse_result.is_err(),
            "corrupt metadata should fail to parse"
        );
    }

    #[test]
    fn test_check_base_image_stale_when_old() {
        let old_meta = BaseImageMeta {
            built_at: chrono::Utc::now() - chrono::Duration::days(15),
            content_hash: "abc123".to_string(),
        };

        let age = age_in_days(&old_meta.built_at);
        assert!(
            age > BASE_IMAGE_MAX_AGE_DAYS,
            "15-day-old image should exceed max age of {BASE_IMAGE_MAX_AGE_DAYS}"
        );
    }

    #[test]
    fn test_check_base_image_fresh_when_recent_and_matching() {
        let recent_meta = BaseImageMeta {
            built_at: chrono::Utc::now() - chrono::Duration::days(2),
            content_hash: "matching_hash".to_string(),
        };

        let age = age_in_days(&recent_meta.built_at);
        assert!(
            age <= BASE_IMAGE_MAX_AGE_DAYS,
            "2-day-old image should be within max age"
        );
        // If hash matches, this would be Fresh.
    }

    #[test]
    fn test_base_image_meta_serialization_roundtrip() {
        let meta = BaseImageMeta {
            built_at: chrono::Utc::now(),
            content_hash: "deadbeef01234567".to_string(),
        };

        let json = serde_json::to_string_pretty(&meta).unwrap();
        let deserialized: BaseImageMeta = serde_json::from_str(&json).unwrap();

        assert_eq!(meta.content_hash, deserialized.content_hash);
        assert_eq!(meta.built_at, deserialized.built_at);
    }

    #[test]
    fn test_base_image_status_equality() {
        assert_eq!(BaseImageStatus::Missing, BaseImageStatus::Missing);
        assert_eq!(BaseImageStatus::Fresh, BaseImageStatus::Fresh);
        assert_eq!(
            BaseImageStatus::Stale {
                age_days: 5,
                hash_mismatch: true
            },
            BaseImageStatus::Stale {
                age_days: 5,
                hash_mismatch: true
            }
        );
        assert_ne!(BaseImageStatus::Missing, BaseImageStatus::Fresh);
        assert_ne!(
            BaseImageStatus::Stale {
                age_days: 5,
                hash_mismatch: true
            },
            BaseImageStatus::Stale {
                age_days: 5,
                hash_mismatch: false
            }
        );
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(
            hex_encode(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
            "0123456789abcdef"
        );
    }

    #[test]
    fn test_age_in_days() {
        let now = chrono::Utc::now();
        assert_eq!(age_in_days(&now), 0);

        let yesterday = now - chrono::Duration::days(1);
        assert_eq!(age_in_days(&yesterday), 1);

        let ten_days_ago = now - chrono::Duration::days(10);
        assert_eq!(age_in_days(&ten_days_ago), 10);

        // Future timestamps should clamp to 0.
        let future = now + chrono::Duration::days(5);
        assert_eq!(age_in_days(&future), 0);
    }

    #[test]
    fn test_default_base_vm_name_constant() {
        assert_eq!(DEFAULT_BASE_VM_NAME, "sandbox-base");
    }

    #[test]
    fn test_base_vm_name_threaded_through_template() {
        // A LimaManager built with a non-default base name must produce a
        // base template that references that name in every place where the
        // hard-coded `sandbox-base` used to appear (hostname provisioning).
        let mgr = LimaManager::with_helper_path(
            PathBuf::from("/tmp/test"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            "sandbox-test-base".to_string(),
        );

        assert_eq!(mgr.base_vm_name(), "sandbox-test-base");

        let template = mgr.generate_base_template();
        assert!(
            template.contains("hostnamectl set-hostname sandbox-test-base"),
            "base template should set hostname to the configured base VM name"
        );
        assert!(
            template.contains("127.0.1.1 sandbox-test-base"),
            "base template should map 127.0.1.1 to the configured base VM name"
        );
        assert!(
            !template.contains("sandbox-base"),
            "base template must not embed the default base VM name when an override is set"
        );
        assert!(
            template.contains("step=net-tune"),
            "base template should include the net-tune provision step"
        );
        assert!(
            template.contains("mtu: 1280"),
            "base template should clamp eth0 MTU to 1280 (libslirp PMTU workaround)"
        );
    }

    #[test]
    fn test_base_image_max_age_constant() {
        assert_eq!(BASE_IMAGE_MAX_AGE_DAYS, 10);
    }

    #[test]
    fn test_guest_agent_path_returns_a_sandbox_guest_path_when_resolved() {
        // `cargo nextest run --workspace` does not build `sandbox-guest`
        // (no crate transitively depends on it), so this test cannot
        // assume any of the four resolution branches is satisfied in a
        // hermetic test run. Instead, exercise the function and accept
        // either outcome:
        //   * `Ok(path)` — at least one branch (production install,
        //     dev sibling, or dev grandparent) resolved. The
        //     `file_name()` must be `sandbox-guest`.
        //   * `Err(_)` — every branch missed. The error message must
        //     name `sandbox-guest` so the operator log is greppable.
        match guest_agent_path() {
            Ok(path) => {
                assert_eq!(
                    path.file_name().unwrap(),
                    std::ffi::OsStr::new("sandbox-guest"),
                    "guest_agent_path should return a path ending in sandbox-guest"
                );
            }
            Err(SandboxError::Internal(msg)) => {
                assert!(
                    msg.contains("sandbox-guest"),
                    "miss-error should name the binary it was looking for: {msg}"
                );
                assert!(
                    msg.contains(PRODUCTION_GUEST_BINARY_PATH),
                    "miss-error should name the production install path so \
                     operators know what to install: {msg}"
                );
            }
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[cfg(feature = "test-env-override")]
    #[test]
    fn test_guest_agent_path_honors_env_override_under_test_feature() {
        // Synthesize a sandbox-guest stand-in and pin the override at
        // it; the resolver must return that path before checking the
        // production install location.
        let dir = tempfile::TempDir::new().expect("create tempdir");
        let pinned = dir.path().join("sandbox-guest");
        std::fs::write(&pinned, b"#!/bin/echo synthetic\n").expect("write stub");

        let prev = std::env::var(GUEST_BINARY_PATH_OVERRIDE_ENV).ok();
        // SAFETY: setting/unsetting env vars is unsafe in Rust 2024
        // because of cross-thread races; we accept the risk in a unit
        // test that doesn't spawn other env-reading threads.
        unsafe { std::env::set_var(GUEST_BINARY_PATH_OVERRIDE_ENV, &pinned) };
        let result = guest_agent_path();
        // SAFETY: see rationale above.
        unsafe {
            match prev {
                Some(v) => std::env::set_var(GUEST_BINARY_PATH_OVERRIDE_ENV, v),
                None => std::env::remove_var(GUEST_BINARY_PATH_OVERRIDE_ENV),
            }
        }

        let resolved = result.expect("override should resolve");
        assert_eq!(resolved, pinned);
    }

    // -----------------------------------------------------------------------
    // operator_lima_home: path construction
    // -----------------------------------------------------------------------

    #[test]
    fn operator_lima_home_path_is_correct() {
        // Use the pure inner fn with fixed uids so the assertion is
        // independent of the live process uid.
        let path = operator_lima_home_inner("/var/lib/sandboxd", 999, 1000);
        assert_eq!(
            path,
            PathBuf::from("/var/lib/sandboxd/999/1000/lima"),
            "per-operator LIMA_HOME must be <root>/<daemon_uid>/<op_uid>/lima"
        );
    }

    #[test]
    fn operator_lima_home_varies_by_op_uid() {
        // Different operator uids must yield different paths (daemon uid fixed).
        let path_1000 = operator_lima_home_inner("/var/lib/sandboxd", 999, 1000);
        let path_1001 = operator_lima_home_inner("/var/lib/sandboxd", 999, 1001);
        assert_ne!(
            path_1000, path_1001,
            "different operator uids must produce distinct LIMA_HOME paths"
        );
        assert!(
            path_1000.as_os_str().to_string_lossy().contains("1000"),
            "path must contain the operator uid"
        );
        assert!(
            path_1001.as_os_str().to_string_lossy().contains("1001"),
            "path must contain the operator uid"
        );
    }

    #[test]
    fn operator_lima_home_varies_by_daemon_uid() {
        // Different daemon uids must yield different paths (op uid fixed).
        let path_d999 = operator_lima_home_inner("/var/lib/sandboxd", 999, 1000);
        let path_d1000 = operator_lima_home_inner("/var/lib/sandboxd", 1000, 1000);
        assert_ne!(
            path_d999, path_d1000,
            "different daemon uids must produce distinct LIMA_HOME paths"
        );
        assert!(
            path_d999.as_os_str().to_string_lossy().contains("999"),
            "path must contain the daemon uid"
        );
        assert!(
            path_d1000.as_os_str().to_string_lossy().contains("1000"),
            "path must contain the daemon uid"
        );
    }

    // -----------------------------------------------------------------------
    // ensure_operator_lima_home: directory mode and ACL shape
    // -----------------------------------------------------------------------
    //
    // These tests require `setfacl` and `getfacl` on the host.  A missing
    // `setfacl` binary is surfaced as a test failure with a clear message
    // (not a skip) because the project's `make setup-dev-env` instructions
    // document `acl` as a required package — a missing binary on a
    // correctly-configured dev host is a real gap.
    //
    // We use a tempdir as the base path to avoid touching real system state.
    // The tests call a private helper (`ensure_operator_lima_home_at`) that
    // accepts an explicit base path so integration tests can inject a
    // non-root dir.  Hermetic tests verify mode and ACL assertions via
    // `getfacl`; the public API uses the production path
    // `/var/lib/sandboxd/`.

    /// Run `getfacl` on `dir` and return its stdout as a String.
    /// Linux-only — `getfacl` is not available on macOS.
    #[cfg(not(target_os = "macos"))]
    fn getfacl_output(dir: &std::path::Path) -> String {
        let out = std::process::Command::new("getfacl")
            .arg(dir.to_string_lossy().as_ref())
            .output()
            .expect("getfacl must be available");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Like [`ensure_operator_lima_home`] but with caller-supplied base
    /// directory and daemon uid.  Used by hermetic tests to avoid writing
    /// under `/var/lib/sandboxd/` and to exercise the 3-level path scheme
    /// with an explicit daemon uid rather than the live process uid.
    pub(super) fn ensure_operator_lima_home_at(
        base: &std::path::Path,
        daemon_uid: u32,
        op_uid: u32,
    ) -> Result<PathBuf, SandboxError> {
        let lima_home = base.join(format!("{daemon_uid}/{op_uid}/lima"));
        std::fs::create_dir_all(&lima_home).map_err(|e| {
            SandboxError::Internal(format!(
                "failed to create per-operator LIMA_HOME {}: {e}",
                lima_home.display()
            ))
        })?;
        // macOS: mirror the production path — chmod 0700 then chmod +a to
        // grant the operator ACE on the directory only (no inheritance).
        // See ensure_operator_lima_home for the full rationale.
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&lima_home, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| {
                    SandboxError::Internal(format!(
                        "failed to chmod 0700 LIMA_HOME {}: {e}",
                        lima_home.display()
                    ))
                },
            )?;

            // Resolve op_uid → username for the chmod +a ACE.  Production
            // `ensure_operator_lima_home` hard-fails on an unresolvable uid
            // because the operator is always a real logged-in user.  This
            // test helper, however, is exercised by the registry tests with
            // synthetic uids (1000, 1001) that intentionally have no passwd
            // entry on macOS (user uids start at 501).  Those tests only care
            // about per-operator path isolation, not the ACL — the ACL itself
            // is covered by the `ensure_operator_lima_home_macos_*` tests,
            // which always pass `Uid::current()`.  So when the uid does not
            // resolve, fall back to the current user's name: the tempdir is
            // owned by the test runner and a uid with no Directory Services
            // UUID cannot be named in a `chmod +a` ACE anyway.
            let username = match nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(op_uid))
                .map_err(|e| {
                    SandboxError::Internal(format!(
                        "failed to look up username for uid {op_uid}: {e}"
                    ))
                })? {
                Some(user) => user.name,
                None => {
                    nix::unistd::User::from_uid(nix::unistd::Uid::current())
                        .map_err(|e| {
                            SandboxError::Internal(format!(
                                "failed to look up current username: {e}"
                            ))
                        })?
                        .ok_or_else(|| {
                            SandboxError::Internal("no passwd entry for current uid".to_string())
                        })?
                        .name
                }
            };

            let ace = format!(
                "user:{username} allow \
                 list,search,add_file,add_subdirectory,delete_child,\
                 readattr,writeattr,readextattr,writeextattr,readsecurity"
            );
            let output = run_with_timeout(
                Command::new("chmod").arg("+a").arg(&ace).arg(&lima_home),
                std::time::Duration::from_secs(10),
                "chmod +a",
            )?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(SandboxError::Internal(format!(
                    "chmod +a on {} failed: {stderr}",
                    lima_home.display()
                )));
            }
            return Ok(lima_home);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let acl_spec = format!("u:{op_uid}:rwx,d:g::---,d:o::---");
            let output = run_with_timeout(
                Command::new("setfacl")
                    .arg("-m")
                    .arg(&acl_spec)
                    .arg(&lima_home),
                std::time::Duration::from_secs(10),
                "setfacl",
            )?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(SandboxError::Internal(format!(
                    "setfacl on {} failed: {stderr}",
                    lima_home.display()
                )));
            }
            return Ok(lima_home);
        }
        #[allow(unreachable_code)]
        Ok(lima_home)
    }

    #[test]
    fn ensure_operator_lima_home_creates_directory() {
        let tmp = tempfile::TempDir::new().expect("create tempdir");
        let current_uid = nix::unistd::Uid::current().as_raw();
        let lima_home = ensure_operator_lima_home_at(tmp.path(), current_uid, current_uid)
            .expect("ensure_operator_lima_home_at must succeed");
        assert!(
            lima_home.is_dir(),
            "LIMA_HOME directory must exist after ensure call"
        );
    }

    #[test]
    fn ensure_operator_lima_home_is_idempotent() {
        let tmp = tempfile::TempDir::new().expect("create tempdir");
        let current_uid = nix::unistd::Uid::current().as_raw();
        // First call: creates the directory and applies ACLs.
        ensure_operator_lima_home_at(tmp.path(), current_uid, current_uid)
            .expect("first ensure call must succeed");
        // Second call: directory already exists; setfacl is idempotent.
        ensure_operator_lima_home_at(tmp.path(), current_uid, current_uid)
            .expect("second ensure call must succeed (idempotent)");
    }

    // Linux ACL verification uses setfacl + getfacl.  macOS uses chmod +a;
    // see ensure_operator_lima_home_macos_acl_* tests below.
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn ensure_operator_lima_home_acl_contains_user_entry() {
        // Verify that `getfacl` output on the provisioned directory
        // contains:
        //   - an access ACL entry for the current user (rwx on the dir root)
        //   - default:group::--- (suppress group read on children)
        //   - default:other::--- (suppress world read on children)
        //   - NO default named-user ACL for op_uid
        //
        // The default named-user ACL was intentionally removed because Linux
        // ACL semantics force st_mode group bits >= the named-user mask,
        // turning Lima's `_config/user` key file from 0600 to 0640+, which
        // OpenSSH's StrictKeyfileMode rejects. The operator owns every file
        // limactl creates (post-setresuid pivot) and accesses them via owner
        // bits — no default named-user propagation needed.
        //
        // We use the current uid as both daemon uid and operator uid so the
        // test doesn't need root to set ACLs for an arbitrary uid.
        let tmp = tempfile::TempDir::new().expect("create tempdir");
        let op_uid = nix::unistd::Uid::current().as_raw();
        let lima_home = ensure_operator_lima_home_at(tmp.path(), op_uid, op_uid)
            .expect("ensure_operator_lima_home_at must succeed");

        let acl = getfacl_output(&lima_home);

        // `getfacl` resolves numeric uids to names when the uid is known to
        // NSS (the common case on a dev host where uid 1000 resolves to
        // "olek").  On hosts where the uid is unknown it prints the numeric
        // form.  We accept either representation.
        //
        // The setfacl invocation always uses the numeric uid form (per
        // spec); getfacl output form is an observability detail, not the
        // contract.  What matters is that the correct ACL entry was applied.
        let username = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(op_uid))
            .ok()
            .flatten()
            .map(|u| u.name);

        // Access ACL: op_uid must have rwx on the dir root so it can
        // traverse, read, and write the LIMA_HOME directory.
        let user_acl_numeric = format!("user:{op_uid}:rwx");
        let user_acl_named = username
            .as_deref()
            .map(|n| format!("user:{n}:rwx"))
            .unwrap_or_default();
        assert!(
            acl.contains(&user_acl_numeric) || acl.contains(&user_acl_named),
            "getfacl output must contain access ACL for op_uid {op_uid} \
             (numeric '{user_acl_numeric}' or named '{user_acl_named}');\n\
             got:\n{acl}"
        );

        // Default group and other ACLs must suppress group/world read on
        // all children (belt-and-suspenders against the ACL mask).
        assert!(
            acl.contains("default:group::---"),
            "getfacl output must contain 'default:group::---' to suppress group \
             read on children (including Lima's _config/user SSH key);\n\
             got:\n{acl}"
        );
        assert!(
            acl.contains("default:other::---"),
            "getfacl output must contain 'default:other::---' to suppress world \
             read on children;\n\
             got:\n{acl}"
        );

        // No default named-user ACL for op_uid. Such an entry would force
        // st_mode group bits >= the ACL mask and turn 0600 files into 0640+,
        // breaking OpenSSH's StrictKeyfileMode for Lima's _config/user key.
        let default_acl_numeric = format!("default:user:{op_uid}:");
        let default_acl_named = username
            .as_deref()
            .map(|n| format!("default:user:{n}:"))
            .unwrap_or_default();
        assert!(
            !acl.contains(&default_acl_numeric)
                && (default_acl_named.is_empty() || !acl.contains(&default_acl_named)),
            "getfacl output must NOT contain a default named-user ACL for op_uid {op_uid} \
             — such an entry causes OpenSSH StrictKeyfileMode rejection of _config/user;\n\
             got:\n{acl}"
        );
    }

    // macOS ACL verification: ensure_operator_lima_home_at applies a
    // non-inheriting `allow` ACE for the operator on the directory, mirroring
    // the Linux setfacl grant, without propagating to child files (which would
    // trigger OpenSSH StrictKeyfileMode rejection of _config/user).

    /// Parse `ls -led` output for a directory and return the raw ACL lines
    /// (everything after the first line).  The first line is the stat line;
    /// subsequent lines are ACE entries prefixed with a space and index.
    #[cfg(target_os = "macos")]
    fn lsled_acl_lines(dir: &std::path::Path) -> String {
        let out = std::process::Command::new("ls")
            .arg("-led")
            .arg(dir.to_string_lossy().as_ref())
            .output()
            .expect("ls -led must be available");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        // Drop the first line (the stat summary); return the rest.
        text.lines().skip(1).collect::<Vec<_>>().join("\n")
    }

    /// Parse `ls -le` output for a file and return the ACL lines.
    #[cfg(target_os = "macos")]
    fn lsle_acl_lines(file: &std::path::Path) -> String {
        let out = std::process::Command::new("ls")
            .arg("-le")
            .arg(file.to_string_lossy().as_ref())
            .output()
            .expect("ls -le must be available");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.lines().skip(1).collect::<Vec<_>>().join("\n")
    }

    /// After provisioning, the LIMA_HOME directory must carry a macOS `allow`
    /// ACE for the operator uid that grants traverse/read/write access.
    #[test]
    #[cfg(target_os = "macos")]
    fn ensure_operator_lima_home_macos_acl_grants_operator_allow_ace() {
        // Use the current uid as both daemon uid and operator uid so the test
        // is self-contained (no cross-uid chmod needed).
        let tmp = tempfile::TempDir::new().expect("create tempdir");
        let current_uid = nix::unistd::Uid::current().as_raw();
        let lima_home = ensure_operator_lima_home_at(tmp.path(), current_uid, current_uid)
            .expect("ensure_operator_lima_home_at must succeed");

        let acl = lsled_acl_lines(&lima_home);

        // Resolve uid → username the same way the implementation does.
        let username = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(current_uid))
            .expect("nix lookup must not error")
            .expect("current uid must have a passwd entry")
            .name;

        // The ACE must be an `allow` entry for the operator username.
        assert!(
            acl.contains(&format!("user:{username} allow")),
            "ls -led ACL lines must contain an 'allow' ACE for user {username};\n\
             got:\n{acl}"
        );

        // The ACE must NOT contain inheritance flags.  Inheritance would
        // propagate into `_config/user` (Lima's SSH key), whose ACL presence
        // triggers OpenSSH StrictKeyfileMode rejection.
        assert!(
            !acl.contains("file_inherit"),
            "ls -led ACL lines must NOT contain 'file_inherit' — the ACE must \
             apply to the directory only, not propagate to child files;\n\
             got:\n{acl}"
        );
        assert!(
            !acl.contains("directory_inherit"),
            "ls -led ACL lines must NOT contain 'directory_inherit';\n\
             got:\n{acl}"
        );
    }

    /// A file created inside the provisioned LIMA_HOME must NOT inherit the
    /// operator ACE — it must be a plain mode file with no ACL.
    ///
    /// This is the load-bearing correctness property: Lima's `_config/user`
    /// SSH private key lives inside LIMA_HOME and must remain 0600 with no
    /// ACL so OpenSSH StrictKeyfileMode does not reject it.
    #[test]
    #[cfg(target_os = "macos")]
    fn ensure_operator_lima_home_macos_child_file_has_no_inherited_ace() {
        let tmp = tempfile::TempDir::new().expect("create tempdir");
        let current_uid = nix::unistd::Uid::current().as_raw();
        let lima_home = ensure_operator_lima_home_at(tmp.path(), current_uid, current_uid)
            .expect("ensure_operator_lima_home_at must succeed");

        // Create a child file to simulate what limactl would create.
        let child = lima_home.join("_config_user_sim");
        std::fs::write(&child, b"").expect("create child file");

        let child_acl = lsle_acl_lines(&child);

        // A plain file with no ACL has no lines after the stat line in
        // `ls -le` output.
        assert!(
            child_acl.trim().is_empty(),
            "child file must have no ACL (empty ls -le ACL lines) — the \
             parent dir ACE must not propagate via inheritance;\n\
             got:\n{child_acl}"
        );
    }

    // -----------------------------------------------------------------------
    // LimaManagerRegistry: concurrency and isolation
    // -----------------------------------------------------------------------

    #[test]
    fn registry_get_or_create_returns_same_arc_for_same_uid() {
        // The registry must return the same Arc for repeated calls with the
        // same operator uid — not a fresh LimaManager on every call.
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().to_path_buf();
        let registry = LimaManagerRegistry::new_with_provisioner(
            "sandbox-base".to_string(),
            Arc::new(SetuidHelperExecutor::new(PathBuf::from(
                "/usr/local/libexec/sandboxd/sandbox-lima-helper",
            ))),
            "test-pool".to_string(),
            false, // is_macos: Linux test environment
            move |uid| {
                ensure_operator_lima_home_at(&root, nix::unistd::Uid::current().as_raw(), uid)
            },
        );
        let mgr1 = registry.get_or_create(1000).expect("get_or_create");
        let mgr2 = registry.get_or_create(1000).expect("get_or_create");
        assert!(
            Arc::ptr_eq(&mgr1, &mgr2),
            "registry must return the same Arc<LimaManager> for the same operator uid"
        );
        assert_eq!(registry.len(), 1, "registry must have exactly one entry");
    }

    #[test]
    fn registry_get_or_create_returns_different_arcs_for_different_uids() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().to_path_buf();
        let registry = LimaManagerRegistry::new_with_provisioner(
            "sandbox-base".to_string(),
            Arc::new(SetuidHelperExecutor::new(PathBuf::from(
                "/usr/local/libexec/sandboxd/sandbox-lima-helper",
            ))),
            "test-pool".to_string(),
            false, // is_macos: Linux test environment
            move |uid| {
                ensure_operator_lima_home_at(&root, nix::unistd::Uid::current().as_raw(), uid)
            },
        );
        let mgr1000 = registry.get_or_create(1000).expect("get_or_create 1000");
        let mgr1001 = registry.get_or_create(1001).expect("get_or_create 1001");
        assert!(
            !Arc::ptr_eq(&mgr1000, &mgr1001),
            "registry must return distinct Arc<LimaManager> instances for different operator uids"
        );
        assert_eq!(registry.len(), 2, "registry must have two entries");
    }

    #[test]
    fn registry_operators_have_isolated_lima_homes() {
        // Each operator's LimaManager must be rooted at a distinct
        // LIMA_HOME path under <state_root>/<daemon_uid>/<op_uid>/lima.
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path().to_path_buf();
        let registry = LimaManagerRegistry::new_with_provisioner(
            "sandbox-base".to_string(),
            Arc::new(SetuidHelperExecutor::new(PathBuf::from(
                "/usr/local/libexec/sandboxd/sandbox-lima-helper",
            ))),
            "test-pool".to_string(),
            false, // is_macos: Linux test environment
            move |uid| {
                ensure_operator_lima_home_at(&root, nix::unistd::Uid::current().as_raw(), uid)
            },
        );
        let mgr1000 = registry.get_or_create(1000).expect("get_or_create 1000");
        let mgr1001 = registry.get_or_create(1001).expect("get_or_create 1001");
        assert_ne!(
            mgr1000.base_dir(),
            mgr1001.base_dir(),
            "distinct operators must have distinct LIMA_HOME base_dirs"
        );
        assert!(
            mgr1000
                .base_dir()
                .as_os_str()
                .to_string_lossy()
                .contains("1000"),
            "operator 1000's LIMA_HOME must contain '1000'"
        );
        assert!(
            mgr1001
                .base_dir()
                .as_os_str()
                .to_string_lossy()
                .contains("1001"),
            "operator 1001's LIMA_HOME must contain '1001'"
        );
    }

    #[test]
    fn registry_serialises_same_operator_builds_via_same_arc() {
        // Same-operator concurrent base-image builds are serialised because
        // `get_or_create` returns the same `Arc<LimaManager>`, and the
        // build mutex lives inside `LimaManager`.  We verify the
        // serialisation contract here by confirming that two threads
        // holding the registry concurrently for the same uid both receive
        // the identical Arc — they would contend on the same per-instance
        // mutex if they both called `build_base_image`.
        use std::sync::Barrier;

        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let root = tmp.path().to_path_buf();
        let registry = Arc::new(LimaManagerRegistry::new_with_provisioner(
            "sandbox-base".to_string(),
            Arc::new(SetuidHelperExecutor::new(PathBuf::from(
                "/usr/local/libexec/sandboxd/sandbox-lima-helper",
            ))),
            "test-pool".to_string(),
            false, // is_macos: Linux test environment
            move |uid| {
                ensure_operator_lima_home_at(&root, nix::unistd::Uid::current().as_raw(), uid)
            },
        ));

        let barrier = Arc::new(Barrier::new(2));
        let r1 = Arc::clone(&registry);
        let b1 = Arc::clone(&barrier);
        let h1 = std::thread::spawn(move || {
            b1.wait();
            r1.get_or_create(1000)
        });

        let r2 = Arc::clone(&registry);
        let b2 = Arc::clone(&barrier);
        let h2 = std::thread::spawn(move || {
            b2.wait();
            r2.get_or_create(1000)
        });

        let arc1 = h1
            .join()
            .expect("thread 1 must not panic")
            .expect("get_or_create");
        let arc2 = h2
            .join()
            .expect("thread 2 must not panic")
            .expect("get_or_create");

        assert!(
            Arc::ptr_eq(&arc1, &arc2),
            "concurrent get_or_create for the same uid must return the same Arc"
        );
        assert_eq!(
            registry.len(),
            1,
            "registry must have exactly one entry after concurrent same-uid creates"
        );
    }

    #[test]
    fn registry_distinct_operators_do_not_contend() {
        // Distinct operators get separate Arcs and can build base images
        // concurrently without any ordering dependency.  We verify that
        // the registry produces two independent entries.
        use std::sync::Barrier;

        let tmp = tempfile::TempDir::new().expect("tmpdir");
        let root = tmp.path().to_path_buf();
        let registry = Arc::new(LimaManagerRegistry::new_with_provisioner(
            "sandbox-base".to_string(),
            Arc::new(SetuidHelperExecutor::new(PathBuf::from(
                "/usr/local/libexec/sandboxd/sandbox-lima-helper",
            ))),
            "test-pool".to_string(),
            false, // is_macos: Linux test environment
            move |uid| {
                ensure_operator_lima_home_at(&root, nix::unistd::Uid::current().as_raw(), uid)
            },
        ));

        let barrier = Arc::new(Barrier::new(2));
        let r1 = Arc::clone(&registry);
        let b1 = Arc::clone(&barrier);
        let h1 = std::thread::spawn(move || {
            b1.wait();
            r1.get_or_create(1000)
        });

        let r2 = Arc::clone(&registry);
        let b2 = Arc::clone(&barrier);
        let h2 = std::thread::spawn(move || {
            b2.wait();
            r2.get_or_create(1001)
        });

        let arc1 = h1
            .join()
            .expect("thread 1 must not panic")
            .expect("get_or_create 1000");
        let arc2 = h2
            .join()
            .expect("thread 2 must not panic")
            .expect("get_or_create 1001");

        assert!(
            !Arc::ptr_eq(&arc1, &arc2),
            "concurrent get_or_create for distinct uids must return independent Arcs"
        );
        assert_eq!(
            registry.len(),
            2,
            "registry must have two entries after concurrent distinct-uid creates"
        );
    }

    // -----------------------------------------------------------------------
    // enumerate_operator_uids_from_fs tests
    // -----------------------------------------------------------------------
    //
    // These tests use the test-env-override state-root redirect so they do
    // not touch `/var/lib/sandboxd/`. The daemon-uid segment is derived from
    // `getuid()` in production; here we rely on `daemon_lima_root()` which
    // reads the same env var redirect.

    #[test]
    #[cfg(feature = "test-env-override")]
    fn enumerate_operator_uids_returns_numeric_subdirs_with_lima_child() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path();
        let daemon_uid = nix::unistd::Uid::current().as_raw();

        // Create two valid operator entries and one invalid one.
        let op1 = root.join(daemon_uid.to_string()).join("1001").join("lima");
        let op2 = root.join(daemon_uid.to_string()).join("1002").join("lima");
        // Non-numeric dir — must be skipped.
        let non_num = root
            .join(daemon_uid.to_string())
            .join("notanumber")
            .join("lima");
        // Numeric dir without lima/ — must be skipped.
        let no_lima = root.join(daemon_uid.to_string()).join("1003").join("other");

        for dir in [&op1, &op2, &non_num, &no_lima] {
            std::fs::create_dir_all(dir).expect("create dir");
        }

        // Point the enumerator at our tempdir.
        // SAFETY: test-only, single-threaded at this point in the test.
        unsafe { std::env::set_var(STATE_ROOT_OVERRIDE_ENV, root.to_str().unwrap()) };
        let uids = enumerate_operator_uids_from_fs();
        unsafe { std::env::remove_var(STATE_ROOT_OVERRIDE_ENV) };

        let mut sorted = uids.clone();
        sorted.sort();
        assert_eq!(sorted, vec![1001u32, 1002]);
    }

    #[test]
    #[cfg(feature = "test-env-override")]
    fn enumerate_operator_uids_returns_empty_when_root_absent() {
        // A state root that does not exist on disk should yield an empty list,
        // not an error or panic.
        // SAFETY: test-only, single-threaded at this point.
        unsafe {
            std::env::set_var(
                STATE_ROOT_OVERRIDE_ENV,
                "/tmp/this-dir-does-not-exist-12345",
            )
        };
        let uids = enumerate_operator_uids_from_fs();
        unsafe { std::env::remove_var(STATE_ROOT_OVERRIDE_ENV) };
        assert!(uids.is_empty());
    }

    #[test]
    #[cfg(feature = "test-env-override")]
    fn enumerate_operator_uids_skips_root_uid() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let root = tmp.path();
        let daemon_uid = nix::unistd::Uid::current().as_raw();

        // uid 0 should always be skipped.
        let op0 = root.join(daemon_uid.to_string()).join("0").join("lima");
        let op1001 = root.join(daemon_uid.to_string()).join("1001").join("lima");
        for dir in [&op0, &op1001] {
            std::fs::create_dir_all(dir).expect("create dir");
        }

        // SAFETY: test-only, single-threaded at this point in the test.
        unsafe { std::env::set_var(STATE_ROOT_OVERRIDE_ENV, root.to_str().unwrap()) };
        let uids = enumerate_operator_uids_from_fs();
        unsafe { std::env::remove_var(STATE_ROOT_OVERRIDE_ENV) };

        assert!(!uids.contains(&0), "uid 0 must be excluded");
        assert!(uids.contains(&1001), "uid 1001 must be included");
    }

    // -----------------------------------------------------------------------
    // decide_lima_vm tests — pure classification logic, no I/O
    // -----------------------------------------------------------------------

    fn test_sid(hex: &str) -> SessionId {
        SessionId::parse(hex).expect("12-hex session id")
    }

    fn test_live(sids: &[&str]) -> std::collections::HashSet<SessionId> {
        sids.iter().map(|s| test_sid(s)).collect()
    }

    #[test]
    fn decide_lima_vm_skips_no_session_id() {
        // Base image VMs have session_id == None.
        let live = test_live(&[]);
        assert_eq!(
            decide_lima_vm(None, None, &live, "10.209.0.0/20"),
            LimaVmDecision::SkipNoSessionId
        );
    }

    #[test]
    fn decide_lima_vm_skips_live_session() {
        let sid = test_sid("aabbccddeeff");
        let live = test_live(&["aabbccddeeff"]);
        assert_eq!(
            decide_lima_vm(Some(&sid), Some("10.209.0.0/20"), &live, "10.209.0.0/20"),
            LimaVmDecision::SkipLive
        );
    }

    #[test]
    fn decide_lima_vm_skips_live_session_regardless_of_marker() {
        // A live session is never reaped, even if marker is absent.
        let sid = test_sid("aabbccddeeff");
        let live = test_live(&["aabbccddeeff"]);
        assert_eq!(
            decide_lima_vm(Some(&sid), None, &live, "10.209.0.0/20"),
            LimaVmDecision::SkipLive
        );
    }

    #[test]
    fn decide_lima_vm_reaps_orphan_with_matching_marker() {
        let sid = test_sid("112233445566");
        let live = test_live(&[]); // not in live set
        assert_eq!(
            decide_lima_vm(Some(&sid), Some("10.209.0.0/20"), &live, "10.209.0.0/20"),
            LimaVmDecision::Reap
        );
    }

    #[test]
    fn decide_lima_vm_reaps_orphan_with_absent_marker() {
        // Absent marker = legacy VM in our own LIMA_HOME. Name + live-set
        // scoping is sufficient: still ours to reap.
        let sid = test_sid("112233445566");
        let live = test_live(&[]);
        assert_eq!(
            decide_lima_vm(Some(&sid), None, &live, "10.209.0.0/20"),
            LimaVmDecision::Reap
        );
    }

    #[test]
    fn decide_lima_vm_skips_foreign_marker() {
        // Marker present and != my_pool → belongs to a different daemon.
        // Do NOT reap even though the session is absent from our live set.
        let sid = test_sid("112233445566");
        let live = test_live(&[]);
        assert_eq!(
            decide_lima_vm(Some(&sid), Some("10.220.0.0/20"), &live, "10.209.0.0/20"),
            LimaVmDecision::SkipForeignMarker {
                marker_pool: "10.220.0.0/20".to_string()
            }
        );
    }

    #[test]
    fn decide_lima_vm_live_takes_priority_over_foreign_marker() {
        // If a session is live, it's skipped before the marker is even checked.
        let sid = test_sid("aabbccddeeff");
        let live = test_live(&["aabbccddeeff"]);
        assert_eq!(
            decide_lima_vm(Some(&sid), Some("10.220.0.0/20"), &live, "10.209.0.0/20"),
            LimaVmDecision::SkipLive
        );
    }

    // -----------------------------------------------------------------------
    // reap_lima_orphans_inner orchestration tests
    // -----------------------------------------------------------------------
    //
    // These tests drive the full enumerate→list→decide→delete flow over
    // injected fakes (no real Lima helper, no VMs, no /dev/kvm). They verify
    // the glue that decide_lima_vm unit tests cannot cover: that the
    // orchestration correctly wires op-uid enumeration, marker lookup, and
    // delete dispatch together.

    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory fake for [`LimaReaperOps`]. Drives the orchestration loop
    /// with canned VMs and markers; records which VMs were deleted.
    struct FakeLimaReaperOps {
        /// op_uid → list of VMs that belong to that operator.
        vms: HashMap<u32, Vec<VmInfo>>,
        /// (op_uid, session_id_str) → Option<pool_cidr>. `None` = absent marker.
        markers: HashMap<(u32, String), Option<String>>,
        /// Collects (op_uid, session_id_str) pairs for every delete_vm call.
        deleted: Mutex<Vec<(u32, String)>>,
        /// Set of (op_uid, session_id_str) whose delete_vm should return Err.
        fail_delete: std::collections::HashSet<(u32, String)>,
    }

    impl FakeLimaReaperOps {
        fn new() -> Self {
            Self {
                vms: HashMap::new(),
                markers: HashMap::new(),
                deleted: Mutex::new(Vec::new()),
                fail_delete: std::collections::HashSet::new(),
            }
        }

        /// Register a VM for an operator.
        fn add_vm(mut self, op_uid: u32, name: &str, sid: Option<&str>) -> Self {
            let session_id = sid.and_then(|s| SessionId::parse(s).ok());
            self.vms.entry(op_uid).or_default().push(VmInfo {
                name: name.to_string(),
                status: VmStatus::Stopped,
                session_id,
            });
            self
        }

        /// Register a marker for a VM (None = absent marker).
        fn set_marker(mut self, op_uid: u32, sid: &str, pool: Option<&str>) -> Self {
            self.markers
                .insert((op_uid, sid.to_string()), pool.map(|s| s.to_string()));
            self
        }

        /// Mark a delete as failing (returns Err).
        fn fail_on_delete(mut self, op_uid: u32, sid: &str) -> Self {
            self.fail_delete.insert((op_uid, sid.to_string()));
            self
        }

        fn deleted_vms(&self) -> Vec<(u32, String)> {
            self.deleted.lock().expect("mutex").clone()
        }
    }

    impl LimaReaperOps for FakeLimaReaperOps {
        fn list_vms(&self, op_uid: u32) -> Option<Vec<VmInfo>> {
            Some(self.vms.get(&op_uid).cloned().unwrap_or_default())
        }

        fn read_marker(&self, op_uid: u32, session_id: &SessionId) -> Option<String> {
            // Look up the marker. Key present with None = explicitly absent;
            // key absent = not registered = treat as absent marker.
            self.markers
                .get(&(op_uid, session_id.to_string()))
                .and_then(|v| v.clone())
        }

        fn delete_vm(&self, op_uid: u32, session_id: &SessionId) -> Result<(), SandboxError> {
            let key = (op_uid, session_id.to_string());
            if self.fail_delete.contains(&key) {
                return Err(SandboxError::Lima(format!(
                    "fake delete_vm failed for op={op_uid} sid={session_id}"
                )));
            }
            self.deleted.lock().expect("mutex").push(key);
            Ok(())
        }
    }

    const MY_POOL: &str = "10.209.0.0/20";
    const FOREIGN_POOL: &str = "10.220.0.0/20";

    // SIDs used across orchestration tests.
    const OWN_ORPHAN_SID: &str = "aa0000000001";
    const FOREIGN_SID: &str = "bb0000000002";
    const LIVE_SID: &str = "cc0000000003";
    const ABSENT_MARKER_SID: &str = "dd0000000004";

    fn orchestration_fake() -> FakeLimaReaperOps {
        FakeLimaReaperOps::new()
            // op 1001: owns four VMs across different cases
            .add_vm(
                1001,
                &format!("sandbox-{OWN_ORPHAN_SID}"),
                Some(OWN_ORPHAN_SID),
            )
            .add_vm(1001, &format!("sandbox-{FOREIGN_SID}"), Some(FOREIGN_SID))
            .add_vm(1001, &format!("sandbox-{LIVE_SID}"), Some(LIVE_SID))
            .add_vm(
                1001,
                &format!("sandbox-{ABSENT_MARKER_SID}"),
                Some(ABSENT_MARKER_SID),
            )
            .add_vm(1001, "sandbox-base", None) // base image — no session id
            // Markers
            .set_marker(1001, OWN_ORPHAN_SID, Some(MY_POOL))
            .set_marker(1001, FOREIGN_SID, Some(FOREIGN_POOL))
        // LIVE_SID and ABSENT_MARKER_SID: no marker registered
    }

    /// An operator with VMs on disk is not scanned while the daemon cannot
    /// reach them — the pass that would have listed them can only fail.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_unreachable_operator_on_disk_is_not_scanned() {
        assert_eq!(
            scan_scoped_to_reachable(vec![1001, 1002], &[1002]),
            vec![1002]
        );
    }

    /// A reachable operator with no LIMA_HOME is not scanned either. Asking
    /// for their manager would create the directory, so the disk decides what
    /// exists and reachability only narrows it.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_reachable_operator_with_no_lima_home_is_not_scanned() {
        assert!(scan_scoped_to_reachable(vec![1001], &[1001, 1002]).contains(&1001));
        assert!(!scan_scoped_to_reachable(vec![1001], &[1001, 1002]).contains(&1002));
    }

    /// Nobody reachable is nobody scanned — not everybody.
    #[cfg(target_os = "macos")]
    #[test]
    fn no_reachable_operators_scans_nothing() {
        assert!(scan_scoped_to_reachable(vec![1001, 1002], &[]).is_empty());
    }

    /// An orphan whose marker == my pool must be deleted (own orphan).
    #[test]
    fn reap_lima_orphans_inner_reaps_own_orphan_with_matching_marker() {
        let fake = orchestration_fake();
        let live = test_live(&[LIVE_SID]);
        let report = reap_lima_orphans_inner(&[1001], &fake, &live, MY_POOL);

        assert_eq!(report.vms_reaped, 2, "own orphan + absent-marker orphan");
        let deleted = fake.deleted_vms();
        assert!(
            deleted.iter().any(|(_, s)| s == OWN_ORPHAN_SID),
            "own orphan with matching marker must be deleted; deleted={deleted:?}"
        );
    }

    /// A VM with a FOREIGN marker must NOT be deleted (coexistence guarantee).
    #[test]
    fn reap_lima_orphans_inner_skips_foreign_marker() {
        let fake = orchestration_fake();
        let live = test_live(&[LIVE_SID]);
        let report = reap_lima_orphans_inner(&[1001], &fake, &live, MY_POOL);

        assert_eq!(report.vms_skipped_foreign, 1);
        let deleted = fake.deleted_vms();
        assert!(
            !deleted.iter().any(|(_, s)| s == FOREIGN_SID),
            "foreign-marker VM must NOT be deleted; deleted={deleted:?}"
        );
    }

    /// A VM whose session is in the live set must NOT be deleted.
    #[test]
    fn reap_lima_orphans_inner_skips_live_vm() {
        let fake = orchestration_fake();
        let live = test_live(&[LIVE_SID]);
        let report = reap_lima_orphans_inner(&[1001], &fake, &live, MY_POOL);

        assert_eq!(report.vms_skipped_live, 1);
        let deleted = fake.deleted_vms();
        assert!(
            !deleted.iter().any(|(_, s)| s == LIVE_SID),
            "live VM must NOT be deleted; deleted={deleted:?}"
        );
    }

    /// An absent-marker orphan within our own LIMA_HOME is reaped.
    /// This is the legacy-VM path: marker absent = assume ours.
    #[test]
    fn reap_lima_orphans_inner_reaps_absent_marker_orphan() {
        let fake = orchestration_fake();
        let live = test_live(&[LIVE_SID]);
        let _report = reap_lima_orphans_inner(&[1001], &fake, &live, MY_POOL);

        let deleted = fake.deleted_vms();
        assert!(
            deleted.iter().any(|(_, s)| s == ABSENT_MARKER_SID),
            "absent-marker orphan within own LIMA_HOME must be reaped; deleted={deleted:?}"
        );
    }

    /// An operator with NO live session rows in the DB must still have its VMs
    /// enumerated — the case an op_uid list built from session rows misses,
    /// and the reason this one is built from the disk. The test passes op_uid 1002
    /// (an operator whose only VM is orphaned and has no session rows) and
    /// verifies the orphan IS reaped.
    #[test]
    fn reap_lima_orphans_inner_reaps_orphaned_operator_with_no_live_sessions() {
        const ORPHANED_OP_SID: &str = "ee0000000005";
        let fake = FakeLimaReaperOps::new()
            .add_vm(
                1002,
                &format!("sandbox-{ORPHANED_OP_SID}"),
                Some(ORPHANED_OP_SID),
            )
            .set_marker(1002, ORPHANED_OP_SID, Some(MY_POOL));

        // Live set is empty — simulates an operator whose last session was
        // deleted from the DB but whose Lima VM was never cleaned up.
        let live = test_live(&[]);
        let report = reap_lima_orphans_inner(&[1002], &fake, &live, MY_POOL);

        assert_eq!(
            report.vms_reaped, 1,
            "orphaned operator's VM must be reaped even with no session rows"
        );
        let deleted = fake.deleted_vms();
        assert!(
            deleted.iter().any(|(_, s)| s == ORPHANED_OP_SID),
            "VM for op with no session rows must appear in deleted list; deleted={deleted:?}"
        );
    }

    /// A delete failure must be logged and skipped, not abort the sweep.
    /// The report must not count the failed delete as reaped.
    #[test]
    fn reap_lima_orphans_inner_continues_on_delete_failure() {
        const SID_A: &str = "ff0000000006";
        const SID_B: &str = "fe0000000007";
        let fake = FakeLimaReaperOps::new()
            .add_vm(1003, &format!("sandbox-{SID_A}"), Some(SID_A))
            .add_vm(1003, &format!("sandbox-{SID_B}"), Some(SID_B))
            .set_marker(1003, SID_A, Some(MY_POOL))
            .set_marker(1003, SID_B, Some(MY_POOL))
            .fail_on_delete(1003, SID_A);

        let live = test_live(&[]);
        let report = reap_lima_orphans_inner(&[1003], &fake, &live, MY_POOL);

        // SID_A fails to delete; SID_B succeeds.
        assert_eq!(
            report.vms_reaped, 1,
            "only SID_B should be counted as reaped"
        );
        let deleted = fake.deleted_vms();
        assert!(
            deleted.iter().any(|(_, s)| s == SID_B),
            "SID_B must be deleted; deleted={deleted:?}"
        );
    }

    /// A gateway VM survives a pass that would otherwise delete it.
    ///
    /// **The fixture cannot occur in production, and that is deliberate.** It
    /// pairs a gateway instance name with a session id, and nothing writes such
    /// a VM: `list_vms` admits only `VM_NAME_PREFIX`-prefixed names, and a
    /// gateway name has no 12-hex tail for `parse_session_id_from_name` to
    /// return an id from. A real gateway VM therefore arrives here — if it
    /// arrives at all — with every input the classifier reads absent. No
    /// realistic input can make this test red.
    ///
    /// It is written anyway, because the alternative is that the gateway's
    /// survival stays a by-product of two name schemes that were never
    /// required to stay apart, with no test that fails when the exclusion is
    /// removed. Pinning the schemes is a different assertion and already
    /// exists, next to the names, as
    /// `gateway_names_are_disjoint_from_the_session_vm_grammar`. This one
    /// supplies the only input the exclusion can be observed on: a VM the
    /// classifier rules `Reap` on, wearing the gateway's name.
    ///
    /// The session-named VM beside it is the control — same session-id shape,
    /// same matching marker, same absence from the live set, differing only in
    /// its name — and it is reaped in the same pass. Without it a green run
    /// would be equally consistent with a pass that reaped nothing at all.
    ///
    /// macOS-gated because the gateway VM is. Off macOS the gateway is a
    /// container on the host, no Lima instance is a gateway, and
    /// `is_gateway_instance` answers `false` — so there the fixture is reaped,
    /// correctly.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_gateway_vm_is_not_reaped_as_an_orphan() {
        const GATEWAY_SID: &str = "a10000000010";
        const CONTROL_SID: &str = "a20000000011";

        // Both naming modes, spelled out: the exclusion is not supposed to
        // consult the switch, so neither does the test.
        for gateway_name in ["sandboxd-gateway", "sandboxd-gateway-501"] {
            let fake = FakeLimaReaperOps::new()
                .add_vm(1004, gateway_name, Some(GATEWAY_SID))
                .add_vm(1004, &format!("sandbox-{CONTROL_SID}"), Some(CONTROL_SID))
                .set_marker(1004, GATEWAY_SID, Some(MY_POOL))
                .set_marker(1004, CONTROL_SID, Some(MY_POOL));

            let live = test_live(&[]);
            let report = reap_lima_orphans_inner(&[1004], &fake, &live, MY_POOL);

            let deleted = fake.deleted_vms();
            assert!(
                !deleted.iter().any(|(_, s)| s == GATEWAY_SID),
                "{gateway_name} was reaped as an orphan, taking egress away from \
                 every running session; deleted={deleted:?}"
            );
            assert!(
                deleted.iter().any(|(_, s)| s == CONTROL_SID),
                "the control VM was not reaped either, so this pass proves nothing \
                 about {gateway_name}; deleted={deleted:?}"
            );
            assert_eq!(
                report.vms_reaped, 1,
                "only the control VM is an orphan in this fixture"
            );
        }
    }

    // -----------------------------------------------------------------------
    // macOS qemu-wrapper script content tests
    // -----------------------------------------------------------------------

    /// The macOS wrapper must detect the real qemu-system-aarch64 binary,
    /// pass probe commands straight through, and rewrite the user netdev.
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_qemu_wrapper_script_probe_passthrough() {
        assert!(
            QEMU_WRAPPER_MACOS_SCRIPT.contains("help|--version|--help|-help"),
            "macOS wrapper must pass Lima probe commands straight through"
        );
        assert!(
            QEMU_WRAPPER_MACOS_SCRIPT.contains("exec \"$REAL_QEMU\" \"$@\""),
            "macOS wrapper must exec probe commands without modification"
        );
    }

    /// The macOS wrapper must contain the in-place restrict=on rewrite.
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_qemu_wrapper_rewrites_user_netdev() {
        assert!(
            QEMU_WRAPPER_MACOS_SCRIPT.contains("user|user,*)"),
            "macOS wrapper must scan for -netdev user,... backends"
        );
        assert!(
            QEMU_WRAPPER_MACOS_SCRIPT.contains("netdev=\"$restricted_netdev,restrict=on\""),
            "macOS wrapper must splice restrict=on into the user netdev"
        );
    }

    /// Fail-closed: zero user netdev tokens → abort.
    ///
    /// The shell variable is referenced as `"$user_netdev_count"` (quoted expansion)
    /// in the actual script; the test must match the exact form used.
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_qemu_wrapper_fails_closed_on_zero_user_netdev() {
        assert!(
            QEMU_WRAPPER_MACOS_SCRIPT.contains("\"$user_netdev_count\" -eq 0"),
            "macOS wrapper must abort when no -netdev user,... token is found; \
             check that the zero-count guard uses \"$user_netdev_count\" -eq 0"
        );
    }

    /// Fail-closed: >1 user netdev tokens → abort.
    ///
    /// The shell variable is referenced as `"$user_netdev_count"` (quoted expansion)
    /// in the actual script; the test must match the exact form used.
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_qemu_wrapper_fails_closed_on_multiple_user_netdevs() {
        assert!(
            QEMU_WRAPPER_MACOS_SCRIPT.contains("\"$user_netdev_count\" -gt 1"),
            "macOS wrapper must abort when more than one -netdev user,... token is found; \
             check that the multiple-count guard uses \"$user_netdev_count\" -gt 1"
        );
    }

    /// The wrapper must verify restrict=on is present after the rewrite.
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_qemu_wrapper_confirms_restrict_on_present() {
        assert!(
            QEMU_WRAPPER_MACOS_SCRIPT.contains("*restrict=on*)"),
            "macOS wrapper must confirm restrict=on is present in the rewritten token"
        );
    }

    /// The wrapper must record the rewritten netdev to the marker file.
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_qemu_wrapper_writes_marker_file() {
        assert!(
            QEMU_WRAPPER_MACOS_SCRIPT.contains("SANDBOX_RESTRICT_MARKER"),
            "macOS wrapper must write the rewritten netdev token to SANDBOX_RESTRICT_MARKER"
        );
        assert!(
            QEMU_WRAPPER_MACOS_SCRIPT.contains("> \"$SANDBOX_RESTRICT_MARKER\""),
            "macOS wrapper must write marker file content"
        );
    }

    /// The wrapper must respect SANDBOX_UNRESTRICTED_SLIRP_FOR_PROVISIONING.
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_qemu_wrapper_respects_unrestricted_slirp_flag() {
        assert!(
            QEMU_WRAPPER_MACOS_SCRIPT.contains("SANDBOX_UNRESTRICTED_SLIRP_FOR_PROVISIONING"),
            "macOS wrapper must skip rewrite when SANDBOX_UNRESTRICTED_SLIRP_FOR_PROVISIONING=1"
        );
    }

    /// The macOS wrapper must NOT contain bridge networking (socket_vmnet is
    /// the gateway-facing NIC; the wrapper never adds a second NIC).
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_qemu_wrapper_has_no_bridge_networking() {
        assert!(
            !QEMU_WRAPPER_MACOS_SCRIPT.contains("SANDBOX_DOCKER_BRIDGE"),
            "macOS wrapper must not reference SANDBOX_DOCKER_BRIDGE; bridge networking is Linux-only"
        );
        assert!(
            !QEMU_WRAPPER_MACOS_SCRIPT.contains("qemu-bridge-helper"),
            "macOS wrapper must not reference qemu-bridge-helper"
        );
    }

    /// The macOS wrapper must NOT contain systemd-run (cgroups are Linux-only).
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_qemu_wrapper_has_no_systemd_run() {
        assert!(
            !QEMU_WRAPPER_MACOS_SCRIPT.contains("systemd-run"),
            "macOS wrapper must not use systemd-run; cgroup limits are Linux-only"
        );
    }

    /// The macOS wrapper targets qemu-system-aarch64 (Apple Silicon only).
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_qemu_wrapper_targets_aarch64() {
        assert!(
            QEMU_WRAPPER_MACOS_SCRIPT.contains("qemu-system-aarch64"),
            "macOS wrapper must target qemu-system-aarch64 (Apple Silicon)"
        );
        assert!(
            !QEMU_WRAPPER_MACOS_SCRIPT.contains("qemu-system-x86_64"),
            "macOS wrapper must not reference x86_64 QEMU binary"
        );
    }

    /// Idempotent: re-running ensure_qemu_wrapper_macos with an existing
    /// wrapper file overwrites it cleanly.
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_ensure_qemu_wrapper_is_idempotent() {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let lima_home = dir.path().join("lima");
        std::fs::create_dir_all(&lima_home).expect("create lima_home");
        let mgr = LimaManager::with_helper_path_and_platform(
            lima_home,
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
            true,
        );

        let wrapper1 = mgr.ensure_qemu_wrapper_macos_for_test().unwrap();
        let wrapper2 = mgr.ensure_qemu_wrapper_macos_for_test().unwrap();
        assert_eq!(
            wrapper1, wrapper2,
            "idempotent calls must return the same path"
        );
        assert!(
            wrapper1.exists(),
            "wrapper script must exist after second call"
        );
        let content = std::fs::read_to_string(&wrapper1).unwrap();
        assert!(
            content.contains("restrict=on"),
            "wrapper must contain restrict=on rewrite logic"
        );
    }

    // -----------------------------------------------------------------------
    // macOS generate_template tests
    // -----------------------------------------------------------------------

    fn macos_mgr() -> LimaManager {
        LimaManager::with_helper_path_and_platform(
            PathBuf::from("/tmp/test/lima"),
            PathBuf::from("/usr/local/libexec/sandboxd/sandbox-lima-helper"),
            nix::unistd::Uid::current().as_raw(),
            DEFAULT_BASE_VM_NAME.to_string(),
            true,
        )
    }

    /// macOS template must use aarch64 image only (no amd64 entry).
    #[test]
    fn macos_template_uses_aarch64_image_only() {
        let mgr = macos_mgr();
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default();
        let template = mgr.generate_template(&id, &config, None, Some(0));
        assert!(
            template.contains("aarch64"),
            "macOS template must contain aarch64 image"
        );
        assert!(
            !template.contains("amd64") && !template.contains("x86_64"),
            "macOS template must not contain x86_64/amd64 image entry"
        );
    }

    /// macOS template must have a networks: [{socket: ...}] entry for the
    /// allocated vmnet slot.
    #[test]
    fn macos_template_has_socket_vmnet_nic() {
        let mgr = macos_mgr();
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default();
        let template = mgr.generate_template(&id, &config, None, Some(3));
        assert!(
            template.contains("networks:"),
            "macOS template must contain networks section"
        );
        assert!(
            template.contains("- socket: /var/run/sandbox/vmnet/slot-3.sock"),
            "macOS template must reference the correct vmnet slot socket path"
        );
    }

    /// macOS template must explicitly emit `vmType: "qemu"`.
    /// Lima on macOS defaults to VZ when vmType is unset; VZ cannot attach
    /// socket_vmnet and would void egress control. The template must always
    /// emit vmType: "qemu" explicitly so the agent validator can enforce it.
    #[test]
    fn macos_template_has_vmtype_qemu() {
        let mgr = macos_mgr();
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default();
        let template = mgr.generate_template(&id, &config, None, Some(0));
        assert!(
            template.contains("vmType: \"qemu\""),
            "macOS template must emit vmType: \"qemu\"; Lima defaults to VZ on macOS \
             when vmType is unset, which cannot attach socket_vmnet and voids egress control"
        );
    }

    /// macOS template must NOT contain Linux seccomp/cgroup wrapper references.
    #[test]
    fn macos_template_has_no_linux_wrapper() {
        let mgr = macos_mgr();
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default();
        let template = mgr.generate_template(&id, &config, None, Some(0));
        assert!(
            !template.contains("SANDBOX_DOCKER_BRIDGE"),
            "macOS template must not reference SANDBOX_DOCKER_BRIDGE"
        );
        assert!(
            !template.contains("systemd-run"),
            "macOS template must not reference systemd-run"
        );
    }

    /// macOS template must contain static IP cloud-init for the socket_vmnet NIC.
    #[test]
    fn macos_template_has_static_ip_cloud_init() {
        let mgr = macos_mgr();
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default();
        // Slot 0: B=10.209.128.0, B+3=.3 (gateway), B+4=.4 (VM)
        let template = mgr.generate_template(&id, &config, None, Some(0));
        assert!(
            template.contains("10.209.128.4/29"),
            "macOS template slot 0 must configure VM IP 10.209.128.4/29; got: {}",
            &template[..template.len().min(3000)]
        );
        assert!(
            template.contains("via: 10.209.128.3"),
            "macOS template slot 0 must set default route via gateway 10.209.128.3"
        );
    }

    /// Verify static IP arithmetic for a non-zero slot.
    #[test]
    fn macos_template_static_ip_slot_2() {
        let mgr = macos_mgr();
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default();
        // Slot 2: B=10.209.128.16, B+3=.19 (gateway), B+4=.20 (VM)
        let template = mgr.generate_template(&id, &config, None, Some(2));
        assert!(
            template.contains("10.209.128.20/29"),
            "macOS template slot 2 must configure VM IP 10.209.128.20/29"
        );
        assert!(
            template.contains("via: 10.209.128.19"),
            "macOS template slot 2 must set default route via gateway 10.209.128.19"
        );
    }

    /// macOS template must emit operator-uid cloud-init when uid != 1000.
    #[test]
    fn macos_template_emits_operator_uid_step_for_non_default_uid() {
        let mgr = macos_mgr();
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default();
        let template = mgr.generate_template(&id, &config, Some((5001, 5001)), Some(0));
        assert!(
            template.contains("step=operator-uid"),
            "macOS template must emit operator-uid cloud-init step for uid != 1000"
        );
        assert!(
            template.contains("groupmod -g 5001 sandbox"),
            "macOS template must call groupmod with operator gid"
        );
        assert!(
            template.contains("usermod -u 5001 -g 5001 sandbox"),
            "macOS template must call usermod with operator uid:gid"
        );
    }

    /// macOS template must elide operator-uid cloud-init at uid 1000.
    #[test]
    fn macos_template_elides_operator_uid_step_at_1000() {
        let mgr = macos_mgr();
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default();
        let template = mgr.generate_template(&id, &config, Some((1000, 1000)), Some(0));
        assert!(
            !template.contains("step=operator-uid"),
            "macOS template must elide operator-uid step at uid 1000 (no-op)"
        );
    }

    /// macOS template must pass structural shape validation.
    ///
    /// This test checks the key invariants the agent's `validate_lima_yaml_shape`
    /// enforces: vmType must be "qemu", networks with exactly one socket entry, and
    /// the socket path confined to `/var/run/sandbox/vmnet/`. It does so via text
    /// inspection (sandbox-core has no serde_yaml dep; the full structural parse
    /// lives in sandbox-agent's `validate_lima_yaml_shape` which is tested
    /// separately by the validator round-trip test in sandbox-agent/src/validation.rs).
    #[test]
    fn macos_template_shape_is_valid_for_agent_validator() {
        let mgr = macos_mgr();
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default();
        let template = mgr.generate_template(&id, &config, None, Some(0));

        // 1. vmType: "qemu" must be present. Lima defaults to VZ on macOS when
        //    vmType is absent; VZ cannot attach socket_vmnet and voids egress.
        assert!(
            template.contains("vmType: \"qemu\""),
            "macOS template must emit vmType: \"qemu\" (agent validator requires it)"
        );
        // 2. networks section present.
        assert!(
            template.contains("\nnetworks:"),
            "macOS template must have a networks: section"
        );
        // 3. Exactly one socket entry within /var/run/sandbox/vmnet/.
        let socket_count = template
            .matches("- socket: /var/run/sandbox/vmnet/")
            .count();
        assert_eq!(
            socket_count, 1,
            "macOS template must have exactly one socket vmnet entry; found {socket_count}"
        );
        // 4. No mode: key inside the networks section.
        assert!(
            !template.contains("  mode:"),
            "macOS template must not have a mode: key in the networks section"
        );
        // 5. No top-level network: (singular) key.
        //
        // The naive check (iterate lines and strip_start) false-positives on the
        // netplan `network:` root key embedded inside the cloud-init `script:` block
        // (which is a multi-line string value, not a top-level YAML key). The real
        // agent validator (`validate_lima_yaml_shape`) parses structurally and only
        // checks top-level keys — it never trips on `network:` inside a string value.
        //
        // Reliable proxy for top-level YAML keys: lines that start at column 0 (no
        // leading whitespace). The netplan `network:` key is always indented inside
        // the provision script block; a true top-level `network:` would start at col 0.
        for line in template.lines() {
            if line.starts_with("network:") {
                panic!(
                    "macOS template must not have a top-level 'network:' key (column 0); \
                     found: {line:?}"
                );
            }
        }
    }

    /// macOS template must include the systemd-networkd-wait-online --any drop-in.
    ///
    /// The drop-in prevents `systemd-networkd-wait-online` from blocking boot
    /// on the socket_vmnet (lima0) interface when the gateway segment is not yet
    /// bridged. Without it, first boot can exceed START_VM_TIMEOUT (300 s) and
    /// `create` rolls back with a confusing timeout.
    #[test]
    fn macos_template_has_wait_online_any_dropin() {
        let mgr = macos_mgr();
        let id = SessionId::parse("550e8400e29b").unwrap();
        let config = SessionConfig::default();
        let template = mgr.generate_template(&id, &config, None, Some(0));
        assert!(
            template.contains("step=wait-online"),
            "macOS template must include the wait-online provision step"
        );
        assert!(
            template.contains("systemd-networkd-wait-online.service.d"),
            "macOS template must install a systemd-networkd-wait-online drop-in directory"
        );
        assert!(
            template.contains("--any"),
            "macOS template wait-online drop-in must pass --any to avoid blocking on all interfaces"
        );
        assert!(
            template.contains("sandbox-any.conf"),
            "macOS template must install the sandbox-any.conf drop-in file"
        );
    }

    // -- verify_restrict_on negative tests -----------------------------------
    //
    // These tests confirm that `LimaManager::verify_restrict_on` fails closed:
    // a missing or wrong marker causes `Err`, ensuring the daemon can never
    // mark a session Running without restrict=on confirmed.
    //
    // The `DirectLimaExecutor` (via `SetuidHelperExecutor` on Linux, the direct
    // marker-file read on macOS via `LimaOp::RestrictOnVerify`) reads the wrapper
    // marker from the LIMA_HOME on the filesystem — making hermetic tempdir
    // testing possible without a real QEMU process.

    fn make_test_manager_in_tempdir(tmpdir: &std::path::Path) -> LimaManager {
        use crate::test_support::direct_executor::DirectLimaExecutor;
        LimaManager::new(
            tmpdir.to_path_buf(),
            DirectLimaExecutor::arc(),
            nix::unistd::Uid::current().as_raw(),
            "sandbox-base".to_string(),
            "test-pool".to_string(),
            true, // is_macos
        )
    }

    /// verify_restrict_on must return Err when the wrapper marker file is absent.
    ///
    /// A missing marker means the qemu-wrapper did not run or failed, and the
    /// daemon must refuse to mark the session Running. Any weakening of this
    /// check would be a security regression — the test failing means the egress
    /// promise is broken.
    ///
    /// Uses a session ID that is unlikely to exist in the system LIMA_HOME so
    /// the test reliably sees an absent marker on macOS (where the executor reads
    /// from operator_lima_home).
    #[test]
    fn verify_restrict_on_fails_closed_when_marker_absent() {
        // Session ID chosen to be unique per this test — avoid the IDs used by
        // other verify_restrict_on tests that write to operator_lima_home.
        let id_str = "aabbccddee00";
        let id = SessionId::parse(id_str).unwrap();

        // Ensure the system LIMA_HOME does NOT have a marker for this session ID
        // (could exist from a crashed previous test run — clean it up).
        let op_uid = nix::unistd::Uid::current().as_raw();
        let system_vm_dir = operator_lima_home(op_uid).join(format!("sandbox-{id_str}"));
        let system_marker = system_vm_dir.join("sandboxd-restrict-marker");
        let _ = std::fs::remove_file(&system_marker);

        let tmpdir = std::env::temp_dir().join("test_verify_restrict_on_no_marker_mgr");
        let _ = std::fs::remove_dir_all(&tmpdir);
        std::fs::create_dir_all(&tmpdir).expect("failed to create tmpdir");

        let mgr = make_test_manager_in_tempdir(&tmpdir);
        // No marker file exists in tmpdir or operator_lima_home — simulates wrapper never running.
        let result = mgr.verify_restrict_on(&id);
        assert!(
            result.is_err(),
            "verify_restrict_on must return Err when the marker file is absent \
             (the session must NOT be marked Running without restrict=on confirmed)"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("restrict") || msg.contains("marker"),
            "error message must mention 'restrict' or 'marker' for operator diagnostics; got: {msg}"
        );

        let _ = std::fs::remove_dir_all(&tmpdir);
    }

    /// verify_restrict_on must return Err when the marker exists but lacks restrict=on.
    ///
    /// A marker written by a buggy or tampered wrapper that does not contain
    /// `restrict=on` must not pass verification — the daemon must tear down.
    ///
    /// Uses a distinct session ID from the positive test to avoid cross-test
    /// state pollution (on macOS the executor reads from operator_lima_home,
    /// not the test tmpdir).
    #[test]
    fn verify_restrict_on_fails_closed_when_marker_has_wrong_content() {
        use std::io::Write;
        // Distinct from the positive-test session ID to avoid cross-test pollution.
        let id_str = "112233445566";
        let session_id = SessionId::parse(id_str).unwrap();

        // On macOS the executor reads from operator_lima_home(op_uid).
        // Write the wrong-content marker there.
        let op_uid = nix::unistd::Uid::current().as_raw();
        let system_lima_home = operator_lima_home(op_uid);
        let vm_dir_system = system_lima_home.join(format!("sandbox-{id_str}"));
        std::fs::create_dir_all(&vm_dir_system).expect("failed to create vm dir");
        let marker_system = vm_dir_system.join("sandboxd-restrict-marker");
        let mut f = std::fs::File::create(&marker_system).unwrap();
        writeln!(f, "-netdev user,id=net0,hostfwd=tcp::60022-:22").unwrap(); // NO restrict=on
        drop(f);

        // Also write to tmpdir for the Linux direct-read path (LimaManager.base_dir).
        let tmpdir = std::env::temp_dir().join("test_verify_restrict_on_wrong_content_mgr");
        let vm_dir_tmp = tmpdir.join(format!("sandbox-{id_str}"));
        std::fs::create_dir_all(&vm_dir_tmp).expect("failed to create vm dir in tmpdir");
        let marker_tmp = vm_dir_tmp.join("sandboxd-restrict-marker");
        let mut f2 = std::fs::File::create(&marker_tmp).unwrap();
        writeln!(f2, "-netdev user,id=net0,hostfwd=tcp::60022-:22").unwrap(); // NO restrict=on
        drop(f2);

        let mgr = make_test_manager_in_tempdir(&tmpdir);
        let result = mgr.verify_restrict_on(&session_id);

        // Cleanup before asserting so a panic doesn't leave stale markers.
        let _ = std::fs::remove_dir_all(&vm_dir_system);
        let _ = std::fs::remove_dir_all(&tmpdir);

        assert!(
            result.is_err(),
            "verify_restrict_on must return Err when marker does not contain 'restrict=on'"
        );
    }

    /// verify_restrict_on must return Ok when the marker contains restrict=on.
    ///
    /// Belt-and-suspenders: the positive path also needs a test so we can
    /// detect any future regression where the success path stops working.
    ///
    /// On macOS the executor resolves the marker via `operator_lima_home(op_uid)`
    /// (the broker / DirectLimaExecutor both derive the path from the current uid),
    /// so we write the marker to that path in this test rather than a tmpdir.
    /// On Linux the manager reads `self.base_dir` directly, so the tmpdir is used.
    #[test]
    fn verify_restrict_on_succeeds_when_marker_confirms_restrict_on() {
        use std::io::Write;
        let id_str = "aabbccddeeff";
        let session_id = SessionId::parse(id_str).unwrap();

        // The marker path the executor reads — on macOS this is derived from
        // `operator_lima_home(current_uid)`, on Linux from `self.base_dir`.
        // Build both and pick the one the executor will actually use.
        let op_uid = nix::unistd::Uid::current().as_raw();
        let system_lima_home = operator_lima_home(op_uid);
        let vm_dir_system = system_lima_home.join(format!("sandbox-{id_str}"));
        std::fs::create_dir_all(&vm_dir_system)
            .expect("failed to create vm dir under system LIMA_HOME");
        let marker_system = vm_dir_system.join("sandboxd-restrict-marker");
        let mut f = std::fs::File::create(&marker_system).unwrap();
        writeln!(f, "-netdev user,id=net0,hostfwd=tcp::60022-:22,restrict=on").unwrap();
        drop(f);

        // The manager's base_dir is the tmpdir; on Linux it reads from there.
        // Also write the marker in the tmpdir for the Linux path.
        let tmpdir = std::env::temp_dir().join("test_verify_restrict_on_ok_mgr");
        let vm_dir_tmp = tmpdir.join(format!("sandbox-{id_str}"));
        std::fs::create_dir_all(&vm_dir_tmp).expect("failed to create vm dir in tmpdir");
        let marker_tmp = vm_dir_tmp.join("sandboxd-restrict-marker");
        let mut f2 = std::fs::File::create(&marker_tmp).unwrap();
        writeln!(
            f2,
            "-netdev user,id=net0,hostfwd=tcp::60022-:22,restrict=on"
        )
        .unwrap();
        drop(f2);

        let mgr = make_test_manager_in_tempdir(&tmpdir);
        let result = mgr.verify_restrict_on(&session_id);

        // Clean up both marker dirs to avoid polluting real LIMA_HOME.
        let _ = std::fs::remove_dir_all(&vm_dir_system);
        let _ = std::fs::remove_dir_all(&tmpdir);

        assert!(
            result.is_ok(),
            "verify_restrict_on must return Ok when marker contains 'restrict=on': {result:?}"
        );
    }
}
