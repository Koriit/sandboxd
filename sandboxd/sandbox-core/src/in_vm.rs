//! Typed operations that run *inside* the gateway Lima VM, and the seam that
//! executes them.
//!
//! # Why a seam, and why not the Docker one
//!
//! [`crate::docker`] already carries the daemon's requests to the Docker
//! daemon inside the gateway VM. These operations are the layer underneath:
//! they run against the VM itself — `limactl shell` to run a command as the
//! VM's login user, `limactl copy` to put a file in it. Once the VM belongs to
//! an operator rather than to the daemon account, the daemon can no more run
//! `limactl` against it than it can open its Docker socket, so the same
//! "ask rather than do" shape applies.
//!
//! It is a **separate** seam from the Docker one because the trust story is
//! different, not merely the program name. A `docker exec` enters a container
//! the product exists to contain. A `limactl shell` runs in the VM hosting
//! those containers, as a user with passwordless `sudo` — and one of the
//! operations below installs the nftables baseline that is the egress promise.
//! Reading the two enums separately is what makes "what can the daemon ask for
//! in here?" a question with two short answers instead of one long one.
//!
//! # The set is closed
//!
//! [`InVmOp`] carries no argv, no shell string, no command name and no path to
//! run something on. The one path-shaped value in it — a session identifier —
//! is validated on the executing side before it is joined onto a constant
//! root, and the one large value — an nftables ruleset — is content delivered
//! on stdin to a parser, never a command line. Adding a variant that took a
//! command would make every other variant decorative, because the destination
//! is a host where `sudo` needs no password.
//!
//! The remaining values are a container pid and a gateway address, typed as
//! `u32` and `Ipv4Addr` so that neither can render an argv word that is a flag,
//! a path, or anything a parser might read as syntax. That is a claim about
//! their *shape*, and it is the only claim this side of the seam can make about
//! them: whether the gateway address is the correct one for that container is
//! decided in the helper, from inside the namespace it enters, because a caller
//! who runs the helper directly never passes through here at all.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sandbox_invm_argv::lite_stage::LiteStageFile;

use crate::error::SandboxError;

/// The closed set of in-VM operations the daemon may request.
///
/// In-process representation — the wire-serializable counterpart lives in the
/// broker protocol crate and is mapped from this one by an exhaustive match,
/// so a variant added here without a wire mapping is a compile error rather
/// than a silent gap.
///
/// Owned rather than borrowed, for the same reason [`crate::docker::DockerOp`]
/// is: every caller hands an op to `spawn_blocking`, which requires
/// `'static`.
#[derive(Debug, Clone)]
pub enum InVmOp {
    // -- VM readiness and topology -------------------------------------------
    /// Is the VM's own Docker daemon answering yet?
    ///
    /// The authoritative readiness signal, and deliberately taken from inside
    /// the VM: the host-side forwarded socket can lag the daemon by seconds
    /// after a cold boot, so a host-side probe alone cannot distinguish "not
    /// started" from "not forwarded yet".
    DockerReady,
    /// The guest's own view of its NICs, as JSON.
    ///
    /// Verification input only. The slot→NIC map is built host-side from the
    /// declared slot set; this is what it is checked against.
    LinkShowJson,

    // -- Egress plane --------------------------------------------------------
    /// Apply the gateway VM's `eth0` default-drop nftables baseline.
    ///
    /// `ruleset` is the policy itself, delivered to `nft -f -` on standard
    /// input where nothing parses it as a command line. See
    /// [`sandbox_invm_argv::vm::apply_nft_baseline_argv`] for why stdin rather
    /// than an argv or a file, and what each of those alternatives got wrong.
    ///
    /// A failure here must fail the caller. What goes missing is the bound on
    /// the gateway VM's *own host-namespace* egress — the table has no
    /// `forward` chain and does not govern session traffic, which the
    /// per-session `sandbox_dnat`/`sandbox_policy` ruleset in each gateway
    /// container's netns judges instead. So a failure removes no constraint on
    /// session egress, and is no evidence about session egress in either
    /// direction. What it loses is the blast-radius bound on a component that
    /// escapes a container netns into the VM. Two paths install
    /// that table and nothing at runtime re-checks it, so a failure logged and
    /// swallowed here leaves a running VM without the bound and nothing that
    /// would notice. `sandbox_core::gateway_lima`'s `apply_eth0_nft_policy`
    /// spells out both halves.
    ApplyNftBaseline { ruleset: String },

    // -- Route-helper provisioning -------------------------------------------
    /// Is `sandbox-route-helper` installed in the VM **with its
    /// capabilities**?
    ///
    /// Returns the executing side's `getcap` output for the caller to judge,
    /// rather than judging in the VM. Checking the capabilities and not merely
    /// the executable bit is the point: a binary whose `setcap` failed passes
    /// an executable check and then fails at route-install time.
    RouteHelperProbe,
    /// Create the root-owned directory the helper is installed into.
    RouteHelperMakeInstallDir,
    /// Copy the pre-staged Linux/aarch64 helper binary into the VM.
    ///
    /// Carries no source path. The binary is named by
    /// [`sandbox_invm_argv::route_helper::HOST_BINARY_FILENAME`] and resolved
    /// against the executing side's **own** LIMA_HOME — the same discipline
    /// `ImageLoad` uses for staged tarballs, and for the same reason: a source
    /// path on an op is a request to copy an arbitrary file into a VM that is
    /// about to give it `cap_net_admin`.
    RouteHelperStage,
    /// Move the staged copy into its root-owned final location.
    RouteHelperInstall,
    /// Mark the installed helper executable and give it its capabilities.
    RouteHelperSetcap,

    // -- Lite-session file staging -------------------------------------------
    /// Create a session's staging directory inside the VM.
    LiteStageCreate { session_id: String },
    /// Put one of the four enumerated provisioning files into a session's
    /// staging directory.
    ///
    /// The **content** travels, not a path. The daemon writes these files into
    /// its own session directory at mode 0700, which the operator's agent
    /// cannot read at all once the VM is the operator's — so a source path
    /// would not merely be a weaker control, it would not work. What the
    /// variant names is which of four files this is; the executing side
    /// resolves the basename and the mode from that.
    LiteStageWrite {
        session_id: String,
        file: LiteStageFile,
        body: String,
    },
    /// Remove a session's staging directory from the VM.
    LiteStageRemove { session_id: String },

    // -- Container routing ---------------------------------------------------
    /// Install a sandbox container's default route, by running the provisioned
    /// `sandbox-route-helper` inside the gateway VM.
    ///
    /// **This op is what puts a sandbox's traffic in front of the gateway's
    /// policy.** What decides where that traffic may go is the per-session
    /// `sandbox_dnat`/`sandbox_policy` ruleset in the gateway container's own
    /// netns; this decides whether the traffic arrives there to be judged at
    /// all. [`Self::ApplyNftBaseline`] is a different bound — the gateway VM's
    /// own host-namespace egress — and does not govern session traffic. A
    /// wrong value here does not fail loudly: it produces a container whose
    /// packets leave by some other route, with nothing inside the sandbox able
    /// to tell.
    ///
    /// The two values are typed rather than stringly for that reason: a `u32`
    /// pid cannot render a leading `-` and so can never be read as a flag by
    /// the helper's parser, and an `Ipv4Addr` cannot be a hostname, a path, or
    /// anything carrying a shell metacharacter.
    ///
    /// What the types cannot establish is that `gateway_ip` is the *right*
    /// gateway for `container_pid`. Nothing on this side of the seam can:
    /// a process inside the VM may invoke the helper directly, never passing
    /// through the daemon, the broker, or the agent's validation. The control
    /// that survives that path is inside the helper — it enters the container's
    /// network namespace and checks the address against what the kernel reports
    /// there. See `sandbox-route-helper`'s `containment` module.
    InstallContainerRoute {
        container_pid: u32,
        gateway_ip: std::net::Ipv4Addr,
    },
}

impl InVmOp {
    /// The command to run **inside** the VM, as a sequence of argv.
    ///
    /// Most ops are one argv; the two that were `&&` chains before they were
    /// typed are two. Both sides of the seam render an op through this
    /// function, so the daemon's idea of an op and the agent's cannot drift.
    ///
    /// Returns `None` for [`InVmOp::RouteHelperStage`] and
    /// [`InVmOp::LiteStageWrite`], which are file transfers rather than
    /// commands — see [`Self::transfer`].
    pub fn shell_steps(&self) -> Option<Vec<Vec<String>>> {
        use sandbox_invm_argv::{lite_stage, route_helper, vm};

        let steps = match self {
            InVmOp::DockerReady => vec![vm::docker_ready_argv()],
            InVmOp::LinkShowJson => vec![vm::link_show_json_argv()],
            InVmOp::ApplyNftBaseline { .. } => vec![vm::apply_nft_baseline_argv()],
            InVmOp::RouteHelperProbe => vec![
                route_helper::probe_executable_argv(),
                route_helper::probe_caps_argv(),
            ],
            InVmOp::RouteHelperMakeInstallDir => vec![route_helper::make_install_dir_argv()],
            InVmOp::RouteHelperInstall => route_helper::install_argv(),
            InVmOp::RouteHelperSetcap => {
                vec![route_helper::chmod_argv(), route_helper::setcap_argv()]
            }
            InVmOp::LiteStageCreate { session_id } => {
                vec![lite_stage::mkdir_argv(&lite_stage::stage_dir(session_id))]
            }
            InVmOp::LiteStageRemove { session_id } => {
                vec![lite_stage::rm_argv(&lite_stage::stage_dir(session_id))]
            }
            InVmOp::InstallContainerRoute {
                container_pid,
                gateway_ip,
            } => vec![route_helper::install_container_route_argv(
                *container_pid,
                *gateway_ip,
            )],
            InVmOp::RouteHelperStage | InVmOp::LiteStageWrite { .. } => return None,
        };
        Some(steps)
    }

    /// The file transfer this op performs, if it is one.
    ///
    /// The source is described rather than named: [`InVmTransfer`] says which
    /// file, and the executing side resolves it against its own LIMA_HOME.
    pub fn transfer(&self) -> Option<InVmTransfer> {
        match self {
            InVmOp::RouteHelperStage => Some(InVmTransfer::RouteHelperBinary),
            InVmOp::LiteStageWrite {
                session_id,
                file,
                body,
            } => Some(InVmTransfer::LiteStageFile {
                session_id: session_id.clone(),
                file: *file,
                body: body.clone(),
            }),
            _ => None,
        }
    }

    /// The artifact this op writes to the child's standard input, if any.
    ///
    /// Only the nftables baseline has one, and that it is the only one is
    /// worth keeping true: stdin on a `limactl shell` is a channel into a VM
    /// with passwordless `sudo`, and the single reader on the far end of it
    /// today is an `nft` parser.
    pub fn stdin_body(&self) -> Option<&str> {
        match self {
            InVmOp::ApplyNftBaseline { ruleset } => Some(ruleset),
            _ => None,
        }
    }

    /// A stable label for logs, error messages and timeouts.
    pub fn label(&self) -> &'static str {
        match self {
            InVmOp::DockerReady => "in-vm: docker readiness",
            InVmOp::LinkShowJson => "in-vm: link show",
            InVmOp::ApplyNftBaseline { .. } => "in-vm: apply nft baseline",
            InVmOp::RouteHelperProbe => "in-vm: route-helper probe",
            InVmOp::RouteHelperMakeInstallDir => "in-vm: route-helper install dir",
            InVmOp::RouteHelperStage => "in-vm: route-helper stage",
            InVmOp::RouteHelperInstall => "in-vm: route-helper install",
            InVmOp::RouteHelperSetcap => "in-vm: route-helper setcap",
            InVmOp::LiteStageCreate { .. } => "in-vm: lite stage create",
            InVmOp::LiteStageWrite { .. } => "in-vm: lite stage write",
            InVmOp::LiteStageRemove { .. } => "in-vm: lite stage remove",
            InVmOp::InstallContainerRoute { .. } => "in-vm: install container route",
        }
    }
}

/// A file this seam puts into the VM, described rather than named.
#[derive(Debug, Clone)]
pub enum InVmTransfer {
    /// The pre-staged Linux/aarch64 `sandbox-route-helper`, taken from the
    /// executing side's own LIMA_HOME.
    RouteHelperBinary,
    /// One of a session's four provisioning files, carried as content.
    LiteStageFile {
        session_id: String,
        file: LiteStageFile,
        body: String,
    },
}

/// Runs typed in-VM operations somewhere the caller may not be able to reach
/// directly.
///
/// One-shot and blocking, matching [`crate::lima::LimaExecutor::run`] and
/// [`crate::docker::DockerExecutor::run`]: callers in async contexts wrap it
/// in `spawn_blocking`. There is no streaming counterpart — none of these
/// operations holds a channel open, and the long-lived streams that do are
/// the Docker seam's.
pub trait InVmExecutor: Send + Sync {
    /// Run one op as `op_uid` and return the captured output.
    ///
    /// For a multi-step op the output is the **last** step's; a non-zero step
    /// short-circuits and its output is returned, so a caller reading the
    /// status sees the step that failed.
    fn run(
        &self,
        op_uid: u32,
        op: InVmOp,
        timeout: Duration,
        label: &str,
    ) -> Result<std::process::Output, SandboxError>;
}

/// Where a call site's in-VM operations go.
///
/// Carries the operator uid alongside the executor so a call site names an
/// operation and nothing else. Whether the executor runs `limactl` itself
/// (the VM is the daemon's own) or forwards the op to the operator's agent is
/// the executor's business.
#[derive(Clone)]
pub struct InVmRoute {
    op_uid: u32,
    executor: Arc<dyn InVmExecutor>,
}

impl std::fmt::Debug for InVmRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InVmRoute {{ op_uid: {} }}", self.op_uid)
    }
}

impl InVmRoute {
    /// Route in-VM operations for `op_uid` through `executor`.
    pub fn new(op_uid: u32, executor: Arc<dyn InVmExecutor>) -> Self {
        Self { op_uid, executor }
    }

    /// The operator uid this route runs as.
    pub fn op_uid(&self) -> u32 {
        self.op_uid
    }

    /// Run one typed op on this route.
    ///
    /// Blocking; callers in async contexts wrap this in `spawn_blocking` per
    /// the project's `std::process::Command` convention.
    pub fn run(
        &self,
        op: InVmOp,
        timeout: Duration,
        label: &str,
    ) -> Result<std::process::Output, SandboxError> {
        self.executor.run(self.op_uid, op, timeout, label)
    }
}

/// Runs typed in-VM ops against a Lima instance this process can drive itself.
///
/// The executor for the degenerate case where the VM is the daemon's own —
/// "act as the operator" and "act as yourself" are the same instruction. It is
/// the in-VM counterpart of [`crate::docker::LocalSocketDockerExecutor`], and
/// it is the seam's implementation rather than a bypass of it: the `limactl`
/// invocations below are reached only through [`InVmExecutor::run`], and every
/// argv word in them comes from `sandbox-invm-argv`.
pub struct LocalLimactlInVmExecutor {
    /// The Lima instance these operations run against.
    instance: String,
    /// This process's own LIMA_HOME — the root both the `limactl` environment
    /// and the transfer sources are resolved against.
    lima_home: PathBuf,
}

impl LocalLimactlInVmExecutor {
    /// Drive `instance`, resolving `limactl`'s home and every transfer source
    /// against `lima_home`.
    pub fn new(instance: impl Into<String>, lima_home: impl Into<PathBuf>) -> Self {
        Self {
            instance: instance.into(),
            lima_home: lima_home.into(),
        }
    }

    /// Minimal-reconstruction environment for a `limactl` invocation.
    ///
    /// Mirrors the discipline in the daemon's `run_limactl_direct`: clear the
    /// inherited environment and put back only what `limactl` needs. A stale
    /// `LIMA_HOME` in the daemon's own environment would otherwise point these
    /// operations at a different Lima tree entirely.
    fn apply_env(&self, cmd: &mut std::process::Command) {
        let lima_home = self.lima_home.to_string_lossy().into_owned();
        let current_path = std::env::var("PATH").unwrap_or_default();
        let path_value = format!("/opt/homebrew/bin:/usr/local/bin:{current_path}");
        let home = std::env::var("HOME").unwrap_or_default();
        if home.is_empty() {
            tracing::warn!(
                "in-vm op: HOME is unset; limactl may fail to locate its config directory"
            );
        }
        cmd.env_clear()
            .env("LIMA_HOME", lima_home)
            .env("PATH", path_value)
            .env("HOME", home)
            .env("TERM", "dumb");
    }

    fn limactl(&self, argv: &[String]) -> std::process::Command {
        let mut cmd = std::process::Command::new(sandbox_invm_argv::LIMACTL_BIN);
        self.apply_env(&mut cmd);
        cmd.args(argv);
        cmd
    }

    /// Materialise a transfer's source inside this process's own LIMA_HOME and
    /// return its path.
    ///
    /// The route-helper binary is already there. A lite-session file arrives
    /// as content, so it is written out — at the mode its variant declares,
    /// because `limactl copy` preserves the source's mode and that mode is
    /// what the container sees.
    fn transfer_source(&self, transfer: &InVmTransfer) -> Result<PathBuf, SandboxError> {
        use sandbox_invm_argv::lite_stage;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        match transfer {
            InVmTransfer::RouteHelperBinary => Ok(self
                .lima_home
                .join(sandbox_invm_argv::route_helper::HOST_BINARY_FILENAME)),
            InVmTransfer::LiteStageFile {
                session_id,
                file,
                body,
            } => {
                let path = self
                    .lima_home
                    .join(lite_stage::transfer_basename(session_id, *file));
                let mut f = std::fs::File::create(&path).map_err(|e| {
                    SandboxError::Internal(format!(
                        "in-vm transfer: failed to create {}: {e}",
                        path.display()
                    ))
                })?;
                f.write_all(body.as_bytes()).map_err(|e| {
                    SandboxError::Internal(format!(
                        "in-vm transfer: failed to write {}: {e}",
                        path.display()
                    ))
                })?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(file.mode()))
                    .map_err(|e| {
                        SandboxError::Internal(format!(
                            "in-vm transfer: failed to chmod {:o} on {}: {e}",
                            file.mode(),
                            path.display()
                        ))
                    })?;
                Ok(path)
            }
        }
    }

    /// The in-VM destination for a transfer.
    fn transfer_destination(transfer: &InVmTransfer) -> String {
        use sandbox_invm_argv::{lite_stage, route_helper};
        match transfer {
            InVmTransfer::RouteHelperBinary => route_helper::STAGED_PATH_IN_VM.to_string(),
            InVmTransfer::LiteStageFile {
                session_id, file, ..
            } => lite_stage::file_path(&lite_stage::stage_dir(session_id), *file),
        }
    }
}

impl InVmExecutor for LocalLimactlInVmExecutor {
    fn run(
        &self,
        _op_uid: u32,
        op: InVmOp,
        timeout: Duration,
        label: &str,
    ) -> Result<std::process::Output, SandboxError> {
        if let Some(transfer) = op.transfer() {
            let src = self.transfer_source(&transfer)?;
            let dst = Self::transfer_destination(&transfer);
            let argv = sandbox_invm_argv::copy_argv(&src.to_string_lossy(), &self.instance, &dst);
            let mut cmd = self.limactl(&argv);
            let output = crate::process::run_with_timeout(&mut cmd, timeout, label)?;
            // A lite-session source is a scratch copy of content the op
            // carried; the route-helper binary is not ours to remove.
            if matches!(transfer, InVmTransfer::LiteStageFile { .. }) {
                let _ = std::fs::remove_file(&src);
            }
            return Ok(output);
        }

        let steps = op.shell_steps().ok_or_else(|| {
            SandboxError::Internal(format!("{label}: op is neither a command nor a transfer"))
        })?;
        let body = op.stdin_body().map(|b| b.to_string());

        let mut last: Option<std::process::Output> = None;
        for step in &steps {
            let argv = sandbox_invm_argv::shell_argv(&self.instance, step);
            let mut cmd = self.limactl(&argv);
            let output = match &body {
                Some(b) => {
                    crate::process::run_with_timeout_stdin(&mut cmd, b.as_bytes(), timeout, label)?
                }
                None => crate::process::run_with_timeout(&mut cmd, timeout, label)?,
            };
            let failed = !output.status.success();
            last = Some(output);
            if failed {
                break;
            }
        }

        last.ok_or_else(|| SandboxError::Internal(format!("{label}: op produced no steps")))
    }
}

/// Whether `getcap` output from [`InVmOp::RouteHelperProbe`] shows the helper
/// carrying **every** capability [`InVmOp::RouteHelperSetcap`] grants it.
///
/// Kept next to the op rather than at the call site because it is the other
/// half of the probe: the op deliberately reports rather than decides, and
/// this is the deciding.
///
/// The whole set is required, not one member of it. A binary carrying only
/// some of them passes `test -x`, and a probe satisfied by one of them then
/// reports "already installed" — so provisioning is skipped and the missing
/// capability surfaces much later as `EPERM` at `setns`, which is the late,
/// confusing failure the probe exists to prevent.
///
/// The required names are read off the same constant the `setcap` step
/// renders, so the two cannot drift: a capability added to the install is one
/// this immediately starts requiring.
///
/// Matching is per-name and order-independent, because `getcap` does not echo
/// back what `setcap` was given — it prints the names in the kernel's own
/// order after the file path, so the set installed here comes back as
/// `cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip`.
///
/// What this does **not** check is which capability sets each name sits in. A
/// file carrying all three names under the wrong flags would pass here and
/// still fail at route-install time; catching the install that left the
/// capabilities off altogether is what this is for.
pub fn route_helper_probe_says_installed(output: &std::process::Output) -> bool {
    if !output.status.success() {
        return false;
    }
    let mut required = required_route_helper_capabilities().peekable();
    if required.peek().is_none() {
        // `all` over an empty iterator is vacuously true, which would turn
        // this into an unconditional "installed". Nothing can currently
        // produce an empty set; this is what keeps that unable to matter.
        return false;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    required.all(|cap| getcap_output_names(&stdout, cap))
}

/// The capability names the in-VM `setcap` step asks for.
///
/// Parsed from the constant that renders the install rather than restated
/// beside it — a second list is a second thing to keep in agreement, and the
/// one that drifts is the one nothing executes.
fn required_route_helper_capabilities() -> impl Iterator<Item = &'static str> {
    sandbox_invm_argv::route_helper::CAPABILITIES
        .split(['=', '+', '-'])
        .next()
        .unwrap_or("")
        .split(',')
        .filter(|name| !name.is_empty())
}

/// Whether `getcap` output names `cap` as a whole token.
///
/// Tokenised rather than substring-matched: the output carries the installed
/// file's path on the same line as the names, and the punctuation separating
/// the names from the flag letters is not something this side should have to
/// predict.
fn getcap_output_names(getcap_output: &str, cap: &str) -> bool {
    getcap_output
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|token| token == cap)
}

/// The path a `limactl copy` of the route helper takes its source from, given
/// a LIMA_HOME. Exposed so the caller can check the binary is present before
/// asking for a transfer that would fail.
pub fn route_helper_host_binary(lima_home: &Path) -> PathBuf {
    lima_home.join(sandbox_invm_argv::route_helper::HOST_BINARY_FILENAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every op is either a command or a transfer, and never both. A variant
    /// that is neither would be silently unreachable; one that is both would
    /// have two executors disagreeing about what it means.
    #[test]
    fn every_op_is_exactly_one_of_a_command_or_a_transfer() {
        for op in all_ops() {
            let is_command = op.shell_steps().is_some();
            let is_transfer = op.transfer().is_some();
            assert!(
                is_command ^ is_transfer,
                "{:?} is {}",
                op,
                if is_command {
                    "both a command and a transfer"
                } else {
                    "neither a command nor a transfer"
                }
            );
        }
    }

    /// The no-shell rule, asserted over the whole op set rather than per
    /// builder: this is the property `protocol.rs`'s NON-FEATURES block names,
    /// and the one every op in this set used to violate.
    #[test]
    fn no_op_renders_a_shell_invocation() {
        for op in all_ops() {
            let Some(steps) = op.shell_steps() else {
                continue;
            };
            for step in steps {
                for word in &step {
                    assert!(
                        !matches!(word.as_str(), "sh" | "bash" | "zsh" | "dash" | "-c"),
                        "{op:?} renders {step:?}, which invokes a shell"
                    );
                }
            }
        }
    }

    /// Only the nftables baseline feeds stdin. Stdin on a `limactl shell` is a
    /// pipe into a VM with passwordless sudo; keeping the reader list at one
    /// parser is the whole control.
    #[test]
    fn only_the_nft_baseline_carries_a_stdin_body() {
        for op in all_ops() {
            let expected = matches!(op, InVmOp::ApplyNftBaseline { .. });
            assert_eq!(
                op.stdin_body().is_some(),
                expected,
                "{op:?} disagrees about carrying a stdin body"
            );
        }
    }

    /// An op that puts a payload on stdin must never run a `sudo` that could
    /// prompt.
    ///
    /// The two facts are only dangerous together, which is why the invariant
    /// is stated over the pair rather than over either one. `sudo` reads a
    /// password from **the command's stdin**, and for an op carrying a body
    /// that stdin is the payload — so an interactive `sudo` does not hang
    /// waiting for a human, it silently consumes the payload as a credential
    /// attempt and fails. For the one op in this set that carries a body, the
    /// payload is the egress baseline.
    ///
    /// Asserted across the whole op set, not at the one site that has the
    /// combination today: the failure reappears the moment someone adds a
    /// stdin-carrying op without knowing why `-n` is on the existing one, and
    /// that is exactly the person this test is for. `all_ops()` carries a
    /// count assertion, so a new variant cannot dodge it by being absent
    /// either.
    #[test]
    fn an_op_that_carries_a_payload_on_stdin_never_runs_a_sudo_that_could_prompt() {
        for op in all_ops() {
            if op.stdin_body().is_none() {
                continue;
            }
            let steps = op
                .shell_steps()
                .expect("an op carrying a stdin body is a command, not a transfer");
            for step in steps {
                if step.first().map(String::as_str) != Some("sudo") {
                    continue;
                }
                assert_eq!(
                    step.get(1).map(String::as_str),
                    Some("-n"),
                    "{op:?} carries a stdin body and renders {step:?}, whose sudo may \
                     prompt — it would read the payload as the password"
                );
            }
        }
    }

    /// The ruleset reaches the op unmodified. It is policy: a transformation
    /// anywhere between the generator and `nft` is a policy change nobody
    /// wrote.
    #[test]
    fn the_nft_baseline_carries_the_ruleset_verbatim() {
        let ruleset =
            "table inet gw {\n  chain out { type filter hook output priority 0; drop }\n}\n";
        let op = InVmOp::ApplyNftBaseline {
            ruleset: ruleset.to_string(),
        };
        assert_eq!(op.stdin_body(), Some(ruleset));
        assert_eq!(
            op.shell_steps().unwrap(),
            vec![vec!["sudo", "-n", "nft", "-f", "-"]]
        );
    }

    #[test]
    fn the_lite_stage_ops_address_the_session_directory() {
        let create = InVmOp::LiteStageCreate {
            session_id: "sess1".to_string(),
        };
        assert_eq!(
            create.shell_steps().unwrap(),
            vec![vec!["mkdir", "-p", "/tmp/sandbox-lite/sess1"]]
        );
        let remove = InVmOp::LiteStageRemove {
            session_id: "sess1".to_string(),
        };
        assert_eq!(
            remove.shell_steps().unwrap(),
            vec![vec!["rm", "-rf", "/tmp/sandbox-lite/sess1"]]
        );
    }

    #[test]
    fn the_route_helper_probe_reports_rather_than_decides() {
        let steps = InVmOp::RouteHelperProbe.shell_steps().unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0][0], "test");
        assert_eq!(steps[1][0], "getcap");
        // Nothing in the rendered command matches or greps.
        for step in steps {
            assert!(!step.iter().any(|w| w == "grep"));
        }
    }

    /// A successful `getcap` run whose stdout is `stdout`.
    fn probe_output(stdout: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn probe_output_is_judged_on_the_capability_not_the_exit_status_alone() {
        let ok = probe_output(
            "/usr/local/libexec/sandboxd/sandbox-route-helper cap_net_admin,cap_sys_admin,cap_sys_ptrace=eip\n",
        );
        assert!(route_helper_probe_says_installed(&ok));

        // Exit zero, but the capabilities were stripped: the binary runs and
        // then fails at route-install time. This is the case the probe exists
        // for.
        let stripped = probe_output("");
        assert!(!route_helper_probe_says_installed(&stripped));
    }

    /// What the probe demands is what the install grants, read off the one
    /// constant that renders the install.
    #[test]
    fn the_required_capabilities_are_the_ones_the_install_grants() {
        let mut required: Vec<&str> = required_route_helper_capabilities().collect();
        required.sort_unstable();
        assert_eq!(
            required,
            vec!["cap_net_admin", "cap_sys_admin", "cap_sys_ptrace"],
            "derived from {}",
            sandbox_invm_argv::route_helper::CAPABILITIES
        );
    }

    /// Every incomplete set is rejected, not just the empty one.
    ///
    /// A binary carrying some of the capabilities is the case that motivates
    /// this: it passes `test -x`, it names `cap_net_admin`, and a probe
    /// satisfied by that reports "already installed" — so provisioning never
    /// repairs it and the missing capability surfaces as `EPERM` at `setns`,
    /// far from the decision that caused it.
    #[test]
    fn every_proper_subset_of_the_installed_capabilities_is_rejected() {
        let required: Vec<&str> = required_route_helper_capabilities().collect();
        assert_eq!(required.len(), 3, "the subset enumeration below assumes 3");
        // 0..7 is every subset except the full one.
        for bits in 0u8..(1 << 3) - 1 {
            let present: Vec<&str> = required
                .iter()
                .enumerate()
                .filter(|(i, _)| bits & (1 << i) != 0)
                .map(|(_, name)| *name)
                .collect();
            let stdout = format!(
                "/usr/local/libexec/sandboxd/sandbox-route-helper {}=eip\n",
                present.join(",")
            );
            assert!(
                !route_helper_probe_says_installed(&probe_output(&stdout)),
                "accepted a binary carrying only {present:?}"
            );
        }
    }

    /// The probe reads names, not layout.
    ///
    /// `getcap` does not echo the string `setcap` was given: the set installed
    /// here is asked for as `cap_net_admin,cap_sys_admin,cap_sys_ptrace` and
    /// comes back reordered, because the names print in the kernel's order.
    /// The remaining cases are here to say that the punctuation around them is
    /// not something this side has to predict — they are a claim about the
    /// parser, not about what any particular `getcap` release emits.
    #[test]
    fn the_probe_reads_names_rather_than_layout() {
        for stdout in [
            // Measured on libcap 2.66: reordered relative to the setcap argument.
            "/usr/local/libexec/sandboxd/sandbox-route-helper cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip\n",
            "/usr/local/libexec/sandboxd/sandbox-route-helper = cap_net_admin,cap_sys_ptrace,cap_sys_admin+eip\n",
            "/usr/local/libexec/sandboxd/sandbox-route-helper cap_sys_admin=eip cap_net_admin=eip cap_sys_ptrace=eip\n",
        ] {
            assert!(
                route_helper_probe_says_installed(&probe_output(stdout)),
                "rejected {stdout:?}"
            );
        }
    }

    /// A name is matched whole. `cap_net_admin_wrapper` is not `cap_net_admin`,
    /// and the substring test that would say otherwise is the one this
    /// replaced.
    #[test]
    fn a_longer_name_containing_a_required_one_does_not_satisfy_it() {
        let stdout = "/usr/local/libexec/sandboxd/sandbox-route-helper \
             cap_net_admin_x,cap_sys_admin,cap_sys_ptrace=eip\n";
        assert!(!route_helper_probe_says_installed(&probe_output(stdout)));
    }

    /// A non-zero `getcap` still decides nothing on its own — but neither does
    /// stdout that would otherwise pass.
    #[test]
    fn a_failed_probe_run_is_not_installed_however_it_printed() {
        use std::os::unix::process::ExitStatusExt;
        let failed = std::process::Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: b"/usr/local/libexec/sandboxd/sandbox-route-helper cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip\n".to_vec(),
            stderr: Vec::new(),
        };
        assert!(!route_helper_probe_says_installed(&failed));
    }

    /// Neither transfer names a source path. What the op carries is which
    /// file, and — for the lite files — its content.
    #[test]
    fn transfers_describe_their_source_rather_than_naming_it() {
        assert!(matches!(
            InVmOp::RouteHelperStage.transfer(),
            Some(InVmTransfer::RouteHelperBinary)
        ));
        let write = InVmOp::LiteStageWrite {
            session_id: "sess1".to_string(),
            file: LiteStageFile::CertPem,
            body: "-----BEGIN CERTIFICATE-----\n".to_string(),
        };
        let Some(InVmTransfer::LiteStageFile { file, body, .. }) = write.transfer() else {
            panic!("expected a lite-stage transfer");
        };
        assert_eq!(file, LiteStageFile::CertPem);
        assert_eq!(body, "-----BEGIN CERTIFICATE-----\n");
    }

    #[test]
    fn transfer_destinations_land_where_the_binds_look() {
        assert_eq!(
            LocalLimactlInVmExecutor::transfer_destination(&InVmTransfer::RouteHelperBinary),
            "/tmp/sandbox-route-helper.staged"
        );
        assert_eq!(
            LocalLimactlInVmExecutor::transfer_destination(&InVmTransfer::LiteStageFile {
                session_id: "sess1".to_string(),
                file: LiteStageFile::AuthorizedKeys,
                body: String::new(),
            }),
            "/tmp/sandbox-lite/sess1/authorized_keys"
        );
    }

    /// A lite-session file is written at the mode its variant declares, not
    /// at whatever the process umask happens to be — `limactl copy` preserves
    /// the source mode, and the container reads the result as a non-owner.
    #[test]
    fn a_staged_lite_file_is_written_at_the_mode_its_variant_declares() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().expect("tempdir");
        let exec = LocalLimactlInVmExecutor::new("sandboxd-gateway", home.path());
        let src = exec
            .transfer_source(&InVmTransfer::LiteStageFile {
                session_id: "sess1".to_string(),
                file: LiteStageFile::Passwd,
                body: "sandbox:x:501:20:Sandbox guest user:/home/sandbox:/bin/bash\n".to_string(),
            })
            .expect("transfer source");

        let meta = std::fs::metadata(&src).expect("metadata");
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);
        assert_eq!(
            std::fs::read_to_string(&src).expect("read"),
            "sandbox:x:501:20:Sandbox guest user:/home/sandbox:/bin/bash\n"
        );
    }

    /// The route-helper source is resolved against the executing side's own
    /// LIMA_HOME, and is the enumerated filename.
    #[test]
    fn the_route_helper_source_is_the_named_file_in_the_running_sides_lima_home() {
        let home = tempfile::tempdir().expect("tempdir");
        let exec = LocalLimactlInVmExecutor::new("sandboxd-gateway", home.path());
        let src = exec
            .transfer_source(&InVmTransfer::RouteHelperBinary)
            .expect("transfer source");
        assert_eq!(src, home.path().join("sandbox-route-helper-linux-aarch64"));
    }

    /// Every op carries a distinct label. They appear in timeout and failure
    /// messages, where two ops sharing one is a diagnosis pointing at the
    /// wrong step.
    #[test]
    fn every_op_has_its_own_label() {
        let mut labels: Vec<&str> = all_ops().iter().map(|op| op.label()).collect();
        let before = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(before, labels.len(), "two ops share a label");
    }

    /// One instance of every variant. A new variant that is not added here
    /// escapes every property test above, so the count is asserted.
    fn all_ops() -> Vec<InVmOp> {
        let ops = vec![
            InVmOp::DockerReady,
            InVmOp::LinkShowJson,
            InVmOp::ApplyNftBaseline {
                ruleset: "table inet t {}\n".to_string(),
            },
            InVmOp::RouteHelperProbe,
            InVmOp::RouteHelperMakeInstallDir,
            InVmOp::RouteHelperStage,
            InVmOp::RouteHelperInstall,
            InVmOp::RouteHelperSetcap,
            InVmOp::LiteStageCreate {
                session_id: "sess1".to_string(),
            },
            InVmOp::LiteStageWrite {
                session_id: "sess1".to_string(),
                file: LiteStageFile::CertPem,
                body: "body".to_string(),
            },
            InVmOp::LiteStageRemove {
                session_id: "sess1".to_string(),
            },
            InVmOp::InstallContainerRoute {
                container_pid: 4242,
                gateway_ip: std::net::Ipv4Addr::new(10, 42, 7, 2),
            },
        ];
        assert_eq!(
            ops.len(),
            12,
            "the in-VM op set changed size; every property test in this module \
             iterates this list, and a variant missing from it is a variant \
             nothing here checks"
        );
        ops
    }
}
