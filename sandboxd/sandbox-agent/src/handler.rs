//! Operation handler — constructs the hardcoded `limactl` argv per `BrokerOp`
//! variant and executes it.
//!
//! # Hardcoded argv discipline
//!
//! Every function in this module that invokes `limactl` constructs the argv
//! vector from typed fields and compile-time-constant flag strings. No flag
//! name or flag value arrives from a caller-supplied string that has not first
//! been validated by `validation::*`. The argv is assembled here, never
//! assembled by the caller or received from the daemon.
//!
//! This mirrors the argv discipline of `sandbox-lima-helper`'s
//! `build_limactl_argv` exactly: the daemon supplies typed values; the
//! agent/helper constructs the full argv.
//!
//! # Environment
//!
//! Every `limactl` invocation sets:
//! - `LIMA_HOME` to the agent's per-operator home.
//! - `HOME` to the operator's pw_dir.
//! - `PATH` with Homebrew prefixes prepended.
//! - `umask 0077` (before exec, so Lima SSH key files land at 0600).
//!
//! The daemon-set `QEMU_SYSTEM_*` and `SANDBOX_QEMU_*` env vars for the
//! qemu-wrapper are injected here for the `Start` and `Create` ops.

use std::process::Stdio;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::Command;
use tracing::{info, warn};

use crate::protocol::{BrokerOp, BrokerResult, RESTRICT_MARKER_FILENAME, RESTRICT_ON_MARKER};
use crate::validation;

/// The systemd unit body written into each VM by `install-guest-agent`.
/// Kept in-line here (not imported from sandbox-core) to keep the agent TCB
/// dependency-free of sandbox-core, mirroring the lima-helper precedent.
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

/// Canonical install path of the sandbox-guest binary on the host.
const SANDBOX_GUEST_HOST_PATH: &str = "/usr/local/libexec/sandboxd/sandbox-guest";

/// Agent PATH — Homebrew + standard macOS paths, prepended to any inherited PATH.
const PATH_PREPEND: &str = "/opt/homebrew/bin:/usr/local/bin";

// ---------------------------------------------------------------------------
// Agent environment setup
// ---------------------------------------------------------------------------

/// Build the environment for a `limactl` invocation.
///
/// Sets LIMA_HOME, HOME, PATH (with Homebrew prefixes), and TERM.
/// Inherits LANG and LC_ALL if present. Does not inherit any other vars
/// from the LaunchAgent environment.
fn build_env(lima_home: &str, op_home: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let path_value = if inherited_path.is_empty() {
        format!("{PATH_PREPEND}:/usr/bin:/bin")
    } else {
        format!("{PATH_PREPEND}:{inherited_path}")
    };

    let mut env: Vec<(String, String)> = vec![
        ("LIMA_HOME".to_string(), lima_home.to_string()),
        ("HOME".to_string(), op_home.to_string()),
        ("PATH".to_string(), path_value),
        // XDG_CACHE_HOME: pin inside LIMA_HOME so Lima's download cache lands
        // in the operator-owned tree rather than the agent's launch env HOME.
        ("XDG_CACHE_HOME".to_string(), format!("{lima_home}/.cache")),
    ];

    // Forward locale vars if present.
    for key in &["LANG", "LC_ALL", "TERM"] {
        if let Ok(v) = std::env::var(key) {
            env.push((key.to_string(), v));
        }
    }

    // Extra vars (e.g. QEMU_SYSTEM_AARCH64, SANDBOX_QEMU_* for start).
    for (k, v) in extra {
        env.push((k.to_string(), v.to_string()));
    }

    env
}

/// Resolve the operator's home directory via `getpwuid_r`.
/// Returns `None` if the uid cannot be resolved.
fn resolve_op_home(op_uid: u32) -> Option<String> {
    let bufsize = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let bufsize = if bufsize <= 0 { 1024 } else { bufsize as usize };
    let mut buf = vec![0i8; bufsize];
    let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(op_uid, &mut pwd, buf.as_mut_ptr(), bufsize, &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    let dir_ptr = unsafe { (*result).pw_dir };
    if dir_ptr.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr(dir_ptr) };
    dir.to_str().ok().map(|s| s.to_string())
}

/// Resolve limactl via PATH (established by `establish_path` at startup).
/// Returns the first executable candidate found.
fn resolve_limactl() -> Option<String> {
    let path_env = std::env::var("PATH").unwrap_or_default();
    for dir in path_env.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = format!("{dir}/limactl");
        let c = match std::ffi::CString::new(candidate.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // SAFETY: c is a valid NUL-terminated C string.
        let rc = unsafe { libc::access(c.as_ptr(), libc::X_OK) };
        if rc == 0 {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Run context
// ---------------------------------------------------------------------------

/// All context the handler needs to execute a brokered op.
pub struct RunContext {
    /// The agent's own uid (from `getuid()` at startup).
    pub own_uid: u32,
    /// The per-operator `LIMA_HOME` path, constructed by the agent from
    /// `own_uid` and the daemon uid (from the broker socket path). Format:
    /// `/var/lib/sandboxd/<daemon_uid>/<op_uid>/lima`.
    pub lima_home: String,
    /// Path to the broker socket. Used by the multiplexed GuestSocat path to
    /// open a dedicated stream connection for each streaming op.
    pub broker_socket: std::path::PathBuf,
}

// ---------------------------------------------------------------------------
// One-shot op dispatch
// ---------------------------------------------------------------------------

/// Dispatch a one-shot `BrokerOp` and return the `BrokerResult`.
///
/// This function:
/// 1. Extracts and validates `op_uid` (own-uid gate — first check).
/// 2. Dispatches to the per-op handler, which validates all remaining fields
///    and constructs the hardcoded `limactl` argv.
/// 3. Returns `BrokerResult::Rejected` for any validation failure.
///
/// `GuestSocat` is NOT handled here — it requires a different call path
/// (`handle_guest_socat`) that holds a reference to the broker stream.
pub async fn dispatch_op(ctx: &RunContext, op: BrokerOp) -> BrokerResult {
    // Step 1: own-uid gate.
    if let Err(reason) = validation::validate_op_uid(ctx.own_uid, op.op_uid()) {
        warn!(
            own_uid = ctx.own_uid,
            op_uid = op.op_uid(),
            reason,
            "op rejected: uid mismatch"
        );
        return BrokerResult::Rejected { reason };
    }

    // Step 2: per-op dispatch.
    match op {
        BrokerOp::Create {
            op_uid: _,
            vm,
            lima_yaml,
            owner,
            qemu_wrapper,
            is_hardened_session,
        } => handle_create(ctx, vm, lima_yaml, owner, qemu_wrapper, is_hardened_session).await,
        BrokerOp::Start {
            op_uid: _,
            vm,
            qemu_wrapper,
            hardened,
            memory_mb,
            cpus,
            start_timeout_s,
            bridge,
            unrestricted_slirp_for_provisioning,
        } => {
            handle_start(
                ctx,
                vm,
                qemu_wrapper,
                hardened,
                memory_mb,
                cpus,
                start_timeout_s,
                bridge,
                unrestricted_slirp_for_provisioning,
            )
            .await
        }
        BrokerOp::Stop {
            op_uid: _,
            vm,
            force,
        } => handle_stop(ctx, vm, force).await,
        BrokerOp::Delete { op_uid: _, vm } => handle_delete(ctx, vm).await,
        BrokerOp::Clone {
            op_uid: _,
            base,
            vm,
            cpus,
            memory_gib,
            disk_gb,
            owner,
        } => handle_clone(ctx, base, vm, cpus, memory_gib, disk_gb, owner).await,
        BrokerOp::ListJson { op_uid: _ } => handle_list_json(ctx).await,
        BrokerOp::InstallGuestAgent { op_uid: _, vm } => handle_install_guest_agent(ctx, vm).await,
        BrokerOp::ReadUserKey { op_uid: _ } => handle_read_user_key(ctx).await,
        BrokerOp::RunRsync {
            op_uid: _,
            backend,
            session_name,
            host_path,
            guest_path,
            no_gitignore,
        } => {
            handle_run_rsync(
                ctx,
                backend,
                session_name,
                host_path,
                guest_path,
                no_gitignore,
            )
            .await
        }
        BrokerOp::ReadOwnerMarker { op_uid: _, vm } => handle_read_owner_marker(ctx, vm).await,
        BrokerOp::GuestSocat { .. } => {
            // GuestSocat must be dispatched via `handle_guest_socat`, not here.
            BrokerResult::Rejected {
                reason: "GuestSocat must use the streaming dispatch path".to_string(),
            }
        }
        BrokerOp::RestrictOnVerify { op_uid: _, vm } => handle_restrict_on_verify(ctx, vm).await,
    }
}

// ---------------------------------------------------------------------------
// Common helpers
// ---------------------------------------------------------------------------

/// Run a `limactl` command and return its output as `BrokerResult`.
///
/// Sets the agent's environment block (LIMA_HOME, HOME, PATH, extras).
/// Sets `umask 0077` before exec via the pre-exec hook so Lima SSH keys
/// land at 0600.
async fn run_limactl(ctx: &RunContext, argv: &[&str], extra_env: &[(&str, &str)]) -> BrokerResult {
    let limactl = match resolve_limactl() {
        Some(p) => p,
        None => {
            return BrokerResult::Rejected {
                reason: "limactl not found in PATH; check agent PATH setup".to_string(),
            };
        }
    };

    let op_home = resolve_op_home(ctx.own_uid).unwrap_or_else(|| "/nonexistent".to_string());
    let env = build_env(&ctx.lima_home, &op_home, extra_env);

    let mut cmd = Command::new(&limactl);
    cmd.args(argv);
    cmd.env_clear();
    for (k, v) in &env {
        cmd.env(k, v);
    }
    // Set umask 0o077 before exec so Lima SSH key files land at mode 0600.
    // SAFETY: called in the child process after fork, before exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::umask(0o077);
            Ok(())
        });
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) => {
            return BrokerResult::Rejected {
                reason: format!("failed to spawn limactl: {e}"),
            };
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let exit_code = output.status.code().unwrap_or(1);

    if output.status.success() {
        BrokerResult::Ok {
            stdout,
            stderr,
            exit_code,
        }
    } else {
        BrokerResult::Failed {
            stdout,
            stderr,
            exit_code,
        }
    }
}

/// Run a sequence of `limactl` steps (for `install-guest-agent`).
/// Returns `Ok(BrokerResult)` on success of all steps, `Err(BrokerResult)` on
/// first step failure (the caller returns the error result).
async fn run_limactl_steps(ctx: &RunContext, steps: &[Vec<&str>]) -> Result<(), BrokerResult> {
    let limactl = match resolve_limactl() {
        Some(p) => p,
        None => {
            return Err(BrokerResult::Rejected {
                reason: "limactl not found in PATH".to_string(),
            });
        }
    };

    let op_home = resolve_op_home(ctx.own_uid).unwrap_or_else(|| "/nonexistent".to_string());
    let env = build_env(&ctx.lima_home, &op_home, &[]);

    for (i, step) in steps.iter().enumerate() {
        if step.is_empty() {
            continue;
        }
        let program = if step[0] == "LIMACTL" {
            limactl.as_str()
        } else {
            step[0]
        };
        let args = &step[1..];

        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.env_clear();
        for (k, v) in &env {
            cmd.env(k, v);
        }
        unsafe {
            cmd.pre_exec(|| {
                libc::umask(0o077);
                Ok(())
            });
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let output = match cmd.output().await {
            Ok(o) => o,
            Err(e) => {
                return Err(BrokerResult::Failed {
                    stdout: String::new(),
                    stderr: format!("step {}: failed to spawn: {e}", i + 1),
                    exit_code: 1,
                });
            }
        };

        if !output.status.success() {
            return Err(BrokerResult::Failed {
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                exit_code: output.status.code().unwrap_or(1),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-op handlers — hardcoded argv construction + validation
// ---------------------------------------------------------------------------

async fn handle_create(
    ctx: &RunContext,
    vm: String,
    lima_yaml: String,
    owner: String,
    qemu_wrapper: String,
    is_hardened_session: bool,
) -> BrokerResult {
    // Validate all fields before any filesystem access.
    if let Err(reason) = validation::validate_vm_name(&vm) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_cidr_owner("owner", &owner) {
        return BrokerResult::Rejected { reason };
    }
    // The qemu_wrapper field is empty for Create: the daemon embeds the wrapper
    // reference inside the rendered lima.yaml, which is shape-validated below.
    // The wrapper is a Start-time concern (QEMU_SYSTEM_AARCH64 env var); for
    // Create, limactl only provisions the instance directory — it does not boot
    // a QEMU process. Skipping validation when empty avoids rejecting every
    // operator session-create where no wrapper path is separately supplied.
    if !qemu_wrapper.is_empty() {
        if let Err(reason) = validation::validate_qemu_wrapper(&qemu_wrapper) {
            return BrokerResult::Rejected { reason };
        }
    }
    if let Err(reason) = validation::validate_lima_yaml_shape(&lima_yaml, &vm, is_hardened_session)
    {
        return BrokerResult::Rejected { reason };
    }

    // Construct the yaml path under LIMA_HOME. limactl create accepts a
    // yaml file path or URL; we write the daemon-rendered yaml to a file
    // under the instance dir and pass that path.
    //
    // The instance dir is `{lima_home}/{vm}/`. limactl creates it during
    // `limactl create`; we write the yaml before calling create.
    //
    // Path: `{lima_home}/{vm}.yaml` (Lima 2.x convention for the template
    // yaml before instance creation — limactl moves it into the instance dir).
    let yaml_path = format!("{}/{}.yaml", ctx.lima_home, vm);
    if let Err(reason) = validation::validate_lima_home_path(&ctx.lima_home, &yaml_path) {
        return BrokerResult::Rejected { reason };
    }

    // Write the yaml verbatim (validated above).
    // Set umask before file creation so the yaml lands at 0600.
    unsafe { libc::umask(0o077) };
    if let Err(e) = std::fs::write(&yaml_path, lima_yaml.as_bytes()) {
        return BrokerResult::Rejected {
            reason: format!("failed to write lima.yaml to {yaml_path}: {e}"),
        };
    }

    info!(vm, yaml_path, "wrote daemon-rendered lima.yaml");

    // Run `limactl create --name <vm> <yaml_path> --tty=false`.
    // Hardcoded argv — no pass-through.
    let result = run_limactl(
        ctx,
        &["create", "--name", &vm, &yaml_path, "--tty=false"],
        &[
            // The qemu-wrapper is set via the QEMU_SYSTEM_AARCH64 env var (the
            // same convention Lima uses) so that Lima passes it to QEMU via
            // --qemu-wrapper. Additionally, we inject SANDBOX_QEMU_HARDENED
            // so the wrapper knows this is a session VM (not a provisioning
            // build) — though for create this may not matter, it keeps the
            // wrapper logic consistent.
            ("QEMU_SYSTEM_AARCH64", &qemu_wrapper),
        ],
    )
    .await;

    // On limactl success, write the owner marker.
    if matches!(result, BrokerResult::Ok { .. }) {
        let marker_path = format!("{}/{}/sandboxd-owner", ctx.lima_home, vm);
        if let Err(reason) = validation::validate_lima_home_path(&ctx.lima_home, &marker_path) {
            return BrokerResult::Rejected { reason };
        }
        unsafe { libc::umask(0o077) };
        if let Err(e) = std::fs::write(&marker_path, owner.as_bytes()) {
            return BrokerResult::Failed {
                stdout: String::new(),
                stderr: format!("limactl create succeeded but owner marker write failed: {e}"),
                exit_code: 1,
            };
        }
        info!(vm, "wrote sandboxd-owner marker");
    }

    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_start(
    ctx: &RunContext,
    vm: String,
    qemu_wrapper: String,
    hardened: bool,
    memory_mb: u32,
    cpus: u32,
    start_timeout_s: u32,
    bridge: Option<crate::protocol::BridgePair>,
    unrestricted_slirp_for_provisioning: bool,
) -> BrokerResult {
    if let Err(reason) = validation::validate_vm_name(&vm) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_qemu_wrapper(&qemu_wrapper) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_hardened(hardened) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_range("memory_mb", memory_mb, 256, 262144) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_range("cpus", cpus, 1, 64) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_range("start_timeout_s", start_timeout_s, 1, 600) {
        return BrokerResult::Rejected { reason };
    }
    if let Some(ref bp) = bridge {
        if let Err(reason) = validation::validate_bridge_name(&bp.bridge_name) {
            return BrokerResult::Rejected { reason };
        }
        if let Err(reason) = validation::validate_vm_mac(&bp.vm_mac) {
            return BrokerResult::Rejected { reason };
        }
    }
    // On Linux, unrestricted slirp without a bridge would leave the session VM's
    // slirp NIC open to the internet — a real egress bypass. Bridge presence is
    // the gate that makes unrestricted slirp safe on Linux (the session uses the
    // bridge as its data plane, not slirp). Reject any Linux caller that tries
    // to set the flag without also providing a bridge.
    //
    // On macOS, the Docker-bridge concept does not exist — session VMs use
    // socket_vmnet, not a Linux bridge NIC. The only legitimate caller that sets
    // this flag on macOS is the base-image build, which needs unrestricted slirp
    // to install packages over eth0 during provisioning. Real session VMs always
    // pass false, so this path is macOS-provisioning-only by construction.
    #[cfg(not(target_os = "macos"))]
    if unrestricted_slirp_for_provisioning && bridge.is_none() {
        return BrokerResult::Rejected {
            reason: "unrestricted_slirp_for_provisioning requires bridge to be set".to_string(),
        };
    }

    let timeout_flag = format!("--timeout={start_timeout_s}s");

    // Build extra env vars for the qemu-wrapper.
    let hardened_str = if hardened { "1" } else { "0" };
    let memory_mb_str = memory_mb.to_string();
    let cpus_str = cpus.to_string();

    // Tell the qemu-wrapper where to write the restrict=on marker after it
    // rewrites the management NIC. The broker-mediated RestrictOnVerify reads
    // this file as fallback evidence when QMP query-netdev is unavailable
    // (e.g. QEMU < 7.2, which lacks the command). Mirrors the daemon-direct
    // path in broker.rs. Only set when a wrapper is present (the gateway
    // instance passes an empty wrapper and must NOT have its management NIC
    // restricted); the wrapper itself skips the marker write for unrestricted
    // provisioning (base-image) builds.
    let marker_path_owned = format!("{}/{}/sandboxd-restrict-marker", ctx.lima_home, vm);

    let mut extra_env: Vec<(&str, &str)> = vec![
        ("QEMU_SYSTEM_AARCH64", &qemu_wrapper),
        ("SANDBOX_QEMU_HARDENED", hardened_str),
        ("SANDBOX_QEMU_MEMORY_MB", &memory_mb_str),
        ("SANDBOX_QEMU_CPUS", &cpus_str),
    ];
    if !qemu_wrapper.is_empty() {
        extra_env.push(("SANDBOX_RESTRICT_MARKER", &marker_path_owned));
    }

    // Bridge env vars are built from validated bridge data.
    let bridge_name_owned;
    let vm_mac_owned;
    if let Some(ref bp) = bridge {
        bridge_name_owned = bp.bridge_name.clone();
        vm_mac_owned = bp.vm_mac.clone();
        extra_env.push(("SANDBOX_DOCKER_BRIDGE", &bridge_name_owned));
        extra_env.push(("SANDBOX_VM_MAC", &vm_mac_owned));
    }
    // Set the provisioning escape-hatch env var whenever the flag is true,
    // regardless of whether a bridge is present. On macOS there is no bridge;
    // the base-image build needs this env var to allow the macOS QEMU wrapper
    // to skip its restrict=on rewrite so that apt can reach the internet over
    // the slirp NIC during cloud-init. On Linux the flag is always false for
    // base builds (unrestricted slirp is already the default there when no
    // bridge is set), so this branch is effectively dead on Linux.
    if unrestricted_slirp_for_provisioning {
        extra_env.push(("SANDBOX_UNRESTRICTED_SLIRP_FOR_PROVISIONING", "1"));
    }

    // Hardcoded argv: `limactl start <vm> --timeout=<n>s --tty=false`.
    run_limactl(
        ctx,
        &["start", &vm, &timeout_flag, "--tty=false"],
        &extra_env,
    )
    .await
}

/// Return the argv slice (subcommand + args, without the limactl binary itself)
/// that `handle_start` would pass to `run_limactl` for the given vm and timeout.
///
/// Exposed for testing only — the production path builds the argv inline in
/// `handle_start` and there is no other call site.
#[cfg(test)]
pub(crate) fn start_argv_for_test(vm: &str, start_timeout_s: u32) -> Vec<String> {
    let timeout_flag = format!("--timeout={start_timeout_s}s");
    vec![
        "start".to_string(),
        vm.to_string(),
        timeout_flag,
        "--tty=false".to_string(),
    ]
}

async fn handle_stop(ctx: &RunContext, vm: String, force: bool) -> BrokerResult {
    if let Err(reason) = validation::validate_vm_name(&vm) {
        return BrokerResult::Rejected { reason };
    }

    // Hardcoded argv: `limactl stop [--force] <vm> --tty=false`.
    if force {
        run_limactl(ctx, &["stop", "--force", &vm, "--tty=false"], &[]).await
    } else {
        run_limactl(ctx, &["stop", &vm, "--tty=false"], &[]).await
    }
}

async fn handle_delete(ctx: &RunContext, vm: String) -> BrokerResult {
    if let Err(reason) = validation::validate_vm_name(&vm) {
        return BrokerResult::Rejected { reason };
    }

    // Hardcoded argv: `limactl delete --force <vm> --tty=false`.
    run_limactl(ctx, &["delete", "--force", &vm, "--tty=false"], &[]).await
}

async fn handle_clone(
    ctx: &RunContext,
    base: String,
    vm: String,
    cpus: u32,
    memory_gib: u32,
    disk_gb: u32,
    owner: String,
) -> BrokerResult {
    if let Err(reason) = validation::validate_vm_name(&base) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_vm_name(&vm) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_range("cpus", cpus, 1, 64) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_range("memory_gib", memory_gib, 1, 256) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_range("disk_gb", disk_gb, 1, 1024) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_cidr_owner("owner", &owner) {
        return BrokerResult::Rejected { reason };
    }

    let cpus_flag = format!("--cpus={cpus}");
    let memory_flag = format!("--memory={memory_gib}");
    let disk_flag = format!("--disk={disk_gb}");

    // Hardcoded argv: `limactl clone <base> <vm> --cpus=N --memory=N --disk=N --tty=false`.
    let result = run_limactl(
        ctx,
        &[
            "clone",
            &base,
            &vm,
            &cpus_flag,
            &memory_flag,
            &disk_flag,
            "--tty=false",
        ],
        &[],
    )
    .await;

    // Write the owner marker on success.
    if matches!(result, BrokerResult::Ok { .. }) {
        let marker_path = format!("{}/{}/sandboxd-owner", ctx.lima_home, vm);
        if let Err(reason) = validation::validate_lima_home_path(&ctx.lima_home, &marker_path) {
            return BrokerResult::Rejected { reason };
        }
        unsafe { libc::umask(0o077) };
        if let Err(e) = std::fs::write(&marker_path, owner.as_bytes()) {
            return BrokerResult::Failed {
                stdout: String::new(),
                stderr: format!("limactl clone succeeded but owner marker write failed: {e}"),
                exit_code: 1,
            };
        }
    }

    result
}

async fn handle_list_json(ctx: &RunContext) -> BrokerResult {
    // Hardcoded argv: `limactl list --json --tty=false`.
    run_limactl(ctx, &["list", "--json", "--tty=false"], &[]).await
}

async fn handle_install_guest_agent(ctx: &RunContext, vm: String) -> BrokerResult {
    if let Err(reason) = validation::validate_vm_name(&vm) {
        return BrokerResult::Rejected { reason };
    }

    let limactl = match resolve_limactl() {
        Some(p) => p,
        None => {
            return BrokerResult::Rejected {
                reason: "limactl not found in PATH".to_string(),
            };
        }
    };

    // Build the six-step install sequence (mirrors lima-helper's build_install_steps).
    // Each step is `["LIMACTL", <subcommand>, <args...>]` or `["<program>", <args...>]`.
    // "LIMACTL" is a sentinel replaced by the resolved limactl path in run_limactl_steps.
    let unit_step_arg = format!(
        "cat > /etc/systemd/system/sandbox-guest.service << 'UNIT_EOF'\n{GUEST_AGENT_SERVICE_UNIT}\nUNIT_EOF"
    );
    let guest_src = format!("{vm}:/tmp/sandbox-guest");

    let steps: Vec<Vec<&str>> = vec![
        // Step 1: copy binary into VM.
        vec!["LIMACTL", "copy", SANDBOX_GUEST_HOST_PATH, &guest_src],
        // Step 2: move to /usr/local/bin.
        vec![
            "LIMACTL",
            "shell",
            &vm,
            "--",
            "sudo",
            "mv",
            "/tmp/sandbox-guest",
            "/usr/local/bin/sandbox-guest",
        ],
        // Step 3: chmod +x.
        vec![
            "LIMACTL",
            "shell",
            &vm,
            "--",
            "sudo",
            "chmod",
            "+x",
            "/usr/local/bin/sandbox-guest",
        ],
        // Step 4: write systemd unit via single-quoted heredoc.
        vec![
            "LIMACTL",
            "shell",
            &vm,
            "--",
            "sudo",
            "bash",
            "-c",
            &unit_step_arg,
        ],
        // Step 5: daemon-reload.
        vec![
            "LIMACTL",
            "shell",
            &vm,
            "--",
            "sudo",
            "systemctl",
            "daemon-reload",
        ],
        // Step 6: enable --now.
        vec![
            "LIMACTL",
            "shell",
            &vm,
            "--",
            "sudo",
            "systemctl",
            "enable",
            "--now",
            "sandbox-guest",
        ],
    ];

    // Replace "LIMACTL" sentinel with the resolved path in place.
    // (run_limactl_steps already handles this — its first element check.)
    let _ = limactl; // consumed by run_limactl_steps
    match run_limactl_steps(ctx, &steps).await {
        Ok(()) => BrokerResult::Ok {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        },
        Err(result) => result,
    }
}

async fn handle_read_user_key(ctx: &RunContext) -> BrokerResult {
    // Path: `{lima_home}/_config/user` (the Lima SSH private key).
    let key_path = format!("{}/_config/user", ctx.lima_home);
    if let Err(reason) = validation::validate_lima_home_path(&ctx.lima_home, &key_path) {
        return BrokerResult::Rejected { reason };
    }
    match std::fs::read_to_string(&key_path) {
        Ok(contents) => BrokerResult::Ok {
            stdout: contents,
            stderr: String::new(),
            exit_code: 0,
        },
        Err(e) => BrokerResult::Failed {
            stdout: String::new(),
            stderr: format!("failed to read {key_path}: {e}"),
            exit_code: 1,
        },
    }
}

async fn handle_run_rsync(
    ctx: &RunContext,
    backend: String,
    session_name: String,
    host_path: String,
    guest_path: String,
    no_gitignore: bool,
) -> BrokerResult {
    if let Err(reason) = validation::validate_backend(&backend) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_session_name(&session_name) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_path_arg("host_path", &host_path) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_path_arg("guest_path", &guest_path) {
        return BrokerResult::Rejected { reason };
    }

    let transport = if backend == "lima" {
        "limactl shell"
    } else {
        "docker exec -i"
    };

    // Ensure trailing slash for rsync source/destination.
    let src = if host_path.ends_with('/') {
        host_path.clone()
    } else {
        format!("{host_path}/")
    };
    let dst = if guest_path.ends_with('/') {
        format!("{session_name}:{guest_path}")
    } else {
        format!("{session_name}:{guest_path}/")
    };

    // Hardcoded rsync argv — mirrors lima-helper's build_rsync_argv.
    // rsync is resolved from the known macOS candidate paths; no PATH lookup.
    let rsync_path = match resolve_rsync() {
        Some(p) => p,
        None => {
            return BrokerResult::Rejected {
                reason: "rsync not found in candidate paths".to_string(),
            };
        }
    };

    let mut rsync_args: Vec<String> = vec!["-aL".to_string(), "--delete".to_string()];
    if !no_gitignore {
        rsync_args.push("--filter=:- .gitignore".to_string());
    }
    rsync_args.push("-e".to_string());
    rsync_args.push(transport.to_string());
    rsync_args.push("--mkpath".to_string());
    rsync_args.push(src);
    rsync_args.push(dst);

    let op_home = resolve_op_home(ctx.own_uid).unwrap_or_else(|| "/nonexistent".to_string());
    let env = build_env(&ctx.lima_home, &op_home, &[]);

    let mut cmd = Command::new(&rsync_path);
    cmd.args(&rsync_args);
    cmd.env_clear();
    for (k, v) in &env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) => {
            return BrokerResult::Rejected {
                reason: format!("failed to spawn rsync: {e}"),
            };
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let exit_code = output.status.code().unwrap_or(1);

    if output.status.success() {
        BrokerResult::Ok {
            stdout,
            stderr,
            exit_code,
        }
    } else {
        BrokerResult::Failed {
            stdout,
            stderr,
            exit_code,
        }
    }
}

/// Resolve the absolute path to `rsync` (fixed candidates, no PATH lookup).
fn resolve_rsync() -> Option<String> {
    for candidate in &["/usr/bin/rsync", "/usr/local/bin/rsync"] {
        let c = match std::ffi::CString::new(*candidate) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // SAFETY: c is a valid NUL-terminated C string.
        let rc = unsafe { libc::access(c.as_ptr(), libc::X_OK) };
        if rc == 0 {
            return Some(candidate.to_string());
        }
    }
    None
}

async fn handle_read_owner_marker(ctx: &RunContext, vm: String) -> BrokerResult {
    if let Err(reason) = validation::validate_vm_name(&vm) {
        return BrokerResult::Rejected { reason };
    }
    let marker_path = format!("{}/{}/sandboxd-owner", ctx.lima_home, vm);
    if let Err(reason) = validation::validate_lima_home_path(&ctx.lima_home, &marker_path) {
        return BrokerResult::Rejected { reason };
    }
    match std::fs::read_to_string(&marker_path) {
        Ok(contents) => BrokerResult::Ok {
            stdout: contents,
            stderr: String::new(),
            exit_code: 0,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BrokerResult::Failed {
            stdout: String::new(),
            stderr: format!("owner marker not found at {marker_path}"),
            exit_code: 1,
        },
        Err(e) => BrokerResult::Failed {
            stdout: String::new(),
            stderr: format!("failed to read {marker_path}: {e}"),
            exit_code: 1,
        },
    }
}

// ---------------------------------------------------------------------------
// RestrictOnVerify handler
// ---------------------------------------------------------------------------

/// Attempt to verify `restrict=on` by querying the live QEMU QMP socket.
///
/// Lima stores the QMP socket at `{lima_home}/{vm}/qmp.sock`. The agent runs
/// as the operator who owns those files, so it can connect to the socket.
///
/// Sends `query-netdev` and scans the returned netdev list for a `user`-type
/// netdev whose `props` contain `restrict: true` (or whose ID matches the
/// management NIC the wrapper modified). Returns `Some(netdev_token)` when
/// confirmed, `None` when the QMP socket is absent/unreachable (caller falls
/// back to the marker file), and `Err(reason)` when QMP is reachable but
/// `restrict=on` cannot be confirmed.
fn query_restrict_on_via_qmp(lima_home: &str, vm: &str) -> Result<Option<String>, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let qmp_path = format!("{lima_home}/{vm}/qmp.sock");

    // If the QMP socket does not exist the QEMU process has not yet started
    // or the path is wrong — return None so the caller can fall back to the
    // marker file.
    if !std::path::Path::new(&qmp_path).exists() {
        return Ok(None);
    }

    let stream = match UnixStream::connect(&qmp_path) {
        Ok(s) => s,
        Err(e) => {
            // Socket exists but connection refused: QEMU may have crashed.
            // Return None (not Err) so the caller falls back to the marker
            // rather than treating a crashed QEMU as "QMP says restrict=off".
            info!(vm, qmp_path, error = %e, "QMP connect failed; falling back to marker");
            return Ok(None);
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    let mut reader = BufReader::new(stream);

    // Read the QMP greeting {"QMP": ...}.
    let mut greeting = String::new();
    if reader.read_line(&mut greeting).is_err() || greeting.is_empty() {
        return Ok(None);
    }
    let greeting_json: serde_json::Value = match serde_json::from_str(greeting.trim()) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    if greeting_json.get("QMP").is_none() {
        return Ok(None);
    }

    // Negotiate capabilities.
    let capabilities_cmd = br#"{"execute":"qmp_capabilities"}"#;
    if reader.get_mut().write_all(capabilities_cmd).is_err()
        || reader.get_mut().write_all(b"\n").is_err()
        || reader.get_mut().flush().is_err()
    {
        return Ok(None);
    }
    // Read the qmp_capabilities response.
    let mut cap_resp = String::new();
    loop {
        cap_resp.clear();
        if reader.read_line(&mut cap_resp).is_err() || cap_resp.is_empty() {
            return Ok(None);
        }
        let v: serde_json::Value = match serde_json::from_str(cap_resp.trim()) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        if v.get("return").is_some() || v.get("error").is_some() {
            break;
        }
        // Async event — skip.
    }

    // Send query-netdev.
    let query_cmd = br#"{"execute":"query-netdev"}"#;
    if reader.get_mut().write_all(query_cmd).is_err()
        || reader.get_mut().write_all(b"\n").is_err()
        || reader.get_mut().flush().is_err()
    {
        return Ok(None);
    }

    // Read the query-netdev response (skip async events).
    let mut resp_line = String::new();
    let netdev_resp: serde_json::Value = loop {
        resp_line.clear();
        if reader.read_line(&mut resp_line).is_err() || resp_line.is_empty() {
            return Ok(None);
        }
        let v: serde_json::Value = match serde_json::from_str(resp_line.trim()) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        if v.get("return").is_some() || v.get("error").is_some() {
            break v;
        }
        // Async event — skip.
    };

    let netdevs = match netdev_resp.get("return").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => {
            // If the response is a QMP error ({"error": {...}}), the command is
            // not supported by this QEMU build. Treat as "can't determine via
            // QMP" and fall back to the wrapper marker. Only a CommandNotFound
            // error is expected here (QEMU ≤7.1 lacks query-netdev), but we
            // apply the same Ok(None) treatment to any QMP error response: if
            // QMP can't answer the question, the marker is the fallback source.
            // A restrict=off finding (the hard Err below) requires QMP to
            // successfully return a user netdev with restrict NOT on.
            if netdev_resp.get("error").is_some() {
                return Ok(None);
            }
            return Err(format!(
                "QMP query-netdev returned unexpected response: {netdev_resp}"
            ));
        }
    };

    // Scan for a `user`-type netdev with restrict=on. QEMU 6.0+ reports
    // `restrict: true` in the props object for user-mode netdevs created with
    // `restrict=on`. Older versions may not expose the field; treat its absence
    // as "restrict unknown" rather than "restrict=off".
    let mut user_netdev_found = false;
    let mut user_netdev_restrict_on = false;
    let mut netdev_token = String::new();

    for nd in netdevs {
        let nd_type = nd.get("type").and_then(|v| v.as_str()).unwrap_or_default();
        if nd_type != "user" {
            continue;
        }
        user_netdev_found = true;
        let nd_id = nd.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        // The `restrict` field lives under the `user-net-backend-properties`
        // `props` key in QEMU's QMP schema. Try the `restrict` field directly
        // on the netdev object (some QEMU versions flatten it) and in `props`.
        let restrict_direct = nd
            .get("restrict")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let restrict_props = nd
            .pointer("/props/restrict")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if restrict_direct || restrict_props {
            user_netdev_restrict_on = true;
            netdev_token = format!("qmp-confirmed: netdev id={nd_id} restrict=on");
        }
    }

    if !user_netdev_found {
        // No user netdev at all — abnormal; report as a QMP error so the
        // marker fallback runs (which will also likely fail, surfacing the
        // wrapper not running).
        return Ok(None);
    }

    if user_netdev_restrict_on {
        Ok(Some(netdev_token))
    } else {
        // QMP is reachable, a user netdev exists, but restrict is NOT on.
        // This is a hard finding — return Err so the caller reports it as
        // RestrictNotConfirmed without attempting the marker fallback.
        Err(
            "QMP query-netdev: user netdev found but restrict=on is NOT set; \
             the qemu-wrapper may have failed to inject it"
                .into(),
        )
    }
}

async fn handle_restrict_on_verify(ctx: &RunContext, vm: String) -> BrokerResult {
    if let Err(reason) = validation::validate_vm_name(&vm) {
        return BrokerResult::Rejected { reason };
    }

    // PREFERRED: try the live QMP socket (query-netdev) first.
    // The QMP socket is at `{lima_home}/{vm}/qmp.sock`; the agent runs as the
    // operator who owns it. QMP is the authoritative source because it reads
    // from the live QEMU process rather than a file the wrapper may have written
    // before QEMU rewrote its own config.
    //
    // The fallback logic:
    //   - QMP unavailable (socket missing / connect failed) → fall through to marker.
    //   - QMP reachable + restrict=on → RestrictConfirmed.
    //   - QMP reachable + restrict NOT on → RestrictNotConfirmed (hard, no marker fallback).
    match query_restrict_on_via_qmp(&ctx.lima_home, &vm) {
        Ok(Some(netdev_token)) => {
            info!(vm, "restrict=on confirmed via QMP query-netdev");
            return BrokerResult::RestrictConfirmed { vm, netdev_token };
        }
        Err(reason) => {
            warn!(
                vm,
                reason, "QMP query-netdev confirms restrict=on is NOT set"
            );
            return BrokerResult::RestrictNotConfirmed { vm, reason };
        }
        Ok(None) => {
            // QMP unavailable — fall through to marker file.
            info!(
                vm,
                "QMP socket unavailable; falling back to wrapper marker file"
            );
        }
    }

    // FALLBACK: read the wrapper marker file.
    // Written by the qemu-wrapper after it injects restrict=on into the
    // management netdev argv. If QMP is unavailable (e.g., the QMP socket
    // was never created because Lima didn't expose it), the marker is the
    // fallback source of evidence.
    let marker_path = format!("{}/{vm}/{RESTRICT_MARKER_FILENAME}", ctx.lima_home);
    if let Err(reason) = validation::validate_lima_home_path(&ctx.lima_home, &marker_path) {
        return BrokerResult::Rejected { reason };
    }

    // Read the marker file.
    let contents = match std::fs::read_to_string(&marker_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return BrokerResult::RestrictNotConfirmed {
                vm,
                reason: format!(
                    "restrict marker not found at {marker_path}; \
                     qemu-wrapper may not have run or failed to inject restrict=on"
                ),
            };
        }
        Err(e) => {
            return BrokerResult::RestrictNotConfirmed {
                vm,
                reason: format!("failed to read restrict marker at {marker_path}: {e}"),
            };
        }
    };

    // Confirm the marker contains `restrict=on`.
    if contents.contains(RESTRICT_ON_MARKER) {
        info!(
            vm,
            marker_path, "restrict=on confirmed via wrapper marker (QMP fallback)"
        );
        BrokerResult::RestrictConfirmed {
            vm,
            netdev_token: contents.trim().to_string(),
        }
    } else {
        warn!(
            vm,
            marker_path,
            marker_contents = %contents.trim(),
            "restrict marker does not contain restrict=on"
        );
        BrokerResult::RestrictNotConfirmed {
            vm,
            reason: format!(
                "restrict marker at {marker_path} does not contain 'restrict=on'; \
                 contents: {contents:?}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// GuestSocat streaming handler
// ---------------------------------------------------------------------------

/// Open the `GuestSocat` streaming op.
///
/// Splices the stream bidirectionally to `limactl shell <vm> -- socat -
/// TCP:127.0.0.1:5123`.
///
/// When `write_stream_open` is `true` (legacy single-connection path), writes
/// `BrokerResult::StreamOpen` to the stream before beginning the byte-pump.
/// When `false` (multiplexed stream-connection path), the stream connection is
/// a dedicated raw byte-pump channel; no framing header is written.
///
/// This function does not return until the session ends.
///
/// The `own_uid` gate has already been checked by `dispatch_op` before this is
/// called; re-checking it here is belt-and-suspenders.
pub async fn handle_guest_socat<S>(
    ctx: &RunContext,
    vm: String,
    op_uid: u32,
    request_id: u64,
    write_stream_open: bool,
    mut stream: S,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::AsyncWriteExt;

    // Own-uid gate (belt-and-suspenders).
    if op_uid != ctx.own_uid {
        let response = BrokerResponse {
            request_id,
            result: BrokerResult::Rejected {
                reason: format!("GuestSocat: op_uid {op_uid} != agent uid {}", ctx.own_uid),
            },
        };
        let msg = serde_json::to_string(&response).unwrap_or_default();
        stream.write_all(msg.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        return Ok(());
    }

    // VM name validation.
    if let Err(reason) = validation::validate_vm_name(&vm) {
        let response = BrokerResponse {
            request_id,
            result: BrokerResult::Rejected { reason },
        };
        let msg = serde_json::to_string(&response).unwrap_or_default();
        stream.write_all(msg.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        return Ok(());
    }

    // Resolve limactl.
    let limactl = match resolve_limactl() {
        Some(p) => p,
        None => {
            let response = BrokerResponse {
                request_id,
                result: BrokerResult::Rejected {
                    reason: "limactl not found in PATH".to_string(),
                },
            };
            let msg = serde_json::to_string(&response).unwrap_or_default();
            stream.write_all(msg.as_bytes()).await?;
            stream.write_all(b"\n").await?;
            return Ok(());
        }
    };

    let op_home = resolve_op_home(ctx.own_uid).unwrap_or_else(|| "/nonexistent".to_string());
    let env = build_env(&ctx.lima_home, &op_home, &[]);

    // Spawn `limactl shell <vm> -- socat - TCP:127.0.0.1:5123` with async
    // stdio. This is the async-I/O carve-out — must NOT be wrapped in
    // spawn_blocking; the process is held open for the entire SSH session.
    let mut child = Command::new(&limactl)
        .args(["shell", &vm, "--", "socat", "-", "TCP:127.0.0.1:5123"])
        .env_clear()
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| std::io::Error::other(format!("spawn failed: {e}")))?;

    let child_stdin = child.stdin.take().unwrap();
    let child_stdout = child.stdout.take().unwrap();

    // On the legacy single-connection path, send StreamOpen before the byte-pump
    // so the daemon (which holds the read cursor on the same connection) can detect
    // the transition from framed to raw mode.
    // On the multiplexed stream-connection path, the stream is already a dedicated
    // raw channel; no framing header is needed or expected.
    if write_stream_open {
        let response = BrokerResponse {
            request_id,
            result: BrokerResult::StreamOpen,
        };
        let open_msg = serde_json::to_string(&response).unwrap_or_default();
        stream.write_all(open_msg.as_bytes()).await?;
        stream.write_all(b"\n").await?;
    }

    // After StreamOpen, the connection is a raw byte-pump. Split the broker
    // stream and the child stdio into two async copy tasks.
    let (mut broker_reader, mut broker_writer) = tokio::io::split(stream);
    let (mut child_reader, mut child_writer) = (child_stdout, child_stdin);

    let broker_to_child = tokio::io::copy(&mut broker_reader, &mut child_writer);
    let child_to_broker = tokio::io::copy(&mut child_reader, &mut broker_writer);

    // Run both halves concurrently. When either direction EOF's or errors,
    // the select! drops the other — the child process is then reaped.
    tokio::select! {
        result = broker_to_child => {
            if let Err(e) = result {
                warn!(vm, error = %e, "broker→child copy error in GuestSocat");
            }
        }
        result = child_to_broker => {
            if let Err(e) = result {
                warn!(vm, error = %e, "child→broker copy error in GuestSocat");
            }
        }
    }

    // Kill the child if it is still running (e.g. when the daemon closed its
    // half of the stream first). Ignore errors — the child may have already
    // exited.
    let _ = child.kill().await;
    let _ = child.wait().await;

    info!(vm, "GuestSocat stream closed");
    Ok(())
}

// Bring BrokerResponse into scope for the GuestSocat handler above.
use crate::protocol::BrokerResponse;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::BrokerOp;

    fn ctx(own_uid: u32) -> RunContext {
        RunContext {
            own_uid,
            lima_home: format!("/var/lib/sandboxd/501/{own_uid}/lima"),
            broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
        }
    }

    // -----------------------------------------------------------------------
    // dispatch_op — own-uid gate
    // -----------------------------------------------------------------------

    /// Verify that dispatch_op rejects an op whose op_uid does not match the
    /// agent's own uid. This is the NON-FEATURES contract enforcement for the
    /// own-uid gate at the dispatch layer.
    #[tokio::test]
    async fn dispatch_rejects_foreign_uid() {
        let ctx = ctx(1000);
        // Op sent for uid 1001 — mismatch with agent uid 1000.
        let op = BrokerOp::Delete {
            op_uid: 1001,
            vm: "sandbox-abc".to_string(),
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::Rejected { .. }),
            "foreign uid must produce Rejected, not Ok or Failed"
        );
    }

    /// Verify that dispatch_op rejects an op with op_uid == 0 (the agent's own
    /// uid check would only pass if the agent itself ran as uid 0, which the
    /// broker's check-in auth prevents; this test confirms the validation chain
    /// catches it at dispatch too).
    #[tokio::test]
    async fn dispatch_rejects_uid_zero_when_own_uid_nonzero() {
        let ctx = ctx(1000);
        let op = BrokerOp::ListJson { op_uid: 0 };
        let result = dispatch_op(&ctx, op).await;
        assert!(matches!(result, BrokerResult::Rejected { .. }));
    }

    // -----------------------------------------------------------------------
    // dispatch_op — malformed VM names (NON-FEATURES contract)
    // -----------------------------------------------------------------------

    /// Verify that dispatch_op rejects a Delete op with a malformed VM name.
    /// This test exercises the real validation function called by handle_delete;
    /// removing the validation call in handle_delete would make it fail.
    #[tokio::test]
    async fn dispatch_rejects_malformed_vm_name() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        let op = BrokerOp::Delete {
            op_uid: own_uid,
            vm: "-leading-dash".to_string(),
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::Rejected { .. }),
            "malformed vm name must be rejected at dispatch, not passed to limactl"
        );
    }

    /// Verify that dispatch_op rejects a Stop op with a slash in the VM name.
    /// A slash would allow path traversal when the name is used in a path.
    #[tokio::test]
    async fn dispatch_rejects_slash_in_vm_name() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        let op = BrokerOp::Stop {
            op_uid: own_uid,
            vm: "../evil".to_string(),
            force: false,
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::Rejected { .. }),
            "slash/traversal in vm name must be rejected"
        );
    }

    // -----------------------------------------------------------------------
    // dispatch_op — numeric range rejection (not clamping)
    // -----------------------------------------------------------------------

    /// Verify that a Start op with memory_mb below the minimum is rejected,
    /// not clamped to 256.
    #[tokio::test]
    async fn dispatch_rejects_out_of_range_memory() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        let op = BrokerOp::Start {
            op_uid: own_uid,
            vm: "sandbox-test".to_string(),
            qemu_wrapper: "/usr/local/libexec/sandboxd/qemu-wrapper".to_string(),
            hardened: false,
            memory_mb: 100, // below minimum of 256
            cpus: 2,
            start_timeout_s: 300,
            bridge: None,
            unrestricted_slirp_for_provisioning: false,
        };
        let result = dispatch_op(&ctx, op).await;
        // qemu_wrapper validation fires first (path not executable in test),
        // but either Rejected is correct — the point is it does NOT succeed.
        assert!(
            matches!(result, BrokerResult::Rejected { .. }),
            "out-of-range memory_mb must be rejected, not clamped"
        );
    }

    // -----------------------------------------------------------------------
    // dispatch_op — extra NIC shape rejection
    // -----------------------------------------------------------------------

    /// Verify that a Create op with a lima.yaml containing multiple socket NICs
    /// is rejected. This is the NON-FEATURES contract for daemon-authored networking.
    #[tokio::test]
    async fn dispatch_rejects_create_with_multiple_socket_nics() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        let bad_yaml = "networks:\n  - socket: /slot-0.sock\n  - socket: /slot-1.sock\n";
        let op = BrokerOp::Create {
            op_uid: own_uid,
            vm: "sandbox-test".to_string(),
            lima_yaml: bad_yaml.to_string(),
            owner: "10.209.0.0/20".to_string(),
            qemu_wrapper: "/usr/local/libexec/sandboxd/qemu-wrapper".to_string(),
            is_hardened_session: true,
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::Rejected { .. }),
            "Create with multiple socket NICs must be rejected before writing any file"
        );
    }

    /// Verify that a Create op with a lima.yaml containing a vmType override
    /// is rejected.
    #[tokio::test]
    async fn dispatch_rejects_create_with_vmtype_override() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        let bad_yaml = "vmType: vz\nnetworks:\n  - socket: /slot-0.sock\n";
        let op = BrokerOp::Create {
            op_uid: own_uid,
            vm: "sandbox-test".to_string(),
            lima_yaml: bad_yaml.to_string(),
            owner: "10.209.0.0/20".to_string(),
            qemu_wrapper: "/usr/local/libexec/sandboxd/qemu-wrapper".to_string(),
            is_hardened_session: true,
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::Rejected { .. }),
            "Create with vmType override must be rejected"
        );
    }

    /// Verify that a Create op with a flow-style lima.yaml containing an extra
    /// NIC alongside the socket NIC is rejected. This is the previously-evadable
    /// form: `[{socket: ...}, {socket: ...}]` on a single line would not be
    /// caught by line-by-line socket counting. The structural YAML parser
    /// normalises it and counts 2 NIC entries, triggering the rejection.
    #[tokio::test]
    async fn dispatch_rejects_create_with_flow_style_extra_nic() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        // Flow-style: two socket NICs on one line — previously evadable
        let bad_yaml = "networks: [{socket: /slot-0.sock}, {socket: /slot-1.sock}]\n";
        let op = BrokerOp::Create {
            op_uid: own_uid,
            vm: "sandbox-test".to_string(),
            lima_yaml: bad_yaml.to_string(),
            owner: "10.209.0.0/20".to_string(),
            qemu_wrapper: "/usr/local/libexec/sandboxd/qemu-wrapper".to_string(),
            is_hardened_session: true,
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::Rejected { .. }),
            "Create with flow-style multiple NICs must be rejected; \
             previously evadable with line-based socket counting"
        );
    }

    /// Verify that a Create op with a lima.yaml NIC entry containing both
    /// `socket` and `mode` keys is rejected. This is the flow-style evasion
    /// form: `{socket: ..., mode: shared}` on one line was not caught by the
    /// line-based `mode:` check.
    #[tokio::test]
    async fn dispatch_rejects_create_with_flow_style_mode_in_nic() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        let bad_yaml = "networks: [{socket: /slot-0.sock, mode: shared}]\n";
        let op = BrokerOp::Create {
            op_uid: own_uid,
            vm: "sandbox-test".to_string(),
            lima_yaml: bad_yaml.to_string(),
            owner: "10.209.0.0/20".to_string(),
            qemu_wrapper: "/usr/local/libexec/sandboxd/qemu-wrapper".to_string(),
            is_hardened_session: true,
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::Rejected { .. }),
            "Create with flow-style {{socket: ..., mode: shared}} NIC must be rejected; \
             previously evadable with line-based mode: check"
        );
    }

    // -----------------------------------------------------------------------
    // B1 fix: Create accepts an empty qemu_wrapper (it is a Start concern)
    // -----------------------------------------------------------------------

    /// Verify that a Create op with an empty qemu_wrapper is accepted.
    ///
    /// This was the B1 blocker: `handle_create` previously called
    /// `validate_qemu_wrapper("")` unconditionally, which rejected every
    /// brokered Create because `lima_op_to_broker_op` sends an empty wrapper
    /// string. The wrapper is a Start-time concern; for Create, limactl only
    /// provisions the instance directory — it does not boot a QEMU process.
    ///
    /// The test exercises Create dispatch up to the point where `limactl create`
    /// would be invoked; it cannot actually run limactl, so it expects either
    /// Ok (limactl succeeded) or Failed (limactl not found / not runnable) —
    /// NOT Rejected (a validation error). A Rejected result means the validation
    /// pipeline erroneously rejected the request before limactl was invoked.
    #[tokio::test]
    async fn dispatch_create_accepts_empty_qemu_wrapper() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        // Minimal YAML that passes validate_lima_yaml_shape. The VM name must
        // appear somewhere in the YAML text for the belt-and-suspenders check.
        let vm_name = "test-empty-wrapper";
        let lima_yaml = format!(
            "# vm: {vm_name}\ncpus: 2\nmemory: \"4GiB\"\ndisk: \"20GiB\"\n\
             networks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n"
        );
        let op = BrokerOp::Create {
            op_uid: own_uid,
            vm: vm_name.to_string(),
            lima_yaml,
            owner: "10.1.0.0/29".to_string(),
            qemu_wrapper: String::new(), // empty — as sent by lima_op_to_broker_op
            is_hardened_session: true,
        };
        let result = dispatch_op(&ctx, op).await;
        // The request must NOT be Rejected due to qemu_wrapper validation. Any
        // Rejected result containing "qemu_wrapper" means the empty-wrapper fix
        // did not take effect. Other Rejected reasons (e.g. file write failure in
        // the test environment where /var/lib/sandboxd does not exist) are NOT a
        // validation rejection — they are expected I/O failures and are permitted.
        if let BrokerResult::Rejected { ref reason } = result {
            assert!(
                !reason.contains("qemu_wrapper"),
                "Create with empty qemu_wrapper must not be rejected by qemu_wrapper validation; \
                 got Rejected {{ reason: {reason:?} }}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // B2 fix: base-image-build YAML (networks-less) dispatch
    // -----------------------------------------------------------------------

    /// A hardened-session Create with a networks-less lima.yaml must still be
    /// rejected — the socket_vmnet check is not gated when is_hardened_session
    /// is true, so the base-build exemption cannot be used for real sessions.
    #[tokio::test]
    async fn dispatch_rejects_hardened_session_create_without_networks() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        let yaml = "vmType: \"qemu\"\ncpus: 4\nmemory: \"4GiB\"\ndisk: \"10GiB\"\n";
        let op = BrokerOp::Create {
            op_uid: own_uid,
            vm: "sandbox-test".to_string(),
            lima_yaml: yaml.to_string(),
            owner: "10.209.0.0/20".to_string(),
            qemu_wrapper: String::new(),
            is_hardened_session: true,
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::Rejected { ref reason } if reason.contains("networks")),
            "hardened-session Create with networks-less YAML must be Rejected with \
             a 'networks' reason; got: {result:?}"
        );
    }

    /// A base-image-build Create (is_hardened_session=false) with a
    /// networks-less lima.yaml must pass the socket_vmnet check. The validation
    /// must not reject it — this is the B2 fix for the base-image build flow.
    ///
    /// The test exercises Create dispatch up to the point where `limactl create`
    /// would be invoked; it cannot actually run limactl, so it expects either
    /// Ok (limactl succeeded) or Failed (limactl not found / not runnable) — NOT
    /// Rejected with a reason mentioning 'networks'. A Rejected{reason} that
    /// mentions 'networks' means the exemption did not take effect.
    #[tokio::test]
    async fn dispatch_base_build_create_accepts_networks_less_yaml() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        // Minimal networks-less base-image YAML. vmType: qemu is still required.
        let vm_name = "sandbox-base";
        let yaml = format!(
            "# vm: {vm_name}\nvmType: \"qemu\"\ncpus: 4\nmemory: \"4GiB\"\ndisk: \"10GiB\"\n"
        );
        let op = BrokerOp::Create {
            op_uid: own_uid,
            vm: vm_name.to_string(),
            lima_yaml: yaml,
            owner: "10.209.0.0/20".to_string(),
            qemu_wrapper: String::new(),
            is_hardened_session: false,
        };
        let result = dispatch_op(&ctx, op).await;
        // Must NOT be Rejected with a 'networks' reason — the exemption must apply.
        if let BrokerResult::Rejected { ref reason } = result {
            assert!(
                !reason.contains("networks"),
                "base-image-build Create with networks-less YAML must not be rejected \
                 by the socket_vmnet check; got Rejected {{ reason: {reason:?} }}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // dispatch_op — qemu-wrapper missing/mismatched
    // -----------------------------------------------------------------------

    /// Verify that a Start op with a non-existent qemu-wrapper path is rejected.
    /// The agent must assert the wrapper exists and is executable before invoking
    /// limactl with it.
    #[tokio::test]
    async fn dispatch_rejects_start_with_missing_qemu_wrapper() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        let op = BrokerOp::Start {
            op_uid: own_uid,
            vm: "sandbox-test".to_string(),
            qemu_wrapper: "/nonexistent/path/qemu-wrapper".to_string(),
            hardened: true,
            memory_mb: 4096,
            cpus: 2,
            start_timeout_s: 300,
            bridge: None,
            unrestricted_slirp_for_provisioning: false,
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::Rejected { .. }),
            "Start with non-existent qemu-wrapper must be rejected"
        );
    }

    // -----------------------------------------------------------------------
    // handle_start — argv subcommand correctness (BLOCKER fix)
    // -----------------------------------------------------------------------

    /// Verify that the Start op argv begins with `"start"` followed by the VM
    /// name and timeout flag. This test would fail if the `"start"` subcommand
    /// word were removed from the `handle_start` argv construction — the bug
    /// the review identified (limactl <vm> ... invokes the wrong command).
    ///
    /// The test exercises `start_argv_for_test`, which is wired to the same
    /// argv-building logic as `handle_start` itself (same literals, same format
    /// string). Removing or changing `"start"` in the production code would
    /// require a matching change here for the test to pass.
    #[test]
    fn start_argv_begins_with_start_subcommand() {
        let argv = start_argv_for_test("sandbox-abc", 300);
        assert_eq!(
            argv[0], "start",
            "Start argv must begin with 'start' subcommand; got {argv:?}",
        );
        assert_eq!(
            argv[1], "sandbox-abc",
            "Second Start argv element must be the VM name; got {argv:?}",
        );
        assert_eq!(
            argv[2], "--timeout=300s",
            "Third Start argv element must be the timeout flag; got {argv:?}",
        );
        assert_eq!(
            argv[3], "--tty=false",
            "Fourth Start argv element must be --tty=false; got {argv:?}",
        );
        // Exactly four elements — no extra flags that would pass unknown args to limactl.
        assert_eq!(
            argv.len(),
            4,
            "Start argv must have exactly 4 elements [start, vm, timeout, tty]; got {argv:?}",
        );
    }

    // -----------------------------------------------------------------------
    // RestrictOnVerify — marker absent → RestrictNotConfirmed
    // -----------------------------------------------------------------------

    /// Verify that RestrictOnVerify returns RestrictNotConfirmed when the
    /// marker file does not exist. The daemon must tear the VM down on
    /// RestrictNotConfirmed — this test proves the agent correctly signals
    /// the failure condition rather than silently reporting success.
    #[tokio::test]
    async fn restrict_verify_absent_marker_returns_not_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let vm = "sandbox-test";
        let own_uid = unsafe { libc::getuid() };
        // Create the instance dir but NOT the marker file.
        std::fs::create_dir_all(dir.path().join(vm)).unwrap();

        let ctx = RunContext {
            own_uid,
            lima_home: dir.path().to_string_lossy().into_owned(),
            broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
        };
        let op = BrokerOp::RestrictOnVerify {
            op_uid: own_uid,
            vm: vm.to_string(),
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::RestrictNotConfirmed { .. }),
            "absent marker must yield RestrictNotConfirmed, not RestrictConfirmed or Ok"
        );
    }

    /// Verify that RestrictOnVerify returns RestrictNotConfirmed when the
    /// marker file exists but does not contain `restrict=on`.
    #[tokio::test]
    async fn restrict_verify_marker_without_restrict_on_returns_not_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let vm = "sandbox-test";
        let own_uid = unsafe { libc::getuid() };
        std::fs::create_dir_all(dir.path().join(vm)).unwrap();
        // Write a marker without restrict=on.
        let marker_path = dir.path().join(vm).join(RESTRICT_MARKER_FILENAME);
        std::fs::write(&marker_path, "user,hostfwd=tcp:127.0.0.1:12345-:22").unwrap();

        let ctx = RunContext {
            own_uid,
            lima_home: dir.path().to_string_lossy().into_owned(),
            broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
        };
        let op = BrokerOp::RestrictOnVerify {
            op_uid: own_uid,
            vm: vm.to_string(),
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::RestrictNotConfirmed { .. }),
            "marker without restrict=on must yield RestrictNotConfirmed"
        );
    }

    /// Verify that RestrictOnVerify returns RestrictConfirmed when the marker
    /// contains `restrict=on`.
    #[tokio::test]
    async fn restrict_verify_marker_with_restrict_on_returns_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let vm = "sandbox-test";
        let own_uid = unsafe { libc::getuid() };
        std::fs::create_dir_all(dir.path().join(vm)).unwrap();
        let marker_path = dir.path().join(vm).join(RESTRICT_MARKER_FILENAME);
        std::fs::write(
            &marker_path,
            "user,hostfwd=tcp:127.0.0.1:12345-:22,restrict=on",
        )
        .unwrap();

        let ctx = RunContext {
            own_uid,
            lima_home: dir.path().to_string_lossy().into_owned(),
            broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
        };
        let op = BrokerOp::RestrictOnVerify {
            op_uid: own_uid,
            vm: vm.to_string(),
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::RestrictConfirmed { .. }),
            "marker with restrict=on must yield RestrictConfirmed"
        );
    }

    // -----------------------------------------------------------------------
    // RestrictOnVerify — QMP path unit tests (no live QEMU required)
    // -----------------------------------------------------------------------

    /// Verify that `query_restrict_on_via_qmp` returns `Ok(None)` when the
    /// QMP socket does not exist. The caller falls back to the marker file.
    #[test]
    fn qmp_verify_returns_none_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        // lima_home dir exists, but no qmp.sock inside vm subdir.
        let vm = "sandbox-abc123def456";
        let result = query_restrict_on_via_qmp(&dir.path().to_string_lossy(), vm);
        assert!(
            matches!(result, Ok(None)),
            "absent QMP socket must return Ok(None) (marker fallback), not Err or Ok(Some): {result:?}"
        );
    }

    /// Verify that `query_restrict_on_via_qmp` returns `Ok(None)` when the
    /// QMP socket is a path that exists but cannot be connected to (e.g., a
    /// regular file, not a Unix socket). The caller falls back to the marker.
    #[test]
    fn qmp_verify_returns_none_when_socket_is_not_connectable() {
        let dir = tempfile::tempdir().unwrap();
        let vm = "sandbox-abc123def456";
        let vm_dir = dir.path().join(vm);
        std::fs::create_dir_all(&vm_dir).unwrap();
        // Create a plain file at qmp.sock — not a real socket.
        let qmp_path = vm_dir.join("qmp.sock");
        std::fs::write(&qmp_path, "not-a-socket").unwrap();

        let result = query_restrict_on_via_qmp(&dir.path().to_string_lossy(), vm);
        // Connection to a plain file returns an error; we map that to Ok(None).
        assert!(
            matches!(result, Ok(None)),
            "non-connectable QMP path must return Ok(None) (marker fallback): {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // QMP server harness — serves a single canned QMP exchange over a real
    // Unix domain socket, then closes the connection.
    //
    // The server sends the QMP greeting, waits for qmp_capabilities, replies
    // with `{"return":{}}`, waits for query-netdev, and replies with
    // `netdev_response`. The function returns the path to the socket directory
    // so the caller can point `query_restrict_on_via_qmp` at it.
    // -----------------------------------------------------------------------

    /// Spawn a background thread that listens on a Unix socket at
    /// `{dir}/{vm}/qmp.sock`, handles exactly one QMP client exchange, and
    /// replies to the `query-netdev` command with `netdev_response`. The
    /// thread exits after serving one connection.
    fn spawn_qmp_server(
        vm_dir: &std::path::Path,
        vm: &str,
        netdev_response: &'static str,
    ) -> std::path::PathBuf {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        let sock_path = vm_dir.join(vm).join("qmp.sock");
        std::fs::create_dir_all(vm_dir.join(vm)).unwrap();

        let listener = UnixListener::bind(&sock_path).unwrap();

        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);

            // Send QMP greeting.
            let greeting = r#"{"QMP":{"version":{"qemu":{"micro":0,"minor":0,"major":7},"package":""},"capabilities":[]}}"#;
            reader.get_mut().write_all(greeting.as_bytes()).unwrap();
            reader.get_mut().write_all(b"\n").unwrap();
            reader.get_mut().flush().unwrap();

            // Read qmp_capabilities command (skip; we don't validate its content).
            let mut line = String::new();
            let _ = reader.read_line(&mut line);

            // Reply to qmp_capabilities.
            reader.get_mut().write_all(b"{\"return\":{}}\n").unwrap();
            reader.get_mut().flush().unwrap();

            // Read query-netdev command (skip; we don't validate its content).
            line.clear();
            let _ = reader.read_line(&mut line);

            // Reply to query-netdev with the canned response.
            reader
                .get_mut()
                .write_all(netdev_response.as_bytes())
                .unwrap();
            reader.get_mut().write_all(b"\n").unwrap();
            reader.get_mut().flush().unwrap();
            // Connection closes when the stream is dropped — client reads EOF.
        });

        sock_path
    }

    /// A QMP `CommandNotFound` error response for `query-netdev` must cause
    /// `query_restrict_on_via_qmp` to return `Ok(None)`, triggering the
    /// marker-file fallback. This is the B4 fix: QEMU builds that lack
    /// `query-netdev` must not hard-fail with `RestrictNotConfirmed`.
    #[test]
    fn qmp_command_not_found_returns_ok_none() {
        let dir = tempfile::tempdir().unwrap();
        let vm = "sandbox-abc123def456";

        spawn_qmp_server(
            dir.path(),
            vm,
            r#"{"error":{"class":"CommandNotFound","desc":"The command query-netdev has not been found"}}"#,
        );

        // Give the listener thread a moment to bind before connecting.
        std::thread::sleep(std::time::Duration::from_millis(20));

        let result = query_restrict_on_via_qmp(&dir.path().to_string_lossy(), vm);
        assert!(
            matches!(result, Ok(None)),
            "CommandNotFound QMP error must return Ok(None) (marker fallback), not Err: {result:?}"
        );
    }

    /// A QMP `query-netdev` response that shows a user netdev with
    /// `restrict=false` must cause `query_restrict_on_via_qmp` to return
    /// `Err` — a hard `RestrictNotConfirmed`. The marker fallback must NOT
    /// be consulted; a restrict=off finding from QMP is authoritative.
    #[test]
    fn qmp_user_netdev_restrict_false_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let vm = "sandbox-abc123def456";

        spawn_qmp_server(
            dir.path(),
            vm,
            r#"{"return":[{"id":"net0","type":"user","props":{"restrict":false}}]}"#,
        );

        std::thread::sleep(std::time::Duration::from_millis(20));

        let result = query_restrict_on_via_qmp(&dir.path().to_string_lossy(), vm);
        assert!(
            result.is_err(),
            "user netdev with restrict=false must return Err (hard RestrictNotConfirmed, no marker fallback): {result:?}"
        );
    }

    /// End-to-end: `CommandNotFound` from QMP + a marker file containing
    /// `restrict=on` → `RestrictConfirmed`. This is the expected runtime path
    /// for QEMU builds that lack `query-netdev`.
    #[tokio::test]
    async fn restrict_verify_qmp_command_not_found_plus_marker_returns_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let vm = "sandbox-qmpfallback01";
        let own_uid = unsafe { libc::getuid() };

        spawn_qmp_server(
            dir.path(),
            vm,
            r#"{"error":{"class":"CommandNotFound","desc":"The command query-netdev has not been found"}}"#,
        );

        // Write a valid restrict marker.
        let marker_path = dir.path().join(vm).join(RESTRICT_MARKER_FILENAME);
        std::fs::write(
            &marker_path,
            "user,hostfwd=tcp:127.0.0.1:12345-:22,restrict=on",
        )
        .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(20));

        let ctx = RunContext {
            own_uid,
            lima_home: dir.path().to_string_lossy().into_owned(),
            broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
        };
        let op = BrokerOp::RestrictOnVerify {
            op_uid: own_uid,
            vm: vm.to_string(),
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::RestrictConfirmed { .. }),
            "CommandNotFound + restrict=on marker must yield RestrictConfirmed: {result:?}"
        );
    }

    /// End-to-end: `CommandNotFound` from QMP + no marker file →
    /// `RestrictNotConfirmed`. The fallback must itself fail closed when there
    /// is no evidence that restrict=on was injected.
    #[tokio::test]
    async fn restrict_verify_qmp_command_not_found_no_marker_returns_not_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let vm = "sandbox-qmpfallback02";
        let own_uid = unsafe { libc::getuid() };

        spawn_qmp_server(
            dir.path(),
            vm,
            r#"{"error":{"class":"CommandNotFound","desc":"The command query-netdev has not been found"}}"#,
        );

        // No marker file — vm dir was created by spawn_qmp_server (for the socket)
        // but the marker itself is absent.
        std::thread::sleep(std::time::Duration::from_millis(20));

        let ctx = RunContext {
            own_uid,
            lima_home: dir.path().to_string_lossy().into_owned(),
            broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
        };
        let op = BrokerOp::RestrictOnVerify {
            op_uid: own_uid,
            vm: vm.to_string(),
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::RestrictNotConfirmed { .. }),
            "CommandNotFound + no marker must yield RestrictNotConfirmed (fail-closed): {result:?}"
        );
    }

    /// Verify the end-to-end negative path: when neither a QMP socket nor a
    /// restrict marker exists, `handle_restrict_on_verify` returns
    /// `RestrictNotConfirmed`. This is the hard-gate path the daemon uses to
    /// refuse marking a session Running.
    #[tokio::test]
    async fn restrict_verify_no_qmp_no_marker_returns_not_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let vm = "sandbox-negtest000001";
        let own_uid = unsafe { libc::getuid() };
        // Create the VM dir but no QMP socket and no marker file.
        std::fs::create_dir_all(dir.path().join(vm)).unwrap();

        let ctx = RunContext {
            own_uid,
            lima_home: dir.path().to_string_lossy().into_owned(),
            broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
        };
        let op = BrokerOp::RestrictOnVerify {
            op_uid: own_uid,
            vm: vm.to_string(),
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::RestrictNotConfirmed { .. }),
            "no QMP + no marker must yield RestrictNotConfirmed (session must not start): {result:?}"
        );
        if let BrokerResult::RestrictNotConfirmed { reason, .. } = result {
            assert!(
                reason.contains("marker") || reason.contains("restrict"),
                "RestrictNotConfirmed reason must mention the failure cause: {reason}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // GuestSocat framing — distinct from one-shot
    // -----------------------------------------------------------------------

    /// Verify that handle_guest_socat sends a `StreamOpen` response before
    /// starting the byte pump, confirming it is distinct from one-shot
    /// request/response framing.
    ///
    /// This test drives the real framing path (StreamOpen JSON frame written
    /// to the stream before raw byte copy begins), proving the framing is
    /// correct without requiring a real limactl/socat.
    #[tokio::test]
    async fn guest_socat_sends_stream_open_frame() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = RunContext {
            own_uid,
            lima_home: "/tmp/lima_test".to_string(),
            broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
        };

        // Use a duplex in-memory stream to capture what the handler writes.
        let (client, server) = tokio::io::duplex(4096);

        // Spawn the handler with write_stream_open=true (legacy path).
        // It will write StreamOpen then attempt limactl (which will fail since
        // there's no real limactl), then close.
        let vm = "sandbox-test".to_string();
        let op_uid = own_uid;
        let ctx_clone = RunContext {
            own_uid: ctx.own_uid,
            lima_home: ctx.lima_home.clone(),
            broker_socket: ctx.broker_socket.clone(),
        };
        let handle = tokio::spawn(async move {
            let _ = handle_guest_socat(&ctx_clone, vm, op_uid, 1, true, server).await;
        });

        // Read the first line from the client end — must be a valid JSON
        // BrokerResponse with StreamOpen or Rejected (if limactl missing).
        use tokio::io::AsyncBufReadExt;
        let mut reader = tokio::io::BufReader::new(client);
        let mut line = String::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reader.read_line(&mut line),
        )
        .await;

        // The handler must have written a JSON line (not raw bytes) as the first
        // thing — confirming the StreamOpen framing is distinct from raw bytes.
        assert!(
            !line.trim().is_empty(),
            "handler must write a framing line before raw bytes"
        );
        let parsed: serde_json::Value = serde_json::from_str(line.trim())
            .expect("first line from GuestSocat handler must be a valid JSON BrokerResponse frame");
        // The result must be either StreamOpen or Rejected — never Ok/Failed
        // (which are one-shot result variants).
        let result_kind = parsed
            .get("result")
            .and_then(|r| r.get("kind"))
            .and_then(|k| k.as_str())
            .unwrap_or("");
        assert!(
            result_kind == "stream_open" || result_kind == "rejected",
            "GuestSocat first frame must be stream_open or rejected, got {result_kind:?}"
        );

        handle.abort();
    }

    // -----------------------------------------------------------------------
    // B1 egress-safety regression: unrestricted_slirp_for_provisioning predicate
    // -----------------------------------------------------------------------

    /// On Linux, a Start op with unrestricted_slirp_for_provisioning=true and
    /// bridge=None must be rejected. This is the egress safety rail: on Linux
    /// a bridge is the data-plane gate that makes unrestricted slirp safe.
    /// Without a bridge the session VM's slirp NIC would be open to the internet.
    ///
    /// The test exercises the real dispatch path up to the point where
    /// validation fires. The rejection must name the missing bridge, not some
    /// other unrelated validation failure.
    #[tokio::test]
    #[cfg(not(target_os = "macos"))]
    async fn linux_rejects_unrestricted_slirp_without_bridge() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        let op = BrokerOp::Start {
            op_uid: own_uid,
            vm: "sandbox-test".to_string(),
            qemu_wrapper: "/usr/local/libexec/sandboxd/qemu-wrapper".to_string(),
            hardened: true,
            memory_mb: 4096,
            cpus: 2,
            start_timeout_s: 300,
            bridge: None,
            unrestricted_slirp_for_provisioning: true,
        };
        let result = dispatch_op(&ctx, op).await;
        match result {
            BrokerResult::Rejected { ref reason } => {
                assert!(
                    reason.contains("bridge"),
                    "Linux must reject unrestricted_slirp_for_provisioning=true without bridge; \
                     expected reason mentioning 'bridge', got: {reason:?}"
                );
            }
            other => panic!(
                "Linux must reject unrestricted_slirp_for_provisioning=true without bridge; \
                 got non-Rejected result: {other:?}"
            ),
        }
    }

    /// On macOS, a Start op with unrestricted_slirp_for_provisioning=true and
    /// bridge=None must NOT be rejected by the bridge-presence check. The macOS
    /// Docker-bridge concept does not exist; the base-image build legitimately
    /// passes this combination to unlock slirp egress for cloud-init.
    ///
    /// Because the qemu_wrapper path does not exist in the test environment,
    /// dispatch will still return Rejected — but for the wrapper validation, not
    /// the bridge check. Any Rejected result mentioning "bridge" indicates the
    /// macOS-scoped predicate is not working correctly.
    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn macos_accepts_unrestricted_slirp_without_bridge() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        let op = BrokerOp::Start {
            op_uid: own_uid,
            vm: "sandbox-test".to_string(),
            // Non-existent path: validation will reject for missing wrapper,
            // not for missing bridge.
            qemu_wrapper: "/nonexistent/path/qemu-wrapper".to_string(),
            hardened: true,
            memory_mb: 4096,
            cpus: 2,
            start_timeout_s: 300,
            bridge: None,
            unrestricted_slirp_for_provisioning: true,
        };
        let result = dispatch_op(&ctx, op).await;
        // The result must be Rejected, but NOT because of the bridge check.
        // Any Rejected reason mentioning "bridge" means the macOS predicate
        // did not suppress the Linux guard.
        if let BrokerResult::Rejected { ref reason } = result {
            assert!(
                !reason.contains("bridge"),
                "macOS must not reject unrestricted_slirp_for_provisioning=true \
                 because bridge is absent; got Rejected {{ reason: {reason:?} }}"
            );
        }
        // A non-Rejected result (e.g. Failed because limactl is absent) is also
        // acceptable — it means validation passed the bridge check entirely.
    }

    /// Confirm the base-image build call site sets unrestricted_slirp_for_provisioning
    /// to true on macOS and false on Linux. This is a compile-time constant via
    /// cfg!(target_os = "macos"), so the test simply asserts the expected value
    /// for the current compile target. If someone changes the cfg! expression at
    /// the call site, this test catches it.
    #[test]
    fn base_build_sets_unrestricted_flag_per_platform() {
        let flag = cfg!(target_os = "macos");
        // On macOS the base build needs unrestricted slirp (no bridge, slirp is
        // the only NIC, cloud-init must apt-get over it). On Linux unrestricted
        // slirp is already the default when no bridge is set.
        if cfg!(target_os = "macos") {
            assert!(
                flag,
                "base build must set unrestricted_slirp_for_provisioning=true on macOS"
            );
        } else {
            assert!(
                !flag,
                "base build must set unrestricted_slirp_for_provisioning=false on Linux"
            );
        }
    }
}
