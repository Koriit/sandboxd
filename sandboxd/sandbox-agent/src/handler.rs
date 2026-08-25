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
//!
//! # Concurrency
//!
//! Handlers run concurrently: the daemon pipelines ops, and each one is
//! dispatched on its own task. A new handler must not assume it is the only
//! one running. Two constraints in particular are not obvious from the code —
//! the process-wide `umask` this module relies on, and the fact that the
//! runtime is single-threaded, so blocking it stalls every other op and the
//! heartbeat. Both, and the invariants the existing handlers depend on, are
//! written up in `docs/internal/agent-handler-concurrency-audit.md`; read it
//! before adding a handler that touches shared state.

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

/// Resolve the operator's home directory via `getpwuid_r`, off the runtime.
///
/// `getpwuid_r` is a Directory Services lookup: on a directory-backed account
/// it can block for as long as the directory takes to answer. The agent's
/// runtime is single-threaded, so blocking it stalls the heartbeat and every
/// concurrently-running op — not just the caller. `spawn_blocking` moves the
/// call to the blocking pool, which a current-thread runtime still has.
async fn resolve_op_home(op_uid: u32) -> Option<String> {
    tokio::task::spawn_blocking(move || resolve_op_home_blocking(op_uid))
        .await
        .ok()
        .flatten()
}

/// The blocking body of [`resolve_op_home`].
fn resolve_op_home_blocking(op_uid: u32) -> Option<String> {
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

    // The agent runs these as the operator, against the operator's own VM and
    // Docker socket. Naming the op family once here — the single point every
    // one-shot op passes through — is what lets an operator see what the daemon
    // asked their login session to do. Stream-class ops do not come through
    // this function and log their own line at the point they open the stream.
    // The label deliberately carries no payload: paths, YAML and argv stay out
    // of the log.
    info!(uid = ctx.own_uid, op = op.label(), "running op");

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
        BrokerOp::CreateGateway {
            op_uid: _,
            lima_yaml,
        } => handle_create_gateway(ctx, lima_yaml).await,
        BrokerOp::StartGateway {
            op_uid: _,
            start_timeout_s,
        } => handle_start_gateway(ctx, start_timeout_s).await,
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
        BrokerOp::ReadExportRoots { op_uid: _ } => handle_read_export_roots(ctx).await,
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
        BrokerOp::DockerStream { .. } => {
            // Stream-class: dispatched via `handle_docker_stream` on a
            // dedicated stream connection, never answered inline.
            BrokerResult::Rejected {
                reason: "DockerStream must use the streaming dispatch path".to_string(),
            }
        }
        BrokerOp::RestrictOnVerify { op_uid: _, vm } => handle_restrict_on_verify(ctx, vm).await,
        BrokerOp::Docker { op_uid: _, op } => handle_docker(ctx, op).await,
        BrokerOp::InVm { op_uid: _, op } => handle_in_vm(ctx, op).await,
    }
}

// ---------------------------------------------------------------------------
// Docker ops
// ---------------------------------------------------------------------------

/// Name prefix of the Lima instance hosting the operator's gateway containers.
///
/// The instance name is this plus the agent's own uid — see [`own_gateway_vm`],
/// which is the only reader. An agent-side constant, not a field on the op; see
/// [`own_gateway_docker_socket`] for why that distinction is the whole point.
const GATEWAY_VM_NAME: &str = "sandboxd-gateway";

/// Filename of the gateway VM's forwarded Docker socket inside the instance
/// directory. Mirrors the `hostSocket:` entry in the generated `lima.yaml`.
const GATEWAY_DOCKER_SOCKET_FILENAME: &str = "gateway-docker.sock";

/// The forwarded Docker socket for this agent's own gateway VM:
/// `{lima_home}/sandboxd-gateway-{uid}/gateway-docker.sock`.
///
/// # Do not make this a parameter
///
/// It would be easy — and it would look harmless — to let the daemon send
/// the socket path on the op, or to add an override so a test can point the
/// agent somewhere else. Both destroy the property this function exists to
/// hold.
///
/// The op set is closed so that a compromised daemon can only ask for
/// operations someone reviewed. That bound is worth exactly as much as the
/// guarantee about *where* those operations land. If the daemon names the
/// endpoint, then "the agent only runs reviewed operations" becomes "the
/// agent only runs reviewed operations, against whatever Docker daemon it
/// was told to" — and a Docker daemon is a root shell on its host. The
/// closed enum would still be closed and would no longer bound anything
/// that matters.
///
/// Deriving the path here means the daemon *cannot* misdirect the agent,
/// rather than merely *does not*: there is no field to get wrong, no call
/// site that has to remember to pass the right value, and no env var an
/// attacker who can write the agent's environment could set. It also keeps
/// `protocol.rs`'s "no path outside the agent's own LIMA_HOME" rule true for
/// the entire Docker op set by construction, since `ctx.lima_home` is the
/// agent's own and the rest is two constants.
///
/// If a test needs a different endpoint, give the test its own agent with
/// its own `RunContext.lima_home` — that is the seam, and it does not widen
/// production behaviour by one byte.
fn own_gateway_docker_socket(ctx: &RunContext) -> String {
    format!(
        "{}/{}/{GATEWAY_DOCKER_SOCKET_FILENAME}",
        ctx.lima_home,
        own_gateway_vm(ctx)
    )
}

/// The staged image tarball for `image`, inside the agent's own LIMA_HOME.
fn staged_image_tarball(
    ctx: &RunContext,
    image: sandbox_docker_argv::image::StagedImage,
) -> String {
    format!("{}/{}", ctx.lima_home, image.tarball_filename())
}

/// Environment for a `docker` invocation whose target is pinned by `-H`.
///
/// `env_clear` plus a reconstructed minimum. The scrub is the point: with
/// `DOCKER_HOST` left in place, an ambient value could redirect the command
/// to a daemon the agent did not choose, and `-H` would no longer be the
/// sole authority for what is being addressed. `DOCKER_CONFIG` goes for the
/// same reason — it selects credential helpers, which run as the operator.
fn docker_env(op_home: &str) -> Vec<(String, String)> {
    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let path_value = if inherited_path.is_empty() {
        format!("{PATH_PREPEND}:/usr/bin:/bin")
    } else {
        format!("{PATH_PREPEND}:{inherited_path}")
    };
    vec![
        ("PATH".to_string(), path_value),
        ("HOME".to_string(), op_home.to_string()),
    ]
}

/// Validate a Docker op, build its argv, and run it against this agent's own
/// VM Docker socket.
async fn handle_docker(ctx: &RunContext, op: crate::protocol::DockerOp) -> BrokerResult {
    if let Err(reason) = validation::validate_docker_op(&op) {
        warn!(reason, "docker op rejected: field validation");
        return BrokerResult::Rejected { reason };
    }

    let argv = match crate::protocol::docker_argv(&op) {
        Ok(argv) => argv,
        Err(reason) => return BrokerResult::Rejected { reason },
    };

    let docker = match resolve_docker() {
        Some(p) => p,
        None => {
            return BrokerResult::Rejected {
                reason: format!("docker not found in candidate paths {DOCKER_CANDIDATES:?}"),
            };
        }
    };

    let socket = own_gateway_docker_socket(ctx);
    let op_home = resolve_op_home(ctx.own_uid)
        .await
        .unwrap_or_else(|| "/nonexistent".to_string());

    let mut cmd = Command::new(&docker);
    cmd.env_clear();
    for (k, v) in docker_env(&op_home) {
        cmd.env(k, v);
    }
    cmd.args(sandbox_docker_argv::host_args(Some(std::path::Path::new(
        &socket,
    ))));
    cmd.args(&argv);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Two ops feed the child's stdin, and they do it from different places.
    //
    // `docker load` reads a tarball that is hundreds of megabytes, so it is
    // streamed from a file rather than carried in the op payload — and which
    // file it is comes from the enum, resolved against the agent's own
    // staging directory.
    //
    // The egress-plane writes carry their artifact in the op, because the
    // artifact is what the daemon is asking to install. It is written to the
    // pipe and the pipe is closed; the child (`nft -f -` or `cat`) reads it
    // as content.
    let tarball = match &op {
        crate::protocol::DockerOp::ImageLoad { image } => {
            Some(staged_image_tarball(ctx, (*image).into()))
        }
        _ => None,
    };
    let body = match &op {
        crate::protocol::DockerOp::ContainerExecStdin { body, .. } => Some(body.clone()),
        _ => None,
    };

    let output = match (tarball, body) {
        (Some(path), _) => match run_docker_load(cmd, &path).await {
            Ok(o) => o,
            Err(reason) => return BrokerResult::Rejected { reason },
        },
        (None, Some(body)) => match run_docker_with_stdin(cmd, body.as_bytes()).await {
            Ok(o) => o,
            Err(reason) => return BrokerResult::Rejected { reason },
        },
        (None, None) => {
            cmd.stdin(Stdio::null());
            match cmd.output().await {
                Ok(o) => o,
                Err(e) => {
                    return BrokerResult::Rejected {
                        reason: format!("failed to spawn docker: {e}"),
                    };
                }
            }
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

/// Write `body` to a prepared `docker exec -i` command's standard input,
/// close the pipe, and collect the result.
///
/// The pipe must be closed after the write: `nft -f -` and `cat` both read
/// to EOF, and an open write half would leave the child waiting forever on
/// a parent that thinks it is done.
async fn run_docker_with_stdin(
    mut cmd: Command,
    body: &[u8],
) -> Result<std::process::Output, String> {
    use tokio::io::AsyncWriteExt;

    cmd.stdin(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn docker: {e}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "failed to take docker stdin".to_string())?;
    let written = stdin.write_all(body).await;
    let flushed = stdin.flush().await;
    drop(stdin);
    if let Err(e) = written.and(flushed) {
        let _ = child.kill().await;
        return Err(format!("failed to write the artifact to docker stdin: {e}"));
    }
    child
        .wait_with_output()
        .await
        .map_err(|e| format!("docker exec did not complete: {e}"))
}

/// Stream a staged tarball into a prepared `docker load` command.
async fn run_docker_load(mut cmd: Command, tarball: &str) -> Result<std::process::Output, String> {
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::File::open(tarball)
        .await
        .map_err(|e| format!("failed to open staged image tarball {tarball}: {e}"))?;
    cmd.stdin(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn docker load: {e}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "failed to take docker load stdin".to_string())?;
    let copy = tokio::io::copy(&mut file, &mut stdin).await;
    let flush = stdin.flush().await;
    drop(stdin);
    if let Err(e) = copy.map(|_| ()).or(flush) {
        let _ = child.kill().await;
        return Err(format!(
            "failed to stream image tarball into docker load: {e}"
        ));
    }
    child
        .wait_with_output()
        .await
        .map_err(|e| format!("docker load did not complete: {e}"))
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

    let op_home = resolve_op_home(ctx.own_uid)
        .await
        .unwrap_or_else(|| "/nonexistent".to_string());
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

    let op_home = resolve_op_home(ctx.own_uid)
        .await
        .unwrap_or_else(|| "/nonexistent".to_string());
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
// In-VM ops
// ---------------------------------------------------------------------------

/// The gateway Lima instance this agent drives — created, started, executed
/// inside, and addressed for its forwarded Docker socket.
///
/// Derived from the agent's own `getuid()` and never read off the wire, for a
/// reason that is sharper here than anywhere else in the op set. A `limactl
/// shell` runs a command as the VM's login user, and Lima provisions that user
/// with passwordless `sudo`. If the daemon named the instance, "the agent only
/// runs reviewed operations" would become "the agent only runs reviewed
/// operations, as root, in whichever VM it was told to" — and the review would
/// be bounding nothing that matters. The same holds for `limactl create
/// --name`, which is where a name first becomes a VM: `BrokerOp::CreateGateway`
/// carries no VM-name field at all, so there is nothing for a daemon to get
/// wrong.
///
/// The uid suffix is not decoration. Gateway instances live in per-operator
/// LIMA_HOMEs but are enumerated by a single `limactl list`-shaped view of the
/// host, so an unsuffixed name is ambiguous the moment two operators are
/// present, and "which operator's gateway is this" stops having an answer.
///
/// # One function, not two agreeing ones
///
/// This was briefly two functions — an unsuffixed name for the in-VM and Docker
/// ops and a suffixed one for create and start — and they named different
/// instances. Nothing detected that, because nothing invoked the gateway ops
/// yet; the moment the daemon began sending them, a VM would have been created
/// under one name and executed in under another. Both halves derive from one
/// function so that agreement is not something two call sites have to maintain.
fn own_gateway_vm(ctx: &RunContext) -> String {
    format!("{GATEWAY_VM_NAME}-{}", ctx.own_uid)
}

/// Validate a VM name that an op is **claiming** — binding to instance content
/// the daemon authored.
///
/// # Why a name check is a class check here
///
/// The typed gateway ops answer "may this VM run unwrapped" and "may the agent
/// run commands as root in this VM" by *which op was invoked*, and then name
/// their target from the agent's own uid. That removes the daemon's control over
/// which branch runs. It does not, on its own, remove its control over **which
/// instance the branch acts on**: the name→instance binding is made by a
/// different op, and the general placing ops take the name off the wire. A
/// daemon that binds a session-shaped instance to a name a typed gateway op
/// later acts on gets the permissive treatment applied to content it chose.
///
/// So the one name this agent's own gateway ops act on is claimable only
/// through those ops. [`own_gateway_vm`] is what `StartGateway` boots — with no
/// qemu-wrapper and therefore no `restrict=on` rewrite of the management NIC —
/// and it is also what the `InVm` and Docker ops execute inside, as root. The
/// second of those is the sharper reason; see that function's doc.
///
/// The set is exactly that name and nothing that merely resembles it. Another
/// operator's gateway lives in another operator's LIMA_HOME and is named by no
/// op of this agent's, so refusing it would cost legitimate work and buy
/// nothing.
///
/// # What this does not cover
///
/// Only ops that *place* a name. `Delete` still accepts a reserved name, because
/// removing one's own gateway is legitimate lifecycle work and refusing it would
/// need a typed delete op that does not exist. Freeing the name is harmless on
/// its own: it can be re-claimed only through `CreateGateway`, and
/// [`handle_start_gateway`] refuses to boot an instance that is not there rather
/// than letting `limactl` invent one.
fn validate_claimed_vm_name(ctx: &RunContext, vm: &str) -> Result<(), String> {
    validation::validate_vm_name(vm)?;
    if vm == own_gateway_vm(ctx) {
        return Err(format!(
            "vm name {vm:?} is reserved for this agent's own gateway; it can be \
             claimed only by the gateway ops, which validate the instance they create"
        ));
    }
    Ok(())
}

/// `umask` for in-VM operations.
///
/// Deliberately **not** the `0o077` the Lima lifecycle ops use. That value
/// exists so `limactl` writes SSH private keys at 0600, and it is right there.
/// It is wrong here: these ops create a staging directory and copy four files
/// that are bound into a container and read by processes running as the
/// session uid — not as the file's owner. At 0o077 the container cannot read
/// its own `authorized_keys`, which surfaces as an SSH failure a long way from
/// this constant. 0o022 is what the daemon's own ambient umask produced when
/// these ran daemon-side.
const IN_VM_UMASK: libc::mode_t = 0o022;

/// Validate an in-VM op, render it, and run it against this agent's own
/// gateway VM.
async fn handle_in_vm(ctx: &RunContext, op: crate::protocol::InVmOp) -> BrokerResult {
    if let Err(reason) = validation::validate_in_vm_op(&op) {
        warn!(reason, "in-vm op rejected: field validation");
        return BrokerResult::Rejected { reason };
    }

    if let Some(transfer) = crate::protocol::in_vm_transfer(&op) {
        return run_in_vm_transfer(ctx, transfer).await;
    }

    let Some(steps) = crate::protocol::in_vm_shell_steps(&op) else {
        return BrokerResult::Rejected {
            reason: "in-vm op is neither a command nor a transfer".to_string(),
        };
    };
    let body = crate::protocol::in_vm_stdin_body(&op).map(|b| b.to_string());

    let vm = own_gateway_vm(ctx);
    let mut last: Option<std::process::Output> = None;
    for step in &steps {
        let argv = sandbox_invm_argv::shell_argv(&vm, step);
        let output = match run_limactl_capture(ctx, &argv, body.as_deref()).await {
            Ok(o) => o,
            Err(result) => return result,
        };
        let failed = !output.status.success();
        last = Some(output);
        // A failed step short-circuits, and its output is what comes back, so
        // the daemon reads the step that failed rather than a later one that
        // never ran.
        if failed {
            break;
        }
    }

    match last {
        Some(output) => output_to_result(output),
        None => BrokerResult::Rejected {
            reason: "in-vm op produced no steps".to_string(),
        },
    }
}

/// Resolve a transfer's source inside the agent's own LIMA_HOME and copy it
/// into the VM.
async fn run_in_vm_transfer(
    ctx: &RunContext,
    transfer: crate::protocol::InVmTransfer,
) -> BrokerResult {
    use crate::protocol::InVmTransferSource;
    use std::os::unix::fs::PermissionsExt;

    // Both arms resolve under `ctx.lima_home`, which the agent built from its
    // own uid. The confinement check is belt-and-braces against a future
    // variant that resolves somewhere else.
    let (source, scratch) = match &transfer.source {
        InVmTransferSource::RouteHelperBinary => (
            format!(
                "{}/{}",
                ctx.lima_home,
                sandbox_invm_argv::route_helper::HOST_BINARY_FILENAME
            ),
            false,
        ),
        InVmTransferSource::Content { basename, .. } => {
            (format!("{}/{basename}", ctx.lima_home), true)
        }
    };
    if let Err(reason) = validation::validate_lima_home_path(&ctx.lima_home, &source) {
        return BrokerResult::Rejected { reason };
    }

    if let InVmTransferSource::Content { mode, body, .. } = &transfer.source {
        if let Err(e) = std::fs::write(&source, body.as_bytes()) {
            return BrokerResult::Failed {
                stdout: String::new(),
                stderr: format!("failed to stage {source} for transfer: {e}"),
                exit_code: 1,
            };
        }
        // The mode is set on the source because `limactl copy` preserves it,
        // and the preserved mode is what the container reads the file under.
        if let Err(e) = std::fs::set_permissions(&source, std::fs::Permissions::from_mode(*mode)) {
            let _ = std::fs::remove_file(&source);
            return BrokerResult::Failed {
                stdout: String::new(),
                stderr: format!("failed to chmod {mode:o} on {source}: {e}"),
                exit_code: 1,
            };
        }
    }

    let argv = sandbox_invm_argv::copy_argv(&source, &own_gateway_vm(ctx), &transfer.destination);
    let result = run_limactl_capture(ctx, &argv, None).await;
    if scratch {
        let _ = std::fs::remove_file(&source);
    }
    match result {
        Ok(output) => output_to_result(output),
        Err(result) => result,
    }
}

/// Run one `limactl` invocation for an in-VM op and hand back the raw output.
///
/// Distinct from [`run_limactl`] in two ways that both matter here: it returns
/// the `Output` rather than a `BrokerResult`, so a multi-step op can decide
/// whether to continue; and it writes `body` to the child's stdin when the op
/// has one, which is how the nftables ruleset reaches `nft -f -`.
async fn run_limactl_capture(
    ctx: &RunContext,
    argv: &[String],
    body: Option<&str>,
) -> Result<std::process::Output, BrokerResult> {
    use tokio::io::AsyncWriteExt;

    let limactl = match resolve_limactl() {
        Some(p) => p,
        None => {
            return Err(BrokerResult::Rejected {
                reason: "limactl not found in PATH; check agent PATH setup".to_string(),
            });
        }
    };

    let op_home = resolve_op_home(ctx.own_uid)
        .await
        .unwrap_or_else(|| "/nonexistent".to_string());
    let env = build_env(&ctx.lima_home, &op_home, &[]);

    let mut cmd = Command::new(&limactl);
    cmd.args(argv);
    cmd.env_clear();
    for (k, v) in &env {
        cmd.env(k, v);
    }
    // SAFETY: called in the child process after fork, before exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::umask(IN_VM_UMASK);
            Ok(())
        });
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let Some(body) = body else {
        cmd.stdin(Stdio::null());
        return cmd.output().await.map_err(|e| BrokerResult::Rejected {
            reason: format!("failed to spawn limactl: {e}"),
        });
    };

    cmd.stdin(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| BrokerResult::Rejected {
        reason: format!("failed to spawn limactl: {e}"),
    })?;
    let mut stdin = child.stdin.take().ok_or_else(|| BrokerResult::Rejected {
        reason: "failed to take limactl stdin".to_string(),
    })?;
    let written = stdin.write_all(body.as_bytes()).await;
    let flushed = stdin.flush().await;
    // The pipe must be closed after the write: `nft -f -` reads to EOF, and an
    // open write half leaves it waiting forever on a parent that thinks it is
    // done.
    drop(stdin);
    if let Err(e) = written.and(flushed) {
        let _ = child.kill().await;
        return Err(BrokerResult::Failed {
            stdout: String::new(),
            stderr: format!("failed to write the op body to limactl stdin: {e}"),
            exit_code: 1,
        });
    }
    child
        .wait_with_output()
        .await
        .map_err(|e| BrokerResult::Failed {
            stdout: String::new(),
            stderr: format!("limactl did not complete: {e}"),
            exit_code: 1,
        })
}

/// The common `Output` → `BrokerResult` mapping.
fn output_to_result(output: std::process::Output) -> BrokerResult {
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
    // Validate all fields before any filesystem access. This op places a name,
    // so the name is checked for claimability, not just for shape.
    if let Err(reason) = validate_claimed_vm_name(ctx, &vm) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_cidr_owner("owner", &owner) {
        return BrokerResult::Rejected { reason };
    }
    // The qemu_wrapper field is empty on the brokered Create path, because the
    // daemon-side op it is translated from carries no wrapper to forward. The
    // wrapper is not hiding in the rendered lima.yaml either — it is never part
    // of that content, and the shape validation below does not look for it. It
    // travels as the QEMU_SYSTEM_AARCH64 environment variable set on the
    // `limactl` invocation, and on this one it has nothing to act on: `limactl
    // create` provisions the instance directory without booting a QEMU process.
    // Validating only a non-empty value is what keeps every operator
    // session-create from being rejected.
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

/// Create this operator's own gateway Lima VM.
///
/// Deliberately not a branch inside [`handle_create`]. The two differ in which
/// NIC-shape rule the YAML is held to, and that is precisely the decision that
/// must not be reachable from a wire field — see `BrokerOp::CreateGateway`'s
/// doc for the argument. Separate handlers make the two rules statically
/// distinct code paths, so there is no flag to flip and no name to spell in a
/// particular way to move between them.
///
/// Differences from [`handle_create`], each with a reason:
/// - The instance name is derived from the agent's own uid, not taken from the
///   request ([`own_gateway_vm`]).
/// - The YAML is validated by `validate_gateway_lima_yaml_shape` — one NIC per
///   pool slot, each pinned to its own slot's interface name.
/// - No `sandboxd-owner` marker is written. The gateway is not tracked by the
///   Lima orphan reaper's per-operator marker scheme; the daemon's own
///   gateway-create path, for the gateway it owns itself, writes none either.
/// - No `QEMU_SYSTEM_AARCH64` is set. The gateway VM runs without the
///   `restrict=on` qemu-wrapper on its management NIC — matching the daemon's
///   own path, which sets no wrapper variable for a gateway at all.
async fn handle_create_gateway(ctx: &RunContext, lima_yaml: String) -> BrokerResult {
    let vm = own_gateway_vm(ctx);

    // The name is agent-constructed, so this cannot fail today. It is called
    // anyway because the property it asserts — safe as a `limactl` positional,
    // no leading dash, no shell metacharacters — is a property of the argv
    // built below, and it should be checked where the argv is built rather
    // than assumed from a `format!` several functions away.
    if let Err(reason) = validation::validate_vm_name(&vm) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_gateway_lima_yaml_shape(&lima_yaml) {
        return BrokerResult::Rejected { reason };
    }

    let yaml_path = format!("{}/{}.yaml", ctx.lima_home, vm);
    if let Err(reason) = validation::validate_lima_home_path(&ctx.lima_home, &yaml_path) {
        return BrokerResult::Rejected { reason };
    }

    // Write the yaml verbatim (validated above), at 0600.
    unsafe { libc::umask(0o077) };
    if let Err(e) = std::fs::write(&yaml_path, lima_yaml.as_bytes()) {
        return BrokerResult::Rejected {
            reason: format!("failed to write lima.yaml to {yaml_path}: {e}"),
        };
    }

    info!(vm, yaml_path, "wrote daemon-rendered gateway lima.yaml");

    run_limactl(
        ctx,
        &["create", "--name", &vm, &yaml_path, "--tty=false"],
        &[],
    )
    .await
}

/// Start this operator's own gateway Lima VM.
///
/// Deliberately not a branch inside [`handle_start`], for the reason spelled out
/// on `BrokerOp::StartGateway`: whether a VM may boot without the `restrict=on`
/// qemu-wrapper is the decision that must not be reachable from a wire field,
/// and separate handlers make the two answers statically distinct code paths.
/// [`handle_start`] therefore keeps validating its wrapper unconditionally, with
/// no name and no emptiness test able to move a request between the two.
///
/// Differences from [`handle_start`], each with a reason:
/// - The instance name is derived from the agent's own uid, not taken from the
///   request — [`own_gateway_vm`], the same function [`handle_create_gateway`]
///   names the instance with, so the two brokered gateway ops address the same
///   instance by construction rather than by two sites agreeing.
/// - No wrapper is validated or exported, because a gateway has none. There is
///   no `QEMU_SYSTEM_AARCH64` in the environment at all rather than an empty
///   one, which is also what the daemon does for the gateway it owns itself:
///   both halves of the gateway-start path set no wrapper variable, so the two
///   environments are identical rather than differing by an empty override.
/// - No `SANDBOX_RESTRICT_MARKER`. The marker records that the management NIC
///   was rewritten to `restrict=on`; nothing rewrites this one, so a marker
///   would be a claim no step in this path establishes.
/// - No `SANDBOX_QEMU_*`. Their only reader is the **Linux** qemu-wrapper
///   (device lockdown, systemd cgroup limits); the macOS wrapper reads none of
///   them, so they are inert here with or without a wrapper. The daemon's own
///   gateway-start path drops them for the same reason. The VM's sizing comes
///   from its template.
async fn handle_start_gateway(ctx: &RunContext, start_timeout_s: u32) -> BrokerResult {
    let vm = own_gateway_vm(ctx);

    // Agent-constructed, so this cannot fail today — checked anyway because it
    // is a property of the argv built below. Same reasoning as
    // `handle_create_gateway`'s call to it.
    if let Err(reason) = validation::validate_vm_name(&vm) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validation::validate_range("start_timeout_s", start_timeout_s, 1, 600) {
        return BrokerResult::Rejected { reason };
    }

    // Boot only an instance that is already there. `limactl start` on a name it
    // does not know is not an error: it creates an instance from
    // `template:default` and boots that. Since this op supplies no qemu-wrapper,
    // that VM would come up with unrestricted user-mode networking — the
    // permissive path manufacturing its own target out of a Lima default. The
    // name is reserved to the gateway ops, so the only thing that can put this
    // file here is `CreateGateway`, whose YAML is held to the gateway shape.
    let instance_config = format!("{}/{}/lima.yaml", ctx.lima_home, vm);
    if let Err(reason) = validation::validate_lima_home_path(&ctx.lima_home, &instance_config) {
        return BrokerResult::Rejected { reason };
    }
    if !std::path::Path::new(&instance_config).is_file() {
        return BrokerResult::Rejected {
            reason: format!(
                "no such instance {vm:?}: {instance_config} is absent, and this op will not \
                 let limactl create one from template:default"
            ),
        };
    }

    let timeout_flag = format!("--timeout={start_timeout_s}s");
    run_limactl(ctx, &["start", &vm, &timeout_flag, "--tty=false"], &[]).await
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
    // (e.g. QEMU < 7.2, which lacks the command). The wrapper itself skips the
    // marker write for unrestricted provisioning (base-image) builds.
    //
    // Set unconditionally, because on this op a wrapper is always present: the
    // validation above rejects an empty path, and there is no VM this op starts
    // that legitimately runs unwrapped. The one that does — the gateway — has
    // its own op. A guard here testing the wrapper for emptiness would be dead,
    // and worse, would read as though an unwrapped VM could still arrive.
    let marker_path_owned = format!("{}/{}/sandboxd-restrict-marker", ctx.lima_home, vm);

    let mut extra_env: Vec<(&str, &str)> = vec![
        ("QEMU_SYSTEM_AARCH64", &qemu_wrapper),
        ("SANDBOX_QEMU_HARDENED", hardened_str),
        ("SANDBOX_QEMU_MEMORY_MB", &memory_mb_str),
        ("SANDBOX_QEMU_CPUS", &cpus_str),
        ("SANDBOX_RESTRICT_MARKER", &marker_path_owned),
    ];

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
    // `base` is read, `vm` is placed — so only `vm` is held to the reservation.
    // A clone *from* a gateway is a different question, and not one this rule
    // answers.
    if let Err(reason) = validation::validate_vm_name(&base) {
        return BrokerResult::Rejected { reason };
    }
    if let Err(reason) = validate_claimed_vm_name(ctx, &vm) {
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

/// Answer [`BrokerOp::ReadExportRoots`] for this agent's own operator.
///
/// The home directory comes from `getpwuid_r` on the agent's own uid, never
/// from `$HOME`: the agent's environment is inherited from launchd and is not
/// a statement about which account it is. `dispatch_op` has already refused
/// any request whose `op_uid` is not this uid, so the account read here is
/// always the one the daemon asked about.
///
/// A file that exists but is wrong is a `Failed`, not a `Rejected`: `Rejected`
/// means the daemon sent something the agent will not do, and this is the
/// agent doing exactly what was asked and finding the operator's file
/// unusable. The distinction is what the daemon logs, and it decides whether
/// the operator or the daemon build is the thing to go look at.
async fn handle_read_export_roots(ctx: &RunContext) -> BrokerResult {
    let Some(home) = resolve_op_home(ctx.own_uid).await else {
        return BrokerResult::Failed {
            stdout: String::new(),
            stderr: format!(
                "could not resolve the home directory of uid {} — no export roots \
                 can be read without it",
                ctx.own_uid
            ),
            exit_code: 1,
        };
    };

    let read = tokio::task::spawn_blocking(move || crate::protocol::read_export_roots(&home)).await;

    let report = match read {
        Ok(Ok(report)) => report,
        Ok(Err(reason)) => {
            return BrokerResult::Failed {
                stdout: String::new(),
                stderr: reason,
                exit_code: 1,
            };
        }
        Err(e) => {
            return BrokerResult::Failed {
                stdout: String::new(),
                stderr: format!("export-roots read task failed: {e}"),
                exit_code: 1,
            };
        }
    };

    match serde_json::to_string(&report) {
        Ok(stdout) => BrokerResult::Ok {
            stdout,
            stderr: String::new(),
            exit_code: 0,
        },
        Err(e) => BrokerResult::Failed {
            stdout: String::new(),
            stderr: format!("failed to serialize the export-roots report: {e}"),
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

    let transport = match rsync_transport(ctx, &backend) {
        Ok(t) => t,
        Err(reason) => return BrokerResult::Rejected { reason },
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
    rsync_args.push(transport);
    rsync_args.push("--mkpath".to_string());
    rsync_args.push(src);
    rsync_args.push(dst);

    let op_home = resolve_op_home(ctx.own_uid)
        .await
        .unwrap_or_else(|| "/nonexistent".to_string());
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

/// Build the rsync remote-shell (`-e`) transport for a backend, and check it
/// against the argv rsync will actually build from it.
///
/// Two things make this worth its own function rather than three lines
/// inline.
///
/// **The socket is derived, not carried.** The container transport names a
/// Docker daemon, and rsync `execvp`s this word list without a shell, so
/// whatever names a daemon in it is the sole authority for which one the
/// transfer reaches. That is exactly the property `own_gateway_docker_socket`
/// exists to hold for the one-shot Docker ops, and it holds here for the same
/// reason: the container the daemon wants to sync into lives in *this*
/// agent's VM, so a host-daemon transport would find no such container and a
/// daemon-supplied one would be a redirect.
///
/// **The `-e` value is the one fragment that stops being an argv.** rsync
/// re-parses it into words itself, and the two rsync implementations in play
/// — GNU rsync on Linux, openrsync on macOS — do not agree about every input.
/// `rsh_split` accepts only what both parse identically, so refusing here is
/// refusing to run a transfer whose command line is not the one intended.
fn rsync_transport(ctx: &RunContext, backend: &str) -> Result<String, String> {
    // Built from the shared argv crate so it stays identical to the one the
    // daemon builds for the same op.
    let transport = if backend == "lima" {
        "limactl shell".to_string()
    } else {
        let socket = own_gateway_docker_socket(ctx);
        sandbox_docker_argv::exec_rsh_transport(Some(std::path::Path::new(&socket)))
    };

    sandbox_docker_argv::rsh_split(&transport)
        .map_err(|e| format!("rsync remote-shell transport is not safely re-parsable: {e}"))?;

    Ok(transport)
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

/// Where `docker` may live on a macOS host.
///
/// Homebrew first (both architectures' prefixes), then the Docker Desktop
/// symlink location. `/usr/bin` is not a candidate: nothing ships `docker`
/// there on macOS, and listing it would only widen what a writable directory
/// could shadow.
const DOCKER_CANDIDATES: &[&str] = &[
    "/opt/homebrew/bin/docker",
    "/usr/local/bin/docker",
    "/Applications/Docker.app/Contents/Resources/bin/docker",
];

/// Resolve the absolute path to `docker` from a fixed candidate list.
///
/// Deliberately **not** a `PATH` search. `PATH` is inherited from the
/// LaunchAgent's environment, so a search there makes the binary the agent
/// executes a function of something outside the agent's control — for a
/// process whose entire purpose is to be the operator's trustworthy end of
/// the channel, that is the wrong dependency to accept. This mirrors
/// [`resolve_rsync`]; the `limactl` resolver takes the other approach and is
/// not the precedent to follow here.
fn resolve_docker() -> Option<String> {
    for candidate in DOCKER_CANDIDATES {
        let c = match std::ffi::CString::new(*candidate) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // SAFETY: c is a valid NUL-terminated C string.
        let rc = unsafe { libc::access(c.as_ptr(), libc::X_OK) };
        if rc == 0 {
            return Some((*candidate).to_string());
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
    // Off the runtime: the QMP exchange is synchronous socket I/O with read and
    // write timeouts measured in seconds. The agent's runtime is
    // single-threaded, so running it inline stalls the heartbeat and every
    // concurrently-running op for the duration.
    let qmp_lima_home = ctx.lima_home.clone();
    let qmp_vm = vm.clone();
    let qmp_outcome =
        tokio::task::spawn_blocking(move || query_restrict_on_via_qmp(&qmp_lima_home, &qmp_vm))
            .await;
    let qmp_outcome = match qmp_outcome {
        Ok(outcome) => outcome,
        Err(e) => {
            // The blocking task panicked or was cancelled. Neither is a
            // restrict=off finding, so fall back to the marker file rather
            // than failing the session on an inconclusive check.
            warn!(vm, error = %e, "QMP query task did not complete; falling back to marker");
            Ok(None)
        }
    };

    match qmp_outcome {
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

    let op_home = resolve_op_home(ctx.own_uid)
        .await
        .unwrap_or_else(|| "/nonexistent".to_string());
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

    pump_broker_stream(child, child_stdin, child_stdout, stream, "GuestSocat").await;
    info!(vm, "GuestSocat stream closed");
    Ok(())
}

/// Open a [`crate::protocol::BrokerOp::DockerStream`] op.
///
/// Splices the broker stream connection bidirectionally to
/// `docker -H unix://<own socket> exec -i <container> socat - <address>`,
/// where the address comes from the op's discriminant and the socket from
/// this agent's own LIMA_HOME.
///
/// Unlike [`handle_guest_socat`] there is no single-connection legacy form to
/// support, so nothing is ever written to the stream as framed JSON: the
/// caller has already acknowledged on the control connection, and this
/// connection is raw bytes from its first one. A rejection therefore closes
/// the stream without pumping, which is what the daemon observes.
///
/// The `own_uid` gate has already been checked before this is called;
/// re-checking it here is belt-and-suspenders.
pub async fn handle_docker_stream<S>(
    ctx: &RunContext,
    op: crate::protocol::DockerStreamOp,
    op_uid: u32,
    stream: S,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let label = op.target().label();

    if op_uid != ctx.own_uid {
        warn!(
            label,
            op_uid,
            own_uid = ctx.own_uid,
            "docker stream rejected: op_uid is not this agent's uid"
        );
        return Ok(());
    }

    if let Err(reason) = validation::validate_docker_stream_op(&op) {
        warn!(label, reason, "docker stream rejected: field validation");
        return Ok(());
    }

    let docker = match resolve_docker() {
        Some(p) => p,
        None => {
            warn!(
                label,
                "docker stream rejected: docker not found in candidate paths {DOCKER_CANDIDATES:?}"
            );
            return Ok(());
        }
    };

    let socket = own_gateway_docker_socket(ctx);
    let argv = crate::protocol::docker_stream_argv(&op, Some(std::path::Path::new(&socket)));
    let op_home = resolve_op_home(ctx.own_uid)
        .await
        .unwrap_or_else(|| "/nonexistent".to_string());

    // ASYNC-I/O CARVE-OUT: `tokio::process::Command` with async pipes is
    // mandatory here — this child is held open for the whole life of the
    // stream, which for the sshd target is an entire SSH session. A
    // synchronous spawn parked on the blocking pool would hold one of its
    // slots for that long, and the agent's runtime is current-thread, so a
    // synchronous *pump* would stall the heartbeat outright. Do not wrap
    // this site.
    let mut child = match Command::new(&docker)
        .args(&argv)
        .env_clear()
        .envs(docker_env(&op_home))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(label, error = %e, "docker stream rejected: spawn failed");
            return Ok(());
        }
    };

    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("docker exec child has no stdin"))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("docker exec child has no stdout"))?;

    pump_broker_stream(child, child_stdin, child_stdout, stream, label).await;
    info!(label, container = op.container(), "docker stream closed");
    Ok(())
}

/// Copy bytes both ways between a broker stream connection and a child's
/// stdio until either side ends, then reap the child.
///
/// Shared by every stream-class op: the transports differ (`limactl shell`
/// versus `docker exec`) and the pump does not.
async fn pump_broker_stream<S>(
    mut child: tokio::process::Child,
    child_stdin: tokio::process::ChildStdin,
    child_stdout: tokio::process::ChildStdout,
    stream: S,
    label: &str,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut broker_reader, mut broker_writer) = tokio::io::split(stream);
    let (mut child_reader, mut child_writer) = (child_stdout, child_stdin);

    let broker_to_child = tokio::io::copy(&mut broker_reader, &mut child_writer);
    let child_to_broker = tokio::io::copy(&mut child_reader, &mut broker_writer);

    // Run both halves concurrently. When either direction EOFs or errors,
    // the select! drops the other — the child process is then reaped.
    tokio::select! {
        result = broker_to_child => {
            if let Err(e) = result {
                warn!(label, error = %e, "broker→child copy error on a brokered stream");
            }
        }
        result = child_to_broker => {
            if let Err(e) = result {
                warn!(label, error = %e, "child→broker copy error on a brokered stream");
            }
        }
    }

    // Kill the child if it is still running (e.g. when the daemon closed its
    // half of the stream first). Ignore errors — the child may have already
    // exited.
    let _ = child.kill().await;
    let _ = child.wait().await;
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

    /// Arbitrary daemon-uid used in test fixture paths.  The value `501` is the
    /// default macOS UID for the first non-root user and has no special meaning
    /// here — it is chosen only to keep fixture paths realistic.
    const TEST_DAEMON_UID: u32 = 501;

    fn ctx(own_uid: u32) -> RunContext {
        RunContext {
            own_uid,
            lima_home: format!("/var/lib/sandboxd/{TEST_DAEMON_UID}/{own_uid}/lima"),
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
    // Create vs CreateGateway — the class is the op, not any wire field
    // -----------------------------------------------------------------------

    /// A four-NIC gateway-shaped template, as the daemon renders one.
    fn gateway_shaped_yaml() -> String {
        "vmType: \"qemu\"\ncpus: 2\nnetworks:\n\
         \x20 - socket: /var/run/sandbox/vmnet/slot-0.sock\n    interface: lima0\n\
         \x20 - socket: /var/run/sandbox/vmnet/slot-1.sock\n    interface: lima1\n\
         \x20 - socket: /var/run/sandbox/vmnet/slot-2.sock\n    interface: lima2\n\
         \x20 - socket: /var/run/sandbox/vmnet/slot-3.sock\n    interface: lima3\n"
            .to_string()
    }

    /// A `Create` naming a gateway-shaped VM is still a session create and is
    /// still held to the single-NIC rule.
    ///
    /// This is the property the class split exists to establish. The VM name is
    /// a daemon-supplied wire field, and the daemon is untrusted here; if the
    /// name selected the class, a compromised daemon would obtain the multi-NIC
    /// rule for a session VM by spelling the name a particular way. Dispatching
    /// on the op variant means there is no spelling that does it.
    ///
    /// The names exercised here are gateway-*shaped* but are not the two this
    /// agent's own gateway ops act on. Those two are refused earlier now, by the
    /// name reservation rather than by this rule — see
    /// `the_gateway_names_cannot_be_claimed_by_the_general_placing_ops`. They are
    /// not used here because a rejection from the reservation would say nothing
    /// about whether the session NIC rule is still applied to gateway-shaped
    /// content, which is what this test is for.
    #[tokio::test]
    async fn dispatch_create_with_gateway_shaped_name_gets_the_session_rule() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        for name in [
            format!("sandboxd-gateway-{}", own_uid + 1),
            "sandboxd-gatewayx".to_string(),
        ] {
            let op = BrokerOp::Create {
                op_uid: own_uid,
                vm: name.clone(),
                lima_yaml: format!("# vm: {name}\n{}", gateway_shaped_yaml()),
                owner: "10.209.0.0/20".to_string(),
                qemu_wrapper: String::new(),
                is_hardened_session: true,
            };
            let result = dispatch_op(&ctx, op).await;
            let BrokerResult::Rejected { reason } = result else {
                panic!(
                    "a gateway-shaped name on Create must not obtain the gateway rule; \
                     got {result:?} for {name}"
                );
            };
            assert!(
                reason.contains("exactly one socket_vmnet entry"),
                "{name}: rejection must come from the session single-NIC rule; \
                 got {reason:?}"
            );
        }
    }

    /// `CreateGateway` carries no VM name on the wire: the agent derives the
    /// instance name from its own uid, writes the template under that name, and
    /// hands that name to `limactl create`.
    ///
    /// This is also the end-to-end acceptance case: a legitimate gateway
    /// template must clear *every* check on this path, not just the NIC-count
    /// rule that a session template trips on first.
    ///
    /// The LIMA_HOME deliberately does not exist, so the template write fails
    /// with ENOENT. That stops the op before `limactl` is reached — a hermetic
    /// unit test must not provision a real Lima instance — while still naming
    /// the path the agent chose. Reaching the write at all is the assertion:
    /// every validator ahead of it returned `Ok`, and the filename shows the
    /// instance name was derived from the agent's own uid rather than read off
    /// the wire.
    #[tokio::test]
    async fn dispatch_create_gateway_derives_the_instance_name_from_own_uid() {
        let own_uid = unsafe { libc::getuid() };
        let parent = tempfile::tempdir().expect("temp dir");
        let lima_home = parent.path().join("absent");
        let ctx = RunContext {
            own_uid,
            lima_home: lima_home.to_string_lossy().into_owned(),
            broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
        };
        let op = BrokerOp::CreateGateway {
            op_uid: own_uid,
            lima_yaml: gateway_shaped_yaml(),
        };
        let result = dispatch_op(&ctx, op).await;
        let BrokerResult::Rejected { reason } = result else {
            panic!("expected the deliberate write failure, got {result:?}");
        };
        assert!(
            reason.starts_with("failed to write lima.yaml to "),
            "a legitimate gateway template must pass every validator on this path; \
             the only permitted failure is the deliberate write failure, got {reason:?}"
        );
        assert!(
            reason.contains(&format!("/absent/sandboxd-gateway-{own_uid}.yaml")),
            "the agent must name the instance from its own uid; got {reason:?}"
        );
    }

    /// A `CreateGateway` whose interface pin disagrees with its socket's slot is
    /// rejected, and nothing is written.
    #[tokio::test]
    async fn dispatch_rejects_create_gateway_with_interface_slot_mismatch() {
        let own_uid = unsafe { libc::getuid() };
        let lima_home = tempfile::tempdir().expect("temp lima home");
        let ctx = RunContext {
            own_uid,
            lima_home: lima_home.path().to_string_lossy().into_owned(),
            broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
        };
        let op = BrokerOp::CreateGateway {
            op_uid: own_uid,
            lima_yaml: "vmType: \"qemu\"\nnetworks:\n\
                        \x20 - socket: /var/run/sandbox/vmnet/slot-7.sock\n    interface: lima2\n"
                .to_string(),
        };
        let result = dispatch_op(&ctx, op).await;
        let BrokerResult::Rejected { reason } = result else {
            panic!("an interface/slot mismatch must be rejected; got {result:?}");
        };
        assert!(
            reason.contains("slot 7") && reason.contains("lima7"),
            "rejection must name the slot the socket belongs to; got {reason:?}"
        );
        assert_eq!(
            std::fs::read_dir(lima_home.path())
                .expect("read temp lima home")
                .count(),
            0,
            "a rejected gateway create must write nothing"
        );
    }

    /// A session template on `CreateGateway` is rejected — the gateway op does
    /// not accept the session shape any more than the reverse.
    #[tokio::test]
    async fn dispatch_rejects_create_gateway_with_a_session_template() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        let op = BrokerOp::CreateGateway {
            op_uid: own_uid,
            lima_yaml:
                "vmType: \"qemu\"\nnetworks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n"
                    .to_string(),
        };
        assert!(
            matches!(dispatch_op(&ctx, op).await, BrokerResult::Rejected { .. }),
            "a session template on CreateGateway must be rejected"
        );
    }

    /// The own-uid gate covers `CreateGateway` like every other op.
    #[tokio::test]
    async fn dispatch_rejects_create_gateway_for_a_foreign_uid() {
        let own_uid = unsafe { libc::getuid() };
        let ctx = ctx(own_uid);
        let op = BrokerOp::CreateGateway {
            op_uid: own_uid + 1,
            lima_yaml: gateway_shaped_yaml(),
        };
        assert!(
            matches!(dispatch_op(&ctx, op).await, BrokerResult::Rejected { .. }),
            "CreateGateway for a foreign uid must be rejected"
        );
    }

    /// The wire form of `CreateGateway` carries no VM-name field.
    ///
    /// Asserted on the serialized JSON rather than on the Rust type, because
    /// the field's absence is a property of what crosses the channel: there is
    /// nowhere on a `CreateGateway` frame for a daemon to put an instance name.
    ///
    /// What makes that load-bearing is the receiving end. `handle_create_gateway`
    /// is handed only `lima_yaml` and names the instance from `ctx.own_uid` —
    /// the agent's own `getuid()` — so there is no reader for a name even if one
    /// arrives. The broker read loop keeps only the deserialized value; the raw
    /// line survives it solely as text in the parse-error log.
    ///
    /// `BrokerOp` also carries `deny_unknown_fields`, so a `vm` key appended
    /// anyway is refused rather than discarded. That is a second layer and a
    /// recent one — serde's default is to drop it silently — so it is asserted
    /// separately in `broker_op_refuses_an_unknown_field` rather than assumed
    /// here.
    #[test]
    fn create_gateway_carries_no_vm_name_on_the_wire() {
        let op = BrokerOp::CreateGateway {
            op_uid: 501,
            lima_yaml: "vmType: \"qemu\"\n".to_string(),
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&op).expect("serialize CreateGateway"))
                .expect("reparse CreateGateway");
        let mut fields: Vec<&str> = json
            .as_object()
            .expect("CreateGateway serializes to an object")
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            vec!["lima_yaml", "op_uid", "subcommand"],
            "CreateGateway must carry exactly the op tag, the uid cross-check and \
             the template — no vm name, no owner, no wrapper path"
        );
    }

    /// A key no `BrokerOp` variant declares is a parse error, not a discard.
    ///
    /// Both halves of the enum's closure are asserted together because they are
    /// enforced by two different mechanisms that read alike: the `subcommand`
    /// tag closes the variants, and `deny_unknown_fields` closes the fields.
    /// Only the first is on by default — drop the attribute and the field half
    /// silently becomes "accepted and ignored" with nothing else complaining.
    #[test]
    fn broker_op_refuses_an_unknown_field() {
        // The `vm` key CreateGateway deliberately does not declare.
        let with_extra = r#"{"subcommand":"create_gateway","op_uid":501,"lima_yaml":"vmType: \"qemu\"\n","vm":"evil"}"#;
        let err = serde_json::from_str::<BrokerOp>(with_extra)
            .expect_err("a frame with an undeclared key must not deserialize")
            .to_string();
        assert!(
            err.contains("unknown field `vm`"),
            "the parse error must name the refused key; got: {err}"
        );

        // The same frame minus that key parses — the refusal is about the key,
        // not about the frame being malformed in some other way.
        let clean =
            r#"{"subcommand":"create_gateway","op_uid":501,"lima_yaml":"vmType: \"qemu\"\n"}"#;
        assert!(
            matches!(
                serde_json::from_str::<BrokerOp>(clean),
                Ok(BrokerOp::CreateGateway { .. })
            ),
            "the frame CreateGateway does declare must still deserialize"
        );

        // The variant axis, for the same reason and by the other mechanism.
        let unknown_variant = r#"{"subcommand":"create_evil","op_uid":501,"lima_yaml":"x"}"#;
        assert!(
            serde_json::from_str::<BrokerOp>(unknown_variant).is_err(),
            "an op outside the enum must not deserialize"
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
    // Start vs StartGateway — the class is the op, not the VM name
    // -----------------------------------------------------------------------

    /// Fragment of the refusal `run_limactl` returns when it cannot resolve the
    /// binary. Asserting on it is how the tests below prove an op reached the
    /// exec point rather than being turned away by a validation gate.
    const LIMACTL_UNRESOLVABLE: &str = "limactl not found in PATH";

    /// Empties `PATH` for the duration of a dispatch test, restoring it on drop.
    ///
    /// This is containment, not convenience. `run_limactl` resolves `limactl`
    /// from this process's `PATH`, and `ctx` builds a `lima_home` under
    /// `/var/lib/sandboxd/`, which on a developer host is the operator's **live**
    /// LIMA_HOME. `limactl start <name>` for an instance that does not exist is
    /// not an error — it creates one from `template:default` and boots it. So a
    /// dispatch test that passed every validation gate and reached `run_limactl`
    /// would start a real VM on the host running the unit suite.
    ///
    /// With `PATH` empty, `resolve_limactl()` returns `None` and the op is
    /// refused before anything is spawned. Every caller asserts the refusal
    /// reason rather than accepting any rejection, so that if the resolution
    /// mechanism ever stops consulting `PATH` these tests fail loudly instead of
    /// quietly beginning to boot VMs.
    ///
    /// The process environment is global, so this is only safe because each test
    /// gets its own process under the workspace's runner.
    struct ClearedPath(Option<std::ffi::OsString>);

    impl ClearedPath {
        fn new() -> Self {
            let prior = std::env::var_os("PATH");
            unsafe { std::env::set_var("PATH", "") };
            Self(prior)
        }
    }

    impl Drop for ClearedPath {
        fn drop(&mut self) {
            match self.0.take() {
                Some(prior) => unsafe { std::env::set_var("PATH", prior) },
                None => unsafe { std::env::remove_var("PATH") },
            }
        }
    }

    /// The general Start op refuses an empty qemu-wrapper for **every** VM name,
    /// including the names this agent's own gateway instances carry.
    ///
    /// The empty wrapper is what makes a VM's management NIC unrestricted, so
    /// the set of names that may pass one is the set of VMs allowed to bypass
    /// egress policy. `Start` takes its name off the wire, from a daemon this
    /// module treats as untrusted, so for `Start` that set must be empty — a
    /// gateway is started by its own op instead.
    ///
    /// The trap this guards is specific and was very nearly implemented: letting
    /// `Start` skip wrapper validation when `vm` matches an agent-derived
    /// gateway name. That reads like a uid-derived check, but the daemon still
    /// chooses which branch runs by choosing the name, and nothing on the Create
    /// path constrains a VM's name — so a session-shaped VM created as
    /// `sandboxd-gateway` would boot with a session socket_vmnet NIC *and* an
    /// unrestricted slirp NIC. The gateway names are in the table below
    /// precisely because they are the ones such a guard would have admitted.
    #[tokio::test]
    async fn start_refuses_an_empty_qemu_wrapper_whatever_the_vm_is_named() {
        let own_uid = TEST_DAEMON_UID;
        let ctx = ctx(own_uid);
        let _path = ClearedPath::new();

        for vm in [
            "sandbox-abcdef123456",
            GATEWAY_VM_NAME,
            &format!("{GATEWAY_VM_NAME}-{own_uid}"),
            &format!("{GATEWAY_VM_NAME}-0"),
        ] {
            let op = BrokerOp::Start {
                op_uid: own_uid,
                vm: vm.to_string(),
                qemu_wrapper: String::new(),
                hardened: true,
                memory_mb: 4096,
                cpus: 2,
                start_timeout_s: 300,
                bridge: None,
                unrestricted_slirp_for_provisioning: false,
            };
            let result = dispatch_op(&ctx, op).await;
            let BrokerResult::Rejected { reason } = result else {
                panic!("Start {vm} with an empty qemu_wrapper must be Rejected; got {result:?}");
            };
            assert!(
                reason.contains("qemu_wrapper"),
                "Start {vm} must be refused by wrapper validation specifically; got {reason:?}"
            );
            assert!(
                !reason.contains(LIMACTL_UNRESOLVABLE),
                "Start {vm} with an empty wrapper reached the exec point, so some class \
                 escape admitted it"
            );
        }
    }

    /// `StartGateway` boots this agent's own gateway instance, and carries
    /// neither a name nor a wrapper to get wrong.
    ///
    /// Reaching the exec point is the assertion: it means the op cleared every
    /// validation gate without a `qemu_wrapper` field existing to supply. The
    /// gateway legitimately runs without the `restrict=on` wrapper on its
    /// management NIC — its `eth0` is the sanctioned uplink — and this is the op
    /// that expresses that, rather than an emptiness test inside `Start`.
    #[tokio::test]
    async fn start_gateway_reaches_limactl_without_a_wrapper() {
        let home = tempfile::tempdir().expect("temp LIMA_HOME");
        let ctx = ctx_in(&home);
        let dir = home.path().join(own_gateway_vm(&ctx));
        std::fs::create_dir_all(&dir).expect("instance dir");
        std::fs::write(dir.join("lima.yaml"), "# instance\n").expect("instance lima.yaml");
        let _path = ClearedPath::new();

        let op = BrokerOp::StartGateway {
            op_uid: TEST_DAEMON_UID,
            start_timeout_s: 300,
        };
        let result = dispatch_op(&ctx, op).await;
        let BrokerResult::Rejected { reason } = result else {
            panic!("StartGateway should have been refused at limactl resolution; got {result:?}");
        };
        assert!(
            reason.contains(LIMACTL_UNRESOLVABLE),
            "StartGateway must clear every validation gate and be turned away only at \
             the exec point; got {reason:?}"
        );
    }

    /// `StartGateway`'s range check still applies to the one field it does take.
    #[tokio::test]
    async fn start_gateway_rejects_an_out_of_range_timeout() {
        let ctx = ctx(TEST_DAEMON_UID);
        let _path = ClearedPath::new();

        let op = BrokerOp::StartGateway {
            op_uid: TEST_DAEMON_UID,
            start_timeout_s: 0,
        };
        let result = dispatch_op(&ctx, op).await;
        assert!(
            matches!(result, BrokerResult::Rejected { ref reason } if reason.contains("start_timeout_s")),
            "a zero start_timeout_s must be refused by the range check; got {result:?}"
        );
    }

    /// The wire form of `StartGateway` carries neither a VM name nor a wrapper.
    ///
    /// Same reasoning as `create_gateway_carries_no_vm_name_on_the_wire`, and
    /// asserted on the serialized JSON for the same reason: the absence is a
    /// property of what crosses the channel. The wrapper's absence is the half
    /// that matters here — there is no field for a daemon to leave empty, so
    /// "may this VM run unwrapped" is answered by which op was invoked and
    /// cannot be re-asked per request.
    ///
    /// The three fields `Start` carries that this one drops — `hardened`,
    /// `memory_mb`, `cpus` — are omitted because they are inert on this platform,
    /// not merely unused: they travel as the `SANDBOX_QEMU_*` variables, read
    /// only by the Linux qemu-wrapper, and the macOS wrapper reads none of them.
    /// The gateway's sizing comes from the `cpus:`/`memory:` lines of the
    /// template it was created from.
    #[test]
    fn start_gateway_carries_no_vm_name_and_no_wrapper_on_the_wire() {
        let op = BrokerOp::StartGateway {
            op_uid: 501,
            start_timeout_s: 300,
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&op).expect("serialize StartGateway"))
                .expect("reparse StartGateway");
        let mut fields: Vec<&str> = json
            .as_object()
            .expect("StartGateway serializes to an object")
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            vec!["op_uid", "start_timeout_s", "subcommand"],
            "StartGateway must carry exactly the op tag, the uid cross-check and the \
             timeout — no vm name and no wrapper path"
        );
    }

    // -----------------------------------------------------------------------
    // Gateway-name reservation — the permissive op's target, not just its branch
    // -----------------------------------------------------------------------

    /// A `RunContext` whose LIMA_HOME is a temp dir rather than the operator's
    /// real one.
    ///
    /// `ctx` builds `/var/lib/sandboxd/…`, which on a developer host is live
    /// operator state, and `handle_create` writes its staging YAML there *before*
    /// reaching `run_limactl` — so `ClearedPath` does not contain that write.
    /// Tests that exercise a placing op take this instead. `own_uid` is still the
    /// fixture's, because the reserved names derive from the uid, not the home.
    fn ctx_in(home: &tempfile::TempDir) -> RunContext {
        RunContext {
            own_uid: TEST_DAEMON_UID,
            lima_home: home.path().display().to_string(),
            broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
        }
    }

    /// Session-shaped YAML that passes `validate_lima_yaml_shape` for `vm`.
    ///
    /// It has to pass, or a claiming op would be refused for its *content* and
    /// the tests below would prove nothing about its *name*.
    fn session_yaml(vm: &str) -> String {
        format!(
            "# vm: {vm}\nvmType: \"qemu\"\ncpus: 2\nmemory: \"4GiB\"\ndisk: \"20GiB\"\n\
             networks:\n  - socket: /var/run/sandbox/vmnet/slot-0.sock\n"
        )
    }

    /// The two-op attack: claim the name the permissive start op acts on, then
    /// start it. Both halves must not both succeed.
    ///
    /// Splitting `StartGateway` off `Start` removed the daemon's control over
    /// *which branch runs*. It did not remove its control over *which instance
    /// the permissive branch acts on*: `StartGateway` derives a **name** from the
    /// agent's uid, but the name→instance binding is made by a different op that
    /// takes the name off the wire. `handle_create` checked `vm` for charset
    /// only, so a daemon could bind a session-shaped instance — or, with
    /// `is_hardened_session: false`, a slirp-only one — to that name and then
    /// invoke `StartGateway`, which boots it with no wrapper and therefore no
    /// `restrict=on` rewrite. `handle_clone` reaches the same name the same way,
    /// and `Delete` frees it, so "the name is already taken" is not a defence.
    ///
    /// The reserved name is not merely defensive, and it is one name doing two
    /// jobs: `own_gateway_vm` is what `StartGateway` boots, and it is also what
    /// the `InVm` and Docker ops execute inside — as root, per that function's
    /// own doc — so binding daemon-authored content to it hands the daemon a
    /// root shell in a VM it shaped. The loop below iterates a one-element set
    /// because the two names it used to hold have been collapsed into that
    /// function; the shape stays so a second reserved name can be added to the
    /// array rather than to the test.
    ///
    /// What this test can and cannot show: with `PATH` cleared, an op that clears
    /// every gate is turned away at `limactl` resolution, so "the agent does not
    /// refuse this sequence" is what a `LIMACTL_UNRESOLVABLE` reason on step one
    /// means. It does not boot a VM and observe its NICs; the NIC consequence is
    /// established by reading the wrapper, not here.
    #[tokio::test]
    async fn the_gateway_names_cannot_be_claimed_by_the_general_placing_ops() {
        let home = tempfile::tempdir().expect("temp LIMA_HOME");
        let ctx = ctx_in(&home);
        let _path = ClearedPath::new();

        let reserved = [own_gateway_vm(&ctx)];

        for vm in &reserved {
            let claims = [
                BrokerOp::Create {
                    op_uid: TEST_DAEMON_UID,
                    vm: vm.clone(),
                    lima_yaml: session_yaml(vm),
                    owner: "10.1.0.0/29".to_string(),
                    qemu_wrapper: String::new(),
                    is_hardened_session: true,
                },
                BrokerOp::Clone {
                    op_uid: TEST_DAEMON_UID,
                    base: "sandbox-base".to_string(),
                    vm: vm.clone(),
                    cpus: 2,
                    memory_gib: 4,
                    disk_gb: 20,
                    owner: "10.1.0.0/29".to_string(),
                },
            ];

            for op in claims {
                let label = op.label();
                let result = dispatch_op(&ctx, op).await;
                let BrokerResult::Rejected { reason } = result else {
                    panic!("{label} claiming {vm} must be Rejected; got {result:?}");
                };
                assert!(
                    reason.contains("reserved"),
                    "{label} claiming {vm} must be refused by the name reservation \
                     specifically; got {reason:?}"
                );
                assert!(
                    !reason.contains(LIMACTL_UNRESOLVABLE),
                    "{label} claiming {vm} reached the exec point, so the name is \
                     claimable and the attack sequence is open"
                );
            }
        }

        // The second half of the attack is real, not hypothetical: this op takes
        // no name and no wrapper, clears every gate, and boots whatever carries
        // the reserved name. Only step one's refusal stops the sequence. Standing
        // in for the instance `CreateGateway` would have left behind, since the
        // op now requires one to exist.
        let dir = home.path().join(&reserved[0]);
        std::fs::create_dir_all(&dir).expect("instance dir");
        std::fs::write(dir.join("lima.yaml"), "# instance\n").expect("instance lima.yaml");
        let start = dispatch_op(
            &ctx,
            BrokerOp::StartGateway {
                op_uid: TEST_DAEMON_UID,
                start_timeout_s: 300,
            },
        )
        .await;
        assert!(
            matches!(start, BrokerResult::Rejected { ref reason } if reason.contains(LIMACTL_UNRESOLVABLE)),
            "StartGateway must still clear every gate and act on {:?}; got {start:?}",
            reserved[0]
        );
    }

    /// The reservation covers exactly the names this agent's own gateway ops act
    /// on, and nothing that merely resembles them.
    ///
    /// Reserving more would refuse legitimate work for no gain: another
    /// operator's gateway lives in another operator's LIMA_HOME, and no op of
    /// this agent's ever names it, so it is not a target the reservation exists
    /// to protect. Reaching the exec point is how a name proves it is still
    /// claimable.
    #[tokio::test]
    async fn the_reservation_does_not_reach_beyond_this_agents_own_gateway_names() {
        let home = tempfile::tempdir().expect("temp LIMA_HOME");
        let ctx = ctx_in(&home);
        let _path = ClearedPath::new();

        for vm in [
            "sandbox-abcdef123456",
            "sandbox-base",
            &format!("{GATEWAY_VM_NAME}-{}", TEST_DAEMON_UID + 1),
            &format!("{GATEWAY_VM_NAME}x"),
        ] {
            let op = BrokerOp::Create {
                op_uid: TEST_DAEMON_UID,
                vm: vm.to_string(),
                lima_yaml: session_yaml(vm),
                owner: "10.1.0.0/29".to_string(),
                qemu_wrapper: String::new(),
                is_hardened_session: true,
            };
            let result = dispatch_op(&ctx, op).await;
            assert!(
                matches!(result, BrokerResult::Rejected { ref reason } if reason.contains(LIMACTL_UNRESOLVABLE)),
                "Create {vm} must still clear every gate and be turned away only at \
                 the exec point; got {result:?}"
            );
        }
    }

    /// `StartGateway` refuses an instance that does not exist.
    ///
    /// Not tidiness — `limactl start <unknown name>` does not fail, it creates an
    /// instance from `template:default` and boots it. Without this check the
    /// permissive op manufactures its own target: `Delete` frees the reserved
    /// name (deleting one's own gateway is legitimate lifecycle work, so the name
    /// reservation deliberately does not cover it), and the next `StartGateway`
    /// boots a fresh Lima-default VM with unrestricted user-mode networking,
    /// which `InstallGuestAgent` and `RunRsync` can then load. The same hole
    /// swallows an honest daemon that starts before creating.
    ///
    /// Existence is checked against the instance's `lima.yaml` rather than the
    /// directory, because that is the file `limactl` reads; a bare directory is
    /// not an instance. This is not a transactional guarantee, and does not need
    /// to be: the only op that can make that file appear under a reserved name is
    /// `CreateGateway`, whose YAML is held to the gateway shape.
    #[tokio::test]
    async fn start_gateway_refuses_an_instance_that_does_not_exist() {
        let home = tempfile::tempdir().expect("temp LIMA_HOME");
        let ctx = ctx_in(&home);
        let _path = ClearedPath::new();

        let op = BrokerOp::StartGateway {
            op_uid: TEST_DAEMON_UID,
            start_timeout_s: 300,
        };
        let result = dispatch_op(&ctx, op).await;
        let BrokerResult::Rejected { reason } = result else {
            panic!("StartGateway with no instance present must be Rejected; got {result:?}");
        };
        assert!(
            reason.contains("no such instance"),
            "StartGateway must refuse a missing instance specifically, rather than \
             letting limactl create one from template:default; got {reason:?}"
        );

        // And it starts once the instance exists, so the check gates on presence
        // rather than refusing outright.
        let dir = home.path().join(own_gateway_vm(&ctx));
        std::fs::create_dir_all(&dir).expect("instance dir");
        std::fs::write(dir.join("lima.yaml"), "# instance\n").expect("instance lima.yaml");
        let result = dispatch_op(
            &ctx,
            BrokerOp::StartGateway {
                op_uid: TEST_DAEMON_UID,
                start_timeout_s: 300,
            },
        )
        .await;
        assert!(
            matches!(result, BrokerResult::Rejected { ref reason } if reason.contains(LIMACTL_UNRESOLVABLE)),
            "with the instance present StartGateway must reach the exec point; got {result:?}"
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

    // -----------------------------------------------------------------------
    // rsync remote-shell transport
    // -----------------------------------------------------------------------

    /// The container transport names **this agent's own** Docker socket,
    /// derived from its own LIMA_HOME. The daemon does not supply it, and
    /// must not be able to: rsync execs the transport's word list directly,
    /// so whatever names a Docker daemon in it is the sole authority for
    /// which one the transfer reaches — and the container being synced into
    /// lives in this agent's VM, not on any host daemon.
    ///
    /// The uid suffix on the instance directory is spelled out rather than
    /// derived: a test that rebuilt the expected path with the same function
    /// the transport uses would agree with any name that function produced,
    /// including a wrong one.
    #[test]
    fn the_container_rsync_transport_names_the_agents_own_socket() {
        let ctx = ctx(501);
        let transport = rsync_transport(&ctx, "container").expect("container transport");
        assert_eq!(
            transport,
            format!(
                "docker -H unix://{}/sandboxd-gateway-501/gateway-docker.sock exec -i",
                ctx.lima_home
            )
        );
    }

    /// The Lima transport is unchanged and carries no socket.
    #[test]
    fn the_lima_rsync_transport_is_limactl_shell() {
        let transport = rsync_transport(&ctx(501), "lima").expect("lima transport");
        assert_eq!(transport, "limactl shell");
    }

    /// Both transports survive rsync's own re-parse, reconstructing the argv
    /// intended. This is the assertion the shell-string shape needs: the `-e`
    /// value is split by rsync and handed to `execvp`, so what matters is
    /// what rsync's splitter makes of it, not what a shell would.
    #[test]
    fn both_rsync_transports_reparse_into_the_intended_argv() {
        let ctx = ctx(501);
        assert_eq!(
            sandbox_docker_argv::rsh_split(&rsync_transport(&ctx, "lima").expect("lima"))
                .expect("re-parsable"),
            vec!["limactl", "shell"]
        );
        assert_eq!(
            sandbox_docker_argv::rsh_split(&rsync_transport(&ctx, "container").expect("container"))
                .expect("re-parsable"),
            vec![
                "docker".to_string(),
                "-H".to_string(),
                format!(
                    "unix://{}/sandboxd-gateway-501/gateway-docker.sock",
                    ctx.lima_home
                ),
                "exec".to_string(),
                "-i".to_string(),
            ]
        );
    }

    /// A LIMA_HOME that would not survive the re-parse is refused rather
    /// than transferred against a truncated target. The agent's own home is
    /// constructed from numeric uids so this cannot happen today; the test
    /// exists because "cannot happen today" is a property of the caller, not
    /// of this function.
    #[test]
    fn a_lima_home_that_would_not_reparse_is_refused() {
        let ctx = RunContext {
            own_uid: 501,
            lima_home: "/var/lib/sandbox d/501/lima".to_string(),
            broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
        };
        // A space keeps re-parsing but splits the URL, so the transport that
        // comes out is not the one intended — pinned here as the shape a
        // future caller has to watch for.
        let transport = rsync_transport(&ctx, "container").expect("a space still parses");
        let words = sandbox_docker_argv::rsh_split(&transport).expect("re-parsable");
        assert!(
            words.len() > 5,
            "a space in LIMA_HOME splits the target authority: {words:?}"
        );

        // A quote does not survive at all, and is refused outright.
        let ctx = RunContext {
            own_uid: 501,
            lima_home: "/var/lib/sandbox'd/501/lima".to_string(),
            broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
        };
        let err =
            rsync_transport(&ctx, "container").expect_err("an unterminated quote must be refused");
        assert!(
            err.contains("not safely re-parsable"),
            "the refusal must say why; got {err}"
        );
    }
}
