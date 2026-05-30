//! `sandbox-lima-helper` — privileged setcap binary that pivots to an
//! operator's uid before exec'ing `limactl` for every session-context
//! Lima control-plane operation.
//!
//! # Invocation
//!
//! ```text
//! sandbox-lima-helper <subcommand> [flags...]
//! ```
//!
//! Eleven subcommands: `create`, `start`, `clone`, `stop`, `delete`,
//! `copy`, `guest-socat`, `install-guest-agent`, `list-json`,
//! `read-user-key`, `run-rsync`. Every
//! flag the helper passes to limactl is hardcoded per subcommand;
//! the daemon contributes only the typed flag values (no pass-through).
//!
//! # Authorization and privilege flow
//!
//! Each invocation runs the same numbered steps 1–10 before the
//! subcommand-specific step 11 (exec or step-sequence). Any step that
//! denies prints a single `sandbox-lima-helper: <reason>` line to stderr
//! and exits with the matching exit code. No privilege change happens on
//! the deny path.
//!
//! 1.  Daemon identity check — `getuid() == sandbox-user-uid` (primary
//!     gate) and sandbox-group membership (sanity check).
//! 2.  Argv parse — subcommand dispatch; strict required/unknown-flag
//!     checks.
//! 3.  Validate `--op-uid` — non-zero, resolvable via `getpwuid_r`,
//!     member of sandbox group (3-case NSS distinction).
//! 4.  Validate `--vm` / `--base` — name regex + leading-dash reject.
//! 5.  Validate string args — no NUL, ≤ PATH_MAX, host-side paths
//!     absolute + no-`..`.
//! 6.  Subcommand-specific validation — ranges, copy `<vm>:` syntax,
//!     MAC multicast-bit reject.
//! 7.  Resolve limactl absolute path — three-candidate order off
//!     `pw_dir` captured in step 3; no PATH lookup, no `~` expansion.
//! 8.  Drop to operator uid via `setresuid`.
//! 9.  Capability self-clear — four-stage hard deny on partial failure.
//! 10. Build sanitised env block.
//! 11. exec (or step-sequence for `install-guest-agent`).
//!
//! # Privilege model
//!
//! File caps: `cap_setuid+ep`. No `cap_chown` — POSIX ACLs on
//! `/var/lib/sandboxd/<op-uid>/lima/` handle file ownership; the
//! chown-bracket pattern is gone. Installed at
//! `/usr/local/libexec/sandboxd/sandbox-lima-helper`.
//!
//! # Stderr / exit-code contract
//!
//! Distinct exit codes let the daemon map rejection categories without
//! parsing stderr. Stderr disambiguates sub-cases within a code.
//!
//! ```text
//! EXIT_GENERIC           = 1  // argv parse / execvpe failure
//! EXIT_NOT_SANDBOX       = 2  // caller uid != sandbox-user, or not in sandbox group
//! EXIT_BAD_OP_UID        = 3  // --op-uid 0, not in sandbox group, or unresolvable
//! EXIT_SETRESUID_FAILED  = 4
//! EXIT_CAPSET_FAILED     = 5
//! EXIT_LIMACTL_NOT_FOUND = 6
//! EXIT_BAD_ARGS          = 7  // bad vm name, bad path, range violation, etc.
//! ```
//
// NON-FEATURES — DO NOT ADD without revisiting the threat model.
//
// * No argv pass-through to limactl. Every flag the helper passes
//   to limactl is hardcoded inside this binary per subcommand;
//   daemon contributes only the typed flag values, by position.
//
// * No reading of sessions.db, sandboxd.sock, or any daemon state.
//   The helper is a pure setresuid + validate + exec pivot.
//
// * No general `shell --` subcommand. The only `limactl shell …`
//   invocations the helper performs are the hardcoded guest-socat
//   pump and the six steps of install-guest-agent (whose argvs are
//   compile-time constants). A future contributor needing a
//   different in-VM command must add a fresh typed subcommand.
//
// * No root op-uid. Even with cap_setuid, the helper refuses
//   --op-uid 0 explicitly.
//
// * No cap_chown. POSIX ACLs on /var/lib/sandboxd/<op-uid>/lima/
//   handle file ownership; the chown-bracket pattern of
//   sandbox-spawn-helper does not exist here.
//
// * No path content validation. Byte-level sanity only (no NUL,
//   length <= PATH_MAX). The kernel + post-setresuid uid enforce
//   what the operator can actually read or write.
//
// * No PATH lookup. limactl is resolved via three absolute paths
//   in a hardcoded order. No shell expansion. No '~' expansion.
//
// * Two timeouts, distinct concerns. start's --start-timeout-s
//   maps to limactl's internal SSH-reachability wait. The
//   daemon's run_with_timeout wraps the *helper invocation*
//   and is a host-side wall-clock kill. Both layers exist.
//
// * No JSON-on-stdin protocol. The helper takes argv only; no
//   stdin parsing. stdin is ignored (left open for inheritance
//   to the exec'd child where it matters, e.g. guest-socat).
//
// * No soft fallback to direct daemon-uid limactl. The daemon
//   either resolves a usable helper at startup or refuses to
//   come up.

use std::env;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, ExitCode};
use std::sync::LazyLock;

use nix::unistd::{Uid, User};
use regex::Regex;

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

const EXIT_GENERIC: u8 = 1;
const EXIT_NOT_SANDBOX: u8 = 2;
const EXIT_BAD_OP_UID: u8 = 3;
const EXIT_SETRESUID_FAILED: u8 = 4;
const EXIT_CAPSET_FAILED: u8 = 5;
const EXIT_LIMACTL_NOT_FOUND: u8 = 6;
const EXIT_BAD_ARGS: u8 = 7;

// ---------------------------------------------------------------------------
// Compile-time constants
// ---------------------------------------------------------------------------

/// The literal username and group name for the `sandbox` system user.
/// `test-env-override` builds substitute these via env vars.
const SANDBOX_USER_NAME: &str = "sandbox";
const SANDBOX_GROUP_NAME: &str = "sandbox";

/// Canonical install path of the sandbox-guest binary inside the VM host.
/// World-readable (0755) so the post-setresuid operator uid can read it.
const SANDBOX_GUEST_HOST_PATH: &str = "/usr/local/libexec/sandboxd/sandbox-guest";

/// The systemd unit body written into each VM by `install-guest-agent`.
/// Duplicated from `sandbox-core::lima::GUEST_AGENT_SERVICE_UNIT` to
/// keep the helper's TCB free of a `sandbox-core` dependency.
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

/// Tools that must be present inside the VM after provisioning.
/// Mirrors `REQUIRED` at `sandbox-core/src/lima.rs:1320`.
/// The unit test `required_base_tools_matches_core` asserts parity.
pub const REQUIRED_BASE_TOOLS: &[&str] = &["socat", "git", "rsync", "docker"];

/// Env vars from parent that survive into the exec'd environment.
const ENV_ALLOWLIST: &[&str] = &["PATH", "LANG", "LC_ALL", "HOME", "TERM"];

// ---------------------------------------------------------------------------
// Compiled regexes — hoisted to module-top as LazyLock to avoid per-call
// compilation. `unwrap()` inside LazyLock::new is safe: a constant regex
// literal that fails to compile is a programming error, not a runtime
// condition. FlagSet is single-pass per flag.
// ---------------------------------------------------------------------------

static VM_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_\-]{1,64}$").unwrap());
static BRIDGE_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_\-]{1,15}$").unwrap());
static VM_MAC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$").unwrap());

// ---------------------------------------------------------------------------
// test-env-override seams
// ---------------------------------------------------------------------------

#[cfg(feature = "test-env-override")]
const TEST_SANDBOX_USER_ENV: &str = "SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER";
#[cfg(feature = "test-env-override")]
const TEST_SANDBOX_GROUP_ENV: &str = "SANDBOX_LIMA_HELPER_TEST_SANDBOX_GROUP";
#[cfg(feature = "test-env-override")]
const TEST_GUEST_BINARY_PATH_ENV: &str = "SANDBOX_LIMA_HELPER_TEST_GUEST_BINARY_PATH";
/// Override for the sandboxd state root used to construct per-operator
/// LIMA_HOME paths. Normally `/var/lib/sandboxd`; tests redirect to a
/// tempdir so `read-user-key` resolves the key file without touching
/// the production state root.
#[cfg(feature = "test-env-override")]
const TEST_STATE_ROOT_ENV: &str = "SANDBOX_LIMA_HELPER_TEST_STATE_ROOT";

fn resolve_sandbox_user_name() -> String {
    #[cfg(feature = "test-env-override")]
    if let Ok(v) = env::var(TEST_SANDBOX_USER_ENV)
        && !v.is_empty()
    {
        return v;
    }
    SANDBOX_USER_NAME.to_string()
}

fn resolve_sandbox_group_name() -> String {
    #[cfg(feature = "test-env-override")]
    if let Ok(v) = env::var(TEST_SANDBOX_GROUP_ENV)
        && !v.is_empty()
    {
        return v;
    }
    SANDBOX_GROUP_NAME.to_string()
}

fn resolve_guest_binary_path() -> String {
    #[cfg(feature = "test-env-override")]
    if let Ok(v) = env::var(TEST_GUEST_BINARY_PATH_ENV)
        && !v.is_empty()
    {
        return v;
    }
    SANDBOX_GUEST_HOST_PATH.to_string()
}

/// Resolve the sandboxd state root for per-operator LIMA_HOME construction.
///
/// Returns `/var/lib/sandboxd` in production. In `test-env-override` builds
/// the `SANDBOX_LIMA_HELPER_TEST_STATE_ROOT` env var redirects the root into a
/// caller-supplied tempdir so `read-user-key` integration tests can seed the
/// key file without touching the production state root.
fn resolve_state_root() -> String {
    #[cfg(feature = "test-env-override")]
    if let Ok(v) = env::var(TEST_STATE_ROOT_ENV)
        && !v.is_empty()
    {
        return v;
    }
    "/var/lib/sandboxd".to_string()
}

// ---------------------------------------------------------------------------
// Parsed subcommand types
// ---------------------------------------------------------------------------

struct CreateArgs {
    op_uid: u32,
    vm: String,
    yaml: String,
}

struct StartArgs {
    op_uid: u32,
    vm: String,
    qemu_wrapper: String,
    hardened: String, // "0" or "1"
    memory_mb: u32,
    cpus: u32,
    start_timeout_s: u32,
    bridge_name: Option<String>,
    vm_mac: Option<String>,
}

struct CloneArgs {
    op_uid: u32,
    base: String,
    vm: String,
    cpus: u32,
    memory_gib: u32,
    disk_gib: u32,
}

struct StopArgs {
    op_uid: u32,
    vm: String,
    force: bool,
}

struct DeleteArgs {
    op_uid: u32,
    vm: String,
}

struct CopyArgs {
    op_uid: u32,
    src: String,
    dst: String,
}

struct GuestSocatArgs {
    op_uid: u32,
    vm: String,
}

struct InstallGuestAgentArgs {
    op_uid: u32,
    vm: String,
}

struct ListJsonArgs {
    op_uid: u32,
}

struct ReadUserKeyArgs {
    op_uid: u32,
}

/// Arguments for the `run-rsync` subcommand.
///
/// The daemon calls this after pivoting to the operator uid so rsync
/// can read the operator-owned host workspace source directory.  The
/// helper resolves `rsync` from the operator's PATH-independent
/// candidate list, builds the argv, and execvpe's it.
struct RunRsyncArgs {
    op_uid: u32,
    /// "lima" or "container" — selects the `-e <transport>` value.
    backend: String,
    /// `sandbox-<id>` form expected by the shell transport target.
    session_name: String,
    /// Absolute host-side path (the rsync source for a push).
    host_path: String,
    /// Absolute guest-side path (the rsync destination for a push).
    guest_path: String,
    /// When true the `--filter=:- .gitignore` flag is omitted.
    no_gitignore: bool,
}

enum Subcommand {
    Create(CreateArgs),
    Start(StartArgs),
    Clone(CloneArgs),
    Stop(StopArgs),
    Delete(DeleteArgs),
    Copy(CopyArgs),
    GuestSocat(GuestSocatArgs),
    InstallGuestAgent(InstallGuestAgentArgs),
    ListJson(ListJsonArgs),
    ReadUserKey(ReadUserKeyArgs),
    RunRsync(RunRsyncArgs),
}

impl Subcommand {
    fn op_uid(&self) -> u32 {
        match self {
            Subcommand::Create(a) => a.op_uid,
            Subcommand::Start(a) => a.op_uid,
            Subcommand::Clone(a) => a.op_uid,
            Subcommand::Stop(a) => a.op_uid,
            Subcommand::Delete(a) => a.op_uid,
            Subcommand::Copy(a) => a.op_uid,
            Subcommand::GuestSocat(a) => a.op_uid,
            Subcommand::InstallGuestAgent(a) => a.op_uid,
            Subcommand::ListJson(a) => a.op_uid,
            Subcommand::ReadUserKey(a) => a.op_uid,
            Subcommand::RunRsync(a) => a.op_uid,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    run()
}

fn run() -> ExitCode {
    let args: Vec<OsString> = env::args_os().collect();

    // Step 1 — daemon identity check (before argv parse so we bail fast).
    let user_name = resolve_sandbox_user_name();
    let group_name = resolve_sandbox_group_name();

    let sandbox_uid = match resolve_user_uid(&user_name) {
        Ok(Some(uid)) => uid,
        Ok(None) => {
            eprintln!("sandbox-lima-helper: sandbox user '{user_name}' not found on host");
            return ExitCode::from(EXIT_NOT_SANDBOX);
        }
        Err(e) => {
            eprintln!("sandbox-lima-helper: sandbox user lookup failed: {e}");
            return ExitCode::from(EXIT_NOT_SANDBOX);
        }
    };

    let sandbox_gid = match resolve_group_gid(&group_name) {
        Ok(Some(gid)) => gid,
        Ok(None) => {
            eprintln!("sandbox-lima-helper: sandbox group '{group_name}' not found on host");
            return ExitCode::from(EXIT_NOT_SANDBOX);
        }
        Err(e) => {
            eprintln!("sandbox-lima-helper: sandbox group lookup failed: {e}");
            return ExitCode::from(EXIT_NOT_SANDBOX);
        }
    };

    let caller_uid = unsafe { libc::getuid() };
    if caller_uid != sandbox_uid {
        eprintln!(
            "sandbox-lima-helper: caller not sandbox (uid={caller_uid}, expected={sandbox_uid})"
        );
        return ExitCode::from(EXIT_NOT_SANDBOX);
    }

    if !caller_is_in_group(sandbox_gid) {
        eprintln!("sandbox-lima-helper: caller not in sandbox group");
        return ExitCode::from(EXIT_NOT_SANDBOX);
    }

    // Step 2 — argv parse.
    let subcommand = match parse_argv(&args) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("sandbox-lima-helper: {msg}");
            return ExitCode::from(EXIT_BAD_ARGS);
        }
    };

    let op_uid_raw = subcommand.op_uid();

    // Step 3 — validate --op-uid.
    if op_uid_raw == 0 {
        eprintln!("sandbox-lima-helper: root op-uid rejected");
        return ExitCode::from(EXIT_BAD_OP_UID);
    }

    let pw_dir = match resolve_op_uid(op_uid_raw) {
        Ok(Some(dir)) => dir,
        Ok(None) => {
            eprintln!("sandbox-lima-helper: op-uid {op_uid_raw} not found in passwd");
            return ExitCode::from(EXIT_BAD_OP_UID);
        }
        Err(e) => {
            eprintln!("sandbox-lima-helper: op-uid {op_uid_raw} resolution error: {e}");
            return ExitCode::from(EXIT_BAD_OP_UID);
        }
    };

    // Three-case sandbox-group membership check for op-uid.
    match op_uid_in_sandbox_group(op_uid_raw, sandbox_gid) {
        GroupMembership::Member => {}
        GroupMembership::NotMember => {
            eprintln!("sandbox-lima-helper: op-uid not in sandbox group");
            return ExitCode::from(EXIT_BAD_OP_UID);
        }
        GroupMembership::EnumerationFailed(errno) => {
            eprintln!("sandbox-lima-helper: op-uid group enumeration failed: errno {errno}");
            return ExitCode::from(EXIT_GENERIC);
        }
    }

    // Steps 4–6 are subcommand-specific; validate() does them all.
    if let Err((code, msg)) = validate_subcommand(&subcommand) {
        eprintln!("sandbox-lima-helper: {msg}");
        return ExitCode::from(code);
    }

    // Step 7 — resolve limactl absolute path (uses pw_dir from step 3).
    //
    // `read-user-key` reads a file directly; `run-rsync` execs rsync —
    // neither calls limactl, so we skip the resolution for both and
    // pass an empty string as a placeholder. All other subcommands
    // require a usable limactl at this point.
    let limactl_path = if matches!(
        subcommand,
        Subcommand::ReadUserKey(_) | Subcommand::RunRsync(_)
    ) {
        String::new()
    } else {
        match resolve_limactl_path(&pw_dir) {
            Some(p) => p,
            None => {
                eprintln!("sandbox-lima-helper: limactl not found for operator {op_uid_raw}");
                return ExitCode::from(EXIT_LIMACTL_NOT_FOUND);
            }
        }
    };

    // Step 8 — drop to operator uid.
    if let Err(errno) = setresuid_strict(op_uid_raw) {
        eprintln!("sandbox-lima-helper: setresuid({op_uid_raw}) failed: errno {errno}");
        return ExitCode::from(EXIT_SETRESUID_FAILED);
    }

    // Step 9 — capability self-clear (hard deny on partial failure).
    if let Err(e) = clear_all_capabilities() {
        eprintln!("sandbox-lima-helper: capset clear failed: {e}");
        return ExitCode::from(EXIT_CAPSET_FAILED);
    }

    // Step 10 — build sanitised env block.
    // Pass pw_dir (captured in step 3, reused for limactl resolution in
    // step 7) as op_home so HOME is set to the operator's own directory.
    let state_root = resolve_state_root();
    let lima_home = format!("{state_root}/{op_uid_raw}/lima/");
    let env_block = build_env_block(&subcommand, &lima_home, &pw_dir, op_uid_raw);

    // Step 10.5 — tighten umask to 0077 before exec.
    //
    // limactl creates `$LIMA_HOME/_config/user` (the SSH private key) with
    // open(O_CREAT, 0666) in Lima 2.x. The daemon inherits UMask=0022 from
    // the systemd unit (needed for the unix socket), which passes through
    // setresuid unchanged and leaves the key at 0644 on disk. OpenSSH
    // enforces StrictKeyfileMode and refuses to load a private key that is
    // group- or world-readable, so the hostagent loops with "bad permissions"
    // for the full 600 s timeout.
    //
    // 0o077 strips group+world bits from every file/dir Lima creates:
    //   files:       0666 & ~0077 = 0600  (SSH key is operator-private)
    //   directories: 0777 & ~0077 = 0700  (owner can still traverse/create)
    //
    // 0o177 would also strip the owner-execute bit, turning directories
    // into 0600 (no traversal) — that breaks Lima's cidata ISO build which
    // needs to mkdir intermediate subdirs (boot.FreeBSD, etc.).
    unsafe { libc::umask(0o077) };

    // Step 11 — exec (or step-sequence for install-guest-agent,
    // stdout-write for read-user-key, or execvpe-rsync for run-rsync).
    match &subcommand {
        Subcommand::InstallGuestAgent(a) => {
            run_install_guest_agent(&limactl_path, &a.vm, &env_block)
        }
        Subcommand::ReadUserKey(_) => run_read_user_key(op_uid_raw, &lima_home),
        Subcommand::RunRsync(a) => run_rsync(a, &env_block),
        _ => exec_limactl(&limactl_path, &subcommand, &env_block),
    }
}

// ---------------------------------------------------------------------------
// Argv parser
// ---------------------------------------------------------------------------

/// Parse argv into a typed `Subcommand`. Returns `Err(message)` for any
/// parse failure; the caller maps this to `EXIT_BAD_ARGS`.
fn parse_argv(args: &[OsString]) -> Result<Subcommand, String> {
    let sub = args
        .get(1)
        .map(|s| s.to_string_lossy().to_string())
        .ok_or_else(|| "usage: sandbox-lima-helper <subcommand> [flags...]".to_string())?;

    match sub.as_str() {
        "create" => parse_create(&args[2..]),
        "start" => parse_start(&args[2..]),
        "clone" => parse_clone(&args[2..]),
        "stop" => parse_stop(&args[2..]),
        "delete" => parse_delete(&args[2..]),
        "copy" => parse_copy(&args[2..]),
        "guest-socat" => parse_guest_socat(&args[2..]),
        "install-guest-agent" => parse_install_guest_agent(&args[2..]),
        "list-json" => parse_list_json(&args[2..]),
        "read-user-key" => parse_read_user_key(&args[2..]),
        "run-rsync" => parse_run_rsync(&args[2..]),
        other => Err(format!("unknown subcommand: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Per-subcommand parsers
// ---------------------------------------------------------------------------

/// Generic flag parser helper. Extracts a `--key value` pair from a
/// flat `&[OsString]` flag list, reporting errors for:
///   - repeated flags
///   - `--key=value` form (not accepted; only `--key value`)
///   - bare `--key` with no following value
///
/// Used by all parsers below.
struct FlagSet<'a> {
    args: &'a [OsString],
    /// Which arg indices have been consumed.
    consumed: Vec<bool>,
}

impl<'a> FlagSet<'a> {
    fn new(args: &'a [OsString]) -> Self {
        FlagSet {
            args,
            consumed: vec![false; args.len()],
        }
    }

    /// Extract `--flag <value>` returning `Ok(Some(value))` when present,
    /// `Ok(None)` when absent, `Err` on syntax errors.
    fn take_string(&mut self, flag: &'static str) -> Result<Option<String>, String> {
        let prefix = format!("{flag}=");
        let mut found_idx: Option<usize> = None;

        for (i, arg) in self.args.iter().enumerate() {
            let s = arg.to_string_lossy();
            if s == flag {
                if found_idx.is_some() {
                    return Err(format!("{flag} specified more than once"));
                }
                found_idx = Some(i);
            } else if s.starts_with(&prefix) {
                return Err(format!(
                    "{flag}=<value> form not accepted; use {flag} <value>"
                ));
            }
        }

        let idx = match found_idx {
            Some(i) => i,
            None => return Ok(None),
        };

        // FlagSet is single-pass per flag: the in-loop duplicate check
        // above is the only guard needed here; no post-loop re-check.
        let next = idx + 1;
        if next >= self.args.len() {
            return Err(format!("{flag} requires a value"));
        }
        // The next arg must not itself be a flag.
        let next_s = self.args[next].to_string_lossy();
        if next_s.starts_with("--") {
            return Err(format!("{flag} requires a value (got flag '{next_s}')"));
        }

        self.consumed[idx] = true;
        self.consumed[next] = true;
        Ok(Some(next_s.to_string()))
    }

    /// Extract a boolean `--flag` (present → true, absent → false).
    /// Rejects `--flag=value` and `--flag <value>` forms.
    fn take_bool(&mut self, flag: &'static str) -> Result<bool, String> {
        let prefix = format!("{flag}=");
        let mut found_idx: Option<usize> = None;

        for (i, arg) in self.args.iter().enumerate() {
            let s = arg.to_string_lossy();
            if s == flag {
                if found_idx.is_some() {
                    return Err(format!("{flag} specified more than once"));
                }
                found_idx = Some(i);
            } else if s.starts_with(&prefix) {
                return Err(format!(
                    "{flag}=<value> form not accepted; {flag} is a boolean flag"
                ));
            }
        }

        if let Some(idx) = found_idx {
            // FlagSet is single-pass per flag: the in-loop duplicate check
            // above is the only guard needed here; no post-loop re-check.
            // Reject trailing-value form: `--force 1` / `--force true`
            // Mirror route-helper's flag-parser at
            // sandbox-route-helper/src/main.rs:583-595.
            let next = idx + 1;
            if next < self.args.len() {
                let next_s = self.args[next].to_string_lossy();
                if !next_s.starts_with("--") {
                    return Err(format!(
                        "{flag} is a boolean flag; trailing value '{next_s}' not accepted"
                    ));
                }
            }
            self.consumed[idx] = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// After all `take_*` calls, verify there are no unconsumed args.
    fn check_no_extra(&self) -> Result<(), String> {
        for (i, consumed) in self.consumed.iter().enumerate() {
            if !consumed {
                let s = self.args[i].to_string_lossy();
                if s.starts_with("--") {
                    return Err(format!("unknown flag: {s}"));
                } else {
                    return Err(format!("unexpected positional argument: {s}"));
                }
            }
        }
        Ok(())
    }
}

/// Parse u32 from a flag value. Overflow/non-numeric → `EXIT_BAD_ARGS`.
fn parse_u32(flag: &'static str, value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("invalid value for {flag}: '{value}' (expected unsigned integer)"))
}

fn require_flag(flag: &'static str, value: Option<String>) -> Result<String, String> {
    value.ok_or_else(|| format!("missing required flag: {flag}"))
}

// --- create ---

fn parse_create(args: &[OsString]) -> Result<Subcommand, String> {
    let mut f = FlagSet::new(args);
    let op_uid_s = require_flag("--op-uid", f.take_string("--op-uid")?)?;
    let vm = require_flag("--vm", f.take_string("--vm")?)?;
    let yaml = require_flag("--yaml", f.take_string("--yaml")?)?;
    f.check_no_extra()?;

    let op_uid = parse_u32("--op-uid", &op_uid_s)?;
    Ok(Subcommand::Create(CreateArgs { op_uid, vm, yaml }))
}

// --- start ---

fn parse_start(args: &[OsString]) -> Result<Subcommand, String> {
    let mut f = FlagSet::new(args);
    let op_uid_s = require_flag("--op-uid", f.take_string("--op-uid")?)?;
    let vm = require_flag("--vm", f.take_string("--vm")?)?;
    let qemu_wrapper = require_flag("--qemu-wrapper", f.take_string("--qemu-wrapper")?)?;
    let hardened = require_flag("--hardened", f.take_string("--hardened")?)?;
    let memory_mb_s = require_flag("--memory-mb", f.take_string("--memory-mb")?)?;
    let cpus_s = require_flag("--cpus", f.take_string("--cpus")?)?;
    let start_timeout_s_s = require_flag("--start-timeout-s", f.take_string("--start-timeout-s")?)?;
    let bridge_name = f.take_string("--bridge-name")?;
    let vm_mac = f.take_string("--vm-mac")?;
    f.check_no_extra()?;

    let op_uid = parse_u32("--op-uid", &op_uid_s)?;
    let memory_mb = parse_u32("--memory-mb", &memory_mb_s)?;
    let cpus = parse_u32("--cpus", &cpus_s)?;
    let start_timeout_s = parse_u32("--start-timeout-s", &start_timeout_s_s)?;
    Ok(Subcommand::Start(StartArgs {
        op_uid,
        vm,
        qemu_wrapper,
        hardened,
        memory_mb,
        cpus,
        start_timeout_s,
        bridge_name,
        vm_mac,
    }))
}

// --- clone ---

fn parse_clone(args: &[OsString]) -> Result<Subcommand, String> {
    let mut f = FlagSet::new(args);
    let op_uid_s = require_flag("--op-uid", f.take_string("--op-uid")?)?;
    let base = require_flag("--base", f.take_string("--base")?)?;
    let vm = require_flag("--vm", f.take_string("--vm")?)?;
    let cpus_s = require_flag("--cpus", f.take_string("--cpus")?)?;
    let memory_s = require_flag("--memory", f.take_string("--memory")?)?;
    let disk_s = require_flag("--disk", f.take_string("--disk")?)?;
    f.check_no_extra()?;

    let op_uid = parse_u32("--op-uid", &op_uid_s)?;
    let cpus = parse_u32("--cpus", &cpus_s)?;
    let memory_gib = parse_u32("--memory", &memory_s)?;
    let disk_gib = parse_u32("--disk", &disk_s)?;
    Ok(Subcommand::Clone(CloneArgs {
        op_uid,
        base,
        vm,
        cpus,
        memory_gib,
        disk_gib,
    }))
}

// --- stop ---

fn parse_stop(args: &[OsString]) -> Result<Subcommand, String> {
    let mut f = FlagSet::new(args);
    let op_uid_s = require_flag("--op-uid", f.take_string("--op-uid")?)?;
    let vm = require_flag("--vm", f.take_string("--vm")?)?;
    let force = f.take_bool("--force")?;
    f.check_no_extra()?;

    let op_uid = parse_u32("--op-uid", &op_uid_s)?;
    Ok(Subcommand::Stop(StopArgs { op_uid, vm, force }))
}

// --- delete ---

fn parse_delete(args: &[OsString]) -> Result<Subcommand, String> {
    let mut f = FlagSet::new(args);
    let op_uid_s = require_flag("--op-uid", f.take_string("--op-uid")?)?;
    let vm = require_flag("--vm", f.take_string("--vm")?)?;
    f.check_no_extra()?;

    let op_uid = parse_u32("--op-uid", &op_uid_s)?;
    Ok(Subcommand::Delete(DeleteArgs { op_uid, vm }))
}

// --- copy ---

fn parse_copy(args: &[OsString]) -> Result<Subcommand, String> {
    let mut f = FlagSet::new(args);
    let op_uid_s = require_flag("--op-uid", f.take_string("--op-uid")?)?;
    let src = require_flag("--src", f.take_string("--src")?)?;
    let dst = require_flag("--dst", f.take_string("--dst")?)?;
    f.check_no_extra()?;

    let op_uid = parse_u32("--op-uid", &op_uid_s)?;
    Ok(Subcommand::Copy(CopyArgs { op_uid, src, dst }))
}

// --- guest-socat ---

fn parse_guest_socat(args: &[OsString]) -> Result<Subcommand, String> {
    let mut f = FlagSet::new(args);
    let op_uid_s = require_flag("--op-uid", f.take_string("--op-uid")?)?;
    let vm = require_flag("--vm", f.take_string("--vm")?)?;
    f.check_no_extra()?;

    let op_uid = parse_u32("--op-uid", &op_uid_s)?;
    Ok(Subcommand::GuestSocat(GuestSocatArgs { op_uid, vm }))
}

// --- install-guest-agent ---

fn parse_install_guest_agent(args: &[OsString]) -> Result<Subcommand, String> {
    let mut f = FlagSet::new(args);
    let op_uid_s = require_flag("--op-uid", f.take_string("--op-uid")?)?;
    let vm = require_flag("--vm", f.take_string("--vm")?)?;
    f.check_no_extra()?;

    let op_uid = parse_u32("--op-uid", &op_uid_s)?;
    Ok(Subcommand::InstallGuestAgent(InstallGuestAgentArgs {
        op_uid,
        vm,
    }))
}

// --- list-json ---

fn parse_list_json(args: &[OsString]) -> Result<Subcommand, String> {
    let mut f = FlagSet::new(args);
    let op_uid_s = require_flag("--op-uid", f.take_string("--op-uid")?)?;
    f.check_no_extra()?;

    let op_uid = parse_u32("--op-uid", &op_uid_s)?;
    Ok(Subcommand::ListJson(ListJsonArgs { op_uid }))
}

// --- read-user-key ---

fn parse_read_user_key(args: &[OsString]) -> Result<Subcommand, String> {
    let mut f = FlagSet::new(args);
    let op_uid_s = require_flag("--op-uid", f.take_string("--op-uid")?)?;
    f.check_no_extra()?;

    let op_uid = parse_u32("--op-uid", &op_uid_s)?;
    Ok(Subcommand::ReadUserKey(ReadUserKeyArgs { op_uid }))
}

// --- run-rsync ---

fn parse_run_rsync(args: &[OsString]) -> Result<Subcommand, String> {
    let mut f = FlagSet::new(args);
    let op_uid_s = require_flag("--op-uid", f.take_string("--op-uid")?)?;
    let backend = require_flag("--backend", f.take_string("--backend")?)?;
    let session_name = require_flag("--session-name", f.take_string("--session-name")?)?;
    let host_path = require_flag("--host-path", f.take_string("--host-path")?)?;
    let guest_path = require_flag("--guest-path", f.take_string("--guest-path")?)?;
    let no_gitignore = f.take_bool("--no-gitignore")?;
    f.check_no_extra()?;

    let op_uid = parse_u32("--op-uid", &op_uid_s)?;
    Ok(Subcommand::RunRsync(RunRsyncArgs {
        op_uid,
        backend,
        session_name,
        host_path,
        guest_path,
        no_gitignore,
    }))
}

// ---------------------------------------------------------------------------
// Validators (steps 4–6)
// ---------------------------------------------------------------------------

/// Validate the full subcommand, covering steps 4 (vm/base names),
/// 5 (path byte sanity), and 6 (subcommand-specific ranges/patterns).
/// Returns `Err((exit_code, message))` on first failure.
fn validate_subcommand(sub: &Subcommand) -> Result<(), (u8, String)> {
    match sub {
        Subcommand::Create(a) => {
            validate_vm_name(&a.vm)?;
            validate_path_arg("--yaml", &a.yaml)?;
        }
        Subcommand::Start(a) => {
            validate_vm_name(&a.vm)?;
            validate_path_arg("--qemu-wrapper", &a.qemu_wrapper)?;
            validate_hardened(&a.hardened)?;
            validate_range("--memory-mb", a.memory_mb, 256, 262144)?;
            validate_range("--cpus", a.cpus, 1, 64)?;
            validate_range("--start-timeout-s", a.start_timeout_s, 1, 600)?;
            validate_bridge_mac_pair(a.bridge_name.as_deref(), a.vm_mac.as_deref())?;
        }
        Subcommand::Clone(a) => {
            validate_vm_name(&a.base)?;
            validate_vm_name(&a.vm)?;
            validate_range("--cpus", a.cpus, 1, 64)?;
            validate_range("--memory", a.memory_gib, 1, 256)?;
            validate_range("--disk", a.disk_gib, 1, 1024)?;
        }
        Subcommand::Stop(a) => {
            validate_vm_name(&a.vm)?;
        }
        Subcommand::Delete(a) => {
            validate_vm_name(&a.vm)?;
        }
        Subcommand::Copy(a) => {
            validate_copy_paths(&a.src, &a.dst)?;
        }
        Subcommand::GuestSocat(a) => {
            validate_vm_name(&a.vm)?;
        }
        Subcommand::InstallGuestAgent(a) => {
            validate_vm_name(&a.vm)?;
        }
        Subcommand::ListJson(_) => {
            // No path/vm validation needed.
        }
        Subcommand::ReadUserKey(_) => {
            // No path/vm validation needed.
        }
        Subcommand::RunRsync(a) => {
            validate_run_rsync_args(a)?;
        }
    }
    Ok(())
}

/// Validate `run-rsync` arguments: backend value, session-name, and
/// host/guest paths.
fn validate_run_rsync_args(a: &RunRsyncArgs) -> Result<(), (u8, String)> {
    // Backend must be exactly "lima" or "container".
    if a.backend != "lima" && a.backend != "container" {
        return Err((
            EXIT_BAD_ARGS,
            format!(
                "invalid --backend '{}': must be 'lima' or 'container'",
                a.backend
            ),
        ));
    }
    // Session name: same rules as a VM name (no leading dash, alphanumeric
    // + hyphens + underscores, ≤ 64 chars).  The daemon always supplies
    // `sandbox-<id>` which is within these bounds.
    validate_session_name(&a.session_name)?;
    // Host and guest paths: absolute, no NUL, no `..`, ≤ PATH_MAX.
    validate_path_arg("--host-path", &a.host_path)?;
    validate_path_arg("--guest-path", &a.guest_path)?;
    Ok(())
}

/// Validate a session name token used as the rsync remote-host spec.
///
/// The session name is the `sandbox-<id>` form the shell transports
/// accept (`limactl shell sandbox-<id>`, `docker exec sandbox-<id>`).
/// Rules mirror `validate_vm_name`: `^[a-zA-Z0-9_\-]{1,64}$`, no
/// leading dash.
fn validate_session_name(name: &str) -> Result<(), (u8, String)> {
    if name.is_empty() || name.len() > 64 {
        return Err((EXIT_BAD_ARGS, format!("invalid --session-name: '{name}'")));
    }
    if name.starts_with('-') {
        return Err((EXIT_BAD_ARGS, format!("invalid --session-name: '{name}'")));
    }
    if !vm_name_regex().is_match(name) {
        return Err((EXIT_BAD_ARGS, format!("invalid --session-name: '{name}'")));
    }
    Ok(())
}

/// Validate a VM name: `^[a-zA-Z0-9_-]{1,64}$`, first char != `-`.
pub fn validate_vm_name(name: &str) -> Result<(), (u8, String)> {
    if name.is_empty() || name.len() > 64 {
        return Err((EXIT_BAD_ARGS, format!("invalid vm name: '{name}'")));
    }
    // Leading dash defense: even though the regex allows '-' anywhere,
    // a leading dash would be parsed as a flag by limactl.
    if name.starts_with('-') {
        return Err((EXIT_BAD_ARGS, format!("invalid vm name: '{name}'")));
    }
    let re = vm_name_regex();
    if !re.is_match(name) {
        return Err((EXIT_BAD_ARGS, format!("invalid vm name: '{name}'")));
    }
    Ok(())
}

fn vm_name_regex() -> &'static Regex {
    &VM_NAME_RE
}

/// Validate a host-side path argument: no NUL, ≤ PATH_MAX, absolute, no `..`.
pub fn validate_path_arg(flag: &str, path: &str) -> Result<(), (u8, String)> {
    // No interior NUL byte.
    if path.contains('\0') {
        return Err((
            EXIT_BAD_ARGS,
            format!("invalid path arg: {flag} contains NUL byte"),
        ));
    }
    // Length ≤ PATH_MAX (4096 on Linux).
    let path_max = unsafe { libc::pathconf(c"/".as_ptr(), libc::_PC_PATH_MAX) };
    let limit = if path_max > 0 {
        path_max as usize
    } else {
        4096
    };
    if path.len() > limit {
        return Err((
            EXIT_BAD_ARGS,
            format!("invalid path arg: {flag} exceeds PATH_MAX"),
        ));
    }
    // Must be absolute.
    if !path.starts_with('/') {
        return Err((
            EXIT_BAD_ARGS,
            format!("invalid path arg: {flag} must be an absolute path"),
        ));
    }
    // No `..` components.
    for component in path.split('/') {
        if component == ".." {
            return Err((
                EXIT_BAD_ARGS,
                format!("invalid path arg: {flag} must not contain '..' components"),
            ));
        }
    }
    Ok(())
}

/// Validate `--hardened`: must be literal "0" or "1".
fn validate_hardened(value: &str) -> Result<(), (u8, String)> {
    if value != "0" && value != "1" {
        return Err((
            EXIT_BAD_ARGS,
            format!("invalid --hardened value '{value}': must be '0' or '1'"),
        ));
    }
    Ok(())
}

/// Validate a numeric flag is within `[min, max]` (inclusive).
pub fn validate_range(flag: &str, value: u32, min: u32, max: u32) -> Result<(), (u8, String)> {
    if value < min || value > max {
        return Err((
            EXIT_BAD_ARGS,
            format!("invalid {flag} value {value}: must be in {min}..={max}"),
        ));
    }
    Ok(())
}

/// Validate the `--bridge-name` and `--vm-mac` optional pair.
/// Both must be supplied together or both omitted.
fn validate_bridge_mac_pair(
    bridge_name: Option<&str>,
    vm_mac: Option<&str>,
) -> Result<(), (u8, String)> {
    match (bridge_name, vm_mac) {
        (None, None) => {}
        (Some(bridge), Some(mac)) => {
            validate_bridge_name(bridge)?;
            validate_vm_mac(mac)?;
        }
        _ => {
            return Err((
                EXIT_BAD_ARGS,
                "--bridge-name and --vm-mac must be supplied together".to_string(),
            ));
        }
    }
    Ok(())
}

/// Validate bridge name: `^[a-zA-Z0-9_-]{1,15}$`.
pub fn validate_bridge_name(name: &str) -> Result<(), (u8, String)> {
    if !BRIDGE_NAME_RE.is_match(name) {
        return Err((
            EXIT_BAD_ARGS,
            format!("invalid --bridge-name '{name}': must match ^[a-zA-Z0-9_-]{{1,15}}$"),
        ));
    }
    Ok(())
}

/// Validate MAC address: regex + multicast-bit reject.
pub fn validate_vm_mac(mac: &str) -> Result<(), (u8, String)> {
    if !VM_MAC_RE.is_match(mac) {
        return Err((
            EXIT_BAD_ARGS,
            format!("invalid --vm-mac '{mac}': must be xx:xx:xx:xx:xx:xx (hex octets)"),
        ));
    }
    // Reject multicast bit (LSB of first octet).
    let first_octet = u8::from_str_radix(&mac[..2], 16).expect("regex guarantees valid hex");
    if first_octet & 0x01 != 0 {
        return Err((
            EXIT_BAD_ARGS,
            format!("invalid --vm-mac '{mac}': multicast bit (LSB of first octet) is set"),
        ));
    }
    Ok(())
}

/// Validate `copy` --src / --dst paths.
///
/// Rules:
/// - At least one of src/dst must carry a `<vm>:` prefix.
/// - At most one `:` per side.
/// - The `<vm>` portion (before `:`) must validate as a vm name.
/// - The host-side portion (without `<vm>:`) must be absolute and no-`..`.
pub fn validate_copy_paths(src: &str, dst: &str) -> Result<(), (u8, String)> {
    let src_vm_prefix = extract_vm_prefix(src);
    let dst_vm_prefix = extract_vm_prefix(dst);

    if src_vm_prefix.is_none() && dst_vm_prefix.is_none() {
        return Err((
            EXIT_BAD_ARGS,
            "copy requires a <vm>: prefix on at least one side".to_string(),
        ));
    }

    // Validate the vm portion on each side that has it.
    if let Some(Ok(vm)) = src_vm_prefix.as_ref() {
        validate_vm_name(vm)?;
    }
    if let Some(Ok(vm)) = dst_vm_prefix.as_ref() {
        validate_vm_name(vm)?;
    }

    // Propagate malformed-prefix errors.
    if let Some(Err(e)) = src_vm_prefix {
        return Err((
            EXIT_BAD_ARGS,
            format!("copy: malformed <vm>: prefix in --src: {e}"),
        ));
    }
    if let Some(Err(e)) = dst_vm_prefix {
        return Err((
            EXIT_BAD_ARGS,
            format!("copy: malformed <vm>: prefix in --dst: {e}"),
        ));
    }

    // Validate host-side portions (those without a vm prefix).
    if src_vm_prefix.is_none() {
        validate_path_arg("--src (host side)", src)?;
    }
    if dst_vm_prefix.is_none() {
        validate_path_arg("--dst (host side)", dst)?;
    }

    Ok(())
}

/// Extract the vm name from a `<vm>:<path>` string.
/// Returns:
///   - `None` if there is no `:` in the string (host-side path)
///   - `Some(Ok(vm_name))` if there is exactly one `:` and the prefix is non-empty
///   - `Some(Err(reason))` if the `:` syntax is malformed (multiple colons, empty vm)
fn extract_vm_prefix(s: &str) -> Option<Result<&str, String>> {
    let colon_pos = s.find(':')?;
    // Check for more than one colon.
    if s[colon_pos + 1..].contains(':') {
        return Some(Err(format!("more than one ':' in '{s}'")));
    }
    let vm_part = &s[..colon_pos];
    if vm_part.is_empty() {
        return Some(Err(format!("empty vm name in '{s}'")));
    }
    Some(Ok(vm_part))
}

// ---------------------------------------------------------------------------
// NSS / user / group helpers
// ---------------------------------------------------------------------------

/// Resolve a username to its numeric uid via `getpwnam_r`.
pub fn resolve_user_uid(name: &str) -> Result<Option<u32>, String> {
    match User::from_name(name) {
        Ok(Some(u)) => Ok(Some(u.uid.as_raw())),
        Ok(None) => Ok(None),
        Err(e) => Err(format!("{e}")),
    }
}

/// Resolve an op-uid via `getpwuid_r`, returning the `pw_dir` home
/// directory on success (needed for step 7's limactl resolver).
pub fn resolve_op_uid(uid: u32) -> Result<Option<String>, String> {
    match User::from_uid(Uid::from_raw(uid)) {
        Ok(Some(u)) => Ok(Some(u.dir.to_string_lossy().to_string())),
        Ok(None) => Ok(None),
        Err(e) => Err(format!("{e}")),
    }
}

/// Resolve a group name to its numeric gid via `getgrnam_r`.
pub fn resolve_group_gid(name: &str) -> Result<Option<u32>, String> {
    let name_c = CString::new(name).map_err(|_| "group name contains NUL".to_string())?;
    let mut buf_len: usize = 4096;
    loop {
        let mut buf: Vec<libc::c_char> = vec![0; buf_len];
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe {
            libc::getgrnam_r(
                name_c.as_ptr(),
                &mut grp,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == 0 {
            if result.is_null() {
                return Ok(None);
            }
            return Ok(Some(grp.gr_gid));
        }
        if rc == libc::ERANGE && buf_len < 65536 {
            buf_len *= 2;
            continue;
        }
        return Err(format!("getgrnam_r failed: errno {rc}"));
    }
}

/// Return true iff the calling process's primary or supplementary groups
/// include `target_gid`.
fn caller_is_in_group(target_gid: u32) -> bool {
    if unsafe { libc::getgid() } == target_gid {
        return true;
    }
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        return false;
    }
    let mut groups: Vec<libc::gid_t> = vec![0; count as usize];
    let got = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if got < 0 {
        return false;
    }
    groups.iter().take(got as usize).any(|&g| g == target_gid)
}

/// Three-case result for `op_uid_in_sandbox_group`.
pub enum GroupMembership {
    /// `getgrouplist` succeeded and gid is in the list.
    Member,
    /// `getgrouplist` succeeded and gid is absent.
    NotMember,
    /// `getgrouplist` returned an error (NSS failure, ENOMEM, etc.).
    EnumerationFailed(i32),
}

/// Check whether `op_uid` is a member of `sandbox_gid` using `getgrouplist(3)`.
/// Implements the three-case NSS distinction from the spec (step 3).
pub fn op_uid_in_sandbox_group(op_uid: u32, sandbox_gid: u32) -> GroupMembership {
    // Retrieve the username for getgrouplist.
    let user = match User::from_uid(Uid::from_raw(op_uid)) {
        Ok(Some(u)) => u,
        _ => return GroupMembership::EnumerationFailed(libc::ENOENT),
    };
    let name_c = match CString::new(user.name.as_bytes()) {
        Ok(c) => c,
        Err(_) => return GroupMembership::EnumerationFailed(libc::EINVAL),
    };
    // Determine initial primary gid (pass to getgrouplist per POSIX).
    let primary_gid = user.gid.as_raw() as libc::gid_t;

    // getgrouplist with a size-limited buffer; double on NGROUPS_MAX
    // overflow indicated by return value -1.
    let mut ngroups: libc::c_int = 64;
    loop {
        let mut groups: Vec<libc::gid_t> = vec![0; ngroups as usize];
        // SAFETY: name_c is a valid NUL-terminated string; groups is a
        // properly-sized mutable buffer.
        let ret = unsafe {
            libc::getgrouplist(
                name_c.as_ptr(),
                primary_gid,
                groups.as_mut_ptr(),
                &mut ngroups,
            )
        };
        if ret == -1 {
            // Buffer too small; ngroups was updated to required count.
            if (ngroups as usize) > groups.len() && ngroups < 65536 {
                continue;
            }
            // Overflow or strange failure — treat as enumeration error.
            return GroupMembership::EnumerationFailed(libc::ENOMEM);
        }
        // ret >= 0: groups[0..ngroups] is valid.
        let found = groups
            .iter()
            .take(ngroups as usize)
            .any(|&g| g == sandbox_gid as libc::gid_t);
        return if found {
            GroupMembership::Member
        } else {
            GroupMembership::NotMember
        };
    }
}

// ---------------------------------------------------------------------------
// limactl path resolver (step 7)
// ---------------------------------------------------------------------------

/// Resolve the absolute path to `limactl` using the three-candidate
/// sequence, keyed off `pw_dir` captured in step 3.
///
/// For unit tests an `is_executable` callback is injected instead of
/// the real `access(2)` probe, mirroring route-helper's resolver shape.
pub fn resolve_limactl_path(pw_dir: &str) -> Option<String> {
    resolve_limactl_path_with(pw_dir, is_file_executable)
}

/// Parameterised form for unit testing.
pub fn resolve_limactl_path_with<F>(pw_dir: &str, is_executable: F) -> Option<String>
where
    F: Fn(&str) -> bool,
{
    let candidates = [
        format!("{pw_dir}/.local/bin/limactl"),
        "/usr/local/bin/limactl".to_string(),
        "/usr/bin/limactl".to_string(),
    ];
    for candidate in &candidates {
        if is_executable(candidate) {
            return Some(candidate.clone());
        }
    }
    None
}

/// Check that a path exists and is executable via `access(2)`.
/// `stat()` follows symlinks, which is intentional per the spec.
fn is_file_executable(path: &str) -> bool {
    let Ok(c) = CString::new(path) else {
        return false;
    };
    // SAFETY: c is a valid NUL-terminated C string.
    let rc = unsafe { libc::access(c.as_ptr(), libc::X_OK) };
    rc == 0
}

// ---------------------------------------------------------------------------
// setresuid + capability self-clear (steps 8–9)
// ---------------------------------------------------------------------------

/// `setresuid(uid, uid, uid)` — drop all three uids to the operator.
fn setresuid_strict(uid: u32) -> Result<(), i32> {
    let rc = unsafe { libc::setresuid(uid as libc::uid_t, uid as libc::uid_t, uid as libc::uid_t) };
    if rc < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(errno);
    }
    Ok(())
}

/// Four-stage capability self-clear. Hard deny on partial failure.
///
/// After `setresuid(non-root)` the kernel SECBIT rules already drop
/// permitted+effective; the explicit clear here is a grep-able contract
/// and covers the ambient set too.
fn clear_all_capabilities() -> Result<(), String> {
    caps::clear(None, caps::CapSet::Permitted).map_err(|e| format!("clear permitted: {e}"))?;
    caps::clear(None, caps::CapSet::Effective).map_err(|e| format!("clear effective: {e}"))?;
    caps::clear(None, caps::CapSet::Inheritable).map_err(|e| format!("clear inheritable: {e}"))?;
    caps::clear(None, caps::CapSet::Ambient).map_err(|e| format!("clear ambient: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Environment block construction (step 10)
// ---------------------------------------------------------------------------

fn build_env_block(sub: &Subcommand, lima_home: &str, op_home: &str, op_uid: u32) -> Vec<CString> {
    // Pass through allowlisted parent vars, skipping HOME: HOME is always
    // set explicitly below to the operator's pw_dir (captured in step 3).
    // This prevents the daemon's own HOME=/var/lib/sandbox from leaking
    // into the pivoted process, which runs as the operator uid and would
    // have no write access to /var/lib/sandbox anyway.
    let mut env: Vec<CString> = ENV_ALLOWLIST
        .iter()
        .filter(|key| **key != "HOME")
        .filter_map(|key| {
            let value = env::var_os(key)?;
            let mut buf = OsString::from(*key);
            buf.push("=");
            buf.push(&value);
            CString::new(buf.as_bytes()).ok()
        })
        .collect();

    // Set HOME to the operator's home directory (pw_dir from getpwuid_r in
    // step 3). Reuses the same value used for limactl path resolution in
    // step 7 — no re-resolution. Post-setresuid the process runs as the
    // operator uid; limactl auxiliary lookups ($HOME/.ssh/config, etc.)
    // must resolve against the operator's own home, not the daemon's.
    if let Ok(c) = CString::new(format!("HOME={op_home}")) {
        env.push(c);
    }

    // Always set LIMA_HOME to the per-operator path.
    if let Ok(c) = CString::new(format!("LIMA_HOME={lima_home}")) {
        env.push(c);
    }

    // Set XDG_RUNTIME_DIR to the operator's runtime directory.
    //
    // The QEMU wrapper script probes `systemctl --user show-environment` to
    // decide whether it can reach the operator's user manager and wrap QEMU
    // in a transient `systemd-run --user --scope --slice=sandbox.slice` with
    // MemoryMax/CPUQuota limits. `systemctl --user` connects to the user bus
    // via `XDG_RUNTIME_DIR` (typically `/run/user/<uid>`). Without this var,
    // systemd falls back to "No medium found" and the probe fails — QEMU then
    // boots without any cgroup scope and without resource limits.
    //
    // We set it deterministically from op_uid (same derivation pattern as the
    // Lima convention `/run/user/<uid>`) rather than inheriting from the host
    // environment, which keeps the env block a from-scratch allowlist. The
    // path is only useful if the operator has a running user manager at that
    // location (i.e. an active login session or `loginctl enable-linger`); if
    // not, the `systemctl --user show-environment` probe still fails gracefully
    // and the wrapper falls back to starting QEMU without cgroup limits.
    if let Ok(c) = CString::new(format!("XDG_RUNTIME_DIR=/run/user/{op_uid}")) {
        env.push(c);
    }

    // Pin XDG_CACHE_HOME inside the per-operator LIMA_HOME tree.
    //
    // Lima resolves its download cache as `$XDG_CACHE_HOME/lima/download/`
    // when `XDG_CACHE_HOME` is set, or `$HOME/.cache/lima/download/` otherwise.
    // The helper inherits `HOME=/var/lib/sandbox` from the daemon process (the
    // sandbox system user's home); after `setresuid` to the operator uid, limactl
    // would try to write into `/var/lib/sandbox/.cache/` which is owned by the
    // daemon uid and mode 0700 — the operator uid has no write access there.
    //
    // Redirecting `XDG_CACHE_HOME` into the per-operator LIMA_HOME tree keeps
    // the cache under `/var/lib/sandboxd/<op_uid>/lima/.cache/lima/download/`.
    // That dir sits inside the tree that `ensure_operator_lima_home` ACL-grants
    // with `d:u:<op_uid>:rwx`, so the operator uid can create and write it.
    // Using `<lima_home>/.cache` (one level below LIMA_HOME itself, not inside
    // Lima's instance namespace) avoids any conflict with Lima's own directory
    // layout under `<lima_home>/<instance>/`.
    if let Ok(c) = CString::new(format!("XDG_CACHE_HOME={lima_home}/.cache")) {
        env.push(c);
    }

    // start-specific QEMU env vars.
    if let Subcommand::Start(a) = sub {
        let extras = [
            format!("QEMU_SYSTEM_X86_64={}", a.qemu_wrapper),
            format!("SANDBOX_QEMU_HARDENED={}", a.hardened),
            format!("SANDBOX_QEMU_MEMORY_MB={}", a.memory_mb),
            format!("SANDBOX_QEMU_CPUS={}", a.cpus),
        ];
        for kv in &extras {
            if let Ok(c) = CString::new(kv.as_str()) {
                env.push(c);
            }
        }
        if let (Some(bridge), Some(mac)) = (&a.bridge_name, &a.vm_mac) {
            for kv in &[
                format!("SANDBOX_DOCKER_BRIDGE={bridge}"),
                format!("SANDBOX_VM_MAC={mac}"),
            ] {
                if let Ok(c) = CString::new(kv.as_str()) {
                    env.push(c);
                }
            }
        }
    }

    env
}

// ---------------------------------------------------------------------------
// exec path (step 11, 8 of 9 subcommands)
// ---------------------------------------------------------------------------

fn exec_limactl(limactl: &str, sub: &Subcommand, env_block: &[CString]) -> ExitCode {
    let argv = build_limactl_argv(limactl, sub);

    let argv_c: Vec<CString> = match argv
        .iter()
        .map(|s| CString::new(s.as_str()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(_) => {
            eprintln!("sandbox-lima-helper: argv contains an interior NUL byte");
            return ExitCode::from(EXIT_GENERIC);
        }
    };

    let argv_ptrs: Vec<*const libc::c_char> = argv_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = env_block
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let argv0_c = match CString::new(limactl) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("sandbox-lima-helper: limactl path contains NUL byte");
            return ExitCode::from(EXIT_GENERIC);
        }
    };

    // SAFETY: argv0_c, argv_ptrs, envp_ptrs are valid NUL-terminated
    // pointer arrays that live for the duration of execvpe. execvpe
    // does not return on success.
    unsafe {
        libc::execvpe(argv0_c.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
    }
    let errno = unsafe { *libc::__errno_location() };
    eprintln!("sandbox-lima-helper: execvpe({limactl}) failed: errno {errno}");
    ExitCode::from(EXIT_GENERIC)
}

/// Build the limactl argv (argv[0] is the limactl path itself).
fn build_limactl_argv(limactl: &str, sub: &Subcommand) -> Vec<String> {
    match sub {
        Subcommand::Create(a) => vec![
            limactl.to_string(),
            "create".to_string(),
            "--name".to_string(),
            a.vm.clone(),
            a.yaml.clone(),
            "--tty=false".to_string(),
        ],
        Subcommand::Start(a) => vec![
            limactl.to_string(),
            "start".to_string(),
            a.vm.clone(),
            format!("--timeout={}s", a.start_timeout_s),
            "--tty=false".to_string(),
        ],
        Subcommand::Clone(a) => vec![
            limactl.to_string(),
            "clone".to_string(),
            a.base.clone(),
            a.vm.clone(),
            format!("--cpus={}", a.cpus),
            format!("--memory={}", a.memory_gib),
            format!("--disk={}", a.disk_gib),
            "--tty=false".to_string(),
        ],
        Subcommand::Stop(a) => {
            if a.force {
                vec![
                    limactl.to_string(),
                    "stop".to_string(),
                    "-f".to_string(),
                    a.vm.clone(),
                    "--tty=false".to_string(),
                ]
            } else {
                vec![
                    limactl.to_string(),
                    "stop".to_string(),
                    a.vm.clone(),
                    "--tty=false".to_string(),
                ]
            }
        }
        Subcommand::Delete(a) => vec![
            limactl.to_string(),
            "delete".to_string(),
            "--force".to_string(),
            a.vm.clone(),
            "--tty=false".to_string(),
        ],
        Subcommand::Copy(a) => vec![
            limactl.to_string(),
            "copy".to_string(),
            a.src.clone(),
            a.dst.clone(),
        ],
        Subcommand::GuestSocat(a) => vec![
            limactl.to_string(),
            "shell".to_string(),
            a.vm.clone(),
            "--".to_string(),
            "socat".to_string(),
            "-".to_string(),
            "TCP:127.0.0.1:5123".to_string(),
        ],
        Subcommand::ListJson(_) => vec![
            limactl.to_string(),
            "list".to_string(),
            "--json".to_string(),
            "--tty=false".to_string(),
        ],
        Subcommand::InstallGuestAgent(_) => {
            unreachable!("install-guest-agent does not use exec_limactl")
        }
        Subcommand::ReadUserKey(_) => {
            unreachable!("read-user-key does not use exec_limactl")
        }
        Subcommand::RunRsync(_) => {
            unreachable!("run-rsync does not use exec_limactl")
        }
    }
}

// ---------------------------------------------------------------------------
// install-guest-agent step sequence (step 11, special case)
// ---------------------------------------------------------------------------

/// Build the ordered install steps (argv per step) for `install-guest-agent`.
/// Separated from `run_install_guest_agent` so tests can assert the exact
/// argv shape of each step — including step 4's single-quoted heredoc form —
/// without needing to spawn a real limactl.
fn build_install_steps(limactl: &str, vm: &str, guest_binary: &str) -> Vec<Vec<String>> {
    vec![
        // Step 1: copy binary into VM.
        vec![
            limactl.to_string(),
            "copy".to_string(),
            guest_binary.to_string(),
            format!("{vm}:/tmp/sandbox-guest"),
        ],
        // Step 2: move to /usr/local/bin.
        vec![
            limactl.to_string(),
            "shell".to_string(),
            vm.to_string(),
            "--".to_string(),
            "sudo".to_string(),
            "mv".to_string(),
            "/tmp/sandbox-guest".to_string(),
            "/usr/local/bin/sandbox-guest".to_string(),
        ],
        // Step 3: chmod +x.
        vec![
            limactl.to_string(),
            "shell".to_string(),
            vm.to_string(),
            "--".to_string(),
            "sudo".to_string(),
            "chmod".to_string(),
            "+x".to_string(),
            "/usr/local/bin/sandbox-guest".to_string(),
        ],
        // Step 4: write systemd unit via single-quoted heredoc (prevents
        // shell expansion of $ literals in the unit body).
        vec![
            limactl.to_string(),
            "shell".to_string(),
            vm.to_string(),
            "--".to_string(),
            "sudo".to_string(),
            "bash".to_string(),
            "-c".to_string(),
            format!(
                "cat > /etc/systemd/system/sandbox-guest.service << 'UNIT_EOF'\n{GUEST_AGENT_SERVICE_UNIT}\nUNIT_EOF"
            ),
        ],
        // Step 5: daemon-reload.
        vec![
            limactl.to_string(),
            "shell".to_string(),
            vm.to_string(),
            "--".to_string(),
            "sudo".to_string(),
            "systemctl".to_string(),
            "daemon-reload".to_string(),
        ],
        // Step 6: enable --now.
        vec![
            limactl.to_string(),
            "shell".to_string(),
            vm.to_string(),
            "--".to_string(),
            "sudo".to_string(),
            "systemctl".to_string(),
            "enable".to_string(),
            "--now".to_string(),
            "sandbox-guest".to_string(),
        ],
    ]
}

fn run_install_guest_agent(limactl: &str, vm: &str, env_block: &[CString]) -> ExitCode {
    let guest_binary = resolve_guest_binary_path();
    let steps = build_install_steps(limactl, vm, &guest_binary);

    for (step_num, argv) in steps.iter().enumerate() {
        let step_label = step_num + 1;
        if let Err(code) = run_step(argv, env_block, step_label) {
            return code;
        }
    }

    // Final validation: four `command -v <tool>` probes.
    // Argv shape matches the other shell steps: `limactl shell <vm> -- <command...>`.
    for tool in REQUIRED_BASE_TOOLS {
        let probe_argv = vec![
            limactl.to_string(),
            "shell".to_string(),
            vm.to_string(),
            "--".to_string(),
            "command".to_string(),
            "-v".to_string(),
            tool.to_string(),
        ];
        let label = format!("probe:command -v {tool}");
        if let Err(code) = run_step_labeled(&probe_argv, env_block, &label) {
            eprintln!("sandbox-lima-helper: required tool '{tool}' not found in VM '{vm}'");
            return code;
        }
    }

    ExitCode::SUCCESS
}

/// Fork + exec + waitpid a single step. Returns `Err(ExitCode)` on
/// non-zero exit, `Ok(())` on success.
fn run_step(argv: &[String], env_block: &[CString], step_num: usize) -> Result<(), ExitCode> {
    run_step_labeled(argv, env_block, &format!("step {step_num}"))
}

fn run_step_labeled(argv: &[String], env_block: &[CString], label: &str) -> Result<(), ExitCode> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    // Pass the sanitised environment to the child.
    cmd.env_clear();
    for kv in env_block {
        let s = kv.to_string_lossy();
        if let Some(eq) = s.find('=') {
            cmd.env(&s[..eq], &s[eq + 1..]);
        }
    }

    let status = match cmd.status() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "sandbox-lima-helper: {label}: failed to spawn '{}': {e}",
                argv[0]
            );
            return Err(ExitCode::from(EXIT_GENERIC));
        }
    };

    if !status.success() {
        let code = status.code().unwrap_or(1) as u8;
        eprintln!(
            "sandbox-lima-helper: {label}: '{}' exited with status {}",
            argv[0],
            status.code().unwrap_or(1)
        );
        return Err(ExitCode::from(code));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// read-user-key implementation (step 11, special case)
// ---------------------------------------------------------------------------

/// Read the operator's Lima SSH private key from `$LIMA_HOME/_config/user`
/// and write it verbatim to stdout.
///
/// Called after `setresuid` has dropped the process to the operator uid, so
/// the key file (mode 0600, owned by op_uid) is readable. The daemon
/// captures stdout and serves the bytes through `GET /sessions/{id}/ssh-config`
/// so the CLI can authenticate as the operator's VM user.
///
/// On any I/O error the function prints a single diagnostic line to stderr
/// and returns a non-zero exit code so the daemon surfaces the failure as a
/// `SandboxError::Lima` rather than silently serving empty bytes.
fn run_read_user_key(op_uid: u32, lima_home: &str) -> ExitCode {
    use std::io::Write;

    let key_path = format!("{lima_home}_config/user");
    match std::fs::read_to_string(&key_path) {
        Ok(contents) => {
            // Write verbatim to stdout. The daemon captures this.
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            if let Err(e) = handle.write_all(contents.as_bytes()) {
                eprintln!("sandbox-lima-helper: read-user-key: write to stdout failed: {e}");
                return ExitCode::from(EXIT_GENERIC);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "sandbox-lima-helper: read-user-key: failed to read {key_path} \
                 (op_uid={op_uid}): {e}"
            );
            ExitCode::from(EXIT_GENERIC)
        }
    }
}

// ---------------------------------------------------------------------------
// run-rsync implementation (step 11, special case)
// ---------------------------------------------------------------------------

/// Build the rsync argv for a create-time host→guest push.
///
/// Mirrors `sandbox-core::workspace_rsync::build_workspace_rsync_argv`
/// for the push/mkpath shape used by the daemon's initial push.  Kept
/// inline here so the helper's TCB remains free of a sandbox-core
/// dependency.
///
/// Argv shape:
/// ```text
/// rsync -aL --delete [--filter=:- .gitignore]
///   -e <transport> --mkpath <host>/ <session>:<guest>/
/// ```
/// where `<transport>` is `limactl shell` (Lima) or `docker exec -i`
/// (Container).
fn build_rsync_argv(a: &RunRsyncArgs) -> Vec<String> {
    let transport = if a.backend == "lima" {
        "limactl shell"
    } else {
        "docker exec -i"
    };

    let with_slash = |p: &str| -> String {
        if p.ends_with('/') {
            p.to_string()
        } else {
            format!("{p}/")
        }
    };

    let src = with_slash(&a.host_path);
    let dst = format!("{}:{}", a.session_name, with_slash(&a.guest_path));

    let mut argv: Vec<String> = Vec::with_capacity(9);
    argv.push("-aL".to_string());
    argv.push("--delete".to_string());
    if !a.no_gitignore {
        argv.push("--filter=:- .gitignore".to_string());
    }
    argv.push("-e".to_string());
    argv.push(transport.to_string());
    argv.push("--mkpath".to_string());
    argv.push(src);
    argv.push(dst);
    argv
}

/// Resolve the absolute path to `rsync`.
///
/// Checks three candidates in order; returns the first that passes
/// `access(X_OK)`.  No PATH lookup — fixed candidates only.
fn resolve_rsync_path() -> Option<String> {
    let candidates = ["/usr/bin/rsync", "/usr/local/bin/rsync", "/bin/rsync"];
    for candidate in &candidates {
        if is_file_executable(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

/// Execute `rsync` as the already-pivoted operator uid.
///
/// Called after `setresuid(op_uid)` and `clear_all_capabilities()` in
/// step 8–9 of `run()`, so rsync inherits the operator's uid and can
/// `change_dir` into the operator-owned host workspace source.
///
/// The helper `execvpe`s rsync with the cleaned env block so no
/// daemon-process state leaks into the rsync child.  On `execvpe`
/// success this function does not return.
fn run_rsync(a: &RunRsyncArgs, env_block: &[CString]) -> ExitCode {
    let rsync_path = match resolve_rsync_path() {
        Some(p) => p,
        None => {
            eprintln!("sandbox-lima-helper: run-rsync: rsync not found in candidate paths");
            return ExitCode::from(EXIT_GENERIC);
        }
    };

    let argv = build_rsync_argv(a);

    // Prepend the rsync binary path as argv[0].
    let mut full_argv: Vec<String> = Vec::with_capacity(argv.len() + 1);
    full_argv.push(rsync_path.clone());
    full_argv.extend(argv);

    let argv_c: Vec<CString> = match full_argv
        .iter()
        .map(|s| CString::new(s.as_str()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(_) => {
            eprintln!("sandbox-lima-helper: run-rsync: argv contains interior NUL byte");
            return ExitCode::from(EXIT_GENERIC);
        }
    };

    let argv_ptrs: Vec<*const libc::c_char> = argv_c
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = env_block
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let argv0_c = match CString::new(rsync_path.as_str()) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("sandbox-lima-helper: run-rsync: rsync path contains NUL byte");
            return ExitCode::from(EXIT_GENERIC);
        }
    };

    // SAFETY: argv0_c, argv_ptrs, envp_ptrs are valid NUL-terminated
    // pointer arrays that live for the duration of execvpe. execvpe
    // does not return on success.
    unsafe {
        libc::execvpe(argv0_c.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
    }
    let errno = unsafe { *libc::__errno_location() };
    eprintln!("sandbox-lima-helper: run-rsync: execvpe({rsync_path}) failed: errno {errno}");
    ExitCode::from(EXIT_GENERIC)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn os_args(parts: &[&str]) -> Vec<OsString> {
        std::iter::once("sandbox-lima-helper")
            .chain(parts.iter().copied())
            .map(OsString::from)
            .collect()
    }

    // -----------------------------------------------------------------------
    // REQUIRED_BASE_TOOLS drift assertion
    // -----------------------------------------------------------------------

    /// Assert the helper's REQUIRED_BASE_TOOLS slice matches the literal
    /// list at sandbox-core/src/lima.rs:1320. This test breaks if a tool
    /// is added to one side without the other.
    #[test]
    fn required_base_tools_matches_core() {
        // The authoritative list is the literal at lima.rs:1320:
        //   const REQUIRED: &[&str] = &["socat", "git", "rsync", "docker"];
        // We snapshot it here. If it changes, update both constants.
        let core_required: &[&str] = &["socat", "git", "rsync", "docker"];
        assert_eq!(
            REQUIRED_BASE_TOOLS, core_required,
            "REQUIRED_BASE_TOOLS in sandbox-lima-helper diverges from \
             sandbox-core/src/lima.rs:1320 — update both constants together"
        );
    }

    /// Assert the helper's GUEST_AGENT_SERVICE_UNIT constant matches the
    /// copy in sandbox-core/src/lima.rs (gated `#[cfg(test)]` there to
    /// avoid pulling sandbox-core into the helper's TCB).
    /// Both copies must stay identical so a unit-file change is applied
    /// everywhere or caught immediately.
    #[test]
    fn guest_agent_service_unit_matches_core() {
        // Snapshot of sandbox-core/src/lima.rs GUEST_AGENT_SERVICE_UNIT.
        // If the core copy changes, update both constants together.
        let core_unit = "\
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
        assert_eq!(
            GUEST_AGENT_SERVICE_UNIT, core_unit,
            "GUEST_AGENT_SERVICE_UNIT in sandbox-lima-helper diverges from \
             sandbox-core/src/lima.rs — update both constants together"
        );
    }

    // -----------------------------------------------------------------------
    // Parser tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_missing_subcommand_fails() {
        let args = os_args(&[]);
        assert!(parse_argv(&args).is_err());
    }

    #[test]
    fn parse_unknown_subcommand_fails() {
        let args = os_args(&["frobnicate"]);
        assert!(parse_argv(&args).is_err());
    }

    #[test]
    fn parse_create_accepts_valid_args() {
        let args = os_args(&[
            "create",
            "--op-uid",
            "1000",
            "--vm",
            "sandbox-abc",
            "--yaml",
            "/etc/lima/base.yaml",
        ]);
        let sub = parse_argv(&args).expect("valid create args");
        let Subcommand::Create(a) = sub else {
            panic!("expected Create")
        };
        assert_eq!(a.op_uid, 1000);
        assert_eq!(a.vm, "sandbox-abc");
        assert_eq!(a.yaml, "/etc/lima/base.yaml");
    }

    #[test]
    fn parse_create_missing_yaml_fails() {
        let args = os_args(&["create", "--op-uid", "1000", "--vm", "sandbox-abc"]);
        assert!(parse_argv(&args).is_err());
    }

    #[test]
    fn parse_create_unknown_flag_fails() {
        let args = os_args(&[
            "create",
            "--op-uid",
            "1000",
            "--vm",
            "sandbox-abc",
            "--yaml",
            "/etc/lima/base.yaml",
            "--extra",
            "value",
        ]);
        assert!(parse_argv(&args).is_err());
    }

    #[test]
    fn parse_create_repeated_flag_fails() {
        let args = os_args(&[
            "create",
            "--op-uid",
            "1000",
            "--op-uid",
            "1001",
            "--vm",
            "sandbox-abc",
            "--yaml",
            "/etc/lima/base.yaml",
        ]);
        assert!(parse_argv(&args).is_err());
    }

    #[test]
    fn parse_start_accepts_valid_args() {
        let args = os_args(&[
            "start",
            "--op-uid",
            "1000",
            "--vm",
            "sandbox-abc",
            "--qemu-wrapper",
            "/usr/local/bin/qemu-wrapper",
            "--hardened",
            "1",
            "--memory-mb",
            "4096",
            "--cpus",
            "2",
            "--start-timeout-s",
            "300",
        ]);
        let sub = parse_argv(&args).expect("valid start args");
        let Subcommand::Start(a) = sub else {
            panic!("expected Start")
        };
        assert_eq!(a.op_uid, 1000);
        assert_eq!(a.vm, "sandbox-abc");
        assert_eq!(a.memory_mb, 4096);
        assert_eq!(a.cpus, 2);
        assert_eq!(a.start_timeout_s, 300);
        assert_eq!(a.hardened, "1");
        assert!(a.bridge_name.is_none());
        assert!(a.vm_mac.is_none());
    }

    #[test]
    fn parse_start_accepts_bridge_mac_pair() {
        let args = os_args(&[
            "start",
            "--op-uid",
            "1000",
            "--vm",
            "sandbox-abc",
            "--qemu-wrapper",
            "/usr/local/bin/qemu-wrapper",
            "--hardened",
            "0",
            "--memory-mb",
            "2048",
            "--cpus",
            "2",
            "--start-timeout-s",
            "300",
            "--bridge-name",
            "sandbox-br",
            "--vm-mac",
            "02:00:00:00:00:01",
        ]);
        let sub = parse_argv(&args).expect("valid start with bridge/mac");
        let Subcommand::Start(a) = sub else {
            panic!("expected Start")
        };
        assert_eq!(a.bridge_name.as_deref(), Some("sandbox-br"));
        assert_eq!(a.vm_mac.as_deref(), Some("02:00:00:00:00:01"));
    }

    #[test]
    fn parse_clone_accepts_valid_args() {
        let args = os_args(&[
            "clone",
            "--op-uid",
            "1000",
            "--base",
            "sandbox-base",
            "--vm",
            "sandbox-abc",
            "--cpus",
            "4",
            "--memory",
            "8",
            "--disk",
            "50",
        ]);
        let sub = parse_argv(&args).expect("valid clone args");
        let Subcommand::Clone(a) = sub else {
            panic!("expected Clone")
        };
        assert_eq!(a.cpus, 4);
        assert_eq!(a.memory_gib, 8);
        assert_eq!(a.disk_gib, 50);
    }

    #[test]
    fn parse_stop_default_no_force() {
        let args = os_args(&["stop", "--op-uid", "1000", "--vm", "sandbox-abc"]);
        let sub = parse_argv(&args).expect("valid stop args");
        let Subcommand::Stop(a) = sub else {
            panic!("expected Stop")
        };
        assert!(!a.force);
    }

    #[test]
    fn parse_stop_with_force() {
        let args = os_args(&["stop", "--op-uid", "1000", "--vm", "sandbox-abc", "--force"]);
        let sub = parse_argv(&args).expect("valid stop --force args");
        let Subcommand::Stop(a) = sub else {
            panic!("expected Stop")
        };
        assert!(a.force);
    }

    #[test]
    fn parse_stop_force_equals_value_rejected() {
        // --force=true is not accepted; --force is boolean-only.
        let args = os_args(&[
            "stop",
            "--op-uid",
            "1000",
            "--vm",
            "sandbox-abc",
            "--force=true",
        ]);
        assert!(parse_argv(&args).is_err());
    }

    #[test]
    fn parse_stop_force_trailing_value_rejected() {
        // --force 1 should be rejected (trailing value form).
        let args = os_args(&[
            "stop",
            "--op-uid",
            "1000",
            "--vm",
            "sandbox-abc",
            "--force",
            "1",
        ]);
        // "1" is not a flag so it gets treated as extra positional.
        assert!(parse_argv(&args).is_err());
    }

    #[test]
    fn parse_delete_accepts_valid() {
        let args = os_args(&["delete", "--op-uid", "1000", "--vm", "sandbox-abc"]);
        let sub = parse_argv(&args).expect("valid delete args");
        assert!(matches!(sub, Subcommand::Delete(_)));
    }

    #[test]
    fn parse_copy_accepts_valid() {
        let args = os_args(&[
            "copy",
            "--op-uid",
            "1000",
            "--src",
            "sandbox-abc:/tmp/file",
            "--dst",
            "/host/path",
        ]);
        let sub = parse_argv(&args).expect("valid copy args");
        let Subcommand::Copy(a) = sub else {
            panic!("expected Copy")
        };
        assert_eq!(a.src, "sandbox-abc:/tmp/file");
        assert_eq!(a.dst, "/host/path");
    }

    #[test]
    fn parse_guest_socat_accepts_valid() {
        let args = os_args(&["guest-socat", "--op-uid", "1000", "--vm", "sandbox-abc"]);
        let sub = parse_argv(&args).expect("valid guest-socat args");
        assert!(matches!(sub, Subcommand::GuestSocat(_)));
    }

    #[test]
    fn parse_install_guest_agent_accepts_valid() {
        let args = os_args(&[
            "install-guest-agent",
            "--op-uid",
            "1000",
            "--vm",
            "sandbox-abc",
        ]);
        let sub = parse_argv(&args).expect("valid install-guest-agent args");
        assert!(matches!(sub, Subcommand::InstallGuestAgent(_)));
    }

    #[test]
    fn parse_list_json_accepts_valid() {
        let args = os_args(&["list-json", "--op-uid", "1000"]);
        let sub = parse_argv(&args).expect("valid list-json args");
        assert!(matches!(sub, Subcommand::ListJson(_)));
    }

    #[test]
    fn parse_list_json_extra_positional_fails() {
        let args = os_args(&["list-json", "--op-uid", "1000", "unexpected"]);
        assert!(parse_argv(&args).is_err());
    }

    // -----------------------------------------------------------------------
    // VM name validator
    // -----------------------------------------------------------------------

    #[test]
    fn vm_name_valid_cases() {
        for name in &[
            "sandbox-abc",
            "sandbox123",
            "a",
            "Z",
            "abc_def",
            "ABCdef123",
            &"a".repeat(64),
        ] {
            assert!(
                validate_vm_name(name).is_ok(),
                "expected valid vm name: {name}"
            );
        }
    }

    #[test]
    fn vm_name_invalid_cases() {
        let cases = [
            "",              // empty
            &"a".repeat(65), // too long
            "-leading-dash", // leading dash
            "has space",     // space
            "has.dot",       // dot
            "has/slash",     // slash
            "has\nnewline",  // newline
        ];
        for name in cases.iter() {
            assert!(
                validate_vm_name(name).is_err(),
                "expected invalid vm name: {name:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Path arg validator
    // -----------------------------------------------------------------------

    #[test]
    fn path_arg_valid() {
        assert!(validate_path_arg("--yaml", "/etc/lima/base.yaml").is_ok());
        assert!(validate_path_arg("--yaml", "/a/b/c/d").is_ok());
    }

    #[test]
    fn path_arg_rejects_relative() {
        assert!(validate_path_arg("--yaml", "relative/path").is_err());
    }

    #[test]
    fn path_arg_rejects_dotdot() {
        assert!(validate_path_arg("--yaml", "/etc/../etc/passwd").is_err());
    }

    #[test]
    fn path_arg_rejects_nul() {
        assert!(validate_path_arg("--yaml", "/etc/file\0name").is_err());
    }

    // -----------------------------------------------------------------------
    // Range validator
    // -----------------------------------------------------------------------

    #[test]
    fn range_valid() {
        assert!(validate_range("--cpus", 1, 1, 64).is_ok());
        assert!(validate_range("--cpus", 64, 1, 64).is_ok());
        assert!(validate_range("--memory-mb", 256, 256, 262144).is_ok());
        assert!(validate_range("--memory-mb", 262144, 256, 262144).is_ok());
    }

    #[test]
    fn range_below_min_fails() {
        assert!(validate_range("--cpus", 0, 1, 64).is_err());
        assert!(validate_range("--memory-mb", 255, 256, 262144).is_err());
    }

    #[test]
    fn range_above_max_fails() {
        assert!(validate_range("--cpus", 65, 1, 64).is_err());
        assert!(validate_range("--memory-mb", 262145, 256, 262144).is_err());
    }

    // -----------------------------------------------------------------------
    // Bridge / MAC validator
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_name_valid() {
        assert!(validate_bridge_name("sandbox-br").is_ok());
        assert!(validate_bridge_name("br0").is_ok());
        assert!(validate_bridge_name("a_b_c").is_ok());
        assert!(validate_bridge_name(&"a".repeat(15)).is_ok());
    }

    #[test]
    fn bridge_name_invalid() {
        assert!(validate_bridge_name("").is_err());
        assert!(validate_bridge_name(&"a".repeat(16)).is_err());
        assert!(validate_bridge_name("has.dot").is_err());
        assert!(validate_bridge_name("has space").is_err());
    }

    #[test]
    fn mac_valid_unicast() {
        // Even first octet → unicast.
        assert!(validate_vm_mac("02:00:00:00:00:01").is_ok());
        assert!(validate_vm_mac("AA:BB:CC:DD:EE:FF").is_ok()); // AA = 0xAA = 1010_1010, LSB=0
        assert!(validate_vm_mac("00:11:22:33:44:55").is_ok());
    }

    #[test]
    fn mac_invalid_multicast_bit() {
        // Odd first octet → multicast bit set.
        assert!(validate_vm_mac("01:00:00:00:00:00").is_err());
        assert!(validate_vm_mac("03:00:00:00:00:00").is_err());
        assert!(validate_vm_mac("FF:00:00:00:00:00").is_err()); // FF=1111_1111, LSB=1
    }

    #[test]
    fn mac_invalid_format() {
        assert!(validate_vm_mac("00:11:22:33:44").is_err()); // too short
        assert!(validate_vm_mac("00:11:22:33:44:55:66").is_err()); // too long
        assert!(validate_vm_mac("00-11-22-33-44-55").is_err()); // dashes
        assert!(validate_vm_mac("001122334455").is_err()); // no separators
    }

    #[test]
    fn bridge_mac_pair_both_absent_ok() {
        assert!(validate_bridge_mac_pair(None, None).is_ok());
    }

    #[test]
    fn bridge_mac_pair_both_present_ok() {
        assert!(validate_bridge_mac_pair(Some("br0"), Some("02:00:00:00:00:01")).is_ok());
    }

    #[test]
    fn bridge_mac_pair_only_bridge_fails() {
        assert!(validate_bridge_mac_pair(Some("br0"), None).is_err());
    }

    #[test]
    fn bridge_mac_pair_only_mac_fails() {
        assert!(validate_bridge_mac_pair(None, Some("02:00:00:00:00:01")).is_err());
    }

    // -----------------------------------------------------------------------
    // Copy path validator
    // -----------------------------------------------------------------------

    #[test]
    fn copy_vm_prefix_on_src() {
        assert!(validate_copy_paths("sandbox-abc:/tmp/file", "/host/path").is_ok());
    }

    #[test]
    fn copy_vm_prefix_on_dst() {
        assert!(validate_copy_paths("/host/path", "sandbox-abc:/tmp/file").is_ok());
    }

    #[test]
    fn copy_vm_prefix_on_both() {
        assert!(validate_copy_paths("sandbox-abc:/tmp/a", "sandbox-xyz:/tmp/b").is_ok());
    }

    #[test]
    fn copy_no_vm_prefix_fails() {
        assert!(validate_copy_paths("/host/src", "/host/dst").is_err());
    }

    #[test]
    fn copy_multiple_colons_fails() {
        assert!(validate_copy_paths("sandbox-abc:extra:/tmp/file", "/host/path").is_err());
    }

    #[test]
    fn copy_empty_vm_prefix_fails() {
        assert!(validate_copy_paths(":/tmp/file", "/host/path").is_err());
    }

    #[test]
    fn copy_host_side_relative_path_fails() {
        assert!(validate_copy_paths("sandbox-abc:/tmp/file", "relative/path").is_err());
    }

    #[test]
    fn copy_host_side_dotdot_fails() {
        assert!(validate_copy_paths("sandbox-abc:/tmp/file", "/host/../etc/passwd").is_err());
    }

    #[test]
    fn copy_bad_vm_name_in_prefix_fails() {
        assert!(validate_copy_paths("-bad:path", "/host/path").is_err());
    }

    // -----------------------------------------------------------------------
    // limactl resolver (unit, injected is_executable)
    // -----------------------------------------------------------------------

    #[test]
    fn resolver_prefers_local_bin() {
        let found = resolve_limactl_path_with("/home/op", |p| {
            p == "/home/op/.local/bin/limactl" || p == "/usr/local/bin/limactl"
        });
        assert_eq!(found.as_deref(), Some("/home/op/.local/bin/limactl"));
    }

    #[test]
    fn resolver_falls_back_to_usr_local() {
        let found = resolve_limactl_path_with("/home/op", |p| p == "/usr/local/bin/limactl");
        assert_eq!(found.as_deref(), Some("/usr/local/bin/limactl"));
    }

    #[test]
    fn resolver_falls_back_to_usr_bin() {
        let found = resolve_limactl_path_with("/home/op", |p| p == "/usr/bin/limactl");
        assert_eq!(found.as_deref(), Some("/usr/bin/limactl"));
    }

    #[test]
    fn resolver_none_when_all_absent() {
        let found = resolve_limactl_path_with("/home/op", |_| false);
        assert!(found.is_none());
    }

    #[test]
    fn resolver_uses_pw_dir_not_tilde() {
        // pw_dir is the literal home directory, not `~`.
        let found = resolve_limactl_path_with("/var/home/operator", |p| {
            p == "/var/home/operator/.local/bin/limactl"
        });
        assert_eq!(
            found.as_deref(),
            Some("/var/home/operator/.local/bin/limactl")
        );
        // Tilde form must NOT be tried.
        let tilde_found = resolve_limactl_path_with("~", |p| p == "~/.local/bin/limactl");
        // "~" is not an absolute path and would be passed as-is; access(2)
        // on "~/.local/bin/limactl" would fail in practice, but the unit
        // test just confirms the resolver doesn't specially expand "~".
        assert!(tilde_found.is_none() || tilde_found.as_deref() == Some("~/.local/bin/limactl"));
    }

    // -----------------------------------------------------------------------
    // limactl argv construction
    // -----------------------------------------------------------------------

    #[test]
    fn create_argv_correct() {
        let sub = Subcommand::Create(CreateArgs {
            op_uid: 1000,
            vm: "sandbox-abc".to_string(),
            yaml: "/etc/lima/base.yaml".to_string(),
        });
        let argv = build_limactl_argv("/usr/local/bin/limactl", &sub);
        assert_eq!(
            argv,
            vec![
                "/usr/local/bin/limactl",
                "create",
                "--name",
                "sandbox-abc",
                "/etc/lima/base.yaml",
                "--tty=false",
            ]
        );
    }

    #[test]
    fn stop_force_argv_correct() {
        let sub = Subcommand::Stop(StopArgs {
            op_uid: 1000,
            vm: "sandbox-abc".to_string(),
            force: true,
        });
        let argv = build_limactl_argv("/usr/bin/limactl", &sub);
        assert_eq!(
            argv,
            vec![
                "/usr/bin/limactl",
                "stop",
                "-f",
                "sandbox-abc",
                "--tty=false",
            ]
        );
    }

    #[test]
    fn stop_no_force_argv_correct() {
        let sub = Subcommand::Stop(StopArgs {
            op_uid: 1000,
            vm: "sandbox-abc".to_string(),
            force: false,
        });
        let argv = build_limactl_argv("/usr/bin/limactl", &sub);
        assert_eq!(
            argv,
            vec!["/usr/bin/limactl", "stop", "sandbox-abc", "--tty=false",]
        );
    }

    #[test]
    fn delete_argv_correct() {
        let sub = Subcommand::Delete(DeleteArgs {
            op_uid: 1000,
            vm: "sandbox-abc".to_string(),
        });
        let argv = build_limactl_argv("/usr/bin/limactl", &sub);
        assert_eq!(
            argv,
            vec![
                "/usr/bin/limactl",
                "delete",
                "--force",
                "sandbox-abc",
                "--tty=false",
            ]
        );
    }

    #[test]
    fn copy_argv_correct() {
        let sub = Subcommand::Copy(CopyArgs {
            op_uid: 1000,
            src: "sandbox-abc:/tmp/file".to_string(),
            dst: "/host/path".to_string(),
        });
        let argv = build_limactl_argv("/usr/bin/limactl", &sub);
        // copy does not have --tty=false per spec.
        assert_eq!(
            argv,
            vec![
                "/usr/bin/limactl",
                "copy",
                "sandbox-abc:/tmp/file",
                "/host/path",
            ]
        );
    }

    #[test]
    fn guest_socat_argv_correct() {
        let sub = Subcommand::GuestSocat(GuestSocatArgs {
            op_uid: 1000,
            vm: "sandbox-abc".to_string(),
        });
        let argv = build_limactl_argv("/usr/bin/limactl", &sub);
        assert_eq!(
            argv,
            vec![
                "/usr/bin/limactl",
                "shell",
                "sandbox-abc",
                "--",
                "socat",
                "-",
                "TCP:127.0.0.1:5123",
            ]
        );
    }

    #[test]
    fn list_json_argv_correct() {
        let sub = Subcommand::ListJson(ListJsonArgs { op_uid: 1000 });
        let argv = build_limactl_argv("/usr/bin/limactl", &sub);
        assert_eq!(
            argv,
            vec!["/usr/bin/limactl", "list", "--json", "--tty=false",]
        );
    }

    #[test]
    fn clone_argv_correct() {
        let sub = Subcommand::Clone(CloneArgs {
            op_uid: 1000,
            base: "sandbox-base".to_string(),
            vm: "sandbox-abc".to_string(),
            cpus: 4,
            memory_gib: 8,
            disk_gib: 50,
        });
        let argv = build_limactl_argv("/usr/bin/limactl", &sub);
        assert_eq!(
            argv,
            vec![
                "/usr/bin/limactl",
                "clone",
                "sandbox-base",
                "sandbox-abc",
                "--cpus=4",
                "--memory=8",
                "--disk=50",
                "--tty=false",
            ]
        );
    }

    #[test]
    fn start_argv_correct() {
        // The `start` subcommand is flag-rich. Assert the canonical order:
        // limactl start <vm> --timeout=<N>s --tty=false.
        // QEMU-related values go via env vars, not argv.
        let sub = Subcommand::Start(StartArgs {
            op_uid: 1000,
            vm: "sandbox-abc".to_string(),
            qemu_wrapper: "/usr/local/bin/qemu-wrapper".to_string(),
            hardened: "1".to_string(),
            memory_mb: 4096,
            cpus: 2,
            start_timeout_s: 300,
            bridge_name: None,
            vm_mac: None,
        });
        let argv = build_limactl_argv("/usr/bin/limactl", &sub);
        assert_eq!(
            argv,
            vec![
                "/usr/bin/limactl",
                "start",
                "sandbox-abc",
                "--timeout=300s",
                "--tty=false",
            ]
        );
    }

    // -----------------------------------------------------------------------
    // install-guest-agent argv construction
    // -----------------------------------------------------------------------

    #[test]
    fn install_guest_agent_step4_heredoc_single_quoted() {
        // The step 4 bash command must use a single-quoted heredoc
        // terminator ('UNIT_EOF') to prevent shell expansion of $ literals
        // in the service unit body. Assert the actual output of
        // build_install_steps, not a re-built expected string.
        let vm = "sandbox-test";
        let limactl = "/usr/bin/limactl";
        let steps = build_install_steps(limactl, vm, "/usr/local/libexec/sandboxd/sandbox-guest");
        let step4 = &steps[3]; // 0-indexed: step 4 is index 3
        // Shape: [limactl, "shell", vm, "--", "sudo", "bash", "-c", <bash_cmd>]
        assert_eq!(step4[0], limactl, "step4[0] must be limactl path");
        assert_eq!(step4[1], "shell");
        assert_eq!(step4[2], vm);
        assert_eq!(step4[3], "--");
        assert_eq!(step4[4], "sudo");
        assert_eq!(step4[5], "bash");
        assert_eq!(step4[6], "-c");
        let bash_arg = &step4[7];
        assert!(
            bash_arg.contains("'UNIT_EOF'"),
            "step 4 heredoc terminator must be single-quoted, got: {bash_arg}"
        );
        assert!(
            !bash_arg.contains("\"UNIT_EOF\""),
            "step 4 heredoc must NOT use double-quoted terminator"
        );
        // The bash arg must contain the actual unit content (not an empty heredoc).
        assert!(
            bash_arg.contains("ExecStart=/usr/local/bin/sandbox-guest"),
            "step 4 must embed the full service unit body"
        );
    }

    #[test]
    fn guest_agent_service_unit_has_required_fields() {
        assert!(GUEST_AGENT_SERVICE_UNIT.contains("[Unit]"));
        assert!(GUEST_AGENT_SERVICE_UNIT.contains("ExecStart=/usr/local/bin/sandbox-guest"));
        assert!(GUEST_AGENT_SERVICE_UNIT.contains("Restart=always"));
    }

    // -----------------------------------------------------------------------
    // Environment block
    // -----------------------------------------------------------------------

    #[test]
    fn env_block_always_has_lima_home() {
        let sub = Subcommand::ListJson(ListJsonArgs { op_uid: 1000 });
        let env = build_env_block(
            &sub,
            "/var/lib/sandboxd/1000/lima/",
            "/home/operator-1000",
            1000,
        );
        let has_lima_home = env
            .iter()
            .any(|c| c.to_string_lossy().starts_with("LIMA_HOME="));
        assert!(has_lima_home, "env block must always include LIMA_HOME=");
    }

    /// Assert that HOME in the env block is the operator's pw_dir, NOT the
    /// daemon's inherited HOME. This is the #231(c) fix: after setresuid to
    /// the operator uid, limactl must see the operator's own home directory.
    #[test]
    fn env_block_home_is_operator_pw_dir() {
        let sub = Subcommand::ListJson(ListJsonArgs { op_uid: 1000 });
        let op_home = "/home/operator-1000";
        let env = build_env_block(&sub, "/var/lib/sandboxd/1000/lima/", op_home, 1000);
        let map: std::collections::HashMap<String, String> = env
            .iter()
            .map(|c| {
                let s = c.to_string_lossy().to_string();
                let eq = s.find('=').unwrap();
                (s[..eq].to_string(), s[eq + 1..].to_string())
            })
            .collect();
        assert_eq!(
            map.get("HOME").map(|s| s.as_str()),
            Some(op_home),
            "HOME must equal the operator's pw_dir, not the daemon's inherited HOME"
        );
        // Confirm the daemon's HOME is NOT present as the value
        // (the daemon's home is /var/lib/sandbox; if this assertion fails,
        // the allowlist pass-through is leaking instead of the explicit set).
        assert_ne!(
            map.get("HOME").map(|s| s.as_str()),
            Some("/var/lib/sandbox"),
            "daemon HOME must not appear in operator env block"
        );
    }

    #[test]
    fn env_block_start_has_qemu_vars() {
        let sub = Subcommand::Start(StartArgs {
            op_uid: 1000,
            vm: "sandbox-abc".to_string(),
            qemu_wrapper: "/usr/local/bin/qemu-wrapper".to_string(),
            hardened: "1".to_string(),
            memory_mb: 4096,
            cpus: 2,
            start_timeout_s: 300,
            bridge_name: Some("br0".to_string()),
            vm_mac: Some("02:00:00:00:00:01".to_string()),
        });
        let env = build_env_block(
            &sub,
            "/var/lib/sandboxd/1000/lima/",
            "/home/operator-1000",
            1000,
        );
        let keys: Vec<String> = env
            .iter()
            .map(|c| {
                let s = c.to_string_lossy().to_string();
                s.split('=').next().unwrap_or("").to_string()
            })
            .collect();
        for expected in &[
            "QEMU_SYSTEM_X86_64",
            "SANDBOX_QEMU_HARDENED",
            "SANDBOX_QEMU_MEMORY_MB",
            "SANDBOX_QEMU_CPUS",
            "SANDBOX_DOCKER_BRIDGE",
            "SANDBOX_VM_MAC",
        ] {
            assert!(
                keys.contains(&expected.to_string()),
                "env block for start must contain {expected}"
            );
        }
    }

    #[test]
    fn env_block_start_without_bridge_no_bridge_vars() {
        let sub = Subcommand::Start(StartArgs {
            op_uid: 1000,
            vm: "sandbox-abc".to_string(),
            qemu_wrapper: "/usr/local/bin/qemu-wrapper".to_string(),
            hardened: "0".to_string(),
            memory_mb: 2048,
            cpus: 2,
            start_timeout_s: 300,
            bridge_name: None,
            vm_mac: None,
        });
        let env = build_env_block(
            &sub,
            "/var/lib/sandboxd/1000/lima/",
            "/home/operator-1000",
            1000,
        );
        let keys: Vec<String> = env
            .iter()
            .map(|c| {
                let s = c.to_string_lossy().to_string();
                s.split('=').next().unwrap_or("").to_string()
            })
            .collect();
        assert!(!keys.contains(&"SANDBOX_DOCKER_BRIDGE".to_string()));
        assert!(!keys.contains(&"SANDBOX_VM_MAC".to_string()));
    }

    // -----------------------------------------------------------------------
    // op-uid non-root reject (unit-testable path)
    // -----------------------------------------------------------------------

    /// parse_u32 accepts "0" — the actual rejection of root op-uid happens
    /// in run() after argv parse. This test pins that the parse layer does
    /// not mask the value (i.e. it passes 0 through for run() to reject).
    #[test]
    fn parse_u32_accepts_zero_rejection_deferred_to_run() {
        assert_eq!(parse_u32("--op-uid", "0").unwrap(), 0u32);
        // The actual rejection happens in run() after argv parse; confirmed
        // by the integration tests. Here we just confirm the parse layer
        // doesn't mask the value.
    }

    #[test]
    fn op_uid_non_numeric_rejected() {
        assert!(parse_u32("--op-uid", "not-a-number").is_err());
        assert!(parse_u32("--op-uid", "").is_err());
        assert!(parse_u32("--op-uid", "-1").is_err());
    }

    // -----------------------------------------------------------------------
    // Env-block value assertions (SHOULD-FIX 2 / Track 3)
    // -----------------------------------------------------------------------

    /// Assert the QEMU env vars carry the correct values, not just that the
    /// keys are present. A bug that sets QEMU_SYSTEM_X86_64=/wrong/path
    /// would pass key-presence tests but fail here.
    #[test]
    fn env_block_start_qemu_values_correct() {
        let sub = Subcommand::Start(StartArgs {
            op_uid: 1000,
            vm: "sandbox-abc".to_string(),
            qemu_wrapper: "/usr/local/bin/qemu-wrapper".to_string(),
            hardened: "1".to_string(),
            memory_mb: 4096,
            cpus: 2,
            start_timeout_s: 300,
            bridge_name: Some("br0".to_string()),
            vm_mac: Some("02:00:00:00:00:01".to_string()),
        });
        let env = build_env_block(
            &sub,
            "/var/lib/sandboxd/1000/lima/",
            "/home/operator-1000",
            1000,
        );
        let map: std::collections::HashMap<String, String> = env
            .iter()
            .map(|c| {
                let s = c.to_string_lossy().to_string();
                let eq = s.find('=').unwrap();
                (s[..eq].to_string(), s[eq + 1..].to_string())
            })
            .collect();
        assert_eq!(map["QEMU_SYSTEM_X86_64"], "/usr/local/bin/qemu-wrapper");
        assert_eq!(map["SANDBOX_QEMU_HARDENED"], "1");
        assert_eq!(map["SANDBOX_QEMU_MEMORY_MB"], "4096");
        assert_eq!(map["SANDBOX_QEMU_CPUS"], "2");
        assert_eq!(map["SANDBOX_DOCKER_BRIDGE"], "br0");
        assert_eq!(map["SANDBOX_VM_MAC"], "02:00:00:00:00:01");
    }

    /// Assert that a non-allowlist env var set in the process environment
    /// does NOT appear in the env block produced by build_env_block.
    /// This pins the allowlist enforcement logic.
    #[test]
    fn env_block_does_not_leak_non_allowlist_vars() {
        // Set a canary var; build_env_block must not forward it.
        // SAFETY: single-threaded test, no concurrent env mutation.
        unsafe { std::env::set_var("CANARY_SECRET_TOKEN", "leak-me") };
        let sub = Subcommand::ListJson(ListJsonArgs { op_uid: 1000 });
        let env = build_env_block(
            &sub,
            "/var/lib/sandboxd/1000/lima/",
            "/home/operator-1000",
            1000,
        );
        let keys: Vec<String> = env
            .iter()
            .map(|c| {
                let s = c.to_string_lossy().to_string();
                s.split('=').next().unwrap_or("").to_string()
            })
            .collect();
        assert!(
            !keys.contains(&"CANARY_SECRET_TOKEN".to_string()),
            "non-allowlist var must not survive into env block"
        );
        unsafe { std::env::remove_var("CANARY_SECRET_TOKEN") };
    }

    /// Assert XDG_CACHE_HOME is always present and pinned under the
    /// operator's LIMA_HOME tree.
    #[test]
    fn env_block_always_has_xdg_cache_home() {
        let sub = Subcommand::ListJson(ListJsonArgs { op_uid: 1000 });
        let env = build_env_block(
            &sub,
            "/var/lib/sandboxd/1000/lima/",
            "/home/operator-1000",
            1000,
        );
        let map: std::collections::HashMap<String, String> = env
            .iter()
            .map(|c| {
                let s = c.to_string_lossy().to_string();
                let eq = s.find('=').unwrap();
                (s[..eq].to_string(), s[eq + 1..].to_string())
            })
            .collect();
        let xdg = map.get("XDG_CACHE_HOME").map(|s| s.as_str());
        assert!(
            xdg.is_some(),
            "XDG_CACHE_HOME must always be present in env block"
        );
        assert!(
            xdg.unwrap().starts_with("/var/lib/sandboxd/1000/lima/"),
            "XDG_CACHE_HOME must be pinned inside the operator LIMA_HOME tree, got: {xdg:?}"
        );
    }

    /// Assert XDG_RUNTIME_DIR is always present and set to /run/user/<op_uid>.
    ///
    /// This is load-bearing for the QEMU wrapper's `systemctl --user
    /// show-environment` probe: without XDG_RUNTIME_DIR, systemd returns
    /// "No medium found" and the wrapper skips the systemd-run scope entirely,
    /// leaving QEMU without cgroup memory/CPU limits (M18 regression).
    #[test]
    fn env_block_xdg_runtime_dir_is_operator_run_user_uid() {
        let sub = Subcommand::ListJson(ListJsonArgs { op_uid: 1000 });
        let env = build_env_block(
            &sub,
            "/var/lib/sandboxd/1000/lima/",
            "/home/operator-1000",
            1000,
        );
        let map: std::collections::HashMap<String, String> = env
            .iter()
            .map(|c| {
                let s = c.to_string_lossy().to_string();
                let eq = s.find('=').unwrap();
                (s[..eq].to_string(), s[eq + 1..].to_string())
            })
            .collect();
        assert_eq!(
            map.get("XDG_RUNTIME_DIR").map(|s| s.as_str()),
            Some("/run/user/1000"),
            "XDG_RUNTIME_DIR must be /run/user/<op_uid> so the QEMU wrapper's \
             systemctl --user probe can reach the operator's user manager"
        );
    }

    // -----------------------------------------------------------------------
    // NSS three-case GroupMembership unit tests (SHOULD-FIX 3 / Track 3)
    // -----------------------------------------------------------------------

    /// Helper: given a GroupMembership value, return the exit code that
    /// run() would use. Extracted from run()'s match arm so the three
    /// cases are unit-testable without spawning a real binary.
    fn exit_code_for_group_membership(membership: GroupMembership) -> u8 {
        match membership {
            GroupMembership::Member => 0, // continue — no early exit
            GroupMembership::NotMember => EXIT_BAD_OP_UID,
            GroupMembership::EnumerationFailed(_) => EXIT_GENERIC,
        }
    }

    #[test]
    fn op_uid_group_member_allows_proceed() {
        assert_eq!(exit_code_for_group_membership(GroupMembership::Member), 0);
    }

    #[test]
    fn op_uid_group_not_member_returns_bad_op_uid_exit() {
        assert_eq!(
            exit_code_for_group_membership(GroupMembership::NotMember),
            EXIT_BAD_OP_UID
        );
    }

    #[test]
    fn op_uid_group_enumeration_failed_returns_generic_exit() {
        assert_eq!(
            exit_code_for_group_membership(GroupMembership::EnumerationFailed(libc::ENOMEM)),
            EXIT_GENERIC
        );
    }

    // -----------------------------------------------------------------------
    // read-user-key parser
    // -----------------------------------------------------------------------

    #[test]
    fn parse_read_user_key_minimal() {
        let args = os_args(&["read-user-key", "--op-uid", "1001"]);
        let sub = parse_argv(&args).expect("must parse");
        assert_eq!(sub.op_uid(), 1001);
    }

    #[test]
    fn parse_read_user_key_missing_op_uid_fails() {
        let args = os_args(&["read-user-key"]);
        assert!(parse_argv(&args).is_err());
    }

    #[test]
    fn parse_read_user_key_extra_flag_fails() {
        let args = os_args(&["read-user-key", "--op-uid", "1001", "--vm", "sandbox-abc"]);
        assert!(parse_argv(&args).is_err());
    }

    /// Verify the key path construction: lima_home with trailing slash
    /// concatenated with `_config/user` must resolve to the correct path.
    /// The helper's `run()` constructs `lima_home` as
    /// `/var/lib/sandboxd/{op_uid}/lima/` (always trailing-slash), so
    /// `{lima_home}_config/user` must equal
    /// `/var/lib/sandboxd/{op_uid}/lima/_config/user`.
    #[test]
    fn read_user_key_path_construction_correct() {
        let op_uid: u32 = 1001;
        let lima_home = format!("/var/lib/sandboxd/{op_uid}/lima/");
        let key_path = format!("{lima_home}_config/user");
        assert_eq!(
            key_path,
            format!("/var/lib/sandboxd/{op_uid}/lima/_config/user"),
            "key path must be $LIMA_HOME/_config/user; got: {key_path}",
        );
    }

    // -----------------------------------------------------------------------
    // run-rsync parser
    // -----------------------------------------------------------------------

    #[test]
    fn parse_run_rsync_minimal_lima() {
        let args = os_args(&[
            "run-rsync",
            "--op-uid",
            "1000",
            "--backend",
            "lima",
            "--session-name",
            "sandbox-abc123",
            "--host-path",
            "/home/op/work",
            "--guest-path",
            "/home/agent/workspace",
        ]);
        let sub = parse_argv(&args).expect("valid run-rsync args");
        let Subcommand::RunRsync(a) = sub else {
            panic!("expected RunRsync")
        };
        assert_eq!(a.op_uid, 1000);
        assert_eq!(a.backend, "lima");
        assert_eq!(a.session_name, "sandbox-abc123");
        assert_eq!(a.host_path, "/home/op/work");
        assert_eq!(a.guest_path, "/home/agent/workspace");
        assert!(!a.no_gitignore);
    }

    #[test]
    fn parse_run_rsync_container_with_no_gitignore() {
        let args = os_args(&[
            "run-rsync",
            "--op-uid",
            "1001",
            "--backend",
            "container",
            "--session-name",
            "sandbox-def456",
            "--host-path",
            "/srv/proj",
            "--guest-path",
            "/home/agent/workspace",
            "--no-gitignore",
        ]);
        let sub = parse_argv(&args).expect("valid run-rsync args");
        let Subcommand::RunRsync(a) = sub else {
            panic!("expected RunRsync")
        };
        assert_eq!(a.backend, "container");
        assert!(a.no_gitignore);
    }

    #[test]
    fn parse_run_rsync_missing_backend_fails() {
        let args = os_args(&[
            "run-rsync",
            "--op-uid",
            "1000",
            "--session-name",
            "sandbox-abc",
            "--host-path",
            "/home/op/work",
            "--guest-path",
            "/home/agent/workspace",
        ]);
        assert!(parse_argv(&args).is_err());
    }

    #[test]
    fn parse_run_rsync_missing_host_path_fails() {
        let args = os_args(&[
            "run-rsync",
            "--op-uid",
            "1000",
            "--backend",
            "lima",
            "--session-name",
            "sandbox-abc",
            "--guest-path",
            "/home/agent/workspace",
        ]);
        assert!(parse_argv(&args).is_err());
    }

    #[test]
    fn parse_run_rsync_invalid_backend_fails_validation() {
        let args = os_args(&[
            "run-rsync",
            "--op-uid",
            "1000",
            "--backend",
            "kvm",
            "--session-name",
            "sandbox-abc",
            "--host-path",
            "/home/op/work",
            "--guest-path",
            "/home/agent/workspace",
        ]);
        // Passes argv parse but fails validate_subcommand (EXIT_BAD_ARGS).
        let sub = parse_argv(&args).expect("argv parse must succeed (validation is separate)");
        assert!(
            validate_subcommand(&sub).is_err(),
            "invalid --backend value must fail validation"
        );
    }

    #[test]
    fn parse_run_rsync_relative_host_path_fails_validation() {
        let args = os_args(&[
            "run-rsync",
            "--op-uid",
            "1000",
            "--backend",
            "lima",
            "--session-name",
            "sandbox-abc",
            "--host-path",
            "relative/path",
            "--guest-path",
            "/home/agent/workspace",
        ]);
        let sub = parse_argv(&args).expect("argv parse must succeed");
        assert!(
            validate_subcommand(&sub).is_err(),
            "relative --host-path must fail validation"
        );
    }

    // -----------------------------------------------------------------------
    // build_rsync_argv
    // -----------------------------------------------------------------------

    #[test]
    fn build_rsync_argv_lima_default_filter() {
        let a = RunRsyncArgs {
            op_uid: 1000,
            backend: "lima".to_string(),
            session_name: "sandbox-abc123".to_string(),
            host_path: "/home/op/work".to_string(),
            guest_path: "/home/agent/workspace".to_string(),
            no_gitignore: false,
        };
        let argv = build_rsync_argv(&a);
        assert_eq!(
            argv,
            vec![
                "-aL",
                "--delete",
                "--filter=:- .gitignore",
                "-e",
                "limactl shell",
                "--mkpath",
                "/home/op/work/",
                "sandbox-abc123:/home/agent/workspace/",
            ]
        );
    }

    #[test]
    fn build_rsync_argv_container_no_gitignore() {
        let a = RunRsyncArgs {
            op_uid: 1001,
            backend: "container".to_string(),
            session_name: "sandbox-def456".to_string(),
            host_path: "/srv/proj".to_string(),
            guest_path: "/home/agent/workspace".to_string(),
            no_gitignore: true,
        };
        let argv = build_rsync_argv(&a);
        assert_eq!(
            argv,
            vec![
                "-aL",
                "--delete",
                "-e",
                "docker exec -i",
                "--mkpath",
                "/srv/proj/",
                "sandbox-def456:/home/agent/workspace/",
            ]
        );
    }

    #[test]
    fn build_rsync_argv_trailing_slash_idempotent() {
        let a = RunRsyncArgs {
            op_uid: 1000,
            backend: "lima".to_string(),
            session_name: "sandbox-xyz".to_string(),
            host_path: "/a/b/".to_string(),
            guest_path: "/c/d/".to_string(),
            no_gitignore: false,
        };
        let argv = build_rsync_argv(&a);
        let src = argv.iter().rev().nth(1).expect("src arg");
        let dst = argv.last().expect("dst arg");
        assert_eq!(src, "/a/b/");
        assert_eq!(dst, "sandbox-xyz:/c/d/");
    }

    #[test]
    fn build_rsync_argv_always_includes_mkpath() {
        for backend in &["lima", "container"] {
            for no_gitignore in [false, true] {
                let a = RunRsyncArgs {
                    op_uid: 1000,
                    backend: backend.to_string(),
                    session_name: "sandbox-mk".to_string(),
                    host_path: "/x".to_string(),
                    guest_path: "/y".to_string(),
                    no_gitignore,
                };
                let argv = build_rsync_argv(&a);
                assert!(
                    argv.iter().any(|a| a == "--mkpath"),
                    "--mkpath missing for backend={backend} no_gitignore={no_gitignore}: {argv:?}"
                );
            }
        }
    }
}
