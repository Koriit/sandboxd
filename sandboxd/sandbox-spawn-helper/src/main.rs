//! `sandbox-spawn-helper` — privileged setcap binary that drops to a
//! specified operator uid and `execve`'s a runtime tool on behalf of an
//! authorised caller.
//!
//! # Invocation
//!
//! ```text
//! sandbox-spawn-helper <operator_uid> <runtime_argv0> [runtime_argv...]
//! ```
//!
//! Two or more positional arguments. No stdin. No env-var configuration
//! in production (a `SANDBOX_SPAWN_HELPER_TEST_SANDBOX_GROUP` override
//! exists for the `test-env-override` Cargo feature only — see the
//! crate-level note in `Cargo.toml`).
//!
//! # Authorisation flow
//!
//! Each invocation runs ordered steps; any step that denies prints a
//! single `sandbox-spawn-helper: <reason>` line to stderr and exits with
//! the matching exit code (1..=5). No privilege change happens on the
//! deny path — the helper exits before `setresuid` is reached.
//!
//! 1. Argv parse — `<operator_uid> <runtime_argv0> [runtime_argv...]`.
//! 2. Caller authorisation — the calling process must be a member of
//!    the `sandbox` group. Membership is read from `getgroups(2)`
//!    (which reflects the process's *supplementary* groups, populated
//!    by the kernel from `/etc/group` at session start) and the
//!    primary `getgid()`. The `sandbox` group's gid is resolved via
//!    `getgrnam_r(3)`. Both the literal group name and the primary
//!    `sandbox` user's account live in `/etc/group` / `/etc/passwd`,
//!    consistent with the route-helper precedent.
//! 3. Operator-uid resolution — `getpwuid(operator_uid)` via
//!    `User::from_uid` must return `Ok(Some(_))`. STRICT — an
//!    unresolvable uid denies.
//! 4. `setresuid(operator_uid, operator_uid, operator_uid)` — drop all
//!    three uids (real, effective, saved) to the operator. The helper
//!    has `cap_setuid+ep` so this succeeds; on failure the helper
//!    exits without invoking the runtime tool.
//! 5. Capability self-clear — `capset` with empty `permitted`,
//!    `effective`, and `inheritable` sets, then drop the ambient set
//!    via `caps::clear(None, CapSet::Ambient)`. The runtime tool
//!    inherits zero capabilities even though the helper carried
//!    `cap_setuid+ep` into the exec chain. Defence-in-depth: the
//!    `setresuid(operator_uid)` in step 4 already clears the
//!    permitted/effective sets for any non-root uid per the kernel's
//!    SECBIT rules, but we issue the explicit `capset` so the
//!    contract is grep-able and unambiguous.
//! 6. `execvp` of the runtime tool with the explicit-allowlist
//!    environment subset (`PATH`, `LANG`, `LC_ALL`, `HOME`, `TERM`).
//!    No `env::vars()` propagation — the helper does not leak its own
//!    host environment into the runtime tool.
//!
//! # Privilege model
//!
//! The helper requires `CAP_SETUID` to call `setresuid(2)` to an
//! arbitrary uid. Operators install it with:
//!
//! ```text
//! sudo setcap 'cap_setuid+ep' /usr/local/libexec/sandboxd/sandbox-spawn-helper
//! ```
//!
//! The `+ep` flags put `CAP_SETUID` in the file's Permitted and
//! Effective sets (no Inheritable — the runtime tool does NOT need
//! this capability). On exec by an unprivileged caller, the thread's
//! Permitted gets the file Permitted (gated by bset); Effective tracks
//! Permitted because the file Effective bit is set.
//!
//! The production install path is `/usr/local/libexec/sandboxd/` per
//! FHS § 4.7 (libexec is for non-user-facing helper binaries). This
//! mirrors `sandbox-route-helper`'s install location and operator
//! runbook.
//!
//! The daemon (`sandboxd`) stays uncapped at uid 999 with zero file
//! capabilities. `sandboxd.service` does NOT carry an
//! `AmbientCapabilities=CAP_SETUID` directive; the daemon exec's the
//! helper, and the helper's file capabilities supply the privilege at
//! exec time, narrowly scoped to the lifetime of this single ~100 LoC
//! binary.
//!
//! # Stderr / exit-code contract
//!
//! Each deny path exits with a distinct numeric code so callers
//! (integration tests, the daemon's session-create error path) can
//! distinguish them programmatically. The reason text on stderr names
//! the failure for the operator's debugging.

use std::env;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

use nix::unistd::{Uid, User};

/// Exit codes. `0` is reserved for the success path that never returns
/// (we `execvp`); on the deny path each step has its own code so the
/// caller can map the rejection without parsing stderr.
const EXIT_GENERIC: u8 = 1;
const EXIT_CALLER_NOT_AUTHORIZED: u8 = 2;
const EXIT_OPERATOR_UID_UNRESOLVED: u8 = 3;
const EXIT_SETRESUID_FAILED: u8 = 4;
const EXIT_CAPSET_FAILED: u8 = 5;

/// The literal group name whose membership authorises a caller. The
/// `test-env-override` Cargo feature lets integration tests swap this
/// for a synthetic test group; the default production build resolves
/// the literal.
const SANDBOX_GROUP_NAME: &str = "sandbox";

/// Env var honoured ONLY by `test-env-override` builds.
#[cfg(feature = "test-env-override")]
const SANDBOX_SPAWN_HELPER_TEST_GROUP_ENV: &str = "SANDBOX_SPAWN_HELPER_TEST_SANDBOX_GROUP";

/// Resolve the group name used for the caller-authorisation check.
///
/// Production builds always return the literal `"sandbox"`. Test
/// builds (with the `test-env-override` Cargo feature enabled) honour
/// `SANDBOX_SPAWN_HELPER_TEST_SANDBOX_GROUP` so integration tests can
/// drive the check against a synthetic group they own.
fn resolve_sandbox_group_name() -> String {
    #[cfg(feature = "test-env-override")]
    {
        if let Ok(v) = env::var(SANDBOX_SPAWN_HELPER_TEST_GROUP_ENV)
            && !v.is_empty()
        {
            return v;
        }
    }
    SANDBOX_GROUP_NAME.to_string()
}

/// Environment-variable allow-list propagated into the runtime tool's
/// environment. Anything not in this list is dropped — the helper does
/// NOT pass through its own environment to the runtime invocation.
const ENV_ALLOWLIST: &[&str] = &["PATH", "LANG", "LC_ALL", "HOME", "TERM"];

fn main() -> ExitCode {
    run()
}

/// Top-level orchestration. Each branch decides allow / deny via the
/// step rules in the module docstring; the success path ends in
/// `execvp` and never returns.
fn run() -> ExitCode {
    // Step 1 — argv parse.
    let args: Vec<OsString> = env::args_os().collect();
    let parsed = match parse_argv(&args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("sandbox-spawn-helper: {msg}");
            return ExitCode::from(EXIT_GENERIC);
        }
    };
    let ParsedArgs {
        operator_uid,
        runtime_argv,
    } = parsed;

    // Step 2 — caller must be a member of the `sandbox` group.
    let group_name = resolve_sandbox_group_name();
    let target_gid = match resolve_group_gid(&group_name) {
        Ok(Some(gid)) => gid,
        Ok(None) => {
            eprintln!("sandbox-spawn-helper: group {group_name} not present on host",);
            return ExitCode::from(EXIT_CALLER_NOT_AUTHORIZED);
        }
        Err(err) => {
            eprintln!("sandbox-spawn-helper: group lookup failed for {group_name}: {err}",);
            return ExitCode::from(EXIT_CALLER_NOT_AUTHORIZED);
        }
    };
    if !caller_is_in_group(target_gid) {
        let caller_uid = Uid::current().as_raw();
        eprintln!(
            "sandbox-spawn-helper: caller uid {caller_uid} is not a member of group {group_name}",
        );
        return ExitCode::from(EXIT_CALLER_NOT_AUTHORIZED);
    }

    // Step 3 — operator uid must resolve to a local user. STRICT.
    match User::from_uid(Uid::from_raw(operator_uid)) {
        Ok(Some(_)) => {}
        Ok(None) => {
            eprintln!(
                "sandbox-spawn-helper: operator uid {operator_uid} does not resolve to a local user",
            );
            return ExitCode::from(EXIT_OPERATOR_UID_UNRESOLVED);
        }
        Err(err) => {
            eprintln!("sandbox-spawn-helper: operator uid {operator_uid} resolution error: {err}",);
            return ExitCode::from(EXIT_OPERATOR_UID_UNRESOLVED);
        }
    }

    // Step 4 — drop real+effective+saved uid to the operator.
    if let Err(errno) = setresuid_strict(operator_uid) {
        eprintln!("sandbox-spawn-helper: setresuid({operator_uid}) failed: errno {errno}",);
        return ExitCode::from(EXIT_SETRESUID_FAILED);
    }

    // Step 5 — capability self-clear. After `setresuid(non-root)` the
    // kernel SECBIT rules already drop permitted/effective; we issue
    // the explicit `capset` to make the contract grep-able and
    // unambiguous, then drop ambient too.
    if let Err(err) = clear_all_capabilities() {
        eprintln!("sandbox-spawn-helper: capset clear failed: {err}",);
        return ExitCode::from(EXIT_CAPSET_FAILED);
    }

    // Step 6 — execvp the runtime tool with the allow-listed env.
    let argv0 = &runtime_argv[0];
    let cstring_argv: Vec<CString> = match runtime_argv
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(_) => {
            eprintln!("sandbox-spawn-helper: runtime argv contains an interior NUL byte",);
            return ExitCode::from(EXIT_GENERIC);
        }
    };
    // Build a sanitised environment from the allow-list. Anything
    // outside the list is dropped before exec — the helper does not
    // propagate its own environment.
    let cstring_envp: Vec<CString> = build_sanitised_env();

    // SAFETY: `execvpe` does not return on success; on failure errno is
    // set and we surface the failure via stderr+exit. The argv0 and
    // argv slices live as `CString`s for the duration of the call.
    let argv0_c = match CString::new(argv0.as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("sandbox-spawn-helper: runtime argv0 contains an interior NUL byte",);
            return ExitCode::from(EXIT_GENERIC);
        }
    };
    let argv_ptrs: Vec<*const libc::c_char> = cstring_argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = cstring_envp
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    // SAFETY: argv0_c and argv_ptrs/envp_ptrs are valid pointers to
    // null-terminated arrays of valid C strings for the lifetime of
    // this call. `execvpe` does not return on success.
    unsafe {
        libc::execvpe(argv0_c.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
    }
    // SAFETY: errno is thread-local and set by the failed exec.
    let errno = unsafe { *libc::__errno_location() };
    let argv0_str = argv0.to_string_lossy();
    eprintln!("sandbox-spawn-helper: execvpe({argv0_str}) failed: errno {errno}",);
    ExitCode::from(EXIT_GENERIC)
}

// ---------------------------------------------------------------------------
// Argv parsing
// ---------------------------------------------------------------------------

/// Parsed argv. `runtime_argv[0]` is the program name passed to
/// `execvp`; subsequent entries are the program's arguments.
struct ParsedArgs {
    operator_uid: u32,
    runtime_argv: Vec<OsString>,
}

/// Parse argv: `<operator_uid> <runtime_argv0> [runtime_argv...]`.
///
/// Hand-rolled — the helper deliberately does not pull in a CLI
/// parsing crate so the TCB stays small.
fn parse_argv(args: &[OsString]) -> Result<ParsedArgs, String> {
    const USAGE: &str =
        "usage: sandbox-spawn-helper <operator_uid> <runtime_argv0> [runtime_argv...]";

    if args.len() < 3 {
        return Err(USAGE.to_string());
    }
    let uid_arg = args[1].to_string_lossy();
    let operator_uid: u32 = uid_arg
        .parse()
        .map_err(|_| format!("invalid operator_uid: {uid_arg}"))?;
    let runtime_argv: Vec<OsString> = args[2..].to_vec();
    Ok(ParsedArgs {
        operator_uid,
        runtime_argv,
    })
}

// ---------------------------------------------------------------------------
// Group resolution & membership
// ---------------------------------------------------------------------------

/// Resolve a group name to its numeric gid via `getgrnam_r(3)`.
///
/// `Ok(Some(gid))` on success, `Ok(None)` when the group is not on the
/// host. Errors other than ENOENT propagate as `Err`.
fn resolve_group_gid(name: &str) -> Result<Option<u32>, String> {
    let name_c = CString::new(name).map_err(|_| "group name contains NUL".to_string())?;
    // Use `getgrnam_r` via libc directly for a minimal TCB. nix offers
    // a `Group::from_name` wrapper under the `user` feature but its
    // error surface is different from `User::from_uid` so handling
    // the two together gets noisy.
    //
    // SAFETY: the buffer is sized at the libc-recommended initial
    // size; we re-allocate on ERANGE up to a sane ceiling.
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
            // `libc::gid_t` is `u32` on every platform we target;
            // no cast needed.
            return Ok(Some(grp.gr_gid));
        }
        if rc == libc::ERANGE && buf_len < 65536 {
            buf_len *= 2;
            continue;
        }
        return Err(format!("getgrnam_r failed: errno {rc}"));
    }
}

/// Return `true` iff the calling process's primary or supplementary
/// groups include `target_gid`.
fn caller_is_in_group(target_gid: u32) -> bool {
    // `libc::getgid` returns `libc::gid_t` which is `u32` on Linux —
    // no cast needed.
    if unsafe { libc::getgid() } == target_gid {
        return true;
    }
    // First call: how many supplementary groups?
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        return false;
    }
    if count == 0 {
        return false;
    }
    let mut groups: Vec<libc::gid_t> = vec![0; count as usize];
    let got = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if got < 0 {
        return false;
    }
    groups.iter().take(got as usize).any(|&g| g == target_gid)
}

// ---------------------------------------------------------------------------
// setresuid + capability self-clear
// ---------------------------------------------------------------------------

/// Strict `setresuid(operator_uid, operator_uid, operator_uid)`.
/// Returns the errno on failure so the caller can include it in
/// stderr.
fn setresuid_strict(operator_uid: u32) -> Result<(), i32> {
    // SAFETY: setresuid is a kernel syscall with no Rust-side
    // invariants. The kernel handles the privilege check (the helper's
    // `cap_setuid` Permitted+Effective satisfies it for any target uid).
    let rc = unsafe {
        libc::setresuid(
            operator_uid as libc::uid_t,
            operator_uid as libc::uid_t,
            operator_uid as libc::uid_t,
        )
    };
    if rc < 0 {
        // SAFETY: errno is thread-local and set by the failed syscall.
        let errno = unsafe { *libc::__errno_location() };
        return Err(errno);
    }
    Ok(())
}

/// Clear the helper's own capability sets (permitted, effective,
/// inheritable) and the ambient set, so the `execve`'d runtime tool
/// inherits zero capabilities.
///
/// After `setresuid(non-root)` the kernel's SECBIT rules already drop
/// permitted+effective on the transition (because the helper does not
/// set `PR_SET_KEEPCAPS`); the explicit `capset` here is defence in
/// depth and makes the contract grep-able.
fn clear_all_capabilities() -> Result<(), String> {
    caps::clear(None, caps::CapSet::Permitted).map_err(|e| format!("clear permitted: {e}"))?;
    caps::clear(None, caps::CapSet::Effective).map_err(|e| format!("clear effective: {e}"))?;
    caps::clear(None, caps::CapSet::Inheritable).map_err(|e| format!("clear inheritable: {e}"))?;
    caps::clear(None, caps::CapSet::Ambient).map_err(|e| format!("clear ambient: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Sanitised environment construction
// ---------------------------------------------------------------------------

/// Build a sanitised env block from the allow-list. Anything outside
/// `ENV_ALLOWLIST` is dropped; the runtime tool receives ONLY the
/// allow-listed variables, plus nothing else.
fn build_sanitised_env() -> Vec<CString> {
    ENV_ALLOWLIST
        .iter()
        .filter_map(|key| {
            let value = env::var_os(key)?;
            let mut buf = OsString::from(*key);
            buf.push("=");
            buf.push(&value);
            CString::new(buf.as_bytes()).ok()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Hermetic unit tests. The privileged path (`setresuid` +
    //! `execvpe`) cannot be exercised here without a setcap'd binary
    //! and a target uid we own; the integration test target covers
    //! that surface against the installed cap'd binary.

    use super::*;
    use std::ffi::OsString;

    /// Build an `args` vector shaped like `env::args_os()` so
    /// `parse_argv` can be driven directly.
    fn argv(parts: &[&str]) -> Vec<OsString> {
        std::iter::once("sandbox-spawn-helper")
            .chain(parts.iter().copied())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn parse_argv_rejects_too_few_args() {
        let cases: &[&[&str]] = &[&[], &["1000"]];
        for parts in cases {
            let args = argv(parts);
            assert!(parse_argv(&args).is_err(), "expected error for {parts:?}");
        }
    }

    #[test]
    fn parse_argv_rejects_non_numeric_uid() {
        let args = argv(&["not-a-uid", "/bin/sh"]);
        assert!(parse_argv(&args).is_err());
    }

    #[test]
    fn parse_argv_accepts_uid_plus_argv0() {
        let args = argv(&["1000", "/bin/sh"]);
        let parsed = parse_argv(&args).expect("two-arg form should parse");
        assert_eq!(parsed.operator_uid, 1000);
        assert_eq!(parsed.runtime_argv, vec![OsString::from("/bin/sh")]);
    }

    #[test]
    fn parse_argv_accepts_uid_plus_argv0_plus_args() {
        let args = argv(&["1000", "/bin/sh", "-c", "echo hi"]);
        let parsed = parse_argv(&args).expect("multi-arg form should parse");
        assert_eq!(parsed.operator_uid, 1000);
        assert_eq!(
            parsed.runtime_argv,
            vec![
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                OsString::from("echo hi"),
            ]
        );
    }

    /// The literal group name `"sandbox"` is what the production
    /// build resolves — test-env-override builds may shadow it but the
    /// default must remain stable so the privilege story is grep-able.
    #[test]
    fn sandbox_group_name_is_literal_sandbox() {
        assert_eq!(SANDBOX_GROUP_NAME, "sandbox");
    }

    /// `resolve_sandbox_group_name` in a default (non-test-env)
    /// build returns the literal regardless of any env var.
    #[cfg(not(feature = "test-env-override"))]
    #[test]
    fn resolve_sandbox_group_name_ignores_env_in_default_build() {
        // SAFETY: env mutation is sound here because the test does
        // not spawn threads and the var is restored after.
        let prev = env::var("SANDBOX_SPAWN_HELPER_TEST_SANDBOX_GROUP").ok();
        unsafe {
            env::set_var("SANDBOX_SPAWN_HELPER_TEST_SANDBOX_GROUP", "attacker");
        }
        assert_eq!(resolve_sandbox_group_name(), "sandbox");
        unsafe {
            match prev {
                Some(v) => env::set_var("SANDBOX_SPAWN_HELPER_TEST_SANDBOX_GROUP", v),
                None => env::remove_var("SANDBOX_SPAWN_HELPER_TEST_SANDBOX_GROUP"),
            }
        }
    }

    /// `resolve_sandbox_group_name` in a `test-env-override` build
    /// honours the env-var seam.
    #[cfg(feature = "test-env-override")]
    #[test]
    fn resolve_sandbox_group_name_honors_env_with_feature() {
        let prev = env::var("SANDBOX_SPAWN_HELPER_TEST_SANDBOX_GROUP").ok();
        unsafe {
            env::set_var("SANDBOX_SPAWN_HELPER_TEST_SANDBOX_GROUP", "sandbox-test");
        }
        assert_eq!(resolve_sandbox_group_name(), "sandbox-test");
        unsafe {
            match prev {
                Some(v) => env::set_var("SANDBOX_SPAWN_HELPER_TEST_SANDBOX_GROUP", v),
                None => env::remove_var("SANDBOX_SPAWN_HELPER_TEST_SANDBOX_GROUP"),
            }
        }
    }

    /// `build_sanitised_env` keeps only allow-listed variables; any
    /// non-listed env var the helper inherits is dropped.
    #[test]
    fn build_sanitised_env_drops_non_allowlisted_vars() {
        // SAFETY: env mutation is sound here because the test does not
        // spawn threads and the vars are restored after.
        let prev_secret = env::var("SANDBOX_SPAWN_HELPER_SECRET").ok();
        let prev_path = env::var("PATH").ok();
        unsafe {
            env::set_var("SANDBOX_SPAWN_HELPER_SECRET", "hunter2");
            env::set_var("PATH", "/usr/bin:/bin");
        }
        let env = build_sanitised_env();
        let env_strs: Vec<String> = env
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        assert!(
            env_strs.iter().any(|e| e == "PATH=/usr/bin:/bin"),
            "PATH should appear in the sanitised env, got {env_strs:?}",
        );
        assert!(
            !env_strs
                .iter()
                .any(|e| e.starts_with("SANDBOX_SPAWN_HELPER_SECRET=")),
            "secret env var leaked past allow-list: {env_strs:?}",
        );
        unsafe {
            match prev_secret {
                Some(v) => env::set_var("SANDBOX_SPAWN_HELPER_SECRET", v),
                None => env::remove_var("SANDBOX_SPAWN_HELPER_SECRET"),
            }
            match prev_path {
                Some(v) => env::set_var("PATH", v),
                None => env::remove_var("PATH"),
            }
        }
    }

    /// `caller_is_in_group` MUST return `false` when the target gid
    /// matches neither the caller's primary gid nor any supplementary
    /// group. Drive with an obviously-impossible gid to keep the test
    /// hermetic on every host.
    #[test]
    fn caller_is_in_group_rejects_unrelated_gid() {
        // 0xFFFFFE is reserved (overflow-id space); no real host will
        // grant the test process membership in it.
        assert!(!caller_is_in_group(0x00FF_FFFE));
    }
}
