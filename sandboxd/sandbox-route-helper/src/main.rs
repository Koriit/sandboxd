//! `sandbox-route-helper` — privileged setcap binary that installs a
//! default route inside a container's netns on behalf of an authorized
//! caller.
//!
//! # Invocation
//!
//! ```text
//! sandbox-route-helper [--for-user <name>] <container_pid> <gateway_ip>
//! ```
//!
//! Two positional arguments preceded by an optional `--for-user <name>`
//! flag. No stdin, no env-var configuration in production. The
//! `SANDBOX_USERS_CONF` env var seam exists in `sandbox-core::users_conf`
//! for daemon-side and helper-side integration tests, but the helper
//! consults it ONLY when this crate is built with the `test-env-override`
//! Cargo feature. Default production builds (used by the
//! `install-route-helper-prod-cap` make target) ignore the env var
//! entirely. See [`sandbox_core::users_conf::route_helper_users_conf_path`]
//! for the gating logic.
//!
//! # Authorization flow
//!
//! Each invocation runs ordered steps; any step that denies prints a
//! single `sandbox-route-helper: <reason>` line to stderr, writes an
//! append-only JSON-Lines audit record (per spec § 3.5), and exits with
//! code `1`. No netns mutation occurs on the deny path — the helper
//! exits before reaching the route install.
//!
//! 1. Caller identity — read `getuid()` and resolve to a username via
//!    `getpwuid_r`. STRICT per spec § 3.4: unresolvable uid denies.
//! 2. Argv parse — `--for-user <name>` (optional, defaults to caller)
//!    plus the two positional args. Strict resolution of `--for-user`
//!    via `getpwnam_r` per spec § 3.4.
//! 3. Load `users.conf`; locate the subnet whose CIDR contains the
//!    gateway IP argument.
//! 4. **Pair-membership check** (spec §§ 3.1–3.2) — both the caller's
//!    uid AND the `--for-user` uid must appear in the chosen pool's
//!    `allow_users` (each resolved numerically via `getpwnam_r`).
//! 5. `pidfd_open(container_pid)` then `setns(pidfd, CLONE_NEWNET)` —
//!    closes the PID-recycle TOCTOU window that `setns(open("/proc/<pid>
//!    /ns/net"))` would leave open.
//! 6. Enumerate every IPv4 address on every non-`lo` interface inside
//!    the netns; require all of them to live inside the caller's
//!    subnet. A single outside-subnet address denies — that's the
//!    cross-user MITM closure.
//! 7. `ip route replace default via <gateway_ip>` inside the netns.
//! 8. Append an `allowed`-decision audit record and exit 0 with a
//!    one-line stdout confirmation.
//!
//! # Privilege model
//!
//! The helper requires `CAP_SYS_ADMIN` to call `setns(2)` on a foreign
//! netns and `CAP_NET_ADMIN` to issue `RTM_NEWROUTE` (which the spawned
//! `ip(8)` needs to inherit via the ambient set — see step 7 below).
//! Operators install it with:
//!
//! ```text
//! sudo setcap 'cap_net_admin,cap_sys_admin=eip' /usr/local/libexec/sandboxd/sandbox-route-helper
//! ```
//!
//! The `=eip` flags put both caps in the file's Permitted, Inheritable,
//! and Effective sets. On exec by an unprivileged caller, the thread's
//! Permitted gets the file Permitted (gated by bset); Effective tracks
//! Permitted because the file Effective bit is set; but Inheritable is
//! taken from the *parent's* Inheritable, which is empty. The helper
//! itself must therefore promote `CAP_NET_ADMIN` from its Permitted into
//! its Inheritable set before raising ambient — see `install_default_route`.
//!
//! Under rootless Docker the container netns lives in a child userns
//! and `CAP_SYS_ADMIN` in the parent userns implicitly promotes to all
//! caps inside it, so the previous `cap_sys_admin+ep`-only install
//! happened to also let `ip(8)` `RTM_NEWROUTE` succeed; under rootful
//! Docker the netns is in init userns directly and there is no such
//! promotion, so we must hand the child its own `CAP_NET_ADMIN`
//! explicitly via the ambient set.
//!
//! The production install path is `/usr/local/libexec/sandboxd/` per
//! FHS § 4.7 (libexec is for non-user-facing helper binaries).
//!
//! Under setcap, the helper retains the capabilities across `exec`
//! without running as root, so the only privileged operations in the
//! sandbox stack are namespace-entry and route install — everything
//! else (config read, authorization) runs as the invoking user.
//!
//! # Stderr / exit-code contract
//!
//! All deny paths use a single exit code `1`. The reason text on stderr
//! is the load-bearing signal for both operators and the integration
//! tests; assertions key on substrings of the messages emitted here.

use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Command, ExitCode};

use nix::errno::Errno;
use nix::ifaddrs::getifaddrs;
use nix::sched::{CloneFlags, setns};
use nix::unistd::{Uid, User};
use sandbox_core::users_conf::{SubnetEntry, load_users_config_route_helper};

mod audit;
mod pair_check;

use audit::{AuditOutcome, AuditRecord, Decision};
use pair_check::{Verdict, pair_check};

/// Single deny exit code per the spec — the stderr reason carries the
/// "what went wrong" payload, distinct codes per step would only
/// invite scripts to grow ad-hoc dependencies on internal step
/// numbering.
const DENY_EXIT: u8 = 1;

fn main() -> ExitCode {
    run()
}

/// Render the pool field for an audit record. Spec § 3.5 specifies the
/// CIDR string form (e.g. `"10.209.0.0/20"`).
fn pool_string(subnet: &SubnetEntry) -> String {
    format!("{}/{}", subnet.cidr.base(), subnet.cidr.prefix_len())
}

/// Emit an audit record. The per-decision asymmetry (allow vs. deny on
/// write failure) lives here, in one place, so the security contract is
/// grep-able.
///
/// On allow-path write failure: log to stderr, return — the caller
/// proceeds with the routing install. On deny-path write failure: log
/// to stderr; the caller will already be on its way to exiting
/// `DENY_EXIT`, so no extra escalation is needed at *this* call site,
/// but for paths where the caller would otherwise have exited `0`
/// (impossible by construction here, but the type prevents accidental
/// regression), the return-value distinction is preserved.
fn emit_audit(record: &AuditRecord<'_>) -> AuditOutcome {
    let path = audit::audit_log_path();
    audit::write_record(&path, record)
}

/// Deny path: write the audit-deny record (with the per-spec-§3.5
/// escalation if the write fails), print the stderr reason, and return
/// `DENY_EXIT`. Used by every deny branch in `run`.
fn deny_with_audit(
    reason_tag: &'static str,
    stderr_msg: &str,
    caller: &str,
    for_user: &str,
    pool: Option<&str>,
    gateway_ip: &str,
    pid: i32,
) -> ExitCode {
    let outcome = emit_audit(&AuditRecord {
        decision: Decision::Denied { reason: reason_tag },
        caller,
        for_user,
        pool,
        gateway_ip,
        pid,
    });
    eprintln!("sandbox-route-helper: {stderr_msg}");
    if let AuditOutcome::WriteFailed(err) = outcome {
        // Deny-path escalation per spec § 3.5: surface the missing
        // forensic record on stderr. The deny itself is unconditional
        // (the exit code below stays `DENY_EXIT`); the escalation only
        // adds the operator-visible signal that the audit trail
        // evaporated.
        eprintln!("sandbox-route-helper: audit log write failed: {err}");
    }
    ExitCode::from(DENY_EXIT)
}

/// Allow-path post-success audit. Spec § 3.5: write-failure surfaces on
/// stderr but DOES NOT block the allow (routing-path-availability wins).
fn allow_audit(caller: &str, for_user: &str, pool: Option<&str>, gateway_ip: &str, pid: i32) {
    let outcome = emit_audit(&AuditRecord {
        decision: Decision::Allowed,
        caller,
        for_user,
        pool,
        gateway_ip,
        pid,
    });
    if let AuditOutcome::WriteFailed(err) = outcome {
        eprintln!("sandbox-route-helper: audit log write failed: {err}");
    }
}

/// Top-level orchestration. Each branch decides allow / deny and writes
/// an audit record before returning the `ExitCode`. No deny branch
/// reaches netns mutation (steps 5–7); pair-check denials and gateway-IP
/// denials short-circuit early.
fn run() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let parsed = match parse_argv(&args) {
        Ok(p) => p,
        Err(e) => {
            // Argv-parse failures pre-date the audit-log contract: the
            // helper cannot even name a caller/for-user pair, so no
            // record can be written that conforms to the schema. Match
            // the pre-change behavior — stderr + DENY_EXIT.
            eprintln!("sandbox-route-helper: {e}");
            return ExitCode::from(DENY_EXIT);
        }
    };
    let ParsedArgs {
        container_pid,
        gateway_ip,
        for_user_arg,
    } = parsed;
    let gateway_ip_str = gateway_ip.to_string();

    // Step 1 — caller identity. STRICT resolution per spec § 3.4:
    // unresolvable uid is a deny path, not a stderr-clarity hint. The
    // pair-check below needs both identities reliably; falling back to
    // numeric-only comparison would allow a request whose `for_user`
    // resolves to the same uid as `caller` (e.g. via NSS misconfig) to
    // sneak through pair-check on a name-mismatch.
    let caller_uid = Uid::current();
    let caller_name = match User::from_uid(caller_uid) {
        Ok(Some(u)) => u.name,
        // ENOENT-on-not-found is glibc-version-specific (≥2.36 surfaces it
        // as an error instead of Ok(None)); collapse with Ok(None) for
        // stable audit classification across libc versions. Mirrors the
        // `User::from_name` arm below for the `--for-user` lookup.
        Ok(None) | Err(Errno::ENOENT) => {
            let raw = caller_uid.as_raw();
            let msg = format!("caller uid {raw} does not resolve to a username");
            // No `caller` name to put in the audit record — fall back
            // to `uid:<n>` so the deny is still recorded with as much
            // identity as the helper could establish. The deny is
            // unconditional regardless of audit-record completeness.
            let placeholder = format!("uid:{raw}");
            let for_user_for_audit = for_user_arg.as_deref().unwrap_or(placeholder.as_str());
            return deny_with_audit(
                "caller-uid-unresolvable",
                &msg,
                &placeholder,
                for_user_for_audit,
                None,
                &gateway_ip_str,
                container_pid,
            );
        }
        Err(e) => {
            let raw = caller_uid.as_raw();
            let msg = format!("username resolution failed for uid {raw}: {e}");
            let placeholder = format!("uid:{raw}");
            let for_user_for_audit = for_user_arg.as_deref().unwrap_or(placeholder.as_str());
            return deny_with_audit(
                "caller-uid-resolution-error",
                &msg,
                &placeholder,
                for_user_for_audit,
                None,
                &gateway_ip_str,
                container_pid,
            );
        }
    };

    // `--for-user` defaults to the caller's name when omitted (§ 3.1),
    // so direct-CLI helper invocations remain meaningful.
    let for_user = for_user_arg.unwrap_or_else(|| caller_name.clone());

    // Resolve `--for-user` to a uid strictly. An unresolvable for-user
    // name is a deny path per § 3.4.
    let for_user_uid = match User::from_name(&for_user) {
        Ok(Some(u)) => u.uid.as_raw(),
        // ENOENT-on-not-found is glibc-version-specific (≥2.36 surfaces it
        // as an error instead of Ok(None)); collapse with Ok(None) for
        // stable audit classification across libc versions.
        Ok(None) | Err(Errno::ENOENT) => {
            let msg = format!("--for-user {for_user} does not resolve to a uid");
            return deny_with_audit(
                "for-user-unresolvable",
                &msg,
                &caller_name,
                &for_user,
                None,
                &gateway_ip_str,
                container_pid,
            );
        }
        Err(e) => {
            let msg = format!("username resolution failed for {for_user}: {e}");
            return deny_with_audit(
                "for-user-resolution-error",
                &msg,
                &caller_name,
                &for_user,
                None,
                &gateway_ip_str,
                container_pid,
            );
        }
    };

    // Step 3 — load users.conf and locate the gateway-IP's subnet.
    // `load_users_config_route_helper` ignores `SANDBOX_USERS_CONF` in
    // default builds and reads `/etc/sandboxd/users.conf`
    // unconditionally; only `test-env-override` builds honor the env
    // var. See the crate-level docstring + `route_helper_users_conf_path`.
    let config = match load_users_config_route_helper() {
        Ok(c) => c,
        Err(e) => {
            let msg = e.to_string();
            return deny_with_audit(
                "users-conf-load-failed",
                &msg,
                &caller_name,
                &for_user,
                None,
                &gateway_ip_str,
                container_pid,
            );
        }
    };
    let subnet = match config.find_subnet_by_gateway_ip(gateway_ip) {
        Some(s) => s,
        None => {
            let msg = format!("gateway ip {gateway_ip} not in any subnet");
            return deny_with_audit(
                "gateway-ip not in any subnet",
                &msg,
                &caller_name,
                &for_user,
                None,
                &gateway_ip_str,
                container_pid,
            );
        }
    };
    let pool = pool_string(subnet);

    // Step 4 — pair-membership check per spec §§ 3.1–3.2. Both caller
    // and for-user uids must appear in the pool's `allow_users` (each
    // resolved numerically via `SubnetEntry::allows_uid`). On mismatch,
    // exit DENY_EXIT with stderr naming both identities (§ 3.3).
    let verdict = pair_check(subnet, caller_uid.as_raw(), for_user_uid);
    if verdict == Verdict::Denied {
        let msg =
            format!("pair-check failed: caller={caller_name} for-user={for_user} pool={pool}");
        return deny_with_audit(
            "pair-check failed",
            &msg,
            &caller_name,
            &for_user,
            Some(&pool),
            &gateway_ip_str,
            container_pid,
        );
    }

    // Step 5 — pidfd_open + setns(CLONE_NEWNET). Using a pidfd, not a
    // /proc/<pid>/ns/net path, closes the PID-recycle TOCTOU window:
    // pidfd_open binds to the *thread-group leader* identity at open
    // time, so a recycled pid in the meantime cannot redirect the
    // setns target.
    let pidfd = match pidfd_open(container_pid) {
        Ok(fd) => fd,
        Err(errno) => {
            let msg = format_pidfd_error(container_pid, errno);
            return deny_with_audit(
                "pidfd-open-failed",
                &msg,
                &caller_name,
                &for_user,
                Some(&pool),
                &gateway_ip_str,
                container_pid,
            );
        }
    };
    if let Err(err) = setns(&pidfd, CloneFlags::CLONE_NEWNET) {
        // Drop the pidfd before returning so we don't leak it across
        // the deny path. It would close on process exit either way,
        // but explicit close keeps the fd lifecycle obvious.
        drop_pidfd(pidfd);
        let msg = format!("setns failed: {err}");
        return deny_with_audit(
            "setns-failed",
            &msg,
            &caller_name,
            &for_user,
            Some(&pool),
            &gateway_ip_str,
            container_pid,
        );
    }

    // After this point, the helper's /proc/self/ns/net symlink points
    // at the container's netns. getifaddrs() and the subsequent ip(8)
    // invocation operate inside it.

    // Step 6 — every IPv4 address on every non-lo interface must live
    // inside the caller's subnet. A single outside-subnet address
    // denies (cross-user MITM closure).
    if let Err(msg) = enforce_netns_addresses_in_subnet(subnet) {
        return deny_with_audit(
            "netns-address-outside-subnet",
            &msg,
            &caller_name,
            &for_user,
            Some(&pool),
            &gateway_ip_str,
            container_pid,
        );
    }

    // Step 7 — install the default route inside the netns.
    if let Err(msg) = install_default_route(gateway_ip) {
        return deny_with_audit(
            "route-install-failed",
            &msg,
            &caller_name,
            &for_user,
            Some(&pool),
            &gateway_ip_str,
            container_pid,
        );
    }

    // Step 8 — allow path. Record the audit line, then operator-facing
    // confirmation. Audit-log write failure on the allow path is a
    // stderr-only signal — routing-path-availability wins.
    allow_audit(
        &caller_name,
        &for_user,
        Some(&pool),
        &gateway_ip_str,
        container_pid,
    );
    println!("sandbox-route-helper: route installed for pid {container_pid} via {gateway_ip}");
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Argv parsing
// ---------------------------------------------------------------------------

/// Parsed argv. `for_user_arg` is `None` if `--for-user` was omitted —
/// the caller defaults it to `name(getuid())` per spec § 3.1, which
/// preserves the pre-existing direct-CLI invocation shape.
struct ParsedArgs {
    container_pid: i32,
    gateway_ip: Ipv4Addr,
    for_user_arg: Option<String>,
}

/// Parse argv: optional `--for-user <name>` before the two positional
/// args. `argv[0]` is the program name.
///
/// Hand-rolled per spec § 9.4 — pulling `clap` into the cap'd helper
/// would inflate the TCB by several thousand lines that have to be
/// reviewed for the privilege story. The flag accepts both
/// `--for-user <name>` (two-arg form) and `--for-user=<name>` (one-arg
/// form); both shapes show up in practice.
fn parse_argv(args: &[OsString]) -> Result<ParsedArgs, String> {
    const USAGE: &str =
        "usage: sandbox-route-helper [--for-user <name>] <container_pid> <gateway_ip>";

    // Walk argv left-to-right, consuming `--for-user` (and value) where
    // it appears. Anything that is not the flag is a positional. We
    // intentionally do NOT accept `--for-user` after the positionals,
    // because the daemon emits it before them (§ 6.5) and an
    // after-positionals form would create two ways to spell the same
    // intent for no benefit.
    let mut for_user_arg: Option<String> = None;
    let mut positionals: Vec<&OsString> = Vec::with_capacity(2);

    // argv[0] is the program name; skip it.
    let mut iter = args.iter().enumerate().skip(1).peekable();
    let mut accepting_flags = true;

    while let Some((_idx, arg)) = iter.next() {
        let arg_str = arg.to_string_lossy();
        if accepting_flags && arg_str == "--for-user" {
            // Two-argument form: --for-user NAME
            let Some((_, value)) = iter.next() else {
                return Err(format!("{USAGE} (missing value after --for-user)"));
            };
            if for_user_arg.is_some() {
                return Err(format!("{USAGE} (--for-user specified more than once)"));
            }
            let name = value.to_string_lossy().into_owned();
            if name.is_empty() {
                return Err(format!("{USAGE} (--for-user value must be non-empty)"));
            }
            if name.starts_with("--") {
                // Guard against the daemon accidentally passing
                // `--for-user --some-other-flag`: the value would
                // shadow a missing arg and tank pair-check later.
                return Err(format!(
                    "{USAGE} (--for-user value looks like a flag: {name})"
                ));
            }
            for_user_arg = Some(name);
        } else if accepting_flags && let Some(rest) = arg_str.strip_prefix("--for-user=") {
            // Single-argument form: --for-user=NAME
            if for_user_arg.is_some() {
                return Err(format!("{USAGE} (--for-user specified more than once)"));
            }
            if rest.is_empty() {
                return Err(format!("{USAGE} (--for-user value must be non-empty)"));
            }
            for_user_arg = Some(rest.to_string());
        } else if accepting_flags && arg_str == "--" {
            // End-of-flags sentinel — everything after this is
            // positional. The daemon never emits this; it's a hook for
            // operator debugging.
            accepting_flags = false;
        } else if accepting_flags && arg_str.starts_with("--") {
            // Unknown flag. Reject — the helper deliberately does not
            // accept arbitrary flags, and silently treating an unknown
            // `--something` as a positional would hide typos in daemon-
            // emitted argv.
            return Err(format!("{USAGE} (unrecognised flag: {arg_str})"));
        } else {
            positionals.push(arg);
        }
    }

    if positionals.len() != 2 {
        return Err(USAGE.to_string());
    }

    let pid_arg = positionals[0].to_string_lossy();
    let pid: i32 = pid_arg
        .parse()
        .ok()
        .filter(|n: &i32| *n >= 1)
        .ok_or_else(|| format!("invalid container pid: {pid_arg}"))?;

    let ip_arg = positionals[1].to_string_lossy();
    let gateway_ip: Ipv4Addr = ip_arg
        .parse()
        .map_err(|_| format!("invalid gateway ip: {ip_arg}"))?;

    Ok(ParsedArgs {
        container_pid: pid,
        gateway_ip,
        for_user_arg,
    })
}

// ---------------------------------------------------------------------------
// pidfd_open — direct libc syscall (nix 0.29 does not expose it)
// ---------------------------------------------------------------------------

/// Open a pidfd referring to `pid`. Returns an `OwnedFd` so the close
/// is RAII; on error returns the captured `errno` so the caller can
/// distinguish ESRCH (pid gone) from EINVAL (kernel too old) etc.
///
/// `pidfd_open(2)` is Linux 5.3+. If the running kernel is older the
/// syscall returns -1 with errno=ENOSYS, which surfaces here as the
/// raw errno. The kernel-floor check is documentation-only (Phase 2D);
/// at runtime an old kernel just produces a deny.
fn pidfd_open(pid: i32) -> Result<OwnedFd, i32> {
    // SAFETY: `libc::syscall` returns -1 on error with errno set; on
    // success it returns a non-negative file descriptor that we
    // immediately wrap in `OwnedFd` to take ownership. The flags
    // argument is 0 — the only currently-defined flag is
    // `PIDFD_NONBLOCK` (Linux 5.10+) which we don't need here.
    // nix-rust/nix#2748: pidfd_open wrapper not yet provided; using libc::syscall as a deliberate gap.
    let raw: libc::c_long =
        unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0u32) };
    if raw < 0 {
        // SAFETY: errno is thread-local and set by the failed syscall
        // immediately above. No intervening libc call has had a chance
        // to clobber it.
        let errno = unsafe { *libc::__errno_location() };
        return Err(errno);
    }
    // SAFETY: `raw` is a non-negative kernel-issued fd we have
    // exclusive ownership of.
    let fd = i32::try_from(raw)
        .expect("pidfd_open returned a non-negative fd; kernel-allocated fd numbers fit in i32");
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Render a `pidfd_open` errno into the helper's stderr phrasing.
/// ESRCH gets the dedicated "not found" message that the spec calls
/// out; everything else surfaces the errno verbatim (callers reading
/// stderr can look the symbol up).
fn format_pidfd_error(pid: i32, errno: i32) -> String {
    if errno == libc::ESRCH {
        format!("container pid {pid} not found")
    } else {
        format!("pidfd_open({pid}) failed: errno {errno}")
    }
}

/// Explicit drop site so the deny path's intent is grep-able. Function
/// exists purely for documentation; calling `drop()` directly would
/// achieve the same close.
fn drop_pidfd(fd: OwnedFd) {
    drop(fd);
}

// ---------------------------------------------------------------------------
// Step 6 — netns address enforcement
// ---------------------------------------------------------------------------

/// Verify that every IPv4 address bound to a non-`lo` interface inside
/// the (already-entered) netns falls inside the caller's subnet.
///
/// IPv6 addresses are ignored: the project is IPv4-only today (no IPv6
/// in the Lima setup), and the spec is explicit that IPv6 enforcement
/// is deferred. Interfaces without an address (e.g. an unconfigured
/// `eth0` that hasn't yet had an IP assigned) are skipped — they have
/// no address to validate.
///
/// An interface count of zero non-lo entries trivially passes; the
/// step-7 `ip route replace` would then fail at the kernel level
/// (nothing to attach the default route to), which is the natural
/// surface for that misconfiguration. Adding an explicit "must have at
/// least one non-lo address" check would over-specify what the spec
/// asks of step 6.
fn enforce_netns_addresses_in_subnet(subnet: &SubnetEntry) -> Result<(), String> {
    let iter = getifaddrs().map_err(|err| format!("getifaddrs failed: {err}"))?;
    for ifaddr in iter {
        if ifaddr.interface_name == "lo" {
            continue;
        }
        let Some(addr) = ifaddr.address else {
            // Interface present but no address bound — nothing to check.
            continue;
        };
        let Some(sock) = addr.as_sockaddr_in() else {
            // Not IPv4 (most commonly an IPv6 address or a link-layer
            // AF_PACKET entry); skip.
            continue;
        };
        // `SockaddrIn::ip()` already returns a `std::net::Ipv4Addr`
        // in nix 0.29 — no conversion needed.
        let ip = sock.ip();
        if !subnet.cidr.contains(ip) {
            return Err(format!(
                "netns address {} on {} outside caller subnet {}/{}",
                ip,
                ifaddr.interface_name,
                subnet.cidr.base(),
                subnet.cidr.prefix_len(),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 7 — install default route
// ---------------------------------------------------------------------------

/// `ip route replace default via <gateway_ip>` inside the (already-
/// entered) netns. We let `ip(8)`'s own stderr surface to the user on
/// failure rather than re-formatting it.
///
/// Before exec we raise `CAP_NET_ADMIN` to the ambient set so the
/// `ip(8)` child inherits permitted+effective `CAP_NET_ADMIN` and can
/// issue `RTM_NEWROUTE`. The file caps `cap_net_admin,cap_sys_admin=eip`
/// place `CAP_NET_ADMIN` in the file's permitted+inheritable+effective
/// sets, but on exec a process's *thread* inheritable set is taken from
/// the parent — which is the unprivileged caller, so inheritable is
/// empty after exec. `PR_CAP_AMBIENT_RAISE` requires the cap in both
/// permitted AND inheritable, so we first promote permitted →
/// inheritable, then inheritable → ambient.
fn install_default_route(gateway_ip: Ipv4Addr) -> Result<(), String> {
    caps::raise(
        None,
        caps::CapSet::Inheritable,
        caps::Capability::CAP_NET_ADMIN,
    )
    .map_err(|err| format!("raise CAP_NET_ADMIN to inheritable: {err}"))?;
    caps::raise(None, caps::CapSet::Ambient, caps::Capability::CAP_NET_ADMIN)
        .map_err(|err| format!("raise CAP_NET_ADMIN to ambient: {err}"))?;

    let status = Command::new("ip")
        .args([
            "route",
            "replace",
            "default",
            "via",
            &gateway_ip.to_string(),
        ])
        .status()
        .map_err(|err| format!("failed to spawn ip(8): {err}"))?;
    if !status.success() {
        return Err(format!(
            "ip route replace failed: exit {}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The route helper's `test-env-override` Cargo feature
    //! gates whether the helper-side `users.conf` path resolver
    //! consults `SANDBOX_USERS_CONF`. The feature lives on this crate
    //! and forwards to the same-named feature on `sandbox-core`; the
    //! resolver itself
    //! ([`sandbox_core::users_conf::route_helper_users_conf_path`]) is
    //! the unit under test, but the `cfg(feature = ...)` evaluation
    //! point that matters for the privilege story is *this crate*: a
    //! production build of `sandbox-route-helper` (no feature flag) is
    //! what gets `cap_sys_admin+ep` applied at install time, and that
    //! build must not honor the env var even if some upstream code
    //! sets it.
    //!
    //! Two compile-time-mutually-exclusive tests pin the contract from
    //! both directions: one fires under `cfg(feature = "test-env-override")`,
    //! the other under `cfg(not(...))`. The integration-test target
    //! enables the feature; the default workspace `cargo nextest run`
    //! picks the negative arm.

    use sandbox_core::users_conf::{USERS_CONF_PATH_ENV, route_helper_users_conf_path};
    // `DEFAULT_USERS_CONF_PATH` is only referenced from the
    // `cfg(not(feature = "test-env-override"))` test below, so a
    // `cfg`-mirrored use keeps the `test-env-override` build clean of
    // unused-import warnings.
    #[cfg(not(feature = "test-env-override"))]
    use sandbox_core::users_conf::DEFAULT_USERS_CONF_PATH;
    use std::path::PathBuf;

    /// Helper that snapshots / restores the env var around a callback
    /// so the test does not leak state into other tests in the same
    /// binary. Env-var mutation is `unsafe` in Rust 2024 (cross-thread
    /// races on libc env block); the route-helper tests serialize via
    /// being the only consumers of this var inside this binary.
    fn with_env<F: FnOnce()>(value: Option<&str>, body: F) {
        let prev = std::env::var(USERS_CONF_PATH_ENV).ok();
        // SAFETY: see above.
        unsafe {
            match value {
                Some(v) => std::env::set_var(USERS_CONF_PATH_ENV, v),
                None => std::env::remove_var(USERS_CONF_PATH_ENV),
            }
        }
        body();
        unsafe {
            match prev {
                Some(v) => std::env::set_var(USERS_CONF_PATH_ENV, v),
                None => std::env::remove_var(USERS_CONF_PATH_ENV),
            }
        }
    }

    /// Default builds of `sandbox-route-helper` (production cap'd
    /// binary) MUST NOT honor `SANDBOX_USERS_CONF`. The privilege story
    /// rests on this: any user who can exec the cap'd helper would
    /// otherwise be able to redirect its auth-config read to a file
    /// they own, granting themselves arbitrary `allow_users` entries.
    #[cfg(not(feature = "test-env-override"))]
    #[test]
    fn route_helper_path_resolution_ignores_env_in_default_build() {
        with_env(Some("/tmp/route-helper-test-attacker.conf"), || {
            let p = route_helper_users_conf_path();
            assert_eq!(
                p,
                PathBuf::from(DEFAULT_USERS_CONF_PATH),
                "production build of sandbox-route-helper MUST ignore SANDBOX_USERS_CONF"
            );
        });
    }

    /// `test-env-override` builds (used by `make install-route-helper-test-cap`
    /// for the route-helper integration tests) honor the env var so
    /// tests can drive a tempfile users.conf they own. This arm
    /// proves the feature flag actually opens the gate.
    #[cfg(feature = "test-env-override")]
    #[test]
    fn route_helper_path_resolution_honors_env_with_test_env_override_feature() {
        with_env(Some("/tmp/route-helper-test-tempfile.conf"), || {
            let p = route_helper_users_conf_path();
            assert_eq!(
                p,
                PathBuf::from("/tmp/route-helper-test-tempfile.conf"),
                "test-env-override build of sandbox-route-helper must honor \
                 SANDBOX_USERS_CONF for integration-test seam"
            );
        });
    }
}
