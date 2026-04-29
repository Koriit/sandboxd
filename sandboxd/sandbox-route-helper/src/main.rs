//! `sandbox-route-helper` — privileged setcap binary that installs a
//! default route inside a container's netns on behalf of an authorized
//! caller.
//!
//! # Invocation
//!
//! ```text
//! sandbox-route-helper <container_pid> <gateway_ip>
//! ```
//!
//! Exactly two positional arguments. No flags, no stdin, no env-var
//! configuration in production. The `SANDBOX_USERS_CONF` env var seam
//! exists in `sandbox-core::users_conf` for daemon-side and helper-side
//! integration tests, but the helper consults it ONLY when this crate
//! is built with the `test-env-override` Cargo feature. Default
//! production builds (used by the `install-route-helper-prod-cap` make
//! target) ignore the env var entirely. See
//! [`sandbox_core::users_conf::route_helper_users_conf_path`] for the
//! gating logic.
//!
//! # Authorization flow
//!
//! Per the M11 lite-mode container backend spec (§ "Helper authorization
//! flow"), every invocation runs eight ordered steps. Any step that
//! denies prints a single `sandbox-route-helper: <reason>` line to
//! stderr and exits with code `1`. No netns mutation occurs on the deny
//! path — the helper exits before reaching step 7.
//!
//! 1. Caller identity — read `getuid()`; resolve username best-effort
//!    for stderr clarity.
//! 2. Argv parse — already done above.
//! 3. Load `users.conf`; locate the subnet whose CIDR contains the
//!    gateway IP argument.
//! 4. Verify the caller's uid appears in that subnet's `allow_users`
//!    (numeric comparison via `getpwnam_r`, per spec line 406-408).
//! 5. `pidfd_open(container_pid)` then `setns(pidfd, CLONE_NEWNET)` —
//!    closes the PID-recycle TOCTOU window that `setns(open("/proc/<pid>
//!    /ns/net"))` would leave open.
//! 6. Enumerate every IPv4 address on every non-`lo` interface inside
//!    the netns; require all of them to live inside the caller's
//!    subnet. A single outside-subnet address denies — that's the
//!    cross-user MITM closure (spec lines 420-430).
//! 7. `ip route replace default via <gateway_ip>` inside the netns.
//! 8. Exit 0 with a one-line stdout confirmation.
//!
//! # Privilege model
//!
//! The helper requires `cap_sys_admin+ep` to call `setns(2)` on a
//! foreign netns. Operators install it with:
//!
//! ```text
//! sudo setcap cap_sys_admin+ep /usr/local/libexec/sandboxd/sandbox-route-helper
//! ```
//!
//! The production install path is `/usr/local/libexec/sandboxd/` per
//! FHS § 4.7 (libexec is for non-user-facing helper binaries).
//!
//! Under setcap, the helper retains the capability across `exec`
//! without running as root, so the only privileged operation in the
//! sandbox stack is namespace-entry — everything else (config read,
//! authorization, route install via `ip(8)`) runs as the invoking user.
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

use nix::ifaddrs::getifaddrs;
use nix::sched::{CloneFlags, setns};
use nix::unistd::{Uid, User};
use sandbox_core::users_conf::{SubnetEntry, load_users_config_route_helper};

/// Single deny exit code per the spec — the stderr reason carries the
/// "what went wrong" payload, distinct codes per step would only
/// invite scripts to grow ad-hoc dependencies on internal step
/// numbering.
const DENY_EXIT: u8 = 1;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("sandbox-route-helper: {reason}");
            ExitCode::from(DENY_EXIT)
        }
    }
}

/// Top-level orchestration. Every error returned bubbles up to `main`
/// and surfaces as a single stderr line — the caller doesn't see step
/// numbers, only the failure reason.
fn run() -> Result<(), String> {
    let args: Vec<OsString> = std::env::args_os().collect();
    let (container_pid, gateway_ip) = parse_argv(&args)?;

    // Step 1 — caller identity.
    let caller_uid = Uid::current();
    // Username is best-effort for stderr clarity. A resolution failure
    // (rare — typically only on /etc/passwd corruption) does not deny;
    // the auth check uses the numeric uid.
    let caller_user = User::from_uid(caller_uid).ok().flatten();

    // Step 3 — load users.conf and locate the gateway-IP's subnet.
    // `load_users_config_route_helper` ignores `SANDBOX_USERS_CONF` in
    // default builds and reads `/etc/sandboxd/users.conf`
    // unconditionally; only `test-env-override` builds honor the env
    // var. See the crate-level docstring + `route_helper_users_conf_path`.
    let config = load_users_config_route_helper().map_err(|e| e.to_string())?;
    let subnet = config
        .find_subnet_by_gateway_ip(gateway_ip)
        .ok_or_else(|| format!("gateway ip {gateway_ip} not in any subnet"))?;

    // Step 4 — allow_users check. NUMERIC ground truth: usernames in
    // users.conf are admin-readability only (spec line 406-408).
    if !subnet.allows_uid(caller_uid.as_raw()) {
        return Err(format!(
            "uid {} ({}) not in allow_users for subnet {}/{}",
            caller_uid.as_raw(),
            caller_user
                .as_ref()
                .map(|u| u.name.as_str())
                .unwrap_or("<unknown>"),
            subnet.cidr.base(),
            subnet.cidr.prefix_len(),
        ));
    }

    // Step 5 — pidfd_open + setns(CLONE_NEWNET). Using a pidfd, not a
    // /proc/<pid>/ns/net path, closes the PID-recycle TOCTOU window:
    // pidfd_open binds to the *thread-group leader* identity at open
    // time, so a recycled pid in the meantime cannot redirect the
    // setns target.
    let pidfd =
        pidfd_open(container_pid).map_err(|errno| format_pidfd_error(container_pid, errno))?;
    setns(&pidfd, CloneFlags::CLONE_NEWNET).map_err(|err| {
        // Drop the pidfd before returning so we don't leak it across
        // the deny path. It would close on process exit either way,
        // but explicit close keeps the fd lifecycle obvious.
        drop_pidfd(pidfd);
        format!("setns failed: {err}")
    })?;

    // After this point, the helper's /proc/self/ns/net symlink points
    // at the container's netns. getifaddrs() and the subsequent ip(8)
    // invocation operate inside it.

    // Step 6 — every IPv4 address on every non-lo interface must live
    // inside the caller's subnet. A single outside-subnet address
    // denies (cross-user MITM closure).
    enforce_netns_addresses_in_subnet(subnet)?;

    // Step 7 — install the default route inside the netns.
    install_default_route(gateway_ip)?;

    // Step 8 — operator-facing confirmation.
    println!("sandbox-route-helper: route installed for pid {container_pid} via {gateway_ip}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Argv parsing
// ---------------------------------------------------------------------------

/// Parse the two positional arguments. argv[0] is the program name.
fn parse_argv(args: &[OsString]) -> Result<(i32, Ipv4Addr), String> {
    if args.len() != 3 {
        return Err("usage: sandbox-route-helper <container_pid> <gateway_ip>".to_string());
    }

    let pid_arg = args[1].to_string_lossy();
    let pid: i32 = pid_arg
        .parse()
        .ok()
        .filter(|n: &i32| *n >= 1)
        .ok_or_else(|| format!("invalid container pid: {pid_arg}"))?;

    let ip_arg = args[2].to_string_lossy();
    let gateway_ip: Ipv4Addr = ip_arg
        .parse()
        .map_err(|_| format!("invalid gateway ip: {ip_arg}"))?;

    Ok((pid, gateway_ip))
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
fn install_default_route(gateway_ip: Ipv4Addr) -> Result<(), String> {
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
    //! M11-S9 — the route helper's `test-env-override` Cargo feature
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
