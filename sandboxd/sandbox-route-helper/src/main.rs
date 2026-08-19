//! `sandbox-route-helper` — privileged setcap binary that installs a
//! default route inside a container's netns on behalf of an authorized
//! caller.
//!
//! # Invocation
//!
//! ```text
//! sandbox-route-helper [--for-user <name>] <container_pid> <gateway_ip>
//! sandbox-route-helper --vm-gateway-mode <container_pid> <gateway_ip>
//! ```
//!
//! Standard form: two positional arguments preceded by an optional
//! `--for-user <name>` flag. Nothing is read from stdin, and no environment
//! variable feeds the authorization decision in a production build: the
//! `SANDBOX_USERS_CONF` seam exists in `sandbox-core::users_conf` for
//! daemon-side and helper-side integration tests, but the helper consults it
//! ONLY when this crate is built with the `test-env-override` Cargo feature.
//! Default production builds (used by the `install-route-helper-prod-cap`
//! make target) ignore the env var entirely. See
//! [`sandbox_core::users_conf::route_helper_users_conf_path`] for the gating
//! logic.
//!
//! The caller's environment is not ignored altogether, though, and where it
//! still reaches is worth naming rather than leaving to be discovered. In a
//! production build this crate's own code reads it in exactly one place:
//! `XDG_RUNTIME_DIR`, else `HOME`, selects where the audit record is written
//! (`audit::audit_log_path`). A caller therefore picks the file its own
//! record lands in — and, by naming one that cannot be appended to, whether a
//! record lands at all. What it does not pick is the decision: a deny is
//! still a deny, with the same exit code, whether or not its record was
//! written.
//!
//! The `ip(8)` child was a second such place for as long as the program was
//! spawned by name, because `PATH` then chose which binary received the
//! ambient `CAP_NET_ADMIN`. It is now exec'd from an absolute path with the
//! caller's environment discarded — see `install_default_route`.
//!
//! `test-env-override` builds read three further variables, each gated at its
//! own site: `SANDBOX_USERS_CONF` (through `sandbox-core`),
//! `SANDBOX_ROUTE_HELPER_AUDIT_LOG` (`audit`), and
//! `SANDBOX_ROUTE_HELPER_TEST_INJECT_USER_RESOLUTION_ERROR`. The installed
//! cap'd binary is not built with that feature and reads none of them.
//!
//! VM-gateway mode: `--vm-gateway-mode` activates the degenerate
//! authorization path for invocations inside the `sandboxd-gateway` Lima
//! VM. See the "In-VM authorization" section below.
//!
//! # Authorization flow
//!
//! Each invocation runs ordered steps; any step that denies prints a
//! `sandbox-route-helper: <reason>` line to stderr and exits with code `1`.
//! Denials from step 2 onward *attempt* a JSON-Lines audit record — attempt,
//! because the append can fail, and when it does the deny proceeds anyway
//! with the failure reported on its own stderr line. The record's destination
//! comes from the caller's environment (see the Invocation section above), so
//! a caller has some say over whether its record survives and none over
//! whether it is denied. Two kinds of denial do not attempt a record at all:
//! an argv parse failure, which is step 1 and has no caller/for-user pair to
//! name yet, and anything on the `--vm-gateway-mode` path, which has no audit
//! sink at all — see `run_vm_gateway_mode`.
//!
//! A deny does not imply the namespace was left untouched. Steps 1–4 all run
//! before the helper enters anything, but the step-6 and step-7 deny branches
//! are reached from *inside* the container's netns — and the step-7 one can be
//! reached after `CAP_NET_ADMIN` was raised into the ambient set and `ip(8)`
//! ran there, which is the case where `ip` itself exited non-zero. What no
//! deny branch does is report success: the allow record and the exit-0
//! confirmation are downstream of the install returning `Ok`. See `run` for
//! the branch-by-branch version.
//!
//! 1. Argv parse — `--for-user <name>` (optional) or `--vm-gateway-mode`,
//!    plus the two positional args. Syntax only: no name is resolved and no
//!    identity is known yet, which is why a failure here has nothing to write
//!    a record about.
//! 2. Identities — read `getuid()` and resolve it to a username via
//!    `getpwuid_r`, then resolve `--for-user` (defaulting to the caller's own
//!    name) to a uid via `getpwnam_r`. Both STRICT — either one unresolvable
//!    denies.
//! 3. Load `users.conf`; locate the subnet whose CIDR contains the
//!    gateway IP argument.
//! 4. **Pair-membership check** — both the caller's
//!    uid AND the `--for-user` uid must appear in the chosen pool's
//!    `allow_users` (each resolved numerically via `getpwnam_r`).
//! 5. `pidfd_open(container_pid)` then `setns(pidfd, CLONE_NEWNET)`. The
//!    pidfd binds to the thread-group leader that held `container_pid` at open
//!    time, so nothing occurring between the open and the `setns` can redirect
//!    the target: if that process is gone by then, the `setns` fails with
//!    `ESRCH` rather than landing somewhere else.
//!
//!    Read that as a property of this form and not as an advantage over
//!    `setns(open("/proc/<pid>/ns/net"))`, which is what this file used to
//!    claim. An nsfs fd pins the namespace just as firmly — opened against a
//!    live pid that is then killed and reaped, it still enters the original
//!    namespace. Both forms resolve `container_pid` at the moment the helper
//!    calls them, so the one window that is real — between the daemon reading
//!    the container's pid and the helper acting on it — is the same width
//!    either way and is closed by neither. A pid recycled inside that window
//!    puts the helper in whatever namespace now holds it; what stands between
//!    that and a route is the address checking that follows (step 6 here, the
//!    two in-VM checks on the other path), not the choice of handle.
//! 6. Enumerate every IPv4 address on every non-`lo` interface inside
//!    the netns; require all of them to live inside the subnet the
//!    gateway IP was matched to in step 3. A single outside-subnet
//!    address denies. That is the cross-*pool* closure: the namespace
//!    being routed and the gateway it is routed to must belong to the
//!    same `users.conf` pool, which step 4 has already tied to both
//!    identities. It says nothing about two users listed in one pool's
//!    `allow_users` — they are inside each other's boundary by
//!    configuration, and this check does not separate them.
//! 7. `ip route replace default via <gateway_ip>` inside the netns, running
//!    an `ip(8)` taken from a fixed list of absolute paths, with the caller's
//!    environment discarded.
//! 8. Append an `allowed`-decision audit record and exit 0 with a
//!    one-line stdout confirmation. A failed append here is a stderr line
//!    only: the route exists by then, so there is nothing left to withhold.
//!
//! # In-VM authorization (`--vm-gateway-mode`)
//!
//! When invoked inside the `sandboxd-gateway` Lima VM via
//! `sudo sandbox-route-helper --vm-gateway-mode <pid> <gw_ip>`, the caller
//! the helper sees is root (uid 0, via sudo) and there is no `users.conf` in
//! the VM. The standard host-uid + pair-membership gate cannot apply here:
//! neither half has anything to work with.
//!
//! What stands in its place is weaker, and the difference is worth stating
//! rather than describing the VM as a boundary it is not:
//!
//! - On the *host* side, the gateway instance lives in the daemon's own
//!   LIMA_HOME rather than in any operator's, and the SSH key `limactl`
//!   wrote there is owned by the daemon uid. Measured on a provisioned
//!   gateway: the key is mode `0600`, and the LIMA_HOME holding it —
//!   together with both state-tree levels above it — is `0700` owned by
//!   that uid, so traversal stops there for anyone else. Driving
//!   `limactl shell sandboxd-gateway -- sudo <helper> …` from outside the VM
//!   therefore means being the daemon (or root), and the directory chain
//!   closes it without relying on the key's own mode.
//! - That constrains how an invocation gets *into* the VM from outside. It
//!   says nothing about one that starts inside, and the helper cannot tell
//!   the two apart — both arrive as uid 0. The gateway template writes
//!   `ALL ALL=(root) NOPASSWD:` for this binary, so the grant is not the
//!   login user's alone: code execution in the VM under *any* account is
//!   already past this gate. Container code is not yet in that position.
//!   A lite container gets its own mount namespace — a home volume, the
//!   guest binary, the workspace, the session CA and three SSH credential
//!   files, with no docker socket among them and the helper's install
//!   directory not bound in — so reaching the installed binary from inside
//!   one takes leaving it first, a step this gate says nothing about
//!   either.
//!
//! The checks that bind such a caller are therefore the ones the helper makes
//! from inside the namespace it enters, not the mode gate. See the
//! `containment` module for what they establish and what they do not.
//!
//! In `--vm-gateway-mode` the helper:
//! 1. Runs step 1 of the standard flow unchanged — the same parser, before
//!    the mode is even known. `--for-user` and `--vm-gateway-mode` are
//!    mutually exclusive, so what a `--vm-gateway-mode` argv leaves is
//!    `<container_pid>` and `<gateway_ip>`.
//! 2. Verifies it is running as root (uid 0). What this is worth depends on
//!    where the caller is. On the *host*, where the helper is a cap'd binary
//!    an unprivileged operator can exec, it is load-bearing: it stops that
//!    operator from passing `--vm-gateway-mode` to skip steps 2–4 and the
//!    `users.conf` gate with them. *Inside* the VM it establishes only that
//!    the caller holds root there — nothing about which host process asked,
//!    and nothing a caller who can run the VM's passwordless `sudo` does not
//!    already have.
//! 3. Skips steps 2–4 of the standard flow: caller-uid resolution, for-user
//!    resolution, `users.conf` load, pair-membership check.
//! 4. Proceeds directly to `pidfd_open` + `setns`, then to two address
//!    checks that are *not* step 6 — there is no pool CIDR here to check
//!    against. `enforce_netns_addresses_private` constrains the *container's*
//!    addresses: every IPv4 address the kernel reports on a non-`lo` interface
//!    must be RFC 1918. `containment::gateway_is_on_an_observed_subnet`
//!    constrains the *argument*, from what the namespace reports about itself.
//!    Addresses in other families are skipped by both checks rather than
//!    judged, IPv6 among them; the route being installed is IPv4-only, and the
//!    silence is scoped to match it.
//!
//!    What that second check accepts, what it refuses, and what either is
//!    worth are stated in the `containment` module docs and pinned by the tests
//!    beside them. They are deliberately not summarised here: how much it
//!    establishes is relative to what the namespace reports, a summary that
//!    drops that qualifier reads as a stronger guarantee than the code gives,
//!    and nothing fails when a summary and the rules it describes drift apart.
//!
//!    What this path establishes on its own is the ceiling over both checks.
//!    The helper holds no record of what the session was allocated — inside the
//!    VM there is no `users.conf` and nothing else it reads — so the gateway it
//!    installs is whichever address its caller named, and both checks can only
//!    ask whether that address is consistent with the namespace they were
//!    pointed at. Then the route install (step 7).
//! 5. Prints confirmation to stdout and exits 0 on success.
//!
//! Nothing on this path constrains `<container_pid>`: the caller names a
//! process and the helper enters whatever netns that process is in. The
//! address checks then speak about *that* namespace, which is what keeps a
//! mis-aimed pid from being useful, but the aim itself is unchecked.
//!
//! # Privilege model
//!
//! The helper requires three capabilities when an unprivileged caller execs
//! it — the standard host path. On the in-VM path the caller is already root
//! and holds them without the file caps mattering.
//!
//! - `CAP_SYS_ADMIN` to call `setns(2)` on a foreign netns.
//! - `CAP_NET_ADMIN` to issue `RTM_NEWROUTE` (which the spawned `ip(8)`
//!   needs to inherit via the ambient set — see step 7 below).
//! - `CAP_SYS_PTRACE` because the container's PID 1 runs as the
//!   operator's uid (`docker create --user <op>:<op>`), distinct from the
//!   helper's own `sandbox` uid. The pidfd `setns` path (step 5) makes
//!   the kernel run `ptrace_may_access(target, PTRACE_MODE_READ_REALCREDS)`
//!   on the container leader; across the uid boundary that check is
//!   satisfied only with `CAP_SYS_PTRACE`, and without it the cross-uid
//!   `setns` fails with `EPERM`. The mode reads *real* credentials rather
//!   than effective ones — measured: a prober whose real uid matched the
//!   target while its effective uid did not was allowed, and the mirror
//!   case was denied. The distinction costs nothing here, because the
//!   helper is setcap rather than setuid and its two uids agree (see
//!   `is_regular_executable_file`). A same-uid container would not need the
//!   capability, and that case is reachable rather than hypothetical:
//!   `effective_container_user` in `sandbox-core::backend::container` falls
//!   back to the runtime's constructor-time pair when a session carries no
//!   operator identity — the daemon's own uid and gid for any non-root
//!   daemon, though `map_container_uid_gid` degrades a uid-0 daemon to
//!   `1000:1000` rather than passing root through. A session row persisted
//!   before that identity was recorded deserialises to exactly that
//!   fallback. The capability is needed in the split-uid case and
//!   unused in the other, so the install below carries it either way. Only
//!   `CAP_NET_ADMIN` is promoted to the ambient set for `ip(8)`;
//!   `CAP_SYS_PTRACE` stays with the helper and is not inherited by the
//!   child.
//!
//! Operators install it with:
//!
//! ```text
//! sudo setcap 'cap_net_admin,cap_sys_admin,cap_sys_ptrace=eip' /usr/local/libexec/sandboxd/sandbox-route-helper
//! ```
//!
//! The `=eip` flags put all three caps in the file's Permitted,
//! Inheritable, and Effective sets. On exec by an unprivileged caller, the thread's
//! Permitted gets the file Permitted (gated by bset); Effective tracks
//! Permitted because the file Effective bit is set; but Inheritable is
//! taken from the *parent's* Inheritable, which is empty. The helper
//! itself must therefore promote `CAP_NET_ADMIN` from its Permitted into
//! its Inheritable set before raising ambient — see `install_default_route`.
//!
//! Under rootless Docker the container netns lives in a child userns. That
//! does not make `CAP_SYS_ADMIN` a master key inside it. Measured on Linux
//! 6.8 aarch64, with two processes in the parent userns carrying an identical
//! `cap_sys_admin,cap_sys_ptrace` set and differing only in effective uid: the
//! one whose euid differed from the namespace's owner was refused a
//! `CAP_NET_ADMIN` operation in that netns, and the one whose euid equalled it
//! was allowed. The rule doing the work is the `user_namespaces(7)` one — a
//! process in the parent userns whose effective uid matches the owner (the
//! euid of whoever created the namespace) holds every capability inside it.
//! That is a uid coincidence rather than a capability, and not one this uid
//! split produces: the helper runs as `sandbox`, while a rootless daemon's
//! userns is owned by the uid that started it.
//!
//! What does cross a userns boundary on capability alone is each capability
//! separately — in the same measurement the euid-mismatched process's `setns`
//! succeeded, because a capability held in an ancestor userns applies within
//! its descendants. That carries the *helper* in with the caps it holds and
//! does nothing for a child that holds none — which is what the `ip(8)` child
//! holds when an unprivileged helper execs it, unless the ambient set gives it
//! something. Under rootful Docker the netns is in the init userns and the
//! owner rule has nothing to apply to at all. On either layout, for the
//! unprivileged host caller this section describes, `ip(8)` must be handed its
//! own `CAP_NET_ADMIN` explicitly via the ambient set — see
//! `install_default_route`.
//!
//! The `--vm-gateway-mode` branch is not in that position, and the qualifier
//! above is doing real work. That branch refuses any caller whose uid is not 0
//! (see `run_vm_gateway_mode`) and does not drop privilege before spawning
//! `ip(8)`, so its exec is root's. Measured on the same kernel, a uid-0 parent
//! that execs a file carrying no file capabilities gives the child the full
//! bounding set — even with the parent's own permitted set narrowed to
//! `CAP_NET_ADMIN` alone and its ambient set left empty. Root's exec
//! re-populates the child on its own, so on that branch the ambient raise in
//! `install_default_route` is redundant rather than load-bearing.
//!
//! The production install path is `/usr/local/libexec/sandboxd/` per
//! FHS § 4.7 (libexec is for non-user-facing helper binaries).
//!
//! Under setcap, the helper retains the capabilities across `exec`
//! without running as root, so the only operations *this binary* performs
//! with elevated privilege are namespace entry and route install —
//! everything else (config read, authorization) runs with the invoking
//! user's uid, and the capability set granted here contains no DAC bypass,
//! so the `users.conf` read is subject to that user's own file permissions.
//! Other privileged surfaces exist elsewhere in the stack — the setuid pivot
//! in `sandbox-lima-helper`, the passwordless `sudo` inside the gateway VM —
//! and nothing here constrains them.
//!
//! # Stderr / exit-code contract
//!
//! All deny paths use a single exit code `1`. The reason text on stderr
//! is the load-bearing signal for both operators and the integration
//! tests; assertions key on substrings of the messages emitted here.

#[cfg(target_os = "linux")]
mod audit;
#[cfg(target_os = "linux")]
mod pair_check;

// Deliberately not gated to Linux, unlike its three neighbours. The module is
// pure `std` and holds the decision the in-VM route install turns on; keeping
// it off the platform gate is what lets its test table run on a macOS
// development host, where the rest of this crate stops at a stub. A control
// whose tests only run on the deployment platform is a control that gets
// reviewed by reading.
mod containment;

#[cfg(target_os = "linux")]
mod imp {
    use std::ffi::OsString;
    use std::net::Ipv4Addr;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::process::{Command, ExitCode};

    use nix::errno::Errno;
    use nix::ifaddrs::getifaddrs;
    use nix::sched::{CloneFlags, setns};
    use nix::unistd::{Uid, User};
    use sandbox_core::users_conf::{SubnetEntry, load_users_config_route_helper};

    use super::audit::{AuditOutcome, AuditRecord, Decision};
    use super::pair_check::{Verdict, pair_check};

    /// Fault-injection env var for the `Err(non-ENOENT)` arms of
    /// `User::from_uid` / `User::from_name`. Honored only in
    /// `test-env-override` builds (privilege story: a cap'd binary that let
    /// an attacker steer libc errors via env would be a step backwards from
    /// the production hardening).
    ///
    /// Format: `<site>:<errno>` where `<site>` is `caller_uid` (targets the
    /// `User::from_uid` lookup) or `for_user` (targets the `User::from_name`
    /// lookup), and `<errno>` is the base-10 integer errno value to return.
    /// Unparseable values are treated as "no injection".
    ///
    /// `getpwuid_r` / `getpwnam_r` can legitimately return errnos other
    /// than `ENOENT` under environment conditions (NSS service down,
    /// `EIO`, `EINTR`, `ENOMEM`, ...) that cannot be reproduced
    /// deterministically in a hermetic test. This env var is the seam that
    /// lets the integration tests cover the `caller-uid-resolution-error`
    /// and `for-user-resolution-error` audit branches independently.
    #[cfg(feature = "test-env-override")]
    pub(super) const SANDBOX_ROUTE_HELPER_TEST_INJECT_USER_RESOLUTION_ERROR_ENV: &str =
        "SANDBOX_ROUTE_HELPER_TEST_INJECT_USER_RESOLUTION_ERROR";

    /// Which site the injected errno targets.
    #[cfg(feature = "test-env-override")]
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum InjectionSite {
        CallerUid,
        ForUser,
    }

    /// Parse the env-var value `"<site>:<errno>"` and return the injected
    /// errno iff `site` matches `want`. Returns `None` in production builds
    /// unconditionally.
    #[cfg(feature = "test-env-override")]
    pub(super) fn injected_user_resolution_errno(want: InjectionSite) -> Option<Errno> {
        let raw = std::env::var(SANDBOX_ROUTE_HELPER_TEST_INJECT_USER_RESOLUTION_ERROR_ENV).ok()?;
        let (site, errno_str) = raw.split_once(':')?;
        let parsed_site = match site {
            "caller_uid" => InjectionSite::CallerUid,
            "for_user" => InjectionSite::ForUser,
            _ => return None,
        };
        if parsed_site != want {
            return None;
        }
        errno_str.parse::<i32>().ok().map(Errno::from_raw)
    }
    #[cfg(not(feature = "test-env-override"))]
    #[derive(Clone, Copy)]
    pub(super) enum InjectionSite {
        CallerUid,
        ForUser,
    }
    #[cfg(not(feature = "test-env-override"))]
    pub(super) fn injected_user_resolution_errno(_want: InjectionSite) -> Option<Errno> {
        None
    }

    /// `User::from_uid` with the `test-env-override` fault-injection seam.
    /// Production builds inline to a direct call.
    fn resolve_user_from_uid(uid: Uid) -> Result<Option<User>, Errno> {
        if let Some(errno) = injected_user_resolution_errno(InjectionSite::CallerUid) {
            return Err(errno);
        }
        User::from_uid(uid)
    }

    /// `User::from_name` with the `test-env-override` fault-injection seam.
    /// Production builds inline to a direct call.
    fn resolve_user_from_name(name: &str) -> Result<Option<User>, Errno> {
        if let Some(errno) = injected_user_resolution_errno(InjectionSite::ForUser) {
            return Err(errno);
        }
        User::from_name(name)
    }

    /// Single deny exit code per the design — the stderr reason carries the
    /// "what went wrong" payload, distinct codes per step would only
    /// invite scripts to grow ad-hoc dependencies on internal step
    /// numbering.
    const DENY_EXIT: u8 = 1;

    /// Render the pool field for an audit record.
    /// CIDR string form (e.g. `"10.209.0.0/20"`).
    fn pool_string(subnet: &SubnetEntry) -> String {
        format!("{}/{}", subnet.cidr.base(), subnet.cidr.prefix_len())
    }

    /// Emit an audit record: resolve the log path, append one line, hand back
    /// whether that worked.
    ///
    /// Nothing about the decision is branched on here — an allow and a deny
    /// take the identical path through this function. The per-decision
    /// asymmetry lives in the two callers below, [`deny_with_audit`] and
    /// [`allow_audit`], and even there it is not a branch on the write
    /// outcome: both report a failed write with the same stderr line, and what
    /// differs is only the exit each was already returning. A write failure
    /// therefore never changes a verdict, in either direction.
    ///
    /// The failure comes back as a value rather than as an `exit()` inside the
    /// audit module, which is what keeps the exit shape in this file.
    fn emit_audit(record: &AuditRecord<'_>) -> AuditOutcome {
        let path = super::audit::audit_log_path();
        super::audit::write_record(&path, record)
    }

    /// Deny path: write the audit-deny record (with stderr escalation
    /// if the write fails), print the stderr reason, and return
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
            // Deny-path escalation: shows the operator that the audit record is missing.
            // The deny itself is unconditional (the exit code below stays `DENY_EXIT`);
            // the escalation only adds the operator-visible signal that the audit trail
            // evaporated.
            eprintln!("sandbox-route-helper: audit log write failed: {err}");
        }
        ExitCode::from(DENY_EXIT)
    }

    /// Allow-path post-success audit. A failed write is reported on stderr
    /// but DOES NOT block the allow — the route is already installed by the
    /// time this runs, so there is nothing left to withhold
    /// (routing-path-availability wins).
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

    /// In-VM degenerate route install: used when the helper runs inside the
    /// `sandboxd-gateway` Lima VM via `sudo … --vm-gateway-mode`.
    ///
    /// Authorization gate: the caller must be root (uid 0). On the host that
    /// is what stops an unprivileged operator from taking this branch to skip
    /// the `users.conf` gate. Inside the VM it is the whole of what this mode
    /// establishes, and it does not establish that the daemon asked — sudo
    /// here is passwordless, so any account reaches uid 0 and invokes the
    /// installed binary directly, arriving indistinguishable from the
    /// daemon's own invocation. No `users.conf`, no pair-membership check.
    ///
    /// The checks that do bind such a caller are the two address checks below,
    /// made after `pidfd_open` + `setns`, and they answer different questions.
    /// `enforce_netns_addresses_private` constrains the *container's*
    /// addresses: every IPv4 address the kernel reports on a non-`lo`
    /// interface must be RFC 1918, there being no pool CIDR here to check them
    /// against. Other address families — IPv6, and the link-layer entries
    /// `getifaddrs` also returns — are skipped rather than judged, matching
    /// the IPv4-only route this path exists to install.
    /// `containment::gateway_is_on_an_observed_subnet` constrains the
    /// *argument*, from what the namespace reports about itself. The condition
    /// it applies, and how much that condition establishes, belong to that
    /// module and are read there rather than summarised here: a summary is a
    /// second statement of the rules with nothing to keep it honest. Neither
    /// check implies the other, and neither identifies the session's assigned
    /// gateway.
    fn run_vm_gateway_mode(container_pid: i32, gateway_ip: Ipv4Addr) -> ExitCode {
        use nix::unistd::Uid;

        // Gate: caller must be root (uid 0). Two different things depending on
        // where the caller sits. On the host this is the check that keeps
        // `--vm-gateway-mode` from being a users.conf bypass: the installed
        // binary is cap'd and exec-able by any operator, and without this they
        // could take this branch and skip steps 2–4 outright. Inside the VM it
        // is a floor and not the thing that makes the install safe — sudo here
        // is passwordless, so every account already clears it.
        let caller_uid = Uid::current();
        if caller_uid.as_raw() != 0 {
            eprintln!(
                "sandbox-route-helper: --vm-gateway-mode requires root (uid 0); \
                 caller is uid {}",
                caller_uid.as_raw()
            );
            return ExitCode::from(DENY_EXIT);
        }

        // pidfd_open + setns — the same handle the standard flow's step 5 uses;
        // see the comment there for what that choice does and does not close.
        let pidfd = match pidfd_open(container_pid) {
            Ok(fd) => fd,
            Err(errno) => {
                eprintln!(
                    "sandbox-route-helper: {}",
                    format_pidfd_error(container_pid, errno)
                );
                return ExitCode::from(DENY_EXIT);
            }
        };
        if let Err(err) = setns(&pidfd, CloneFlags::CLONE_NEWNET) {
            drop_pidfd(pidfd);
            eprintln!("sandbox-route-helper: setns failed: {err}");
            return ExitCode::from(DENY_EXIT);
        }

        // Address enforcement: every IPv4 address on a non-loopback interface
        // must be a private (RFC 1918) address. This bounds what addresses the
        // container may have been assigned inside the in-VM Docker network —
        // a rogue address outside private space would suggest the container
        // was given an external address, which must be rejected. It bounds
        // only the IPv4 ones: anything the kernel reports in another family is
        // skipped, so a public IPv6 address in this namespace is not what this
        // refuses. See `enforce_netns_addresses_private`.
        if let Err(msg) = enforce_netns_addresses_private() {
            eprintln!("sandbox-route-helper: {msg}");
            return ExitCode::from(DENY_EXIT);
        }

        // Subnet containment: the gateway address must be consistent with what
        // this namespace says about itself.
        //
        // This is the only check on this path that constrains the *argument*
        // rather than the environment, and the only argument-constraining one
        // that survives the caller that matters. Everything upstream — the
        // daemon that built the op, the agent that validated it — is bypassed
        // entirely by a process inside this VM that runs
        // `sudo sandbox-route-helper --vm-gateway-mode` itself. Such a caller
        // supplies the gateway address, so no check made on that address
        // before this point means anything against it.
        //
        // What such a caller does not supply in the *argument* is what the
        // kernel reports for the namespace the helper has just entered. That
        // is the ground truth this uses, and it is why the check is here
        // rather than three layers up. Ground truth is not the same as out of
        // reach, though: root in this VM can shape what a namespace reports by
        // attaching the container to a network whose subnet it chose. This is
        // defence in depth, not a boundary — the `containment` module docs are
        // explicit about which values it does and does not refuse.
        //
        // It runs *after* the setns, deliberately. Before it, `getifaddrs`
        // reports the VM's own addresses and the answer would be about the
        // wrong namespace.
        //
        // Distinct from the enforcement above it, not a stronger version of it:
        // that one constrains the container's own addresses, this one
        // constrains the argument. Neither implies the other — see the
        // `containment` module docs for the case that separates them.
        match collect_netns_addresses() {
            Ok(observed) => {
                if let Err(rejection) =
                    crate::containment::gateway_is_on_an_observed_subnet(&observed, gateway_ip)
                {
                    eprintln!("sandbox-route-helper: {rejection}");
                    return ExitCode::from(DENY_EXIT);
                }
            }
            Err(msg) => {
                eprintln!("sandbox-route-helper: {msg}");
                return ExitCode::from(DENY_EXIT);
            }
        }

        // Install default route.
        if let Err(msg) = install_default_route(gateway_ip) {
            eprintln!("sandbox-route-helper: {msg}");
            return ExitCode::from(DENY_EXIT);
        }

        // No audit record is emitted here — not on this success, and not on
        // any deny above it. The standard host path calls `deny_with_audit` /
        // `allow_audit`, which append JSON-Lines records to
        // `audit::audit_log_path()`: a path derived from the caller's own
        // `XDG_RUNTIME_DIR` or `HOME`, which inside this VM names nothing an
        // operator collects. What is left is external to the helper: the
        // daemon's tracing at the limactl-shell call site that asked for the
        // install, and the VM's journald record of the `sudo` that ran it.
        // Both cover invocations that came through `sudo` from the daemon. A
        // caller already holding root in the VM, invoking this binary
        // directly, appears in neither.
        println!("sandbox-route-helper: route installed for pid {container_pid} via {gateway_ip}");
        ExitCode::SUCCESS
    }

    /// Verify that every IPv4 address on every non-`lo` interface inside
    /// the (already-entered) netns is a private RFC 1918 address.
    ///
    /// Used by the in-VM degenerate path where there is no pool CIDR to
    /// check against. This provides defense-in-depth: a container that
    /// somehow received a publicly-routable IPv4 address cannot have its route
    /// redirected via this helper.
    ///
    /// IPv4 is the whole of its reach, and that is silence rather than
    /// enforcement — the same shape `enforce_netns_addresses_in_subnet` has on
    /// the host path. Entries `getifaddrs` reports in another family are
    /// skipped: an IPv6 address in this namespace is neither validated nor
    /// denied here, publicly routable or not. The route this helper installs
    /// is IPv4-only, so the silence matches the route's scope; it does not
    /// make the namespace an IPv4-only place.
    fn enforce_netns_addresses_private() -> Result<(), String> {
        let iter = getifaddrs().map_err(|err| format!("getifaddrs failed: {err}"))?;
        for ifaddr in iter {
            if ifaddr.interface_name == "lo" {
                continue;
            }
            let Some(addr) = ifaddr.address else {
                continue;
            };
            let Some(sock) = addr.as_sockaddr_in() else {
                continue;
            };
            let ip = sock.ip();
            // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. Shared with the
            // containment check below rather than spelled out twice: two
            // definitions of "private" in one binary is two things to keep in
            // agreement, and this one has no reason to differ.
            if !crate::containment::is_rfc1918(ip) {
                return Err(format!(
                    "netns address {} on {} is not a private RFC 1918 address; \
                     refusing route install",
                    ip, ifaddr.interface_name,
                ));
            }
        }
        Ok(())
    }

    /// Read every IPv4 address and netmask the kernel reports on a non-`lo`
    /// interface in the (already-entered) netns.
    ///
    /// The impure half of the containment check, and deliberately the whole of
    /// it: this function decides nothing. It walks `getifaddrs`, narrows each
    /// entry to an IPv4 address-and-mask pair, and hands the result to
    /// [`crate::containment::gateway_is_on_an_observed_subnet`]. Keeping the
    /// judgement out of here is what makes the judgement testable without a
    /// namespace to enter.
    ///
    /// Entries without an address, without a netmask, or in another address
    /// family are skipped. A skipped entry is not evidence *for* anything —
    /// the decision function fails closed when it ends up with nothing.
    fn collect_netns_addresses() -> Result<Vec<crate::containment::NetnsAddr>, String> {
        let iter = getifaddrs().map_err(|err| format!("getifaddrs failed: {err}"))?;
        let mut observed = Vec::new();
        for ifaddr in iter {
            if ifaddr.interface_name == "lo" {
                continue;
            }
            let (Some(addr), Some(mask)) = (ifaddr.address, ifaddr.netmask) else {
                continue;
            };
            let (Some(addr_in), Some(mask_in)) = (addr.as_sockaddr_in(), mask.as_sockaddr_in())
            else {
                continue;
            };
            observed.push(crate::containment::NetnsAddr::new(
                addr_in.ip(),
                mask_in.ip(),
            ));
        }
        Ok(observed)
    }

    /// Top-level orchestration. Each branch of the standard flow decides
    /// allow / deny and attempts an audit record before returning the
    /// `ExitCode`; the argv-parse branch below and the whole
    /// `--vm-gateway-mode` path attempt none.
    ///
    /// Denying is not the same as having touched nothing. Four deny branches
    /// sit at or after the namespace entry in step 5, and they differ in what
    /// they leave behind:
    ///
    /// - `pidfd-open-failed` and `setns-failed` — the namespace was never
    ///   entered; the helper is still in its own.
    /// - `netns-address-outside-subnet` — entered, but only read from:
    ///   `getifaddrs` is the only thing that ran in there.
    /// - `route-install-failed` — entered, and how much further it got depends
    ///   on which part of the install failed. If no `ip(8)` was found at a
    ///   pinned path, if a capability raise was refused, or if the spawn never
    ///   started, nothing ran in there. The remaining case — `ip` itself
    ///   exiting non-zero — means `CAP_NET_ADMIN` *was* raised into the
    ///   ambient set and a privileged child *did* run inside the container's
    ///   netns. This is the only deny branch that can have done so.
    ///
    /// What no deny branch does is report success. The allow audit record and
    /// the exit-0 confirmation are both downstream of `install_default_route`
    /// returning `Ok`, which it does only after `ip` exited zero.
    pub fn run() -> ExitCode {
        // Step 1 — argv parse. Syntax only: nothing here resolves a name or
        // reads a config, which is why the failure arm below has no identities
        // to name.
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
            vm_gateway_mode,
        } = parsed;
        let gateway_ip_str = gateway_ip.to_string();

        // In-VM degenerate path: the standard gate has nothing to work with.
        //
        // This path is taken when the helper is invoked inside the
        // `sandboxd-gateway` Lima VM via `limactl shell … sudo <helper>
        // --vm-gateway-mode <pid> <gw_ip>`. The standard host-uid +
        // pair-membership gate cannot apply here because (a) the caller the
        // helper sees is root (uid 0, via sudo), the same uid whichever
        // process asked, and (b) there is no `users.conf` in the VM to
        // resolve a pool from.
        //
        // What the host side does provide is that driving `limactl` against
        // this instance means being the daemon (`_sandboxd`, running on the
        // macOS host) or root: the gateway lives in the daemon's own
        // LIMA_HOME, not in any operator's, and the SSH key there is owned by
        // the daemon uid. What it does not provide — and what this branch
        // must not be read as enforcing — is anything about a caller that
        // starts inside the VM. Sudo there is passwordless and, on the lite
        // path, the sandbox containers run in this same VM; such a caller
        // invokes the installed binary directly with the same uid 0 the
        // daemon's invocation carries, and no check made before this point
        // applies to it. The checks that do apply to it are the ones
        // `run_vm_gateway_mode` makes after entering the namespace.
        //
        // The root check it starts with does its real work on the host, where
        // it stops an unprivileged operator taking this branch to skip the
        // pair-membership gate. In the VM it is a floor: it rejects a process
        // that cannot reach root at all, and every account there can.
        if vm_gateway_mode {
            return run_vm_gateway_mode(container_pid, gateway_ip);
        }

        // Step 2, first half — caller identity. STRICT resolution —
        // unresolvable uid is a deny path, not a stderr-clarity hint. The
        // pair-check below needs both identities reliably; falling back to
        // numeric-only comparison would allow a request whose `for_user`
        // resolves to the same uid as `caller` (e.g. via NSS misconfig) to
        // sneak through pair-check on a name-mismatch.
        let caller_uid = Uid::current();
        let caller_name = match resolve_user_from_uid(caller_uid) {
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

        // `--for-user` defaults to the caller's name when omitted,
        // so direct-CLI helper invocations remain meaningful.
        let for_user = for_user_arg.unwrap_or_else(|| caller_name.clone());

        // Step 2, second half — resolve `--for-user` to a uid strictly. An
        // unresolvable for-user name is a deny path.
        let for_user_uid = match resolve_user_from_name(&for_user) {
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

        // Step 4 — pair-membership check per the membership check. Both caller
        // and for-user uids must appear in the pool's `allow_users` (each
        // resolved numerically via `SubnetEntry::allows_uid`). On mismatch,
        // exit DENY_EXIT with stderr naming both identities.
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

        // Step 5 — pidfd_open + setns(CLONE_NEWNET). pidfd_open binds to the
        // *thread-group leader* that holds container_pid at open time, so a
        // pid recycled after the open cannot redirect the setns target: the
        // setns fails with ESRCH instead. That is a property of the handle,
        // not an edge over /proc/<pid>/ns/net, whose nsfs fd pins its
        // namespace equally well. Both resolve container_pid right here, and
        // the window between the daemon reading that pid and this call is
        // closed by neither. See crate-level step 5.
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
        // inside the subnet the gateway IP was matched to in step 3. A single
        // outside-subnet address denies: that is what stops a route being
        // installed across pool boundaries. Two users listed in the same
        // pool's `allow_users` are not separated by it.
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
    /// the caller defaults it to `name(getuid())` and defaults to the caller username, which
    /// preserves the pre-existing direct-CLI invocation shape.
    /// `vm_gateway_mode` is `true` when `--vm-gateway-mode` was present.
    // pub(super) so unit tests in tests::parse_argv_tests can call parse_argv directly.
    // Debug so those tests can use `expect_err` on a `Result<ParsedArgs, _>`;
    // without it the crate's test binary does not compile on Linux, which is
    // the only platform where `imp` — and every test that reaches into it —
    // exists at all.
    #[derive(Debug)]
    pub(super) struct ParsedArgs {
        pub(super) container_pid: i32,
        pub(super) gateway_ip: Ipv4Addr,
        pub(super) for_user_arg: Option<String>,
        /// When `true`, the degenerate in-VM authorization path is active.
        /// See the crate-level "In-VM authorization" doc comment.
        pub(super) vm_gateway_mode: bool,
    }

    /// Parse argv: optional flags before the two positional args.
    /// `argv[0]` is the program name.
    ///
    /// Exposed as `pub(super)` so the `tests::parse_argv_tests` module can call it
    /// directly to pin the parsing contract without exec'ing a process.
    ///
    /// Accepted flags (mutually exclusive):
    /// - `--for-user <name>` / `--for-user=<name>`: standard operator identity
    ///   for the host pair-membership check. Not compatible with
    ///   `--vm-gateway-mode`.
    /// - `--vm-gateway-mode`: activates the degenerate in-VM authorization
    ///   path. Incompatible with `--for-user`.
    ///
    /// Hand-rolled — pulling `clap` into the cap'd helper would inflate the
    /// TCB by several thousand lines that have to be reviewed for the privilege
    /// story. The flag accepts both `--for-user <name>` (two-arg form) and
    /// `--for-user=<name>` (one-arg form); both shapes show up in practice.
    pub(super) fn parse_argv(args: &[OsString]) -> Result<ParsedArgs, String> {
        const USAGE: &str = "usage: sandbox-route-helper [--for-user <name>] <container_pid> <gateway_ip>\n\
             usage: sandbox-route-helper --vm-gateway-mode <container_pid> <gateway_ip>";

        // Walk argv left-to-right, consuming recognized flags where
        // they appear. Anything that is not a flag is a positional.
        let mut for_user_arg: Option<String> = None;
        let mut vm_gateway_mode = false;
        let mut positionals: Vec<&OsString> = Vec::with_capacity(2);

        // argv[0] is the program name; skip it.
        let mut iter = args.iter().enumerate().skip(1).peekable();
        let mut accepting_flags = true;

        while let Some((_idx, arg)) = iter.next() {
            let arg_str = arg.to_string_lossy();
            if accepting_flags && arg_str == "--for-user" {
                // Two-argument form: --for-user NAME
                if vm_gateway_mode {
                    return Err(format!(
                        "{USAGE} (--for-user and --vm-gateway-mode are mutually exclusive)"
                    ));
                }
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
                if vm_gateway_mode {
                    return Err(format!(
                        "{USAGE} (--for-user and --vm-gateway-mode are mutually exclusive)"
                    ));
                }
                if for_user_arg.is_some() {
                    return Err(format!("{USAGE} (--for-user specified more than once)"));
                }
                if rest.is_empty() {
                    return Err(format!("{USAGE} (--for-user value must be non-empty)"));
                }
                for_user_arg = Some(rest.to_string());
            } else if accepting_flags && arg_str == "--vm-gateway-mode" {
                // In-VM degenerate authorization path. Mutually exclusive
                // with --for-user: this mode skips the pair-membership check
                // that `--for-user` feeds, so accepting both would let argv
                // name a second identity that nothing then reads.
                if for_user_arg.is_some() {
                    return Err(format!(
                        "{USAGE} (--for-user and --vm-gateway-mode are mutually exclusive)"
                    ));
                }
                if vm_gateway_mode {
                    return Err(format!(
                        "{USAGE} (--vm-gateway-mode specified more than once)"
                    ));
                }
                vm_gateway_mode = true;
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
            vm_gateway_mode,
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
        let fd = i32::try_from(raw).expect(
            "pidfd_open returned a non-negative fd; kernel-allocated fd numbers fit in i32",
        );
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Render a `pidfd_open` errno into the helper's stderr phrasing.
    /// ESRCH gets the dedicated "not found" message that the design calls
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
    /// the (already-entered) netns falls inside the subnet the gateway IP was
    /// matched to in step 3.
    ///
    /// IPv6 addresses are ignored, and that is silence rather than
    /// enforcement: an IPv6 address inside the netns is neither validated nor
    /// denied here. The route this helper installs is IPv4-only, so the
    /// silence matches the route's scope. Interfaces without an address (e.g.
    /// an unconfigured `eth0` that hasn't yet had an IP assigned) are skipped
    /// — they have no address to validate.
    ///
    /// An interface count of zero non-lo entries trivially passes, unlike the
    /// in-VM containment check, which treats empty evidence as a deny. The
    /// asymmetry is deliberate: a vacuous pass here reaches a step-7 `ip route
    /// replace` with no interface the nexthop is reachable through, which the
    /// kernel rejects — so no route results either way, and the kernel's error
    /// is the more useful surface for that misconfiguration.
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

    /// Absolute paths this helper will run `ip(8)` from, tried in order.
    ///
    /// Absolute rather than a bare program name because the child is exec'd
    /// with `CAP_NET_ADMIN` in its ambient set: a bare name is resolved
    /// through the caller's `PATH`, which would let whoever invoked the helper
    /// choose the binary that receives it. An absolute path moves that choice
    /// to whoever can write the named directory, and it is the *directory*
    /// that carries the argument — not the shape of the entry inside it. An
    /// entry here may be a regular file or a symlink, and either way replacing
    /// what the path resolves to means writing `/sbin`, `/usr/sbin`,
    /// `/usr/bin` or `/bin` (or, for a symlink, whatever directory it lands
    /// in). That is a property of the host rather than something this code can
    /// enforce, but a host on which a non-root user can write those has lost
    /// more than this already.
    ///
    /// A list rather than one literal because `ip(8)`'s absolute path is not
    /// the same everywhere the helper runs. All four exist and resolve to one
    /// file on the Ubuntu 24.04 host this was checked against — the gateway
    /// VM's distribution — while layouts carrying only some of them are the
    /// reason the lookup walks a list. Order matters only where two entries
    /// are different files, in which case the `sbin` copy wins.
    // pub(super) so `tests::ip_binary_tests` can pin the list's shape.
    pub(super) const IP_BINARY_CANDIDATES: &[&str] =
        &["/sbin/ip", "/usr/sbin/ip", "/usr/bin/ip", "/bin/ip"];

    /// The whole environment the `ip(8)` child is given.
    ///
    /// A fixed value rather than nothing at all, so that an `ip` which is a
    /// wrapper script still finds what it calls. Nothing in it comes from the
    /// caller.
    pub(super) const IP_CHILD_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

    /// Whether `path` is a regular file the helper may execute.
    ///
    /// Two questions rather than one, because neither alone answers it. A
    /// directory is searchable and so passes `access(X_OK)` while `execve`
    /// refuses it; a regular file with no execute bit passes an
    /// is-it-a-regular-file test while `execve` refuses that. Both follow
    /// symlinks, which two of [`IP_BINARY_CANDIDATES`] are on the Ubuntu 24.04
    /// image the gateway VM runs.
    ///
    /// `access(2)` answers for the real uid, and that is the uid the child
    /// will be exec'd as: the helper is setcap rather than setuid, so its real
    /// and effective uids are both the caller's, and none of the three
    /// capabilities it carries bypasses a DAC check.
    ///
    /// What this pair is not is a guarantee that the exec will work — a
    /// candidate can change under it, and a wrapper script with a missing
    /// interpreter fails later still. Its job is narrower: keep an unusable
    /// candidate from ending the search.
    fn is_regular_executable_file(path: &str) -> bool {
        if !std::path::Path::new(path).is_file() {
            return false;
        }
        let Ok(c_path) = std::ffi::CString::new(path) else {
            return false;
        };
        // SAFETY: `c_path` is a NUL-terminated C string that outlives the
        // call; `access` only reads it and returns 0 or -1.
        unsafe { libc::access(c_path.as_ptr(), libc::X_OK) == 0 }
    }

    /// The first entry of [`IP_BINARY_CANDIDATES`] that is a regular file the
    /// helper can execute, or an error.
    ///
    /// The walk **continues past a candidate it cannot use**, and that is the
    /// load-bearing part rather than the strictness of the test: a candidate
    /// that exists as a directory, as a device node, or as a regular file
    /// without the execute bit is skipped, so an unusable entry early in the
    /// list cannot shadow a working one later in it. That is not an abstract
    /// concern for this list, whose first entry is `/sbin/ip` and whose third
    /// is `/usr/bin/ip`: with a non-executable regular file at the former and
    /// a working binary at the latter, a walk that stopped at the first entry
    /// which merely exists selects `/sbin/ip`, and the helper dies at the
    /// spawn with no route installed. "It would only move the failure to
    /// `execve`" is the reasoning that licenses stopping there, and it is
    /// wrong exactly when a later candidate would have worked.
    ///
    /// Fails closed: there is deliberately no bare-name fallback, because a
    /// fallback would reinstate the `PATH` lookup on exactly the hosts where
    /// the pinned paths did not resolve. The list is therefore a closed set,
    /// and a host that keeps `ip(8)` outside it — a Nix-style store path, say
    /// — gets a named deny rather than a route, which is the safe direction to
    /// fail in but is better read here than discovered at install time.
    pub(super) fn resolve_ip_binary() -> Result<&'static str, String> {
        IP_BINARY_CANDIDATES
            .iter()
            .copied()
            .find(|candidate| is_regular_executable_file(candidate))
            .ok_or_else(|| {
                format!(
                    "no executable ip(8) at any of {}; refusing to resolve it through PATH",
                    IP_BINARY_CANDIDATES.join(", ")
                )
            })
    }

    /// `ip route replace default via <gateway_ip>` inside the (already-
    /// entered) netns. We let `ip(8)`'s own stderr surface to the user on
    /// failure rather than re-formatting it.
    ///
    /// Before exec we raise `CAP_NET_ADMIN` to the ambient set so the
    /// `ip(8)` child inherits permitted+effective `CAP_NET_ADMIN` and can
    /// issue `RTM_NEWROUTE`. The file caps
    /// `cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip`
    /// place `CAP_NET_ADMIN` in the file's permitted+inheritable+effective
    /// sets, but on exec a process's *thread* inheritable set is taken from
    /// the parent — which is the unprivileged caller, so inheritable is
    /// empty after exec. `PR_CAP_AMBIENT_RAISE` requires the cap in both
    /// permitted AND inheritable, so we first promote permitted →
    /// inheritable, then inheritable → ambient.
    ///
    /// Note what the child is, because the caller does not get to say: the
    /// program is [`resolve_ip_binary`]'s pick from a fixed list of absolute
    /// paths, and it runs with the caller's environment discarded and
    /// [`IP_CHILD_PATH`] in its place. If no candidate resolves the helper
    /// denies instead of installing a route — and the lookup runs before
    /// either raise below, so that denial happens without `CAP_NET_ADMIN`
    /// having been put anywhere new.
    ///
    /// One residual is a property of the mechanism rather than of the lookup,
    /// and pinning the path does not touch it: the kernel clears the ambient
    /// set across an `execve` of a file that itself carries file
    /// capabilities. Were the resolved `ip` such a file, the child would start
    /// without `CAP_NET_ADMIN` and the install would fail — visibly, as a
    /// non-zero exit, not silently. `getcap` reports no file capabilities on
    /// the Ubuntu 24.04 `ip` this was checked against.
    fn install_default_route(gateway_ip: Ipv4Addr) -> Result<(), String> {
        let ip_binary = resolve_ip_binary()?;

        caps::raise(
            None,
            caps::CapSet::Inheritable,
            caps::Capability::CAP_NET_ADMIN,
        )
        .map_err(|err| format!("raise CAP_NET_ADMIN to inheritable: {err}"))?;
        caps::raise(None, caps::CapSet::Ambient, caps::Capability::CAP_NET_ADMIN)
            .map_err(|err| format!("raise CAP_NET_ADMIN to ambient: {err}"))?;

        let status = Command::new(ip_binary)
            .args([
                "route",
                "replace",
                "default",
                "via",
                &gateway_ip.to_string(),
            ])
            .env_clear()
            .env("PATH", IP_CHILD_PATH)
            .status()
            .map_err(|err| format!("failed to spawn {ip_binary}: {err}"))?;
        if !status.success() {
            return Err(format!(
                "ip route replace failed: exit {}",
                status.code().unwrap_or(-1)
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    imp::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("error: this binary runs on Linux only");
    std::process::exit(2);
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
    //! what gets `cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip` applied
    //! at install time, and that build must not honor the env var even if
    //! some upstream code sets it.
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

    // ---------------------------------------------------------------------------
    // Argv-parse tests for --vm-gateway-mode
    // ---------------------------------------------------------------------------

    /// These tests drive `imp::parse_argv` directly (Linux-cfg'd module).
    /// They run on Linux only (where the imp module is compiled).
    #[cfg(target_os = "linux")]
    mod parse_argv_tests {
        use std::ffi::OsString;

        fn argv(args: &[&str]) -> Vec<OsString> {
            let mut v: Vec<OsString> = vec!["sandbox-route-helper".into()];
            v.extend(args.iter().map(|&s| OsString::from(s)));
            v
        }

        #[test]
        fn vm_gateway_mode_flag_sets_mode() {
            let parsed =
                super::super::imp::parse_argv(&argv(&["--vm-gateway-mode", "1234", "10.0.0.1"]))
                    .expect("parse must succeed");
            assert!(
                parsed.vm_gateway_mode,
                "vm_gateway_mode must be true when flag is present"
            );
            assert_eq!(parsed.container_pid, 1234);
            assert_eq!(
                parsed.gateway_ip,
                "10.0.0.1"
                    .parse::<std::net::Ipv4Addr>()
                    .expect("literal is an IPv4")
            );
            assert!(
                parsed.for_user_arg.is_none(),
                "for_user_arg must be None in vm_gateway_mode"
            );
        }

        #[test]
        fn standard_form_no_vm_gateway_mode() {
            let parsed = super::super::imp::parse_argv(&argv(&["1234", "10.0.0.1"]))
                .expect("parse must succeed");
            assert!(
                !parsed.vm_gateway_mode,
                "vm_gateway_mode must be false when flag is absent"
            );
            assert_eq!(parsed.container_pid, 1234);
        }

        #[test]
        fn vm_gateway_mode_and_for_user_are_mutually_exclusive() {
            // --vm-gateway-mode before --for-user
            let err = super::super::imp::parse_argv(&argv(&[
                "--vm-gateway-mode",
                "--for-user",
                "alice",
                "1",
                "10.0.0.1",
            ]))
            .expect_err("must fail when both flags are present");
            assert!(
                err.contains("mutually exclusive"),
                "error must mention mutual exclusivity: {err}"
            );

            // --for-user before --vm-gateway-mode
            let err2 = super::super::imp::parse_argv(&argv(&[
                "--for-user",
                "alice",
                "--vm-gateway-mode",
                "1",
                "10.0.0.1",
            ]))
            .expect_err("must fail when both flags are present");
            assert!(
                err2.contains("mutually exclusive"),
                "error must mention mutual exclusivity: {err2}"
            );
        }

        #[test]
        fn vm_gateway_mode_duplicate_rejected() {
            let err = super::super::imp::parse_argv(&argv(&[
                "--vm-gateway-mode",
                "--vm-gateway-mode",
                "1",
                "10.0.0.1",
            ]))
            .expect_err("duplicate --vm-gateway-mode must fail");
            assert!(
                err.contains("more than once"),
                "error must mention duplicate: {err}"
            );
        }

        #[test]
        fn for_user_flag_does_not_set_vm_gateway_mode() {
            let parsed =
                super::super::imp::parse_argv(&argv(&["--for-user", "alice", "1", "10.0.0.1"]))
                    .expect("parse must succeed");
            assert!(!parsed.vm_gateway_mode);
            assert_eq!(parsed.for_user_arg.as_deref(), Some("alice"));
        }
    }

    // ---------------------------------------------------------------------------
    // How `ip(8)` is located for the privileged exec
    // ---------------------------------------------------------------------------

    /// The `ip(8)` the helper runs is exec'd with `CAP_NET_ADMIN` in its
    /// ambient set. A program *name* is resolved through the caller's `PATH`,
    /// which makes the caller the one who picks that binary; these tests pin
    /// the shape that keeps them from doing so.
    ///
    /// Linux-only because the lookup lives in the Linux-cfg'd `imp` module.
    #[cfg(target_os = "linux")]
    mod ip_binary_tests {
        use super::super::imp::{IP_BINARY_CANDIDATES, IP_CHILD_PATH, resolve_ip_binary};
        use std::path::{Component, Path};

        #[test]
        fn every_candidate_is_an_absolute_path() {
            // Each entry has to name the `ip` program, and the list has to
            // have entries: a candidate that is some other binary would be
            // exec'd with `CAP_NET_ADMIN` in its ambient set, and an empty
            // list denies every route install. The count is taken from the
            // values rather than asked of the constant — `!CONST.is_empty()`
            // is decided by the compiler, so it reports a check it is not
            // making.
            let naming_ip = IP_BINARY_CANDIDATES
                .iter()
                .filter(|candidate| candidate.ends_with("/ip"))
                .count();
            assert_eq!(
                naming_ip,
                IP_BINARY_CANDIDATES.len(),
                "every candidate must name the ip(8) program: {IP_BINARY_CANDIDATES:?}"
            );
            assert!(
                naming_ip > 0,
                "an empty list would deny every route install"
            );
            for candidate in IP_BINARY_CANDIDATES {
                let path = Path::new(candidate);
                assert!(
                    path.is_absolute(),
                    "{candidate} is not absolute; a relative or bare name is \
                     resolved through the caller's PATH"
                );
                assert!(
                    !path.components().any(|c| c == Component::ParentDir),
                    "{candidate} contains a `..` component"
                );
            }
        }

        /// Two answers, never three: the lookup names one of the pinned paths
        /// or it denies. A bare-name fallback is the hole this closes.
        #[test]
        fn resolution_either_names_a_pinned_path_or_denies() {
            match resolve_ip_binary() {
                Ok(found) => assert!(
                    IP_BINARY_CANDIDATES.contains(&found),
                    "resolved {found}, which is not one of the pinned paths"
                ),
                Err(msg) => assert!(
                    msg.contains("PATH"),
                    "the deny reason must say the helper will not fall back to \
                     PATH, since that is what an operator has to understand: {msg}"
                ),
            }
        }

        /// The child's whole environment is this constant. Every entry is an
        /// absolute directory, so nothing in it is resolved relative to a
        /// working directory the caller chose.
        ///
        /// The loop below is the whole test, emptiness included: `"".split(':')`
        /// yields one entry, the empty string, and `Path::new("")` is not
        /// absolute — so an emptied constant fails here rather than passing
        /// vacuously. The separate `!IP_CHILD_PATH.is_empty()` this replaced
        /// added nothing the loop does not already do, and being a check on a
        /// constant it was decided by the compiler either way.
        #[test]
        fn the_child_environment_is_a_constant_of_absolute_directories() {
            for dir in IP_CHILD_PATH.split(':') {
                assert!(
                    Path::new(dir).is_absolute(),
                    "{dir} in the child PATH is not absolute"
                );
            }
        }
    }
}
