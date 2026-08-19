//! Provisioning `sandbox-route-helper` inside the gateway VM — probe it, stage
//! it, install it, give it its capabilities — and the one invocation of it.
//!
//! Most of this module is about getting the binary *into* the VM.
//! [`install_container_route_argv`] is the other thing: it runs the installed
//! binary. That step is different in kind from the four around it, and the
//! difference is worth stating rather than leaving to be inferred.
//!
//! The provisioning steps put a file somewhere and set a bit on it. The
//! invocation reaches into a container's network namespace and rewrites its
//! default route — the single hop through which every packet the sandbox sends
//! must pass. Getting it wrong does not fail loudly; it silently routes the
//! sandbox's egress somewhere other than the policy gateway.
//!
//! What this crate can contribute to that is narrow and worth being precise
//! about. It renders two values into two argv words, and the types of those
//! values (a `u32` pid, an [`Ipv4Addr`]) are the whole of what it guarantees:
//! neither word can carry a flag, a path, or a shell metacharacter. **Whether
//! the gateway address is the right one for that container is not a question
//! this crate can answer** — the answer lives in the namespace being entered,
//! and so the check lives in the helper, after the `setns`, where the kernel
//! can be asked. See `sandbox-route-helper`'s `containment` module.
//!
//! Every privileged step runs `sudo -n`; see the module docs on
//! [`crate::vm`] for why the flag is not decorative.

use std::net::Ipv4Addr;

use crate::owned;

/// Filename of the pre-staged Linux/aarch64 route-helper binary inside the
/// LIMA_HOME of whichever side is running the copy.
///
/// Named rather than passed: the source of a `limactl copy` into a VM with
/// passwordless `sudo` is a binary that will shortly be given
/// `cap_net_admin`. A caller-supplied path would be the whole of the control.
pub const HOST_BINARY_FILENAME: &str = "sandbox-route-helper-linux-aarch64";

/// Directory the helper is installed into inside the VM. Root-owned, which is
/// why the copy cannot land here directly.
pub const INSTALL_DIR_IN_VM: &str = "/usr/local/libexec/sandboxd";

/// Final path of the installed helper inside the VM.
pub const INSTALLED_PATH_IN_VM: &str = "/usr/local/libexec/sandboxd/sandbox-route-helper";

/// Where the copy lands before the privileged install moves it.
///
/// `limactl copy` runs rsync over SSH as the VM's unprivileged login user,
/// which cannot write [`INSTALL_DIR_IN_VM`]. So the transfer targets a path
/// that user owns and a second, privileged step puts it in place.
pub const STAGED_PATH_IN_VM: &str = "/tmp/sandbox-route-helper.staged";

/// The capability set the in-VM `setcap` step asks for.
///
/// Each name answers for an operation the helper performs: `cap_net_admin` to
/// install a route, `cap_sys_admin` to `setns` into a foreign network
/// namespace, `cap_sys_ptrace` because the container's leader runs as a
/// foreign uid and the `pidfd` + `setns` path then meets a cross-uid
/// `ptrace_may_access` check.
///
/// Those are reasons an **unprivileged** caller needs them on the file, and
/// that caller is on the host rather than here. Every invocation this crate
/// builds reaches the installed binary through `sudo -n`, so it starts as root
/// and holds all three whatever the file carries; this `setcap` is not what
/// makes the in-VM route install work.
///
/// What it does do here is give the provisioning probe a subject. The
/// "already provisioned?" answer is computed from this very string — every
/// name in it must appear in [`probe_caps_argv`]'s output — so a binary that
/// was installed with only some of them is not mistaken for a provisioned one.
pub const CAPABILITIES: &str = "cap_net_admin,cap_sys_admin,cap_sys_ptrace=eip";

/// `sudo -n mkdir -p /usr/local/libexec/sandboxd`.
pub fn make_install_dir_argv() -> Vec<String> {
    owned(&["sudo", "-n", "mkdir", "-p", INSTALL_DIR_IN_VM])
}

/// `test -x <installed>` — the first half of the "already provisioned?"
/// question.
///
/// The exit status is the whole answer; nothing here reads output or chains a
/// second command onto it. Whether the guest resolves `test` to its shell
/// builtin or to `/usr/bin/test` is immaterial — the two agree on `-x`, and
/// neither is reached through a command line this crate assembled.
pub fn probe_executable_argv() -> Vec<String> {
    owned(&["test", "-x", INSTALLED_PATH_IN_VM])
}

/// `getcap <installed>` — the second half.
///
/// The output is returned to the caller rather than matched in the VM. The
/// shape this replaced piped it into `grep -q cap_net_admin` — a pipeline,
/// which has to be written as a shell command line to exist at all. Deciding
/// on the calling side needs no pipeline, and puts the decision where the
/// question was asked.
///
/// Checking the capabilities and not merely the executable bit is the point of
/// the probe: a binary whose `setcap` step failed passes `test -x` and then
/// fails at route-install time with `EPERM`, long after anyone is looking.
///
/// What counts as a pass is not decided here and is not a single name: the
/// caller requires every capability [`CAPABILITIES`] asks for, each matched as
/// a whole token in the output. A one-name test would accept a partial
/// `setcap` and skip provisioning, which is the failure the probe exists to
/// catch.
pub fn probe_caps_argv() -> Vec<String> {
    owned(&["getcap", INSTALLED_PATH_IN_VM])
}

/// The privileged install: put the staged copy in place, then drop it.
///
/// Two argv rather than one `&&` chain — the shape this replaced needed a
/// shell for the `&&`. Both must succeed, which is what the chain meant.
pub fn install_argv() -> Vec<Vec<String>> {
    vec![
        owned(&[
            "sudo",
            "-n",
            "install",
            "-m",
            "0755",
            STAGED_PATH_IN_VM,
            INSTALLED_PATH_IN_VM,
        ]),
        remove_staged_argv(),
    ]
}

/// `rm -f <staged>` — unprivileged, because the staging path belongs to the
/// login user that the copy ran as.
pub fn remove_staged_argv() -> Vec<String> {
    owned(&["rm", "-f", STAGED_PATH_IN_VM])
}

/// `sudo -n chmod +x <installed>`.
///
/// Redundant against `install -m 0755` and kept anyway: it is what the
/// sequence did before it was typed, and the cost of a second call is a round
/// trip on a path that runs once per VM lifetime.
pub fn chmod_argv() -> Vec<String> {
    owned(&["sudo", "-n", "chmod", "+x", INSTALLED_PATH_IN_VM])
}

/// `sudo -n setcap '<caps>' <installed>`.
///
/// The quotes in the shell form were shell syntax; as an argv the capability
/// set is one word and needs none.
pub fn setcap_argv() -> Vec<String> {
    owned(&["sudo", "-n", "setcap", CAPABILITIES, INSTALLED_PATH_IN_VM])
}

/// The flag that selects the helper's in-VM authorization mode.
pub const VM_GATEWAY_MODE_FLAG: &str = "--vm-gateway-mode";

/// `sudo -n <installed> --vm-gateway-mode <container_pid> <gateway_ip>` —
/// install a container's default route from inside the gateway VM.
///
/// # Why the types are what they are
///
/// The helper's own parser takes an `i32` pid and an `Ipv4Addr`, and this
/// builder deliberately takes narrower types than that:
///
/// - `container_pid: u32` cannot render a leading `-`, so the word this
///   produces can never be mistaken for a flag by the parser on the far end.
///   With an `i32` the safety of the invocation would depend on the helper's
///   argument loop treating `-1` as a positional, which is a dependency worth
///   not having. The pid's *upper* bound (the far end parses into `i32`) is
///   checked on the executing side rather than here, because this crate holds
///   no policy.
/// - `gateway_ip: Ipv4Addr` rather than a string means there is no state of the
///   program in which this word is a hostname, a path, a flag, an IPv6 literal,
///   or anything with a shell metacharacter in it. The value is already an
///   address by the time it arrives; rendering it cannot make it something
///   else.
///
/// # What this does not establish
///
/// That the address is *well-formed*, not that it is *correct*. A caller that
/// invokes the installed binary directly never passes through this function at
/// all, so nothing here is a control on that path. The control that survives a
/// direct invocation is in the helper, derived from the namespace it enters.
pub fn install_container_route_argv(container_pid: u32, gateway_ip: Ipv4Addr) -> Vec<String> {
    vec![
        "sudo".to_string(),
        "-n".to_string(),
        INSTALLED_PATH_IN_VM.to_string(),
        VM_GATEWAY_MODE_FLAG.to_string(),
        container_pid.to_string(),
        gateway_ip.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_puts_the_binary_in_place_and_then_removes_the_staged_copy() {
        let steps = install_argv();
        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps[0],
            vec![
                "sudo",
                "-n",
                "install",
                "-m",
                "0755",
                STAGED_PATH_IN_VM,
                INSTALLED_PATH_IN_VM
            ]
        );
        assert_eq!(steps[1], vec!["rm", "-f", STAGED_PATH_IN_VM]);
    }

    /// The staging path must not be the install path: the whole reason it
    /// exists is that the copy runs as a user who cannot write the latter.
    #[test]
    fn the_staged_path_is_not_the_installed_path() {
        assert_ne!(STAGED_PATH_IN_VM, INSTALLED_PATH_IN_VM);
        assert!(INSTALLED_PATH_IN_VM.starts_with(INSTALL_DIR_IN_VM));
    }

    #[test]
    fn setcap_asks_for_exactly_the_three_capabilities_the_helper_documents() {
        let argv = setcap_argv();
        assert_eq!(argv[0], "sudo");
        assert_eq!(argv[2], "setcap");
        assert_eq!(argv[3], "cap_net_admin,cap_sys_admin,cap_sys_ptrace=eip");
        assert_eq!(argv[4], INSTALLED_PATH_IN_VM);
    }

    /// The capability string is one argv word. In the shell form it was
    /// wrapped in single quotes; a builder that carried the quotes over would
    /// hand `setcap` a set name that does not exist.
    #[test]
    fn the_capability_set_carries_no_shell_quotes() {
        assert!(!CAPABILITIES.contains('\''));
        assert!(!CAPABILITIES.contains(' '));
    }

    /// The probe asks `getcap`, not just `test -x`. Which answers count as
    /// "installed" is the caller's decision and is not pinned here — this
    /// crate holds no policy.
    #[test]
    fn the_caps_probe_looks_for_the_capability_not_merely_the_file() {
        assert_eq!(probe_caps_argv(), vec!["getcap", INSTALLED_PATH_IN_VM]);
    }

    /// Every privileged step refuses to prompt. A `sudo` without `-n` on this
    /// path would block the daemon's startup on a password nobody can type.
    ///
    /// The route-install step is in this list for a sharper reason than the
    /// provisioning steps are. Those run once per VM lifetime at startup; this
    /// one runs on every session create and every session restart, and it runs
    /// while a caller is waiting on an HTTP request. A prompt there would hang
    /// the request until the step's timeout rather than merely delaying a
    /// boot.
    #[test]
    fn every_sudo_step_is_non_interactive() {
        let mut argvs = vec![
            make_install_dir_argv(),
            chmod_argv(),
            setcap_argv(),
            install_container_route_argv(1234, Ipv4Addr::new(10, 0, 0, 2)),
        ];
        argvs.extend(install_argv());
        for argv in argvs {
            if argv[0] == "sudo" {
                assert_eq!(argv[1], "-n", "sudo step {argv:?} may prompt");
            }
        }
    }

    #[test]
    fn the_route_install_runs_the_installed_binary_with_the_two_positionals_last() {
        let argv = install_container_route_argv(4242, Ipv4Addr::new(10, 42, 7, 2));
        assert_eq!(
            argv,
            vec![
                "sudo",
                "-n",
                INSTALLED_PATH_IN_VM,
                "--vm-gateway-mode",
                "4242",
                "10.42.7.2"
            ]
        );
    }

    /// The two positionals are read *by position* on the far end, so the pid
    /// coming before the address is what makes this invocation mean what it
    /// says. That half is load-bearing.
    ///
    /// The mode flag's position is not, and the reason once given here — that
    /// the helper's parser stops accepting flags once it starts collecting
    /// positionals — describes a parser the helper does not have.
    /// `sandbox-route-helper`'s `parse_argv` leaves flag acceptance on until a
    /// `--` sentinel, which this builder never emits, so a flag after a
    /// positional would still be read as a flag. The assertion is kept as a
    /// pin on the shape this builder emits — the one the helper's own usage
    /// line shows — and not as a guard against a misparse.
    #[test]
    fn the_mode_flag_precedes_the_positionals() {
        let argv = install_container_route_argv(7, Ipv4Addr::new(192, 168, 5, 1));
        let flag = argv
            .iter()
            .position(|a| a == VM_GATEWAY_MODE_FLAG)
            .expect("the mode flag must be present");
        let pid = argv.iter().position(|a| a == "7").unwrap();
        let ip = argv.iter().position(|a| a == "192.168.5.1").unwrap();
        assert!(flag < pid, "mode flag must precede the pid: {argv:?}");
        assert!(pid < ip, "pid must precede the gateway address: {argv:?}");
    }

    /// No word this builder produces may start with `-` except the two flags
    /// it puts there itself. The `u32` pid is what makes this true for the
    /// pid word — there is no value of the parameter that renders a sign.
    #[test]
    fn the_rendered_values_can_never_look_like_flags() {
        for pid in [1u32, 7, 65535, i32::MAX as u32, u32::MAX] {
            let argv = install_container_route_argv(pid, Ipv4Addr::new(10, 0, 0, 2));
            let values = &argv[4..];
            for word in values {
                assert!(
                    !word.starts_with('-'),
                    "value word {word:?} could be read as a flag"
                );
            }
        }
    }
}
