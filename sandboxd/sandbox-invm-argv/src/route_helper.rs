//! Provisioning `sandbox-route-helper` inside the gateway VM: probe it,
//! stage it, install it, give it its capabilities.
//!
//! This module is about getting the binary *into* the VM. **Invoking** it —
//! `sandbox-route-helper --vm-gateway-mode`, which installs a container's
//! default route — is a separate operation with its own authorization
//! question, and is not here.
//!
//! Every privileged step runs `sudo -n`; see the module docs on
//! [`crate::vm`] for why the flag is not decorative.

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

/// The capability set the helper needs inside the VM.
///
/// `cap_net_admin` to install a route, `cap_sys_admin` to enter a network
/// namespace, `cap_sys_ptrace` because the container runs as a foreign uid and
/// the `pidfd`+`setns` path hits a cross-uid `ptrace_may_access` check.
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
pub fn probe_caps_argv() -> Vec<String> {
    owned(&["getcap", INSTALLED_PATH_IN_VM])
}

/// The substring the caller looks for in [`probe_caps_argv`]'s output.
pub const PROBE_CAPS_MARKER: &str = "cap_net_admin";

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

    #[test]
    fn the_caps_probe_looks_for_the_capability_not_merely_the_file() {
        assert_eq!(probe_caps_argv(), vec!["getcap", INSTALLED_PATH_IN_VM]);
        assert!(CAPABILITIES.contains(PROBE_CAPS_MARKER));
    }

    /// Every privileged step refuses to prompt. A `sudo` without `-n` on this
    /// path would block the daemon's startup on a password nobody can type.
    #[test]
    fn every_sudo_step_is_non_interactive() {
        let mut argvs = vec![make_install_dir_argv(), chmod_argv(), setcap_argv()];
        argvs.extend(install_argv());
        for argv in argvs {
            if argv[0] == "sudo" {
                assert_eq!(argv[1], "-n", "sudo step {argv:?} may prompt");
            }
        }
    }
}
