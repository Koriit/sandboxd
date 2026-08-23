//! `sandbox-invm-argv` — the command lines for work done *inside* the gateway
//! Lima VM, shared by the two sides of the broker channel.
//!
//! # Why this is its own crate, next to `sandbox-docker-argv`
//!
//! The reasoning for a zero-dependency leaf crate is the same one
//! `sandbox-docker-argv` states: `sandbox-core` decides what an invocation
//! should do, the per-operator agent is what runs it once the VM belongs to an
//! operator, and neither of those two crates may depend on the other. Both
//! sides therefore need the same fragments and must not drift.
//!
//! What differs is the transport, and it differs enough to be a separate
//! crate rather than another module of the docker one:
//!
//! - **A different program.** These are `limactl shell` and `limactl copy`,
//!   not `docker`. Nothing here takes a `-H` socket, because the thing being
//!   addressed is a VM instance by name rather than a daemon by endpoint.
//! - **A different trust story.** A `docker exec` runs inside a container the
//!   product exists to contain. A `limactl shell` runs in the VM *hosting*
//!   those containers, as the VM's own login user, with passwordless `sudo`.
//!   The blast radius of a bad argv is the gateway itself — including the
//!   nftables baseline that bounds what the VM's own host-namespace processes
//!   can reach — so the enumeration here is load-bearing in a way that is
//!   worth reading separately.
//! - **A different Linux story.** The docker fragments run on Linux too (the
//!   lite container backend). These do not: there is no gateway VM on Linux.
//!   The crate still builds everywhere, because it is pure data, but nothing
//!   off macOS calls it.
//!
//! # What belongs here
//!
//! Pure functions from typed values to argv, plus the in-VM paths those argv
//! name. No I/O, no process spawning, no policy. Whether an operation is
//! *allowed* is decided on the agent side, next to the rest of its validation.
//!
//! # Why so little is a string
//!
//! Every function below returns a fully-formed argv whose command word is a
//! constant of this crate. There is no builder that takes a command, a shell
//! body, or a path to run something on, because the ops these serve reach a
//! host where `sudo` needs no password: one such builder would make the rest
//! of the enumeration decorative.
//!
//! The values that do vary are a short list, and each is constrained by
//! something other than this crate's good intentions:
//!
//! - a **session identifier**, checked on the executing side against a charset
//!   that admits no shell metacharacter;
//! - an **nftables ruleset**, which never reaches an argv at all — it is
//!   delivered to a parser on stdin as content;
//! - the choice of one of **four staged filenames**, drawn from a closed enum;
//! - a **container pid** and a **gateway address**, which are a `u32` and an
//!   [`std::net::Ipv4Addr`] rather than strings, so the words they render into
//!   cannot be flags, paths, or anything with a metacharacter in it.
//!
//! The last of those is the only one whose *correctness* — as opposed to its
//! shape — is not decided anywhere in this crate or on the calling side. It
//! cannot be: the question "is this the right gateway for that container?" is
//! answerable only from inside the container's network namespace. See
//! [`route_helper::install_container_route_argv`].
//!
//! # No shell — and exactly where the one that exists lives
//!
//! Not one argv here has a shell word in it. Before these operations were
//! typed, most of them did: the readiness probe used `>/dev/null 2>&1 &&`, the
//! capability probe used a pipeline into `grep`, the install and setcap steps
//! used `&&` chains, and the nftables baseline was interpolated into a
//! `bash -c` heredoc. Each of those became either a plain argv or a short
//! sequence of them, and the ruleset became stdin.
//!
//! **There is still a shell underneath, and it is worth naming rather than
//! claiming otherwise.** `limactl shell` is `ssh`, and `ssh` hands its remote
//! command to the login shell. What keeps that harmless is that `limactl`
//! shell-quotes each argv element before passing it on (it links
//! `shellescape.Quote`, and the multi-KB heredoc the guest-agent install has
//! always passed this way is the standing proof), so the guest shell re-parses
//! the words back into the same words. The property this crate holds is
//! therefore the precise one: **nothing here builds a shell command line out
//! of values**. No `&&`, no pipeline, no redirection, no quoting for a parser
//! to undo.
//!
//! That property is what the validation on the executing side completes: the
//! one value that reaches an argv element — a session identifier — is checked
//! against a charset that admits no shell metacharacter, so re-parsing cannot
//! find one. Reintroducing a builder that concatenates values into a command
//! word puts both halves of that back in play at once.

pub mod lite_stage;
pub mod route_helper;
pub mod vm;

/// The Lima CLI. Resolved to an absolute path by whichever side runs it —
/// this constant only names the program.
pub const LIMACTL_BIN: &str = "limactl";

/// `limactl shell <vm> -- <inner…>` — run `inner` inside `vm`.
///
/// `--tty=false` is not passed here and is not an oversight: `limactl shell`
/// has no such flag (it is a `limactl start`/`stop` option), and the shell
/// subcommand already declines to allocate a TTY when its own stdin is not
/// one. Both callers spawn it with piped stdio, so it is not.
pub fn shell_argv(vm: &str, inner: &[String]) -> Vec<String> {
    let mut argv = Vec::with_capacity(3 + inner.len());
    argv.push("shell".to_string());
    argv.push(vm.to_string());
    argv.push("--".to_string());
    argv.extend(inner.iter().cloned());
    argv
}

/// `limactl copy <host_src> <vm>:<vm_dst>` — push one file into `vm`.
///
/// The source is always a path on the side that runs the command, and always
/// one that side derived itself. It is a parameter of this function rather
/// than a constant only because the two callers derive it from different
/// roots; it never arrives from the other end of the broker channel.
pub fn copy_argv(host_src: &str, vm: &str, vm_dst: &str) -> Vec<String> {
    vec![
        "copy".to_string(),
        host_src.to_string(),
        format!("{vm}:{vm_dst}"),
    ]
}

/// Does this argv invoke a shell?
///
/// The predicate behind the no-shell invariant, which three separate
/// enumerations assert over their own contents: this crate's builders, the
/// in-VM op set in `sandbox-core`, and the agent's validation. It lives here,
/// as one function those three share, because three hand-copied `matches!`
/// arms are three chances to disagree about what "a shell" means — and they
/// had already drifted from the property in the same way, all three at once.
///
/// # What it matches
///
/// A word is a shell if its **basename** is one. Comparing the whole word
/// misses `/bin/sh`, which is the same invocation spelled differently; the
/// three copies this replaces all missed it.
///
/// Every word is checked, not only the first. Nearly every argv here begins
/// `sudo -n`, so a shell would appear at index 2, not 0.
///
/// # What it deliberately does not match
///
/// A bare `-c`. The copies this replaces flagged it, and that was a proxy for
/// the property rather than the property: `-c` is a shell's inline-code flag,
/// but it is equally `stat`'s output-format flag, and the socket-hardening
/// op's read-back step is `stat -c '%a %G'`. The proxy therefore failed a
/// correct argv — and a guard that fails correct work gets edited under
/// pressure, where the edit that relieves the pressure is rarely the one that
/// keeps the coverage.
///
/// What the `-c` arm caught that the names below do not is a *non-shell*
/// interpreter taking inline code — `python3 -c`, `perl -e`. That is a real
/// hazard and it is now uncovered. It is also not currently reachable: no
/// interpreter appears in any argv this crate builds. If one ever does, the
/// guard is its name added here, not a flag that unrelated programs share.
pub fn is_shell_invocation(argv: &[String]) -> bool {
    argv.iter().any(|word| {
        let basename = word.rsplit('/').next().unwrap_or(word.as_str());
        matches!(
            basename,
            "sh" | "bash" | "zsh" | "dash" | "ash" | "ksh" | "csh" | "tcsh" | "fish"
        )
    })
}

/// Convenience for building an argv of borrowed string literals.
fn owned(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_argv_puts_the_separator_before_the_command() {
        let argv = shell_argv("sandboxd-gateway", &owned(&["ip", "-json", "link", "show"]));
        assert_eq!(
            argv,
            vec![
                "shell",
                "sandboxd-gateway",
                "--",
                "ip",
                "-json",
                "link",
                "show"
            ]
        );
    }

    #[test]
    fn copy_argv_joins_the_instance_and_the_destination_with_a_colon() {
        let argv = copy_argv("/host/file", "sandboxd-gateway", "/tmp/dest");
        assert_eq!(
            argv,
            vec!["copy", "/host/file", "sandboxd-gateway:/tmp/dest"]
        );
    }

    /// No argv this crate builds may invoke a shell. The point is not that
    /// today's set happens to avoid one — it is that a future variant which
    /// reintroduces `bash -c` fails here rather than in review.
    ///
    /// **This list is maintained by hand, and that is a known weakness.** A
    /// builder added to the crate and not added here is not covered, and the
    /// test still passes — it went green over a `sh -c` builder that existed
    /// for exactly as long as it took the agent-side guard, which enumerates
    /// `every_op()` instead of a literal list, to catch it. So a new builder
    /// belongs in this list, and a reader deciding whether the invariant holds
    /// should compare the list against the crate's public functions rather
    /// than trust the green.
    /// The predicate three guards delegate to. An untested detector makes
    /// three green tests mean nothing at once, so it is exercised on both
    /// sides of its boundary here rather than only through its callers —
    /// where it can only ever be observed saying "no".
    #[test]
    fn a_shell_is_recognised_wherever_and_however_it_is_spelled() {
        for argv in [
            owned(&["sh", "-c", "echo hi"]),
            owned(&["/bin/sh", "-c", "echo hi"]),
            owned(&["/usr/bin/env", "bash", "-c", "echo hi"]),
            owned(&["sudo", "-n", "zsh", "-c", "echo hi"]),
            owned(&["/bin/dash"]),
        ] {
            assert!(
                is_shell_invocation(&argv),
                "{argv:?} invokes a shell and was not recognised"
            );
        }
    }

    /// The false positive that retired the old `-c` arm, plus the argv shapes
    /// it sits next to. A detector that fires on correct work is the reason
    /// guards get weakened, so the case that broke it is pinned.
    #[test]
    fn a_non_shell_flag_named_c_is_not_a_shell() {
        for argv in [
            owned(&["stat", "-c", "%a %G", "/var/run/docker.sock"]),
            owned(&[
                "sudo",
                "-n",
                "install",
                "-D",
                "-m",
                "0644",
                "/dev/stdin",
                "/etc/x.conf",
            ]),
            owned(&["sudo", "-n", "systemctl", "daemon-reload"]),
            owned(&["id", "-g"]),
        ] {
            assert!(
                !is_shell_invocation(&argv),
                "{argv:?} is not a shell invocation but was flagged as one"
            );
        }
    }

    #[test]
    fn no_builder_produces_a_shell_invocation() {
        let mut argvs: Vec<Vec<String>> = vec![
            vm::docker_ready_argv(),
            vm::link_show_json_argv(),
            vm::apply_nft_baseline_argv(),
            vm::login_gid_argv(),
            vm::write_docker_socket_dropin_argv(),
            route_helper::make_install_dir_argv(),
            route_helper::probe_executable_argv(),
            route_helper::probe_caps_argv(),
            route_helper::setcap_argv(),
            route_helper::chmod_argv(),
            route_helper::remove_staged_argv(),
            route_helper::install_container_route_argv(1234, std::net::Ipv4Addr::new(10, 0, 0, 2)),
        ];
        argvs.extend(route_helper::install_argv());
        argvs.extend(vm::harden_docker_socket_argv(1000));
        argvs.push(lite_stage::mkdir_argv("/tmp/sandbox-lite/s1"));
        argvs.push(lite_stage::rm_argv("/tmp/sandbox-lite/s1"));

        for argv in argvs {
            assert!(
                !is_shell_invocation(&argv),
                "argv {argv:?} contains a shell word"
            );
        }
    }
}
