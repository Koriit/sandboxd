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
//!   nftables baseline that is the egress promise — so the enumeration here is
//!   load-bearing in a way that is worth reading separately.
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
    #[test]
    fn no_builder_produces_a_shell_invocation() {
        let mut argvs: Vec<Vec<String>> = vec![
            vm::docker_ready_argv(),
            vm::link_show_json_argv(),
            vm::apply_nft_baseline_argv(),
            route_helper::make_install_dir_argv(),
            route_helper::probe_executable_argv(),
            route_helper::probe_caps_argv(),
            route_helper::setcap_argv(),
            route_helper::chmod_argv(),
            route_helper::remove_staged_argv(),
            route_helper::install_container_route_argv(1234, std::net::Ipv4Addr::new(10, 0, 0, 2)),
        ];
        argvs.extend(route_helper::install_argv());
        argvs.push(lite_stage::mkdir_argv("/tmp/sandbox-lite/s1"));
        argvs.push(lite_stage::rm_argv("/tmp/sandbox-lite/s1"));

        for argv in argvs {
            for word in &argv {
                assert!(
                    !matches!(word.as_str(), "sh" | "bash" | "zsh" | "dash" | "-c"),
                    "argv {argv:?} contains a shell word"
                );
            }
        }
    }
}
