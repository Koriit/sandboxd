//! Resolving an operator-supplied `shared:` workspace path **inside** the
//! gateway VM, and reading the answer.
//!
//! # Why the resolution happens in there
//!
//! A lite session's workspace bind is a host path the operator names and the
//! VM's `dockerd` resolves. Those are two different filesystem views of the
//! same 9p export, and they do not agree about symlinks: a link created from
//! inside the VM is stored on the host as a *regular file* carrying `S_IFLNK`
//! in a `user.virtfs.*` xattr, so a host-side `canonicalize` walks straight
//! past it while `dockerd`, resolving the same `src=` in the guest, follows it
//! out of the export. That is not a race that a re-check narrows — the host
//! view is permanently blind to it. The only place the two views cannot
//! disagree is the namespace the path is actually used in, which is why the
//! containment verdict is taken from in there.
//!
//! # Why one `realpath` answers both questions
//!
//! [`resolve_argv`] renders a single `realpath -e --relative-base=ROOT -- PATH`,
//! and its output carries the verdict *and* the safe spelling at once:
//!
//! - `realpath` canonicalizes **both** operands, so a symlinked export root
//!   works and a symlinked component of the path is followed exactly as
//!   `dockerd` will follow it;
//! - `-e` requires every component to exist, so a path that is not there is a
//!   non-zero exit rather than a plausible-looking answer;
//! - `--relative-base` prints the result **relative** to the root when it lands
//!   under it and **absolute** when it does not — so "escaped" is a leading `/`
//!   rather than a comparison this side has to get right;
//! - `--` closes the one hazard a caller-supplied path still has, which is a
//!   leading `-` being read as a flag.
//!
//! The escape case is worth reading twice: `/tmp/sandbox-shared/escape`, where
//! `escape` is a guest symlink to `/run`, comes back as the absolute `/run`.
//! The refusal therefore knows where the path pointed, not merely that it
//! pointed away.
//!
//! # Why a path may be a field here when it may not on the other ops
//!
//! The crate's `Why so little is a string` enumeration turns on what a value
//! can be made to *do*. [`crate::route_helper`]'s staging op refuses a source
//! path because it would be a request to copy an arbitrary file into a VM that
//! is about to be handed `cap_net_admin`; the lite-staging ops carry a session
//! identifier only because the executing side checks it against a charset with
//! no shell metacharacter in it.
//!
//! This op grants no write, no exec and no privilege. It reads one path and
//! reports where it lands. The two properties that make the string safe to
//! carry are:
//!
//! 1. **It cannot be re-split into words.** `limactl` shell-quotes every argv
//!    element before handing the command to the guest login shell, so the
//!    shell re-parses the words back into the same words. A space, a quote, a
//!    `$(…)` or a newline inside a filename reaches `realpath` as part of the
//!    filename.
//! 2. **It cannot become a flag.** `--` precedes it.
//!
//! What is *not* established here is that the path is one the daemon is
//! entitled to ask about. That is the executing side's check, and it is a
//! narrow one: the root must not be `/`, and the path must already lie under
//! the root lexically. Together those keep the op from being usable as an
//! arbitrary-path existence probe — the answer it can give is only ever about
//! somewhere inside a declared export.

use crate::owned;

/// Where a resolved path landed, relative to the declared export root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Containment {
    /// The path resolves to somewhere inside the root. `resolved` is its
    /// symlink-free absolute spelling, which is what may be bound.
    Inside { resolved: String },
    /// The path resolves to somewhere outside the root. `resolved` is where it
    /// actually landed, so the refusal can say so.
    Outside { resolved: String },
}

/// `realpath -e --relative-base=<shared_root> -- <requested_path>` inside the
/// VM.
///
/// No `sudo`: this reads a path the VM's login user can already read, and the
/// answer is only useful if it is the answer that user gets.
///
/// One step, deliberately. The executor returns the **last** step's output, so
/// an op whose result is parsed has to render exactly one command.
pub fn resolve_argv(shared_root: &str, requested_path: &str) -> Vec<String> {
    let mut argv = owned(&["realpath", "-e"]);
    argv.push(format!("--relative-base={}", root_spelling(shared_root)));
    argv.push("--".to_string());
    argv.push(requested_path.to_string());
    argv
}

/// The root as it is written into the argv and used for prefix decisions: no
/// trailing slash, because `/tmp/x/` and `/tmp/x` name the same directory and
/// only one of them composes cleanly with a relative remainder.
///
/// A root of `/` collapses to the empty string here, which
/// [`path_is_within`] then refuses. That is intentional and is checked again
/// on the executing side: a root of `/` is a containment test that contains
/// everything.
fn root_spelling(shared_root: &str) -> &str {
    shared_root.trim_end_matches('/')
}

/// Is `candidate` the root itself or something beneath it, comparing whole
/// path components?
///
/// A plain `starts_with` says yes to `/tmp/sandbox-shared-evil` for the root
/// `/tmp/sandbox-shared`; requiring a `/` immediately after the prefix is what
/// makes the comparison about the directory tree rather than about the string.
///
/// This is the **lexical** half only. It is a necessary condition the executing
/// side enforces before it will run the op at all, and it is what
/// [`parse_resolution`] applies to the resolved answer. It is not sufficient on
/// its own — a lexical check is exactly what the guest-side resolution exists
/// to backstop.
pub fn path_is_within(shared_root: &str, candidate: &str) -> bool {
    let root = root_spelling(shared_root);
    if root.is_empty() || !root.starts_with('/') {
        return false;
    }
    let candidate = candidate.trim_end_matches('/');
    candidate == root
        || candidate
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Read [`resolve_argv`]'s stdout.
///
/// `None` for anything that is not a single well-formed path, which is what
/// makes an unexpected answer a refusal rather than a value used anyway. The
/// cases that produce one are not hypothetical:
///
/// - **Empty output.** Nothing resolved; there is no path to bind.
/// - **More than one line.** A filename may contain a newline, and `realpath`
///   terminates its answer with one — so a resolved path holding a newline is
///   indistinguishable from two answers. Measured, not assumed.
/// - **A control character or a NUL.** Same reasoning, one step earlier.
/// - **A `..` component in the relative form.** `--relative-base` does not emit
///   one, because it prints an absolute path whenever the target is not under
///   the base. This is the belt to that braces: the parser does not need the
///   reader to have checked `realpath`'s manual to see that it cannot be
///   walked back out of the root.
///
/// A `.` is the root itself — `realpath` never prefixes its relative output
/// with `./`.
pub fn parse_resolution(shared_root: &str, output: &str) -> Option<Containment> {
    let root = root_spelling(shared_root);
    if root.is_empty() || !root.starts_with('/') {
        return None;
    }

    let answer = output.strip_suffix('\n').unwrap_or(output);
    if answer.is_empty() || answer.chars().any(|c| c.is_control()) {
        return None;
    }

    if answer.starts_with('/') {
        // Absolute means "not under the base" — but judge it rather than
        // assume it, so a future `realpath` that spells a contained answer
        // absolutely is accepted instead of silently refused.
        return Some(if path_is_within(root, answer) {
            Containment::Inside {
                resolved: answer.to_string(),
            }
        } else {
            Containment::Outside {
                resolved: answer.to_string(),
            }
        });
    }

    if answer.split('/').any(|component| component == "..") {
        return None;
    }

    Some(Containment::Inside {
        resolved: if answer == "." {
            root.to_string()
        } else {
            format!("{root}/{answer}")
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--` is what stops a path from being read as a flag, and `-e` is what
    /// stops a path that is not there from resolving to something plausible.
    #[test]
    fn the_resolve_argv_closes_the_flag_and_the_missing_path_hazards() {
        assert_eq!(
            resolve_argv("/tmp/sandbox-shared", "/tmp/sandbox-shared/proj"),
            vec![
                "realpath",
                "-e",
                "--relative-base=/tmp/sandbox-shared",
                "--",
                "/tmp/sandbox-shared/proj",
            ]
        );
    }

    /// A path that would otherwise be a flag is still the last word, after the
    /// separator. Nothing about it changes the shape of the command.
    #[test]
    fn a_flag_shaped_path_lands_after_the_separator() {
        let argv = resolve_argv("/tmp/sandbox-shared", "-rf");
        assert_eq!(argv.len(), 5);
        assert_eq!(argv[3], "--");
        assert_eq!(argv[4], "-rf");
    }

    /// The two values reach exactly one word each. Asserted by differencing —
    /// vary an input and see what moves — rather than by reading the words,
    /// which is the same discipline
    /// `the_gid_is_the_only_caller_supplied_word_in_the_remediation` applies to
    /// the socket hardening.
    #[test]
    fn each_supplied_value_reaches_exactly_one_word() {
        let base = resolve_argv("/tmp/a", "/tmp/a/x");
        let other_path = resolve_argv("/tmp/a", "/tmp/a/y");
        let other_root = resolve_argv("/tmp/b", "/tmp/a/x");

        for (varied, label) in [(&other_path, "path"), (&other_root, "root")] {
            assert_eq!(
                base.len(),
                varied.len(),
                "the {label} changed the shape of the command, not just a word in it"
            );
            let differing = base
                .iter()
                .zip(varied.iter())
                .filter(|(a, b)| a != b)
                .count();
            assert_eq!(differing, 1, "the {label} reached {differing} words");
        }
    }

    /// The no-shell invariant, for the one builder whose input is free-form.
    ///
    /// The crate's enumeration asserts it through [`crate::is_shell_invocation`],
    /// which matches a **basename** in any argv position. That detector cannot
    /// be pointed at this builder's adversarial cases: a workspace directory
    /// may legitimately be called `sh`, and the detector would call
    /// `realpath -e … -- /tmp/sandbox-shared/sh` a shell invocation. It is not
    /// one — `realpath` is the command word and the path is an operand after
    /// `--`.
    ///
    /// So the property is asserted where it actually lives: whatever the path
    /// is, the first four words are the same four words. Nothing a caller
    /// supplies can move the command word or the separator.
    #[test]
    fn the_command_word_does_not_depend_on_the_path() {
        let fixed = [
            "realpath",
            "-e",
            "--relative-base=/tmp/sandbox-shared",
            "--",
        ];
        for path in [
            "/tmp/sandbox-shared/proj",
            "/tmp/sandbox-shared/sh",
            "/bin/sh",
            "-rf",
            "--version",
            "/tmp/sandbox-shared/a; sh -c id",
            "/tmp/sandbox-shared/$(sh)",
            "",
        ] {
            let argv = resolve_argv("/tmp/sandbox-shared", path);
            assert_eq!(argv[..4], fixed, "path {path:?} moved the command");
            assert_eq!(argv.len(), 5, "path {path:?} produced extra words");
            assert_eq!(argv[4], path);
        }
    }

    /// A trailing slash on the root is the same directory and must not become
    /// a doubled separator in the answer.
    #[test]
    fn a_trailing_slash_on_the_root_is_normalised_away() {
        assert_eq!(
            resolve_argv("/tmp/sandbox-shared/", "/tmp/sandbox-shared/proj")[2],
            "--relative-base=/tmp/sandbox-shared"
        );
        assert_eq!(
            parse_resolution("/tmp/sandbox-shared/", "proj\n"),
            Some(Containment::Inside {
                resolved: "/tmp/sandbox-shared/proj".to_string()
            })
        );
    }

    /// The measured shapes, from a probe run inside a live gateway VM against
    /// GNU coreutils 9.4. Relative for anything under the base — including a
    /// symlink that stays inside — absolute the moment it leaves.
    #[test]
    fn the_verdict_is_the_leading_slash() {
        let root = "/tmp/sandbox-shared";
        for (output, expected) in [
            (".\n", "/tmp/sandbox-shared"),
            ("sub\n", "/tmp/sandbox-shared/sub"),
            ("sub/file\n", "/tmp/sandbox-shared/sub/file"),
        ] {
            assert_eq!(
                parse_resolution(root, output),
                Some(Containment::Inside {
                    resolved: expected.to_string()
                }),
                "{output:?}"
            );
        }

        for output in ["/run\n", "/run/docker.sock\n", "/tmp/elsewhere\n"] {
            let resolved = output.trim_end();
            assert_eq!(
                parse_resolution(root, output),
                Some(Containment::Outside {
                    resolved: resolved.to_string()
                }),
                "{output:?}"
            );
        }
    }

    /// The escape the whole op exists for: a guest symlink out of the export.
    /// The refusal gets to name where it went.
    #[test]
    fn an_escape_reports_where_it_landed() {
        let Some(Containment::Outside { resolved }) =
            parse_resolution("/tmp/sandbox-shared", "/run/docker.sock\n")
        else {
            panic!("a resolved path outside the root must not be contained");
        };
        assert_eq!(resolved, "/run/docker.sock");
    }

    /// A sibling directory whose name merely begins with the root's is not
    /// inside it. The string comparison that says otherwise is the one this
    /// exists to rule out.
    #[test]
    fn a_sibling_sharing_the_roots_prefix_is_outside() {
        assert!(!path_is_within(
            "/tmp/sandbox-shared",
            "/tmp/sandbox-shared-evil"
        ));
        assert_eq!(
            parse_resolution("/tmp/sandbox-shared", "/tmp/sandbox-shared-evil/x\n"),
            Some(Containment::Outside {
                resolved: "/tmp/sandbox-shared-evil/x".to_string()
            })
        );
        assert!(path_is_within("/tmp/sandbox-shared", "/tmp/sandbox-shared"));
        assert!(path_is_within(
            "/tmp/sandbox-shared",
            "/tmp/sandbox-shared/a/b"
        ));
    }

    /// A root of `/` is a containment test that contains everything. Refused
    /// here as well as on the executing side, so neither is the only thing
    /// standing in front of it.
    #[test]
    fn the_filesystem_root_is_not_a_containment_root() {
        assert!(!path_is_within("/", "/anything"));
        assert!(!path_is_within("", "/anything"));
        assert_eq!(parse_resolution("/", "tmp/x\n"), None);
        assert_eq!(parse_resolution("relative/root", "x\n"), None);
    }

    /// An answer that is not a single well-formed path is refused rather than
    /// used. A filename may contain a newline, so multi-line output is
    /// genuinely ambiguous — measured in the VM, not assumed.
    #[test]
    fn an_unreadable_answer_is_not_treated_as_contained() {
        let root = "/tmp/sandbox-shared";
        for output in [
            "",
            "\n",
            "   \n\n",
            "sub/one\nsub/two\n",
            "/run\n/tmp/sandbox-shared\n",
            "sub/we\0ird\n",
            "sub/tab\there\n",
        ] {
            assert_eq!(parse_resolution(root, output), None, "{output:?}");
        }
    }

    /// Whitespace is a legal filename character and is not a reason to refuse.
    /// Only control characters are, and only because they make the answer
    /// ambiguous rather than because they are dangerous — `limactl` quotes the
    /// argv and nothing here builds a command line out of the value.
    #[test]
    fn ordinary_awkward_filenames_still_resolve() {
        let root = "/tmp/sandbox-shared";
        for (output, expected) in [
            ("my project\n", "/tmp/sandbox-shared/my project"),
            ("a'b\n", "/tmp/sandbox-shared/a'b"),
            ("$(id)\n", "/tmp/sandbox-shared/$(id)"),
            ("naïve\n", "/tmp/sandbox-shared/naïve"),
        ] {
            assert_eq!(
                parse_resolution(root, output),
                Some(Containment::Inside {
                    resolved: expected.to_string()
                }),
                "{output:?}"
            );
        }
    }

    /// `--relative-base` prints an absolute path rather than a `..` walk, so a
    /// relative answer containing one should be impossible. It is refused
    /// anyway: the parser's safety should not rest on the reader having
    /// checked `realpath`'s manual.
    #[test]
    fn a_relative_answer_that_walks_out_is_refused() {
        assert_eq!(
            parse_resolution("/tmp/sandbox-shared", "../elsewhere\n"),
            None
        );
        assert_eq!(
            parse_resolution("/tmp/sandbox-shared", "sub/../../elsewhere\n"),
            None
        );
    }

    /// An absolute answer that *is* under the root is accepted as contained.
    /// Today `realpath` does not spell it that way; the parser judges the
    /// answer rather than trusting the spelling, so a release that changed its
    /// mind would refuse correct work instead of admitting incorrect work —
    /// and this pins which of the two.
    #[test]
    fn an_absolute_answer_under_the_root_is_still_contained() {
        assert_eq!(
            parse_resolution("/tmp/sandbox-shared", "/tmp/sandbox-shared/sub\n"),
            Some(Containment::Inside {
                resolved: "/tmp/sandbox-shared/sub".to_string()
            })
        );
    }
}
