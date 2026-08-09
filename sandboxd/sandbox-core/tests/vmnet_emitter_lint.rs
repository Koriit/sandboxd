//! Cross-emitter lints for the macOS socket_vmnet LaunchDaemon pool.
//!
//! Three independent code paths emit the eight `io.sandboxd.vmnet.<n>` plists:
//! `network.rs` (Rust), the `setup-darwin-vmnet-plists` make target, and
//! `scripts/install.sh`. Each declares the daemon account name in its own
//! language, and nothing in the type system ties them together. When they
//! disagree the damage is invisible at provisioning time and only lands at the
//! next reboot: the plist's root preamble does
//! `install -d -o <account> -g <account> ... /var/run/sandbox`, `/var/run` is
//! wiped on every macOS boot, and an unresolvable account makes that command
//! fail, short-circuit the `&&`-chain, and take all eight slots down.
//!
//! `scripts/check-vmnet-uuid-equivalence.py` is the thing that keeps the three
//! in step: it extracts the account name, the staged binary path and the whole
//! pre-exec wrapper template out of each emitter's source and compares them.
//! These tests run it as part of the hermetic suite so a drift is caught by
//! `make test` on any host, not only by the macOS CI job, and they check the
//! checker itself still fails on a repo that has been pushed out of agreement
//! — a drift detector that cannot fail is worse than none.
//!
//! The macOS-only half additionally pins the two things that need a real
//! `plutil`: that both shell emitters render byte-for-byte what
//! [`render_vmnet_plist`] renders, and that `scripts/darwin-vmnet-drift.sh`
//! notices when launchd's in-memory argv has parted ways with the plist on
//! disk.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Repository root. `CARGO_MANIFEST_DIR` is `<repo>/sandboxd/sandbox-core`.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("sandbox-core lives two levels below the repository root")
        .to_path_buf()
}

fn checker_path() -> PathBuf {
    repo_root().join("scripts/check-vmnet-uuid-equivalence.py")
}

/// Every file the checker reads. A perturbed copy needs exactly these.
const EMITTER_FILES: [&str; 3] = [
    "Makefile",
    "scripts/install.sh",
    "sandboxd/sandbox-core/src/network.rs",
];

fn run_checker(root: &Path) -> Output {
    Command::new("python3")
        .arg(checker_path())
        .arg("--repo-root")
        .arg(root)
        .output()
        .expect(
            "python3 must be on PATH — the vmnet plist generators are written in it \
             (`python3 -c` in the Makefile and in scripts/install.sh)",
        )
}

fn describe(output: &Output) -> String {
    format!(
        "exit {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

/// Copy the emitter files into a temporary tree, applying `edits` on the way.
///
/// Each edit is `(repo-relative path, needle, replacement)` and must match at
/// least once — an edit that silently matches nothing would turn the
/// "checker rejects this" assertion into a test of the pristine repo.
fn perturbed_repo(edits: &[(&str, &str, &str)]) -> tempfile::TempDir {
    let root = repo_root();
    let tmp = tempfile::tempdir().expect("create temp repo");

    for rel in EMITTER_FILES {
        let src = root.join(rel);
        let dst = tmp.path().join(rel);
        fs::create_dir_all(dst.parent().expect("relative path has a parent"))
            .expect("create temp repo subdir");
        let mut text = fs::read_to_string(&src).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        for (edit_rel, needle, replacement) in edits {
            if *edit_rel != rel {
                continue;
            }
            assert!(
                text.contains(needle),
                "perturbation needle not found in {rel} — the test's needle is stale:\n  {needle}"
            );
            text = text.replace(needle, replacement);
        }
        fs::write(&dst, text).unwrap_or_else(|e| panic!("write {}: {e}", dst.display()));
    }
    tmp
}

/// Rewrite the value of a `NAME := value` Makefile assignment, preserving the
/// original column alignment so the needle does not depend on it.
fn makefile_assignment(name: &str) -> (String, String) {
    let text = fs::read_to_string(repo_root().join("Makefile")).expect("read Makefile");
    let line = text
        .lines()
        .find(|l| l.starts_with(name) && l.contains(":="))
        .unwrap_or_else(|| panic!("Makefile has no `{name} :=` assignment"))
        .to_string();
    let value = line
        .split_once(":=")
        .expect("checked above")
        .1
        .trim()
        .to_string();
    (line, value)
}

#[test]
fn vmnet_emitters_agree_in_this_repo() {
    let output = run_checker(&repo_root());
    assert!(
        output.status.success(),
        "the three vmnet plist emitters have drifted apart.\n{}",
        describe(&output)
    );
}

#[test]
fn checker_rejects_a_renamed_makefile_account() {
    let (line, value) = makefile_assignment("DARWIN_SANDBOXD_ACCOUNT");
    let drifted = line.replace(&value, &format!("{value}_drifted"));
    let tmp = perturbed_repo(&[("Makefile", &line, &drifted)]);

    let output = run_checker(tmp.path());
    assert!(
        !output.status.success(),
        "the Makefile now names a different account than network.rs and install.sh, \
         and the checker passed anyway.\n{}",
        describe(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("name different accounts"),
        "expected the failure to be attributed to the account name.\n{}",
        describe(&output)
    );
}

#[test]
fn checker_rejects_a_hardcoded_socket_group() {
    // The historical shape of the bug: the wrapper hardcodes an account
    // instead of interpolating the one variable the repo agrees on.
    let tmp = perturbed_repo(&[(
        "Makefile",
        "--socket-group=$$acct",
        "--socket-group=_sandbox",
    )]);

    let output = run_checker(tmp.path());
    assert!(
        !output.status.success(),
        "the Makefile's wrapper hardcodes an account the other emitters do not name, \
         and the checker passed anyway.\n{}",
        describe(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("wrapper templates differ"),
        "expected the failure to be attributed to the wrapper template.\n{}",
        describe(&output)
    );
}

#[test]
fn checker_rejects_an_installer_that_creates_a_different_account() {
    // install.sh naming one account in its plists and creating another is the
    // exact split that left the pool with no account to run as.
    let tmp = perturbed_repo(&[(
        "scripts/install.sh",
        "/Users/\\$_sandboxd_acct",
        "/Users/_sandbox",
    )]);

    let output = run_checker(tmp.path());
    assert!(
        !output.status.success(),
        "install.sh now creates an account its plists never name, and the checker \
         passed anyway.\n{}",
        describe(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("to create exactly"),
        "expected the failure to be attributed to the created account.\n{}",
        describe(&output)
    );
}

/// A fourth emitter, in a file the checker was never told about, must fail.
///
/// The three-way comparison is only as good as its inventory: it reads three
/// hardcoded paths, so an emitter added in a *new* file would not be compared
/// against anything and could name any account it liked while every check
/// still passed. The checker discovers candidates by signature for that
/// reason; this pins the discovery.
#[test]
fn checker_rejects_an_unregistered_fourth_emitter() {
    let tmp = perturbed_repo(&[]);
    let planted = tmp.path().join("scripts/emit-vmnet-plists.sh");
    fs::write(
        &planted,
        // Both signatures: the boot-time preamble, and a vmnet-labelled job
        // with a ProgramArguments array.
        "#!/bin/sh\n\
         # A fourth emitter nobody registered.\n\
         _label=\"io.sandboxd.vmnet.$1\"\n\
         printf '%s' \"<key>ProgramArguments</key>\"\n\
         printf '%s' \"install -d -o _nobody -g _nobody -m 0750 /var/run/sandbox\"\n",
    )
    .expect("plant a fourth emitter");

    let output = run_checker(tmp.path());
    assert!(
        !output.status.success(),
        "a new file emitting the vmnet plists went unnoticed.\n{}",
        describe(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("scripts/emit-vmnet-plists.sh"),
        "the failure must name the unregistered file so its author knows what to \
         register.\n{}",
        describe(&output)
    );
}

// ---------------------------------------------------------------------------
// The duplicated `launchctl print` parser
// ---------------------------------------------------------------------------

/// Undo an unquoted heredoc's escaping.
///
/// `scripts/install.sh` writes its privileged half into a `<<PRIV_SCRIPT_EOF`
/// heredoc with no quoting, so the shell strips the backslash before `$`, a
/// backtick, and another backslash before the child ever sees the text. Every
/// other backslash — `\{`, `\t`, `\}` in the awk program — is passed through
/// untouched. Reproducing that rule here rather than special-casing `\$` keeps
/// the comparison honest if the parser ever grows a backtick.
fn unescape_unquoted_heredoc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('$') | Some('`') | Some('\\') => {
                    out.push(chars.next().expect("peeked"));
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Pull the body of a single-quoted `awk '…'` program out of a shell script.
///
/// Scans from `anchor` (or the top of the file) for a line ending in `awk '`,
/// then takes every following line until one that begins the closing quote.
/// The awk program contains no single quote of its own, so the terminator is
/// unambiguous.
///
/// Lines come back trimmed: the two copies sit at different nesting depths and
/// awk does not care about leading whitespace, so indentation is the one
/// difference that must not fail the comparison.
fn extract_awk_program(rel: &str, anchor: Option<&str>) -> Vec<String> {
    let text =
        fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"));
    let lines: Vec<&str> = text.lines().collect();

    let start = match anchor {
        Some(a) => lines
            .iter()
            .position(|l| l.contains(a))
            .unwrap_or_else(|| panic!("{rel}: anchor not found, the extractor is stale: {a}")),
        None => 0,
    };
    let open = lines[start..]
        .iter()
        .position(|l| l.trim_end().ends_with("awk '"))
        .map(|i| start + i)
        .unwrap_or_else(|| panic!("{rel}: no `awk '` opener found after the anchor"));

    let mut body = Vec::new();
    for line in &lines[open + 1..] {
        if line.trim_start().starts_with('\'') {
            return body;
        }
        body.push(line.trim().to_string());
    }
    panic!(
        "{rel}: unterminated awk program starting at line {}",
        open + 1
    );
}

/// The two copies of the `launchctl print` argv parser must stay identical.
///
/// `scripts/darwin-vmnet-drift.sh` and `scripts/install.sh` each carry the same
/// awk program. The duplication is forced — a `curl | sh` installer cannot
/// source a script out of the repo — but nothing except a comment held the two
/// in step, and only the drift script's copy was under test.
///
/// An edit that lands on one copy and misses the other breaks the *installer's*
/// drift detection, and breaks it in the worst available way: the parser
/// silently yields no argv, the installer reads that as "not loaded", and a
/// stale definition survives a run that reports success. That is #85's own
/// pathology reproduced inside the mechanism built to prevent it, on the path a
/// fresh production host actually takes.
#[test]
fn launchctl_argv_parser_is_identical_in_both_copies() {
    const DRIFT: &str = "scripts/darwin-vmnet-drift.sh";
    const INSTALL: &str = "scripts/install.sh";

    let drift = extract_awk_program(DRIFT, None);
    let install: Vec<String> = extract_awk_program(INSTALL, Some("_vmnet_loaded_argv() {"))
        .iter()
        .map(|l| unescape_unquoted_heredoc(l))
        .collect();

    // Guard the extractor itself. If either side came back empty, or lost the
    // brace rule that the whole parser turns on, the comparison below could
    // pass while comparing nothing.
    for (rel, body) in [(DRIFT, &drift), (INSTALL, &install)] {
        assert!(
            !body.is_empty(),
            "{rel}: extracted an empty awk program — the extractor is stale"
        );
        assert!(
            body.iter().any(|l| l.contains("in_args = 1")),
            "{rel}: extracted text is not the argv parser:\n{}",
            body.join("\n")
        );
        assert!(
            body.iter().any(|l| l.contains(r"\}")),
            "{rel}: the closing-brace rule is gone. The argv contains a literal `}}` \
             (the codesign guard's `|| {{ …; exit 1; }}`), so the block terminator must \
             match `}}` only when alone on its line:\n{}",
            body.join("\n")
        );
    }

    assert_eq!(
        drift,
        install,
        "the two copies of the launchctl argv parser have diverged.\n\
         \n  {DRIFT}:\n{}\n\n  {INSTALL} (heredoc-unescaped):\n{}\n\n\
         Whichever was edited, the other still ships. {INSTALL} is the path a fresh \
         production host takes, and a parser that yields nothing there reads as \
         \"not loaded\" — the installer then reports success over a stale definition.",
        drift.join("\n"),
        install.join("\n"),
    );
}

/// The broker's enrollment gate must not re-declare the account name.
///
/// The group `broker.rs` checks membership in and the account the plists name
/// are one identity. A private literal there would be a fourth independent
/// declaration of a name that has already drifted once — and the failure it
/// produces is the least legible of the four: an unresolvable group denies
/// every operator with nothing to distinguish that from a legitimate refusal.
/// The checker does not read `broker.rs`, so this is the guard.
#[test]
fn broker_does_not_redeclare_the_account_name() {
    let broker = repo_root().join("sandboxd/sandboxd/src/broker.rs");
    let text = fs::read_to_string(&broker).expect("broker.rs must be readable");

    // Comments and doc-comments may name the account freely — this is about
    // declarations. A Rust string literal is the only form that compiles into
    // a second source of truth.
    let offenders: Vec<usize> = text
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && line.contains("\"_sandboxd\"")
        })
        .map(|(i, _)| i + 1)
        .collect();

    assert!(
        offenders.is_empty(),
        "broker.rs re-declares the account name as a string literal at line(s) {offenders:?}; \
         use `sandbox_core::network::SANDBOXD_ACCOUNT` (or the `SANDBOX_GROUP_NAME` alias) \
         so the plists, the installer and the enrollment gate cannot drift apart"
    );

    // Non-tautological: the alias must actually be wired to the shared
    // constant, or the assertion above would pass on a broker that had simply
    // spelled the literal differently.
    assert!(
        text.contains("sandbox_core::network::SANDBOXD_ACCOUNT"),
        "broker.rs must take its group name from the shared constant"
    );
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use sandbox_core::network::{SANDBOXD_ACCOUNT, render_vmnet_plist, vmnet_slot_daemon_label};

    /// The pool is eight fixed slots; the plists are generated one per slot.
    const POOL_SLOTS: u16 = 8;

    fn drift_script() -> PathBuf {
        repo_root().join("scripts/darwin-vmnet-drift.sh")
    }

    /// Ask a shell emitter to render slot `slot` and hand back its bytes.
    fn shell_emitter_plist(emitter: &str, slot: u16) -> String {
        let output = Command::new("python3")
            .arg(checker_path())
            .arg("--repo-root")
            .arg(repo_root())
            .arg("--emit-plist")
            .arg("--emitter")
            .arg(emitter)
            .arg("--slot")
            .arg(slot.to_string())
            .output()
            .expect("python3 must be on PATH");
        assert!(
            output.status.success(),
            "rendering slot {slot} with the {emitter} emitter failed.\n{}",
            describe(&output)
        );
        String::from_utf8(output.stdout).expect("plists are UTF-8")
    }

    /// All three emitters must produce the same bytes for the same slot. The
    /// Rust renderer is the reference; the two shell emitters are rendered by
    /// their own generators, extracted from the Makefile and install.sh.
    #[test]
    fn all_three_emitters_render_identical_plists() {
        for slot in 0..POOL_SLOTS {
            let reference = render_vmnet_plist(slot, SANDBOXD_ACCOUNT);
            for emitter in ["make", "install-sh"] {
                let rendered = shell_emitter_plist(emitter, slot);
                assert_eq!(
                    reference, rendered,
                    "slot {slot}: the {emitter} emitter does not render what network.rs renders"
                );
            }
        }
    }

    /// One argv entry per line, exactly as the plist on disk declares it.
    fn plist_argv(plist_path: &Path) -> Vec<String> {
        let mut argv = Vec::new();
        for i in 0..64 {
            let output = Command::new("plutil")
                .arg("-extract")
                .arg(format!("ProgramArguments.{i}"))
                .arg("raw")
                .arg("-o")
                .arg("-")
                .arg(plist_path)
                .output()
                .expect("plutil is part of the macOS base system");
            if !output.status.success() {
                break;
            }
            argv.push(
                String::from_utf8_lossy(&output.stdout)
                    .trim_end_matches('\n')
                    .to_string(),
            );
        }
        assert!(!argv.is_empty(), "plist has no ProgramArguments");
        argv
    }

    /// A `launchctl print system/<label>` transcript carrying `argv`.
    ///
    /// The surrounding keys are trimmed but the shape is the real one: the
    /// argv lives in a tab-indented `arguments = { ... }` block, and the block
    /// is followed by more keys — so a parser that stops at the first closing
    /// brace, or that runs to end of file, gets a different answer than one
    /// that closes on a brace alone on its line.
    fn launchctl_transcript(label: &str, argv: &[String]) -> String {
        let mut out = format!(
            "system/{label} = {{\n\tactive count = 1\n\tpath = /Library/LaunchDaemons/{label}.plist\n\targuments = {{\n"
        );
        for arg in argv {
            out.push_str("\t\t");
            out.push_str(arg);
            out.push('\n');
        }
        out.push_str("\t}\n\tdefault environment = {\n\t\tPATH => /usr/bin:/bin\n\t}\n\tstate = running\n}\n");
        out
    }

    /// Write slot 0's plist plus a matching transcript into a temp dir.
    fn drift_fixture() -> (tempfile::TempDir, PathBuf, String, Vec<String>) {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let label = vmnet_slot_daemon_label(0);
        let plist = tmp.path().join(format!("{label}.plist"));
        fs::write(&plist, render_vmnet_plist(0, SANDBOXD_ACCOUNT)).expect("write plist");
        let argv = plist_argv(&plist);
        (tmp, plist, label, argv)
    }

    fn run_drift(label: &str, plist: &Path, transcript: Option<&Path>) -> Output {
        let mut cmd = Command::new(drift_script());
        cmd.arg(label).arg(plist);
        if let Some(t) = transcript {
            cmd.arg("--launchctl-output").arg(t);
        }
        cmd.output().expect("run darwin-vmnet-drift.sh")
    }

    /// The baseline: a job running exactly what its plist says is in sync.
    ///
    /// This is also the regression test for the argv block parser. Our own
    /// argv contains a literal `}` — the codesign guard's
    /// `|| { ...; exit 1; }` — so a parser that ends the block at any `}`
    /// truncates the argv mid-argument and reports a spurious drift here.
    #[test]
    fn drift_script_reports_in_sync_when_the_argv_matches() {
        let (tmp, plist, label, argv) = drift_fixture();
        assert!(
            argv.iter().any(|a| a.contains("exit 1; }")),
            "the fixture no longer exercises the embedded-brace case; argv: {argv:?}"
        );
        let transcript = tmp.path().join("print");
        fs::write(&transcript, launchctl_transcript(&label, &argv)).expect("write transcript");

        let output = run_drift(&label, &plist, Some(&transcript));
        assert_eq!(
            output.status.code(),
            Some(0),
            "a job running its own plist's argv was reported as drifted.\n{}",
            describe(&output)
        );
    }

    /// The case the old "is it loaded?" check could not see: launchd is
    /// serving a definition that no longer matches the plist on disk.
    #[test]
    fn drift_script_detects_a_stale_loaded_definition() {
        let (tmp, plist, label, argv) = drift_fixture();
        let stale: Vec<String> = argv
            .iter()
            .map(|a| {
                a.replace(
                    &format!("--socket-group={SANDBOXD_ACCOUNT}"),
                    "--socket-group=_sandbox",
                )
            })
            .collect();
        assert_ne!(argv, stale, "the perturbation did not change the argv");
        let transcript = tmp.path().join("print");
        fs::write(&transcript, launchctl_transcript(&label, &stale)).expect("write transcript");

        let output = run_drift(&label, &plist, Some(&transcript));
        assert_eq!(
            output.status.code(),
            Some(3),
            "a loaded definition that no longer matches its plist was not reported \
             as drift.\n{}",
            describe(&output)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&label) && stderr.contains("--socket-group=_sandbox "),
            "the drift report should show what is actually loaded.\n{}",
            describe(&output)
        );
    }

    /// A label nothing has ever bootstrapped is "not loaded" (4), which is a
    /// different answer from "loaded but stale" (3) — the caller bootstraps in
    /// one case and boots out first in the other. Read-only: `launchctl print`
    /// does not touch the job it is asked about.
    #[test]
    fn drift_script_reports_not_loaded_for_an_unknown_label() {
        let (_tmp, plist, _label, _argv) = drift_fixture();
        let output = run_drift("io.sandboxd.vmnet.drift-lint.absent", &plist, None);
        assert_eq!(
            output.status.code(),
            Some(4),
            "an unbootstrapped label should be reported as not loaded.\n{}",
            describe(&output)
        );
    }

    /// Unparseable `launchctl print` output is an error (1), never silently
    /// "in sync" — a comparison that cannot be made must not answer "equal".
    #[test]
    fn drift_script_errors_on_output_with_no_argv_block() {
        let (tmp, plist, label, _argv) = drift_fixture();
        let transcript = tmp.path().join("print");
        fs::write(
            &transcript,
            format!("system/{label} = {{\n\tstate = running\n}}\n"),
        )
        .expect("write transcript");

        let output = run_drift(&label, &plist, Some(&transcript));
        assert_eq!(
            output.status.code(),
            Some(1),
            "launchctl output with no arguments block must be an error, not a pass.\n{}",
            describe(&output)
        );
    }
}
