//! Lints for the `setup-dev-env` dependency graph.
//!
//! Setup steps probe the host for things earlier steps produce: an account, a
//! uid, a live vmnet socket. Two mistakes make such a probe worthless, and they
//! compound.
//!
//! The first is leaving the ordering implicit. Listing the producer before the
//! consumer in `setup-dev-env`'s prerequisite list reads like a dependency, and
//! GNU make honours it for a serial build — but only for a serial build. Under
//! `-j` make is free to start them together, so the consumer can run before the
//! thing it probes for exists.
//!
//! The second is treating the failed probe as a skip. A step that prints a
//! warning and exits 0 has not done its work, but `setup-dev-env` still ends in
//! `✓ complete`, and the consequence surfaces much later as an opaque
//! permission error with nothing pointing back at provisioning.
//!
//! Either alone is survivable. Together they are a setup run that reports
//! success and silently did not configure the host. These tests pin both
//! halves: the edges that must be declared, and the absence of the
//! warn-then-skip shape anywhere in the Makefile.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Repository root. `CARGO_MANIFEST_DIR` is `<repo>/sandboxd/sandbox-core`.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("sandbox-core lives two levels below the repository root")
        .to_path_buf()
}

fn makefile() -> String {
    let path = repo_root().join("Makefile");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// Fold backslash-continued lines into the logical lines make sees.
///
/// Both lints need this. The edge lint needs it so a rule whose prerequisites
/// wrap is not truncated; the warn-then-skip lint needs it because a recipe's
/// entire `if`/`then`/`else` chain is one logical line, and that is the unit in
/// which "printed a warning, then exited 0" is meaningful.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut pending: Option<(usize, String)> = None;

    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let continues = raw.ends_with('\\');
        let body = if continues {
            &raw[..raw.len() - 1]
        } else {
            raw
        };

        match pending.as_mut() {
            Some((_, acc)) => {
                acc.push(' ');
                acc.push_str(body.trim());
            }
            None => pending = Some((lineno, body.to_string())),
        }

        if !continues {
            out.push(pending.take().expect("pending was just set"));
        }
    }
    if let Some(last) = pending {
        out.push(last);
    }
    out
}

/// Map every target to the union of its declared prerequisites.
///
/// The union matters: make lets a target collect prerequisites from more than
/// one declaration, and this Makefile uses that to attach an edge from inside an
/// `ifeq`. Parsing only the rule that carries the recipe would miss those.
fn prerequisites(text: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for (_, line) in logical_lines(text) {
        // Rule lines start in column 0; recipe lines start with a tab.
        if line.starts_with(char::is_whitespace) || line.starts_with('#') {
            continue;
        }
        let Some((lhs, rhs)) = line.split_once(':') else {
            continue;
        };
        // Skip `VAR := ...`, `VAR ::= ...`, and pattern/static-pattern rules.
        if rhs.starts_with('=') || lhs.contains('=') || lhs.contains('%') {
            continue;
        }
        // Strip a trailing comment, and drop order-only prerequisites (`|`),
        // which express ordering rather than the edges under test.
        let rhs = rhs.split('#').next().unwrap_or("");
        let rhs = rhs.split('|').next().unwrap_or("");

        for target in lhs.split_whitespace() {
            if target.starts_with('.') {
                continue; // .PHONY and friends
            }
            graph
                .entry(target.to_string())
                .or_default()
                .extend(rhs.split_whitespace().map(str::to_string));
        }
    }
    graph
}

/// Edges that must stay declared, and what breaks when one is dropped.
///
/// Every entry is a step that probes at runtime for something another target
/// produces. The prose is the failure the edge prevents, so a future reader
/// deleting one has to argue with the specific consequence.
const REQUIRED_EDGES: &[(&str, &str, &str)] = &[
    (
        "setup-darwin-sandboxd-test-vmnet-group-membership",
        "setup-darwin-vmnet-daemons",
        "reads the vmnet socket's group off a live slot socket; without the edge \
         a parallel run reaches it before any socket exists and the e2e daemon \
         never gets vmnet access",
    ),
    (
        "setup-darwin-sandboxd-test-vmnet-group-membership",
        "setup-darwin-sandboxd-test-user",
        "enrolls that account into the socket group",
    ),
    (
        "stage-gateway-image-test",
        "setup-darwin-sandboxd-test-user",
        "the account's uid is the staging path",
    ),
    (
        "stage-lite-image-test",
        "setup-darwin-sandboxd-test-user",
        "the account's uid is the staging path",
    ),
    (
        "stage-route-helper-linux-aarch64-test",
        "setup-darwin-sandboxd-test-user",
        "the account's uid is the staging path",
    ),
    (
        "stage-lite-image",
        "setup-darwin-sandboxd-user",
        "SANDBOX_DAEMON_UID resolves through that account by default; the edge is \
         inside an ifeq and drops away when SANDBOX_DAEMON_USER is overridden",
    ),
    (
        "stage-route-helper-linux-aarch64",
        "setup-darwin-sandboxd-user",
        "SANDBOX_DAEMON_UID resolves through that account by default; the edge is \
         inside an ifeq and drops away when SANDBOX_DAEMON_USER is overridden",
    ),
    (
        "setup-darwin-vmnet-daemons",
        "setup-darwin-vmnet-plists",
        "bootstraps the plists that step writes",
    ),
    (
        "setup-darwin-vmnet-plists",
        "setup-darwin-sandboxd-user",
        "refuses to emit a plist naming an account that does not resolve",
    ),
];

#[test]
fn setup_steps_declare_the_producers_they_probe_for() {
    let graph = prerequisites(&makefile());

    // Guard the parser before trusting it: an extractor that silently returns
    // nothing would make every assertion below pass against an empty map.
    assert!(
        graph.len() > 50,
        "parsed only {} targets out of the Makefile — the rule parser is broken, \
         and a broken parser makes this whole lint vacuous",
        graph.len()
    );

    let mut failures = Vec::new();
    for (target, required, why) in REQUIRED_EDGES {
        match graph.get(*target) {
            None => failures.push(format!(
                "target `{target}` is not declared in the Makefile at all — renamed or removed?\n     \
                 It needed `{required}` as a prerequisite because it {why}."
            )),
            Some(prereqs) if !prereqs.contains(*required) => failures.push(format!(
                "`{target}` no longer declares `{required}` as a prerequisite.\n     \
                 It {why}.\n     \
                 Ordering the two in setup-dev-env's prerequisite list is not a \
                 substitute: make honours that order for a serial build and \
                 explicitly does not under `-j`.\n     \
                 Declared prerequisites are: {}",
                prereqs.iter().cloned().collect::<Vec<_>>().join(" ")
            )),
            Some(_) => {}
        }
    }

    assert!(
        failures.is_empty(),
        "setup-dev-env dependency edges have been dropped:\n  - {}",
        failures.join("\n  - ")
    );
}

#[test]
fn no_setup_step_warns_and_then_reports_success() {
    let text = makefile();

    let offenders: Vec<String> = logical_lines(&text)
        .into_iter()
        .filter(|(_, line)| line.starts_with('\t'))
        .filter(|(_, line)| line.contains("WARNING") && line.contains("exit 0"))
        .map(|(lineno, line)| {
            let excerpt: String = line.trim().chars().take(120).collect();
            format!("Makefile:{lineno}: {excerpt}...")
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "these recipe branches print a WARNING and then exit 0, so the step \
         reports success without having done its work and setup-dev-env still \
         ends in `✓ complete`:\n  {}\n\n\
         A step that could not do its work must exit non-zero. If the skip is \
         genuinely correct — the platform does not need the effect, or there is \
         nothing to do — say that plainly instead of calling it a WARNING, so \
         the line does not read as a swallowed failure.",
        offenders.join("\n  ")
    );
}
