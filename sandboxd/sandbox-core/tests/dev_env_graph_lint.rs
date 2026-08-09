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
//!
//! A third variant of the same defect has nothing to do with ordering. The
//! steps that enroll the *invoking operator* read `$USER` to learn who that is,
//! and under `sudo make` they get `root`. Skipping in that case is the same
//! trap: no membership is granted, no sudoers fragment is written, and the run
//! still reports success. The remaining tests pin the refusal — once at the
//! `setup-dev-env` entry point, and once per step for the direct invocation
//! that bypasses it.

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
/// Three of the four lints here need this. The edge lint needs it so a rule
/// whose prerequisites wrap is not truncated; the warn-then-skip lint needs it
/// because a recipe's entire `if`/`then`/`else` chain is one logical line, and
/// that is the unit in which "printed a warning, then exited 0" is meaningful;
/// the operator-identity lint needs it for the same reason, to keep each guard's
/// condition attached to its remedy. Each of the three calls
/// `assert_fold_folded` before trusting what this returns.
///
/// Continuation is decided by the **parity** of the trailing backslash run, not
/// by "ends in a backslash". A line ending `\\` is a literal backslash and the
/// line ends there — the first backslash escapes the second, so nothing is left
/// to escape the newline. Verified against GNU make 3.81 for runs of one through
/// five: odd continues, even does not.
///
/// Treating `\\` as a continuation is not a harmless over-join. It welds the
/// next line onto this one, which invents prerequisites on the current target,
/// deletes the next rule from the graph entirely, and — where the swallowed line
/// was a recipe — hides it from every filter keyed on the leading tab. The
/// warn-then-skip lint stops seeing an offender that is right there in the file.
///
/// What this deliberately does not model: for an odd run longer than one, make
/// also rewrites the backslashes that precede the escaping one, and this strips
/// only the escaping one. The residual is bounded and one-directional — a
/// prerequisite name keeps trailing backslashes make would have removed, so it
/// fails to match a pinned edge rather than spuriously matching one. Left
/// unmodelled on purpose: make's collapsing rule for long runs did not fall out
/// of measurement cleanly (runs of 1, 3 and 5 retained 0, 0 and 1 backslashes),
/// and implementing a guess at it would put an unverified model in the place
/// where the verified parity rule now sits.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut pending: Option<(usize, String)> = None;

    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let trailing_backslashes = raw.len() - raw.trim_end_matches('\\').len();
        let continues = trailing_backslashes % 2 == 1;
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

/// Pins the fold's continuation rule, so a future "simplification" back to
/// `ends_with('\\')` fails here rather than silently corrupting the graph.
///
/// Each case was checked against real GNU make before being written down.
#[test]
fn the_fold_decides_continuation_by_backslash_parity() {
    let even = "target-A: dep-1\\\\\ntarget-B: dep-2\n";
    assert_eq!(
        logical_lines(even).len(),
        2,
        "a line ending in two backslashes is a literal backslash and ends there, \
         so these two rules must stay separate"
    );
    let graph = prerequisites(even);
    assert!(
        graph.contains_key("target-B"),
        "the rule following a line that ends in two backslashes was swallowed — \
         over-joining deletes rules from the graph as well as inventing \
         prerequisites on the rule before them: {graph:?}"
    );
    assert!(
        !graph["target-A"].contains("dep-2"),
        "`target-A` acquired a prerequisite the Makefile declares on another \
         target: {graph:?}"
    );

    let odd = "target-C: dep-3\\\n  dep-4\n";
    assert_eq!(
        logical_lines(odd).len(),
        1,
        "a single trailing backslash escapes the newline and continues the line"
    );
    assert!(
        prerequisites(odd)["target-C"].contains("dep-4"),
        "a wrapped prerequisite list was truncated"
    );

    // The consequence that reaches the warn-then-skip lint: a mis-join absorbs a
    // tab-prefixed recipe line into a rule line, and every filter keyed on the
    // leading tab then skips it. The offender stays in the file and stops being
    // reported.
    let recipe = "warn-step: dep-5\\\\\n\t@echo \"WARNING: x\"; exit 0\n";
    assert_eq!(
        logical_lines(recipe)
            .into_iter()
            .filter(|(_, line)| line.starts_with('\t'))
            .count(),
        1,
        "the recipe line stopped being a recipe line, which hides it from the \
         warn-then-skip and operator-identity lints entirely"
    );
}

/// Positive control on the fold: assert something was actually joined.
///
/// Every test here that consumes `logical_lines` calls this at its own top,
/// before trusting anything the fold returned. Counting lines cannot detect a
/// fold that stopped folding — the counts go *up* in that state — so a count is
/// the wrong instrument regardless of the threshold.
///
/// Threshold-free by construction: if any continuation was joined, that line is
/// longer than the longest single physical line; if folding stopped, the two
/// maxima are equal. Measured 2550 against 1044 when this was written.
///
/// Called explicitly by each consumer rather than hidden inside
/// `logical_lines`, for two reasons. The degradation harnesses that prove these
/// lints work do so by driving a deliberately broken fold, and an assertion
/// inside the fold would fight them. And a test that stops consuming the fold
/// should drop its own call rather than keep inheriting a check it no longer
/// needs.
///
/// This is deliberately not the coupling argument rejected elsewhere in this
/// file. That argument was "test A's control protects test B", which holds only
/// while both keep using the same helper and evaporates without a failure. Here
/// each test carries the control itself; sharing the assertion is code reuse,
/// not shared protection.
///
/// This detects exactly one failure direction: a fold that **stops joining**.
/// Under that degradation the three consumers behave differently, measured
/// rather than assumed, and only one of them was ever vacuous:
///
/// - `no_setup_step_warns_and_then_reports_success` **passed silently**, which
///   is why this control exists. Its assertion is "no offenders found", and its
///   signal is manufactured by the join: `WARNING` and `exit 0` reach the same
///   string only once continuations are collapsed.
/// - `operator_enrolling_steps_refuse…` fails, reporting every site as an
///   offender, because unfolding separates each guard's condition from the
///   remedy on the next physical line.
/// - `setup_steps_declare_the_producers_they_probe_for` cannot go vacuous *in
///   this direction*. Its assertion is "these specific edges are present", and a
///   fold that stops joining can only *remove* edges, so anything it checks
///   fails closed. It passes under a stopped fold today only because no pinned
///   edge's declaration wraps; wrap one and it fails, loudly and by name, rather
///   than dropping the edge quietly.
///
/// So for the last two this control buys attribution rather than coverage: a
/// stopped fold reports itself as a stopped fold, instead of as seven unrouted
/// guards or a Makefile that dropped an edge it still declares.
///
/// The opposite direction — a fold that joins **more** than make would — is a
/// different failure with none of those properties, and **this control cannot
/// see it**. A spurious join makes some line longer, which is the very thing the
/// assertion below looks for, so it passes with more confidence than it has
/// earned. A mis-join also breaks the fail-closed argument above: welding the
/// next rule onto this one invents prerequisites the Makefile never declared and
/// deletes that next rule from the graph, so edges can appear as well as vanish.
/// It hides warn-then-skip offenders too, by absorbing a tab-prefixed recipe line
/// into a rule line that no leading-tab filter will match.
///
/// One such bug lived in the fold — `\\` treated as a continuation — and is
/// fixed. Fixing it does not close the class: nothing here establishes that no
/// other over-joining divergence from make's lexing exists, only that the known
/// one is gone. Read this control as covering the stopped direction and nothing
/// more.
fn assert_fold_folded(text: &str) {
    let lines = logical_lines(text);
    let longest_folded = lines.iter().map(|(_, line)| line.len()).max().unwrap_or(0);
    let longest_physical = text.lines().map(str::len).max().unwrap_or(0);
    assert!(
        longest_folded > longest_physical,
        "the longest folded line ({longest_folded} chars) is no longer than the \
         longest physical line ({longest_physical}) — nothing was joined, so the \
         fold has stopped folding. Line counts do not catch this: they rise when \
         folding stops. Whatever this test went on to report, it was reading \
         physical lines, not the logical lines make sees"
    );
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
    let text = makefile();

    // This lint cannot go vacuous under a fold that stops joining — it asserts
    // specific edges are present, and unfolding can only remove edges — so the
    // control here is for attribution, not coverage. Pin an edge whose
    // prerequisite list wraps and a stopped fold makes this test blame the
    // Makefile for dropping an edge it still declares. A fold that *over*-joins
    // is a different matter; see `assert_fold_folded`.
    assert_fold_folded(&text);

    let graph = prerequisites(&text);

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

/// Catches the literal `WARNING` + `exit 0` shape, and only that.
///
/// It is not a total detector for swallowed failures. A recipe can still report
/// success without doing its work by printing something other than `WARNING`
/// (`echo "skipping …"`), by ending a command in `|| true`, by prefixing the
/// recipe line with `-`, or by discarding stderr. Widening the pattern to reach
/// those trades false negatives for false positives — several are legitimate in
/// cleanup and probe recipes — so the line is drawn here deliberately. Anyone
/// extending this should know which edge they are standing on.
#[test]
fn no_setup_step_warns_and_then_reports_success() {
    let text = makefile();

    // This lint's signal is manufactured by the join, so the control on the fold
    // comes before anything else here. Neither floor below can stand in for it:
    // both count lines, and an unfolded extractor makes both counts go *up*.
    assert_fold_folded(&text);

    let lines = logical_lines(&text);

    // Guard the extractor before trusting it, for the same reason the edge lint
    // does: this assertion is satisfied by finding nothing, so a fold that
    // returned nothing would pass it silently. Sharing `logical_lines` with that
    // lint is not protection — that only holds while both tests keep using the
    // same helper, and it disappears without a failure the moment one stops.
    assert!(
        lines.len() > 500,
        "folded only {} logical lines out of the Makefile — the line folder is \
         broken, and a broken folder makes this lint vacuous rather than failing",
        lines.len()
    );

    let total = lines.len();
    let recipe_lines: Vec<(usize, String)> = lines
        .into_iter()
        .filter(|(_, line)| line.starts_with('\t'))
        .collect();

    // Second floor, on the filtered set — the stage the first floor cannot see.
    // A fold that kept every line but stopped preserving the leading tab reports
    // the same plausible total and hands this lint an empty set, so the
    // assertion below would pass by observing nothing. Flooring one stage of a
    // two-stage extractor leaves the guard resting on an invariant nothing
    // checks.
    assert!(
        recipe_lines.len() > 75,
        "only {} of {total} folded lines start with a tab — the fold has stopped \
         preserving recipe lines, so this lint has nothing left to check and \
         would report success by finding nothing",
        recipe_lines.len()
    );

    let offenders: Vec<String> = recipe_lines
        .iter()
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

/// Recipe lines that decide what to do when `$USER` is absent or `root`.
///
/// Discovered rather than listed: a new step that enrolls the operator picks up
/// the same guard for free, and one that is deleted does not leave a stale
/// entry behind. The shell spelling is stable across all of them.
fn operator_identity_branches(text: &str) -> Vec<(usize, String)> {
    logical_lines(text)
        .into_iter()
        .filter(|(_, line)| line.starts_with('\t'))
        .filter(|(_, line)| line.contains(r#"[ "$$USER" = "root" ]"#))
        .collect()
}

#[test]
fn operator_enrolling_steps_refuse_instead_of_skipping_when_there_is_no_operator() {
    let text = makefile();

    // Like the edge lint, this one fails rather than passes under a broken fold —
    // unfolding splits each guard's condition from the remedy on the next
    // physical line, so all seven sites report as offenders. The control is here
    // so that failure says "the fold broke" instead of accusing seven correct
    // guards of skipping the helper.
    assert_fold_folded(&text);

    let branches = operator_identity_branches(&text);

    // Anti-vacuous floor. The assertion below is "every match does X", which a
    // matcher that finds nothing passes trivially. This is a floor, not a pinned
    // count — deleting one of these steps should not fail the test, but a
    // matcher that stops matching should.
    //
    // That draws a deliberate boundary, and it is a boundary rather than an
    // oversight: this catches a guard that has been *weakened* — still matching,
    // no longer routing through the helper — but not one deleted outright, which
    // stops matching while the remaining sites still clear the floor. That is
    // the accepted trade of discovering the sites instead of listing them: a new
    // enrolling step is covered for free and a removed one leaves no stale entry
    // behind. Pinning an exact count to close the gap would swap that live
    // property for a brittle one that fails on every legitimate add or remove.
    assert!(
        branches.len() >= 4,
        "found only {} recipe branches testing $USER for root/empty — the matcher \
         has stopped matching, which would make the assertion below vacuous",
        branches.len()
    );

    let offenders: Vec<String> = branches
        .iter()
        .filter(|(_, line)| !line.contains("no_operator_identity"))
        .map(|(lineno, line)| {
            let excerpt: String = line.trim().chars().take(140).collect();
            format!("Makefile:{lineno}: {excerpt}...")
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "these steps enroll the invoking operator but do not route the \
         no-operator case through $(call no_operator_identity,<target>):\n  {}\n\n\
         Printing `✓ already configured … skipped (no non-root $USER set)` here \
         is a green line for an effect that did not happen — the operator never \
         joins the group, and it resurfaces later as an unreachable daemon \
         socket or a sudo password prompt mid-e2e-run. Fail instead, and use the \
         shared helper so all of these agree on what the operator is told to do \
         next.",
        offenders.join("\n  ")
    );
}

/// The pieces of the entry-point refusal, and why each one carries weight.
const ROOT_REFUSAL_REQUIREMENTS: &[(&str, &str)] = &[
    (
        "ifeq ($(shell id -u),0)",
        "the guard must key on the real uid, not on $USER — `sudo -E make` \
         preserves $USER while still running as root",
    ),
    (
        "$(error $(DEV_ENV_ROOT_REFUSAL))",
        "it must be a parse-time $(error): make runs a target's prerequisites \
         before its recipe, so a check inside the setup-dev-env recipe would \
         fire only after the whole run had already happened",
    ),
    (
        "$(filter setup-dev-env,$(DEV_ENV_GOALS))",
        "it must be gated on the goal, so that unrelated targets — `make test` \
         in a root container, say — stay runnable as root",
    ),
    (
        "sudo -u $(SUDO_USER) make setup-dev-env",
        "the refusal must name the operator concretely from $SUDO_USER rather \
         than saying `do not run as root` and leaving them to work it out",
    ),
];

#[test]
fn setup_dev_env_refuses_to_run_as_root() {
    let text = makefile();

    // No `assert_fold_folded` here, and that is a decision rather than an
    // omission: this is the one lint that never touches the fold. It substring-
    // matches the raw text, so folding cannot affect what it sees. Adding the
    // control would assert something this test does not depend on.
    let missing: Vec<String> = ROOT_REFUSAL_REQUIREMENTS
        .iter()
        .filter(|(needle, _)| !text.contains(*needle))
        .map(|(needle, why)| format!("`{needle}` is gone.\n     It was there because {why}."))
        .collect();

    assert!(
        missing.is_empty(),
        "the setup-dev-env root refusal has been weakened:\n  - {}\n\n\
         Running the whole setup under sudo leaves cargo artifacts and every \
         operator-owned path it creates owned by root, and gives the \
         operator-enrolling steps no operator to enroll. Falling back to \
         $SUDO_USER instead of refusing would make a root-invoked run look \
         supported while staying broken in the ways the fallback does not \
         address.",
        missing.join("\n  - ")
    );
}
