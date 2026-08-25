//! The operator-declared export roots: what the file may say, and what the
//! agent answers when it reads one.
//!
//! # Why this is an integration test and not a `mod tests` in `protocol.rs`
//!
//! `protocol.rs` is compiled twice — once into the `sandbox_agent_protocol`
//! library target and once into the `sandbox-agent` binary, which declares its
//! own `mod protocol`. Unit tests written inside it therefore run twice and
//! count twice, which is how a workspace test baseline stops being comparable
//! across revisions; the crate's `lib.rs` records the measurement that
//! established this for the sibling `validation` module. A test file under
//! `tests/` links the library target only, so each assertion here runs once.
//!
//! The cost is that only the library's public exports are reachable. That is
//! the right surface anyway: the daemon consumes these same three functions
//! across a crate boundary, so testing them through the export is testing what
//! the daemon actually calls.

#![cfg(target_os = "macos")]

use sandbox_agent_protocol::{
    EXPORT_ROOTS_RELATIVE_PATH, MAX_EXPORT_ROOTS, read_export_roots, validate_declared_root,
    validate_declared_root_set,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A temp directory whose path is already in canonical form.
///
/// On macOS the system temp directory is reached through `/var`, a symlink to
/// `/private/var`. A declared root must be its own canonical spelling, so a
/// test that declared `tempdir().path()` verbatim would be refused for the
/// symlink reason rather than exercising whatever it meant to exercise — and
/// would read as a bug in the validator. Canonicalising here is what keeps the
/// symlink case a deliberate test below rather than an accident in every other
/// one.
fn canonical_tempdir() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir
        .path()
        .canonicalize()
        .expect("canonicalize tempdir")
        .to_str()
        .expect("tempdir path is UTF-8")
        .to_string();
    (dir, path)
}

/// Write `contents` to the declared-roots file inside `home`, creating the
/// intermediate directories the real path has.
fn write_declaration(home: &str, contents: &str) -> String {
    let source = format!("{home}/{EXPORT_ROOTS_RELATIVE_PATH}");
    let parent = std::path::Path::new(&source)
        .parent()
        .expect("the relative path has a directory component");
    std::fs::create_dir_all(parent).expect("create config dir");
    std::fs::write(&source, contents).expect("write declaration");
    source
}

fn owned(roots: &[&str]) -> Vec<String> {
    roots.iter().map(|r| (*r).to_string()).collect()
}

/// `expect_err` with a lazily-built message.
///
/// Several assertions below loop over inputs, and `expect_err` takes a `&str` —
/// so a panic message naming *which* input failed to be refused has to be built
/// per iteration. Without it a loop failure reports only that something in the
/// loop was accepted, which is the half of the finding that costs the most to
/// recover by hand.
fn expect_refused<T: std::fmt::Debug>(result: Result<T, String>, what: String) -> String {
    match result {
        Ok(value) => panic!("{what}, got Ok({value:?})"),
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// One root, in isolation
// ---------------------------------------------------------------------------

#[test]
fn a_plain_absolute_directory_is_a_valid_root() {
    validate_declared_root("/Users/alice/workspaces").expect("a plain absolute path is valid");
}

#[test]
fn a_trailing_slash_is_accepted() {
    // The comparisons that matter — duplicate detection, nesting, containment —
    // all trim it, so refusing the spelling would reject a root that behaves
    // identically to one that is accepted.
    validate_declared_root("/Users/alice/workspaces/").expect("a trailing slash is not an error");
}

#[test]
fn a_relative_root_is_refused() {
    let err = validate_declared_root("workspaces").expect_err("a relative root has no meaning");
    assert!(err.contains("absolute"), "got: {err}");
}

/// `/` is not merely a large export. `root_spelling` in the containment check
/// trims trailing slashes, so `/` collapses to the empty string and every
/// containment test against it answers *false* — the failure would read as
/// "nothing is inside this root" at a site far from the declaration. Each
/// spelling that collapses the same way has to be refused the same way.
#[test]
fn the_filesystem_root_is_refused_however_it_is_spelled() {
    for spelling in ["/", "//", "///"] {
        let err = expect_refused(
            validate_declared_root(spelling),
            format!("{spelling:?} must be refused"),
        );
        assert!(
            err.contains("entire"),
            "the refusal must name the consequence, got: {err}"
        );
    }
}

#[test]
fn non_normalised_components_are_refused() {
    for spelling in ["/Users/alice/../bob", "/Users/./alice", "/Users//alice"] {
        expect_refused(
            validate_declared_root(spelling),
            format!("{spelling:?} must be refused"),
        );
    }
}

#[test]
fn a_dot_dot_component_refusal_says_to_declare_the_plain_path() {
    let err = validate_declared_root("/Users/alice/../bob").expect_err("`..` must be refused");
    assert!(err.contains("\"..\""), "got: {err}");
    assert!(err.contains("plain absolute path"), "got: {err}");
}

/// The two interpolation sinks are separate rules with separate messages,
/// because the fix differs: one is a docker `--mount` option list, the other a
/// quoted YAML scalar in the gateway Lima template. A root is refused at
/// declaration time so neither sink is the first place an operator hears of it.
#[test]
fn characters_that_are_syntax_at_an_interpolation_sink_are_refused() {
    for (spelling, sink) in [
        ("/Users/alice/a,b", "docker"),
        ("/Users/alice/a=b", "docker"),
        ("/Users/alice/a\"b", "YAML"),
        ("/Users/alice/a\\b", "YAML"),
    ] {
        let err = expect_refused(
            validate_declared_root(spelling),
            format!("{spelling:?} must be refused"),
        );
        assert!(
            err.contains(sink),
            "{spelling:?} should be refused for the {sink} sink, got: {err}"
        );
    }
}

#[test]
fn a_newline_in_a_root_is_refused() {
    // It survives JSON, and inside a `mounts:` entry it ends the entry — the
    // one control character with a concrete escape behind it.
    let err = validate_declared_root("/Users/alice/ws\nmountType: virtiofs")
        .expect_err("a newline must be refused");
    assert!(err.contains("control character"), "got: {err}");
}

// ---------------------------------------------------------------------------
// The set
// ---------------------------------------------------------------------------

/// The property the folded-in per-member pass exists for.
///
/// A consumer re-validating a report that arrived over the wire has no loop of
/// its own to run the member check in. If the set entry point checked only the
/// set-level properties, exactly the characters the member check refuses would
/// reach the template.
#[test]
fn the_set_check_also_runs_the_per_member_check() {
    let err = validate_declared_root_set(&owned(&["/Users/alice/a\"b"]))
        .expect_err("a member that fails on its own must fail through the set entry point too");
    assert!(err.contains("YAML"), "got: {err}");
}

#[test]
fn disjoint_roots_are_accepted() {
    validate_declared_root_set(&owned(&[
        "/Users/alice/workspaces",
        "/Users/alice/scratch",
        "/opt/shared",
    ]))
    .expect("three disjoint roots are a valid set");
}

/// A prefix of the *string* is not a prefix of the *tree*. `/tmp/xy` is not
/// inside `/tmp/x`, and refusing the pair would reject a legitimate
/// declaration.
#[test]
fn a_shared_string_prefix_is_not_nesting() {
    validate_declared_root_set(&owned(&["/tmp/x", "/tmp/xy"]))
        .expect("sibling directories with a shared prefix do not nest");
}

#[test]
fn a_duplicate_root_is_refused() {
    let err = validate_declared_root_set(&owned(&["/opt/shared", "/opt/shared"]))
        .expect_err("a duplicate must be refused");
    assert!(err.contains("twice"), "got: {err}");
}

#[test]
fn a_duplicate_spelled_with_a_trailing_slash_is_still_a_duplicate() {
    let err = validate_declared_root_set(&owned(&["/opt/shared", "/opt/shared/"]))
        .expect_err("the same directory spelled two ways is still declared twice");
    assert!(err.contains("twice"), "got: {err}");
}

/// Nesting is refused in both orders, and the message names the one to drop.
/// Which of the two the operator happened to write first is not information the
/// refusal may depend on.
#[test]
fn nesting_is_refused_in_either_order() {
    for pair in [
        ["/Users/alice/workspaces", "/Users/alice/workspaces/proj"],
        ["/Users/alice/workspaces/proj", "/Users/alice/workspaces"],
    ] {
        let err = expect_refused(
            validate_declared_root_set(&owned(&pair)),
            format!("{pair:?} nests and must be refused"),
        );
        assert!(
            err.contains("/Users/alice/workspaces/proj") && err.contains("drop the inner"),
            "the refusal must name the inner root and say to drop it, got: {err}"
        );
    }
}

#[test]
fn the_maximum_number_of_roots_is_accepted_and_one_more_is_not() {
    let at_limit: Vec<String> = (0..MAX_EXPORT_ROOTS)
        .map(|i| format!("/opt/r{i}"))
        .collect();
    validate_declared_root_set(&at_limit).expect("exactly the maximum is allowed");

    let over_limit: Vec<String> = (0..MAX_EXPORT_ROOTS + 1)
        .map(|i| format!("/opt/r{i}"))
        .collect();
    let err = validate_declared_root_set(&over_limit).expect_err("one over the maximum is refused");
    assert!(
        err.contains(&MAX_EXPORT_ROOTS.to_string()),
        "the refusal must name the limit, got: {err}"
    );
    assert!(
        err.contains("9p"),
        "the refusal must say what the limit is about, got: {err}"
    );
}

#[test]
fn an_empty_set_is_valid() {
    validate_declared_root_set(&[]).expect("declaring nothing is a valid declaration");
}

// ---------------------------------------------------------------------------
// Reading the file
// ---------------------------------------------------------------------------

/// Absent is not an error. An operator who has never written the file exports
/// nothing, which is a normal state — and the report still names where the
/// agent looked, so a home-directory divergence stays visible instead of
/// reading exactly like "declared nothing".
#[test]
fn an_absent_file_reads_as_an_empty_declaration() {
    let (_home, home_path) = canonical_tempdir();
    let report = read_export_roots(&home_path).expect("an absent file is not an error");
    assert!(report.roots.is_empty(), "got: {:?}", report.roots);
    assert_eq!(
        report.source,
        format!("{home_path}/{EXPORT_ROOTS_RELATIVE_PATH}")
    );
}

#[test]
fn a_trailing_slash_on_the_home_directory_does_not_double_the_separator() {
    let (_home, home_path) = canonical_tempdir();
    let report = read_export_roots(&format!("{home_path}/")).expect("read");
    assert_eq!(
        report.source,
        format!("{home_path}/{EXPORT_ROOTS_RELATIVE_PATH}")
    );
}

#[test]
fn an_empty_object_reads_as_an_empty_declaration() {
    let (_home, home_path) = canonical_tempdir();
    write_declaration(&home_path, "{}");
    let report = read_export_roots(&home_path).expect("`{}` is a valid declaration of nothing");
    assert!(report.roots.is_empty(), "got: {:?}", report.roots);
}

/// Absent and malformed must not collapse into one answer. A typo that read as
/// "declared nothing" would be indistinguishable from success, and the operator
/// would see only sessions that mysteriously refuse their paths.
#[test]
fn a_malformed_file_is_an_error_naming_the_file() {
    let (_home, home_path) = canonical_tempdir();
    let source = write_declaration(&home_path, "{\"roots\": [");
    let err = read_export_roots(&home_path).expect_err("malformed JSON is an error");
    assert!(err.contains(&source), "got: {err}");
    assert!(err.contains("export-roots JSON"), "got: {err}");
}

#[test]
fn an_unknown_key_does_not_invalidate_the_roots_that_parse() {
    // The one struct in the protocol a human types by hand. A newer-schema or
    // typo'd key must not discard correctly-spelled roots; each root is
    // validated on its own, so an ignored key cannot widen anything.
    let (_home, home_path) = canonical_tempdir();
    let (_root, root_path) = canonical_tempdir();
    write_declaration(
        &home_path,
        &format!("{{\"roots\": [\"{root_path}\"], \"mode\": \"future\"}}"),
    );
    let report = read_export_roots(&home_path).expect("an unknown key is tolerated");
    assert_eq!(report.roots, vec![root_path]);
}

#[test]
fn declared_directories_that_exist_are_returned_in_declaration_order() {
    let (_home, home_path) = canonical_tempdir();
    let (_first, first_path) = canonical_tempdir();
    let (_second, second_path) = canonical_tempdir();
    write_declaration(
        &home_path,
        &format!("{{\"roots\": [\"{first_path}\", \"{second_path}\"]}}"),
    );
    let report = read_export_roots(&home_path).expect("two existing directories are usable");
    assert_eq!(report.roots, vec![first_path, second_path]);
}

#[test]
fn a_root_that_does_not_exist_is_refused() {
    let (_home, home_path) = canonical_tempdir();
    write_declaration(
        &home_path,
        &format!("{{\"roots\": [\"{home_path}/no-such-directory\"]}}"),
    );
    let err = read_export_roots(&home_path).expect_err("a missing directory is not usable");
    assert!(err.contains("not usable"), "got: {err}");
    assert!(err.contains("no-such-directory"), "got: {err}");
}

#[test]
fn a_root_that_is_a_file_is_refused_as_not_a_directory() {
    let (_home, home_path) = canonical_tempdir();
    let file = format!("{home_path}/a-file");
    std::fs::write(&file, "not a directory").expect("write file");
    write_declaration(&home_path, &format!("{{\"roots\": [\"{file}\"]}}"));
    let err = read_export_roots(&home_path).expect_err("a regular file is not an export root");
    assert!(err.contains("not a directory"), "got: {err}");
}

/// A root reached through a symlink exports one subtree while being reasoned
/// about as another: the gateway template mounts the declared spelling and
/// every containment check compares against the declared spelling. The refusal
/// names both spellings, so the fix — declare the target — is in the message.
#[test]
fn a_symlinked_root_is_refused_and_the_refusal_names_both_spellings() {
    let (_home, home_path) = canonical_tempdir();
    let (_target, target_path) = canonical_tempdir();
    let link = format!("{home_path}/link-to-target");
    std::os::unix::fs::symlink(&target_path, &link).expect("symlink");
    write_declaration(&home_path, &format!("{{\"roots\": [\"{link}\"]}}"));

    let err = read_export_roots(&home_path).expect_err("a symlinked root is refused");
    assert!(err.contains(&link), "got: {err}");
    assert!(err.contains(&target_path), "got: {err}");
    assert!(err.contains("declare the resolved path"), "got: {err}");
}

/// The set-level rules apply to what the file says, not only to a set a caller
/// assembles by hand — the read is the only path an operator's declaration
/// takes into the daemon.
#[test]
fn set_level_rules_apply_to_the_file_as_written() {
    let (_home, home_path) = canonical_tempdir();
    let (_outer, outer_path) = canonical_tempdir();
    let inner_path = format!("{outer_path}/inner");
    std::fs::create_dir(&inner_path).expect("create inner");
    write_declaration(
        &home_path,
        &format!("{{\"roots\": [\"{outer_path}\", \"{inner_path}\"]}}"),
    );

    let err = read_export_roots(&home_path).expect_err("a nested pair in the file is refused");
    assert!(err.contains("drop the inner"), "got: {err}");
}
