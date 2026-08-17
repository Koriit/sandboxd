//! The enrollment script and the daemon must name the same things.
//!
//! `scripts/darwin-operator-group.sh` *creates* per-operator vmnet slot
//! groups and records each operator's range on the group record;
//! `sandbox-core::vmnet_assignment` *reads* them back. Neither can import
//! from the other — one is POSIX shell that ships standalone, the other is
//! Rust — so the group-name prefix, the range attribute and the
//! service-account list are declared twice.
//!
//! A drift between the two declarations is silent in the worst possible way.
//! Enrollment keeps succeeding, the groups keep being created, and the daemon
//! simply stops recognising them: every enrolled operator's slots read as
//! still-shared or as unassignable, which surfaces as capacity quietly going
//! missing rather than as anything that looks like a bug. These tests are the
//! tie.

use std::fs;
use std::path::{Path, PathBuf};

use sandbox_core::vmnet_assignment::{
    OPERATOR_GROUP_PREFIX, SERVICE_ACCOUNTS, SLOT_RANGE_ATTRIBUTE,
};

/// Repository root. `CARGO_MANIFEST_DIR` is `<repo>/sandboxd/sandbox-core`.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("sandbox-core lives two levels below the repository root")
        .to_path_buf()
}

fn enrollment_script() -> String {
    let path = repo_root().join("scripts/darwin-operator-group.sh");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()))
}

/// Read a `NAME="value"` assignment out of the script.
fn shell_assignment(script: &str, name: &str) -> String {
    let prefix = format!("{name}=\"");
    let line = script
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| {
            panic!(
                "scripts/darwin-operator-group.sh no longer assigns {name}. \
                 Either it was renamed — in which case this lint and \
                 sandbox-core::vmnet_assignment need the new name — or the \
                 declaration moved somewhere this extractor cannot see, which \
                 would leave the two sides free to drift unchecked."
            )
        });
    line[prefix.len()..]
        .split('"')
        .next()
        .expect("a quoted shell assignment has a closing quote")
        .to_string()
}

/// The prefix the daemon filters group names by must be the prefix the
/// script creates them with.
#[test]
fn the_group_prefix_matches_the_script_that_creates_the_groups() {
    let script = enrollment_script();
    assert_eq!(
        shell_assignment(&script, "GROUP_PREFIX"),
        OPERATOR_GROUP_PREFIX,
        "the enrollment script creates per-operator groups under one prefix and \
         the daemon lists them under another, so every enrolled operator's \
         range becomes invisible to the daemon while enrollment keeps reporting \
         success"
    );
}

/// The attribute the daemon reads must be the attribute the script writes.
#[test]
fn the_range_attribute_matches_the_script_that_writes_it() {
    let script = enrollment_script();
    assert_eq!(
        shell_assignment(&script, "SLOTS_ATTR"),
        SLOT_RANGE_ATTRIBUTE,
        "the daemon reads a slot range from an attribute the script does not \
         write; every enrolled group would report as having no recorded range"
    );
}

/// Both sides must exclude the same accounts from the operator count.
///
/// The count is what decides whether a slot is assignable, so an account one
/// side treats as an operator and the other does not turns a correctly
/// enrolled group into a multi-operator refusal — or the reverse, which is
/// worse: two real operators counted as one, and a slot awarded to whichever
/// of them the walk happened to see first.
#[test]
fn the_service_account_list_matches_the_scripts() {
    let script = enrollment_script();
    let mut from_shell: Vec<String> = shell_assignment(&script, "SERVICE_ACCOUNTS")
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let mut from_rust: Vec<String> = SERVICE_ACCOUNTS.iter().map(|s| s.to_string()).collect();
    from_shell.sort();
    from_rust.sort();

    assert_eq!(
        from_shell, from_rust,
        "the enrollment script and the daemon disagree about which accounts are \
         service accounts rather than operators"
    );
}

/// Non-tautological guard on the extractor: it must actually be reading the
/// script rather than returning something that happens to match.
#[test]
fn the_extractor_reads_real_values_from_the_script() {
    let script = enrollment_script();
    assert!(
        script.contains("dscl . -create \"/Groups/$OP_GROUP\""),
        "this lint compares against a script that creates group records; if the \
         creation moved, the values it extracts may no longer be the ones in use"
    );
    assert!(
        !OPERATOR_GROUP_PREFIX.is_empty()
            && !SLOT_RANGE_ATTRIBUTE.is_empty()
            && !SERVICE_ACCOUNTS.is_empty(),
        "an empty constant would make every comparison above pass vacuously"
    );
}

/// Apple's reserved `_sandbox` (gid 60) merely shares a prefix with ours and
/// must never be produced as a per-operator group name.
#[test]
fn the_prefix_cannot_collide_with_apples_reserved_group() {
    assert_ne!(OPERATOR_GROUP_PREFIX, "_sandbox");
    assert!(
        !"_sandbox".starts_with(OPERATOR_GROUP_PREFIX),
        "no per-operator group name may be Apple's reserved Seatbelt group"
    );
    // The `op-` infix is what keeps an operator named `test` from producing
    // the `_sandboxd-test` service group's name.
    assert_ne!(
        format!("{OPERATOR_GROUP_PREFIX}test"),
        "_sandboxd-test",
        "an operator named 'test' must not enroll into the service group"
    );
}
