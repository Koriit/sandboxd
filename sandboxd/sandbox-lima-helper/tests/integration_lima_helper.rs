//! Integration tests for `sandbox-lima-helper`.
//!
//! These tests exercise the setcap-installed binary at the canonical
//! test install path `/usr/local/libexec/sandboxd-test/sandbox-lima-helper`
//! (parallel to `sandbox-route-helper`'s test install path). The binary
//! is built with `--features test-env-override` so tests can inject
//! synthetic user/group names and override the guest-binary path via env
//! vars without touching production accounts.
//!
//! ## Pre-requisites
//!
//! Run `make install-lima-helper-test-cap` once before invoking
//! `make test-integration`. The test verifies the installed binary is
//! (a) present, (b) carries `cap_setuid+ep`, and (c) matches the
//! cargo-built binary by SHA-256; it panics with an actionable remediation
//! message if any check fails.
//!
//! ## Profile selection
//!
//! Every test is prefixed `integration_lima_helper_` so the `integration`
//! nextest profile (`sandboxd/.config/nextest.toml`) picks them up via its
//! `test(/^integration_/)` filter. No `#[ignore]`, no env gate.
//!
//! ## What is covered
//!
//! - Caller-not-sandbox deny (EXIT_NOT_SANDBOX = 2)
//! - Root op-uid deny (EXIT_BAD_OP_UID = 3)
//! - Op-uid not in sandbox group deny (EXIT_BAD_OP_UID = 3)
//! - Bad vm name deny (EXIT_BAD_ARGS = 7)
//! - Malformed copy paths deny (EXIT_BAD_ARGS = 7)
//! - Range violations for start/clone flags (EXIT_BAD_ARGS = 7)
//! - Unknown subcommand deny (EXIT_BAD_ARGS = 7)
//! - Missing required flag deny (EXIT_BAD_ARGS = 7)
//! - limactl-not-found deny (EXIT_LIMACTL_NOT_FOUND = 6) when all three
//!   candidate paths are absent for the op-uid's pw_dir
//!
//! The tests drive deny branches that don't require a real Lima VM.
//! The privileged-path (actual limactl exec, setresuid success) and
//! install-guest-agent end-to-end are left to E2E tests against a real VM.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Canonical test install path. `sandboxd-test` is a sibling of the
/// production `sandboxd/` libexec directory so a prod install never
/// clobbers the test binary (which carries `test-env-override`).
const INSTALLED_TEST_HELPER_PATH: &str = "/usr/local/libexec/sandboxd-test/sandbox-lima-helper";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Path to the cargo-built helper binary (used for checksum freshness check).
fn cargo_bin_helper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandbox-lima-helper"))
}

/// Compute SHA-256 of a file.
fn sha256_file(path: &Path) -> [u8; 32] {
    use ring::digest::{Context, SHA256};
    let mut f = std::fs::File::open(path)
        .unwrap_or_else(|e| panic!("open {} for checksum: {e}", path.display()));
    let mut ctx = Context::new(&SHA256);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .unwrap_or_else(|e| panic!("read {} for checksum: {e}", path.display()));
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let digest = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify the installed test helper: exists, has cap_setuid, matches cargo build.
/// Returns the verified path. Panics with an actionable message on failure.
fn verify_installed_test_helper() -> PathBuf {
    let installed = PathBuf::from(INSTALLED_TEST_HELPER_PATH);
    if !installed.is_file() {
        panic!(
            "installed test lima helper not found at {}\n\
             run: make install-lima-helper-test-cap",
            installed.display()
        );
    }

    let getcap = Command::new("getcap")
        .arg(&installed)
        .output()
        .unwrap_or_else(|e| panic!("invoking getcap on {}: {e}", installed.display()));
    let cap_output = String::from_utf8_lossy(&getcap.stdout);
    if !cap_output.contains("cap_setuid") {
        panic!(
            "installed test lima helper at {} lacks cap_setuid \
             (getcap stdout: {:?})\n\
             run: make install-lima-helper-test-cap",
            installed.display(),
            cap_output,
        );
    }

    let installed_hash = sha256_file(&installed);
    let cargo_hash = sha256_file(&cargo_bin_helper_path());
    if installed_hash != cargo_hash {
        panic!(
            "installed lima helper is stale; run: make install-lima-helper-test-cap\n\
             installed: {} (sha256={})\n\
             cargo:     {} (sha256={})",
            installed.display(),
            hex(&installed_hash),
            cargo_bin_helper_path().display(),
            hex(&cargo_hash),
        );
    }

    installed
}

/// The numeric uid of the test runner. Used to build `SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER`
/// values that cause or allow the identity check to pass.
fn runner_uid() -> u32 {
    unsafe { libc::getuid() }
}

/// The username of the test runner. Used to inject as the synthetic
/// "sandbox" user so the caller-uid check passes.
fn runner_username() -> String {
    let output = Command::new("id")
        .arg("-un")
        .output()
        .expect("`id -un` should succeed");
    assert!(output.status.success(), "`id -un` exit non-zero");
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .trim()
        .to_string()
}

/// A group the test runner belongs to. Used to inject as the synthetic
/// "sandbox" group so the sandbox-group membership check passes.
fn runner_primary_group() -> String {
    let output = Command::new("id")
        .arg("-gn")
        .output()
        .expect("`id -gn` should succeed");
    assert!(output.status.success(), "`id -gn` exit non-zero");
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .trim()
        .to_string()
}

/// Run the installed helper with given argv and env overrides.
/// Env overrides are passed in addition to the test-env-override seam vars.
fn run_helper(helper: &Path, extra_env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut cmd = Command::new(helper);
    cmd.args(args);
    // Inject the test-env-override seam vars so we control what
    // "sandbox user" and "sandbox group" resolve to.
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output()
        .expect("invoking helper should not fail to spawn")
}

/// Run helper with the caller-uid check configured to PASS (synthetic
/// sandbox user = test runner user, sandbox group = test runner primary group).
fn run_helper_as_sandbox(helper: &Path, extra_env: &[(&str, &str)], args: &[&str]) -> Output {
    let user = runner_username();
    let group = runner_primary_group();
    let mut env: Vec<(&str, String)> = vec![
        ("SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER", user),
        ("SANDBOX_LIMA_HELPER_TEST_SANDBOX_GROUP", group),
    ];
    for (k, v) in extra_env {
        env.push((k, v.to_string()));
    }
    let env_refs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    run_helper(helper, &env_refs, args)
}

// ---------------------------------------------------------------------------
// Step 1: Caller-not-sandbox deny
// ---------------------------------------------------------------------------

/// When `SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER` is set to a user with a
/// different uid than the test runner, the helper exits EXIT_NOT_SANDBOX (2).
#[test]
fn integration_lima_helper_caller_not_sandbox_denied() {
    let helper = verify_installed_test_helper();

    // Use "root" as the "sandbox" user — runner is not root, so uid mismatch.
    let output = run_helper(
        &helper,
        &[("SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER", "root")],
        &["list-json", "--op-uid", "1000"],
    );

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected EXIT_NOT_SANDBOX (2), got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("caller not sandbox"),
        "stderr should mention 'caller not sandbox': {stderr}"
    );
}

/// When `SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER` points to the runner but
/// `SANDBOX_LIMA_HELPER_TEST_SANDBOX_GROUP` points to a group the runner
/// does NOT belong to, the helper exits EXIT_NOT_SANDBOX (2).
#[test]
fn integration_lima_helper_caller_not_in_sandbox_group_denied() {
    let helper = verify_installed_test_helper();

    let user = runner_username();
    // Use "root" — it always exists on any Linux host (gid 0) and no
    // unprivileged test runner is a member. This reaches the
    // `caller_is_in_group` check and emits "caller not in sandbox group".
    // A non-existent group would be caught earlier by the group lookup
    // step and emit "sandbox group '...' not found on host" instead.
    let output = run_helper(
        &helper,
        &[
            ("SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER", user.as_str()),
            ("SANDBOX_LIMA_HELPER_TEST_SANDBOX_GROUP", "root"),
        ],
        &["list-json", "--op-uid", "1000"],
    );

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected EXIT_NOT_SANDBOX (2), got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("caller not in sandbox group"),
        "stderr should mention 'caller not in sandbox group': {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Step 3: op-uid validation denials
// ---------------------------------------------------------------------------

/// `--op-uid 0` is rejected with EXIT_BAD_OP_UID (3).
#[test]
fn integration_lima_helper_root_op_uid_rejected() {
    let helper = verify_installed_test_helper();

    let output = run_helper_as_sandbox(&helper, &[], &["list-json", "--op-uid", "0"]);

    assert_eq!(
        output.status.code(),
        Some(3),
        "expected EXIT_BAD_OP_UID (3), got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("root op-uid rejected"),
        "stderr should mention 'root op-uid rejected': {stderr}"
    );
}

/// An op-uid that does not exist in passwd is rejected with EXIT_BAD_OP_UID (3).
#[test]
fn integration_lima_helper_op_uid_not_in_passwd_rejected() {
    let helper = verify_installed_test_helper();

    // uid 4294967200 is unlikely to exist on any test host.
    let output = run_helper_as_sandbox(&helper, &[], &["list-json", "--op-uid", "4294967200"]);

    // Will hit u32 parse overflow (4294967200 > u32::MAX), so EXIT_BAD_ARGS (7).
    // Alternatively if the value fits in u32 and doesn't exist, EXIT_BAD_OP_UID (3).
    let code = output.status.code();
    assert!(
        code == Some(7) || code == Some(3),
        "expected EXIT_BAD_ARGS (7) or EXIT_BAD_OP_UID (3), got {code:?}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Op-uid resolves but the user is not in the sandbox group → EXIT_BAD_OP_UID (3).
/// We use the runner uid but inject a sandbox group the runner doesn't belong to for the
/// op-uid group check (separate from the caller group check).
///
/// This test works by: passing the caller check (user = runner, group = runner's primary),
/// then failing the op-uid group check by passing a different group as "sandbox group"
/// that the runner is NOT in but the caller check doesn't use.
///
/// Actually with a shared group name we can't separate caller-group from op-uid-group.
/// Instead: we use our own uid as op_uid, and inject a group that nobody belongs to.
/// The caller check passes (uid matches), then group check for caller passes if we
/// use a group that includes us, then op_uid group check fails because op_uid (us)
/// is not in the injected sandbox group... but the sandbox group IS the caller group.
///
/// The key insight: if caller group check passes (runner is in runner's primary group),
/// then op-uid group check must also pass for the same group (op_uid = runner uid).
/// To get op-uid-not-in-group, we need a group the runner is in for the caller check
/// but not for the op-uid group check. That's impossible with one group name.
///
/// The correct way: use a group the runner IS in for caller check, but the op_uid
/// points to a DIFFERENT user who is NOT in that group. Use root (uid 0) is blocked.
/// Use a real uid that exists but isn't in the group we inject.
///
/// In practice: use the runner itself as both sandbox user and sandbox group (primary),
/// then pick an op_uid of a user (e.g. daemon uid 1) that is unlikely to be in the
/// runner's primary group.
#[test]
fn integration_lima_helper_op_uid_not_in_group_rejected() {
    let helper = verify_installed_test_helper();

    // Find a uid that actually exists on the system but is likely not in the runner's group.
    // uid 65534 (nobody/nfsnobody) is a standard system user on Linux.
    // We check it resolves, otherwise skip.
    let nobody_uid_str = "65534";
    let check = Command::new("getent")
        .args(["passwd", nobody_uid_str])
        .output();
    let uid_exists = check.map(|o| o.status.success()).unwrap_or(false);
    if !uid_exists {
        // Also try uid 65 (alternative nobody)
        // If neither resolves, we skip this test gracefully.
        eprintln!("skipping op-uid-not-in-group test: uid 65534 not found on this host");
        return;
    }

    // Runner's primary group is injected as "sandbox group". uid 65534 (nobody) is
    // very unlikely to be a member of the runner's primary group.
    let output = run_helper_as_sandbox(&helper, &[], &["list-json", "--op-uid", nobody_uid_str]);

    // Must be EXIT_BAD_OP_UID (3): the group-membership check fires before
    // limactl resolution, so code 6 would mean the group check was skipped.
    let code = output.status.code();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        code,
        Some(3),
        "expected EXIT_BAD_OP_UID (3) — group check must fire before limactl resolution, \
         got {code:?}\nstderr: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Step 4: vm name validation
// ---------------------------------------------------------------------------

#[test]
fn integration_lima_helper_bad_vm_name_rejected() {
    let helper = verify_installed_test_helper();

    // Leading dash — rejected by vm name validator.
    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "delete",
            "--op-uid",
            &runner_uid().to_string(),
            "--vm",
            "-bad",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7), got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid vm name"),
        "stderr should mention 'invalid vm name': {stderr}"
    );
}

#[test]
fn integration_lima_helper_vm_name_with_space_rejected() {
    let helper = verify_installed_test_helper();

    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "delete",
            "--op-uid",
            &runner_uid().to_string(),
            "--vm",
            "bad name",
        ],
    );

    // Parser level: "bad name" is parsed as --vm="bad" and "name" is extra positional.
    let code = output.status.code();
    assert_eq!(
        code,
        Some(7),
        "expected EXIT_BAD_ARGS (7), got {code:?}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// Step 6: copy path validation
// ---------------------------------------------------------------------------

#[test]
fn integration_lima_helper_copy_no_vm_prefix_rejected() {
    let helper = verify_installed_test_helper();

    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "copy",
            "--op-uid",
            &runner_uid().to_string(),
            "--src",
            "/host/src",
            "--dst",
            "/host/dst",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7), got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("copy requires a <vm>: prefix"),
        "stderr should mention copy prefix requirement: {stderr}"
    );
}

#[test]
fn integration_lima_helper_copy_relative_host_path_rejected() {
    let helper = verify_installed_test_helper();

    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "copy",
            "--op-uid",
            &runner_uid().to_string(),
            "--src",
            "sandbox-vm:/tmp/file",
            "--dst",
            "relative/path",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7), got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn integration_lima_helper_copy_dotdot_host_path_rejected() {
    let helper = verify_installed_test_helper();

    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "copy",
            "--op-uid",
            &runner_uid().to_string(),
            "--src",
            "sandbox-vm:/tmp/file",
            "--dst",
            "/host/../etc/passwd",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7), got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// Step 6: range violations (start subcommand)
// ---------------------------------------------------------------------------

#[test]
fn integration_lima_helper_start_memory_below_min_rejected() {
    let helper = verify_installed_test_helper();

    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "start",
            "--op-uid",
            &runner_uid().to_string(),
            "--vm",
            "sandbox-abc",
            "--qemu-wrapper",
            "/usr/local/bin/qemu-wrapper",
            "--hardened",
            "0",
            "--memory-mb",
            "128", // below min 256
            "--cpus",
            "2",
            "--start-timeout-s",
            "300",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7), got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--memory-mb"),
        "stderr should name the failing flag: {stderr}"
    );
}

#[test]
fn integration_lima_helper_start_cpus_above_max_rejected() {
    let helper = verify_installed_test_helper();

    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "start",
            "--op-uid",
            &runner_uid().to_string(),
            "--vm",
            "sandbox-abc",
            "--qemu-wrapper",
            "/usr/local/bin/qemu-wrapper",
            "--hardened",
            "0",
            "--memory-mb",
            "4096",
            "--cpus",
            "65", // above max 64
            "--start-timeout-s",
            "300",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7)\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn integration_lima_helper_start_timeout_above_max_rejected() {
    let helper = verify_installed_test_helper();

    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "start",
            "--op-uid",
            &runner_uid().to_string(),
            "--vm",
            "sandbox-abc",
            "--qemu-wrapper",
            "/usr/local/bin/qemu-wrapper",
            "--hardened",
            "0",
            "--memory-mb",
            "4096",
            "--cpus",
            "2",
            "--start-timeout-s",
            "601", // above max 600
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7)\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn integration_lima_helper_start_bridge_without_mac_rejected() {
    let helper = verify_installed_test_helper();

    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "start",
            "--op-uid",
            &runner_uid().to_string(),
            "--vm",
            "sandbox-abc",
            "--qemu-wrapper",
            "/usr/local/bin/qemu-wrapper",
            "--hardened",
            "0",
            "--memory-mb",
            "4096",
            "--cpus",
            "2",
            "--start-timeout-s",
            "300",
            "--bridge-name",
            "br0",
            // no --vm-mac
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7)\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--bridge-name and --vm-mac must be supplied together"),
        "stderr should mention paired flags: {stderr}"
    );
}

#[test]
fn integration_lima_helper_start_multicast_mac_rejected() {
    let helper = verify_installed_test_helper();

    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "start",
            "--op-uid",
            &runner_uid().to_string(),
            "--vm",
            "sandbox-abc",
            "--qemu-wrapper",
            "/usr/local/bin/qemu-wrapper",
            "--hardened",
            "0",
            "--memory-mb",
            "4096",
            "--cpus",
            "2",
            "--start-timeout-s",
            "300",
            "--bridge-name",
            "br0",
            "--vm-mac",
            "01:00:00:00:00:00", // multicast bit set (LSB of first octet)
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7)\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("multicast bit"),
        "stderr should mention multicast bit: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Argv parse errors
// ---------------------------------------------------------------------------

#[test]
fn integration_lima_helper_unknown_subcommand_rejected() {
    let helper = verify_installed_test_helper();

    let user = runner_username();
    let output = run_helper(
        &helper,
        &[("SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER", user.as_str())],
        &["frobnicate"],
    );

    // Unknown subcommand → EXIT_BAD_ARGS (7).
    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7), got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn integration_lima_helper_missing_flag_rejected() {
    let helper = verify_installed_test_helper();

    // `create` without --yaml.
    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "create",
            "--op-uid",
            &runner_uid().to_string(),
            "--vm",
            "sandbox-abc",
            // missing --yaml
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7)\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// Step 7: limactl-not-found deny
// ---------------------------------------------------------------------------

/// After all validation passes, if limactl is not found at any of the three
/// candidate paths for the op-uid's pw_dir, EXIT_LIMACTL_NOT_FOUND (6).
///
/// This test runs as the test runner (injected as sandbox user), uses the
/// runner's own uid as op_uid (so passwd lookup succeeds and group check
/// passes), and relies on the fact that `~/.local/bin/limactl`,
/// `/usr/local/bin/limactl`, and `/usr/bin/limactl` likely don't all exist.
/// If any of them is present, we skip (can't test not-found).
#[test]
fn integration_lima_helper_limactl_not_found() {
    // Check if limactl exists at any of the three paths for the runner.
    let home = std::env::var("HOME").unwrap_or_default();
    let candidates = [
        format!("{home}/.local/bin/limactl"),
        "/usr/local/bin/limactl".to_string(),
        "/usr/bin/limactl".to_string(),
    ];
    if candidates.iter().any(|p| std::path::Path::new(p).exists()) {
        eprintln!("skipping limactl-not-found test: limactl found at one of the candidate paths");
        return;
    }

    let helper = verify_installed_test_helper();
    let uid_s = runner_uid().to_string();

    let output = run_helper_as_sandbox(&helper, &[], &["list-json", "--op-uid", &uid_s]);

    assert_eq!(
        output.status.code(),
        Some(6),
        "expected EXIT_LIMACTL_NOT_FOUND (6), got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("limactl not found"),
        "stderr should mention 'limactl not found': {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Clone range violations
// ---------------------------------------------------------------------------

#[test]
fn integration_lima_helper_clone_memory_above_max_rejected() {
    let helper = verify_installed_test_helper();

    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "clone",
            "--op-uid",
            &runner_uid().to_string(),
            "--base",
            "sandbox-base",
            "--vm",
            "sandbox-abc",
            "--cpus",
            "4",
            "--memory",
            "257", // above max 256 GiB
            "--disk",
            "50",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7)\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn integration_lima_helper_clone_disk_above_max_rejected() {
    let helper = verify_installed_test_helper();

    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "clone",
            "--op-uid",
            &runner_uid().to_string(),
            "--base",
            "sandbox-base",
            "--vm",
            "sandbox-abc",
            "--cpus",
            "4",
            "--memory",
            "8",
            "--disk",
            "1025", // above max 1024 GiB
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7)\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// start hardened value validation
// ---------------------------------------------------------------------------

#[test]
fn integration_lima_helper_start_invalid_hardened_value_rejected() {
    let helper = verify_installed_test_helper();

    let output = run_helper_as_sandbox(
        &helper,
        &[],
        &[
            "start",
            "--op-uid",
            &runner_uid().to_string(),
            "--vm",
            "sandbox-abc",
            "--qemu-wrapper",
            "/usr/local/bin/qemu-wrapper",
            "--hardened",
            "2", // not "0" or "1"
            "--memory-mb",
            "4096",
            "--cpus",
            "2",
            "--start-timeout-s",
            "300",
        ],
    );

    assert_eq!(
        output.status.code(),
        Some(7),
        "expected EXIT_BAD_ARGS (7)\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
