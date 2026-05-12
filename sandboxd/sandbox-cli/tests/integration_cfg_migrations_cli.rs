//! Subprocess-level integration tests for the hidden config-migration
//! affordances and the `--backend gateway` refusal.
//!
//! These tests spawn the compiled `sandbox` binary so they exercise
//! `process::exit(<code>)` exactly the way operators see it. The
//! `CARGO_BIN_EXE_sandbox` env var is set by cargo for integration
//! test crates (`tests/*.rs`), but not for unit tests inside the
//! binary's own `src/main.rs`, which is why these live here.
//!
//! Test names are intentionally `integration_*`-prefixed-or-suffixed
//! per the project convention; the names used here mirror the Spec 5
//! § 9.2 test labels so the spec rows map 1:1 to function names.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn sandbox_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sandbox"))
}

// ---------------------------------------------------------------------------
// rebuild-image --backend gateway (Spec 5 § 8.1)
// ---------------------------------------------------------------------------

/// `sandbox rebuild-image --backend gateway` exits 2 with the
/// `sandbox update` substring and never connects to the daemon.
///
/// We pin the "no HTTP request sent" half by pointing `--socket` at a
/// path that does not exist; if the dispatcher actually attempted a
/// connection it would surface a `Connection refused` / `No such file`
/// error in stderr. The refusal arm short-circuits before
/// `send_request_with_timeout`, so neither substring appears.
#[test]
fn integration_rebuild_image_gateway_backend_refuses_with_pointer_to_update() {
    let tmp = TempDir::new().expect("tempdir");
    let unreachable_socket = tmp.path().join("never-listened.sock");
    let output = Command::new(sandbox_bin())
        .arg("--socket")
        .arg(&unreachable_socket)
        .args(["rebuild-image", "--backend", "gateway"])
        .output()
        .expect("spawn sandbox CLI");
    let code = output.status.code().expect("exited normally");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        code, 2,
        "Spec 5 § 8.1: --backend gateway must exit 2; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("sandbox update"),
        "stderr must point at `sandbox update`; got:\n{stderr}"
    );
    assert!(
        !stderr.contains("Connection refused") && !stderr.contains("No such file"),
        "stderr must not surface a connection error (no HTTP request fired); \
         got:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// apply-config-migration access gating (Spec 5 § 4.3)
// ---------------------------------------------------------------------------

/// `apply-config-migration` invoked by a non-root caller (the test
/// process) refuses with the `requires root` substring and exit
/// non-zero. The four refusal arms apply in order; the test user
/// running the suite is not root, so arm 1 fires before any of the
/// path or migration-ID checks.
#[test]
fn integration_apply_config_migration_subprocess_refuses_non_root_caller() {
    let output = Command::new(sandbox_bin())
        .args([
            "apply-config-migration",
            "--file",
            "/etc/sandboxd/users.conf",
            "--migration",
            "V001",
            "--out",
            "/etc/sandboxd/.users.conf.tmp.V001",
        ])
        .output()
        .expect("spawn sandbox CLI");
    let code = output.status.code().expect("exited normally");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_ne!(code, 0, "non-root must exit non-zero; stderr:\n{stderr}");
    assert!(
        stderr.contains("requires root"),
        "stderr must carry `requires root`; got:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// dump-migration-set (Spec 5 § 3.1.4 — exit-criterion #9)
// ---------------------------------------------------------------------------

/// `sandbox dump-migration-set` exits 0 and prints a JSON array
/// whose every entry contains `id`, `from_version`, `to_version`,
/// and `target_file`.
#[test]
fn integration_dump_migration_set_exits_zero_with_documented_json_shape() {
    let output = Command::new(sandbox_bin())
        .arg("dump-migration-set")
        .output()
        .expect("spawn sandbox CLI");
    let code = output.status.code().expect("exited normally");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(code, 0, "must exit 0; stderr was:\n{stderr}");

    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be a JSON array");
    let arr = parsed.as_array().expect("array");
    assert!(!arr.is_empty(), "registry must contain at least V001");
    for entry in arr {
        let obj = entry.as_object().expect("each entry is an object");
        for key in ["id", "from_version", "to_version", "target_file"] {
            assert!(
                obj.contains_key(key),
                "each entry must contain `{key}`; got: {entry}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// integration_config_migration_applies_v001_to_legacy_file (Spec 5 § 9.3)
// ---------------------------------------------------------------------------

/// Stage a pre-V001 `users.conf` in a tempdir, run the framework's
/// `apply_pending_at` against it (via the in-process library entry
/// point so we don't need root for the canonical-path arm), assert the
/// file post-condition stamps `_schema_version: 1` and prepends
/// `"sandbox"` to every `allow_users` per Spec 1 § 5.5.
#[test]
fn integration_config_migration_applies_v001_to_legacy_file() {
    use sandbox_cli::cfg_migrations::{apply_pending_at, TargetFile};

    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("users.conf");

    // Spec 1 § 5.5 Input B (multi-pool, multi-user, with comment).
    let legacy = br#"{
        "subnets": [
            { "cidr": "10.209.0.0/24", "allow_users": ["alice"], "comment": "alice prod" },
            { "cidr": "10.210.0.0/24", "allow_users": ["bob", "carol"] }
        ]
    }"#;
    std::fs::write(&path, legacy).expect("write legacy file");

    let applied =
        apply_pending_at(TargetFile::UsersConf, &path).expect("apply_pending_at succeeds");
    assert_eq!(applied, vec![1], "V001 applied exactly once");

    let post_bytes = std::fs::read(&path).expect("read post-migration");
    let post: serde_json::Value =
        serde_json::from_slice(&post_bytes).expect("post is valid JSON");

    assert_eq!(
        post["_schema_version"],
        serde_json::json!(1),
        "post-V001 file must carry `_schema_version: 1`"
    );

    let subnets = post["subnets"].as_array().expect("subnets is array");
    assert_eq!(subnets.len(), 2, "two pools preserved");

    // Pool 0: ["sandbox", "alice"] (sandbox prepended).
    assert_eq!(
        subnets[0]["allow_users"],
        serde_json::json!(["sandbox", "alice"]),
        "pool 0 allow_users mismatch"
    );
    assert_eq!(
        subnets[0]["comment"],
        serde_json::json!("alice prod"),
        "operator comment preserved"
    );

    // Pool 1: ["sandbox", "bob", "carol"].
    assert_eq!(
        subnets[1]["allow_users"],
        serde_json::json!(["sandbox", "bob", "carol"]),
        "pool 1 allow_users mismatch"
    );

    // Idempotency: re-running yields the same file.
    let applied_again = apply_pending_at(TargetFile::UsersConf, &path)
        .expect("re-apply skip path returns Ok");
    assert!(
        applied_again.is_empty(),
        "second run must be a no-op; got applied={applied_again:?}"
    );
}
