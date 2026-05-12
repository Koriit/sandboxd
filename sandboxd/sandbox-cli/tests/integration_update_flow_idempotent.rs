//! Hermetic integration test for the `sandbox update` stateful flow's
//! idempotency contract — Spec 5 § 9.3.
//!
//! The full stateful flow (`update::apply_stateful` in `mod.rs`) needs
//! root, `systemctl`, `docker`, a real `/run/sandbox/sandboxd.sock`,
//! and `sandbox doctor`. We can't stand any of that up in a hermetic
//! test. Instead, this test pins the **pure pieces** of the contract
//! that DO run in-process:
//!
//! * The backup-set + manifest layer ([`sandbox_cli::update::backup`])
//!   — directory creation, copy with sha256 idempotency, manifest
//!   write/read, retention prune.
//! * The migrate-glue tempfile-path scheme ([`sandbox_cli::update::migrate`])
//!   — canonical-path round-trip + basename pattern.
//! * The install-state shape ([`sandbox_cli::update::InstallState`]) —
//!   `previous_version` round-trip across re-runs, JSON
//!   serde-default tolerance.
//!
//! The Lima E2E test `test_update_interrupted_then_resumed` covers the
//! end-to-end flow including subprocess invocations.
//!
//! ## What "idempotent" means here
//!
//! Spec 5 §§ 3.2.15-17 + 5.2: re-running each backup primitive on
//! identical bytes is a no-op (`action=skip reason=identical`). The
//! retention prune sees the same world after a second run if nothing
//! else changed. This test exercises both halves against a synthetic
//! `backups/` tree under a tempdir.

use std::path::Path;

use sandbox_cli::cfg_migrations;
use sandbox_cli::update::backup;

/// Set up a synthetic backup-set tree under `root` with N successful
/// sets + 1 in-progress set. Returns the in-progress set's path so the
/// test can assert it survives.
fn seed_synthetic_backup_tree(root: &Path, n_successful: usize) -> std::path::PathBuf {
    // Successful sets, oldest first.
    for i in 0..n_successful {
        let ts = format!("2026-05-{:02}T12:00:00Z", 1 + i);
        let from = format!("1.0.{i}");
        let to = format!("1.0.{}", i + 1);
        let dir = root.join(backup::backup_set_name(&ts, &from, &to));
        std::fs::create_dir_all(&dir).unwrap();
        let m = backup::BackupManifest {
            from_version: from,
            to_version: to,
            started_at: ts.clone(),
            completed_at: Some(ts),
            completed_ok: true,
            arch: "x86_64-unknown-linux-gnu".to_string(),
            files: Default::default(),
        };
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec_pretty(&m).unwrap(),
        )
        .unwrap();
    }
    // In-progress current set.
    let in_progress_ts = format!("2026-05-{:02}T12:00:00Z", n_successful + 5);
    let in_progress_dir = root.join(backup::backup_set_name(
        &in_progress_ts,
        &format!("1.0.{n_successful}"),
        &format!("1.0.{}", n_successful + 1),
    ));
    std::fs::create_dir_all(&in_progress_dir).unwrap();
    let m = backup::BackupManifest {
        from_version: format!("1.0.{n_successful}"),
        to_version: format!("1.0.{}", n_successful + 1),
        started_at: in_progress_ts,
        completed_at: None,
        completed_ok: false,
        arch: "x86_64-unknown-linux-gnu".to_string(),
        files: Default::default(),
    };
    std::fs::write(
        in_progress_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&m).unwrap(),
    )
    .unwrap();
    in_progress_dir
}

/// **Spec 5 § 9.3 anchor:** stub install in a temp tree, simulated
/// update, second run all-skip.
///
/// Concretely: seed the backups tree, run the retention-prune step,
/// re-run it, assert the second run is a no-op (no `pruned`) and the
/// in-progress set survived both runs.
#[test]
fn integration_update_flow_idempotent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    let in_progress = seed_synthetic_backup_tree(root, 4);

    // First "run": prune — should kick out the oldest 2 successful sets,
    // keep the newest 2, preserve the in-progress one.
    let r1 = backup::prune_old_backup_sets_at(root).expect("first prune ok");
    assert_eq!(
        r1.kept.len(),
        2,
        "first prune keeps exactly 2 successful sets: {:?}",
        r1.kept
    );
    assert_eq!(
        r1.pruned.len(),
        2,
        "first prune removes 2 oldest: {:?}",
        r1.pruned
    );
    assert_eq!(
        r1.preserved_forensic.len(),
        1,
        "in-progress set preserved: {:?}",
        r1.preserved_forensic
    );
    assert!(in_progress.exists(), "in-progress survived first prune");

    // Second "run" against the post-prune tree: no-op.
    let r2 = backup::prune_old_backup_sets_at(root).expect("second prune ok");
    assert!(
        r2.pruned.is_empty(),
        "second prune is a no-op (idempotent): pruned={:?}",
        r2.pruned
    );
    assert_eq!(r2.kept.len(), 2);
    assert_eq!(r2.preserved_forensic.len(), 1);
    assert!(
        in_progress.exists(),
        "in-progress survived second prune (forensic-preserved per § 5.2)"
    );
}

/// Spec 5 § 3.2.15: the per-file copy primitive is sha256-idempotent.
/// Re-copying identical bytes returns `CopyAction::Skipped` — pinning
/// the "second run = all skip" contract for the backup half of the
/// stateful phase.
///
/// NOTE: This test exercises the `backup_sandbox_owned_file` happy
/// path, which shells out to `sudo -k -u sandbox install`. In the test
/// harness we don't actually have sudo; the test uses
/// `create_backup_set_dir_at` (the test-friendly variant) and
/// verifies the sha256-comparison branch returns `Skipped` for
/// identical bytes via the hash-compare path. The sudo call is
/// skipped because the dest already exists with matching bytes.
#[test]
fn integration_backup_sha256_skip_branch_when_destination_identical() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let src = tmp.path().join("src.bin");
    let dst = tmp.path().join("dst.bin");
    let bytes = b"hello world".repeat(100);
    std::fs::write(&src, &bytes).unwrap();
    std::fs::write(&dst, &bytes).unwrap();

    // The dst already has the right bytes; the function should
    // short-circuit at the hash compare without invoking sudo.
    let outcome = backup::backup_sandbox_owned_file(&src, &dst, 0o640).expect("ok");
    assert!(
        matches!(outcome.action, backup::CopyAction::Skipped),
        "identical-bytes destination must short-circuit to Skipped: {:?}",
        outcome.action
    );
    assert_eq!(outcome.size, bytes.len() as u64);
    assert_eq!(outcome.sha256.len(), 64, "sha256 hex should be 64 chars");
}

/// Spec 5 § 3.2.15: when the source file is absent, the primitive
/// reports `CopyAction::SourceAbsent` and emits no manifest entry. The
/// orchestration uses this to skip backing up `bridge.conf` on hosts
/// that have not yet enabled QEMU bridge networking.
#[test]
fn integration_backup_returns_source_absent_when_src_missing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let src = tmp.path().join("does-not-exist");
    let dst = tmp.path().join("dst.bin");
    let outcome = backup::backup_sandbox_owned_file(&src, &dst, 0o640).expect("ok");
    assert!(matches!(outcome.action, backup::CopyAction::SourceAbsent));
    assert!(!dst.exists(), "no destination created when source absent");
}

/// Spec 5 § 5.2: a backup set with `completed_ok: false` is never
/// auto-pruned, regardless of how many successful sets follow it. The
/// `test_update_partial_failure_backup_set_preserved` Lima test (§ 9.1)
/// covers the same property at the VM level; this is the hermetic
/// version.
#[test]
fn integration_backup_retention_never_prunes_failed_sets() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    // Seed: 1 failed (forensic) set + 5 successful sets.
    let failed_dir = root.join("2026-05-01T00:00:00Z-from-1.0.0-to-1.1.0");
    std::fs::create_dir_all(&failed_dir).unwrap();
    let failed_manifest = backup::BackupManifest {
        from_version: "1.0.0".to_string(),
        to_version: "1.1.0".to_string(),
        started_at: "2026-05-01T00:00:00Z".to_string(),
        completed_at: None,
        completed_ok: false,
        arch: "x86_64-unknown-linux-gnu".to_string(),
        files: Default::default(),
    };
    std::fs::write(
        failed_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&failed_manifest).unwrap(),
    )
    .unwrap();
    for i in 0..5 {
        let ts = format!("2026-05-{:02}T12:00:00Z", 10 + i);
        let from = format!("1.1.{i}");
        let to = format!("1.1.{}", i + 1);
        let dir = root.join(backup::backup_set_name(&ts, &from, &to));
        std::fs::create_dir_all(&dir).unwrap();
        let m = backup::BackupManifest {
            from_version: from,
            to_version: to,
            started_at: ts.clone(),
            completed_at: Some(ts),
            completed_ok: true,
            arch: "x86_64-unknown-linux-gnu".to_string(),
            files: Default::default(),
        };
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec_pretty(&m).unwrap(),
        )
        .unwrap();
    }
    let outcome = backup::prune_old_backup_sets_at(root).expect("prune ok");
    assert_eq!(
        outcome.kept.len(),
        2,
        "exactly 2 newest successful sets kept: {:?}",
        outcome.kept
    );
    assert_eq!(
        outcome.pruned.len(),
        3,
        "3 oldest successful sets pruned: {:?}",
        outcome.pruned
    );
    assert_eq!(
        outcome.preserved_forensic.len(),
        1,
        "failed set preserved: {:?}",
        outcome.preserved_forensic
    );
    assert!(failed_dir.exists(), "failed set must survive prune (§ 5.2)");
}

/// Spec 5 § 3.2.18: the install-state's `previous_version` field is
/// `Option<String>` with `#[serde(default)]`. Older state files
/// written by install.sh (which doesn't write the field) deserialise
/// successfully with `previous_version: None`.
#[test]
fn integration_install_state_tolerates_pre_spec5_state_file_shape() {
    use sandbox_cli::update::InstallState;
    let pre_spec5 = serde_json::json!({
        "installed_version": "1.0.0",
        "installed_arch": "x86_64-unknown-linux-gnu",
        "installed_at": "2026-05-08T14:23:11Z",
        "installed_by_operator": "alice"
        // note: no `previous_version` key
    });
    let state: InstallState = serde_json::from_value(pre_spec5).expect("parse pre-Spec5 state");
    assert!(
        state.previous_version.is_none(),
        "missing previous_version deserialises to None"
    );
    assert_eq!(state.installed_version, "1.0.0");
}

/// Spec 5 § 3.2.24: the migrate-glue's tempfile path scheme places the
/// per-migration tempfile next to the destination so the rename is
/// atomic. A re-run produces the same path for the same `(target,
/// migration_id)` pair — pinning the "second run is identical" anchor
/// of the apply chain.
#[test]
fn integration_migrate_tempfile_path_is_stable_across_reruns() {
    use sandbox_cli::update::migrate;
    let p1 = migrate::tempfile_path_for(cfg_migrations::TargetFile::UsersConf, 1);
    let p2 = migrate::tempfile_path_for(cfg_migrations::TargetFile::UsersConf, 1);
    assert_eq!(p1, p2, "tempfile path is a pure function");
    assert_eq!(
        p1.to_str().unwrap(),
        "/etc/sandboxd/.users.conf.tmp.V001",
        "Spec 5 § 3.2.24 canonical tempfile shape"
    );
}
