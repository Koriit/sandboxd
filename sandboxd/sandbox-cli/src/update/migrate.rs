//! Config-migration glue for `sandbox update` — Spec 5 §§ 3.2.24, 4.3.
//!
//! The framework in `sandbox-cli/src/cfg_migrations/` owns the
//! versioned-transform contract and the atomic-write primitive. This
//! module wires the framework into the `sandbox update` stateful step
//! § 3.2.24: walk each managed file's pending migration chain, run
//! the transform in-process, write to a sudo-controlled tempfile at a
//! canonical path (`/etc/sandboxd/.users.conf.tmp.V001` and friends),
//! and `sudo -k mv` the tempfile over the destination in one atomic
//! `rename(2)` call.
//!
//! Why the tempfile-then-mv split rather than a single in-process
//! atomic_write? Two reasons:
//!
//! 1. The destination (`/etc/sandboxd/users.conf`) is `root:root 0644`;
//!    the running `sandbox update` process is the operator's user, not
//!    root. The framework's `atomic_write` (which uses
//!    `NamedTempFile::new_in(parent) + persist`) cannot create a
//!    tempfile in `/etc/sandboxd/` because the directory is `0755
//!    root:root`. We need a `sudo` elevation for both the tempfile
//!    create and the rename.
//! 2. The atomic-write contract (Spec 5 § 4.4) requires the tempfile
//!    and destination to be on the same filesystem so `rename(2)` is
//!    atomic. Doing the tempfile under `/tmp` and `sudo mv` across
//!    filesystems would degrade to a copy-then-unlink — non-atomic.
//!    Pinning the tempfile path under `/etc/sandboxd/` keeps the
//!    rename atomic.
//!
//! The actual transform runs in-process via the hidden CLI subcommand
//! `sandbox --apply-config-migration --file <path> --migration V<NNN>
//! --out <tmp>`. That subcommand is gated on `getuid() == 0` and
//! canonical-path validation (see `main.rs::apply_config_migration_gate`).
//! The orchestrating shell flow (`sandbox update`) re-execs itself
//! under `sudo` for each pending migration; this is identical to how
//! install.sh shells out to its own helpers — the binary becomes its
//! own trusted helper for the privileged transform step.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cfg_migrations;

/// Canonical tempfile path for a migration's pending write. Spec 5
/// § 3.2.24: `/etc/sandboxd/.users.conf.tmp.V001` (hidden dot-prefix
/// plus `.tmp.V<NNN>` suffix; the basename pattern is the canonical
/// one the `--apply-config-migration` gate accepts).
pub fn tempfile_path_for(target: cfg_migrations::TargetFile, migration_id: u32) -> PathBuf {
    let canonical = target.canonical_path();
    // SAFETY: `TargetFile::canonical_path` returns an absolute
    // file path baked into source code (e.g. `/etc/sandboxd/users.conf`).
    // Every variant has a non-empty parent (`/etc/sandboxd/` or
    // `/etc/qemu/`) and a non-empty basename by construction, so
    // both `.expect()`s here are infallible. The
    // `target_file_canonical_path_round_trip` test in
    // `cfg_migrations::tests` exercises every registered variant
    // through `canonical_path` → `from_canonical_path`, so a
    // future variant that violated the parent/basename invariant
    // would fail that round-trip first.
    let parent = canonical.parent().expect("canonical path has a parent");
    let basename = canonical
        .file_name()
        .expect("canonical path has a file name")
        .to_string_lossy()
        .into_owned();
    parent.join(format!(".{basename}.tmp.V{migration_id:03}"))
}

/// Outcome of running a single managed file's full migration chain.
#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub target: cfg_migrations::TargetFile,
    /// Migration ids actually applied this run. Empty when the file
    /// was already at the latest registered version (idempotency).
    pub applied: Vec<u32>,
    /// `true` when the source file does not exist on disk (e.g.
    /// `bridge.conf` on a system that has not yet enabled QEMU
    /// bridge networking). The caller logs `action=skip reason=absent`.
    pub source_absent: bool,
}

/// Errors from the per-file apply chain.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("apply migration V{migration_id:03}: {message}")]
    Apply { migration_id: u32, message: String },
    #[error("rename over {dst}: {stderr}")]
    Rename { dst: PathBuf, stderr: String },
    #[error("read schema version: {0}")]
    SchemaUnreadable(String),
}

/// Apply every pending migration for the given target file, in
/// registry order, with one `sudo -k sandbox --apply-config-migration
/// ...` invocation per migration. Spec 5 § 3.2.24.
///
/// Returns the (possibly empty) list of applied migration ids. Empty
/// is the idempotent re-run shape — a second `sandbox update` after a
/// successful first sees `latest_for == current`, returns
/// `Ok(applied=[])`, and the caller emits the `action=skip` log.
pub fn apply_file_chain(target: cfg_migrations::TargetFile) -> Result<ApplyOutcome, ApplyError> {
    let canonical = target.canonical_path();
    if !canonical.exists() {
        return Ok(ApplyOutcome {
            target,
            applied: Vec::new(),
            source_absent: true,
        });
    }
    let target_version = cfg_migrations::latest_for(target);
    let mut applied = Vec::new();
    loop {
        let bytes = std::fs::read(&canonical)?;
        let current = cfg_migrations::read_schema_version(&bytes, target)
            .map_err(|e| ApplyError::SchemaUnreadable(e.to_string()))?;
        if current >= target_version {
            return Ok(ApplyOutcome {
                target,
                applied,
                source_absent: false,
            });
        }
        let migration = cfg_migrations::registry()
            .iter()
            .copied()
            .find(|m| m.target_file() == target && m.from_version() == current)
            .ok_or_else(|| ApplyError::Apply {
                migration_id: 0,
                message: format!(
                    "no migration in registry for {} at version {current}",
                    target.display_name()
                ),
            })?;
        let migration_id = migration.id();
        let tmp = tempfile_path_for(target, migration_id);

        // Step 1: in-process transform via `sandbox
        // --apply-config-migration --file <canonical> --migration
        // V<NNN> --out <tmp>`. The subcommand re-execs `sandbox` under
        // `sudo` to satisfy its `getuid() == 0` gate.
        invoke_apply_subcommand(&canonical, migration_id, &tmp)?;

        // Step 2: atomic rename via `sudo -k mv <tmp> <canonical>`.
        // `mv` calls `rename(2)` which is atomic on the same FS.
        rename_via_sudo(&tmp, &canonical)?;

        applied.push(migration_id);
    }
}

/// Invoke the hidden `--apply-config-migration` subcommand against the
/// canonical CLI binary. Production resolves the binary via
/// `/proc/self/exe` (so a half-replaced binary keeps running its own
/// code per Spec 5 § 10.3) but for the production `sandbox update`
/// path we want the **new** binary — the binary swap has already
/// landed at this point of the flow. We invoke `/usr/local/bin/sandbox`
/// directly.
fn invoke_apply_subcommand(
    canonical: &Path,
    migration_id: u32,
    out_tmp: &Path,
) -> Result<(), ApplyError> {
    let migration_arg = format!("V{migration_id:03}");
    let status = Command::new("sudo")
        .args([
            "-k",
            "/usr/local/bin/sandbox",
            "--apply-config-migration",
            "--file",
            canonical.to_str().unwrap(),
            "--migration",
            &migration_arg,
            "--out",
            out_tmp.to_str().unwrap(),
        ])
        .output()
        .map_err(ApplyError::Io)?;
    if !status.status.success() {
        return Err(ApplyError::Apply {
            migration_id,
            message: format!(
                "exit {:?}: {}",
                status.status.code(),
                String::from_utf8_lossy(&status.stderr).trim()
            ),
        });
    }
    Ok(())
}

/// `sudo -k mv <src> <dst>` — atomic rename across the same FS.
fn rename_via_sudo(src: &Path, dst: &Path) -> Result<(), ApplyError> {
    let status = Command::new("sudo")
        .args(["-k", "mv", src.to_str().unwrap(), dst.to_str().unwrap()])
        .output()
        .map_err(ApplyError::Io)?;
    if !status.status.success() {
        return Err(ApplyError::Rename {
            dst: dst.to_path_buf(),
            stderr: String::from_utf8_lossy(&status.stderr).into_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical tempfile path lives next to the destination so a
    /// rename across the same FS is atomic. Spec 5 § 4.4.
    #[test]
    fn tempfile_path_lives_next_to_destination() {
        let p = tempfile_path_for(cfg_migrations::TargetFile::UsersConf, 1);
        assert_eq!(p.to_str().unwrap(), "/etc/sandboxd/.users.conf.tmp.V001");
        let p2 = tempfile_path_for(cfg_migrations::TargetFile::BridgeConf, 7);
        assert_eq!(p2.to_str().unwrap(), "/etc/qemu/.bridge.conf.tmp.V007");
    }

    /// The basename matches the `--apply-config-migration` gate's
    /// expected pattern `\.<basename>\.tmp\.V[0-9]+$` (per
    /// `main.rs::apply_config_migration_gate` Arm 3).
    #[test]
    fn tempfile_basename_matches_gate_pattern() {
        for (target, expected_prefix) in [
            (cfg_migrations::TargetFile::UsersConf, ".users.conf.tmp.V"),
            (cfg_migrations::TargetFile::BridgeConf, ".bridge.conf.tmp.V"),
        ] {
            let p = tempfile_path_for(target, 42);
            let basename = p.file_name().unwrap().to_str().unwrap();
            assert!(
                basename.starts_with(expected_prefix),
                "{basename} should start with {expected_prefix}"
            );
            let suffix = &basename[expected_prefix.len()..];
            assert!(
                suffix.chars().all(|c| c.is_ascii_digit()),
                "{basename}: tail after V is not all digits"
            );
        }
    }

    /// When the source file does not exist (e.g. `bridge.conf` on a
    /// host that has not enabled QEMU bridge networking) the apply
    /// chain reports `source_absent: true` and applies nothing.
    #[test]
    fn apply_file_chain_skips_when_target_absent() {
        // The canonical path /etc/qemu/bridge.conf is almost certainly
        // absent in the test sandbox. If it's present (e.g. local
        // CI worker has bridge networking configured), this test
        // would attempt a real apply and fail at sudo; in that case
        // we accept the test as "vacuously inapplicable" — the
        // production path is exercised by the Lima E2E suite.
        let canonical = cfg_migrations::TargetFile::BridgeConf.canonical_path();
        if canonical.exists() {
            // Don't run the apply path against a real /etc file under
            // test. Bail out — the unit test cannot exercise this
            // safely on the host.
            return;
        }
        let outcome = apply_file_chain(cfg_migrations::TargetFile::BridgeConf)
            .expect("source-absent path returns Ok");
        assert!(outcome.source_absent);
        assert!(outcome.applied.is_empty());
    }
}
