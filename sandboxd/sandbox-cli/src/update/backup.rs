//! Backup-set management for `sandbox update` — Spec 5 §§ 5.1-5.5.
//!
//! A "backup set" is one subdirectory under `/var/lib/sandbox/backups/`
//! capturing every artefact `sandbox update` mutates: the daemon
//! binary, the CLI binary, the route-helper, `sessions.db`, and the
//! managed `/etc` files. Each set carries a `manifest.json` recording
//! the from/to versions, timestamps, and per-file sha256 hashes —
//! that manifest is what the retention prune at § 3.2.25 reads to
//! decide which sets are eligible for removal (`completed_ok: true`
//! only) and what the rollback recipe at § 7.2 enumerates when an
//! operator wants to step back.
//!
//! ## Ownership / mode contract
//!
//! All artefacts in the set are owned `sandbox:sandbox`. Binaries land
//! at mode `0640` — **not executable** — so a wandering operator
//! cannot accidentally invoke the old binary from PATH (the rollback
//! recipe `install -m 0755`s them back in place). The `sessions.db`
//! backup is `0600` (same as the production DB). `/etc` files are
//! `0644` (matches the production modes documented in Spec 4 § 4.4).
//!
//! ## Idempotency
//!
//! Every per-file copy method short-circuits if the destination
//! already exists and its bytes match the source's bytes (compared via
//! sha256). The shell pseudo-code in the spec uses `cmp -s`; we use a
//! sha256 round-trip so the same hash drops into the manifest's
//! `files` map without a second pass.
//!
//! ## Sudo elevation
//!
//! All file operations that need to land at `sandbox:sandbox` ownership
//! shell out via `sudo -k -u sandbox install ...` (matching install.sh
//! § 4.4.14's pattern). `/etc` files require a two-step `sudo cat |
//! sudo -u sandbox tee` because the destination directory is owned by
//! `sandbox:sandbox` but the source is `root:root`-only readable; the
//! intermediate "read as root, write as sandbox" pipeline keeps both
//! ends honest.

use std::path::{Path, PathBuf};
use std::process::Command;

use ring::digest;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Parent directory for every backup set. Spec 5 § 5.1. Created by the
/// daemon at first start (mode `0700 sandbox:sandbox`).
pub const BACKUPS_ROOT: &str = "/var/lib/sandbox/backups";

/// Number of `completed_ok: true` backup sets to keep around. Spec 5
/// § 5.2. Sets with `completed_ok: false` (in-progress / failed) are
/// **never** auto-pruned — they preserve forensic evidence until the
/// operator removes them manually.
pub const RETENTION_KEEP: usize = 2;

/// The sandbox-owned production paths the backup set captures.
pub const SESSIONS_DB_PATH: &str = "/var/lib/sandbox/sessions.db";
pub const USERS_CONF_PATH: &str = "/etc/sandboxd/users.conf";
pub const BRIDGE_CONF_PATH: &str = "/etc/qemu/bridge.conf";
pub const SANDBOXD_BIN_PATH: &str = "/usr/local/bin/sandboxd";
pub const SANDBOX_BIN_PATH: &str = "/usr/local/bin/sandbox";
pub const ROUTE_HELPER_BIN_PATH: &str = "/usr/local/libexec/sandboxd/sandbox-route-helper";

// ---------------------------------------------------------------------------
// Manifest shape
// ---------------------------------------------------------------------------

/// Per-file entry inside the manifest's `files` map. Spec 5 § 5.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFileEntry {
    pub sha256: String,
    pub size: u64,
}

/// Backup set manifest. Spec 5 § 5.3. Written at step § 3.2.19 with
/// `completed_ok: false`, finalised at step § 3.2.29 with
/// `completed_ok: true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub from_version: String,
    pub to_version: String,
    pub started_at: String,
    /// `None` until step § 3.2.29 finalises the set.
    #[serde(default)]
    pub completed_at: Option<String>,
    pub completed_ok: bool,
    pub arch: String,
    /// Map of basename (e.g. `sandboxd.bak`) → `{sha256, size}`.
    pub files: std::collections::BTreeMap<String, ManifestFileEntry>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("subprocess `{cmd}` exited {code:?}: {stderr}")]
    Subprocess {
        cmd: String,
        code: Option<i32>,
        stderr: String,
    },
    #[error("encode manifest: {0}")]
    Encode(serde_json::Error),
    #[error("decode manifest: {0}")]
    Decode(serde_json::Error),
}

// ---------------------------------------------------------------------------
// Set creation
// ---------------------------------------------------------------------------

/// Build the canonical backup-set directory name.
///
/// Format: `<ISO8601>-from-<v1>-to-<v2>`. `ls -td` lists newest first
/// because the ISO8601 prefix is lexicographically chronological.
pub fn backup_set_name(started_at: &str, from_version: &str, to_version: &str) -> String {
    format!("{started_at}-from-{from_version}-to-{to_version}")
}

/// Create the backup-set directory under `BACKUPS_ROOT` (or under the
/// given override for tests). Idempotent — re-running on an existing
/// directory is a no-op. Mode `0700 sandbox:sandbox`.
///
/// In production this shells out to `sudo -k -u sandbox mkdir -p`; for
/// tests we expose [`create_backup_set_dir_at`] which uses plain
/// `std::fs` against a test-owned parent dir.
pub fn create_backup_set_dir(set_name: &str) -> Result<PathBuf, BackupError> {
    let target = Path::new(BACKUPS_ROOT).join(set_name);
    run_sudo(&[
        "-k",
        "-u",
        "sandbox",
        "mkdir",
        "-p",
        target.to_str().unwrap(),
    ])?;
    Ok(target)
}

/// Test-only variant of [`create_backup_set_dir`]. Does NOT shell out
/// to sudo; uses `std::fs::create_dir_all` against an arbitrary parent.
/// Integration tests stash the backup set under a tempdir-owned root
/// so the test process can write/read without root.
pub fn create_backup_set_dir_at(root: &Path, set_name: &str) -> Result<PathBuf, BackupError> {
    let target = root.join(set_name);
    std::fs::create_dir_all(&target)?;
    Ok(target)
}

// ---------------------------------------------------------------------------
// File-level backup primitives
// ---------------------------------------------------------------------------

/// Result of a single backup-copy operation. Returned so the caller can
/// build the per-file `manifest.files` entry without re-hashing.
#[derive(Debug, Clone)]
pub struct CopyOutcome {
    pub action: CopyAction,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyAction {
    /// The destination did not exist, or its bytes differed from the
    /// source — we performed a fresh copy.
    Copied,
    /// The destination already existed with identical bytes — no
    /// state mutation. Spec 5 § 3.2.15-17 idempotency anchor.
    Skipped,
    /// The source did not exist — the backup step is a no-op (e.g.
    /// `bridge.conf` on a fresh install that has not yet touched the
    /// file). The manifest entry is omitted by the caller.
    SourceAbsent,
}

/// Copy `src` to `dst` as `sandbox:sandbox` at `mode`, with sha256
/// idempotency. Spec 5 §§ 3.2.15 / 3.2.17.
///
/// Behaviour:
/// * Source missing → returns `CopyAction::SourceAbsent` (no file
///   mutation).
/// * Destination exists with identical bytes → `CopyAction::Skipped`.
/// * Otherwise → invokes `sudo -k -u sandbox install -m <mode>`.
pub fn backup_sandbox_owned_file(
    src: &Path,
    dst: &Path,
    mode: u32,
) -> Result<CopyOutcome, BackupError> {
    if !src.exists() {
        return Ok(CopyOutcome {
            action: CopyAction::SourceAbsent,
            sha256: String::new(),
            size: 0,
        });
    }
    let (src_sha, src_size) = sha256_of_file(src)?;
    if dst.exists() {
        // The destination is owned `sandbox:sandbox` and may not be
        // world-readable (sessions.db is 0600). Hash via sudo so a
        // root-invoked rerun can compare.
        if let Ok((dst_sha, _)) = sha256_of_file_sudo(dst)
            && dst_sha == src_sha
        {
            return Ok(CopyOutcome {
                action: CopyAction::Skipped,
                sha256: src_sha,
                size: src_size,
            });
        }
    }
    let mode_str = format!("{mode:04o}");
    run_sudo(&[
        "-k",
        "-u",
        "sandbox",
        "install",
        "-m",
        &mode_str,
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ])?;
    Ok(CopyOutcome {
        action: CopyAction::Copied,
        sha256: src_sha,
        size: src_size,
    })
}

/// Backup an `/etc` file (root-owned, world-readable at `0644`) into
/// the `sandbox`-owned backup set. Spec 5 § 3.2.16. The two-step
/// `sudo cat | sudo -u sandbox tee` pipeline lets the daemon-user
/// land bytes it cannot read in-place but can be handed via the
/// pipeline.
pub fn backup_etc_file(src: &Path, dst: &Path, mode: u32) -> Result<CopyOutcome, BackupError> {
    if !src.exists() {
        return Ok(CopyOutcome {
            action: CopyAction::SourceAbsent,
            sha256: String::new(),
            size: 0,
        });
    }
    let (src_sha, src_size) = sha256_of_file(src)?;
    if dst.exists()
        && let Ok((dst_sha, _)) = sha256_of_file_sudo(dst)
        && dst_sha == src_sha
    {
        return Ok(CopyOutcome {
            action: CopyAction::Skipped,
            sha256: src_sha,
            size: src_size,
        });
    }
    // `sudo -k cat <src> | sudo -k -u sandbox tee <dst> >/dev/null` —
    // we drive the pipeline via `std::process::Command` so the parent
    // process can wait on both ends. `tee` is preferred over `cp`
    // because we cross a uid boundary; the bytes are explicit on the
    // pipe and the destination is created at the right ownership.
    pipe_sudo_cat_to_sandbox_tee(src, dst)?;
    let mode_str = format!("{mode:04o}");
    run_sudo(&[
        "-k",
        "-u",
        "sandbox",
        "chmod",
        &mode_str,
        dst.to_str().unwrap(),
    ])?;
    Ok(CopyOutcome {
        action: CopyAction::Copied,
        sha256: src_sha,
        size: src_size,
    })
}

// ---------------------------------------------------------------------------
// Manifest write / finalise
// ---------------------------------------------------------------------------

/// Write the in-progress manifest at `<set>/manifest.json` per Spec 5
/// § 3.2.19. Owned `sandbox:sandbox` at mode `0644`. Idempotent: the
/// write goes through a tempfile under the set directory so a re-run
/// overwrites whatever was there.
pub fn write_in_progress_manifest(
    set_dir: &Path,
    manifest: &BackupManifest,
) -> Result<(), BackupError> {
    let bytes = serde_json::to_vec_pretty(manifest).map_err(BackupError::Encode)?;
    write_sandbox_owned_file(&set_dir.join("manifest.json"), &bytes, 0o644)
}

/// Re-read the manifest from a set directory. Used by retention prune
/// (§ 3.2.25) and by tests that verify post-write shape.
pub fn read_manifest(set_dir: &Path) -> Result<BackupManifest, BackupError> {
    let bytes = read_sandbox_owned_file(&set_dir.join("manifest.json"))?;
    serde_json::from_slice(&bytes).map_err(BackupError::Decode)
}

/// Finalise the manifest with `completed_ok: true` and a `completed_at`
/// timestamp. Spec 5 § 3.2.29.
pub fn finalize_manifest(
    set_dir: &Path,
    completed_at: &str,
) -> Result<BackupManifest, BackupError> {
    let mut m = read_manifest(set_dir)?;
    m.completed_ok = true;
    m.completed_at = Some(completed_at.to_string());
    let bytes = serde_json::to_vec_pretty(&m).map_err(BackupError::Encode)?;
    write_sandbox_owned_file(&set_dir.join("manifest.json"), &bytes, 0o644)?;
    Ok(m)
}

// ---------------------------------------------------------------------------
// Retention prune
// ---------------------------------------------------------------------------

/// Outcome of a retention prune call.
#[derive(Debug, Clone)]
pub struct PruneOutcome {
    /// Set directory names that were removed.
    pub pruned: Vec<String>,
    /// Set directory names kept (the most recent `RETENTION_KEEP`
    /// successful sets).
    pub kept: Vec<String>,
    /// Set directory names skipped because their `completed_ok` flag is
    /// not `true` (in-progress or failed). Spec 5 § 5.2: never auto-prune.
    pub preserved_forensic: Vec<String>,
}

/// Apply the retention policy to every set under `BACKUPS_ROOT`.
/// Spec 5 §§ 3.2.25 / 5.2.
///
/// Algorithm:
/// 1. Enumerate every subdirectory of the backups root.
/// 2. For each, read `manifest.json` (skip on read error).
/// 3. Partition into "completed_ok=true" and "everything else"
///    (in-progress / failed). The latter is never pruned.
/// 4. Sort completed sets by `started_at` descending.
/// 5. Keep the first `RETENTION_KEEP`; `rm -rf` the rest.
///
/// The current run's set is by construction `completed_ok: false` at
/// this point (§ 3.2.19 wrote the in-progress marker; § 3.2.29 sets it
/// to true after this prune step) — it lands in the "preserved" bucket
/// and is not pruned.
pub fn prune_old_backup_sets() -> Result<PruneOutcome, BackupError> {
    prune_old_backup_sets_at(Path::new(BACKUPS_ROOT))
}

/// Path-explicit variant of [`prune_old_backup_sets`] for tests that
/// stage a synthetic backups tree under a tempdir.
pub fn prune_old_backup_sets_at(root: &Path) -> Result<PruneOutcome, BackupError> {
    if !root.exists() {
        return Ok(PruneOutcome {
            pruned: Vec::new(),
            kept: Vec::new(),
            preserved_forensic: Vec::new(),
        });
    }
    let mut completed: Vec<(String, String, PathBuf)> = Vec::new(); // (name, started_at, path)
    let mut preserved: Vec<String> = Vec::new();
    let entries = list_dir_sudo(root)?;
    for entry_name in entries {
        let path = root.join(&entry_name);
        if !path.is_dir() {
            continue;
        }
        let manifest = match read_manifest(&path) {
            Ok(m) => m,
            Err(_) => {
                // Unparseable manifest — forensic. Never prune.
                preserved.push(entry_name);
                continue;
            }
        };
        if manifest.completed_ok {
            completed.push((entry_name, manifest.started_at, path));
        } else {
            preserved.push(entry_name);
        }
    }
    // Descending by started_at — newest first.
    completed.sort_by(|a, b| b.1.cmp(&a.1));
    let mut kept: Vec<String> = Vec::new();
    let mut pruned: Vec<String> = Vec::new();
    for (i, (name, _, path)) in completed.into_iter().enumerate() {
        if i < RETENTION_KEEP {
            kept.push(name);
        } else {
            remove_dir_all_sudo(&path)?;
            pruned.push(name);
        }
    }
    Ok(PruneOutcome {
        pruned,
        kept,
        preserved_forensic: preserved,
    })
}

// ---------------------------------------------------------------------------
// sha256 helpers
// ---------------------------------------------------------------------------

/// Compute the sha256 + size of a file readable by the current process.
fn sha256_of_file(path: &Path) -> Result<(String, u64), BackupError> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut ctx = digest::Context::new(&digest::SHA256);
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex_encode(ctx.finish().as_ref()), total))
}

/// Compute sha256 + size by shelling out to `sudo -k sha256sum`. Used
/// for destinations the current process cannot read directly (e.g.
/// `sessions.db.bak` owned `sandbox:sandbox` at mode `0600`).
fn sha256_of_file_sudo(path: &Path) -> Result<(String, u64), BackupError> {
    let out = run_sudo_capture(&["-k", "sha256sum", path.to_str().unwrap()])?;
    let stdout = String::from_utf8_lossy(&out);
    let first = stdout.split_whitespace().next().unwrap_or("");
    if first.len() != 64 {
        return Err(BackupError::Subprocess {
            cmd: "sha256sum".to_string(),
            code: Some(0),
            stderr: format!("unexpected sha256sum output: {stdout}"),
        });
    }
    let size = match run_sudo_capture(&["-k", "stat", "-c", "%s", path.to_str().unwrap()]) {
        Ok(bytes) => String::from_utf8_lossy(&bytes)
            .trim()
            .parse::<u64>()
            .unwrap_or(0),
        Err(_) => 0,
    };
    Ok((first.to_string(), size))
}

/// `ring::digest::Digest::as_ref()` returns raw bytes; hex-encode them
/// for the manifest's string-typed sha256 field.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// Sudo plumbing
// ---------------------------------------------------------------------------

/// Run `sudo <args>` and propagate stderr on non-zero exit.
fn run_sudo(args: &[&str]) -> Result<(), BackupError> {
    let mut cmd = Command::new("sudo");
    cmd.args(args);
    let status = cmd.output().map_err(BackupError::Io)?;
    if !status.status.success() {
        return Err(BackupError::Subprocess {
            cmd: format!("sudo {}", args.join(" ")),
            code: status.status.code(),
            stderr: String::from_utf8_lossy(&status.stderr).into_owned(),
        });
    }
    Ok(())
}

/// Run `sudo <args>` and return stdout bytes on success.
fn run_sudo_capture(args: &[&str]) -> Result<Vec<u8>, BackupError> {
    let mut cmd = Command::new("sudo");
    cmd.args(args);
    let out = cmd.output().map_err(BackupError::Io)?;
    if !out.status.success() {
        return Err(BackupError::Subprocess {
            cmd: format!("sudo {}", args.join(" ")),
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(out.stdout)
}

/// `sudo -k cat <src>` piped into `sudo -k -u sandbox tee <dst>`.
fn pipe_sudo_cat_to_sandbox_tee(src: &Path, dst: &Path) -> Result<(), BackupError> {
    use std::process::Stdio;
    let mut reader = Command::new("sudo")
        .args(["-k", "cat", src.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(BackupError::Io)?;
    let reader_stdout = reader
        .stdout
        .take()
        .ok_or_else(|| BackupError::Io(std::io::Error::other("cat stdout missing")))?;
    let writer = Command::new("sudo")
        .args(["-k", "-u", "sandbox", "tee", dst.to_str().unwrap()])
        .stdin(Stdio::from(reader_stdout))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(BackupError::Io)?;
    let w_out = writer.wait_with_output().map_err(BackupError::Io)?;
    let r_status = reader.wait().map_err(BackupError::Io)?;
    if !r_status.success() {
        return Err(BackupError::Subprocess {
            cmd: format!("sudo -k cat {}", src.display()),
            code: r_status.code(),
            stderr: "cat failed (stderr captured separately)".to_string(),
        });
    }
    if !w_out.status.success() {
        return Err(BackupError::Subprocess {
            cmd: format!("sudo -k -u sandbox tee {}", dst.display()),
            code: w_out.status.code(),
            stderr: String::from_utf8_lossy(&w_out.stderr).into_owned(),
        });
    }
    Ok(())
}

/// Write `bytes` to a `sandbox`-owned file at `mode`. Uses a tempfile
/// under `/tmp` written by the current process, then `sudo -k -u
/// sandbox install -m <mode> <tmp> <dst>` to atomically land it at
/// the right ownership.
fn write_sandbox_owned_file(dst: &Path, bytes: &[u8], mode: u32) -> Result<(), BackupError> {
    let mut tmp = tempfile::NamedTempFile::new().map_err(BackupError::Io)?;
    use std::io::Write;
    tmp.write_all(bytes).map_err(BackupError::Io)?;
    tmp.flush().map_err(BackupError::Io)?;
    let tmp_path = tmp.path().to_path_buf();
    let mode_str = format!("{mode:04o}");
    run_sudo(&[
        "-k",
        "-u",
        "sandbox",
        "install",
        "-m",
        &mode_str,
        tmp_path.to_str().unwrap(),
        dst.to_str().unwrap(),
    ])?;
    // `tmp` drops here — the tempfile is unlinked from `/tmp`.
    Ok(())
}

/// Read a `sandbox`-owned file via `sudo -k cat`. The current process
/// may not have direct read access (depending on mode) so we always
/// elevate.
fn read_sandbox_owned_file(path: &Path) -> Result<Vec<u8>, BackupError> {
    run_sudo_capture(&["-k", "cat", path.to_str().unwrap()])
}

/// List the basenames of every entry under `dir`. Uses `sudo -k ls -1`
/// because `/var/lib/sandbox/backups/` is mode `0700 sandbox:sandbox`.
fn list_dir_sudo(dir: &Path) -> Result<Vec<String>, BackupError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    // Tests pass a tempdir we own; production passes `/var/lib/...`.
    // For the test path we can read directly; production needs sudo.
    if let Ok(rd) = std::fs::read_dir(dir) {
        let mut names = Vec::new();
        for entry in rd.flatten() {
            if let Some(n) = entry.file_name().to_str() {
                names.push(n.to_string());
            }
        }
        return Ok(names);
    }
    let out = run_sudo_capture(&["-k", "ls", "-1", dir.to_str().unwrap()])?;
    let s = String::from_utf8_lossy(&out);
    Ok(s.lines().map(|l| l.to_string()).collect())
}

/// `rm -rf` on a backup-set directory. Uses `sudo -k -u sandbox` so the
/// ownership semantics match the create path.
fn remove_dir_all_sudo(path: &Path) -> Result<(), BackupError> {
    // For tests against a tempdir-owned tree, plain remove_dir_all
    // works without sudo.
    if std::fs::remove_dir_all(path).is_ok() {
        return Ok(());
    }
    run_sudo(&["-k", "-u", "sandbox", "rm", "-rf", path.to_str().unwrap()])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_manifest(
        from: &str,
        to: &str,
        started_at: &str,
        completed_ok: bool,
    ) -> BackupManifest {
        BackupManifest {
            from_version: from.to_string(),
            to_version: to.to_string(),
            started_at: started_at.to_string(),
            completed_at: if completed_ok {
                Some(started_at.to_string())
            } else {
                None
            },
            completed_ok,
            arch: "x86_64-unknown-linux-gnu".to_string(),
            files: Default::default(),
        }
    }

    fn write_synth_manifest(set_dir: &Path, m: &BackupManifest) {
        std::fs::create_dir_all(set_dir).unwrap();
        let bytes = serde_json::to_vec_pretty(m).unwrap();
        std::fs::write(set_dir.join("manifest.json"), bytes).unwrap();
    }

    /// `backup_set_name` produces the layout documented in § 5.1 and
    /// the prefix is lexicographically chronological.
    #[test]
    fn backup_set_name_shape() {
        let name = backup_set_name("2026-05-11T14:23:11Z", "1.0.0", "1.1.0");
        assert_eq!(name, "2026-05-11T14:23:11Z-from-1.0.0-to-1.1.0");
        let earlier = backup_set_name("2026-05-09T09:11:42Z", "0.9.5", "1.0.0");
        assert!(name > earlier, "ISO8601 prefix should sort chronologically");
    }

    /// Retention prune: 3 successful sets + 1 in-progress → keep the
    /// 2 newest successful, prune the oldest, never touch the
    /// in-progress one.
    #[test]
    fn retention_prune_keeps_two_newest_and_preserves_forensic() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let oldest = root.join("2026-05-07T12:00:00Z-from-0.9.4-to-0.9.5");
        let middle = root.join("2026-05-09T09:11:42Z-from-0.9.5-to-1.0.0");
        let newest = root.join("2026-05-11T14:23:11Z-from-1.0.0-to-1.1.0");
        let in_progress = root.join("2026-05-12T10:00:00Z-from-1.1.0-to-1.2.0");

        write_synth_manifest(
            &oldest,
            &synth_manifest("0.9.4", "0.9.5", "2026-05-07T12:00:00Z", true),
        );
        write_synth_manifest(
            &middle,
            &synth_manifest("0.9.5", "1.0.0", "2026-05-09T09:11:42Z", true),
        );
        write_synth_manifest(
            &newest,
            &synth_manifest("1.0.0", "1.1.0", "2026-05-11T14:23:11Z", true),
        );
        write_synth_manifest(
            &in_progress,
            &synth_manifest("1.1.0", "1.2.0", "2026-05-12T10:00:00Z", false),
        );

        let outcome = prune_old_backup_sets_at(root).expect("prune ok");
        assert_eq!(outcome.kept.len(), 2, "keep exactly 2: {:?}", outcome.kept);
        assert_eq!(outcome.pruned.len(), 1, "prune 1: {:?}", outcome.pruned);
        assert_eq!(outcome.preserved_forensic.len(), 1);
        assert!(
            outcome.preserved_forensic[0].contains("1.1.0-to-1.2.0"),
            "in-progress set preserved: {:?}",
            outcome.preserved_forensic
        );
        assert!(!oldest.exists(), "oldest pruned");
        assert!(middle.exists(), "middle kept");
        assert!(newest.exists(), "newest kept");
        assert!(in_progress.exists(), "in-progress preserved");
    }

    /// Retention prune is idempotent: a second run against the
    /// post-prune tree is a no-op.
    #[test]
    fn retention_prune_idempotent_when_at_retention_count() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for (i, ts) in ["2026-05-09T00:00:00Z", "2026-05-10T00:00:00Z"]
            .iter()
            .enumerate()
        {
            let d = root.join(format!("{ts}-from-1.0.{i}-to-1.0.{}", i + 1));
            write_synth_manifest(&d, &synth_manifest("a", "b", ts, true));
        }
        let first = prune_old_backup_sets_at(root).unwrap();
        assert!(first.pruned.is_empty(), "first run: nothing to prune");
        let second = prune_old_backup_sets_at(root).unwrap();
        assert!(second.pruned.is_empty(), "second run: still nothing");
        assert_eq!(second.kept.len(), 2);
    }

    /// A backup set with an unparseable manifest is preserved (never
    /// pruned) — the file is forensic evidence the operator can
    /// inspect by hand.
    #[test]
    fn retention_prune_preserves_unparseable_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let broken = root.join("2026-05-09T00:00:00Z-from-1.0.0-to-1.1.0");
        std::fs::create_dir_all(&broken).unwrap();
        std::fs::write(broken.join("manifest.json"), b"this is not json").unwrap();
        let outcome = prune_old_backup_sets_at(root).unwrap();
        assert_eq!(outcome.preserved_forensic.len(), 1);
        assert!(outcome.pruned.is_empty());
        assert!(broken.exists());
    }

    /// hex_encode round-trips correctly for a few known inputs.
    #[test]
    fn hex_encode_basic() {
        assert_eq!(hex_encode(&[0]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    /// sha256_of_file matches a known vector (empty file).
    #[test]
    fn sha256_of_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("empty");
        std::fs::write(&p, b"").unwrap();
        let (sha, size) = sha256_of_file(&p).unwrap();
        assert_eq!(size, 0);
        assert_eq!(
            sha,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Manifest round-trip preserves every field.
    #[test]
    fn manifest_serde_round_trip() {
        let mut m = synth_manifest("1.0.0", "1.1.0", "2026-05-11T14:23:11Z", false);
        m.files.insert(
            "sandboxd.bak".to_string(),
            ManifestFileEntry {
                sha256: "deadbeef".repeat(8),
                size: 1234567,
            },
        );
        let bytes = serde_json::to_vec_pretty(&m).unwrap();
        let parsed: BackupManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.from_version, "1.0.0");
        assert_eq!(parsed.files.len(), 1);
        assert!(!parsed.completed_ok);
        assert!(parsed.completed_at.is_none());
    }

    /// Manifest tolerates an older payload that lacks `completed_at`
    /// (the field is `#[serde(default)]`).
    #[test]
    fn manifest_decode_tolerates_missing_completed_at() {
        let json = serde_json::json!({
            "from_version": "1.0.0",
            "to_version": "1.1.0",
            "started_at": "2026-05-11T14:23:11Z",
            "completed_ok": false,
            "arch": "x86_64-unknown-linux-gnu",
            "files": {}
        });
        let parsed: BackupManifest = serde_json::from_value(json).unwrap();
        assert!(parsed.completed_at.is_none());
    }
}
