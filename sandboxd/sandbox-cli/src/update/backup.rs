//! Backup-set management for `sandbox update`.
//!
//! A "backup set" is one subdirectory under `/var/lib/sandbox/backups/`
//! capturing every artefact `sandbox update` mutates: the daemon
//! binary, the CLI binary, the route-helper, `sessions.db`, and the
//! managed `/etc` files. Each set carries a `manifest.json` recording
//! the from/to versions, timestamps, and per-file sha256 hashes —
//! that manifest is what the retention prune reads to
//! decide which sets are eligible for removal (`completed_ok: true`
//! only) and what the rollback recipe enumerates when an
//! operator wants to step back.
//!
//! ## Ownership / mode contract
//!
//! All artefacts in the set are owned `sandbox:sandbox`. Binaries land
//! at mode `0640` — **not executable** — so a wandering operator
//! cannot accidentally invoke the old binary from PATH (the rollback
//! recipe `install -m 0755`s them back in place). The `sessions.db`
//! backup is `0600` (same as the production DB). `/etc` files are
//! `0644` (matches the production modes documented).
//!
//! ## Idempotency
//!
//! Every per-file copy method short-circuits if the destination
//! already exists and its bytes match the source's bytes (compared via
//! sha256). The shell pseudo-code in the design uses `cmp -s`; we use a
//! sha256 round-trip so the same hash drops into the manifest's
//! `files` map without a second pass.
//!
//! ## Sudo elevation
//!
//! All file operations that need to land at `sandbox:sandbox` ownership
//! shell out via `sudo -k -u sandbox install ...` (matching install.sh
//! conventions). `/etc` files require a two-step `sudo cat |
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

/// Parent directory for every backup set. Created by the
/// daemon at first start (mode `0700 sandbox:sandbox`).
pub const BACKUPS_ROOT: &str = "/var/lib/sandbox/backups";

/// Number of `completed_ok: true` backup sets to keep around.
/// Sets with `completed_ok: false` (in-progress / failed) are
/// **never** auto-pruned — they preserve forensic evidence until the
/// operator removes them manually.
pub const RETENTION_KEEP: usize = 2;

/// The sandbox-owned production paths the backup set captures.
pub const SESSIONS_DB_PATH: &str = "/var/lib/sandbox/sessions.db";
/// SQLite WAL companion file. The daemon runs in WAL journal mode
/// (`store.rs:117`), so uncommitted-on-disk-but-committed-in-WAL
/// transactions live in `sessions.db-wal` between checkpoints. Backing
/// up only `sessions.db` would lose those records if the daemon was
/// not cleanly stopped before the snapshot.
pub const SESSIONS_DB_WAL_PATH: &str = "/var/lib/sandbox/sessions.db-wal";
/// SQLite shared-memory index file. The WAL header references offsets
/// stored here; SQLite recovers cleanly from a bundle containing
/// (.db, -wal, -shm) without manual checkpoint orchestration.
pub const SESSIONS_DB_SHM_PATH: &str = "/var/lib/sandbox/sessions.db-shm";
pub const USERS_CONF_PATH: &str = "/etc/sandboxd/users.conf";
pub const BRIDGE_CONF_PATH: &str = "/etc/qemu/bridge.conf";
pub const SANDBOXD_BIN_PATH: &str = "/usr/local/bin/sandboxd";
pub const SANDBOX_BIN_PATH: &str = "/usr/local/bin/sandbox";
pub const ROUTE_HELPER_BIN_PATH: &str = "/usr/local/libexec/sandboxd/sandbox-route-helper";
/// Daemon-internal helper. Installed under libexec (FHS § 4.7) so the
/// daemon's startup-staging path can read it; never exposed on
/// `$PATH`. Mirrors the install.sh layout.
pub const GUEST_BIN_PATH: &str = "/usr/local/libexec/sandboxd/sandbox-guest";

// ---------------------------------------------------------------------------
// Manifest shape
// ---------------------------------------------------------------------------

/// Per-file entry inside the manifest's `files` map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFileEntry {
    pub sha256: String,
    pub size: u64,
}

/// Backup set manifest. Written at the manifest-write step with
/// `completed_ok: false`, finalised at the install-state-finalize step with
/// `completed_ok: true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub from_version: String,
    pub to_version: String,
    pub started_at: String,
    /// `None` until the install-state-finalize step finalises the set.
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
    /// state mutation. Idempotency anchor for the binary-install steps.
    Skipped,
    /// The source did not exist — the backup step is a no-op (e.g.
    /// `bridge.conf` on a fresh install that has not yet touched the
    /// file). The manifest entry is omitted by the caller.
    SourceAbsent,
}

/// Copy `src` to `dst` as `sandbox:sandbox` at `mode`, with sha256
/// idempotency.
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
/// the `sandbox`-owned backup set. The two-step
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

/// Write the in-progress manifest at `<set>/manifest.json`. Owned `sandbox:sandbox`
/// at mode `0644`. Idempotent: the
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
/// and by tests that verify post-write shape.
pub fn read_manifest(set_dir: &Path) -> Result<BackupManifest, BackupError> {
    let bytes = read_sandbox_owned_file(&set_dir.join("manifest.json"))?;
    serde_json::from_slice(&bytes).map_err(BackupError::Decode)
}

/// Finalise the manifest with `completed_ok: true` and a `completed_at`
/// timestamp.
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
    /// not `true` (in-progress or failed)..2: never auto-prune.
    pub preserved_forensic: Vec<String>,
}

/// Apply the retention policy to every set under `BACKUPS_ROOT`.
///
/// Algorithm:
/// 1. Enumerate every subdirectory of the backups root.
/// 2. For each, read `manifest.json` (skip on read error).
/// 3. Partition into "completed_ok=true" and "everything else"
///    (in-progress / failed). The latter is never pruned.
/// 4. Sort completed sets by `started_at` descending.
/// 5. Keep the first `RETENTION_KEEP`; `rm -rf` the rest.
///
/// Call ordering: this function runs AFTER `finalize_manifest`
/// (which flips the current run's set to `completed_ok: true`),
/// so the current run is counted as one of the `RETENTION_KEEP`
/// most-recent successful sets. Running it before finalize would
/// leave the current set at `completed_ok: false`, partition it
/// into the "preserved" bucket, and drift the on-disk count to
/// `RETENTION_KEEP + 1` in steady state.
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

/// Compute sha256 + size of a `sandbox`-owned file. Tries an
/// unprivileged read first and falls back to `sudo sha256sum` when
/// that fails — mirrors `read_sandbox_owned_file`.
fn sha256_of_file_sudo(path: &Path) -> Result<(String, u64), BackupError> {
    // Tests pass a tempdir we own; production passes /var/lib/...
    // For the test path we can hash directly; production needs sudo.
    if let Ok(result) = sha256_of_file(path) {
        return Ok(result);
    }
    let out = run_sudo_capture(&["sha256sum", path.to_str().unwrap()])?;
    let stdout = String::from_utf8_lossy(&out);
    let first = stdout.split_whitespace().next().unwrap_or("");
    if first.len() != 64 {
        return Err(BackupError::Subprocess {
            cmd: "sha256sum".to_string(),
            code: Some(0),
            stderr: format!("unexpected sha256sum output: {stdout}"),
        });
    }
    let size = match run_sudo_capture(&["stat", "-c", "%s", path.to_str().unwrap()]) {
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

/// `sudo` invocation prefix every backup helper runs through. The
/// `-k` flag forces a fresh credential prompt by discarding any
/// cached operator credentials before the call;.3 names
/// this the "no-cached-sudo" invariant — every privileged step in
/// the update flow must re-authenticate so an unattended terminal
/// session cannot inadvertently authorize a stateful mutation.
///
/// The helpers below splice this prefix in front of the caller's
/// args so the invariant is enforced centrally rather than relying
/// on every call site to remember the `-k`. Calls that nominally
/// supply their own `-k` still work — sudo accepts repeated `-k` —
/// but the canonical pattern is now to pass only the post-`sudo -k`
/// argv.
const SUDO_PREFIX: &[&str] = &["-k"];

/// Run `sudo -k <args>` and propagate stderr on non-zero exit. The
/// `-k` (kill cached credentials) prefix is enforced internally —
/// callers pass only the post-`-k` argv. Calls that still include
/// a redundant `-k` are tolerated (repeated `-k` is idempotent in
/// sudo).
fn run_sudo(args: &[&str]) -> Result<(), BackupError> {
    let mut cmd = Command::new("sudo");
    cmd.args(SUDO_PREFIX);
    cmd.args(args);
    let status = cmd.output().map_err(BackupError::Io)?;
    if !status.status.success() {
        return Err(BackupError::Subprocess {
            cmd: format!("sudo -k {}", args.join(" ")),
            code: status.status.code(),
            stderr: String::from_utf8_lossy(&status.stderr).into_owned(),
        });
    }
    Ok(())
}

/// Run `sudo -k <args>` and return stdout bytes on success. Same
/// `-k`-enforcement semantics as [`run_sudo`].
fn run_sudo_capture(args: &[&str]) -> Result<Vec<u8>, BackupError> {
    let mut cmd = Command::new("sudo");
    cmd.args(SUDO_PREFIX);
    cmd.args(args);
    let out = cmd.output().map_err(BackupError::Io)?;
    if !out.status.success() {
        return Err(BackupError::Subprocess {
            cmd: format!("sudo -k {}", args.join(" ")),
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
    // `NamedTempFile` defaults to mode 0600 owned by the running process
    // (root, when invoked via `sudo sandbox update`). The downstream
    // `sudo -u sandbox install` reads this file as the `sandbox` user;
    // widen the read bit so the install succeeds. The destination mode is
    // set independently by `install -m <mode>`.
    use std::os::unix::fs::PermissionsExt;
    let mut perm = std::fs::metadata(tmp.path())
        .map_err(BackupError::Io)?
        .permissions();
    perm.set_mode(0o644);
    std::fs::set_permissions(tmp.path(), perm).map_err(BackupError::Io)?;
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

/// Read a `sandbox`-owned file. Tries an unprivileged read first and
/// falls back to `sudo cat` when that fails — mirrors `list_dir_sudo`.
fn read_sandbox_owned_file(path: &Path) -> Result<Vec<u8>, BackupError> {
    // Tests pass a tempdir we own; production passes /var/lib/...
    // For the test path we can read directly; production needs sudo.
    if let Ok(bytes) = std::fs::read(path) {
        return Ok(bytes);
    }
    run_sudo_capture(&["cat", path.to_str().unwrap()])
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

    /// `backup_set_name` produces the layout `<ISO8601>-from-<ver>-to-<ver>` and
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

    /// WAL-safe backup contract: a SQLite database in WAL mode
    /// whose connection is dropped mid-write — leaving committed
    /// transactions in `sessions.db-wal` (and the offset index in
    /// `sessions.db-shm`) — is restored intact when the backup
    /// captures all three files as a bundle. A backup that copies
    /// only `sessions.db` loses the most recent commit; the bundle
    /// recovers it via SQLite's normal WAL-replay on first open.
    ///
    /// This pins the design contract: the backup step must
    /// bundle `sessions.db` + `sessions.db-wal` + `sessions.db-shm`.
    /// The test uses plain `std::fs::copy` to exercise the design
    /// contract — the production `backup_sandbox_owned_file` adds
    /// sudo plumbing and sha256 idempotency on top of the same
    /// bundling.
    #[test]
    fn wal_bundle_restores_most_recent_committed_transaction() {
        use rusqlite::Connection;

        let src_tmp = tempfile::tempdir().expect("src tempdir");
        let src_db = src_tmp.path().join("sessions.db");

        // Phase 1 — write a row in WAL mode, then drop the
        // connection WITHOUT issuing `PRAGMA wal_checkpoint`. This
        // is the "daemon killed mid-write" simulation: the commit
        // lands in `sessions.db-wal` but never makes it into the
        // main `.db` file. We use two trick-knobs to keep the WAL
        // populated past connection drop:
        //   1. `PRAGMA wal_autocheckpoint = 0` — disables the
        //      every-1000-pages auto-checkpoint that would otherwise
        //      flush the WAL during the INSERT.
        //   2. A second long-lived "reader" connection — SQLite
        //      skips the close-time checkpoint when another
        //      connection still has the WAL open. This pins the
        //      "daemon was killed; no clean shutdown" scenario
        //      against hosts whose libsqlite3 would otherwise
        //      auto-checkpoint on the writer's drop.
        let _reader = Connection::open(&src_db).expect("open reader");
        _reader
            .pragma_update(None, "journal_mode", "WAL")
            .expect("reader journal_mode=WAL");
        _reader
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("reader wal_autocheckpoint=0");
        {
            let conn = Connection::open(&src_db).expect("open writer");
            conn.pragma_update(None, "journal_mode", "WAL")
                .expect("writer journal_mode=WAL");
            conn.pragma_update(None, "wal_autocheckpoint", 0)
                .expect("writer wal_autocheckpoint=0");
            conn.execute_batch(
                "CREATE TABLE sessions (id INTEGER PRIMARY KEY, name TEXT NOT NULL);",
            )
            .expect("schema");
            conn.execute(
                "INSERT INTO sessions (id, name) VALUES (?1, ?2);",
                rusqlite::params![1, "kept-across-wal-replay"],
            )
            .expect("insert");
            // Drop the writer without explicit checkpoint. The
            // surviving `_reader` connection keeps SQLite from
            // close-time-checkpointing, leaving the WAL+SHM as the
            // canonical record of the commit. We deliberately keep
            // `_reader` alive (it's bound to the outer scope) until
            // the snapshot is captured.
            drop(conn);
        }

        // Sanity: WAL companion must exist and be non-empty. If the
        // host's SQLite still managed to auto-checkpoint the test's
        // premise doesn't hold; skip the WAL-safe assertion (we
        // cannot pin a contract we can't reproduce).
        let src_wal = src_tmp.path().join("sessions.db-wal");
        let src_shm = src_tmp.path().join("sessions.db-shm");
        let Ok(wal_meta) = std::fs::metadata(&src_wal) else {
            eprintln!(
                "warning: -wal file missing after drop; host SQLite likely \
                 auto-checkpointed despite wal_autocheckpoint=0 and a held \
                 reader connection — test cannot pin the WAL-safe contract \
                 on this host"
            );
            return;
        };
        if wal_meta.len() == 0 {
            eprintln!("warning: -wal file empty after drop; skipping WAL-safe assertion");
            return;
        }
        assert!(src_shm.exists(), "-shm must exist alongside -wal");

        // Phase 2 — bundle all three files into a backup set
        // mirroring what the sessions.db backup step produces in production. Plain
        // `fs::copy` exercises the file-bundling contract without
        // sudo; production's `backup_sandbox_owned_file` adds
        // sha256-idempotency + ownership transfer on top.
        let backup_tmp = tempfile::tempdir().expect("backup tempdir");
        let backup_set = backup_tmp.path().join("set");
        std::fs::create_dir_all(&backup_set).unwrap();
        for (src, dst_name) in [
            (&src_db, "sessions.db.bak"),
            (&src_wal, "sessions.db-wal.bak"),
            (&src_shm, "sessions.db-shm.bak"),
        ] {
            std::fs::copy(src, backup_set.join(dst_name)).expect("copy succeeds");
        }

        // Phase 3 — stage the backup as a recoverable triple under
        // a fresh tempdir, restoring the canonical filenames SQLite
        // expects. The rollback recipe documents this same step
        // (`sudo install -m 0600 sessions.db.bak /var/lib/sandbox/sessions.db`
        // and the matching `.db-wal` / `.db-shm` copies).
        let restore_tmp = tempfile::tempdir().expect("restore tempdir");
        let restore_db = restore_tmp.path().join("sessions.db");
        let restore_wal = restore_tmp.path().join("sessions.db-wal");
        let restore_shm = restore_tmp.path().join("sessions.db-shm");
        std::fs::copy(backup_set.join("sessions.db.bak"), &restore_db).unwrap();
        std::fs::copy(backup_set.join("sessions.db-wal.bak"), &restore_wal).unwrap();
        std::fs::copy(backup_set.join("sessions.db-shm.bak"), &restore_shm).unwrap();

        // Drop the held reader now that the bundle has been
        // captured. Leaving it open through phase 4 would not
        // affect correctness (the restore lives in a different
        // tempdir on a different inode), but releasing it pins
        // the test's resource lifecycle to the backup capture.
        drop(_reader);

        // Phase 4 — open the restored database. SQLite's normal
        // WAL-recovery on first open re-applies the committed
        // transactions sitting in `-wal`, and the row written in
        // phase 1 must be visible.
        let conn = Connection::open(&restore_db).expect("open restored");
        let name: String = conn
            .query_row("SELECT name FROM sessions WHERE id = 1", [], |row| {
                row.get(0)
            })
            .expect("recovered row must be present");
        assert_eq!(name, "kept-across-wal-replay");
    }

    /// Companion to the WAL bundle test: pin the negative case —
    /// when ONLY `sessions.db` is captured (no `-wal`, no `-shm`),
    /// the restored DB does NOT see the most recent commit. This
    /// is the failure mode the bundle fix exists to prevent;
    /// pinning both halves catches a future refactor that
    /// accidentally narrows the backup back to a single file.
    #[test]
    fn db_only_backup_loses_uncheckpointed_wal_transaction() {
        use rusqlite::Connection;

        let src_tmp = tempfile::tempdir().expect("src tempdir");
        let src_db = src_tmp.path().join("sessions.db");
        // Same trick as the positive case: hold an open reader to
        // suppress the close-time checkpoint. See the comment in
        // `wal_bundle_restores_most_recent_committed_transaction`
        // for the rationale.
        let _reader = Connection::open(&src_db).expect("open reader");
        _reader
            .pragma_update(None, "journal_mode", "WAL")
            .expect("reader journal_mode=WAL");
        _reader
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("reader wal_autocheckpoint=0");
        {
            let conn = Connection::open(&src_db).expect("open writer");
            conn.pragma_update(None, "journal_mode", "WAL")
                .expect("writer journal_mode=WAL");
            conn.pragma_update(None, "wal_autocheckpoint", 0)
                .expect("writer wal_autocheckpoint=0");
            conn.execute_batch(
                "CREATE TABLE sessions (id INTEGER PRIMARY KEY, name TEXT NOT NULL);",
            )
            .expect("schema");
            conn.execute(
                "INSERT INTO sessions (id, name) VALUES (?1, ?2);",
                rusqlite::params![1, "kept-across-wal-replay"],
            )
            .expect("insert");
            drop(conn);
        }
        let src_wal = src_tmp.path().join("sessions.db-wal");
        let Ok(wal_meta) = std::fs::metadata(&src_wal) else {
            // Host SQLite checkpointed despite the suppression
            // tricks; the negative-case premise doesn't apply.
            return;
        };
        if wal_meta.len() == 0 {
            // Same: host auto-checkpointed and emptied the WAL.
            return;
        }

        // Backup `.db` only — no `-wal`, no `-shm`.
        let backup_tmp = tempfile::tempdir().expect("backup tempdir");
        let backup_db = backup_tmp.path().join("sessions.db");
        std::fs::copy(&src_db, &backup_db).expect("copy succeeds");

        // Release the reader now that we've snapshotted; the
        // negative case opens the restore independently.
        drop(_reader);

        // Open the lone-db restore.
        let conn = Connection::open(&backup_db).expect("open restored");
        // The table itself might not exist (CREATE TABLE landed in
        // the WAL too), or the row might be missing. Either way,
        // the SELECT must NOT find the committed row.
        let lookup: rusqlite::Result<String> =
            conn.query_row("SELECT name FROM sessions WHERE id = 1", [], |row| {
                row.get(0)
            });
        match lookup {
            Err(_) => { /* Table or row absent — the loss-on-recovery contract */ }
            Ok(name) => panic!(
                "db-only backup unexpectedly recovered the WAL transaction \
                 (name={name:?}); the WAL-safe bundling contract is now moot — \
                 maybe SQLite auto-checkpointed and the negative case no \
                 longer holds"
            ),
        }
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

    /// `create_backup_set_dir_at` happy path: the returned path is the
    /// `<root>/<set_name>` join, the directory now exists, and the
    /// intermediate `<root>` was created on demand (`mkdir -p` semantics
    /// — `create_dir_all` is what the test-only path uses internally).
    ///
    /// Pre-this test the function was reached only transitively by the
    /// production `create_backup_set_dir` path (which shells to sudo
    /// and is not hermetic). Triage flagged the in-process variant's
    /// lack of direct coverage.
    #[test]
    fn create_backup_set_dir_at_creates_target_under_uncreated_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Nest the "root" one level below the tempdir so `mkdir -p`
        // semantics are exercised — `<tmp>/backups/` doesn't exist
        // when we call. The function's `create_dir_all` must create
        // both the root and the set subdirectory.
        let root = tmp.path().join("backups");
        assert!(!root.exists(), "root must not exist pre-call");
        let set_name = backup_set_name("2026-05-17T09:00:00Z", "1.0.0", "1.1.0");

        let target = create_backup_set_dir_at(&root, &set_name).expect("create ok");

        assert_eq!(
            target,
            root.join(&set_name),
            "returned path must be <root>/<set_name>"
        );
        assert!(target.exists(), "target directory must exist after call");
        assert!(target.is_dir(), "target must be a directory");
        // `mkdir -p` semantics: the parent was created too.
        assert!(root.exists(), "root must exist after call");
        assert!(root.is_dir(), "root must be a directory");
    }

    /// `create_backup_set_dir_at` is idempotent: a second call against
    /// an already-existing set directory is a no-op and does not
    /// disturb pre-existing contents. Pins the "re-run of a partially
    /// completed update doesn't clobber the backup set" property that
    /// the backup-step idempotency relies on at one layer up.
    #[test]
    fn create_backup_set_dir_at_idempotent_preserves_existing_contents() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let set_name = "2026-05-17T09:00:00Z-from-1.0.0-to-1.1.0";

        let target = create_backup_set_dir_at(root, set_name).expect("first call ok");
        // Drop a sentinel file inside; the second call must leave it
        // intact.
        let sentinel = target.join("sentinel.bin");
        std::fs::write(&sentinel, b"sentinel-bytes").expect("write sentinel");

        let target_again = create_backup_set_dir_at(root, set_name).expect("second call ok");

        assert_eq!(target, target_again, "second call returns same path");
        assert!(sentinel.exists(), "sentinel must survive idempotent call");
        assert_eq!(
            std::fs::read(&sentinel).expect("read sentinel"),
            b"sentinel-bytes",
            "sentinel contents must be byte-identical to pre-call"
        );
    }

    /// `create_backup_set_dir_at` error arm: when an intermediate path
    /// component is a regular file (not a directory), `create_dir_all`
    /// returns `io::ErrorKind::NotADirectory` (or `AlreadyExists` on
    /// some kernels — both shapes route through `BackupError::Io` via
    /// the `From<std::io::Error>` impl). Pins the typed-error surface
    /// so a regression that swallowed the io error and returned a
    /// degraded path would fail loudly.
    #[test]
    fn create_backup_set_dir_at_propagates_io_error_when_root_is_a_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Make a regular file at the path we'll pass as `root`. This
        // is the foot-gun shape an operator could trip over if the
        // backups parent path got accidentally clobbered to a file
        // (e.g. a botched `tee` redirection during a manual rollback).
        let root_as_file = tmp.path().join("backups");
        std::fs::write(&root_as_file, b"oops, this is a file").expect("seed regular file");

        let err = create_backup_set_dir_at(&root_as_file, "any-set-name")
            .expect_err("must error when intermediate component is a file");

        match err {
            BackupError::Io(io_err) => {
                // The two kernel-dependent shapes we accept here both
                // unambiguously identify the "not a directory" cause.
                // `NotADirectory` is the Linux-canonical mapping;
                // `AlreadyExists` can surface on older kernels or
                // tmpfs variants. Anything else (PermissionDenied,
                // NotFound, ...) is a regression worth surfacing.
                let kind = io_err.kind();
                assert!(
                    matches!(
                        kind,
                        std::io::ErrorKind::NotADirectory | std::io::ErrorKind::AlreadyExists
                    ),
                    "expected NotADirectory or AlreadyExists; got {kind:?}: {io_err}"
                );
            }
            other => panic!("expected BackupError::Io, got {other:?}"),
        }
    }

    /// `prune_old_backup_sets_at` early-return arm: when the backups
    /// root does not exist (fresh install before the first update has
    /// ever run, or a host where the daemon's startup-time mkdir
    /// hasn't landed yet), the function returns an empty
    /// `PruneOutcome` without erroring. Idempotency
    /// promise depends on this — the prune step must be a no-op when
    /// there are no sets to consider. Triage flagged this
    /// early-return as uncovered.
    #[test]
    fn prune_old_backup_sets_at_empty_outcome_when_root_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let absent_root = tmp.path().join("does-not-exist");
        assert!(!absent_root.exists(), "preflight: root must be absent");

        let outcome = prune_old_backup_sets_at(&absent_root).expect("must not error");

        assert!(
            outcome.pruned.is_empty(),
            "absent root: nothing to prune; got {:?}",
            outcome.pruned
        );
        assert!(
            outcome.kept.is_empty(),
            "absent root: nothing to keep; got {:?}",
            outcome.kept
        );
        assert!(
            outcome.preserved_forensic.is_empty(),
            "absent root: nothing preserved; got {:?}",
            outcome.preserved_forensic
        );
        // The absent root must remain absent — the early-return must
        // not have side-effects (e.g. accidental mkdir).
        assert!(
            !absent_root.exists(),
            "early-return must not create the absent root: {}",
            absent_root.display()
        );
    }

    /// `prune_old_backup_sets_at` skips every in-progress set
    /// (`completed_ok: false` is forensic — never auto-prune).
    /// With three in-progress sets and zero successful ones, all three
    /// land in `preserved_forensic` and the on-disk tree is unchanged
    /// after the prune. Complements
    /// `retention_prune_keeps_two_newest_and_preserves_forensic` which
    /// pins the mixed case; this pins the all-in-progress edge.
    #[test]
    fn prune_old_backup_sets_at_preserves_when_all_sets_in_progress() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();

        let sets = [
            ("2026-05-07T12:00:00Z-from-0.9.4-to-0.9.5", "0.9.4", "0.9.5"),
            ("2026-05-09T09:11:42Z-from-0.9.5-to-1.0.0", "0.9.5", "1.0.0"),
            ("2026-05-11T14:23:11Z-from-1.0.0-to-1.1.0", "1.0.0", "1.1.0"),
        ];
        for (dir_name, from, to) in sets.iter() {
            let set_dir = root.join(dir_name);
            write_synth_manifest(&set_dir, &synth_manifest(from, to, &dir_name[..20], false));
        }

        let outcome = prune_old_backup_sets_at(root).expect("prune ok");

        assert!(
            outcome.pruned.is_empty(),
            "no successful sets means nothing to prune; got: {:?}",
            outcome.pruned
        );
        assert!(
            outcome.kept.is_empty(),
            "no successful sets means nothing kept; got: {:?}",
            outcome.kept
        );
        assert_eq!(
            outcome.preserved_forensic.len(),
            3,
            "every in-progress set is forensic: {:?}",
            outcome.preserved_forensic
        );
        // The on-disk tree is unchanged byte-for-byte (each set
        // directory still has its manifest).
        for (dir_name, _, _) in sets.iter() {
            let manifest_path = root.join(dir_name).join("manifest.json");
            assert!(
                manifest_path.exists(),
                "in-progress set's manifest must survive: {}",
                manifest_path.display()
            );
        }
    }

    /// Atomic-write rename invariant for the manifest finalize step:
    /// `prune_old_backup_sets_at` reads each set's manifest and routes
    /// on the `completed_ok` flag. A set whose manifest is **mid-flip**
    /// — i.e. structurally valid JSON but with the post-write
    /// `completed_ok=true` token spliced in without a fresh
    /// `completed_at` — must still parse and route through the
    /// success path. Pins the property that the manifest writer's
    /// `serde(default)` tolerance on `completed_at` doesn't accidentally
    /// reject a manifest whose `completed_at` would land on the next
    /// finalize call.
    ///
    /// In the production flow the atomic write happens through
    /// `sudo install -m 0644 <tmp> <dst>` (the migration framework.3 — no torn
    /// writes possible because `install` uses rename(2)); the test
    /// stages the post-rename "new" state directly via `std::fs::write`
    /// and asserts the manifest parses and is routed into `kept` (not
    /// `preserved_forensic`).
    #[test]
    fn prune_old_backup_sets_at_routes_finalized_manifest_without_completed_at_into_kept() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let set_dir = root.join("2026-05-11T14:23:11Z-from-1.0.0-to-1.1.0");
        std::fs::create_dir_all(&set_dir).expect("mkdir");

        // The mid-flip shape: `completed_ok: true` reached disk but
        // `completed_at` did not. This is the exact byte layout an
        // older daemon would have written before the
        // `serde(default) completed_at` field was added — and the
        // exact rollback-recoverable shape if a `finalize_manifest`
        // call landed `completed_ok` but a crash happened before the
        // accompanying `completed_at` write reached disk (the
        // production code writes both fields in one rename, so this
        // is a forward-compat assertion as much as a backward-compat
        // one).
        let raw = serde_json::json!({
            "from_version": "1.0.0",
            "to_version": "1.1.0",
            "started_at": "2026-05-11T14:23:11Z",
            "completed_ok": true,
            "arch": "x86_64-unknown-linux-gnu",
            "files": {}
        });
        std::fs::write(
            set_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&raw).unwrap(),
        )
        .expect("write");

        let outcome = prune_old_backup_sets_at(root).expect("prune ok");

        assert_eq!(
            outcome.kept.len(),
            1,
            "completed_ok=true must route through the success arm regardless \
             of completed_at presence; got kept={:?}",
            outcome.kept
        );
        assert!(
            outcome.preserved_forensic.is_empty(),
            "missing completed_at must not flip a finalized manifest into \
             the forensic bucket; got preserved={:?}",
            outcome.preserved_forensic
        );
        assert!(set_dir.exists(), "kept set must remain on disk");
    }
}
