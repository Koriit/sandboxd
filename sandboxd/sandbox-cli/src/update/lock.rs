//! `sandbox update` lock file — Spec 5 § 6.
//!
//! Path: `/var/lib/sandbox/.update.lock`. Mode `0664 sandbox:sandbox`.
//! Persistent across reboots (under `/var/lib/`, not `/run/`) so re-runs
//! can detect and adopt a dead-PID predecessor.
//!
//! The acquisition strategy follows § 6.2.1 pseudo-code: take a
//! non-blocking advisory `flock` via `flock(2)` on a file descriptor we
//! keep open in-process, *then* read the existing JSON payload, decide
//! whether this is a fresh acquisition or a dead-PID adoption, and
//! write the new payload. The "flock first, then read-and-write
//! payload" ordering rule is binding (§ 6.2.2): no racing process can
//! observe a partial payload while we hold the exclusive lock.
//!
//! The `was_running` flag is *sticky* (§ 6.4): on dead-PID adoption we
//! preserve the predecessor's value verbatim rather than re-evaluating
//! `systemctl is-active` (which would always read `inactive` after the
//! stop-daemon step).
//!
//! The lock is released on `Drop`: dropping the [`UpdateLock`] removes
//! the file (best-effort `unlink`) and closes the FD, which the kernel
//! interprets as releasing the advisory `flock`. Mid-flight aborts that
//! exit without removing the file (process killed, panic before
//! `Drop`) leave the payload on disk — the next `sandbox update`
//! invocation will `flock -n` it, see the dead PID, and adopt.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use nix::errno::Errno;
use nix::fcntl::FlockArg;
#[allow(deprecated)]
use nix::fcntl::flock;
use nix::sys::signal::kill;
use nix::unistd::Pid;

/// Canonical lock-file path. Spec 5 § 6.1.
pub const LOCK_PATH: &str = "/var/lib/sandbox/.update.lock";

/// Stale-payload threshold (§ 6.2.1 step 3): a payload older than this
/// triggers an `adopt-stale` log line but is otherwise treated like a
/// normal dead-PID adoption.
pub const STALE_THRESHOLD: Duration = Duration::from_secs(24 * 60 * 60);

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

/// JSON shape of the lock file's payload (§ 6.1).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LockPayload {
    pub pid: u32,
    pub started_at: String,
    pub target_version: String,
    pub from_version: String,
    pub was_running: bool,
}

// ---------------------------------------------------------------------------
// Errors and outcomes
// ---------------------------------------------------------------------------

/// Why a `LockOwner::acquire` call could not produce a held lock.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// Another live process holds the lock. Refuse — § 6.2.3 row 2.
    #[error("another sandbox update is in progress (pid {pid}); wait for it to finish.")]
    HeldByLivePid { pid: u32 },
    /// Could not acquire the kernel `flock` even after the dead-PID
    /// retry — another adopting process won the race.
    #[error("lock busy after retry; another adoption is in progress.")]
    BusyAfterRetry,
    /// Could not open the lock file (path not writable, parent dir
    /// missing, etc.).
    #[error("open lock file {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// I/O error during read / write of the lock file.
    #[error("lock file io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON encode failure for the payload write.
    #[error("encode payload: {0}")]
    Encode(serde_json::Error),
}

/// How the acquisition resolved — surfaced for the log line emitted by
/// the caller (§ 6.2.1 step 4: `step=acquire_lock ... action=<acquire|adopt|adopt-stale>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionKind {
    /// Fresh acquisition: file was absent or the prior payload was
    /// empty / unparseable. `was_running` was sampled now.
    Fresh,
    /// Dead-PID adoption: prior payload's PID was not alive; we
    /// preserved the sticky `was_running`.
    Adopt { adopted_from_pid: u32 },
    /// Same as `Adopt` but the prior payload is older than
    /// [`STALE_THRESHOLD`] — caller emits an additional log line.
    AdoptStale {
        adopted_from_pid: u32,
        stale_hours: u64,
    },
}

// ---------------------------------------------------------------------------
// Lock owner
// ---------------------------------------------------------------------------

/// An open handle on the lock file with the `flock` exclusive lock held.
///
/// Drop semantics: closing the inner `File` releases the kernel `flock`;
/// we also best-effort `unlink` the path so a successful run leaves no
/// stale payload (§ 6.3). For aborted runs the `Drop` path also
/// removes the file — but the dead-PID adoption flow is designed to
/// handle the case where a `Drop` did not run (process killed mid-flight),
/// see § 6.3.
#[derive(Debug)]
pub struct UpdateLock {
    /// The open FD; kept alive for the lifetime of the value so the
    /// kernel keeps the advisory lock. Held but not read by name — the
    /// `Drop` closes it implicitly when the struct field goes out of
    /// scope, which is exactly the contract we need.
    #[allow(dead_code)]
    file: File,
    /// Path the file was opened at — for the `Drop`-time `unlink`.
    path: PathBuf,
    /// The payload we wrote at acquisition time. Held in-process for
    /// the caller's use (`was_running` is read from here, not
    /// re-evaluated).
    payload: LockPayload,
    /// How the acquisition resolved. Caller logs this.
    kind: AcquisitionKind,
    /// Suppress the `Drop`-time `unlink`. Tests set this when they
    /// want to inspect the on-disk artifact after the lock holder has
    /// released the `flock`. Production code never sets this.
    suppress_unlink: bool,
}

impl UpdateLock {
    /// The payload we wrote at acquisition.
    pub fn payload(&self) -> &LockPayload {
        &self.payload
    }
    /// Kind of acquisition — caller emits an audit log line.
    pub fn kind(&self) -> AcquisitionKind {
        self.kind
    }
    /// Path the file lives at (for tests and the "rollback recipe note").
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        if !self.suppress_unlink {
            // Best-effort: the file may already be gone if a separate
            // explicit `release` ran.
            let _ = std::fs::remove_file(&self.path);
        }
        // Closing `self.file` happens when the field is dropped; the
        // kernel releases the flock at that point.
    }
}

// ---------------------------------------------------------------------------
// Acquisition
// ---------------------------------------------------------------------------

/// Parameters for a fresh acquisition. The caller is responsible for
/// providing the version strings (already known at this stage of
/// pre-flight) and the `was_running` probe (evaluated only on the
/// "fresh acquisition" branch).
pub struct AcquireParams<'a> {
    pub path: &'a Path,
    pub target_version: &'a str,
    pub from_version: &'a str,
    /// Closure returning the current `systemctl is-active sandboxd`
    /// reading. Only invoked on the fresh-acquisition branch (§ 6.4
    /// step 1). The adoption branch reads the prior payload's value.
    pub probe_was_running: &'a dyn Fn() -> bool,
    /// Closure returning `true` iff the given PID is currently alive
    /// (`kill -0`). Injected for tests; production uses
    /// [`pid_is_live`].
    pub is_pid_alive: &'a dyn Fn(u32) -> bool,
    /// Optional: the current PID to stamp in the payload. Tests
    /// override this; production defaults to `std::process::id()`.
    pub self_pid: Option<u32>,
    /// Optional: the current timestamp string for `started_at`.
    /// Production renders `chrono::Utc::now()` in ISO-8601; tests can
    /// pin a value.
    pub started_at: Option<String>,
    /// Tests set this to keep the file after `Drop`. Production code
    /// always leaves it `false`.
    pub suppress_drop_unlink: bool,
}

/// Standard "is the given PID currently alive?" probe — `kill(2)` with
/// signal `0` per POSIX semantics: returns `true` if the process exists
/// (alive or a zombie we're allowed to signal), `false` for `ESRCH`
/// (no such process). `EPERM` (target exists but we can't signal it)
/// is treated as "alive" — a different operator owning the PID still
/// holds the file in the sense we care about.
pub fn pid_is_live(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let p = Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX));
    match kill(p, None) {
        Ok(()) => true,
        Err(Errno::EPERM) => true,
        Err(_) => false,
    }
}

/// Acquire the lock. Implements § 6.2.1.
///
/// Outcomes (§ 6.2.3):
///   * File absent or stale-and-dead → fresh / adopt[-stale] acquisition;
///     returns `Ok(UpdateLock)`.
///   * `flock -n` fails and the prior PID is alive → `Err(HeldByLivePid)`.
///   * `flock -n` fails and the prior PID is dead → retries once; if the
///     retry succeeds we adopt; otherwise `Err(BusyAfterRetry)`.
pub fn acquire(params: AcquireParams<'_>) -> Result<UpdateLock, LockError> {
    // Step 1: Open the file `O_RDWR|O_CREAT`. The on-disk mode of a
    // freshly-created file is `0664` (the spec-pinned shape); we set
    // `umask` semantics via `OpenOptions`. The actual install of the
    // file at the right ownership (`sandbox:sandbox`) on a fresh-host
    // first-run is the wrapping shell flow's job (§ 6.2.1 step 1 in the
    // spec uses `sudo -k -u sandbox install -m 0664 /dev/null
    // "$lockfile"`); from Rust we open whatever the operator-side install
    // left in place and assert that we hold a writable FD.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o664)
        .open(params.path)
        .map_err(|e| LockError::Open {
            path: params.path.to_path_buf(),
            source: e,
        })?;

    // Step 2: Non-blocking exclusive flock.
    let mut adopted_pid: Option<u32> = None;
    if let Err(_e) = try_flock_ex(&file) {
        // EWOULDBLOCK. Peek at the existing payload to decide whether
        // the holder is live. The read is *without* the flock — we may
        // see a partial write; the parse-failure / PID-zero branch
        // tolerates that (§ 6.2.2).
        //
        // We tolerate parse failure (covered by `read_payload`'s
        // internal `serde_json::from_str(..).ok()` collapse) and
        // legitimate empty-payload, but an I/O error reading the
        // file itself is unexpected and worth surfacing via
        // `tracing::warn!` — the previous `unwrap_or(None)` swallowed
        // it silently, so an operator chasing a stuck lock had no
        // signal that read_payload itself failed. The graceful-degrade
        // behaviour (treat as held by an unknown holder; fall through
        // to the dead-PID-retry path) is preserved so a transient
        // read glitch doesn't crash the upgrade.
        let prior = match read_payload(&file) {
            Ok(payload) => payload,
            Err(e) => {
                tracing::warn!(
                    target: "sandbox-update",
                    "lock acquire: read_payload failed (treating as no prior payload): {e}"
                );
                None
            }
        };
        let held_pid = prior.as_ref().map(|p| p.pid).unwrap_or(0);
        if held_pid > 0 && (params.is_pid_alive)(held_pid) {
            return Err(LockError::HeldByLivePid { pid: held_pid });
        }
        // Dead-PID branch: retry once after a short sleep. The kernel
        // already released the predecessor's lock; our non-blocking
        // attempt failed because we lost the race against another
        // adopting process.
        std::thread::sleep(Duration::from_millis(1000));
        if try_flock_ex(&file).is_err() {
            return Err(LockError::BusyAfterRetry);
        }
        adopted_pid = Some(held_pid);
    }

    // Step 3: Decide acquisition kind under the held flock.
    let existing = read_payload(&file)?;
    let (kind, was_running) = classify_acquisition(
        existing.as_ref(),
        adopted_pid,
        params.is_pid_alive,
        params.probe_was_running,
    );

    // Step 4: Write the new payload under the held lock.
    let self_pid = params.self_pid.unwrap_or_else(std::process::id);
    let started_at = params.started_at.clone().unwrap_or_else(default_started_at);
    let payload = LockPayload {
        pid: self_pid,
        started_at,
        target_version: params.target_version.to_string(),
        from_version: params.from_version.to_string(),
        was_running,
    };
    write_payload(&file, &payload)?;

    Ok(UpdateLock {
        file,
        path: params.path.to_path_buf(),
        payload,
        kind,
        suppress_unlink: params.suppress_drop_unlink,
    })
}

/// Classify the acquisition outcome from the prior payload (if any),
/// whether we came via the dead-PID retry branch, and the live-probe /
/// fresh-probe closures. Split out so the apply path stays a single
/// straight-line assignment.
fn classify_acquisition(
    existing: Option<&LockPayload>,
    adopted_pid: Option<u32>,
    is_pid_alive: &dyn Fn(u32) -> bool,
    probe_was_running: &dyn Fn() -> bool,
) -> (AcquisitionKind, bool) {
    let prior = match existing {
        Some(p) => p,
        None => {
            // No prior payload — pure fresh acquisition. Sample
            // was_running NOW (§ 6.4 step 1).
            return (AcquisitionKind::Fresh, probe_was_running());
        }
    };

    let adopt_kind = |pid: u32| -> AcquisitionKind {
        let stale_hours = compute_stale_hours(&prior.started_at);
        if stale_hours > 24 {
            AcquisitionKind::AdoptStale {
                adopted_from_pid: pid,
                stale_hours,
            }
        } else {
            AcquisitionKind::Adopt {
                adopted_from_pid: pid,
            }
        }
    };

    if let Some(pid) = adopted_pid {
        // Dead-PID retry branch — preserve the sticky `was_running`.
        return (adopt_kind(pid), prior.was_running);
    }
    if !is_pid_alive(prior.pid) {
        // First-try flock but the prior PID is dead → still an adoption.
        return (adopt_kind(prior.pid), prior.was_running);
    }
    // Prior payload claims a live PID but we got the flock — race
    // where the live holder released but its payload is stale.
    // Treat as adoption to preserve stickiness; the spec leaves this
    // edge to operator judgement.
    (
        AcquisitionKind::Adopt {
            adopted_from_pid: prior.pid,
        },
        prior.was_running,
    )
}

// ---------------------------------------------------------------------------
// Helpers (private)
// ---------------------------------------------------------------------------

/// Non-blocking exclusive `flock` on the given file. Returns `Ok(())`
/// on success, `Err(Errno)` otherwise (most commonly `EWOULDBLOCK`).
///
/// We use the deprecated `nix::fcntl::flock` (not the newer
/// `nix::fcntl::Flock<T>` wrapper) because `Flock<T>` takes ownership
/// of the file; this module's design holds the `File` directly on the
/// `UpdateLock` struct and `try_clone`s it for read/write — losing
/// ownership to `Flock` would force a much larger refactor for no
/// behavioural difference (both call `flock(2)` underneath).
#[allow(deprecated)]
fn try_flock_ex(file: &File) -> Result<(), Errno> {
    flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock)
}

/// Read the existing JSON payload (if any). Returns `Ok(None)` when the
/// file is empty / unparseable — the dead-PID branch and the
/// fresh-create branch both tolerate that.
fn read_payload(file: &File) -> Result<Option<LockPayload>, std::io::Error> {
    let mut buf = String::new();
    let mut f = file.try_clone()?;
    f.seek(SeekFrom::Start(0))?;
    f.read_to_string(&mut buf)?;
    if buf.trim().is_empty() {
        return Ok(None);
    }
    Ok(serde_json::from_str::<LockPayload>(&buf).ok())
}

/// Write the JSON payload over the file's contents. Rewinds + truncates
/// before write so the file ends up with exactly the new payload.
fn write_payload(file: &File, payload: &LockPayload) -> Result<(), LockError> {
    let bytes = serde_json::to_vec_pretty(payload).map_err(LockError::Encode)?;
    let mut f = file.try_clone()?;
    f.seek(SeekFrom::Start(0))?;
    f.set_len(0)?;
    f.write_all(&bytes)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(())
}

/// Default `started_at` — ISO-8601 UTC with second precision. The
/// caller can override via [`AcquireParams::started_at`] for tests.
fn default_started_at() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Hours since the given ISO-8601 timestamp. Returns 0 on parse error
/// (treated as "fresh enough" — the conservative side, since adopt
/// vs adopt-stale only differ in the operator-facing log line; both
/// proceed with the acquisition). Parse failures are surfaced via
/// `tracing::warn!` so an operator chasing a stuck lock sees the
/// timestamp shape that confused the parser; the previous silent
/// return-0 hid this clue.
fn compute_stale_hours(iso: &str) -> u64 {
    let parsed = match chrono::DateTime::parse_from_rfc3339(iso) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(
                target: "sandbox-update",
                "compute_stale_hours: rfc3339 parse failed for `{iso}` ({e}); treating as fresh"
            );
            return 0;
        }
    };
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let then = u64::try_from(parsed.timestamp().max(0)).unwrap_or(0);
    if now > then { (now - then) / 3600 } else { 0 }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn tmp_lock_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join(".update.lock");
        (dir, p)
    }

    fn always_dead(_pid: u32) -> bool {
        false
    }
    fn always_alive(_pid: u32) -> bool {
        true
    }
    fn never_running() -> bool {
        false
    }
    fn always_running() -> bool {
        true
    }

    /// § 6.2.3 row 2: a live PID payload + held flock → refuse.
    #[test]
    fn lock_file_acquisition_refuses_on_live_holder() {
        let (_dir, path) = tmp_lock_path();
        // First acquisition: real flock held by `holder`.
        let holder = acquire(AcquireParams {
            path: &path,
            target_version: "1.1.0",
            from_version: "1.0.0",
            probe_was_running: &always_running,
            is_pid_alive: &always_dead,
            self_pid: Some(11111),
            started_at: Some("2026-05-11T00:00:00Z".to_string()),
            suppress_drop_unlink: false,
        })
        .expect("first acquire");
        assert_eq!(holder.payload().pid, 11111);

        // Second acquisition with the predecessor PID reported as
        // *alive* must refuse.
        let err = acquire(AcquireParams {
            path: &path,
            target_version: "1.1.0",
            from_version: "1.0.0",
            probe_was_running: &never_running,
            is_pid_alive: &always_alive,
            self_pid: Some(22222),
            started_at: Some("2026-05-11T01:00:00Z".to_string()),
            suppress_drop_unlink: false,
        })
        .expect_err("second acquire must refuse");

        match err {
            LockError::HeldByLivePid { pid } => assert_eq!(pid, 11111),
            other => panic!("expected HeldByLivePid, got {other:?}"),
        }
        drop(holder);
    }

    /// § 6.2.3 row 3: file present + flock released + PID dead → adopt.
    #[test]
    fn lock_file_acquisition_adopts_on_dead_pid_payload() {
        let (_dir, path) = tmp_lock_path();
        // Seed with a recent `started_at` (within the 24h staleness
        // threshold) so the adoption resolves to plain `Adopt`, not
        // `AdoptStale`. We use `chrono::Utc::now()` rather than a
        // hard-coded ISO string so the test does not bit-rot as the
        // wall clock moves.
        let recent = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        std::fs::write(
            &path,
            serde_json::to_vec(&LockPayload {
                pid: 99999,
                started_at: recent.clone(),
                target_version: "1.1.0".to_string(),
                from_version: "1.0.0".to_string(),
                was_running: true,
            })
            .unwrap(),
        )
        .unwrap();

        let held = acquire(AcquireParams {
            path: &path,
            target_version: "1.1.0",
            from_version: "1.0.0",
            probe_was_running: &never_running, // would-be fresh; must NOT be used
            is_pid_alive: &always_dead,
            self_pid: Some(22222),
            started_at: Some(recent),
            suppress_drop_unlink: false,
        })
        .expect("adoption succeeds");
        match held.kind() {
            AcquisitionKind::Adopt { adopted_from_pid } => {
                assert_eq!(adopted_from_pid, 99999);
            }
            other => panic!("expected Adopt, got {other:?}"),
        }
    }

    /// § 6.4: sticky `was_running` survives adoption — even when the
    /// fresh probe would return the opposite.
    #[test]
    fn lock_file_acquisition_preserves_was_running_across_adopt() {
        let (_dir, path) = tmp_lock_path();
        // Predecessor wrote was_running=true; use a recent timestamp
        // so the AdoptStale branch isn't triggered (the stickiness
        // contract is the same either way, but Adopt is the spec's
        // primary case).
        let recent = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        std::fs::write(
            &path,
            serde_json::to_vec(&LockPayload {
                pid: 99999,
                started_at: recent,
                target_version: "1.1.0".to_string(),
                from_version: "1.0.0".to_string(),
                was_running: true,
            })
            .unwrap(),
        )
        .unwrap();

        // Probe says "not running now" (mid-update — daemon already
        // stopped). The sticky flag must override the fresh probe.
        let held = acquire(AcquireParams {
            path: &path,
            target_version: "1.1.0",
            from_version: "1.0.0",
            probe_was_running: &never_running,
            is_pid_alive: &always_dead,
            self_pid: Some(22222),
            started_at: None,
            suppress_drop_unlink: false,
        })
        .expect("adopt succeeds");
        assert!(
            held.payload().was_running,
            "sticky was_running must survive adopt; got {:?}",
            held.payload()
        );
    }

    /// § 6.2.2 — binding ordering rule: the kernel `flock` must be
    /// taken before any payload write. Verify by inspecting that
    /// during a held lock, the payload is observable to a reader (the
    /// write completed under the flock) and a second non-blocking
    /// `flock` attempt fails (lock is exclusive).
    #[test]
    fn lock_file_flock_acquired_before_payload_write() {
        let (_dir, path) = tmp_lock_path();
        let holder = acquire(AcquireParams {
            path: &path,
            target_version: "1.1.0",
            from_version: "1.0.0",
            probe_was_running: &always_running,
            is_pid_alive: &always_dead,
            self_pid: Some(11111),
            started_at: Some("2026-05-11T00:00:00Z".to_string()),
            suppress_drop_unlink: false,
        })
        .expect("first acquire");

        // Payload on disk must already contain our PID — the flock was
        // held BEFORE the write returned.
        let on_disk: LockPayload = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(on_disk.pid, 11111);

        // Second flock attempt on the same file must fail (EWOULDBLOCK).
        let f2 = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open for second flock");
        // Use the same deprecated `flock` wrapper the production code
        // uses (see `try_flock_ex` for the rationale).
        #[allow(deprecated)]
        let res = flock(f2.as_raw_fd(), FlockArg::LockExclusiveNonblock);
        assert!(
            res.is_err(),
            "second non-blocking flock must fail while the first is held; got {res:?}"
        );
        drop(holder);
    }

    /// § 6.3: dropping the [`UpdateLock`] removes the file. Verify by
    /// observing that after `drop` the path no longer exists, and a
    /// subsequent fresh acquisition starts from an empty slate.
    #[test]
    fn lock_file_released_on_process_exit() {
        let (_dir, path) = tmp_lock_path();
        {
            let _holder = acquire(AcquireParams {
                path: &path,
                target_version: "1.1.0",
                from_version: "1.0.0",
                probe_was_running: &always_running,
                is_pid_alive: &always_dead,
                self_pid: Some(11111),
                started_at: Some("2026-05-11T00:00:00Z".to_string()),
                suppress_drop_unlink: false,
            })
            .expect("acquire");
            assert!(path.exists(), "lock file present while held");
        }
        // After drop:
        assert!(
            !path.exists(),
            "lock file must be removed on Drop; still at {path:?}"
        );
    }

    /// Stale-payload (>24h) emits `AdoptStale` kind for the audit log.
    #[test]
    fn lock_file_stale_payload_triggers_adopt_stale() {
        let (_dir, path) = tmp_lock_path();
        // 48h in the past.
        let past = chrono::Utc::now() - chrono::Duration::hours(48);
        let past_str = past.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        std::fs::write(
            &path,
            serde_json::to_vec(&LockPayload {
                pid: 99999,
                started_at: past_str,
                target_version: "1.1.0".to_string(),
                from_version: "1.0.0".to_string(),
                was_running: false,
            })
            .unwrap(),
        )
        .unwrap();

        let held = acquire(AcquireParams {
            path: &path,
            target_version: "1.1.0",
            from_version: "1.0.0",
            probe_was_running: &always_running,
            is_pid_alive: &always_dead,
            self_pid: Some(22222),
            started_at: None,
            suppress_drop_unlink: false,
        })
        .expect("stale-adopt succeeds");
        match held.kind() {
            AcquisitionKind::AdoptStale { stale_hours, .. } => {
                assert!(
                    stale_hours >= 24,
                    "stale_hours should reflect 48h; got {stale_hours}"
                );
            }
            other => panic!("expected AdoptStale, got {other:?}"),
        }
    }

    /// Sanity: `pid_is_live(0)` returns false; `pid_is_live(self)`
    /// returns true.
    #[test]
    fn pid_is_live_basic_probes() {
        assert!(!pid_is_live(0));
        assert!(pid_is_live(std::process::id()));
    }

    /// The probe closure for `was_running` is not invoked on the
    /// adoption branch. Verified by passing a probe that panics on
    /// call: an adopt path must not trigger it.
    #[test]
    fn probe_was_running_not_invoked_on_adopt() {
        let (_dir, path) = tmp_lock_path();
        // Seed a prior payload.
        std::fs::write(
            &path,
            serde_json::to_vec(&LockPayload {
                pid: 99999,
                started_at: "2026-05-11T00:00:00Z".to_string(),
                target_version: "1.1.0".to_string(),
                from_version: "1.0.0".to_string(),
                was_running: false,
            })
            .unwrap(),
        )
        .unwrap();

        let calls = Arc::new(AtomicBool::new(false));
        let calls_for_probe = Arc::clone(&calls);
        let probe = move || -> bool {
            calls_for_probe.store(true, Ordering::SeqCst);
            panic!("probe must not be called on adoption path");
        };
        let _held = acquire(AcquireParams {
            path: &path,
            target_version: "1.1.0",
            from_version: "1.0.0",
            probe_was_running: &probe,
            is_pid_alive: &always_dead,
            self_pid: Some(22222),
            started_at: None,
            suppress_drop_unlink: false,
        })
        .expect("adopt");
        assert!(
            !calls.load(Ordering::SeqCst),
            "probe_was_running must not be invoked on adoption"
        );
    }
}
