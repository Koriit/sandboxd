//! Retention sweeper for the persistent sink.
//!
//! Walks `{base_dir}/sessions/*/events/*.jsonl` on a fixed interval
//! (hourly by default — overridable for tests via
//! `SANDBOX_TEST_PRUNER_INTERVAL_SECS`) and removes any file whose
//! filename `YYYY-MM-DD` suffix is older than
//! `today - retention_days` (UTC). Pruner errors are logged at
//! `warn!` and never propagate — one bad file (permission denied,
//! racy rename) must not halt the sweep of the rest.
//!
//! # Retention semantics
//!
//! - `retention_days = 14`, today = 2026-04-22: anything dated
//!   2026-04-08 or earlier is removed (inclusive bound via
//!   `date < cutoff` where `cutoff = today - 14`).
//! - `retention_days = 0`: every dated file is older than the
//!   cutoff (`today - 0 == today` → a file dated `today` is *not*
//!   older and survives; `today-1` or earlier is removed). This
//!   matches the intuitive "keep today only" shape for disabling.
//!   Callers that really want "delete everything" should not call
//!   the pruner at all.
//!
//! # Filename parsing
//!
//! Valid filenames match `<layer>-YYYY-MM-DD.jsonl`, where
//! `<layer>` is itself a non-date string. The parser looks for the
//! last occurrence of the `-YYYY-MM-DD.jsonl` pattern by reading
//! the last 15 characters (`YYYY-MM-DD.jsonl`) and validating the
//! date component. Anything that fails to parse is skipped
//! silently (neither kept nor deleted — the file lingers). This is
//! deliberate: a stray `README.txt` or a future `.jsonl.gz`
//! shouldn't be removed by accident.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{NaiveDate, Utc};
use tokio::fs;
use tracing::{debug, warn};

/// Default pruner interval. Overridable in tests via
/// `SANDBOX_TEST_PRUNER_INTERVAL_SECS=<n>`.
pub(super) const DEFAULT_PRUNER_INTERVAL_SECS: u64 = 3600;

/// Environment variable recognized only by tests to speed up the
/// pruner cycle. Stays out of the CLI surface — operators should not
/// depend on it.
pub(super) const TEST_INTERVAL_ENV: &str = "SANDBOX_TEST_PRUNER_INTERVAL_SECS";

/// Run a single pruner sweep over `{base_dir}/sessions/*/events/*.jsonl`.
///
/// Returns the number of files removed. Errors on a single file
/// (permission denied, file vanished between `read_dir` and
/// `remove_file`) are logged at `warn!` and the walk continues.
///
/// If `base_dir/sessions/` does not exist yet (no session has ever
/// been registered), the function returns `0` without logging. That
/// matches the expected steady-state for a freshly-started daemon
/// before any session is created.
pub async fn prune_once(base_dir: &Path, retention_days: u32) -> u64 {
    let sessions_root = base_dir.join("sessions");
    let today = Utc::now().date_naive();
    // `checked_sub_days` cannot overflow for any realistic
    // retention; we saturate to year 0 on the impossible edge.
    let cutoff = today
        .checked_sub_days(chrono::Days::new(retention_days as u64))
        .unwrap_or(NaiveDate::MIN);

    let mut session_dirs = match fs::read_dir(&sessions_root).await {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            warn!(
                error = %e,
                dir = %sessions_root.display(),
                "pruner: failed to read sessions dir"
            );
            return 0;
        }
    };

    let mut removed = 0u64;
    while let Ok(Some(session_entry)) = session_dirs.next_entry().await {
        let events_dir = session_entry.path().join("events");
        let mut entries = match fs::read_dir(&events_dir).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                warn!(
                    error = %e,
                    dir = %events_dir.display(),
                    "pruner: failed to read events dir"
                );
                continue;
            }
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if let Some(date) = parse_filename_date(&path) {
                if date < cutoff {
                    match fs::remove_file(&path).await {
                        Ok(()) => {
                            removed += 1;
                            debug!(file = %path.display(), "pruner: removed expired file");
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                file = %path.display(),
                                "pruner: failed to remove file"
                            );
                        }
                    }
                }
            }
            // Unparsable filenames (e.g. `README.txt`, a partial
            // `.jsonl.tmp`) are left alone — see module docstring.
        }
    }
    removed
}

/// Parse `<layer>-YYYY-MM-DD.jsonl` out of a filename, returning the
/// date component. Any non-matching filename returns [`None`].
pub(super) fn parse_filename_date(path: &Path) -> Option<NaiveDate> {
    let name = path.file_name()?.to_str()?;
    // Must end with `.jsonl`.
    let stem = name.strip_suffix(".jsonl")?;
    // The last 10 characters of the stem must form `YYYY-MM-DD`, and
    // the character before that must be `-`. Everything before the
    // `-` is the layer name (irrelevant to pruning).
    if stem.len() < 11 {
        return None;
    }
    let (prefix, date_str) = stem.split_at(stem.len() - 10);
    // Ensure the split boundary is a `-` separator, not part of a
    // longer run of `-` or an accidental cut through the layer name.
    if !prefix.ends_with('-') {
        return None;
    }
    NaiveDate::parse_from_str(date_str, "%Y-%m-%d").ok()
}

/// Return the pruner interval to use, honoring the test override.
pub(super) fn pruner_interval() -> Duration {
    let secs = std::env::var(TEST_INTERVAL_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_PRUNER_INTERVAL_SECS);
    Duration::from_secs(secs.max(1))
}

/// Long-running loop that calls [`prune_once`] on a fixed interval.
///
/// Exits cleanly when the task is aborted (via
/// [`super::PersistentSink::shutdown`] → [`tokio::task::JoinHandle::abort`]).
pub(super) async fn run_loop(base_dir: PathBuf, retention_days: u32) {
    let interval_dur = pruner_interval();
    let mut ticker = tokio::time::interval(interval_dur);
    // Skip the initial immediate tick — the pruner's job is to catch
    // files that age out while the daemon is running, not to sweep
    // on every (re)start. The first sweep lands one interval in.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // First tick completes immediately by default; swallow it so we
    // honor the "wait one interval first" shape above.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let removed = prune_once(&base_dir, retention_days).await;
        if removed > 0 {
            debug!(removed, "pruner: sweep complete");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::tempdir;
    use tokio::fs;

    /// Create `{base}/sessions/{sid}/events/{layer}-{date}.jsonl`
    /// with a single byte so the pruner has something to remove.
    async fn fixture(base: &Path, sid: &str, filename: &str) -> PathBuf {
        let dir = base.join("sessions").join(sid).join("events");
        fs::create_dir_all(&dir).await.unwrap();
        let p = dir.join(filename);
        fs::write(&p, b"x").await.unwrap();
        p
    }

    #[test]
    fn parse_filename_date_accepts_canonical_shape() {
        let p = PathBuf::from("/x/events/dns-2026-04-22.jsonl");
        assert_eq!(
            parse_filename_date(&p).unwrap(),
            NaiveDate::from_ymd_opt(2026, 4, 22).unwrap()
        );
    }

    #[test]
    fn parse_filename_date_accepts_kebab_layer() {
        let p = PathBuf::from("/x/events/deny-logger-2026-04-22.jsonl");
        assert_eq!(
            parse_filename_date(&p).unwrap(),
            NaiveDate::from_ymd_opt(2026, 4, 22).unwrap()
        );
    }

    #[test]
    fn parse_filename_date_rejects_malformed() {
        // No trailing `.jsonl`.
        assert!(parse_filename_date(&PathBuf::from("/x/dns-2026-04-22.json")).is_none());
        // Missing date.
        assert!(parse_filename_date(&PathBuf::from("/x/dns.jsonl")).is_none());
        // Date separator wrong.
        assert!(parse_filename_date(&PathBuf::from("/x/dns-2026_04_22.jsonl")).is_none());
        // Non-date tail.
        assert!(parse_filename_date(&PathBuf::from("/x/README.jsonl")).is_none());
        // Partial date.
        assert!(parse_filename_date(&PathBuf::from("/x/dns-2026-04.jsonl")).is_none());
        // Date but no layer prefix at all.
        assert!(parse_filename_date(&PathBuf::from("/x/2026-04-22.jsonl")).is_none());
    }

    #[tokio::test]
    async fn pruner_removes_only_files_older_than_retention() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let today = Utc::now().date_naive();
        let mk = |delta: i64| today - chrono::Duration::days(delta);

        let p_today = fixture(
            base,
            "aaaaaaaaaaaa",
            &format!("dns-{}.jsonl", mk(0).format("%Y-%m-%d")),
        )
        .await;
        let p_7 = fixture(
            base,
            "aaaaaaaaaaaa",
            &format!("dns-{}.jsonl", mk(7).format("%Y-%m-%d")),
        )
        .await;
        let p_14 = fixture(
            base,
            "aaaaaaaaaaaa",
            &format!("dns-{}.jsonl", mk(14).format("%Y-%m-%d")),
        )
        .await;
        let p_15 = fixture(
            base,
            "aaaaaaaaaaaa",
            &format!("dns-{}.jsonl", mk(15).format("%Y-%m-%d")),
        )
        .await;
        let p_100 = fixture(
            base,
            "bbbbbbbbbbbb",
            &format!("envoy-{}.jsonl", mk(100).format("%Y-%m-%d")),
        )
        .await;

        let removed = prune_once(base, 14).await;
        assert_eq!(removed, 2, "expected 2 removed, got {removed}");
        assert!(p_today.exists(), "today must survive");
        assert!(p_7.exists(), "today-7 must survive");
        assert!(p_14.exists(), "today-14 must survive (boundary inclusive)");
        assert!(!p_15.exists(), "today-15 must be removed");
        assert!(!p_100.exists(), "today-100 must be removed");
    }

    #[tokio::test]
    async fn pruner_tolerates_malformed_filenames() {
        // A non-date filename must be skipped, not deleted.
        let dir = tempdir().unwrap();
        let base = dir.path();
        let p_bogus = fixture(base, "aaaaaaaaaaaa", "README.txt").await;
        let p_bogus_jsonl = fixture(base, "aaaaaaaaaaaa", "random.jsonl").await;
        let p_partial = fixture(base, "aaaaaaaaaaaa", "dns-2026-04.jsonl").await;

        let removed = prune_once(base, 14).await;
        assert_eq!(removed, 0);
        assert!(p_bogus.exists(), "non-date .txt must be left alone");
        assert!(p_bogus_jsonl.exists(), "non-date .jsonl must be left alone");
        assert!(p_partial.exists(), "partial-date .jsonl must be left alone");
    }

    #[tokio::test]
    async fn pruner_tolerates_io_errors_on_single_file() {
        // Simulate a permission-denied error by chmod'ing the events
        // directory to deny removal on a specific file. Because
        // POSIX permissions are inherited through the parent dir's
        // write bit (not the file's mode), we flip the events dir's
        // mode to `r-x------` (0o500) so `unlink` on the target
        // file returns `EACCES` — but `read_dir` still succeeds
        // because that needs only `r--`.
        //
        // The sweep must log `warn!` and continue. Other files are
        // unaffected. We assert that a second, removable file in
        // the same directory *is* removed (proving the walk didn't
        // abort on the first error).
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let base = dir.path();
        let today = Utc::now().date_naive();
        let old = today - chrono::Duration::days(100);
        let old_str = old.format("%Y-%m-%d").to_string();

        let _p_locked = fixture(base, "aaaaaaaaaaaa", &format!("dns-{old_str}.jsonl")).await;
        let p_normal = fixture(base, "bbbbbbbbbbbb", &format!("envoy-{old_str}.jsonl")).await;

        // Lock the first session's events dir. Re-enable write at
        // the end of the test via RAII so tempdir cleanup succeeds.
        let locked_dir = base.join("sessions").join("aaaaaaaaaaaa").join("events");
        let orig_mode = fs::metadata(&locked_dir)
            .await
            .unwrap()
            .permissions()
            .mode();
        fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o500))
            .await
            .unwrap();

        let removed = prune_once(base, 14).await;

        // Restore perms before assertions so a panic doesn't leak
        // an unremovable tempdir.
        fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(orig_mode))
            .await
            .unwrap();

        // Running as root (e.g. in CI containers) bypasses POSIX
        // perms entirely, in which case *both* old files are
        // removable and the sweep reports 2. Any other environment
        // should see exactly 1 removal (the lockable case): the
        // locked file survives but the sweep still reaches the
        // second session. Either way, the `bbbbbbbbbbbb` file must
        // be gone — that is the invariant under test.
        assert!(
            removed == 1 || removed == 2,
            "unexpected removed count {removed}; expected 1 (locked-dir case) or 2 (root bypass)"
        );
        assert!(
            !p_normal.exists(),
            "second session's old file must be pruned regardless of the first's lock"
        );
    }

    #[tokio::test]
    async fn pruner_tolerates_missing_sessions_dir() {
        // A freshly-started daemon may have no `sessions/` directory
        // yet. The pruner must not warn or error; it silently
        // returns 0.
        let dir = tempdir().unwrap();
        assert_eq!(prune_once(dir.path(), 14).await, 0);
    }

    #[test]
    fn pruner_interval_honors_test_override() {
        // SAFETY: single-threaded test-locked env; the override is
        // set immediately before read and unset immediately after.
        // Guarded under a tiny scope to avoid polluting sibling
        // tests — nextest runs each test in its own process by
        // default (nextest config default), which also shields us.
        unsafe {
            std::env::set_var(TEST_INTERVAL_ENV, "2");
        }
        assert_eq!(pruner_interval(), Duration::from_secs(2));
        unsafe {
            std::env::remove_var(TEST_INTERVAL_ENV);
        }
        assert_eq!(
            pruner_interval(),
            Duration::from_secs(DEFAULT_PRUNER_INTERVAL_SECS)
        );
    }
}
