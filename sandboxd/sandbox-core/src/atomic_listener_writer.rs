//! Atomic Envoy listener-file writer.
//!
//! Envoy's filesystem LDS subscription watches a directory for changes, but
//! **only fires on `MovedTo` inotify events** — `Modified` events (produced
//! by `sh -c 'cat > file'` / `docker exec ... > file` style writes) are
//! silently ignored (upstream issue `envoyproxy/envoy#20474`). To make an
//! LDS update actually land, the listener file must be *renamed into*
//! its final location on the same filesystem.
//!
//! This module provides the host-side writer that sandboxd uses to deliver
//! each listener generation. It operates on a **bind-mounted host
//! directory** — see [`session_listener_host_dir`] for the per-session path
//! and `gateway.rs::create_gateway` for the container-side mount — so the
//! rename happens on the host kernel's filesystem and propagates as a
//! `MovedTo` event visible to Envoy's inotify watcher inside the
//! container.
//!
//! # Writer invariant
//!
//! Between any two listener generations, **only the region between
//! [`policy::FILTER_CHAINS_BEGIN_MARKER`] and
//! [`policy::FILTER_CHAINS_END_MARKER`] may differ.** Any change outside
//! that region (bind address, `listener_filters`, `metadata`,
//! `socket_options`, `traffic_direction`,
//! `per_connection_buffer_limit_bytes`, etc.) forces Envoy to drain the
//! listener and reset in-flight connections, destroying the
//! connection-preservation property the xDS-based propagation design
//! relies on. [`AtomicListenerWriter::write`] compares the new content
//! against the current on-disk content and fails loudly
//! ([`ListenerWriteError::InvariantViolated`]) when the invariant would be
//! breached.
//!
//! # Ownership and call sites
//!
//! M9-S18 introduces the writer and exercises it from unit tests. The
//! initial listener file is written as part of policy distribution so
//! Envoy has something to consume on first boot. Wiring the writer up for
//! DNS-propagation events is M9-S19's responsibility — this module is
//! deliberately kept independent of the DNS-propagation path so both
//! call sites share a single enforcement point for the invariant.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::Builder as TempFileBuilder;
use tracing::{debug, info};

use crate::policy::{FILTER_CHAINS_BEGIN_MARKER, FILTER_CHAINS_END_MARKER, LISTENER_FILE_NAME};
use crate::session::SessionId;

/// Return the root directory on the host under which per-session listener
/// directories live. `sandboxd` bind-mounts `${root}/<session-id>/` into
/// each gateway container's `/etc/envoy/listeners/`.
///
/// Resolution order (mirrors the socket-path convention documented in
/// `CLAUDE.md`):
/// 1. `SANDBOX_LISTENER_DIR` env override — operators / tests can pin the
///    path explicitly.
/// 2. `$XDG_RUNTIME_DIR/sandboxd/listeners/` — the default on systems with
///    a user runtime dir (typical on systemd-managed hosts). Lives on a
///    tmpfs, so non-persistent across host reboots which matches the
///    ephemeral nature of sessions.
/// 3. `$HOME/.local/share/sandboxd/listeners/` — fallback when XDG is
///    unset (matches the daemon socket-path fallback).
/// 4. `/tmp/sandboxd-listeners` — last-resort fallback when even `HOME`
///    is unset (containerised CI, etc.).
///
/// The path stays short enough for Docker bind mounts on every supported
/// platform under all four cases.
pub fn listener_host_root() -> PathBuf {
    if let Ok(override_dir) = std::env::var("SANDBOX_LISTENER_DIR") {
        return PathBuf::from(override_dir);
    }
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir)
            .join("sandboxd")
            .join("listeners");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("sandboxd")
            .join("listeners");
    }
    PathBuf::from("/tmp/sandboxd-listeners")
}

/// Return the host-side listener directory for `session_id`.
///
/// This directory is bind-mounted into the gateway container as
/// [`crate::policy::LISTENER_DIR_IN_CONTAINER`].
pub fn session_listener_host_dir(session_id: &SessionId) -> PathBuf {
    listener_host_root().join(session_id.to_string())
}

/// Return the host-side path to the LDS-served listener file for
/// `session_id`.
pub fn session_listener_host_path(session_id: &SessionId) -> PathBuf {
    session_listener_host_dir(session_id).join(LISTENER_FILE_NAME)
}

/// Errors produced by [`AtomicListenerWriter`].
#[derive(Debug, thiserror::Error)]
pub enum ListenerWriteError {
    /// I/O error during directory creation, tempfile write, or rename.
    #[error("listener-file I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The new listener content is missing the filter-chains marker
    /// comments. Indicates a policy-compiler bug — every listener we
    /// emit must frame its mutable region so the writer can enforce
    /// the invariant.
    #[error(
        "new listener content is missing filter-chains markers \
         (expected `{begin}` and `{end}`); refusing to write"
    )]
    MissingMarkers {
        begin: &'static str,
        end: &'static str,
    },

    /// The new content differs from the previous generation in a region
    /// outside the filter-chains markers. Writing it would force Envoy
    /// to drain the listener and reset in-flight connections, which
    /// violates the connection-preservation constraint documented in
    /// `.tasks/specs/2026-04-19-l3-envoy-mitmproxy-flow-design.md`.
    #[error(
        "listener-file invariant violated: field(s) outside the \
         filter-chains region differ between generations — {diff_summary}. \
         Only `filter_chains` / `default_filter_chain` may change without \
         draining the listener."
    )]
    InvariantViolated { diff_summary: String },
}

/// Host-side writer that atomically installs Envoy listener generations.
///
/// Each writer is bound to a specific on-disk file path (typically
/// [`session_listener_host_path`] for a given session). Construction does
/// **not** create the file; call [`AtomicListenerWriter::write`] with the
/// initial content. [`AtomicListenerWriter::ensure_dir`] is the
/// recommended one-time setup — it creates the parent directory with
/// permissions that allow the gateway container to read the file via
/// its bind mount.
pub struct AtomicListenerWriter {
    target: PathBuf,
}

impl AtomicListenerWriter {
    /// Create a writer for the given final listener-file path.
    pub fn new(target: impl Into<PathBuf>) -> Self {
        Self {
            target: target.into(),
        }
    }

    /// The listener file this writer targets.
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// Ensure the parent directory exists, creating it if needed.
    ///
    /// Idempotent. The directory is created world-readable so that the
    /// gateway container (running as root, but also compatible with
    /// future non-root variants) can read the listener file via its
    /// bind mount.
    pub fn ensure_dir(&self) -> Result<(), ListenerWriteError> {
        let parent = self.target.parent().ok_or_else(|| ListenerWriteError::Io {
            path: self.target.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "listener target has no parent directory",
            ),
        })?;

        fs::create_dir_all(parent).map_err(|e| ListenerWriteError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;

        Ok(())
    }

    /// Atomically write `new_content` to the target path, enforcing the
    /// framing invariant against the previous generation (if any).
    ///
    /// Strategy:
    /// 1. Validate that `new_content` contains both filter-chains markers.
    /// 2. If a previous generation exists on disk, diff the framing
    ///    region and fail with [`ListenerWriteError::InvariantViolated`]
    ///    if anything outside the markers differs.
    /// 3. Write the new content to a tempfile **in the same directory**
    ///    as the target (required for `rename` to be atomic on the same
    ///    filesystem).
    /// 4. `fs::rename` the tempfile onto the final path. The kernel
    ///    issues a single `MovedTo` inotify event on the containing
    ///    directory, which Envoy's LDS watcher picks up.
    ///
    /// Returns `Ok(true)` if the file was freshly created, `Ok(false)`
    /// if an existing generation was replaced.
    pub fn write(&self, new_content: &str) -> Result<bool, ListenerWriteError> {
        validate_markers(new_content)?;

        let is_initial = !self.target.exists();

        if !is_initial {
            let current = fs::read_to_string(&self.target).map_err(|e| ListenerWriteError::Io {
                path: self.target.clone(),
                source: e,
            })?;
            enforce_invariant(&current, new_content)?;
        }

        self.ensure_dir()?;

        // Tempfile lives in the same directory as the target so the
        // rename is a same-filesystem op (atomic, produces MovedTo).
        let parent = self
            .target
            .parent()
            .expect("ensure_dir guarantees a parent");

        let mut tempfile = TempFileBuilder::new()
            .prefix(".listener.")
            .suffix(".tmp")
            .tempfile_in(parent)
            .map_err(|e| ListenerWriteError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;

        tempfile
            .write_all(new_content.as_bytes())
            .map_err(|e| ListenerWriteError::Io {
                path: tempfile.path().to_path_buf(),
                source: e,
            })?;
        tempfile
            .as_file_mut()
            .sync_all()
            .map_err(|e| ListenerWriteError::Io {
                path: tempfile.path().to_path_buf(),
                source: e,
            })?;

        // `persist` performs the atomic rename onto the target. On
        // POSIX filesystems this is a single syscall that produces a
        // `MovedTo` inotify event on the parent directory, which is
        // exactly what Envoy's LDS watcher subscribes to (upstream
        // issue `#20474`).
        let persisted = tempfile
            .persist(&self.target)
            .map_err(|e| ListenerWriteError::Io {
                path: self.target.clone(),
                source: e.error,
            })?;
        // Drop the returned File explicitly; we don't need the handle
        // past the rename.
        drop(persisted);

        if is_initial {
            info!(
                target = %self.target.display(),
                "wrote initial Envoy listener file"
            );
        } else {
            debug!(
                target = %self.target.display(),
                "atomically replaced Envoy listener file"
            );
        }

        Ok(is_initial)
    }
}

/// Check that `content` contains both filter-chains markers **exactly
/// once** each.
///
/// The writer splits on the markers with [`str::find`] which returns the
/// first occurrence. A duplicated marker (e.g. accidentally embedded in a
/// YAML comment) would silently corrupt the invariant check — the
/// `head`/`tail` regions would include the rest of the file up to the
/// second marker. Reject such content explicitly so the policy compiler
/// surfaces the bug loudly instead of shipping a broken listener.
fn validate_markers(content: &str) -> Result<(), ListenerWriteError> {
    let begin_count = content.matches(FILTER_CHAINS_BEGIN_MARKER).count();
    let end_count = content.matches(FILTER_CHAINS_END_MARKER).count();
    if begin_count != 1 || end_count != 1 {
        return Err(ListenerWriteError::MissingMarkers {
            begin: FILTER_CHAINS_BEGIN_MARKER,
            end: FILTER_CHAINS_END_MARKER,
        });
    }
    Ok(())
}

/// Split `content` at the filter-chains markers into `(head, middle, tail)`.
///
/// - `head` is the text before [`FILTER_CHAINS_BEGIN_MARKER`] (inclusive of
///   everything up to but not including the marker line).
/// - `middle` is the text between the markers (the mutable region).
/// - `tail` is the text after [`FILTER_CHAINS_END_MARKER`] (inclusive of
///   everything after the marker line).
///
/// Returns `None` if either marker is missing. Callers should validate
/// with [`validate_markers`] first.
fn split_at_markers(content: &str) -> Option<(&str, &str, &str)> {
    let begin_idx = content.find(FILTER_CHAINS_BEGIN_MARKER)?;
    let after_begin = begin_idx + FILTER_CHAINS_BEGIN_MARKER.len();
    let end_idx_rel = content[after_begin..].find(FILTER_CHAINS_END_MARKER)?;
    let end_idx = after_begin + end_idx_rel;
    Some((
        &content[..begin_idx],
        &content[after_begin..end_idx],
        &content[end_idx + FILTER_CHAINS_END_MARKER.len()..],
    ))
}

/// Compare the framing region of `old` vs `new` and return an error if
/// any non-filter-chains text differs.
fn enforce_invariant(old: &str, new: &str) -> Result<(), ListenerWriteError> {
    let old_parts = split_at_markers(old);
    let new_parts = split_at_markers(new);

    match (old_parts, new_parts) {
        (Some((old_head, _, old_tail)), Some((new_head, _, new_tail))) => {
            if old_head != new_head || old_tail != new_tail {
                let head_diff = if old_head != new_head {
                    "head (pre-filter_chains)"
                } else {
                    ""
                };
                let tail_diff = if old_tail != new_tail {
                    "tail (post-filter_chains)"
                } else {
                    ""
                };
                let diff_summary = match (head_diff.is_empty(), tail_diff.is_empty()) {
                    (false, false) => format!("{head_diff} and {tail_diff}"),
                    (false, true) => head_diff.to_string(),
                    (true, false) => tail_diff.to_string(),
                    (true, true) => unreachable!("one of the regions must differ"),
                };
                return Err(ListenerWriteError::InvariantViolated { diff_summary });
            }
            Ok(())
        }
        (None, _) => {
            // Old generation lacks markers — this shouldn't happen
            // because we only accept marker-bearing content, but be
            // defensive against manual edits / corruption.
            Err(ListenerWriteError::InvariantViolated {
                diff_summary: "previous generation on disk is missing filter-chains markers"
                    .to_string(),
            })
        }
        (_, None) => Err(ListenerWriteError::MissingMarkers {
            begin: FILTER_CHAINS_BEGIN_MARKER,
            end: FILTER_CHAINS_END_MARKER,
        }),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Render a minimal marker-framed listener file with the given head,
    /// filter-chains body, and tail. The text layout mirrors what
    /// `PolicyCompiler::compile_envoy_listener` emits.
    fn framed(head: &str, body: &str, tail: &str) -> String {
        format!("{head}\n{FILTER_CHAINS_BEGIN_MARKER}\n{body}\n{FILTER_CHAINS_END_MARKER}\n{tail}",)
    }

    #[test]
    fn write_rejects_content_without_markers() {
        let dir = TempDir::new().unwrap();
        let writer = AtomicListenerWriter::new(dir.path().join("listener.yaml"));
        let err = writer.write("resources: []\n").unwrap_err();
        assert!(
            matches!(err, ListenerWriteError::MissingMarkers { .. }),
            "expected MissingMarkers, got {err:?}"
        );
        assert!(
            !dir.path().join("listener.yaml").exists(),
            "no file should be written when markers are missing"
        );
    }

    #[test]
    fn write_rejects_content_with_duplicate_markers() {
        let dir = TempDir::new().unwrap();
        let writer = AtomicListenerWriter::new(dir.path().join("listener.yaml"));
        // Two BEGIN markers — the writer cannot split this
        // unambiguously, so it must refuse.
        let content = format!(
            "header\n{FILTER_CHAINS_BEGIN_MARKER}\n{FILTER_CHAINS_BEGIN_MARKER}\n    filter_chains: []\n{FILTER_CHAINS_END_MARKER}\n",
        );
        let err = writer.write(&content).unwrap_err();
        assert!(
            matches!(err, ListenerWriteError::MissingMarkers { .. }),
            "duplicated BEGIN marker must be rejected with MissingMarkers, got {err:?}"
        );
    }

    #[test]
    fn write_accepts_initial_generation_with_markers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("listener.yaml");
        let writer = AtomicListenerWriter::new(&path);
        let content = framed("head: 1\n", "    filter_chains: []", "tail: 1\n");

        let is_initial = writer.write(&content).unwrap();
        assert!(is_initial, "first write should report as initial");
        assert_eq!(fs::read_to_string(&path).unwrap(), content);
    }

    #[test]
    fn write_allows_filter_chains_only_change() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("listener.yaml");
        let writer = AtomicListenerWriter::new(&path);

        let gen1 = framed("head\n", "    filter_chains: []", "tail\n");
        writer.write(&gen1).unwrap();

        let gen2 = framed(
            "head\n",
            "    filter_chains:\n      - filters: []",
            "tail\n",
        );
        let is_initial = writer.write(&gen2).unwrap();
        assert!(!is_initial, "second write should not report as initial");
        assert_eq!(fs::read_to_string(&path).unwrap(), gen2);
    }

    #[test]
    fn write_rejects_head_region_change() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("listener.yaml");
        let writer = AtomicListenerWriter::new(&path);

        writer
            .write(&framed(
                "bind: 0.0.0.0:10000\n",
                "    filter_chains: []",
                "tail\n",
            ))
            .unwrap();

        // Changing bind address must be rejected — Envoy would drain.
        let err = writer
            .write(&framed(
                "bind: 127.0.0.1:10000\n",
                "    filter_chains: []",
                "tail\n",
            ))
            .unwrap_err();

        match err {
            ListenerWriteError::InvariantViolated { diff_summary } => {
                assert!(
                    diff_summary.contains("head"),
                    "diff summary should mention head: {diff_summary}"
                );
            }
            other => panic!("expected InvariantViolated, got {other:?}"),
        }
    }

    #[test]
    fn write_rejects_tail_region_change() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("listener.yaml");
        let writer = AtomicListenerWriter::new(&path);

        writer
            .write(&framed("head\n", "    filter_chains: []", "traffic: in\n"))
            .unwrap();

        let err = writer
            .write(&framed("head\n", "    filter_chains: []", "traffic: out\n"))
            .unwrap_err();
        assert!(
            matches!(err, ListenerWriteError::InvariantViolated { diff_summary } if diff_summary.contains("tail")),
            "tail change must produce tail-specific InvariantViolated"
        );
    }

    #[test]
    fn write_rejects_both_regions_changing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("listener.yaml");
        let writer = AtomicListenerWriter::new(&path);

        writer
            .write(&framed("head1\n", "    filter_chains: []", "tail1\n"))
            .unwrap();

        let err = writer
            .write(&framed("head2\n", "    filter_chains: []", "tail2\n"))
            .unwrap_err();
        match err {
            ListenerWriteError::InvariantViolated { diff_summary } => {
                assert!(
                    diff_summary.contains("head") && diff_summary.contains("tail"),
                    "diff summary should mention both head and tail: {diff_summary}"
                );
            }
            other => panic!("expected InvariantViolated, got {other:?}"),
        }
    }

    #[test]
    fn session_listener_host_paths_are_per_session() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert_ne!(
            session_listener_host_dir(&a),
            session_listener_host_dir(&b),
            "per-session host dirs must differ"
        );
        assert_eq!(
            session_listener_host_path(&a).file_name().unwrap(),
            LISTENER_FILE_NAME,
            "listener path must end with the canonical basename"
        );
    }

    // -----------------------------------------------------------------------
    // listener_host_root: XDG-compliant resolver
    //
    // These tests mutate process env vars. They are safe under nextest's
    // default per-test-process isolation, but each test snapshots and
    // restores the relevant vars within its own body to be robust against
    // future runner changes that might serialise tests within a process.
    // -----------------------------------------------------------------------

    /// Snapshot the trio of env vars `listener_host_root` reads, clear
    /// them, run `body`, then restore. Returned by-value so the test body
    /// stays linear.
    fn with_clean_env<F: FnOnce() -> R, R>(body: F) -> R {
        let prior_override = std::env::var("SANDBOX_LISTENER_DIR").ok();
        let prior_runtime = std::env::var("XDG_RUNTIME_DIR").ok();
        let prior_home = std::env::var("HOME").ok();
        // SAFETY: env mutation is process-global; nextest gives each
        // test its own process under the default profile, so the
        // unsafe block is sound. See the SANDBOX_SOCKET tests in
        // `sandboxd/src/main.rs` for the same pattern.
        unsafe {
            std::env::remove_var("SANDBOX_LISTENER_DIR");
            std::env::remove_var("XDG_RUNTIME_DIR");
            std::env::remove_var("HOME");
        }
        let result = body();
        unsafe {
            match prior_override {
                Some(v) => std::env::set_var("SANDBOX_LISTENER_DIR", v),
                None => std::env::remove_var("SANDBOX_LISTENER_DIR"),
            }
            match prior_runtime {
                Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
            match prior_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        result
    }

    #[test]
    fn listener_host_root_honors_explicit_override() {
        with_clean_env(|| {
            // SAFETY: see `with_clean_env`.
            unsafe {
                std::env::set_var("SANDBOX_LISTENER_DIR", "/var/lib/custom-listeners");
                // Set XDG and HOME too so we prove the override wins
                // over both lower-priority sources.
                std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
                std::env::set_var("HOME", "/home/test");
            }
            assert_eq!(
                listener_host_root(),
                PathBuf::from("/var/lib/custom-listeners"),
                "SANDBOX_LISTENER_DIR must take precedence over XDG and HOME"
            );
        });
    }

    #[test]
    fn listener_host_root_uses_xdg_runtime_dir_when_no_override() {
        with_clean_env(|| {
            // SAFETY: see `with_clean_env`.
            unsafe {
                std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
                std::env::set_var("HOME", "/home/test");
            }
            assert_eq!(
                listener_host_root(),
                PathBuf::from("/run/user/1000/sandboxd/listeners"),
                "without SANDBOX_LISTENER_DIR, XDG_RUNTIME_DIR must drive the default"
            );
        });
    }

    #[test]
    fn listener_host_root_falls_back_to_home_when_xdg_unset() {
        with_clean_env(|| {
            // SAFETY: see `with_clean_env`.
            unsafe {
                std::env::set_var("HOME", "/home/test");
            }
            assert_eq!(
                listener_host_root(),
                PathBuf::from("/home/test/.local/share/sandboxd/listeners"),
                "without XDG_RUNTIME_DIR, HOME-based fallback must apply"
            );
        });
    }

    #[test]
    fn listener_host_root_falls_back_to_tmp_when_home_and_xdg_unset() {
        with_clean_env(|| {
            assert_eq!(
                listener_host_root(),
                PathBuf::from("/tmp/sandboxd-listeners"),
                "with neither XDG nor HOME set, the last-resort /tmp \
                 path must apply so the daemon can still boot"
            );
        });
    }
}
