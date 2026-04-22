//! Per-(session, layer) JSONL append-only writer.
//!
//! Each [`LayerWriter`] holds one [`tokio::fs::File`] opened in append-
//! only + create mode, targeting a single day's file at
//! `{base_dir}/sessions/{session_id}/events/{layer}-YYYY-MM-DD.jsonl`.
//! The [`super::rotator`] owns a map of these writers and rotates by
//! dropping the handle and reopening once UTC date advances.
//!
//! # Atomicity
//!
//! Linux `write(2)` on a file opened with `O_APPEND` is atomic for
//! writes up to `PIPE_BUF` (4 096 bytes on Linux for regular files as
//! well as pipes, per POSIX.1-2001). Every JSONL line produced by
//! [`crate::api::event_to_jsonl_line`] is a single-line JSON object
//! followed by one `\n` terminator — in practice well under 4 KB
//! (typical sizes are 200-400 bytes; the fattest event today, a
//! `policy_updated` lifecycle with a fully expanded policy, stays
//! below 2 KB). We therefore do **not** need an additional lock
//! between concurrent writers: the kernel guarantees no interleaving
//! of bytes from separate `write` calls.
//!
//! In the current design there is only a single owning task (the sink
//! task — see [`super::mod`]) that writes through each
//! `LayerWriter`, so the atomicity note above is a safety-belt
//! property rather than a load-bearing invariant. If a future caller
//! shares a `LayerWriter` across tasks, the O_APPEND guarantee still
//! keeps the on-disk stream well-formed.

use std::io;
use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::AsyncWriteExt;

use crate::api::LayerKind;
use crate::session::SessionId;

/// A single-day JSONL writer for one `(session, layer)` pair.
///
/// The struct is intentionally minimal: it owns its [`File`] handle
/// and remembers the UTC date that handle was opened for. The
/// [`super::rotator`] is responsible for comparing `date` against
/// today and reopening on mismatch.
pub(super) struct LayerWriter {
    /// Absolute path of the file backing this writer. Retained for
    /// debug/log output; never used for re-open (rotation reopens via
    /// the session-id + layer + date path builder).
    #[allow(dead_code)]
    pub(super) path: PathBuf,
    /// Append-only handle. Opened with `O_APPEND | O_CREAT`.
    pub(super) file: File,
    /// UTC date the handle was opened for. On the first write after
    /// UTC midnight, the rotator drops this writer and opens a new
    /// one for the new date.
    pub(super) date: NaiveDate,
}

impl LayerWriter {
    /// Open (or create) the JSONL file for
    /// `{base_dir}/sessions/{session_id}/events/{layer}-{today}.jsonl`.
    ///
    /// Parent directories are created recursively via
    /// [`fs::create_dir_all`]. The file itself is opened with
    /// `append(true).create(true)` — concurrent opens are safe; bytes
    /// written through this handle always extend the file, never
    /// overwrite.
    pub(super) async fn open(
        base_dir: &Path,
        session_id: &SessionId,
        layer: LayerKind,
        today: NaiveDate,
    ) -> io::Result<Self> {
        let path = file_path(base_dir, session_id, layer, today);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .await?;
        Ok(Self {
            path,
            file,
            date: today,
        })
    }

    /// Append `line` to the file. `line` is expected to include its
    /// own trailing `\n` — [`crate::api::event_to_jsonl_line`] already
    /// does. No additional flushing is performed; the kernel buffer
    /// is implicitly flushed on close (at rotation / drop).
    pub(super) async fn append_line(&mut self, line: &str) -> io::Result<()> {
        self.file.write_all(line.as_bytes()).await
    }
}

/// Build the absolute path for a
/// `{base_dir}/sessions/{session_id}/events/{layer}-YYYY-MM-DD.jsonl`
/// file. Pulled out so both [`LayerWriter::open`] and tests (which
/// may want to fabricate fixture files in retention-pruner tests) use
/// exactly the same layout.
pub(super) fn file_path(
    base_dir: &Path,
    session_id: &SessionId,
    layer: LayerKind,
    date: NaiveDate,
) -> PathBuf {
    base_dir
        .join("sessions")
        .join(session_id.as_str())
        .join("events")
        .join(format!("{layer}-{}.jsonl", date.format("%Y-%m-%d")))
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::tempdir;
    use tokio::fs;

    fn sid() -> SessionId {
        SessionId::parse("0123456789ab").unwrap()
    }

    #[test]
    fn file_path_uses_spec_layout() {
        let date = NaiveDate::from_ymd_opt(2026, 4, 22).unwrap();
        let p = file_path(Path::new("/var/lib/sandboxd"), &sid(), LayerKind::Dns, date);
        assert_eq!(
            p,
            PathBuf::from(
                "/var/lib/sandboxd/sessions/0123456789ab/events/dns-2026-04-22.jsonl"
            ),
            "path layout must match spec (no extra events/ prefix)"
        );
    }

    #[test]
    fn file_path_includes_kebab_layer_name() {
        // `deny-logger` is the only multi-word layer. It must survive
        // into the filename as `deny-logger-YYYY-MM-DD.jsonl` — the
        // trailing `-YYYY-MM-DD` is what the pruner's date parser
        // strips, so preserving the kebab hyphen here is important.
        let date = NaiveDate::from_ymd_opt(2026, 4, 22).unwrap();
        let p = file_path(
            Path::new("/tmp/x"),
            &sid(),
            LayerKind::DenyLogger,
            date,
        );
        assert!(
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "deny-logger-2026-04-22.jsonl"),
            "unexpected filename: {p:?}"
        );
    }

    #[tokio::test]
    async fn layer_writer_appends_newline_terminated_lines() {
        let dir = tempdir().unwrap();
        let date = NaiveDate::from_ymd_opt(2026, 4, 22).unwrap();
        let mut w = LayerWriter::open(dir.path(), &sid(), LayerKind::Envoy, date)
            .await
            .expect("open writer");
        w.append_line("{\"hello\":\"world\"}\n")
            .await
            .expect("first append");
        w.append_line("{\"line\":2}\n").await.expect("second append");
        // Explicit flush before reading back; `tokio::fs::File` is
        // unbuffered at the tokio layer and writes go straight to the
        // kernel, but being explicit here keeps the test resilient if
        // tokio ever adds buffering.
        w.file.flush().await.expect("flush");
        drop(w);

        let path = file_path(dir.path(), &sid(), LayerKind::Envoy, date);
        let body = fs::read_to_string(&path).await.expect("read back");
        assert_eq!(body, "{\"hello\":\"world\"}\n{\"line\":2}\n");
        // Both lines newline-terminated; file ends with `\n`.
        assert!(body.ends_with('\n'));
        assert_eq!(body.matches('\n').count(), 2);
    }

    #[tokio::test]
    async fn layer_writer_creates_parent_dirs() {
        let dir = tempdir().unwrap();
        let date = NaiveDate::from_ymd_opt(2026, 4, 22).unwrap();
        let nested_base = dir.path().join("deeply").join("nested").join("base");
        // Sanity check: path does not exist yet.
        assert!(!nested_base.exists());
        let w = LayerWriter::open(&nested_base, &sid(), LayerKind::Dns, date)
            .await
            .expect("open must create parents");
        // The file must exist, and so must every ancestor.
        assert!(w.path.exists(), "file not created: {:?}", w.path);
        assert!(w.path.parent().unwrap().exists(), "events/ dir not created");
    }

    #[tokio::test]
    async fn layer_writer_reopens_append_without_clobber() {
        // Open, write, drop, reopen, write more — the second handle
        // must append, not truncate. Exercises the
        // `OpenOptions::append(true).create(true)` contract.
        let dir = tempdir().unwrap();
        let date = NaiveDate::from_ymd_opt(2026, 4, 22).unwrap();
        let sid = sid();
        {
            let mut w = LayerWriter::open(dir.path(), &sid, LayerKind::Dns, date)
                .await
                .expect("open #1");
            w.append_line("{\"run\":1}\n").await.unwrap();
            w.file.flush().await.unwrap();
        }
        {
            let mut w = LayerWriter::open(dir.path(), &sid, LayerKind::Dns, date)
                .await
                .expect("open #2");
            w.append_line("{\"run\":2}\n").await.unwrap();
            w.file.flush().await.unwrap();
        }
        let path = file_path(dir.path(), &sid, LayerKind::Dns, date);
        let body = fs::read_to_string(&path).await.unwrap();
        assert_eq!(
            body, "{\"run\":1}\n{\"run\":2}\n",
            "second open must append, not clobber; actual body = {body:?}"
        );
    }
}
