//! Tailing reader for JSONL event files.
//!
//! A [`JsonlTailer`] owns an open file handle, a byte offset, and a
//! partial-line buffer. On every wake ([`JsonlTailer::read_to_eof`]) it
//! reads everything from the current offset to EOF, splits on `\n`, and
//! yields one complete line per iteration via the caller's callback.
//! Incomplete trailing content (a buffered write that didn't land a
//! newline yet) is retained across wakes so no line is ever partially
//! parsed.
//!
//! # Seek-to-EOF rule
//!
//! When the tailer first opens an *existing* file whose size we did
//! **not** see grow, we seek to EOF. Rationale: at session re-ingest
//! (daemon restart) we don't want an avalanche of historical records
//! from the session's previous incarnation to flood the event bus — the
//! ring buffer would just evict them anyway, and a reconnecting
//! subscriber would see misattributed timestamps.
//!
//! When the tailer was spawned in response to an inotify `Create` event
//! for a file that appeared after the watcher started, we start at
//! offset 0. Rationale: the file is empty-then-grown so there's no
//! history to drown in; starting at EOF would miss the very first lines
//! written between the `Create` and our `open(2)`.
//!
//! The [`JsonlTailer::new_at_eof`] / [`JsonlTailer::new_at_start`]
//! constructors make the choice explicit at call sites.
//!
//! # Malformed lines
//!
//! A line that does not parse (invalid UTF-8 via [`String::from_utf8`]
//! or the per-layer parser returning `Err`) is logged at `warn` and
//! skipped. The tailer keeps going — a single bad line does not poison
//! the rest of the file.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use tracing::warn;

use crate::error::SandboxError;

/// Outcome of a single `read_to_eof` pass for test assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOutcome {
    /// Number of complete lines delivered to the callback in this pass.
    pub lines_delivered: usize,
    /// Number of bytes appended to the partial-line buffer but not yet
    /// terminated by `\n`.
    pub pending_bytes: usize,
    /// Current byte offset within the file after the read.
    pub offset: u64,
}

/// A byte-offset-tracking JSONL tailer.
///
/// Owns the [`File`] handle; not clonable. One tailer per file.
pub struct JsonlTailer {
    path: PathBuf,
    file: File,
    offset: u64,
    /// Buffer for the partial (un-terminated) tail of the last read.
    /// When the producer writes `{"a":1}\n{"b":` and we read at this
    /// point, the second record is held here until the next wake reads
    /// `2}\n` and we can concatenate and emit.
    partial: Vec<u8>,
}

impl JsonlTailer {
    /// Open `path` and seek to EOF (see module docs, "Seek-to-EOF rule").
    pub fn new_at_eof(path: &Path) -> Result<Self, SandboxError> {
        let mut file = File::open(path).map_err(|e| {
            SandboxError::Internal(format!("failed to open {}: {e}", path.display()))
        })?;
        let offset = file.seek(SeekFrom::End(0)).map_err(|e| {
            SandboxError::Internal(format!("failed to seek to EOF of {}: {e}", path.display()))
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            offset,
            partial: Vec::new(),
        })
    }

    /// Open `path` and start at byte 0 (see module docs).
    pub fn new_at_start(path: &Path) -> Result<Self, SandboxError> {
        let file = File::open(path).map_err(|e| {
            SandboxError::Internal(format!("failed to open {}: {e}", path.display()))
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            offset: 0,
            partial: Vec::new(),
        })
    }

    /// Path of the tailed file; exposed for logging and tests.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read everything from the current offset to EOF, splitting on
    /// `\n` and invoking `on_line` for each complete line (without the
    /// terminator). Incomplete trailing bytes are buffered.
    ///
    /// `on_line` receives a `&str`; lines that are not valid UTF-8 are
    /// skipped with a warning. This isolates the parser from needing
    /// to handle raw bytes — every producer writes UTF-8.
    pub fn read_to_eof<F>(&mut self, mut on_line: F) -> ReadOutcome
    where
        F: FnMut(&str),
    {
        // `Read::read_to_end` will append bytes from the current offset
        // to the end. We rely on the caller having already seeked the
        // file into position (either at construction or on a previous
        // wake). Short reads are handled by the loop's EOF-detection.
        let mut fresh = Vec::new();
        if let Err(e) = self.file.read_to_end(&mut fresh) {
            warn!(
                path = %self.path.display(),
                error = %e,
                "jsonl tailer: read_to_end failed; skipping wake"
            );
            return ReadOutcome {
                lines_delivered: 0,
                pending_bytes: self.partial.len(),
                offset: self.offset,
            };
        }
        self.offset += fresh.len() as u64;

        // Prepend any partial bytes from the previous wake, then split.
        let mut buf = std::mem::take(&mut self.partial);
        buf.extend_from_slice(&fresh);

        let mut lines_delivered = 0;
        let mut start = 0;
        for (i, &b) in buf.iter().enumerate() {
            if b == b'\n' {
                let line_bytes = &buf[start..i];
                match std::str::from_utf8(line_bytes) {
                    Ok(s) if !s.is_empty() => {
                        on_line(s);
                        lines_delivered += 1;
                    }
                    Ok(_) => {
                        // Empty line (two consecutive `\n`). Silently skip —
                        // not a parse error.
                    }
                    Err(e) => {
                        warn!(
                            path = %self.path.display(),
                            error = %e,
                            "jsonl tailer: non-UTF-8 line; skipping"
                        );
                    }
                }
                start = i + 1;
            }
        }
        // Retain the unterminated tail for the next wake.
        self.partial = buf[start..].to_vec();

        ReadOutcome {
            lines_delivered,
            pending_bytes: self.partial.len(),
            offset: self.offset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    use tempfile::NamedTempFile;

    fn write(file: &mut NamedTempFile, s: &str) {
        file.write_all(s.as_bytes()).unwrap();
        file.flush().unwrap();
    }

    #[test]
    fn new_at_start_reads_full_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        write(&mut tmp, "{\"a\":1}\n{\"b\":2}\n");
        let mut tailer = JsonlTailer::new_at_start(tmp.path()).unwrap();
        let mut lines: Vec<String> = Vec::new();
        let outcome = tailer.read_to_eof(|l| lines.push(l.to_string()));
        assert_eq!(
            lines,
            vec!["{\"a\":1}".to_string(), "{\"b\":2}".to_string()]
        );
        assert_eq!(outcome.lines_delivered, 2);
        assert_eq!(outcome.pending_bytes, 0);
    }

    #[test]
    fn new_at_eof_skips_historical_content() {
        let mut tmp = NamedTempFile::new().unwrap();
        write(&mut tmp, "{\"ignored\":true}\n");
        let mut tailer = JsonlTailer::new_at_eof(tmp.path()).unwrap();
        let mut lines: Vec<String> = Vec::new();
        let outcome = tailer.read_to_eof(|l| lines.push(l.to_string()));
        assert!(lines.is_empty(), "should not see historical content");
        assert_eq!(outcome.lines_delivered, 0);

        // But new content appended after EOF-open lands on the next wake.
        write(&mut tmp, "{\"live\":1}\n");
        let _ = tailer.read_to_eof(|l| lines.push(l.to_string()));
        assert_eq!(lines, vec!["{\"live\":1}".to_string()]);
    }

    #[test]
    fn partial_line_buffering_across_wakes() {
        let mut tmp = NamedTempFile::new().unwrap();
        write(&mut tmp, "{\"a\":1}\n{\"b\":");
        let mut tailer = JsonlTailer::new_at_start(tmp.path()).unwrap();
        let mut lines: Vec<String> = Vec::new();

        // First wake: one complete line, a partial one held back.
        let first = tailer.read_to_eof(|l| lines.push(l.to_string()));
        assert_eq!(lines, vec!["{\"a\":1}".to_string()]);
        assert_eq!(first.lines_delivered, 1);
        assert!(
            first.pending_bytes > 0,
            "partial `{{\"b\":` must be buffered"
        );

        // Producer finishes the partial record.
        write(&mut tmp, "2}\n");
        let second = tailer.read_to_eof(|l| lines.push(l.to_string()));
        assert_eq!(
            lines,
            vec!["{\"a\":1}".to_string(), "{\"b\":2}".to_string()],
            "partial must be joined with new bytes on the next wake"
        );
        assert_eq!(second.lines_delivered, 1);
        assert_eq!(second.pending_bytes, 0);
    }

    #[test]
    fn empty_lines_are_skipped_silently() {
        let mut tmp = NamedTempFile::new().unwrap();
        write(&mut tmp, "\n\n{\"ok\":true}\n");
        let mut tailer = JsonlTailer::new_at_start(tmp.path()).unwrap();
        let mut lines: Vec<String> = Vec::new();
        tailer.read_to_eof(|l| lines.push(l.to_string()));
        assert_eq!(lines, vec!["{\"ok\":true}".to_string()]);
    }

    #[test]
    fn non_utf8_line_is_skipped() {
        let path = NamedTempFile::new().unwrap().into_temp_path();
        // Write an invalid UTF-8 sequence followed by a valid line.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        // 0xFF is not a valid UTF-8 start byte.
        f.write_all(&[
            b'{', 0xFF, b'}', b'\n', b'{', b'"', b'o', b'"', b':', b'1', b'}', b'\n',
        ])
        .unwrap();
        f.flush().unwrap();
        drop(f);

        let mut tailer = JsonlTailer::new_at_start(&path).unwrap();
        let mut lines: Vec<String> = Vec::new();
        tailer.read_to_eof(|l| lines.push(l.to_string()));
        assert_eq!(lines, vec!["{\"o\":1}".to_string()]);
    }

    #[test]
    fn read_with_no_new_bytes_is_a_noop() {
        let mut tmp = NamedTempFile::new().unwrap();
        write(&mut tmp, "{\"a\":1}\n");
        let mut tailer = JsonlTailer::new_at_start(tmp.path()).unwrap();
        let mut lines: Vec<String> = Vec::new();
        tailer.read_to_eof(|l| lines.push(l.to_string()));
        assert_eq!(lines.len(), 1);

        // Second wake, no appended bytes.
        let outcome = tailer.read_to_eof(|l| lines.push(l.to_string()));
        assert_eq!(lines.len(), 1, "no new lines on second wake");
        assert_eq!(outcome.lines_delivered, 0);
        assert_eq!(outcome.pending_bytes, 0);
    }
}
