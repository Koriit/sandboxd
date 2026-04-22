//! JSONL event emitter.
//!
//! The deny-logger's single output sink is a file opened in append mode
//! at `--event-path`. Every denied connection attempt (TCP or UDP) and
//! every periodic rate-limited summary becomes one line of JSON, one
//! line per event, matching the per-layer conventions already in use by
//! Envoy / CoreDNS / mitmproxy inside the gateway container.
//!
//! Spec reference: Part 3 / "Traffic events" table row for layer
//! `deny-logger` — fields `orig_dst_ip`, `orig_dst_port`, `protocol`,
//! `src_ip`, `src_port` for the `deny` shape;
//! `rate_limited_count` + `since_ts` for the summary shape (spec Part 3
//! / "Hardening rules" § 5).
//!
//! **Session awareness:** intentionally absent. sandboxd stamps
//! `session` at ingest via its `vm_ip → session-id` map — matches the
//! Envoy / CoreDNS / mitmproxy pattern.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use serde::Serialize;

/// L4 protocol tag on a `deny` event. Serializes as `"tcp"` / `"udp"`,
/// matching `DenyProtocolDto` in `sandbox-core`.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A single denied connection attempt — one record per accepted TCP
/// connection, one record per received UDP datagram.
///
/// Field names are spec-canonical; **do not rename** without updating
/// the ingest parser in sandbox-core and coordinating with the M10-S3
/// Phase 5 handoff.
#[derive(Debug, Clone, Serialize)]
pub struct DenyRecord {
    pub orig_dst_ip: Ipv4Addr,
    pub orig_dst_port: u16,
    pub protocol: Protocol,
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
}

/// Wire-shape envelope for a single JSONL line.
///
/// `layer` is always `"deny-logger"`; `event` discriminates between
/// `"deny"` (per-attempt) and `"rate_limited"` (periodic summary).
/// Flattened payload keeps the on-the-wire structure flat so the ingest
/// parser (Phase 5) can `serde_json::from_str` a single struct per
/// variant without nesting.
#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Line {
    Deny {
        timestamp: DateTime<Utc>,
        layer: &'static str,
        #[serde(flatten)]
        body: DenyRecord,
    },
    RateLimited {
        timestamp: DateTime<Utc>,
        layer: &'static str,
        rate_limited_count: u32,
        since_ts: DateTime<Utc>,
    },
}

/// Append-mode JSONL emitter.
///
/// The file is opened once at start-up and held behind a `Mutex<File>`
/// so concurrent accepts serialize through the write syscall — this is
/// the simplest way to guarantee whole-line atomicity on the ingest
/// side, since POSIX `write` on a single file descriptor is atomic only
/// for buffers ≤ `PIPE_BUF`, and we must tolerate JSON lines longer
/// than that in the future (wider 5-tuples, richer IPv6, etc.).
///
/// The `events_emitted_60s` gauge is a rolling counter that a later
/// commit wires into `/health` so the healthcheck endpoint can expose a
/// coarse "is the emitter doing anything?" signal. Reset elsewhere via
/// [`EventEmitter::reset_gauge`].
pub struct EventEmitter {
    file: Mutex<File>,
    events_emitted_60s: AtomicU64,
}

impl EventEmitter {
    /// Open `path` in append mode (create if missing) and return a
    /// ready emitter.
    pub fn open(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
            events_emitted_60s: AtomicU64::new(0),
        })
    }

    /// Emit a `deny` line. Flushes through to the OS page cache; the
    /// ingest watcher on the sandboxd side picks the line up via its
    /// 2s inotify + poll fallback.
    pub fn emit_deny(&self, record: DenyRecord) {
        let line = Line::Deny {
            timestamp: Utc::now(),
            layer: "deny-logger",
            body: record,
        };
        self.write_line(&line);
    }

    /// Emit a `rate_limited` summary line. `since_ts` is the timestamp
    /// of the previous flush; `rate_limited_count` is the number of
    /// denies that were dropped in that interval. Called by
    /// [`crate::limits::RateCap`] on window rollover.
    pub fn emit_rate_limited(&self, rate_limited_count: u32, since_ts: DateTime<Utc>) {
        let line = Line::RateLimited {
            timestamp: Utc::now(),
            layer: "deny-logger",
            rate_limited_count,
            since_ts,
        };
        self.write_line(&line);
    }

    /// Current value of the rolling events-per-window gauge. Consumed
    /// by the health listener for the `events_emitted_60s` JSON field.
    pub fn events_emitted_60s(&self) -> u64 {
        self.events_emitted_60s.load(Ordering::Relaxed)
    }

    /// Reset the rolling gauge. Called by the health listener's
    /// background ticker every 60s so the exposed value approximates
    /// "events in the last minute".
    pub fn reset_gauge(&self) {
        self.events_emitted_60s.store(0, Ordering::Relaxed);
    }

    fn write_line(&self, line: &Line) {
        let rendered = match serde_json::to_string(line) {
            Ok(s) => s,
            Err(err) => {
                // Serialization should be infallible for our concrete
                // types; if it ever isn't, log and drop — we never
                // block an accept on a JSON error.
                tracing::error!(error = %err, "deny-logger: serialize failed");
                return;
            }
        };
        let mut guard = match self.file.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        if let Err(err) = writeln!(*guard, "{rendered}") {
            tracing::error!(error = %err, "deny-logger: write failed");
            return;
        }
        self.events_emitted_60s.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    fn read_lines(path: &Path) -> Vec<String> {
        let file = File::open(path).expect("open jsonl for read");
        BufReader::new(file)
            .lines()
            .map(|l| l.expect("read line"))
            .collect()
    }

    #[test]
    fn deny_line_has_required_fields_and_snake_case() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = EventEmitter::open(&path).unwrap();
        emitter.emit_deny(DenyRecord {
            orig_dst_ip: Ipv4Addr::new(203, 0, 113, 5),
            orig_dst_port: 8080,
            protocol: Protocol::Tcp,
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 55123,
        });
        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1);
        let json: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(json["event"], "deny");
        assert_eq!(json["layer"], "deny-logger");
        assert_eq!(json["orig_dst_ip"], "203.0.113.5");
        assert_eq!(json["orig_dst_port"], 8080);
        assert_eq!(json["protocol"], "tcp");
        assert_eq!(json["src_ip"], "10.0.0.2");
        assert_eq!(json["src_port"], 55123);
        // sandboxd-side concern; must not leak here.
        assert!(
            json.get("session").is_none(),
            "deny-logger must not stamp session"
        );
        // Timestamp must be RFC 3339 parseable.
        assert!(DateTime::parse_from_rfc3339(json["timestamp"].as_str().unwrap()).is_ok());
    }

    #[test]
    fn rate_limited_line_uses_spec_field_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = EventEmitter::open(&path).unwrap();
        let since = Utc::now();
        emitter.emit_rate_limited(42, since);
        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1);
        let json: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(json["event"], "rate_limited");
        assert_eq!(json["layer"], "deny-logger");
        // Spec name — see spec Part 3 / "Hardening rules" § 5 and the
        // plan's Q5 / the fix(events) commit on the base branch.
        assert_eq!(json["rate_limited_count"], 42);
        assert!(
            json.get("dropped_events_count").is_none(),
            "spec field is rate_limited_count, not dropped_events_count"
        );
    }

    #[test]
    fn gauge_increments_on_emit_and_resets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = EventEmitter::open(&path).unwrap();
        for _ in 0..3 {
            emitter.emit_deny(DenyRecord {
                orig_dst_ip: Ipv4Addr::new(1, 2, 3, 4),
                orig_dst_port: 1,
                protocol: Protocol::Udp,
                src_ip: Ipv4Addr::new(10, 0, 0, 2),
                src_port: 2,
            });
        }
        assert_eq!(emitter.events_emitted_60s(), 3);
        emitter.reset_gauge();
        assert_eq!(emitter.events_emitted_60s(), 0);
    }
}
