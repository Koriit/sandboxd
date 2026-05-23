//! JSONL event emitter.
//!
//! The gateway-container loggers' single output sink is a file opened in
//! append mode at the configured `--event-path`. Every denied connection
//! attempt (TCP or UDP) becomes one `deny` line; every allowed UDP flow
//! observed via NFCT becomes one `allow` line; every periodic
//! rate-limited summary becomes one `rate_limited` line. One JSON object
//! per line, matching the per-layer conventions already in use by
//! Envoy / CoreDNS / mitmproxy inside the gateway container.
//!
//! Design reference: `2026-04-21-port-explicit-policies-presets-observability-design.md`
//! Part 3 / "Traffic events" table row for layer `deny-logger` (the
//! `deny` / `rate_limited` shape) and
//! `2026-05-01-udp-nft-loggers-design.md` Decision 3 / Decision 5
//! (the `allow` shape).
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

/// L4 protocol tag on a `deny` / `allow` event. Serializes as `"tcp"` /
/// `"udp"`, matching `DenyProtocolDto` in `sandbox-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A single denied connection attempt — one record per accepted TCP
/// connection or per NFLOG-observed dropped UDP datagram (same wire
/// shape across the historical UDP-listener and current NFLOG data
/// sources, per `2026-05-01-udp-nft-loggers-design.md`).
///
/// Field names are wire-canonical; **do not rename** without updating
/// the ingest parser in sandbox-core. The wire shape is part of the
/// daemon-side ingest contract.
#[derive(Debug, Clone, Serialize)]
pub struct DenyRecord {
    pub orig_dst_ip: Ipv4Addr,
    pub orig_dst_port: u16,
    pub protocol: Protocol,
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
}

/// A single allowed UDP flow as observed via `NFCT_T_NEW` on the
/// `nfnetlink_conntrack` multicast group
/// (`2026-05-01-udp-nft-loggers-design.md` Decision 3).
///
/// ## Field rationale
///
/// The wire envelope mirrors [`DenyRecord`] field-for-field on purpose:
/// the design calls out the allow event as "analogous to the deny events"
/// (Decision 3 / 5) and the daemon-side event-mapper in
/// `sandbox-core/src/api/event_mapper.rs` consumes both shapes through
/// the same code path, with only the `event` discriminator distinguishing
/// them. Keeping the field set identical lets the consumer add an
/// `Allow` arm to its enum without forking the 5-tuple parsing logic.
///
/// Specifically:
///
/// - `orig_dst_ip` / `orig_dst_port`: destination as observed on the
///   conntrack ORIGINAL tuple. Under Decision 1 the UDP allow path does
///   *not* DNAT (the rule changes from `dnat to gateway_ip:10000` to a
///   plain `accept`), so the kernel-emitted ORIGINAL tuple's destination
///   is the literal address the VM dialled — `orig_dst_*` reads honestly
///   even though there is no NAT to "originate" past.
/// - `protocol`: always [`Protocol::Udp`] for `AllowRecord`. The field
///   exists on both records so the wire shape is uniform; allow-logger
///   subscribers filter the NFCT stream for UDP at parse time
///   (Decision 3 rationale: "kernel does the filtering for us").
/// - `src_ip` / `src_port`: VM-side endpoint, ORIGINAL tuple source.
///
/// ## Fields deliberately omitted
///
/// - **`flow_id` / conntrack tuple-id.** Considered, omitted. The
///   allow-event signal is NEW-only (no `NFCT_T_DESTROY` subscription,
///   no per-flow lifecycle), so there is no second event to correlate
///   the id against. If a future follow-on adds an `allow_end` event
///   sourced from `NFCT_T_DESTROY`, it can add `flow_id` additively
///   without breaking the existing wire shape.
/// - **`flow_start_ts` distinct from envelope `timestamp`.** The envelope
///   `timestamp` (added by the emitter at line write time) is the
///   moment the logger observed the NFCT_T_NEW event, which on a
///   non-saturated kernel is within ~milliseconds of the flow itself
///   starting. A separate field would be redundant for audit purposes.
///
/// If the audit-log consumer needs richer per-flow metadata later
/// (timing, reverse-tuple post-NAT addresses, conntrack zone, etc.),
/// add the fields here as `Option<T>` with `#[serde(default)]` so old
/// records still deserialise — same forward-compat policy as the rest
/// of the persisted-blob fields in this codebase.
#[derive(Debug, Clone, Serialize)]
pub struct AllowRecord {
    pub orig_dst_ip: Ipv4Addr,
    pub orig_dst_port: u16,
    pub protocol: Protocol,
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
}

/// Wire-shape envelope for a single JSONL line.
///
/// `layer` is the emitting binary's layer tag (`"deny-logger"` for the
/// nft-deny-logger; `"allow-logger"` for the nft-allow-logger — each
/// binary passes its own tag at the `emit_*` call site).
/// `event` discriminates between `"deny"`, `"allow"`, and
/// `"rate_limited"`. Flattened payload keeps the on-the-wire structure
/// flat so the ingest parser can `serde_json::from_str` a single struct
/// per variant without nesting.
#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Line<'a> {
    Deny {
        timestamp: DateTime<Utc>,
        layer: &'a str,
        #[serde(flatten)]
        body: DenyRecord,
    },
    Allow {
        timestamp: DateTime<Utc>,
        layer: &'a str,
        #[serde(flatten)]
        body: AllowRecord,
    },
    RateLimited {
        timestamp: DateTime<Utc>,
        layer: &'a str,
        rate_limited_count: u32,
        since_ts: DateTime<Utc>,
    },
}

/// Append-mode JSONL emitter.
///
/// The file is opened once at start-up and held behind a `Mutex<File>`
/// so concurrent emits serialize through the write syscall — this is
/// the simplest way to guarantee whole-line atomicity on the ingest
/// side, since POSIX `write` on a single file descriptor is atomic only
/// for buffers ≤ `PIPE_BUF`, and we must tolerate JSON lines longer
/// than that in the future (wider 5-tuples, richer IPv6, etc.).
///
/// The `events_emitted_60s` gauge is a rolling counter that the
/// `/health` endpoint exposes so a healthcheck can read a coarse
/// "is the emitter doing anything?" signal. Reset by the health
/// listener's background ticker via [`EventEmitter::reset_gauge`].
///
/// The `layer` tag is captured once at construction and used on every
/// emitted line so the deny-logger and allow-logger can produce
/// distinct layer tags without per-call wiring.
pub struct EventEmitter {
    file: Mutex<File>,
    events_emitted_60s: AtomicU64,
    layer: String,
}

impl EventEmitter {
    /// Open `path` in append mode (create if missing) and return a
    /// ready emitter tagged with `layer` (e.g. `"deny-logger"`).
    pub fn open(path: &Path, layer: impl Into<String>) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
            events_emitted_60s: AtomicU64::new(0),
            layer: layer.into(),
        })
    }

    /// Emit a `deny` line. Flushes through to the OS page cache; the
    /// ingest watcher on the sandboxd side picks the line up via its
    /// 2s inotify + poll fallback.
    pub fn emit_deny(&self, record: DenyRecord) {
        let line = Line::Deny {
            timestamp: Utc::now(),
            layer: &self.layer,
            body: record,
        };
        self.write_line(&line);
    }

    /// Emit an `allow` line.
    ///
    /// Used by `sandbox-nft-allow-logger` when it observes a new UDP
    /// flow on `NFNLGRP_CONNTRACK_NEW`
    /// (`2026-05-01-udp-nft-loggers-design.md` Decision 3). Same
    /// on-disk envelope as `deny`, distinguished by the `event`
    /// discriminator.
    pub fn emit_allow(&self, record: AllowRecord) {
        let line = Line::Allow {
            timestamp: Utc::now(),
            layer: &self.layer,
            body: record,
        };
        self.write_line(&line);
    }

    /// Emit a `rate_limited` summary line. `since_ts` is the timestamp
    /// of the previous flush; `rate_limited_count` is the number of
    /// events that were dropped in that interval. Called by
    /// [`crate::limits::RateCap`] on window rollover.
    pub fn emit_rate_limited(&self, rate_limited_count: u32, since_ts: DateTime<Utc>) {
        let line = Line::RateLimited {
            timestamp: Utc::now(),
            layer: &self.layer,
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

    fn write_line(&self, line: &Line<'_>) {
        let rendered = match serde_json::to_string(line) {
            Ok(s) => s,
            Err(err) => {
                // Serialization should be infallible for our concrete
                // types; if it ever isn't, log and drop — we never
                // block an accept on a JSON error.
                tracing::error!(error = %err, "event-emitter: serialize failed");
                return;
            }
        };
        let mut guard = match self.file.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        if let Err(err) = writeln!(*guard, "{rendered}") {
            tracing::error!(error = %err, "event-emitter: write failed");
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
        let emitter = EventEmitter::open(&path, "deny-logger").unwrap();
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

    /// Round-trip test for `AllowRecord` mirroring the deny equivalent.
    /// Pins the wire-shape contract: same flat envelope, same
    /// snake_case field names, distinct `event` discriminator. The
    /// allow-logger's integration tests cover the real NFCT data
    /// source; this hermetic test pins the on-disk shape so the
    /// daemon-side parser can be written against a stable contract.
    #[test]
    fn allow_line_has_required_fields_and_snake_case() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allow.jsonl");
        let emitter = EventEmitter::open(&path, "allow-logger").unwrap();
        emitter.emit_allow(AllowRecord {
            orig_dst_ip: Ipv4Addr::new(198, 51, 100, 7),
            orig_dst_port: 123,
            protocol: Protocol::Udp,
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 51234,
        });
        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1);
        let json: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(json["event"], "allow");
        assert_eq!(json["layer"], "allow-logger");
        assert_eq!(json["orig_dst_ip"], "198.51.100.7");
        assert_eq!(json["orig_dst_port"], 123);
        assert_eq!(json["protocol"], "udp");
        assert_eq!(json["src_ip"], "10.0.0.2");
        assert_eq!(json["src_port"], 51234);
        assert!(
            json.get("session").is_none(),
            "allow-logger must not stamp session"
        );
        assert!(DateTime::parse_from_rfc3339(json["timestamp"].as_str().unwrap()).is_ok());
    }

    #[test]
    fn rate_limited_line_uses_spec_field_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = EventEmitter::open(&path, "deny-logger").unwrap();
        let since = Utc::now();
        emitter.emit_rate_limited(42, since);
        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1);
        let json: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(json["event"], "rate_limited");
        assert_eq!(json["layer"], "deny-logger");
        // the canonical wire field name.
        assert_eq!(json["rate_limited_count"], 42);
        assert!(
            json.get("dropped_events_count").is_none(),
            "wire field is rate_limited_count, not dropped_events_count"
        );
    }

    #[test]
    fn gauge_increments_on_emit_and_resets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = EventEmitter::open(&path, "deny-logger").unwrap();
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
