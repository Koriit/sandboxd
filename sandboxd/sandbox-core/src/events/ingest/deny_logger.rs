//! Deny-logger JSONL line parser.
//!
//! Parses one JSON object (one line of `deny-logger.jsonl`) produced by
//! the gateway container's deny-logger component into a domain
//! [`crate::events::DenyLoggerEvent`] wrapped in a
//! [`TrafficEvent::DenyLogger`], plus the `src_ip` used by the ingestor
//! for session attribution.
//!
//! Source of truth for the on-disk shape: spec Part 3 / "Deny-logger
//! component" (`.tasks/specs/2026-04-21-port-explicit-policies-presets-
//! observability-design.md`). The spec prescribes:
//!
//! - Common envelope fields `timestamp`, `layer` (`"deny-logger"`),
//!   `event` (`"deny"` or `"rate_limited"`).
//! - `deny` payload (spec "Traffic events" row for `deny-logger`):
//!   `orig_dst_ip`, `orig_dst_port`, `protocol` (`"tcp"` / `"udp"`),
//!   `src_ip`, `src_port`.
//! - `rate_limited` summary payload (spec "Hardening rules" § 5):
//!   `rate_limited_count`, `since_ts`.
//!
//! # Shape conventions
//!
//! - `layer` must equal `"deny-logger"`.
//! - `event` must be `"deny"` or `"rate_limited"`.
//! - On `deny`, the 5-tuple fields are all required; `src_ip` / `src_port`
//!   are the pre-DNAT peer (VM bridge IP), and `orig_dst_ip` /
//!   `orig_dst_port` are recovered from the kernel via `SO_ORIGINAL_DST`
//!   (TCP) or `IP_ORIGDSTADDR` (UDP) cmsg.
//! - On `rate_limited`, there is **no** 5-tuple — the event is a per-
//!   session summary of denied attempts dropped once the per-second rate
//!   cap was hit. The ingestor therefore cannot look up a session from a
//!   VM IP; see [`ParsedDenyLoggerEvent::src_ip`] and the watcher's
//!   dispatch arm for how attribution is resolved (fall back to the
//!   ingestor's own session).
//!
//! # Numeric-as-string tolerance
//!
//! Unlike Envoy's `json_format`, the deny-logger emitter (Phase 3) is a
//! hand-rolled Rust binary under our control, so all numeric fields are
//! authored as bare JSON numbers. The parser accepts only numbers for
//! numeric fields — defensive value-coercion is Envoy-specific.

use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::error::SandboxError;
use crate::events::{DenyLoggerDeny, DenyLoggerEvent, DenyProtocol, TrafficEvent};

/// Raw deny-logger event record, pre-domain.
///
/// Both the `deny` and `rate_limited` shapes share the common envelope
/// keys; payload fields are collected as `Option<_>` so a single struct
/// can deserialise both, with the per-event-type validation done after
/// `serde_json::from_str`.
#[derive(Debug, Deserialize)]
struct RawDenyLoggerRecord {
    timestamp: String,
    layer: String,
    event: String,
    // --- `deny` payload fields --------------------------------------
    #[serde(default)]
    orig_dst_ip: Option<String>,
    #[serde(default)]
    orig_dst_port: Option<u16>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    src_ip: Option<String>,
    #[serde(default)]
    src_port: Option<u16>,
    // --- `rate_limited` payload fields ------------------------------
    #[serde(default)]
    rate_limited_count: Option<u32>,
    #[serde(default)]
    since_ts: Option<String>,
}

/// Parsed deny-logger event, ready to stamp + publish.
///
/// `src_ip` is `Some` for `deny` records (used by the watcher for the
/// `vm_ip_map.lookup` call that stamps `session_id`) and `None` for
/// `rate_limited` summary records — the summary has no per-attempt
/// peer, so the watcher falls back to the ingestor's own session id.
///
/// `timestamp` is parsed from the record's `timestamp` field (RFC 3339 +
/// `Z`) and lifts to [`crate::events::EventEnvelope::timestamp`] — using
/// the producer's timestamp (not the ingestor's wall clock) preserves
/// the source-of-truth instant across the tail → publish latency.
pub struct ParsedDenyLoggerEvent {
    pub timestamp: DateTime<Utc>,
    pub src_ip: Option<Ipv4Addr>,
    pub traffic: TrafficEvent,
}

fn parse_ipv4(field: &str, value: &str) -> Result<Ipv4Addr, SandboxError> {
    value.parse::<Ipv4Addr>().map_err(|e| {
        SandboxError::Internal(format!(
            "deny-logger record: failed to parse {field} as IPv4 from {value:?}: {e}"
        ))
    })
}

fn parse_timestamp(field: &str, value: &str) -> Result<DateTime<Utc>, SandboxError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            SandboxError::Internal(format!(
                "deny-logger record: failed to parse `{field}` from {value:?}: {e}"
            ))
        })
}

fn parse_protocol(value: &str) -> Result<DenyProtocol, SandboxError> {
    match value {
        "tcp" => Ok(DenyProtocol::Tcp),
        "udp" => Ok(DenyProtocol::Udp),
        other => Err(SandboxError::Internal(format!(
            "deny-logger record: unexpected `protocol` value {other:?}, expected `tcp` or `udp`"
        ))),
    }
}

fn require<T>(field: &str, value: Option<T>) -> Result<T, SandboxError> {
    value.ok_or_else(|| {
        SandboxError::Internal(format!("deny-logger record: missing required `{field}` field"))
    })
}

/// Parse one JSONL line emitted by the deny-logger component.
///
/// Returns the [`TrafficEvent::DenyLogger`] plus the source IPv4 for
/// session attribution on `deny` records, or `None` on `rate_limited`
/// records (no 5-tuple to correlate; the watcher falls back to the
/// ingestor's owning session). Returns `Err` for malformed JSON, missing
/// required fields, unknown `event` values, or IP / protocol values that
/// don't parse; the caller logs + drops.
pub fn parse_deny_logger_line(line: &str) -> Result<ParsedDenyLoggerEvent, SandboxError> {
    let raw: RawDenyLoggerRecord = serde_json::from_str(line).map_err(|e| {
        SandboxError::Internal(format!(
            "deny-logger record: failed to parse JSON: {e}; line = {line:?}"
        ))
    })?;

    if raw.layer != "deny-logger" {
        return Err(SandboxError::Internal(format!(
            "deny-logger record: unexpected `layer` field {:?}, expected \"deny-logger\"",
            raw.layer
        )));
    }

    let timestamp = parse_timestamp("timestamp", &raw.timestamp)?;

    match raw.event.as_str() {
        "deny" => {
            let orig_dst_ip_str = require("orig_dst_ip", raw.orig_dst_ip)?;
            let orig_dst_ip = parse_ipv4("orig_dst_ip", &orig_dst_ip_str)?;
            let orig_dst_port = require("orig_dst_port", raw.orig_dst_port)?;
            let protocol_str = require("protocol", raw.protocol)?;
            let protocol = parse_protocol(&protocol_str)?;
            let src_ip_str = require("src_ip", raw.src_ip)?;
            let src_ip = parse_ipv4("src_ip", &src_ip_str)?;
            let src_port = require("src_port", raw.src_port)?;

            let deny = DenyLoggerDeny {
                orig_dst_ip,
                orig_dst_port,
                protocol,
                src_ip,
                src_port,
            };
            Ok(ParsedDenyLoggerEvent {
                timestamp,
                src_ip: Some(src_ip),
                traffic: TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(deny)),
            })
        }
        "rate_limited" => {
            let rate_limited_count = require("rate_limited_count", raw.rate_limited_count)?;
            let since_ts_str = require("since_ts", raw.since_ts)?;
            let since_ts = parse_timestamp("since_ts", &since_ts_str)?;
            Ok(ParsedDenyLoggerEvent {
                timestamp,
                src_ip: None,
                traffic: TrafficEvent::DenyLogger(DenyLoggerEvent::RateLimited {
                    rate_limited_count,
                    since_ts,
                }),
            })
        }
        other => Err(SandboxError::Internal(format!(
            "deny-logger record: unexpected `event` value {other:?}, expected `deny` or `rate_limited`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_deny_logger_line_accepts_tcp_deny() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"deny-logger","event":"deny","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"tcp","src_ip":"10.0.0.42","src_port":51234}"#;
        let parsed = parse_deny_logger_line(line).expect("tcp deny must parse");
        assert_eq!(
            parsed.src_ip,
            Some("10.0.0.42".parse::<Ipv4Addr>().unwrap())
        );
        match parsed.traffic {
            TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(d)) => {
                assert_eq!(d.orig_dst_ip, "203.0.113.1".parse::<Ipv4Addr>().unwrap());
                assert_eq!(d.orig_dst_port, 443);
                assert_eq!(d.protocol, DenyProtocol::Tcp);
                assert_eq!(d.src_ip, "10.0.0.42".parse::<Ipv4Addr>().unwrap());
                assert_eq!(d.src_port, 51234);
            }
            other => panic!("expected Deny variant, got {other:?}"),
        }
        let expected_ts = chrono::DateTime::parse_from_rfc3339("2026-04-22T09:45:00.123Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(parsed.timestamp, expected_ts);
    }

    #[test]
    fn parse_deny_logger_line_accepts_udp_deny() {
        let line = r#"{"timestamp":"2026-04-22T09:45:01.000Z","layer":"deny-logger","event":"deny","orig_dst_ip":"198.51.100.7","orig_dst_port":53,"protocol":"udp","src_ip":"10.0.0.42","src_port":33001}"#;
        let parsed = parse_deny_logger_line(line).expect("udp deny must parse");
        assert_eq!(
            parsed.src_ip,
            Some("10.0.0.42".parse::<Ipv4Addr>().unwrap())
        );
        match parsed.traffic {
            TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(d)) => {
                assert_eq!(d.protocol, DenyProtocol::Udp);
                assert_eq!(d.orig_dst_port, 53);
                assert_eq!(d.src_port, 33001);
            }
            other => panic!("expected Deny(udp) variant, got {other:?}"),
        }
    }

    #[test]
    fn parse_deny_logger_line_accepts_rate_limited() {
        let line = r#"{"timestamp":"2026-04-22T09:45:05.000Z","layer":"deny-logger","event":"rate_limited","rate_limited_count":42,"since_ts":"2026-04-22T09:45:04.000Z"}"#;
        let parsed = parse_deny_logger_line(line).expect("rate_limited summary must parse");
        // No 5-tuple — watcher will fall back to the ingestor's session.
        assert_eq!(parsed.src_ip, None);
        match parsed.traffic {
            TrafficEvent::DenyLogger(DenyLoggerEvent::RateLimited {
                rate_limited_count,
                since_ts,
            }) => {
                assert_eq!(rate_limited_count, 42);
                let expected_since = chrono::DateTime::parse_from_rfc3339("2026-04-22T09:45:04.000Z")
                    .unwrap()
                    .with_timezone(&Utc);
                assert_eq!(since_ts, expected_since);
            }
            other => panic!("expected RateLimited variant, got {other:?}"),
        }
    }

    #[test]
    fn parse_deny_logger_line_rejects_malformed() {
        // Non-JSON input.
        assert!(parse_deny_logger_line("not json").is_err());

        // Wrong layer.
        let wrong_layer = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"envoy","event":"deny","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"tcp","src_ip":"10.0.0.42","src_port":51234}"#;
        assert!(parse_deny_logger_line(wrong_layer).is_err());

        // Unknown event name.
        let unknown_event = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"deny-logger","event":"maybe","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"tcp","src_ip":"10.0.0.42","src_port":51234}"#;
        assert!(parse_deny_logger_line(unknown_event).is_err());

        // `deny` missing `src_ip`.
        let missing_src_ip = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"deny-logger","event":"deny","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"tcp","src_port":51234}"#;
        assert!(parse_deny_logger_line(missing_src_ip).is_err());

        // `deny` with unknown protocol.
        let bad_proto = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"deny-logger","event":"deny","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"sctp","src_ip":"10.0.0.42","src_port":51234}"#;
        assert!(parse_deny_logger_line(bad_proto).is_err());

        // `deny` with non-IPv4 `orig_dst_ip`.
        let bad_ip = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"deny-logger","event":"deny","orig_dst_ip":"not-an-ip","orig_dst_port":443,"protocol":"tcp","src_ip":"10.0.0.42","src_port":51234}"#;
        assert!(parse_deny_logger_line(bad_ip).is_err());

        // `rate_limited` missing `rate_limited_count`.
        let missing_count = r#"{"timestamp":"2026-04-22T09:45:05.000Z","layer":"deny-logger","event":"rate_limited","since_ts":"2026-04-22T09:45:04.000Z"}"#;
        assert!(parse_deny_logger_line(missing_count).is_err());

        // `rate_limited` missing `since_ts`.
        let missing_since = r#"{"timestamp":"2026-04-22T09:45:05.000Z","layer":"deny-logger","event":"rate_limited","rate_limited_count":42}"#;
        assert!(parse_deny_logger_line(missing_since).is_err());

        // Malformed timestamp.
        let bad_ts = r#"{"timestamp":"not a date","layer":"deny-logger","event":"deny","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"tcp","src_ip":"10.0.0.42","src_port":51234}"#;
        assert!(parse_deny_logger_line(bad_ts).is_err());
    }
}
