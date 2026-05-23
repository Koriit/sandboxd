//! Nft-logger family JSONL line parser (deny-logger + allow-logger).
//!
//! Single ingest module covering both producer files written under the
//! gateway container's `/var/log/gateway/events/` mount:
//!
//! - `nft-deny.jsonl`   — produced by `sandbox-nft-deny-logger`.
//!   Records carry `layer == "deny-logger"` and `event` ∈
//!   `{"deny", "rate_limited"}`.
//! - `nft-allow.jsonl`   — produced by `sandbox-nft-allow-logger`.
//!   Records carry `layer == "allow-logger"` and `event` ∈
//!   `{"allow", "rate_limited"}`.
//!
//! Both producers share the same on-disk JSONL shape (RFC 3339 timestamp,
//! 5-tuple payload, common rate-limited summary), so they share one
//! parser and one ingestor dispatch arm. The deny / allow distinction
//! is captured by the `event` discriminator on the bus rather than a
//! separate domain pipeline ("additive change, not a new pipeline").
//!
//! The on-disk shape follows the event wire format / "Deny-logger component":
//!
//! - Common envelope fields `timestamp`, `layer`, `event`.
//! - `deny` / `allow` payload (traffic event for `deny-logger`,
//!   identical for the allow variant): `orig_dst_ip`, `orig_dst_port`,
//!   `protocol` (`"tcp"` / `"udp"`), `src_ip`, `src_port`.
//! - `rate_limited` summary payload (
//!   `rate_limited_count`, `since_ts`.
//!
//! # Layer / event pairing
//!
//! The parser enforces:
//!
//! - `layer == "deny-logger"` only allows `event` ∈ `{"deny", "rate_limited"}`.
//! - `layer == "allow-logger"` only allows `event` ∈ `{"allow", "rate_limited"}`.
//!
//! Cross-pairs (e.g. `layer: "allow-logger"` + `event: "deny"`) are
//! rejected so a gateway-side regression mis-labelling its own files is
//! caught at ingest rather than leaking into the bus.
//!
//! # Numeric-as-string tolerance
//!
//! Unlike Envoy's `json_format`, both nft-logger emitters are hand-rolled
//! Rust binaries under our control, so all numeric fields are authored as
//! bare JSON numbers. The parser accepts only numbers for numeric fields
//! — defensive value-coercion is Envoy-specific.

use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::error::SandboxError;
use crate::events::{DenyLoggerAllow, DenyLoggerDeny, DenyLoggerEvent, DenyProtocol, TrafficEvent};

/// Raw nft-logger event record, pre-domain.
///
/// Both the `deny` / `allow` and `rate_limited` shapes share the common
/// envelope keys; payload fields are collected as `Option<_>` so a single
/// struct can deserialise all four variants, with the per-event-type
/// validation done after `serde_json::from_str`.
#[derive(Debug, Deserialize)]
struct RawNftLoggerRecord {
    timestamp: String,
    layer: String,
    event: String,
    // --- `deny` / `allow` payload fields ----------------------------
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

/// Parsed nft-logger event, ready to stamp + publish.
///
/// `src_ip` is `Some` for `deny` / `allow` records (used by the watcher
/// for the `vm_ip_map.lookup` call that stamps `session_id`) and `None`
/// for `rate_limited` summary records — the summary has no per-attempt
/// peer, so the watcher falls back to the ingestor's own session id.
///
/// `timestamp` is parsed from the record's `timestamp` field (RFC 3339 +
/// `Z`) and lifts to [`crate::events::EventEnvelope::timestamp`] — using
/// the producer's timestamp (not the ingestor's wall clock) preserves
/// the source-of-truth instant across the tail → publish latency.
pub struct ParsedNftLoggerEvent {
    pub timestamp: DateTime<Utc>,
    pub src_ip: Option<Ipv4Addr>,
    pub traffic: TrafficEvent,
}

fn parse_ipv4(field: &str, value: &str) -> Result<Ipv4Addr, SandboxError> {
    value.parse::<Ipv4Addr>().map_err(|e| {
        SandboxError::Internal(format!(
            "nft-logger record: failed to parse {field} as IPv4 from {value:?}: {e}"
        ))
    })
}

fn parse_timestamp(field: &str, value: &str) -> Result<DateTime<Utc>, SandboxError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            SandboxError::Internal(format!(
                "nft-logger record: failed to parse `{field}` from {value:?}: {e}"
            ))
        })
}

fn parse_protocol(value: &str) -> Result<DenyProtocol, SandboxError> {
    match value {
        "tcp" => Ok(DenyProtocol::Tcp),
        "udp" => Ok(DenyProtocol::Udp),
        other => Err(SandboxError::Internal(format!(
            "nft-logger record: unexpected `protocol` value {other:?}, expected `tcp` or `udp`"
        ))),
    }
}

fn require<T>(field: &str, value: Option<T>) -> Result<T, SandboxError> {
    value.ok_or_else(|| {
        SandboxError::Internal(format!(
            "nft-logger record: missing required `{field}` field"
        ))
    })
}

/// Five-tuple shared by the `deny` and `allow` payloads. Returns the
/// concrete IPv4 / port / protocol fields plus the `src_ip` for session
/// attribution.
struct FiveTuple {
    orig_dst_ip: Ipv4Addr,
    orig_dst_port: u16,
    protocol: DenyProtocol,
    src_ip: Ipv4Addr,
    src_port: u16,
}

fn parse_5tuple(raw: &RawNftLoggerRecord) -> Result<FiveTuple, SandboxError> {
    let orig_dst_ip_str = require("orig_dst_ip", raw.orig_dst_ip.clone())?;
    let orig_dst_ip = parse_ipv4("orig_dst_ip", &orig_dst_ip_str)?;
    let orig_dst_port = require("orig_dst_port", raw.orig_dst_port)?;
    let protocol_str = require("protocol", raw.protocol.clone())?;
    let protocol = parse_protocol(&protocol_str)?;
    let src_ip_str = require("src_ip", raw.src_ip.clone())?;
    let src_ip = parse_ipv4("src_ip", &src_ip_str)?;
    let src_port = require("src_port", raw.src_port)?;
    Ok(FiveTuple {
        orig_dst_ip,
        orig_dst_port,
        protocol,
        src_ip,
        src_port,
    })
}

/// Parse one JSONL line emitted by either nft-logger producer.
///
/// Returns the [`TrafficEvent::DenyLogger`] (the on-bus container of the
/// nft-logger family — `Allow` and `Deny` are two of its variants) plus
/// the source IPv4 for session attribution on `deny` / `allow` records,
/// or `None` on `rate_limited` records (no 5-tuple to correlate; the
/// watcher falls back to the ingestor's owning session). Returns `Err`
/// for malformed JSON, missing required fields, unknown `event` values,
/// layer/event mismatches, or IP / protocol values that don't parse;
/// the caller logs + drops.
pub fn parse_nft_logger_line(line: &str) -> Result<ParsedNftLoggerEvent, SandboxError> {
    let raw: RawNftLoggerRecord = serde_json::from_str(line).map_err(|e| {
        SandboxError::Internal(format!(
            "nft-logger record: failed to parse JSON: {e}; line = {line:?}"
        ))
    })?;

    let timestamp = parse_timestamp("timestamp", &raw.timestamp)?;

    match (raw.layer.as_str(), raw.event.as_str()) {
        ("deny-logger", "deny") => {
            let t = parse_5tuple(&raw)?;
            let deny = DenyLoggerDeny {
                orig_dst_ip: t.orig_dst_ip,
                orig_dst_port: t.orig_dst_port,
                protocol: t.protocol,
                src_ip: t.src_ip,
                src_port: t.src_port,
            };
            Ok(ParsedNftLoggerEvent {
                timestamp,
                src_ip: Some(t.src_ip),
                traffic: TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(deny)),
            })
        }
        ("allow-logger", "allow") => {
            let t = parse_5tuple(&raw)?;
            let allow = DenyLoggerAllow {
                orig_dst_ip: t.orig_dst_ip,
                orig_dst_port: t.orig_dst_port,
                protocol: t.protocol,
                src_ip: t.src_ip,
                src_port: t.src_port,
            };
            Ok(ParsedNftLoggerEvent {
                timestamp,
                src_ip: Some(t.src_ip),
                traffic: TrafficEvent::DenyLogger(DenyLoggerEvent::Allow(allow)),
            })
        }
        ("deny-logger", "rate_limited") | ("allow-logger", "rate_limited") => {
            let rate_limited_count = require("rate_limited_count", raw.rate_limited_count)?;
            let since_ts_str = require("since_ts", raw.since_ts.clone())?;
            let since_ts = parse_timestamp("since_ts", &since_ts_str)?;
            Ok(ParsedNftLoggerEvent {
                timestamp,
                src_ip: None,
                traffic: TrafficEvent::DenyLogger(DenyLoggerEvent::RateLimited {
                    rate_limited_count,
                    since_ts,
                }),
            })
        }
        // Layer/event pairing violations are surfaced as parse errors so
        // a gateway-side regression that mis-labels its own files cannot
        // silently leak into the bus.
        ("deny-logger", other) => Err(SandboxError::Internal(format!(
            "nft-logger record: unexpected `event` value {other:?} on layer \"deny-logger\", \
             expected `deny` or `rate_limited`"
        ))),
        ("allow-logger", other) => Err(SandboxError::Internal(format!(
            "nft-logger record: unexpected `event` value {other:?} on layer \"allow-logger\", \
             expected `allow` or `rate_limited`"
        ))),
        (other_layer, _) => Err(SandboxError::Internal(format!(
            "nft-logger record: unexpected `layer` value {other_layer:?}, \
             expected \"deny-logger\" or \"allow-logger\""
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nft_logger_line_accepts_tcp_deny() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"deny-logger","event":"deny","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"tcp","src_ip":"10.0.0.42","src_port":51234}"#;
        let parsed = parse_nft_logger_line(line).expect("tcp deny must parse");
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
    fn parse_nft_logger_line_accepts_udp_deny() {
        let line = r#"{"timestamp":"2026-04-22T09:45:01.000Z","layer":"deny-logger","event":"deny","orig_dst_ip":"198.51.100.7","orig_dst_port":53,"protocol":"udp","src_ip":"10.0.0.42","src_port":33001}"#;
        let parsed = parse_nft_logger_line(line).expect("udp deny must parse");
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
    fn parse_nft_logger_line_accepts_udp_allow() {
        // `nft-allow.jsonl` shape.
        let line = r#"{"timestamp":"2026-04-22T09:45:02.500Z","layer":"allow-logger","event":"allow","orig_dst_ip":"1.1.1.1","orig_dst_port":53,"protocol":"udp","src_ip":"10.0.0.42","src_port":40123}"#;
        let parsed = parse_nft_logger_line(line).expect("udp allow must parse");
        assert_eq!(
            parsed.src_ip,
            Some("10.0.0.42".parse::<Ipv4Addr>().unwrap())
        );
        match parsed.traffic {
            TrafficEvent::DenyLogger(DenyLoggerEvent::Allow(a)) => {
                assert_eq!(a.protocol, DenyProtocol::Udp);
                assert_eq!(a.orig_dst_ip, "1.1.1.1".parse::<Ipv4Addr>().unwrap());
                assert_eq!(a.orig_dst_port, 53);
                assert_eq!(a.src_ip, "10.0.0.42".parse::<Ipv4Addr>().unwrap());
                assert_eq!(a.src_port, 40123);
            }
            other => panic!("expected Allow(udp) variant, got {other:?}"),
        }
    }

    #[test]
    fn parse_nft_logger_line_accepts_rate_limited_from_deny_layer() {
        let line = r#"{"timestamp":"2026-04-22T09:45:05.000Z","layer":"deny-logger","event":"rate_limited","rate_limited_count":42,"since_ts":"2026-04-22T09:45:04.000Z"}"#;
        let parsed = parse_nft_logger_line(line).expect("rate_limited summary must parse");
        // No 5-tuple — watcher will fall back to the ingestor's session.
        assert_eq!(parsed.src_ip, None);
        match parsed.traffic {
            TrafficEvent::DenyLogger(DenyLoggerEvent::RateLimited {
                rate_limited_count,
                since_ts,
            }) => {
                assert_eq!(rate_limited_count, 42);
                let expected_since =
                    chrono::DateTime::parse_from_rfc3339("2026-04-22T09:45:04.000Z")
                        .unwrap()
                        .with_timezone(&Utc);
                assert_eq!(since_ts, expected_since);
            }
            other => panic!("expected RateLimited variant, got {other:?}"),
        }
    }

    #[test]
    fn parse_nft_logger_line_accepts_rate_limited_from_allow_layer() {
        // The allow-logger uses the same per-process RateCap as the
        // deny-logger and so emits the identical summary record under a
        // different layer name.
        let line = r#"{"timestamp":"2026-04-22T09:45:05.000Z","layer":"allow-logger","event":"rate_limited","rate_limited_count":7,"since_ts":"2026-04-22T09:45:04.000Z"}"#;
        let parsed = parse_nft_logger_line(line).expect("rate_limited (allow) must parse");
        assert_eq!(parsed.src_ip, None);
        match parsed.traffic {
            TrafficEvent::DenyLogger(DenyLoggerEvent::RateLimited {
                rate_limited_count, ..
            }) => {
                assert_eq!(rate_limited_count, 7);
            }
            other => panic!("expected RateLimited variant, got {other:?}"),
        }
    }

    #[test]
    fn parse_nft_logger_line_rejects_layer_event_mismatch() {
        // allow-logger + deny event → mismatch.
        let allow_layer_deny_event = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"allow-logger","event":"deny","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"tcp","src_ip":"10.0.0.42","src_port":51234}"#;
        assert!(parse_nft_logger_line(allow_layer_deny_event).is_err());

        // deny-logger + allow event → mismatch.
        let deny_layer_allow_event = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"deny-logger","event":"allow","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"tcp","src_ip":"10.0.0.42","src_port":51234}"#;
        assert!(parse_nft_logger_line(deny_layer_allow_event).is_err());
    }

    #[test]
    fn parse_nft_logger_line_rejects_malformed() {
        // Non-JSON input.
        assert!(parse_nft_logger_line("not json").is_err());

        // Wrong layer entirely.
        let wrong_layer = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"envoy","event":"deny","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"tcp","src_ip":"10.0.0.42","src_port":51234}"#;
        assert!(parse_nft_logger_line(wrong_layer).is_err());

        // Unknown event name on deny-logger.
        let unknown_event = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"deny-logger","event":"maybe","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"tcp","src_ip":"10.0.0.42","src_port":51234}"#;
        assert!(parse_nft_logger_line(unknown_event).is_err());

        // `deny` missing `src_ip`.
        let missing_src_ip = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"deny-logger","event":"deny","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"tcp","src_port":51234}"#;
        assert!(parse_nft_logger_line(missing_src_ip).is_err());

        // `allow` missing `orig_dst_ip`.
        let allow_missing_orig = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"allow-logger","event":"allow","orig_dst_port":53,"protocol":"udp","src_ip":"10.0.0.42","src_port":40123}"#;
        assert!(parse_nft_logger_line(allow_missing_orig).is_err());

        // `deny` with unknown protocol.
        let bad_proto = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"deny-logger","event":"deny","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"sctp","src_ip":"10.0.0.42","src_port":51234}"#;
        assert!(parse_nft_logger_line(bad_proto).is_err());

        // `deny` with non-IPv4 `orig_dst_ip`.
        let bad_ip = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"deny-logger","event":"deny","orig_dst_ip":"not-an-ip","orig_dst_port":443,"protocol":"tcp","src_ip":"10.0.0.42","src_port":51234}"#;
        assert!(parse_nft_logger_line(bad_ip).is_err());

        // `rate_limited` missing `rate_limited_count`.
        let missing_count = r#"{"timestamp":"2026-04-22T09:45:05.000Z","layer":"deny-logger","event":"rate_limited","since_ts":"2026-04-22T09:45:04.000Z"}"#;
        assert!(parse_nft_logger_line(missing_count).is_err());

        // `rate_limited` missing `since_ts`.
        let missing_since = r#"{"timestamp":"2026-04-22T09:45:05.000Z","layer":"deny-logger","event":"rate_limited","rate_limited_count":42}"#;
        assert!(parse_nft_logger_line(missing_since).is_err());

        // Malformed timestamp.
        let bad_ts = r#"{"timestamp":"not a date","layer":"deny-logger","event":"deny","orig_dst_ip":"203.0.113.1","orig_dst_port":443,"protocol":"tcp","src_ip":"10.0.0.42","src_port":51234}"#;
        assert!(parse_nft_logger_line(bad_ts).is_err());
    }
}
