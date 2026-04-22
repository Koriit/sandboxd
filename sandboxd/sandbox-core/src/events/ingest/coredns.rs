//! CoreDNS policy-plugin JSONL line parser.
//!
//! Parses one JSON object (one line of `coredns.jsonl`) produced by the
//! CoreDNS `sandboxpolicy` plugin's [`EventWriter`] into a domain
//! [`crate::events::DnsEvent`] wrapped in a [`TrafficEvent::Dns`], plus
//! the `client_ip` used by the ingestor for session attribution.
//!
//! Source of truth for the on-disk shape: `networking/coredns-plugin/
//! events.go`. Every field name below (`timestamp`, `layer`, `event`,
//! `query`, `qtype`, `client_ip`, `resolved_ips`, `reason`) is authored
//! there.
//!
//! # Shape conventions
//!
//! - `layer` must equal `"dns"`.
//! - `event` must be `"query_allowed"` or `"query_denied"`.
//! - `query_allowed` always carries `resolved_ips: []` (never omitted,
//!   even when the upstream returned `NODATA`) — this is the contract
//!   documented in `events.go`'s `EmitQueryAllowed` doc comment.
//! - `query_denied` always carries `reason`.
//! - `client_ip` is always present; the ingestor rejects records where
//!   it is missing or not parseable as IPv4 (dropped with a warning
//!   rather than published to an unattributable session).
//! - `resolved_ips` entries are IPv4 (Envoy-fronted upstream resolver
//!   returns A records only; AAAA is stripped at the plugin layer).

use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::error::SandboxError;
use crate::events::{DnsEvent, TrafficEvent};

/// Raw CoreDNS event record, pre-domain.
#[derive(Debug, Deserialize)]
struct RawDnsRecord {
    timestamp: String,
    layer: String,
    event: String,
    query: String,
    qtype: String,
    client_ip: String,
    /// Present on `query_allowed`; absent on `query_denied`.
    #[serde(default)]
    resolved_ips: Option<Vec<String>>,
    /// Present on `query_denied`; absent on `query_allowed`.
    #[serde(default)]
    reason: Option<String>,
}

/// Parsed CoreDNS event, ready to stamp + publish.
///
/// `client_ip` is exposed directly because the ingestor uses it for the
/// `vm_ip_map.lookup` call that stamps `session_id`. `timestamp` lifts
/// to [`crate::events::EventEnvelope::timestamp`] so the envelope carries
/// the producer-side instant, not the ingestor's wall clock.
pub struct ParsedDnsEvent {
    pub timestamp: DateTime<Utc>,
    pub client_ip: Ipv4Addr,
    pub traffic: TrafficEvent,
}

fn parse_ipv4(field: &str, value: &str) -> Result<Ipv4Addr, SandboxError> {
    value.parse::<Ipv4Addr>().map_err(|e| {
        SandboxError::Internal(format!(
            "coredns record: failed to parse {field} as IPv4 from {value:?}: {e}"
        ))
    })
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, SandboxError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            SandboxError::Internal(format!(
                "coredns record: failed to parse `timestamp` from {value:?}: {e}"
            ))
        })
}

/// Parse one JSONL line emitted by the CoreDNS policy plugin.
pub fn parse_coredns_line(line: &str) -> Result<ParsedDnsEvent, SandboxError> {
    let raw: RawDnsRecord = serde_json::from_str(line).map_err(|e| {
        SandboxError::Internal(format!(
            "coredns record: failed to parse JSON: {e}; line = {line:?}"
        ))
    })?;

    if raw.layer != "dns" {
        return Err(SandboxError::Internal(format!(
            "coredns record: unexpected `layer` field {:?}, expected \"dns\"",
            raw.layer
        )));
    }

    let timestamp = parse_timestamp(&raw.timestamp)?;
    let client_ip = parse_ipv4("client_ip", &raw.client_ip)?;

    let dns_event = match raw.event.as_str() {
        "query_allowed" => {
            // `resolved_ips: []` is contractually always present on allow;
            // tolerate a missing field by defaulting to empty to keep a
            // hand-written fixture from breaking tests.
            let raw_ips = raw.resolved_ips.unwrap_or_default();
            let mut resolved_ips = Vec::with_capacity(raw_ips.len());
            for (i, s) in raw_ips.iter().enumerate() {
                resolved_ips.push(parse_ipv4(&format!("resolved_ips[{i}]"), s)?);
            }
            DnsEvent::QueryAllowed {
                query: raw.query,
                qtype: raw.qtype,
                resolved_ips,
            }
        }
        "query_denied" => {
            let reason = raw.reason.ok_or_else(|| {
                SandboxError::Internal(
                    "coredns record: `query_denied` missing `reason` field".into(),
                )
            })?;
            DnsEvent::QueryDenied {
                query: raw.query,
                qtype: raw.qtype,
                reason,
            }
        }
        other => {
            return Err(SandboxError::Internal(format!(
                "coredns record: unexpected `event` value {other:?}, expected `query_allowed` or `query_denied`"
            )));
        }
    };

    Ok(ParsedDnsEvent {
        timestamp,
        client_ip,
        traffic: TrafficEvent::Dns(dns_event),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query_allowed_with_resolved_ips() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"dns","event":"query_allowed","query":"api.example.com","qtype":"A","client_ip":"10.0.0.42","resolved_ips":["93.184.216.34","93.184.216.35"]}"#;
        let parsed = parse_coredns_line(line).unwrap();
        assert_eq!(parsed.client_ip, "10.0.0.42".parse::<Ipv4Addr>().unwrap());
        match parsed.traffic {
            TrafficEvent::Dns(DnsEvent::QueryAllowed {
                query,
                qtype,
                resolved_ips,
            }) => {
                assert_eq!(query, "api.example.com");
                assert_eq!(qtype, "A");
                assert_eq!(
                    resolved_ips,
                    vec![
                        "93.184.216.34".parse::<Ipv4Addr>().unwrap(),
                        "93.184.216.35".parse::<Ipv4Addr>().unwrap(),
                    ]
                );
            }
            other => panic!("expected QueryAllowed, got {other:?}"),
        }
    }

    #[test]
    fn parses_query_allowed_with_empty_resolved_ips() {
        // NODATA path from upstream — plugin emits `resolved_ips: []`.
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"dns","event":"query_allowed","query":"api.example.com","qtype":"A","client_ip":"10.0.0.42","resolved_ips":[]}"#;
        let parsed = parse_coredns_line(line).unwrap();
        match parsed.traffic {
            TrafficEvent::Dns(DnsEvent::QueryAllowed { resolved_ips, .. }) => {
                assert!(resolved_ips.is_empty());
            }
            other => panic!("expected QueryAllowed, got {other:?}"),
        }
    }

    #[test]
    fn parses_query_denied_with_reason() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"dns","event":"query_denied","query":"blocked.example.com","qtype":"AAAA","client_ip":"10.0.0.42","reason":"AAAA stripped"}"#;
        let parsed = parse_coredns_line(line).unwrap();
        assert_eq!(parsed.client_ip, "10.0.0.42".parse::<Ipv4Addr>().unwrap());
        match parsed.traffic {
            TrafficEvent::Dns(DnsEvent::QueryDenied {
                query,
                qtype,
                reason,
            }) => {
                assert_eq!(query, "blocked.example.com");
                assert_eq!(qtype, "AAAA");
                assert_eq!(reason, "AAAA stripped");
            }
            other => panic!("expected QueryDenied, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_layer() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"envoy","event":"query_allowed","query":"x","qtype":"A","client_ip":"10.0.0.42","resolved_ips":[]}"#;
        assert!(parse_coredns_line(line).is_err());
    }

    #[test]
    fn rejects_unknown_event_name() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"dns","event":"query_unknown","query":"x","qtype":"A","client_ip":"10.0.0.42"}"#;
        assert!(parse_coredns_line(line).is_err());
    }

    #[test]
    fn rejects_denied_without_reason() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"dns","event":"query_denied","query":"x","qtype":"A","client_ip":"10.0.0.42"}"#;
        assert!(parse_coredns_line(line).is_err());
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(parse_coredns_line("not json").is_err());
    }

    #[test]
    fn rejects_missing_client_ip() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"dns","event":"query_allowed","query":"x","qtype":"A","resolved_ips":[]}"#;
        assert!(parse_coredns_line(line).is_err());
    }

    #[test]
    fn rejects_non_ipv4_client_ip() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"dns","event":"query_allowed","query":"x","qtype":"A","client_ip":"not-an-ip","resolved_ips":[]}"#;
        assert!(parse_coredns_line(line).is_err());
    }

    #[test]
    fn rejects_non_ipv4_resolved_ip() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"dns","event":"query_allowed","query":"x","qtype":"A","client_ip":"10.0.0.42","resolved_ips":["not-an-ip"]}"#;
        assert!(parse_coredns_line(line).is_err());
    }

    #[test]
    fn timestamp_is_parsed_as_utc() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"dns","event":"query_allowed","query":"x","qtype":"A","client_ip":"10.0.0.42","resolved_ips":[]}"#;
        let parsed = parse_coredns_line(line).unwrap();
        let expected = chrono::DateTime::parse_from_rfc3339("2026-04-22T09:45:00.123Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(parsed.timestamp, expected);
    }

    #[test]
    fn malformed_timestamp_returns_err() {
        let line = r#"{"timestamp":"not a date","layer":"dns","event":"query_allowed","query":"x","qtype":"A","client_ip":"10.0.0.42","resolved_ips":[]}"#;
        assert!(parse_coredns_line(line).is_err());
    }

    #[test]
    fn tolerates_missing_resolved_ips_on_allow() {
        // Not written by the Go producer today, but a hand-authored test
        // fixture should still parse — we default to `[]`.
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"dns","event":"query_allowed","query":"x","qtype":"A","client_ip":"10.0.0.42"}"#;
        let parsed = parse_coredns_line(line).unwrap();
        match parsed.traffic {
            TrafficEvent::Dns(DnsEvent::QueryAllowed { resolved_ips, .. }) => {
                assert!(resolved_ips.is_empty());
            }
            other => panic!("expected QueryAllowed, got {other:?}"),
        }
    }
}
