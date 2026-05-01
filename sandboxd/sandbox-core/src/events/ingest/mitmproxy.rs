//! mitmproxy addon JSONL line parser.
//!
//! Parses one JSON object (one line of `mitmproxy.jsonl`) produced by
//! the mitmproxy `EventEmitter` into a domain
//! [`crate::events::MitmproxyEvent`] wrapped in a
//! [`TrafficEvent::Mitmproxy`], plus the `client_ip` used by the
//! ingestor for session attribution.
//!
//! Source of truth for the on-disk shape: `networking/mitmproxy/
//! events.py`. Every field name below (`timestamp`, `layer`, `event`,
//! `host`, `port`, `method`, `path`, `client_ip`, `reason`) is authored
//! there.
//!
//! # Shape conventions
//!
//! - `layer` must equal `"mitmproxy"`.
//! - `event` must be `"request_allowed"` or `"request_denied"`.
//! - `request_denied` always carries `reason`; `request_allowed` does
//!   not carry it.
//! - `client_ip` is **always present** but may be JSON `null` when the
//!   socket peer is unknown. A record with `client_ip: null` cannot be
//!   attributed to a session and is surfaced as a soft parse failure
//!   (the watcher logs and drops).
//! - `client_ip` as a non-null value is IPv4 (mitmproxy binds only to
//!   the container's v4 listener from Envoy's perspective).

use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::error::SandboxError;
use crate::events::{MitmproxyEvent, TrafficEvent};

/// Raw mitmproxy event record, pre-domain.
#[derive(Debug, Deserialize)]
struct RawMitmRecord {
    timestamp: String,
    layer: String,
    event: String,
    host: String,
    port: u16,
    method: String,
    path: String,
    /// Emitted as `null` when the socket peer is unknown; see module
    /// docs. Using `Option` captures both JSON `null` and the addon's
    /// "always present" contract (deserialization fails if the key is
    /// missing entirely, which is a malformed-producer case).
    client_ip: Option<String>,
    /// Present on `request_denied`; absent on `request_allowed`.
    #[serde(default)]
    reason: Option<String>,
}

/// Parsed mitmproxy event, ready to stamp + publish.
pub struct ParsedMitmEvent {
    pub timestamp: DateTime<Utc>,
    pub client_ip: Ipv4Addr,
    pub traffic: TrafficEvent,
}

fn parse_ipv4(field: &str, value: &str) -> Result<Ipv4Addr, SandboxError> {
    value.parse::<Ipv4Addr>().map_err(|e| {
        SandboxError::Internal(format!(
            "mitmproxy record: failed to parse {field} as IPv4 from {value:?}: {e}"
        ))
    })
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, SandboxError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            SandboxError::Internal(format!(
                "mitmproxy record: failed to parse `timestamp` from {value:?}: {e}"
            ))
        })
}

/// Parse one JSONL line emitted by the mitmproxy policy addon.
pub fn parse_mitmproxy_line(line: &str) -> Result<ParsedMitmEvent, SandboxError> {
    let raw: RawMitmRecord = serde_json::from_str(line).map_err(|e| {
        SandboxError::Internal(format!(
            "mitmproxy record: failed to parse JSON: {e}; line = {line:?}"
        ))
    })?;

    if raw.layer != "mitmproxy" {
        return Err(SandboxError::Internal(format!(
            "mitmproxy record: unexpected `layer` field {:?}, expected \"mitmproxy\"",
            raw.layer
        )));
    }

    let timestamp = parse_timestamp(&raw.timestamp)?;
    let client_ip_str = raw.client_ip.ok_or_else(|| {
        SandboxError::Internal(
            "mitmproxy record: `client_ip` is null; cannot attribute to a session".into(),
        )
    })?;
    let client_ip = parse_ipv4("client_ip", &client_ip_str)?;

    let mitm_event = match raw.event.as_str() {
        "request_allowed" => MitmproxyEvent::RequestAllowed {
            host: raw.host,
            port: raw.port,
            method: raw.method,
            path: raw.path,
        },
        "request_denied" => {
            let reason = raw.reason.ok_or_else(|| {
                SandboxError::Internal(
                    "mitmproxy record: `request_denied` missing `reason` field".into(),
                )
            })?;
            MitmproxyEvent::RequestDenied {
                host: raw.host,
                port: raw.port,
                method: raw.method,
                path: raw.path,
                reason,
            }
        }
        other => {
            return Err(SandboxError::Internal(format!(
                "mitmproxy record: unexpected `event` value {other:?}, expected `request_allowed` or `request_denied`"
            )));
        }
    };

    Ok(ParsedMitmEvent {
        timestamp,
        client_ip,
        traffic: TrafficEvent::Mitmproxy(mitm_event),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_allowed() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"mitmproxy","event":"request_allowed","host":"api.example.com","port":443,"method":"GET","path":"/v1/widgets","client_ip":"10.0.0.42"}"#;
        let parsed = parse_mitmproxy_line(line).unwrap();
        assert_eq!(parsed.client_ip, "10.0.0.42".parse::<Ipv4Addr>().unwrap());
        match parsed.traffic {
            TrafficEvent::Mitmproxy(MitmproxyEvent::RequestAllowed {
                host,
                port,
                method,
                path,
            }) => {
                assert_eq!(host, "api.example.com");
                assert_eq!(port, 443);
                assert_eq!(method, "GET");
                assert_eq!(path, "/v1/widgets");
            }
            other => panic!("expected RequestAllowed, got {other:?}"),
        }
    }

    #[test]
    fn parses_request_denied_with_reason() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"mitmproxy","event":"request_denied","host":"api.example.com","port":443,"method":"DELETE","path":"/admin","reason":"no_matching_filter","client_ip":"10.0.0.42"}"#;
        let parsed = parse_mitmproxy_line(line).unwrap();
        match parsed.traffic {
            TrafficEvent::Mitmproxy(MitmproxyEvent::RequestDenied {
                host,
                port,
                method,
                path,
                reason,
            }) => {
                assert_eq!(host, "api.example.com");
                assert_eq!(port, 443);
                assert_eq!(method, "DELETE");
                assert_eq!(path, "/admin");
                assert_eq!(reason, "no_matching_filter");
            }
            other => panic!("expected RequestDenied, got {other:?}"),
        }
    }

    #[test]
    fn null_client_ip_is_soft_err() {
        // The addon emits `client_ip: null` when the socket peer is
        // unknown. We cannot attribute it to a session, so the watcher
        // drops with a warning — parser surfaces `Err`.
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"mitmproxy","event":"request_allowed","host":"x","port":443,"method":"GET","path":"/","client_ip":null}"#;
        assert!(parse_mitmproxy_line(line).is_err());
    }

    #[test]
    fn rejects_wrong_layer() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"dns","event":"request_allowed","host":"x","port":443,"method":"GET","path":"/","client_ip":"10.0.0.42"}"#;
        assert!(parse_mitmproxy_line(line).is_err());
    }

    #[test]
    fn rejects_unknown_event_name() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"mitmproxy","event":"request_maybe","host":"x","port":443,"method":"GET","path":"/","client_ip":"10.0.0.42"}"#;
        assert!(parse_mitmproxy_line(line).is_err());
    }

    #[test]
    fn rejects_denied_without_reason() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"mitmproxy","event":"request_denied","host":"x","port":443,"method":"GET","path":"/","client_ip":"10.0.0.42"}"#;
        assert!(parse_mitmproxy_line(line).is_err());
    }

    #[test]
    fn rejects_missing_client_ip_key() {
        // The addon contractually always includes `client_ip`; a
        // missing key is treated as a malformed-producer case.
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"mitmproxy","event":"request_allowed","host":"x","port":443,"method":"GET","path":"/"}"#;
        assert!(parse_mitmproxy_line(line).is_err());
    }

    #[test]
    fn rejects_non_ipv4_client_ip() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"mitmproxy","event":"request_allowed","host":"x","port":443,"method":"GET","path":"/","client_ip":"not-an-ip"}"#;
        assert!(parse_mitmproxy_line(line).is_err());
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(parse_mitmproxy_line("not json").is_err());
    }

    #[test]
    fn timestamp_is_parsed_as_utc() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"mitmproxy","event":"request_allowed","host":"x","port":443,"method":"GET","path":"/","client_ip":"10.0.0.42"}"#;
        let parsed = parse_mitmproxy_line(line).unwrap();
        let expected = chrono::DateTime::parse_from_rfc3339("2026-04-22T09:45:00.123Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(parsed.timestamp, expected);
    }

    #[test]
    fn malformed_timestamp_returns_err() {
        let line = r#"{"timestamp":"not a date","layer":"mitmproxy","event":"request_allowed","host":"x","port":443,"method":"GET","path":"/","client_ip":"10.0.0.42"}"#;
        assert!(parse_mitmproxy_line(line).is_err());
    }

    #[test]
    fn port_out_of_u16_range_returns_err() {
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"mitmproxy","event":"request_allowed","host":"x","port":70000,"method":"GET","path":"/","client_ip":"10.0.0.42"}"#;
        assert!(parse_mitmproxy_line(line).is_err());
    }
}
