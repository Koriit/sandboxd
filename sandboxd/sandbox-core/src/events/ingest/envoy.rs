//! Envoy access-log line parser.
//!
//! Parses one JSON object (one line of `envoy.jsonl`) produced by the
//! `tcp_proxy` filter's `access_log` stanza into a
//! [`crate::events::EnvoyConnection`] plus the originating `src_ip`
//! (used for the `vm_ip_map` lookup that stamps `session_id`).
//!
//! # Source of truth
//!
//! The field map on the wire is authored in
//! `crate::policy::PolicyCompiler::l1_tcp_proxy_access_log_yaml`,
//! `l2_…`, and `l3_…`. L3 adds `connect_authority`; the rest of the
//! fields are identical across all three.
//!
//! # Numeric-as-string tolerance
//!
//! Envoy's `json_format` produces **string** values for every field when
//! the template value is quoted (`"%BYTES_SENT%"`) — our policy.rs
//! templates quote everything for readability. The parser therefore
//! accepts numeric fields as either strings (Envoy today) or numbers (in
//! case a future Envoy version, or a hand-written test fixture, emits
//! them bare). The serde-with technique is a small `deserialize_with`
//! helper per numeric field.
//!
//! # response_flags → decision
//!
//! Envoy's `%RESPONSE_FLAGS%` is an opaque short-code string documented
//! by Envoy's own access-log reference. The empty / dash form (`""` or
//! `"-"`) indicates no failure bit set ⇒ the connection was allowed.
//! Any other value is a failure code ⇒ the connection was denied. The
//! spec folds all non-empty flag values into a single
//! `connection_denied` variant rather than modeling each flag; the
//! `response_flags` field is carried through to the domain event so
//! downstream consumers can still filter / group on the specific code.
//!
//! Well-known flag values (for reference in the constants block below):
//!
//! | flag | meaning                                           |
//! |------|---------------------------------------------------|
//! | `NR` | no route configured for the request               |
//! | `UF` | upstream connection failure                       |
//! | `UC` | upstream connection termination                   |
//! | `LR` | connection local reset (downstream-initiated)     |
//! | `UH` | upstream host no healthy member                   |
//! | `UT` | upstream request timeout                          |
//! | `LH` | local service failed health check                 |
//! | `DC` | downstream connection termination                 |
//! | `UR` | upstream remote reset                             |
//!
//! This list is non-exhaustive — Envoy can emit additional codes (see
//! its access-log reference); the parser's allow/deny split does **not**
//! depend on the list above, only on the "empty / dash vs. anything
//! else" rule.

use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer};

use crate::error::SandboxError;
use crate::events::{EnvoyConnection, EnvoyEvent, TrafficEvent};

/// response_flags values that indicate "connection allowed".
///
/// Envoy emits the literal `"-"` when no flags are set, and the empty
/// string is also treated as allowed to tolerate future renderings.
const ALLOWED_RESPONSE_FLAGS: &[&str] = &["", "-"];

/// Raw Envoy access-log record, pre-domain.
///
/// All numeric fields are deserialized via helpers that accept both
/// string and number JSON values; see [`deserialize_u64_or_str`] /
/// [`deserialize_u16_or_str`] for the tolerance rationale.
#[derive(Debug, Deserialize)]
struct RawEnvoyRecord {
    timestamp: String,
    /// `layer` must equal `"envoy"` — defensive against a cross-layer
    /// mix-up; the parser rejects records where this field drifts.
    layer: String,
    /// `event` is informational only. Envoy only ever writes
    /// `"connection_allowed"` via the access-log format — the allow/deny
    /// split is derived from `response_flags`. We still read the field
    /// to surface a clearer parse error when the stream is confused
    /// with another producer's output.
    #[serde(default)]
    #[allow(dead_code)]
    event: String,
    src_ip: String,
    #[serde(deserialize_with = "deserialize_u16_or_str")]
    src_port: u16,
    dst_ip: String,
    #[serde(deserialize_with = "deserialize_u16_or_str")]
    dst_port: u16,
    matched_chain: String,
    cluster: String,
    #[serde(default)]
    upstream_host: Option<String>,
    #[serde(deserialize_with = "deserialize_u64_or_str")]
    bytes_sent: u64,
    #[serde(deserialize_with = "deserialize_u64_or_str")]
    bytes_received: u64,
    #[serde(default)]
    response_flags: String,
    #[serde(deserialize_with = "deserialize_u64_or_str")]
    duration_ms: u64,
    #[serde(default)]
    connect_authority: Option<String>,
}

/// Accept either a JSON string like `"1024"` or a JSON number `1024`.
fn deserialize_u64_or_str<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(deserializer)?;
    match v {
        serde_json::Value::Number(n) => n.as_u64().ok_or_else(|| {
            serde::de::Error::custom(format!("expected non-negative integer, got {n}"))
        }),
        serde_json::Value::String(s) => {
            // Envoy sometimes emits `"-"` for a numeric field when the
            // substitution has no value. Treat that as 0 rather than
            // failing the whole record — e.g. `bytes_received` on a
            // connection that never received anything before being reset.
            if s == "-" {
                return Ok(0);
            }
            s.parse::<u64>().map_err(|e| {
                serde::de::Error::custom(format!("failed to parse u64 from string {s:?}: {e}"))
            })
        }
        other => Err(serde::de::Error::custom(format!(
            "expected number or string for u64 field, got {other}"
        ))),
    }
}

fn deserialize_u16_or_str<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let v: u64 = deserialize_u64_or_str(deserializer)?;
    if v > u16::MAX as u64 {
        return Err(serde::de::Error::custom(format!(
            "port value {v} exceeds u16::MAX"
        )));
    }
    Ok(v as u16)
}

/// Parsed Envoy event, ready to stamp + publish.
///
/// `src_ip` is exposed directly because the ingestor uses it for the
/// `vm_ip_map.lookup` call that stamps `session_id`. `timestamp` is
/// parsed from the record's `timestamp` field (RFC 3339 + `Z`) and lifts
/// to [`crate::events::EventEnvelope::timestamp`] — using the producer's
/// timestamp (not the ingestor's wall clock) preserves the source-of-
/// truth instant across the tail → publish latency.
pub struct ParsedEnvoyEvent {
    pub timestamp: DateTime<Utc>,
    pub src_ip: Ipv4Addr,
    pub traffic: TrafficEvent,
}

/// Translate `"-"` empty-ish addresses into a clean error rather than
/// surfacing a confusing `AddrParseError` at the ingestor boundary.
fn parse_ipv4(field: &str, value: &str) -> Result<Ipv4Addr, SandboxError> {
    value.parse::<Ipv4Addr>().map_err(|e| {
        SandboxError::Internal(format!(
            "envoy record: failed to parse {field} as IPv4 from {value:?}: {e}"
        ))
    })
}

/// Parse the producer's RFC 3339 timestamp (millisecond precision, `Z`
/// suffix — the shape written by the policy.rs access-log template's
/// `%START_TIME(%Y-%m-%dT%H:%M:%S.%3fZ)%`).
fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, SandboxError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            SandboxError::Internal(format!(
                "envoy record: failed to parse `timestamp` from {value:?}: {e}"
            ))
        })
}

/// Parse one JSONL line emitted by Envoy's `json_format` access log.
///
/// Returns the [`TrafficEvent::Envoy`] plus the source IPv4 for session
/// attribution. Returns `Err` for malformed JSON, missing required
/// fields, or IP values that don't parse; the caller logs + drops.
pub fn parse_envoy_line(line: &str) -> Result<ParsedEnvoyEvent, SandboxError> {
    let raw: RawEnvoyRecord = serde_json::from_str(line).map_err(|e| {
        SandboxError::Internal(format!(
            "envoy record: failed to parse JSON: {e}; line = {line:?}"
        ))
    })?;

    if raw.layer != "envoy" {
        return Err(SandboxError::Internal(format!(
            "envoy record: unexpected `layer` field {:?}, expected \"envoy\"",
            raw.layer
        )));
    }

    let timestamp = parse_timestamp(&raw.timestamp)?;
    let src_ip = parse_ipv4("src_ip", &raw.src_ip)?;
    let dst_ip = parse_ipv4("dst_ip", &raw.dst_ip)?;

    let connection = EnvoyConnection {
        src_ip,
        src_port: raw.src_port,
        dst_ip,
        dst_port: raw.dst_port,
        matched_chain: raw.matched_chain,
        cluster: raw.cluster,
        upstream_host: raw.upstream_host.and_then(|s| {
            // Envoy writes `"-"` when the substitution has no value; do
            // not surface that as if it were a real upstream host.
            if s == "-" || s.is_empty() {
                None
            } else {
                Some(s)
            }
        }),
        bytes_sent: raw.bytes_sent,
        bytes_received: raw.bytes_received,
        response_flags: raw.response_flags.clone(),
        duration_ms: raw.duration_ms,
        connect_authority: raw.connect_authority.and_then(|s| {
            if s == "-" || s.is_empty() {
                None
            } else {
                Some(s)
            }
        }),
    };

    let event = if ALLOWED_RESPONSE_FLAGS.contains(&raw.response_flags.as_str()) {
        EnvoyEvent::ConnectionAllowed(connection)
    } else {
        EnvoyEvent::ConnectionDenied(connection)
    };

    Ok(ParsedEnvoyEvent {
        timestamp,
        src_ip,
        traffic: TrafficEvent::Envoy(event),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid record template; callers tweak fields as needed.
    fn record(response_flags: &str) -> String {
        format!(
            r#"{{"timestamp":"2026-04-22T09:45:00.123Z","layer":"envoy","event":"connection_allowed","src_ip":"10.0.0.42","src_port":"54321","dst_ip":"93.184.216.34","dst_port":"443","matched_chain":"chain_l3_example","cluster":"mitmproxy","upstream_host":"127.0.0.1:18080","bytes_sent":"1024","bytes_received":"4096","response_flags":"{response_flags}","duration_ms":"42","connect_authority":"example.com:443"}}"#
        )
    }

    /// Table-driven translation of response_flags → allow/deny.
    #[test]
    fn response_flags_translation_table() {
        struct Case<'a> {
            flags: &'a str,
            expect_allow: bool,
        }
        let cases = [
            // Allow cases.
            Case {
                flags: "",
                expect_allow: true,
            },
            Case {
                flags: "-",
                expect_allow: true,
            },
            // Deny cases — well-known Envoy short codes.
            Case {
                flags: "NR",
                expect_allow: false,
            },
            Case {
                flags: "UF",
                expect_allow: false,
            },
            Case {
                flags: "UC",
                expect_allow: false,
            },
            Case {
                flags: "LR",
                expect_allow: false,
            },
            Case {
                flags: "UH",
                expect_allow: false,
            },
            Case {
                flags: "UT",
                expect_allow: false,
            },
            Case {
                flags: "DC",
                expect_allow: false,
            },
            // Composite flag — Envoy can chain codes; still a deny.
            Case {
                flags: "UF,URX",
                expect_allow: false,
            },
            // Future code we don't enumerate above — non-empty ⇒ deny.
            Case {
                flags: "XX",
                expect_allow: false,
            },
        ];
        for c in cases {
            let parsed = parse_envoy_line(&record(c.flags))
                .unwrap_or_else(|e| panic!("flags {:?} failed to parse: {e}", c.flags));
            let is_allow = matches!(
                parsed.traffic,
                TrafficEvent::Envoy(EnvoyEvent::ConnectionAllowed(_))
            );
            assert_eq!(
                is_allow, c.expect_allow,
                "flags {:?}: expected allow={}, got allow={}",
                c.flags, c.expect_allow, is_allow
            );
        }
    }

    #[test]
    fn src_ip_surfaces_for_vm_ip_lookup() {
        let parsed = parse_envoy_line(&record("-")).unwrap();
        assert_eq!(parsed.src_ip, "10.0.0.42".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn accepts_numeric_fields_as_bare_numbers() {
        // Hand-authored record using numbers instead of quoted strings,
        // covering the tolerance path for future Envoy versions / test
        // fixtures that don't quote numeric fields.
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"envoy","event":"connection_allowed","src_ip":"10.0.0.42","src_port":54321,"dst_ip":"93.184.216.34","dst_port":443,"matched_chain":"chain_l3_example","cluster":"mitmproxy","upstream_host":"127.0.0.1:18080","bytes_sent":1024,"bytes_received":4096,"response_flags":"-","duration_ms":42,"connect_authority":"example.com:443"}"#;
        let parsed = parse_envoy_line(line).unwrap();
        match parsed.traffic {
            TrafficEvent::Envoy(EnvoyEvent::ConnectionAllowed(c)) => {
                assert_eq!(c.src_port, 54321);
                assert_eq!(c.dst_port, 443);
                assert_eq!(c.bytes_sent, 1024);
                assert_eq!(c.duration_ms, 42);
            }
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn numeric_field_with_dash_becomes_zero() {
        // Envoy emits `-` for substitutions that have no value (e.g.
        // bytes_received on a reset connection).
        let line = record("NR").replace("\"bytes_received\":\"4096\"", "\"bytes_received\":\"-\"");
        let parsed = parse_envoy_line(&line).unwrap();
        match parsed.traffic {
            TrafficEvent::Envoy(EnvoyEvent::ConnectionDenied(c)) => {
                assert_eq!(c.bytes_received, 0);
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn upstream_host_dash_is_none() {
        let line = record("-").replace(
            "\"upstream_host\":\"127.0.0.1:18080\"",
            "\"upstream_host\":\"-\"",
        );
        let parsed = parse_envoy_line(&line).unwrap();
        match parsed.traffic {
            TrafficEvent::Envoy(EnvoyEvent::ConnectionAllowed(c)) => {
                assert_eq!(c.upstream_host, None);
            }
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn connect_authority_dash_is_none() {
        let line = record("-").replace(
            "\"connect_authority\":\"example.com:443\"",
            "\"connect_authority\":\"-\"",
        );
        let parsed = parse_envoy_line(&line).unwrap();
        match parsed.traffic {
            TrafficEvent::Envoy(EnvoyEvent::ConnectionAllowed(c)) => {
                assert_eq!(c.connect_authority, None);
            }
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn missing_connect_authority_is_none() {
        // L1/L2 records do not carry connect_authority at all.
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"envoy","event":"connection_allowed","src_ip":"10.0.0.42","src_port":"54321","dst_ip":"93.184.216.34","dst_port":"443","matched_chain":"chain_l1_example","cluster":"direct_internet","upstream_host":"93.184.216.34:443","bytes_sent":"1024","bytes_received":"4096","response_flags":"-","duration_ms":"42"}"#;
        let parsed = parse_envoy_line(line).unwrap();
        match parsed.traffic {
            TrafficEvent::Envoy(EnvoyEvent::ConnectionAllowed(c)) => {
                assert_eq!(c.connect_authority, None);
            }
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn malformed_json_returns_err() {
        let r = parse_envoy_line("not json");
        assert!(r.is_err(), "malformed JSON must surface as Err");
    }

    #[test]
    fn missing_required_field_returns_err() {
        // No `src_ip`.
        let line = r#"{"timestamp":"2026-04-22T09:45:00.123Z","layer":"envoy","event":"connection_allowed","src_port":"54321","dst_ip":"93.184.216.34","dst_port":"443","matched_chain":"x","cluster":"y","bytes_sent":"0","bytes_received":"0","response_flags":"-","duration_ms":"0"}"#;
        assert!(parse_envoy_line(line).is_err());
    }

    #[test]
    fn wrong_layer_tag_returns_err() {
        let line = record("-").replace("\"layer\":\"envoy\"", "\"layer\":\"dns\"");
        assert!(parse_envoy_line(&line).is_err());
    }

    #[test]
    fn bad_src_ip_returns_err() {
        let line = record("-").replace("\"src_ip\":\"10.0.0.42\"", "\"src_ip\":\"not-an-ip\"");
        assert!(parse_envoy_line(&line).is_err());
    }

    #[test]
    fn port_out_of_range_returns_err() {
        let line = record("-").replace("\"src_port\":\"54321\"", "\"src_port\":\"70000\"");
        assert!(parse_envoy_line(&line).is_err());
    }

    #[test]
    fn timestamp_is_parsed_as_utc() {
        let parsed = parse_envoy_line(&record("-")).unwrap();
        // `2026-04-22T09:45:00.123Z` in epoch-millis.
        let expected = chrono::DateTime::parse_from_rfc3339("2026-04-22T09:45:00.123Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(parsed.timestamp, expected);
    }

    #[test]
    fn malformed_timestamp_returns_err() {
        let line = record("-").replace(
            "\"timestamp\":\"2026-04-22T09:45:00.123Z\"",
            "\"timestamp\":\"not a date\"",
        );
        assert!(parse_envoy_line(&line).is_err());
    }
}
