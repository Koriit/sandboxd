//! Domain → DTO conversions for events.
//!
//! This module is the **only** place where [`crate::events::Event`] and
//! its nested variants are translated into the wire types in
//! [`super::event_dto`]. Same ownership principle as [`super::mapper`]:
//! adding a domain field is inert on the wire until the corresponding
//! mapper branch is updated.
//!
//! Notable translation rules:
//!
//! - `timestamp: DateTime<Utc>` → RFC 3339 string with millisecond
//!   precision and `Z` suffix (`YYYY-MM-DDTHH:MM:SS.mmmZ`). Sub-millisecond
//!   chrono precision is truncated.
//! - `session: Option<SessionId>` → `String`; [`None`] renders as `""`
//!   (pre-session lifecycle events).
//! - IP addresses → `std::net::Ipv4Addr::to_string()`.
//! - Domain [`crate::policy::Policy`] → [`super::dto::PolicyDto`] via the
//!   existing `From<&Policy>` impl, so the `policy` payload on
//!   lifecycle events matches the shape returned by
//!   `GET /sessions/{id}`.

use chrono::{DateTime, SecondsFormat, Utc};

use crate::events::{
    DenyLoggerAllow, DenyLoggerDeny, DenyLoggerEvent, DenyProtocol, DnsEvent, EnvoyConnection,
    EnvoyEvent, Event, EventEnvelope, GatewayShutdownReason, HealthComponent, LifecycleEvent,
    MitmproxyEvent, PolicyApplyStatus, TrafficEvent,
};
use crate::session::SessionId;

use super::dto::PolicyDto;
use super::event_dto::{
    DenyLoggerEventBodyDto, DenyLoggerEventDto, DenyProtocolDto, DnsEventBodyDto, DnsEventDto,
    EnvoyConnectionDto, EnvoyEventBodyDto, EnvoyEventDto, EventDto, GatewayShutdownReasonDto,
    HealthComponentDto, LifecycleEventBodyDto, LifecycleEventDto, MitmproxyEventBodyDto,
    MitmproxyEventDto, PolicyApplyStatusDto,
};

// ---------------------------------------------------------------------------
// Envelope helpers
// ---------------------------------------------------------------------------

/// Render a timestamp as RFC 3339 with millisecond precision and a `Z`
/// suffix.
///
/// Matches the spec's example `"2026-04-21T12:34:56.789Z"` exactly.
fn render_timestamp(ts: &DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Render the envelope's `session` field.
///
/// [`None`] → `""` per spec; [`Some`] → the 12-hex-char session id.
fn render_session(session: &Option<SessionId>) -> String {
    session
        .as_ref()
        .map(|s| s.as_str().to_string())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Top-level event
// ---------------------------------------------------------------------------

impl From<&Event> for EventDto {
    fn from(event: &Event) -> Self {
        match event {
            Event::Traffic { envelope, event } => match event {
                TrafficEvent::Dns(e) => EventDto::Dns(dns_event_dto(envelope, e)),
                TrafficEvent::Envoy(e) => EventDto::Envoy(envoy_event_dto(envelope, e)),
                TrafficEvent::Mitmproxy(e) => EventDto::Mitmproxy(mitmproxy_event_dto(envelope, e)),
                TrafficEvent::DenyLogger(e) => {
                    EventDto::DenyLogger(deny_logger_event_dto(envelope, e))
                }
            },
            Event::Lifecycle { envelope, event } => {
                EventDto::Lifecycle(lifecycle_event_dto(envelope, event))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

fn dns_event_dto(envelope: &EventEnvelope, event: &DnsEvent) -> DnsEventDto {
    DnsEventDto {
        timestamp: render_timestamp(&envelope.timestamp),
        session: render_session(&envelope.session),
        body: dns_body_dto(event),
    }
}

fn dns_body_dto(event: &DnsEvent) -> DnsEventBodyDto {
    match event {
        DnsEvent::QueryAllowed {
            query,
            qtype,
            resolved_ips,
        } => DnsEventBodyDto::QueryAllowed {
            query: query.clone(),
            qtype: qtype.clone(),
            resolved_ips: resolved_ips.iter().map(|ip| ip.to_string()).collect(),
        },
        DnsEvent::QueryDenied {
            query,
            qtype,
            reason,
        } => DnsEventBodyDto::QueryDenied {
            query: query.clone(),
            qtype: qtype.clone(),
            reason: reason.clone(),
        },
    }
}

// ---------------------------------------------------------------------------
// Envoy
// ---------------------------------------------------------------------------

fn envoy_event_dto(envelope: &EventEnvelope, event: &EnvoyEvent) -> EnvoyEventDto {
    EnvoyEventDto {
        timestamp: render_timestamp(&envelope.timestamp),
        session: render_session(&envelope.session),
        body: envoy_body_dto(event),
    }
}

fn envoy_body_dto(event: &EnvoyEvent) -> EnvoyEventBodyDto {
    match event {
        EnvoyEvent::ConnectionAllowed(c) => EnvoyEventBodyDto::ConnectionAllowed(conn_dto(c)),
        EnvoyEvent::ConnectionDenied(c) => EnvoyEventBodyDto::ConnectionDenied(conn_dto(c)),
    }
}

fn conn_dto(c: &EnvoyConnection) -> EnvoyConnectionDto {
    EnvoyConnectionDto {
        src_ip: c.src_ip.to_string(),
        src_port: c.src_port,
        dst_ip: c.dst_ip.to_string(),
        dst_port: c.dst_port,
        matched_chain: c.matched_chain.clone(),
        cluster: c.cluster.clone(),
        upstream_host: c.upstream_host.clone(),
        bytes_sent: c.bytes_sent,
        bytes_received: c.bytes_received,
        response_flags: c.response_flags.clone(),
        duration_ms: c.duration_ms,
        connect_authority: c.connect_authority.clone(),
    }
}

// ---------------------------------------------------------------------------
// mitmproxy
// ---------------------------------------------------------------------------

fn mitmproxy_event_dto(envelope: &EventEnvelope, event: &MitmproxyEvent) -> MitmproxyEventDto {
    MitmproxyEventDto {
        timestamp: render_timestamp(&envelope.timestamp),
        session: render_session(&envelope.session),
        body: mitmproxy_body_dto(event),
    }
}

fn mitmproxy_body_dto(event: &MitmproxyEvent) -> MitmproxyEventBodyDto {
    match event {
        MitmproxyEvent::RequestAllowed {
            host,
            port,
            method,
            path,
        } => MitmproxyEventBodyDto::RequestAllowed {
            host: host.clone(),
            port: *port,
            method: method.clone(),
            path: path.clone(),
        },
        MitmproxyEvent::RequestDenied {
            host,
            port,
            method,
            path,
            reason,
        } => MitmproxyEventBodyDto::RequestDenied {
            host: host.clone(),
            port: *port,
            method: method.clone(),
            path: path.clone(),
            reason: reason.clone(),
        },
    }
}

// ---------------------------------------------------------------------------
// Deny-logger
// ---------------------------------------------------------------------------

fn deny_logger_event_dto(envelope: &EventEnvelope, event: &DenyLoggerEvent) -> DenyLoggerEventDto {
    DenyLoggerEventDto {
        timestamp: render_timestamp(&envelope.timestamp),
        session: render_session(&envelope.session),
        body: deny_logger_body_dto(event),
    }
}

fn deny_logger_body_dto(event: &DenyLoggerEvent) -> DenyLoggerEventBodyDto {
    match event {
        DenyLoggerEvent::Deny(d) => deny_body_dto(d),
        DenyLoggerEvent::Allow(a) => allow_body_dto(a),
        DenyLoggerEvent::RateLimited {
            rate_limited_count,
            since_ts,
        } => DenyLoggerEventBodyDto::RateLimited {
            rate_limited_count: *rate_limited_count,
            since_ts: render_timestamp(since_ts),
        },
    }
}

fn deny_body_dto(d: &DenyLoggerDeny) -> DenyLoggerEventBodyDto {
    DenyLoggerEventBodyDto::Deny {
        orig_dst_ip: d.orig_dst_ip.to_string(),
        orig_dst_port: d.orig_dst_port,
        protocol: d.protocol.into(),
        src_ip: d.src_ip.to_string(),
        src_port: d.src_port,
    }
}

fn allow_body_dto(a: &DenyLoggerAllow) -> DenyLoggerEventBodyDto {
    DenyLoggerEventBodyDto::Allow {
        orig_dst_ip: a.orig_dst_ip.to_string(),
        orig_dst_port: a.orig_dst_port,
        protocol: a.protocol.into(),
        src_ip: a.src_ip.to_string(),
        src_port: a.src_port,
    }
}

impl From<DenyProtocol> for DenyProtocolDto {
    fn from(p: DenyProtocol) -> Self {
        match p {
            DenyProtocol::Tcp => DenyProtocolDto::Tcp,
            DenyProtocol::Udp => DenyProtocolDto::Udp,
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

fn lifecycle_event_dto(envelope: &EventEnvelope, event: &LifecycleEvent) -> LifecycleEventDto {
    LifecycleEventDto {
        timestamp: render_timestamp(&envelope.timestamp),
        session: render_session(&envelope.session),
        body: lifecycle_body_dto(event),
    }
}

fn lifecycle_body_dto(event: &LifecycleEvent) -> LifecycleEventBodyDto {
    match event {
        LifecycleEvent::GatewayBooting => LifecycleEventBodyDto::GatewayBooting,
        LifecycleEvent::GatewayReady => LifecycleEventBodyDto::GatewayReady,
        LifecycleEvent::PolicyApplied {
            policy,
            source_presets,
            status,
            error,
        } => LifecycleEventBodyDto::PolicyApplied {
            policy: PolicyDto::from(policy),
            source_presets: source_presets.clone(),
            status: (*status).into(),
            error: error.clone(),
        },
        LifecycleEvent::PolicyUpdated {
            policy,
            source_presets,
            status,
            error,
            previous_policy_hash,
        } => LifecycleEventBodyDto::PolicyUpdated {
            policy: PolicyDto::from(policy),
            source_presets: source_presets.clone(),
            status: (*status).into(),
            error: error.clone(),
            previous_policy_hash: previous_policy_hash.clone(),
        },
        LifecycleEvent::PolicyResetOnUpgrade {
            previous_rule_count,
        } => LifecycleEventBodyDto::PolicyResetOnUpgrade {
            previous_rule_count: *previous_rule_count as u64,
        },
        LifecycleEvent::PolicyPropagated { policy_hash } => {
            LifecycleEventBodyDto::PolicyPropagated {
                policy_hash: policy_hash.clone(),
            }
        }
        LifecycleEvent::HealthDegraded { component, reason } => {
            LifecycleEventBodyDto::HealthDegraded {
                component: (*component).into(),
                reason: reason.clone(),
            }
        }
        LifecycleEvent::HealthRestored { component } => LifecycleEventBodyDto::HealthRestored {
            component: (*component).into(),
        },
        LifecycleEvent::GatewayShutdown { reason, error } => {
            LifecycleEventBodyDto::GatewayShutdown {
                reason: (*reason).into(),
                error: error.clone(),
            }
        }
    }
}

impl From<PolicyApplyStatus> for PolicyApplyStatusDto {
    fn from(status: PolicyApplyStatus) -> Self {
        match status {
            PolicyApplyStatus::Ok => PolicyApplyStatusDto::Ok,
            PolicyApplyStatus::Error => PolicyApplyStatusDto::Error,
        }
    }
}

impl From<HealthComponent> for HealthComponentDto {
    fn from(component: HealthComponent) -> Self {
        match component {
            HealthComponent::DenyLogger => HealthComponentDto::DenyLogger,
            HealthComponent::Envoy => HealthComponentDto::Envoy,
            HealthComponent::Mitmproxy => HealthComponentDto::Mitmproxy,
            HealthComponent::Coredns => HealthComponentDto::Coredns,
        }
    }
}

impl From<GatewayShutdownReason> for GatewayShutdownReasonDto {
    fn from(reason: GatewayShutdownReason) -> Self {
        match reason {
            GatewayShutdownReason::SessionStopped => GatewayShutdownReasonDto::SessionStopped,
            GatewayShutdownReason::DaemonShutdown => GatewayShutdownReasonDto::DaemonShutdown,
            GatewayShutdownReason::Error => GatewayShutdownReasonDto::Error,
        }
    }
}

// ---------------------------------------------------------------------------
// Domain → JSONL line helper
// ---------------------------------------------------------------------------

/// Render a domain [`Event`] as a single JSONL line, terminated by `\n`.
///
/// Used by the `GET /sessions/{id}/events` HTTP handler and the
/// persistent sink to produce wire bytes from domain events. The
/// returned string contains exactly one JSON object followed by a
/// trailing newline so callers can concatenate results into a valid
/// JSONL stream without additional framing.
///
/// Returns the underlying [`serde_json::Error`] on the vanishingly
/// rare serialization failure (only reachable if a DTO's serde impl
/// itself panics — every [`EventDto`] variant serializes deterministic
/// primitives, so in practice this path is unreachable in well-formed
/// code, but we propagate the error anyway rather than panicking in a
/// hot-path helper).
pub fn event_to_jsonl_line(event: &Event) -> Result<String, serde_json::Error> {
    let dto = EventDto::from(event);
    let mut line = serde_json::to_string(&dto)?;
    line.push('\n');
    Ok(line)
}

// ---------------------------------------------------------------------------
// DTO wire-shape assertions
// ---------------------------------------------------------------------------
//
// These tests pin the on-wire contract documented in spec Part 3 "Event
// shape" / "Event categories". A failing assertion here is a signal that
// some downstream consumer (CLI filter flag, HTTP endpoint, E2E test) will
// need coordinated updates — do not adjust these tests without
// corresponding spec edits.

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    use chrono::TimeZone;
    use serde_json::Value;

    use crate::events::{
        DenyLoggerAllow, DenyLoggerDeny, DenyLoggerEvent, DenyProtocol, DnsEvent, EnvoyConnection,
        EnvoyEvent, Event, EventEnvelope, GatewayShutdownReason, HealthComponent, LifecycleEvent,
        MitmproxyEvent, PolicyApplyStatus, TrafficEvent,
    };
    use crate::policy::{
        AssuranceLevel, Destination, HttpFilter, HttpMethod, Policy, PolicyRule, Protocol,
    };

    fn policy() -> Policy {
        Policy {
            version: "2.0.0".into(),
            rules: vec![PolicyRule {
                host: Destination::Domain("api.example.com".into()),
                port: 443,
                protocol: Protocol::Tcp,
                reason: None,
                level: AssuranceLevel::Http {
                    http_filters: vec![HttpFilter {
                        method: HttpMethod::Get,
                        path: "/v1/**".into(),
                    }],
                },
            }],
        }
    }

    fn sid() -> SessionId {
        SessionId::parse("0123456789ab").unwrap()
    }

    fn envoy_fixture() -> EnvoyEvent {
        EnvoyEvent::ConnectionAllowed(EnvoyConnection {
            src_ip: Ipv4Addr::new(10, 0, 0, 42),
            src_port: 54321,
            dst_ip: Ipv4Addr::new(93, 184, 216, 34),
            dst_port: 443,
            matched_chain: "chain_l3_example".into(),
            cluster: "upstream_example_443".into(),
            upstream_host: Some("93.184.216.34:443".into()),
            bytes_sent: 1024,
            bytes_received: 4096,
            response_flags: "-".into(),
            duration_ms: 42,
            connect_authority: Some("example.com:443".into()),
        })
    }

    fn to_json(event: Event) -> Value {
        let dto = EventDto::from(&event);
        serde_json::to_value(&dto).expect("serialize")
    }

    #[test]
    fn dto_timestamp_is_rfc3339_ms() {
        // `2026-04-22T09:45:00.123456789Z` — chrono carries nanosecond
        // precision; the wire format must truncate to milliseconds and
        // suffix with `Z`.
        let ts = Utc.with_ymd_and_hms(2026, 4, 22, 9, 45, 0).unwrap()
            + chrono::Duration::nanoseconds(123_456_789);
        let event = Event::Traffic {
            envelope: EventEnvelope {
                timestamp: ts,
                session: Some(sid()),
            },
            event: TrafficEvent::Envoy(envoy_fixture()),
        };
        let json = to_json(event);
        let wire = json["timestamp"].as_str().expect("timestamp is a string");
        assert_eq!(
            wire, "2026-04-22T09:45:00.123Z",
            "timestamp must be RFC 3339 with exactly 3 fractional digits and a `Z` suffix"
        );
    }

    #[test]
    fn dto_session_is_empty_string_when_prelifecycle() {
        // `gateway_booting` precedes session attribution (spec Part 3,
        // "Event shape"). The envelope's `session` is None; the wire
        // renders it as `""`.
        let event = Event::Lifecycle {
            envelope: EventEnvelope {
                timestamp: Utc.with_ymd_and_hms(2026, 4, 22, 9, 45, 0).unwrap(),
                session: None,
            },
            event: LifecycleEvent::GatewayBooting,
        };
        let json = to_json(event);
        assert_eq!(
            json["session"], "",
            "pre-session lifecycle events must serialize session as \"\""
        );
        // Sanity-check the spec-mandated `layer` value is still there.
        assert_eq!(json["layer"], "lifecycle");
    }

    #[test]
    fn dto_layer_field_matches_spec() {
        // Exhaustive check: every variant's serialized `layer` must be one
        // of the spec's five values — `dns`, `envoy`, `mitmproxy`,
        // `deny-logger`, `lifecycle`. No `sandboxd`, no `audit`, no
        // surprises. Note the kebab-case on `deny-logger` (the only
        // multi-word layer name).
        let envelope = EventEnvelope {
            timestamp: Utc.with_ymd_and_hms(2026, 4, 22, 9, 45, 0).unwrap(),
            session: Some(sid()),
        };

        let cases: Vec<(Event, &str)> = vec![
            (
                Event::Traffic {
                    envelope: envelope.clone(),
                    event: TrafficEvent::Dns(DnsEvent::QueryAllowed {
                        query: "a.test".into(),
                        qtype: "A".into(),
                        resolved_ips: vec![Ipv4Addr::new(1, 2, 3, 4)],
                    }),
                },
                "dns",
            ),
            (
                Event::Traffic {
                    envelope: envelope.clone(),
                    event: TrafficEvent::Envoy(envoy_fixture()),
                },
                "envoy",
            ),
            (
                Event::Traffic {
                    envelope: envelope.clone(),
                    event: TrafficEvent::Mitmproxy(MitmproxyEvent::RequestAllowed {
                        host: "a.test".into(),
                        port: 443,
                        method: "GET".into(),
                        path: "/".into(),
                    }),
                },
                "mitmproxy",
            ),
            (
                Event::Traffic {
                    envelope: envelope.clone(),
                    event: TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(DenyLoggerDeny {
                        orig_dst_ip: Ipv4Addr::new(203, 0, 113, 1),
                        orig_dst_port: 443,
                        protocol: DenyProtocol::Tcp,
                        src_ip: Ipv4Addr::new(10, 0, 0, 42),
                        src_port: 55123,
                    })),
                },
                "deny-logger",
            ),
            (
                Event::Lifecycle {
                    envelope: envelope.clone(),
                    event: LifecycleEvent::GatewayReady,
                },
                "lifecycle",
            ),
        ];

        for (event, expected_layer) in cases {
            let json = to_json(event);
            assert_eq!(
                json["layer"], expected_layer,
                "layer mismatch for case expected={expected_layer}; json = {json}"
            );
        }
    }

    #[test]
    fn dto_event_field_matches_spec_per_variant() {
        // Full enumeration of every event string the spec prescribes in
        // Part 3 "Event categories". Each row asserts the variant
        // serializes its `event` discriminator character-for-character to
        // the spec value.
        let envelope = EventEnvelope {
            timestamp: Utc.with_ymd_and_hms(2026, 4, 22, 9, 45, 0).unwrap(),
            session: Some(sid()),
        };
        let pre_session_envelope = EventEnvelope {
            timestamp: envelope.timestamp,
            session: None,
        };

        let conn = EnvoyConnection {
            src_ip: Ipv4Addr::new(10, 0, 0, 42),
            src_port: 54321,
            dst_ip: Ipv4Addr::new(93, 184, 216, 34),
            dst_port: 443,
            matched_chain: "chain".into(),
            cluster: "cluster".into(),
            upstream_host: None,
            bytes_sent: 0,
            bytes_received: 0,
            response_flags: "-".into(),
            duration_ms: 0,
            connect_authority: None,
        };

        let cases: Vec<(Event, &str)> = vec![
            // Traffic.
            (
                Event::Traffic {
                    envelope: envelope.clone(),
                    event: TrafficEvent::Dns(DnsEvent::QueryAllowed {
                        query: "a.test".into(),
                        qtype: "A".into(),
                        resolved_ips: vec![],
                    }),
                },
                "query_allowed",
            ),
            (
                Event::Traffic {
                    envelope: envelope.clone(),
                    event: TrafficEvent::Dns(DnsEvent::QueryDenied {
                        query: "a.test".into(),
                        qtype: "A".into(),
                        reason: "r".into(),
                    }),
                },
                "query_denied",
            ),
            (
                Event::Traffic {
                    envelope: envelope.clone(),
                    event: TrafficEvent::Envoy(EnvoyEvent::ConnectionAllowed(conn.clone())),
                },
                "connection_allowed",
            ),
            (
                Event::Traffic {
                    envelope: envelope.clone(),
                    event: TrafficEvent::Envoy(EnvoyEvent::ConnectionDenied(conn.clone())),
                },
                "connection_denied",
            ),
            (
                Event::Traffic {
                    envelope: envelope.clone(),
                    event: TrafficEvent::Mitmproxy(MitmproxyEvent::RequestAllowed {
                        host: "a.test".into(),
                        port: 443,
                        method: "GET".into(),
                        path: "/".into(),
                    }),
                },
                "request_allowed",
            ),
            (
                Event::Traffic {
                    envelope: envelope.clone(),
                    event: TrafficEvent::Mitmproxy(MitmproxyEvent::RequestDenied {
                        host: "a.test".into(),
                        port: 443,
                        method: "GET".into(),
                        path: "/".into(),
                        reason: "r".into(),
                    }),
                },
                "request_denied",
            ),
            (
                Event::Traffic {
                    envelope: envelope.clone(),
                    event: TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(DenyLoggerDeny {
                        orig_dst_ip: Ipv4Addr::new(203, 0, 113, 1),
                        orig_dst_port: 443,
                        protocol: DenyProtocol::Tcp,
                        src_ip: Ipv4Addr::new(10, 0, 0, 42),
                        src_port: 55123,
                    })),
                },
                "deny",
            ),
            (
                Event::Traffic {
                    envelope: envelope.clone(),
                    event: TrafficEvent::DenyLogger(DenyLoggerEvent::Allow(DenyLoggerAllow {
                        orig_dst_ip: Ipv4Addr::new(198, 51, 100, 7),
                        orig_dst_port: 123,
                        protocol: DenyProtocol::Udp,
                        src_ip: Ipv4Addr::new(10, 0, 0, 42),
                        src_port: 51234,
                    })),
                },
                "allow",
            ),
            (
                Event::Traffic {
                    envelope: envelope.clone(),
                    event: TrafficEvent::DenyLogger(DenyLoggerEvent::RateLimited {
                        rate_limited_count: 7,
                        since_ts: envelope.timestamp,
                    }),
                },
                "rate_limited",
            ),
            // Lifecycle.
            (
                Event::Lifecycle {
                    envelope: pre_session_envelope.clone(),
                    event: LifecycleEvent::GatewayBooting,
                },
                "gateway_booting",
            ),
            (
                Event::Lifecycle {
                    envelope: envelope.clone(),
                    event: LifecycleEvent::GatewayReady,
                },
                "gateway_ready",
            ),
            (
                Event::Lifecycle {
                    envelope: envelope.clone(),
                    event: LifecycleEvent::PolicyApplied {
                        policy: policy(),
                        source_presets: vec![],
                        status: PolicyApplyStatus::Ok,
                        error: None,
                    },
                },
                "policy_applied",
            ),
            (
                Event::Lifecycle {
                    envelope: envelope.clone(),
                    event: LifecycleEvent::PolicyUpdated {
                        policy: policy(),
                        source_presets: vec![],
                        status: PolicyApplyStatus::Ok,
                        error: None,
                        previous_policy_hash: None,
                    },
                },
                "policy_updated",
            ),
            (
                Event::Lifecycle {
                    envelope: envelope.clone(),
                    event: LifecycleEvent::PolicyResetOnUpgrade {
                        previous_rule_count: 3,
                    },
                },
                "policy_reset_on_upgrade",
            ),
            (
                Event::Lifecycle {
                    envelope: envelope.clone(),
                    event: LifecycleEvent::PolicyPropagated {
                        policy_hash: "deadbeef".into(),
                    },
                },
                "policy_propagated",
            ),
            (
                Event::Lifecycle {
                    envelope: envelope.clone(),
                    event: LifecycleEvent::HealthDegraded {
                        component: HealthComponent::Envoy,
                        reason: "r".into(),
                    },
                },
                "health_degraded",
            ),
            (
                Event::Lifecycle {
                    envelope: envelope.clone(),
                    event: LifecycleEvent::HealthRestored {
                        component: HealthComponent::Envoy,
                    },
                },
                "health_restored",
            ),
            (
                Event::Lifecycle {
                    envelope: envelope.clone(),
                    event: LifecycleEvent::GatewayShutdown {
                        reason: GatewayShutdownReason::DaemonShutdown,
                        error: None,
                    },
                },
                "gateway_shutdown",
            ),
        ];

        for (event, expected) in cases {
            let json = to_json(event);
            assert_eq!(
                json["event"], expected,
                "event discriminator mismatch for expected={expected}; json = {json}"
            );
        }
    }

    // ----- deny-logger -----------------------------------------------------
    //
    // Wire shape comes from spec Part 3 "Traffic events" row for layer
    // `deny-logger`: the `deny` event carries `orig_dst_ip`,
    // `orig_dst_port`, `protocol` (`tcp`/`udp`), `src_ip`, `src_port`. The
    // `rate_limited` summary event (spec § "Hardening rules" #5) carries
    // `rate_limited_count` and `since_ts`.

    #[test]
    fn dto_deny_logger_deny_tcp_wire_shape() {
        let event = Event::Traffic {
            envelope: EventEnvelope {
                timestamp: Utc.with_ymd_and_hms(2026, 4, 22, 9, 45, 0).unwrap()
                    + chrono::Duration::milliseconds(123),
                session: Some(sid()),
            },
            event: TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(DenyLoggerDeny {
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 1),
                orig_dst_port: 443,
                protocol: DenyProtocol::Tcp,
                src_ip: Ipv4Addr::new(10, 0, 0, 42),
                src_port: 55123,
            })),
        };
        let json = to_json(event);
        assert_eq!(json["layer"], "deny-logger");
        assert_eq!(json["event"], "deny");
        assert_eq!(json["timestamp"], "2026-04-22T09:45:00.123Z");
        assert_eq!(json["session"], "0123456789ab");
        assert_eq!(json["orig_dst_ip"], "203.0.113.1");
        assert_eq!(json["orig_dst_port"], 443);
        assert_eq!(json["protocol"], "tcp");
        assert_eq!(json["src_ip"], "10.0.0.42");
        assert_eq!(json["src_port"], 55123);
        // Round-trip: parsing back and re-serializing must preserve shape.
        let dto: EventDto = serde_json::from_value(json.clone()).expect("parse back");
        let reserialized = serde_json::to_value(&dto).expect("re-serialize");
        assert_eq!(json, reserialized, "round-trip must preserve JSON shape");
    }

    #[test]
    fn dto_deny_logger_deny_udp_wire_shape() {
        // Same structural fields as the TCP case — the only difference is
        // the `protocol` literal. This test pins the `udp` rename on
        // `DenyProtocol::Udp`.
        let event = Event::Traffic {
            envelope: EventEnvelope {
                timestamp: Utc.with_ymd_and_hms(2026, 4, 22, 9, 45, 0).unwrap(),
                session: Some(sid()),
            },
            event: TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(DenyLoggerDeny {
                orig_dst_ip: Ipv4Addr::new(198, 51, 100, 7),
                orig_dst_port: 53,
                protocol: DenyProtocol::Udp,
                src_ip: Ipv4Addr::new(10, 0, 0, 42),
                src_port: 41234,
            })),
        };
        let json = to_json(event);
        assert_eq!(json["layer"], "deny-logger");
        assert_eq!(json["event"], "deny");
        assert_eq!(json["protocol"], "udp");
        assert_eq!(json["orig_dst_ip"], "198.51.100.7");
        assert_eq!(json["orig_dst_port"], 53);
        let dto: EventDto = serde_json::from_value(json.clone()).expect("parse back");
        let reserialized = serde_json::to_value(&dto).expect("re-serialize");
        assert_eq!(json, reserialized, "round-trip must preserve JSON shape");
    }

    #[test]
    fn dto_deny_logger_allow_udp_wire_shape() {
        // M12-S2 Decision 3 / 5: allow events share the deny event's
        // 5-tuple wire shape (`orig_dst_ip`, `orig_dst_port`,
        // `protocol`, `src_ip`, `src_port`), distinguished only by
        // the `event` discriminator (`"allow"` vs `"deny"`). This
        // test pins the allow shape and the round-trip equality
        // alongside the existing deny tests; the deny round-trip
        // tests stay green untouched.
        let event = Event::Traffic {
            envelope: EventEnvelope {
                timestamp: Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap()
                    + chrono::Duration::milliseconds(789),
                session: Some(sid()),
            },
            event: TrafficEvent::DenyLogger(DenyLoggerEvent::Allow(DenyLoggerAllow {
                orig_dst_ip: Ipv4Addr::new(198, 51, 100, 7),
                orig_dst_port: 123,
                protocol: DenyProtocol::Udp,
                src_ip: Ipv4Addr::new(10, 0, 0, 42),
                src_port: 51234,
            })),
        };
        let json = to_json(event);
        // The on-bus DTO `layer` stays "deny-logger" — the layer is
        // the daemon's classification of "nft-layer logger event"
        // (Decision 5: same code path), not the literal name of the
        // emitting binary. The on-disk JSONL `layer:"allow-logger"`
        // is mapped at ingest into this same domain bucket.
        assert_eq!(json["layer"], "deny-logger");
        assert_eq!(json["event"], "allow");
        assert_eq!(json["timestamp"], "2026-05-01T12:00:00.789Z");
        assert_eq!(json["session"], "0123456789ab");
        assert_eq!(json["orig_dst_ip"], "198.51.100.7");
        assert_eq!(json["orig_dst_port"], 123);
        assert_eq!(json["protocol"], "udp");
        assert_eq!(json["src_ip"], "10.0.0.42");
        assert_eq!(json["src_port"], 51234);
        // `rate_limited_count` / `since_ts` must not leak into
        // an `allow` event.
        for absent in ["rate_limited_count", "since_ts"] {
            assert!(
                json.get(absent).is_none(),
                "`{absent}` must not appear on allow; json = {json}"
            );
        }
        // Round-trip: parsing back and re-serializing must preserve shape.
        let dto: EventDto = serde_json::from_value(json.clone()).expect("parse back");
        let reserialized = serde_json::to_value(&dto).expect("re-serialize");
        assert_eq!(json, reserialized, "round-trip must preserve JSON shape");
    }

    #[test]
    fn dto_deny_logger_rate_limited_wire_shape() {
        // `rate_limited` summary event — `rate_limited_count` is the
        // spec-authoritative field name (spec § "Hardening rules" #5).
        // `since_ts` must use the same RFC 3339 + ms + `Z` format as the
        // envelope timestamp.
        let ts = Utc.with_ymd_and_hms(2026, 4, 22, 9, 45, 0).unwrap()
            + chrono::Duration::milliseconds(500);
        let since = Utc.with_ymd_and_hms(2026, 4, 22, 9, 44, 30).unwrap()
            + chrono::Duration::milliseconds(250);
        let event = Event::Traffic {
            envelope: EventEnvelope {
                timestamp: ts,
                session: Some(sid()),
            },
            event: TrafficEvent::DenyLogger(DenyLoggerEvent::RateLimited {
                rate_limited_count: 42,
                since_ts: since,
            }),
        };
        let json = to_json(event);
        assert_eq!(json["layer"], "deny-logger");
        assert_eq!(json["event"], "rate_limited");
        assert_eq!(json["timestamp"], "2026-04-22T09:45:00.500Z");
        assert_eq!(json["session"], "0123456789ab");
        assert_eq!(json["rate_limited_count"], 42);
        assert_eq!(json["since_ts"], "2026-04-22T09:44:30.250Z");
        // `deny` fields must not leak into a `rate_limited` event.
        for absent in [
            "orig_dst_ip",
            "orig_dst_port",
            "protocol",
            "src_ip",
            "src_port",
        ] {
            assert!(
                json.get(absent).is_none(),
                "`{absent}` must not appear on rate_limited; json = {json}"
            );
        }
        let dto: EventDto = serde_json::from_value(json.clone()).expect("parse back");
        let reserialized = serde_json::to_value(&dto).expect("re-serialize");
        assert_eq!(json, reserialized, "round-trip must preserve JSON shape");
    }

    // ----- event_to_jsonl_line --------------------------------------------
    //
    // Pin the wire contract of the single-line JSONL helper used by the
    // HTTP handler and the persistent sink: every line must end with `\n`,
    // carry exactly one JSON object, and round-trip back into an
    // [`EventDto`] that re-serializes bit-identically.

    fn jsonl_envelope() -> EventEnvelope {
        EventEnvelope {
            timestamp: Utc.with_ymd_and_hms(2026, 4, 22, 9, 45, 0).unwrap()
                + chrono::Duration::milliseconds(123),
            session: Some(sid()),
        }
    }

    fn jsonl_pre_session_envelope() -> EventEnvelope {
        EventEnvelope {
            timestamp: Utc.with_ymd_and_hms(2026, 4, 22, 9, 45, 0).unwrap(),
            session: None,
        }
    }

    #[test]
    fn event_to_jsonl_line_ends_with_newline_and_parses_back() {
        // Cover one of each top-level variant so a regression in any
        // mapper branch surfaces here rather than only in a distant
        // integration test.
        let conn = EnvoyConnection {
            src_ip: Ipv4Addr::new(10, 0, 0, 42),
            src_port: 54321,
            dst_ip: Ipv4Addr::new(93, 184, 216, 34),
            dst_port: 443,
            matched_chain: "chain".into(),
            cluster: "cluster".into(),
            upstream_host: None,
            bytes_sent: 0,
            bytes_received: 0,
            response_flags: "-".into(),
            duration_ms: 0,
            connect_authority: None,
        };

        let cases: Vec<Event> = vec![
            Event::Traffic {
                envelope: jsonl_envelope(),
                event: TrafficEvent::Dns(DnsEvent::QueryAllowed {
                    query: "api.example.com".into(),
                    qtype: "A".into(),
                    resolved_ips: vec![Ipv4Addr::new(93, 184, 216, 34)],
                }),
            },
            Event::Traffic {
                envelope: jsonl_envelope(),
                event: TrafficEvent::Dns(DnsEvent::QueryDenied {
                    query: "blocked.example.com".into(),
                    qtype: "AAAA".into(),
                    reason: "policy_deny".into(),
                }),
            },
            Event::Traffic {
                envelope: jsonl_envelope(),
                event: TrafficEvent::Envoy(EnvoyEvent::ConnectionAllowed(conn.clone())),
            },
            Event::Traffic {
                envelope: jsonl_envelope(),
                event: TrafficEvent::Envoy(EnvoyEvent::ConnectionDenied(conn.clone())),
            },
            Event::Traffic {
                envelope: jsonl_envelope(),
                event: TrafficEvent::Mitmproxy(MitmproxyEvent::RequestAllowed {
                    host: "api.example.com".into(),
                    port: 443,
                    method: "GET".into(),
                    path: "/v1/widgets".into(),
                }),
            },
            Event::Traffic {
                envelope: jsonl_envelope(),
                event: TrafficEvent::Mitmproxy(MitmproxyEvent::RequestDenied {
                    host: "api.example.com".into(),
                    port: 443,
                    method: "DELETE".into(),
                    path: "/admin".into(),
                    reason: "no_matching_filter".into(),
                }),
            },
            Event::Traffic {
                envelope: jsonl_envelope(),
                event: TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(DenyLoggerDeny {
                    orig_dst_ip: Ipv4Addr::new(203, 0, 113, 1),
                    orig_dst_port: 443,
                    protocol: DenyProtocol::Tcp,
                    src_ip: Ipv4Addr::new(10, 0, 0, 42),
                    src_port: 55123,
                })),
            },
            Event::Traffic {
                envelope: jsonl_envelope(),
                event: TrafficEvent::DenyLogger(DenyLoggerEvent::Allow(DenyLoggerAllow {
                    orig_dst_ip: Ipv4Addr::new(198, 51, 100, 7),
                    orig_dst_port: 123,
                    protocol: DenyProtocol::Udp,
                    src_ip: Ipv4Addr::new(10, 0, 0, 42),
                    src_port: 51234,
                })),
            },
            Event::Traffic {
                envelope: jsonl_envelope(),
                event: TrafficEvent::DenyLogger(DenyLoggerEvent::RateLimited {
                    rate_limited_count: 7,
                    since_ts: jsonl_envelope().timestamp,
                }),
            },
            Event::Lifecycle {
                envelope: jsonl_pre_session_envelope(),
                event: LifecycleEvent::GatewayBooting,
            },
            Event::Lifecycle {
                envelope: jsonl_envelope(),
                event: LifecycleEvent::GatewayReady,
            },
            Event::Lifecycle {
                envelope: jsonl_envelope(),
                event: LifecycleEvent::PolicyApplied {
                    policy: policy(),
                    source_presets: vec![],
                    status: PolicyApplyStatus::Ok,
                    error: None,
                },
            },
            Event::Lifecycle {
                envelope: jsonl_envelope(),
                event: LifecycleEvent::HealthDegraded {
                    component: HealthComponent::Envoy,
                    reason: "timeout".into(),
                },
            },
            Event::Lifecycle {
                envelope: jsonl_envelope(),
                event: LifecycleEvent::GatewayShutdown {
                    reason: GatewayShutdownReason::SessionStopped,
                    error: None,
                },
            },
        ];

        for (idx, event) in cases.iter().enumerate() {
            let line = event_to_jsonl_line(event).expect("serialize should never fail");
            assert!(
                line.ends_with('\n'),
                "case {idx}: line must end with `\\n`, got: {line:?}"
            );
            // Exactly one newline, and it must be at the end.
            assert_eq!(
                line.matches('\n').count(),
                1,
                "case {idx}: line must contain exactly one newline"
            );

            // Round-trip: parse the trimmed line back into an EventDto.
            let parsed: EventDto = serde_json::from_str(line.trim_end())
                .unwrap_or_else(|e| panic!("case {idx}: parse back must succeed: {e}"));
            let parsed_value = serde_json::to_value(&parsed)
                .unwrap_or_else(|e| panic!("case {idx}: re-serialize must succeed: {e}"));
            // Compare against the original DTO rendered as a JSON value.
            let original_value = serde_json::to_value(EventDto::from(event))
                .unwrap_or_else(|e| panic!("case {idx}: serialize original: {e}"));
            assert_eq!(
                parsed_value, original_value,
                "case {idx}: round-trip must preserve JSON shape"
            );
        }
    }

    #[test]
    fn event_to_jsonl_line_is_single_json_object_per_line() {
        // Spot-check: the produced line starts with `{` and has no
        // intra-line newline. Guarantees clients can use a dead-simple
        // line-splitter without worrying about multi-line JSON.
        let event = Event::Lifecycle {
            envelope: jsonl_envelope(),
            event: LifecycleEvent::GatewayReady,
        };
        let line = event_to_jsonl_line(&event).expect("serialize");
        assert!(line.starts_with('{'), "line must start with `{{`: {line}");
        // Strip the trailing newline and confirm the body is a single
        // parseable JSON object.
        let body = line.trim_end_matches('\n');
        assert!(!body.contains('\n'), "body must not contain newlines");
        let _: serde_json::Value = serde_json::from_str(body).expect("body is valid json");
    }
}
