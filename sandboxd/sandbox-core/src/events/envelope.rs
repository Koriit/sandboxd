//! Domain types for the unified event stream.
//!
//! Every policy-bearing component (DNS, Envoy, mitmproxy) emits one event
//! per decision; sandboxd itself emits lifecycle events around gateway and
//! policy state changes. The wire surface is in [`crate::api::event_dto`];
//! these domain types never serialize directly.
//!
//! Spec reference: `.tasks/specs/2026-04-21-port-explicit-policies-presets-
//! observability-design.md`, Part 3 ("Event surface", "Event shape",
//! "Event categories"). Every event name and every layer-specific field
//! name below is traceable to the spec's Event-categories tables.
//!
//! Design notes:
//!
//! - Domain types deliberately do **not** derive [`serde::Serialize`] /
//!   [`serde::Deserialize`]. Serialization lives on
//!   [`crate::api::event_dto`] so that a domain-shape change does not
//!   silently leak onto the wire (same principle as `crate::api::dto` /
//!   `crate::api::mapper`).
//! - IP addresses are carried as [`Ipv4Addr`]; the ingestion layer (Phase
//!   7) parses Envoy access-log records into these strict types before
//!   publishing so downstream code cannot see malformed IPs.
//! - `session: Option<SessionId>` is [`None`] for lifecycle events that
//!   precede session creation (daemon boot, gateway boot before session
//!   attachment). The DTO renders [`None`] as `""`, per spec.
//! - Traffic events carry no session on this struct; sandboxd's ingestion
//!   layer stamps the envelope `session` from the `vm_ip → session_id` map
//!   before publishing to the bus (spec Part 3, "Session-ID attribution
//!   is sandboxd's job, not each component's").

use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};

use crate::policy::Policy;
use crate::session::SessionId;

// ---------------------------------------------------------------------------
// Top-level envelope
// ---------------------------------------------------------------------------

/// Common envelope fields shared by every event.
///
/// The `layer` discriminator is **not** stored here — it is determined by
/// which variant of [`Event`] wraps the payload, which keeps the domain
/// type total (no "impossible" layer/event pairings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelope {
    /// UTC timestamp of when the event was emitted.
    pub timestamp: DateTime<Utc>,
    /// Session the event belongs to. [`None`] for pre-session lifecycle
    /// events (e.g., `gateway_booting` before the session's gateway is
    /// attached).
    pub session: Option<SessionId>,
}

/// A single event in the unified stream.
///
/// Split by top-level category (traffic vs. lifecycle) so ingestion and
/// lifecycle-emitter code can share a common type without constantly
/// dispatching on a flat 15-way enum.
///
/// No [`PartialEq`] derive: lifecycle events carry a [`Policy`] payload,
/// and [`Policy`] does not (and should not — rule-ordering semantics, see
/// [`crate::policy`]) implement [`PartialEq`]. Round-trip tests compare
/// at the DTO level, where full structural equality is meaningful.
#[derive(Debug, Clone)]
pub enum Event {
    /// Per-request or per-connection policy decision emitted by a
    /// policy-enforcing component (CoreDNS plugin, Envoy, mitmproxy).
    Traffic {
        envelope: EventEnvelope,
        event: TrafficEvent,
    },
    /// Gateway and daemon control-plane state change emitted by sandboxd.
    Lifecycle {
        envelope: EventEnvelope,
        event: LifecycleEvent,
    },
}

impl Event {
    /// Return a reference to the common [`EventEnvelope`] regardless of
    /// top-level variant. Callers can then inspect `timestamp` / `session`
    /// without dispatching on the variant themselves.
    pub fn envelope(&self) -> &EventEnvelope {
        match self {
            Event::Traffic { envelope, .. } => envelope,
            Event::Lifecycle { envelope, .. } => envelope,
        }
    }

    /// Session this event is attributed to, if any.
    ///
    /// Returns [`None`] for pre-session lifecycle events (e.g.,
    /// `gateway_booting` emitted before the gateway is attached to a
    /// session). The bus uses this to route events to the right per-session
    /// sink; pre-session events currently have no per-session sink to land
    /// in and are dropped by [`crate::events::EventBus::publish`].
    pub fn session(&self) -> Option<&SessionId> {
        self.envelope().session.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Traffic events
// ---------------------------------------------------------------------------

/// Per-layer traffic event.
///
/// Variants correspond 1:1 to the `Layer` column of spec Part 3
/// / "Traffic events".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficEvent {
    /// CoreDNS policy-plugin decision on a client DNS query.
    Dns(DnsEvent),
    /// Envoy per-connection decision (from a harmonized `access_log` JSON
    /// record on an L1, L2, or L3 filter chain).
    Envoy(EnvoyEvent),
    /// mitmproxy addon per-request decision.
    Mitmproxy(MitmproxyEvent),
    /// Deny-logger per-attempt decision on a VM-egress connection that
    /// matches no allow rule (see M10-S3).
    DenyLogger(DenyLoggerEvent),
}

/// CoreDNS `query_allowed` / `query_denied`.
///
/// Fields match the spec Part 3 "Traffic events" table for layer `dns`:
/// `query`, `qtype`, `resolved_ips` (on allow), `reason` (on deny).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsEvent {
    QueryAllowed {
        query: String,
        qtype: String,
        resolved_ips: Vec<Ipv4Addr>,
    },
    QueryDenied {
        query: String,
        qtype: String,
        reason: String,
    },
}

/// Envoy per-connection event derived from the JSON access-log record.
///
/// Harmonized across L1, L2, L3 filter chains; `connect_authority` is
/// present only on L3 records (CONNECT-tunnel `REQUESTED_SERVER_NAME`).
/// Named fields follow the plan's JSON field map (plan Phase 4, line 102):
/// spec Part 3 Table names `matched_chain`, `cluster`; plan adds the
/// remaining access-log-standard fields so ingestion does not have to drop
/// data that operators will want.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvoyEvent {
    ConnectionAllowed(EnvoyConnection),
    ConnectionDenied(EnvoyConnection),
}

/// Payload shared by `connection_allowed` / `connection_denied`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvoyConnection {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub matched_chain: String,
    pub cluster: String,
    pub upstream_host: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub response_flags: String,
    pub duration_ms: u64,
    /// L3 CONNECT-tunnel authority (`REQUESTED_SERVER_NAME`). [`None`] on
    /// L1/L2 chains.
    pub connect_authority: Option<String>,
}

/// mitmproxy addon `request_allowed` / `request_denied`.
///
/// Fields match the spec Part 3 "Traffic events" table for layer
/// `mitmproxy`: `host`, `port`, `method`, `path`, and `reason` on deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MitmproxyEvent {
    RequestAllowed {
        host: String,
        port: u16,
        method: String,
        path: String,
    },
    RequestDenied {
        host: String,
        port: u16,
        method: String,
        path: String,
        reason: String,
    },
}

/// Deny-logger `deny` / `rate_limited`.
///
/// The deny-logger component (spec Part 3 / "Deny-logger component")
/// emits a structured record for every VM-egress connection attempt that
/// lands in the deny-path of `sandbox_dnat` prerouting — i.e. that
/// matches no policy allow rule. The `Deny` variant carries the
/// pre-DNAT 5-tuple per spec Part 3 / "Traffic events" table row for
/// layer `deny-logger`:
/// `orig_dst_ip`, `orig_dst_port`, `protocol` (`tcp` / `udp`), `src_ip`,
/// `src_port`.
///
/// The `RateLimited` variant is a periodic summary event emitted when
/// the component's per-session event rate cap is exceeded — individual
/// denied attempts are dropped from the stream once the cap is hit and
/// are reported in aggregate via this variant. Carries
/// `rate_limited_count` per spec Part 3 / "Hardening rules" § 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyLoggerEvent {
    /// Single denied connection attempt.
    Deny(DenyLoggerDeny),
    /// Periodic cap-breach summary: how many deny events were dropped
    /// since the last summary tick.
    RateLimited {
        rate_limited_count: u32,
        since_ts: DateTime<Utc>,
    },
}

/// Payload of [`DenyLoggerEvent::Deny`].
///
/// Field names match spec Part 3 / "Traffic events" row for layer
/// `deny-logger` character-for-character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyLoggerDeny {
    /// Pre-DNAT original destination IPv4 address (from `SO_ORIGINAL_DST`
    /// / `IP_ORIGDSTADDR` cmsg).
    pub orig_dst_ip: Ipv4Addr,
    /// Pre-DNAT original destination port.
    pub orig_dst_port: u16,
    /// L4 protocol of the denied attempt.
    pub protocol: DenyProtocol,
    /// Source IPv4 address (VM bridge IP), from `getpeername` on TCP or
    /// the datagram's peer address on UDP.
    pub src_ip: Ipv4Addr,
    /// Source port.
    pub src_port: u16,
}

/// L4 protocol on a deny-logger `deny` event.
///
/// Serialized on the wire as `"tcp"` / `"udp"` per spec Part 3 /
/// "Traffic events" row for layer `deny-logger`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyProtocol {
    Tcp,
    Udp,
}

// ---------------------------------------------------------------------------
// Lifecycle events
// ---------------------------------------------------------------------------

/// sandboxd-emitted lifecycle event.
///
/// Variants correspond 1:1 to the rows of spec Part 3 "Lifecycle events"
/// table. Field sets mirror the spec's `Key fields` column exactly; see
/// the per-variant docs for the source row.
///
/// No [`PartialEq`] derive: the [`Policy`] payload on
/// `PolicyApplied` / `PolicyUpdated` cannot trivially be compared for
/// equality (see [`Event`] docs).
#[derive(Debug, Clone)]
pub enum LifecycleEvent {
    /// Gateway container starting (sandboxd initiated).
    GatewayBooting,
    /// Gateway passed startup checks (CoreDNS, Envoy, mitmproxy, deny-
    /// logger all responding).
    GatewayReady,
    /// Initial policy application at session start.
    PolicyApplied {
        policy: Policy,
        /// Original `--preset` invocation strings forwarded by the CLI.
        /// Empty if none.
        source_presets: Vec<String>,
        status: PolicyApplyStatus,
        /// Populated when `status == Error`.
        error: Option<String>,
    },
    /// Subsequent policy update via `sandbox policy update`.
    PolicyUpdated {
        policy: Policy,
        source_presets: Vec<String>,
        status: PolicyApplyStatus,
        error: Option<String>,
        /// Hash of the prior effective policy, for diff attribution.
        previous_policy_hash: Option<String>,
    },
    /// Emitted once per session on first access after V004 migration
    /// removed its v1-shaped rules.
    PolicyResetOnUpgrade { previous_rule_count: usize },
    /// Policy has fully propagated across all three enforcement layers.
    ///
    /// Emit conditions (all must hold at the time of emission):
    /// * The session's current effective [`Policy`] has been mirrored to
    ///   the gateway (nftables `policy_allow_{tcp,udp}` sets, Envoy
    ///   filter chains, mitmproxy rules).
    /// * At least one full cycle of the DNS propagation loop has run
    ///   after the policy was applied, so every `Destination::Domain`
    ///   rule at `level != Deny` has been resolved and the resolved IPs
    ///   mirrored into nftables.
    /// * The hash of the reconciled policy matches the hash of the
    ///   applied policy (i.e., no new apply has raced ahead).
    ///
    /// Transition-only: the loop tracks the last emitted hash per session
    /// and suppresses duplicate emissions while the hash is stable. Fresh
    /// emission resumes on any subsequent policy-apply that changes the
    /// hash.
    PolicyPropagated {
        /// SHA-256 hex digest of the canonical JSON serialization of the
        /// propagated [`Policy`]. Stable across processes; matches
        /// `expected_hash` from the propagation-status endpoint.
        policy_hash: String,
    },
    /// A subcomponent healthcheck started failing.
    HealthDegraded {
        component: HealthComponent,
        reason: String,
    },
    /// A previously-degraded subcomponent recovered.
    HealthRestored { component: HealthComponent },
    /// Gateway container stopping.
    GatewayShutdown {
        reason: GatewayShutdownReason,
        /// Populated when `reason == Error`.
        error: Option<String>,
    },
}

/// Outcome of a policy-apply / policy-update action.
///
/// Serialized as the lowercase strings `"ok"` / `"error"` to match the
/// spec's `status` column for `policy_applied` / `policy_updated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyApplyStatus {
    Ok,
    Error,
}

/// Subcomponent for [`LifecycleEvent::HealthDegraded`] /
/// [`LifecycleEvent::HealthRestored`].
///
/// Matches the spec's enumeration of gateway subcomponents:
/// `deny-logger`, `envoy`, `mitmproxy`, `coredns`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealthComponent {
    DenyLogger,
    Envoy,
    Mitmproxy,
    Coredns,
}

/// Reason carried on [`LifecycleEvent::GatewayShutdown`].
///
/// Matches the spec's `reason` values for `gateway_shutdown`:
/// `session_stopped`, `daemon_shutdown`, `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayShutdownReason {
    SessionStopped,
    DaemonShutdown,
    Error,
}

// ---------------------------------------------------------------------------
// Round-trip tests: domain → DTO → JSON → DTO → domain
// ---------------------------------------------------------------------------
//
// Each round-trip test builds a fixture domain [`Event`], maps it to the
// wire DTO, serializes to JSON, deserializes back, and asserts the full
// round-trip preserves the shape. Traffic-layer tests use direct DTO
// equality; lifecycle tests use [`serde_json::Value`] equality (the
// lifecycle DTO does not derive [`PartialEq`], see the type's rustdoc for
// why).
//
// Every test also asserts the serialized JSON carries the spec's exact
// `layer` and `event` discriminators, plus the layer-specific field names
// from spec Part 3 "Event categories".

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::TimeZone;
    use serde_json::Value;

    use crate::api::event_dto::EventDto;
    use crate::policy::{
        AssuranceLevel, Destination, HttpFilter, HttpMethod, Policy, PolicyRule, Protocol,
    };

    fn fixture_timestamp() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 22, 9, 45, 0)
            .unwrap()
            .with_timezone(&Utc)
            + chrono::Duration::milliseconds(123)
    }

    fn fixture_session() -> SessionId {
        SessionId::parse("0123456789ab").expect("valid fixture id")
    }

    fn fixture_envelope() -> EventEnvelope {
        EventEnvelope {
            timestamp: fixture_timestamp(),
            session: Some(fixture_session()),
        }
    }

    fn fixture_policy() -> Policy {
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

    /// Traffic-layer round-trip helper: serialize → parse back → compare.
    fn round_trip_traffic(event: Event, expected_layer: &str, expected_event: &str) -> Value {
        let dto = EventDto::from(&event);
        let json = serde_json::to_value(&dto).expect("serialize");
        let top = json.as_object().expect("event is a json object");
        assert_eq!(
            top.get("layer").and_then(Value::as_str),
            Some(expected_layer)
        );
        assert_eq!(
            top.get("event").and_then(Value::as_str),
            Some(expected_event)
        );
        // Deserialize back and re-serialize; expect identical JSON.
        let parsed: EventDto = serde_json::from_value(json.clone()).expect("parse back");
        let reserialized = serde_json::to_value(&parsed).expect("re-serialize");
        assert_eq!(json, reserialized, "round-trip must preserve JSON shape");
        json
    }

    /// Lifecycle round-trip helper: same as traffic but always uses JSON
    /// equality (no DTO PartialEq for lifecycle).
    fn round_trip_lifecycle(event: Event, expected_event: &str) -> Value {
        let dto = EventDto::from(&event);
        let json = serde_json::to_value(&dto).expect("serialize");
        let top = json.as_object().expect("event is a json object");
        assert_eq!(
            top.get("layer").and_then(Value::as_str),
            Some("lifecycle"),
            "lifecycle events must carry `layer: \"lifecycle\"`"
        );
        assert_eq!(
            top.get("event").and_then(Value::as_str),
            Some(expected_event)
        );
        let parsed: EventDto = serde_json::from_value(json.clone()).expect("parse back");
        let reserialized = serde_json::to_value(&parsed).expect("re-serialize");
        assert_eq!(json, reserialized, "round-trip must preserve JSON shape");
        json
    }

    // ----- traffic: envoy ---------------------------------------------------

    fn envoy_fixture(response_flags: &str, connect_authority: Option<&str>) -> EnvoyConnection {
        EnvoyConnection {
            src_ip: "10.0.0.42".parse().unwrap(),
            src_port: 54321,
            dst_ip: "93.184.216.34".parse().unwrap(),
            dst_port: 443,
            matched_chain: "chain_l3_example".into(),
            cluster: "upstream_example_443".into(),
            upstream_host: Some("93.184.216.34:443".into()),
            bytes_sent: 1024,
            bytes_received: 4096,
            response_flags: response_flags.into(),
            duration_ms: 42,
            connect_authority: connect_authority.map(str::to_string),
        }
    }

    #[test]
    fn env_round_trip_traffic_envoy_allow() {
        let event = Event::Traffic {
            envelope: fixture_envelope(),
            event: TrafficEvent::Envoy(EnvoyEvent::ConnectionAllowed(envoy_fixture(
                "-",
                Some("example.com:443"),
            ))),
        };
        let json = round_trip_traffic(event, "envoy", "connection_allowed");
        // Spot-check spec field names appear at the top level.
        for field in [
            "timestamp",
            "session",
            "layer",
            "event",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "matched_chain",
            "cluster",
            "upstream_host",
            "bytes_sent",
            "bytes_received",
            "response_flags",
            "duration_ms",
            "connect_authority",
        ] {
            assert!(
                json.get(field).is_some(),
                "missing `{field}` at top level; json = {json}"
            );
        }
        assert_eq!(json["src_ip"], "10.0.0.42");
        assert_eq!(json["dst_port"], 443);
    }

    #[test]
    fn env_round_trip_traffic_envoy_deny() {
        let event = Event::Traffic {
            envelope: fixture_envelope(),
            event: TrafficEvent::Envoy(EnvoyEvent::ConnectionDenied(envoy_fixture("NR", None))),
        };
        let json = round_trip_traffic(event, "envoy", "connection_denied");
        assert_eq!(json["response_flags"], "NR");
        // `connect_authority` absent on this fixture (L1/L2-style).
        assert!(
            json.get("connect_authority").is_none(),
            "connect_authority should be omitted when None; json = {json}"
        );
    }

    // ----- traffic: dns -----------------------------------------------------

    #[test]
    fn env_round_trip_traffic_dns_allow() {
        let event = Event::Traffic {
            envelope: fixture_envelope(),
            event: TrafficEvent::Dns(DnsEvent::QueryAllowed {
                query: "api.example.com".into(),
                qtype: "A".into(),
                resolved_ips: vec!["93.184.216.34".parse().unwrap()],
            }),
        };
        let json = round_trip_traffic(event, "dns", "query_allowed");
        assert_eq!(json["query"], "api.example.com");
        assert_eq!(json["qtype"], "A");
        assert_eq!(json["resolved_ips"][0], "93.184.216.34");
    }

    #[test]
    fn env_round_trip_traffic_dns_deny() {
        let event = Event::Traffic {
            envelope: fixture_envelope(),
            event: TrafficEvent::Dns(DnsEvent::QueryDenied {
                query: "blocked.example.com".into(),
                qtype: "AAAA".into(),
                reason: "policy_deny".into(),
            }),
        };
        let json = round_trip_traffic(event, "dns", "query_denied");
        assert_eq!(json["query"], "blocked.example.com");
        assert_eq!(json["qtype"], "AAAA");
        assert_eq!(json["reason"], "policy_deny");
        // `resolved_ips` must not appear on a deny event.
        assert!(
            json.get("resolved_ips").is_none(),
            "resolved_ips must not appear on deny; json = {json}"
        );
    }

    // ----- traffic: mitmproxy ----------------------------------------------

    #[test]
    fn env_round_trip_traffic_mitmproxy_allow() {
        let event = Event::Traffic {
            envelope: fixture_envelope(),
            event: TrafficEvent::Mitmproxy(MitmproxyEvent::RequestAllowed {
                host: "api.example.com".into(),
                port: 443,
                method: "GET".into(),
                path: "/v1/widgets".into(),
            }),
        };
        let json = round_trip_traffic(event, "mitmproxy", "request_allowed");
        for field in ["host", "port", "method", "path"] {
            assert!(
                json.get(field).is_some(),
                "mitmproxy allow missing `{field}`; json = {json}"
            );
        }
        assert_eq!(json["host"], "api.example.com");
        assert_eq!(json["port"], 443);
        assert_eq!(json["method"], "GET");
        assert_eq!(json["path"], "/v1/widgets");
        // `reason` must not appear on an allow event.
        assert!(
            json.get("reason").is_none(),
            "reason must not appear on allow; json = {json}"
        );
    }

    #[test]
    fn env_round_trip_traffic_mitmproxy_deny() {
        let event = Event::Traffic {
            envelope: fixture_envelope(),
            event: TrafficEvent::Mitmproxy(MitmproxyEvent::RequestDenied {
                host: "api.example.com".into(),
                port: 443,
                method: "DELETE".into(),
                path: "/admin".into(),
                reason: "no_matching_filter".into(),
            }),
        };
        let json = round_trip_traffic(event, "mitmproxy", "request_denied");
        assert_eq!(json["reason"], "no_matching_filter");
        assert_eq!(json["method"], "DELETE");
    }

    // ----- traffic: deny-logger --------------------------------------------
    //
    // Per spec Part 3 "Traffic events" row for `deny-logger`: every `deny`
    // event carries `orig_dst_ip`, `orig_dst_port`, `protocol` (`tcp`/
    // `udp`), `src_ip`, `src_port`. The `rate_limited` summary event
    // carries `rate_limited_count` and `since_ts` (spec § "Hardening
    // rules" #5). Note the kebab-case `deny-logger` layer literal — the
    // only multi-word `layer` value in the spec.

    #[test]
    fn env_round_trip_traffic_deny_logger_tcp() {
        let event = Event::Traffic {
            envelope: fixture_envelope(),
            event: TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(DenyLoggerDeny {
                orig_dst_ip: "203.0.113.1".parse().unwrap(),
                orig_dst_port: 443,
                protocol: DenyProtocol::Tcp,
                src_ip: "10.0.0.42".parse().unwrap(),
                src_port: 55123,
            })),
        };
        let json = round_trip_traffic(event, "deny-logger", "deny");
        for field in [
            "timestamp",
            "session",
            "layer",
            "event",
            "orig_dst_ip",
            "orig_dst_port",
            "protocol",
            "src_ip",
            "src_port",
        ] {
            assert!(
                json.get(field).is_some(),
                "deny-logger deny missing `{field}`; json = {json}"
            );
        }
        assert_eq!(json["orig_dst_ip"], "203.0.113.1");
        assert_eq!(json["orig_dst_port"], 443);
        assert_eq!(json["protocol"], "tcp");
        assert_eq!(json["src_ip"], "10.0.0.42");
        assert_eq!(json["src_port"], 55123);
        // `rate_limited_count` / `since_ts` must not leak into a `deny`.
        assert!(
            json.get("rate_limited_count").is_none(),
            "rate_limited_count must not appear on deny; json = {json}"
        );
        assert!(
            json.get("since_ts").is_none(),
            "since_ts must not appear on deny; json = {json}"
        );
    }

    #[test]
    fn env_round_trip_traffic_deny_logger_udp() {
        let event = Event::Traffic {
            envelope: fixture_envelope(),
            event: TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(DenyLoggerDeny {
                orig_dst_ip: "198.51.100.7".parse().unwrap(),
                orig_dst_port: 53,
                protocol: DenyProtocol::Udp,
                src_ip: "10.0.0.42".parse().unwrap(),
                src_port: 41234,
            })),
        };
        let json = round_trip_traffic(event, "deny-logger", "deny");
        assert_eq!(json["protocol"], "udp");
        assert_eq!(json["orig_dst_port"], 53);
    }

    #[test]
    fn env_round_trip_traffic_deny_logger_rate_limited() {
        let since = Utc
            .with_ymd_and_hms(2026, 4, 22, 9, 44, 30)
            .unwrap()
            .with_timezone(&Utc)
            + chrono::Duration::milliseconds(250);
        let event = Event::Traffic {
            envelope: fixture_envelope(),
            event: TrafficEvent::DenyLogger(DenyLoggerEvent::RateLimited {
                rate_limited_count: 42,
                since_ts: since,
            }),
        };
        let json = round_trip_traffic(event, "deny-logger", "rate_limited");
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
    }

    // ----- lifecycle -------------------------------------------------------

    #[test]
    fn env_round_trip_lifecycle_gateway_booting() {
        // `gateway_booting` is a pre-session event per spec; session is None.
        let event = Event::Lifecycle {
            envelope: EventEnvelope {
                timestamp: fixture_timestamp(),
                session: None,
            },
            event: LifecycleEvent::GatewayBooting,
        };
        let json = round_trip_lifecycle(event, "gateway_booting");
        // No session attribution yet; wire must still carry the field as "".
        assert_eq!(json["session"], "");
    }

    #[test]
    fn env_round_trip_lifecycle_gateway_ready() {
        let event = Event::Lifecycle {
            envelope: fixture_envelope(),
            event: LifecycleEvent::GatewayReady,
        };
        round_trip_lifecycle(event, "gateway_ready");
    }

    #[test]
    fn env_round_trip_lifecycle_policy_applied() {
        let event = Event::Lifecycle {
            envelope: fixture_envelope(),
            event: LifecycleEvent::PolicyApplied {
                policy: fixture_policy(),
                source_presets: vec!["cargo:".into()],
                status: PolicyApplyStatus::Ok,
                error: None,
            },
        };
        let json = round_trip_lifecycle(event, "policy_applied");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["source_presets"][0], "cargo:");
        // Policy object carried through the `policy` field (nested object).
        assert_eq!(json["policy"]["version"], "2.0.0");
        // error is omitted on success.
        assert!(json.get("error").is_none(), "error omitted on ok status");
    }

    #[test]
    fn env_round_trip_lifecycle_policy_updated() {
        let event = Event::Lifecycle {
            envelope: fixture_envelope(),
            event: LifecycleEvent::PolicyUpdated {
                policy: fixture_policy(),
                source_presets: vec![],
                status: PolicyApplyStatus::Error,
                error: Some("compile failed".into()),
                previous_policy_hash: Some("deadbeef".into()),
            },
        };
        let json = round_trip_lifecycle(event, "policy_updated");
        assert_eq!(json["status"], "error");
        assert_eq!(json["error"], "compile failed");
        assert_eq!(json["previous_policy_hash"], "deadbeef");
    }

    #[test]
    fn env_round_trip_lifecycle_policy_reset_on_upgrade() {
        let event = Event::Lifecycle {
            envelope: fixture_envelope(),
            event: LifecycleEvent::PolicyResetOnUpgrade {
                previous_rule_count: 7,
            },
        };
        let json = round_trip_lifecycle(event, "policy_reset_on_upgrade");
        assert_eq!(json["previous_rule_count"], 7);
    }

    #[test]
    fn env_round_trip_lifecycle_policy_propagated() {
        let event = Event::Lifecycle {
            envelope: fixture_envelope(),
            event: LifecycleEvent::PolicyPropagated {
                policy_hash: "abc123def4567890abc123def4567890abc123def4567890abc123def4567890"
                    .into(),
            },
        };
        let json = round_trip_lifecycle(event, "policy_propagated");
        assert_eq!(
            json["policy_hash"],
            "abc123def4567890abc123def4567890abc123def4567890abc123def4567890"
        );
    }

    #[test]
    fn env_round_trip_lifecycle_health_degraded() {
        let event = Event::Lifecycle {
            envelope: fixture_envelope(),
            event: LifecycleEvent::HealthDegraded {
                component: HealthComponent::DenyLogger,
                reason: "healthcheck timeout".into(),
            },
        };
        let json = round_trip_lifecycle(event, "health_degraded");
        // Kebab-case literal per spec.
        assert_eq!(json["component"], "deny-logger");
        assert_eq!(json["reason"], "healthcheck timeout");
    }

    #[test]
    fn env_round_trip_lifecycle_health_restored() {
        let event = Event::Lifecycle {
            envelope: fixture_envelope(),
            event: LifecycleEvent::HealthRestored {
                component: HealthComponent::Coredns,
            },
        };
        let json = round_trip_lifecycle(event, "health_restored");
        assert_eq!(json["component"], "coredns");
    }

    #[test]
    fn env_round_trip_lifecycle_gateway_shutdown() {
        let event = Event::Lifecycle {
            envelope: fixture_envelope(),
            event: LifecycleEvent::GatewayShutdown {
                reason: GatewayShutdownReason::SessionStopped,
                error: None,
            },
        };
        let json = round_trip_lifecycle(event, "gateway_shutdown");
        assert_eq!(json["reason"], "session_stopped");
        assert!(json.get("error").is_none());
    }
}
