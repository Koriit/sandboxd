//! Domain predicate for the event stream filter.
//!
//! Callers build an [`EventsFilter`] from an
//! [`EventsQueryDto`][super::events_query_dto::EventsQueryDto] via
//! [`EventsFilter::from_query`], which is the single conversion point
//! where unknown layer / decision / event strings fail loud as
//! [`crate::error::SandboxError::InvalidArgument`]. Downstream code
//! (HTTP handler, persistent sink, tests) then calls
//! [`EventsFilter::matches`] to decide whether to emit each event.
//!
//! AND semantics across filter axes: every non-empty axis must be
//! satisfied. An empty axis is "no constraint" for that dimension. An
//! `EventsFilter::default()` matches every event.
//!
//! Spec reference: `.tasks/specs/2026-04-21-port-explicit-policies-
//! presets-observability-design.md`, Part 3 § "HTTP endpoint" and
//! Part 3 § "Event categories" (for the enumeration of layer and
//! event-name literals).

use std::collections::HashSet;
use std::fmt;

use chrono::{DateTime, Utc};

use crate::error::SandboxError;
use crate::events::{
    DenyLoggerEvent, DnsEvent, EnvoyEvent, Event, LifecycleEvent, MitmproxyEvent, TrafficEvent,
};

use super::events_query_dto::{DecisionKind, EventsQueryDto};

// ---------------------------------------------------------------------------
// LayerKind
// ---------------------------------------------------------------------------

/// Canonical layer identifier.
///
/// Variant set matches [`super::event_dto::EventDto`] exactly: `Dns`,
/// `Envoy`, `Mitmproxy`, `DenyLogger`, `Lifecycle`. The on-wire
/// representation mirrors the spec's layer literals from Part 3
/// "Event shape": four lowercase single-word values plus the multi-word
/// kebab-case `deny-logger`.
///
/// `Hash` lets us key a `HashSet<LayerKind>` inside [`EventsFilter`]
/// without paying for string hashing on the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LayerKind {
    Dns,
    Envoy,
    Mitmproxy,
    DenyLogger,
    Lifecycle,
}

impl LayerKind {
    /// Parse a spec-authoritative layer string.
    ///
    /// Accepts exactly `"dns"`, `"envoy"`, `"mitmproxy"`,
    /// `"deny-logger"`, `"lifecycle"` (case-sensitive — the spec
    /// prescribes lowercase / kebab-case). Any other value returns
    /// [`SandboxError::InvalidArgument`] with the offending text.
    pub fn parse(s: &str) -> Result<Self, SandboxError> {
        match s {
            "dns" => Ok(Self::Dns),
            "envoy" => Ok(Self::Envoy),
            "mitmproxy" => Ok(Self::Mitmproxy),
            "deny-logger" => Ok(Self::DenyLogger),
            "lifecycle" => Ok(Self::Lifecycle),
            other => Err(SandboxError::InvalidArgument(format!(
                "invalid `layer` value `{other}`: expected one of \
                 `dns`, `envoy`, `mitmproxy`, `deny-logger`, `lifecycle`"
            ))),
        }
    }

    /// Canonical on-wire string for this layer.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Envoy => "envoy",
            Self::Mitmproxy => "mitmproxy",
            Self::DenyLogger => "deny-logger",
            Self::Lifecycle => "lifecycle",
        }
    }
}

impl fmt::Display for LayerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// EventName
// ---------------------------------------------------------------------------

/// Canonical event-name identifier.
///
/// Enumerates every event name the domain can emit today, grouped by
/// layer for readability. Source of truth is
/// [`crate::events::TrafficEvent`] / [`crate::events::LifecycleEvent`]
/// plus the spec's Part 3 "Event categories" tables.
///
/// A mid-stream additive event (e.g., a future synthetic
/// `ring_buffer_lag` lifecycle event — M10-S4 Phase 3 open question
/// Q5) requires a new variant here before it can be named in a
/// filter. That's the right direction of dependency: filters are a
/// user-facing contract, so adding a private event without deciding
/// how it's filterable is a design bug, not a convenience.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventName {
    // -------- DNS --------
    QueryAllowed,
    QueryDenied,
    // -------- Envoy --------
    ConnectionAllowed,
    ConnectionDenied,
    // -------- mitmproxy --------
    RequestAllowed,
    RequestDenied,
    // -------- deny-logger --------
    Deny,
    RateLimited,
    // -------- lifecycle --------
    GatewayBooting,
    GatewayReady,
    PolicyApplied,
    PolicyUpdated,
    PolicyResetOnUpgrade,
    HealthDegraded,
    HealthRestored,
    GatewayShutdown,
}

impl EventName {
    /// Parse a spec-authoritative event string.
    ///
    /// The accepted values are the snake_case strings used as
    /// `#[serde(tag = "event")]` discriminators on each per-layer DTO.
    /// Any other value returns [`SandboxError::InvalidArgument`] with
    /// the offending text.
    pub fn parse(s: &str) -> Result<Self, SandboxError> {
        match s {
            "query_allowed" => Ok(Self::QueryAllowed),
            "query_denied" => Ok(Self::QueryDenied),
            "connection_allowed" => Ok(Self::ConnectionAllowed),
            "connection_denied" => Ok(Self::ConnectionDenied),
            "request_allowed" => Ok(Self::RequestAllowed),
            "request_denied" => Ok(Self::RequestDenied),
            "deny" => Ok(Self::Deny),
            "rate_limited" => Ok(Self::RateLimited),
            "gateway_booting" => Ok(Self::GatewayBooting),
            "gateway_ready" => Ok(Self::GatewayReady),
            "policy_applied" => Ok(Self::PolicyApplied),
            "policy_updated" => Ok(Self::PolicyUpdated),
            "policy_reset_on_upgrade" => Ok(Self::PolicyResetOnUpgrade),
            "health_degraded" => Ok(Self::HealthDegraded),
            "health_restored" => Ok(Self::HealthRestored),
            "gateway_shutdown" => Ok(Self::GatewayShutdown),
            other => Err(SandboxError::InvalidArgument(format!(
                "invalid `event` value `{other}`: not a known event name"
            ))),
        }
    }

    /// Canonical on-wire string for this event name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QueryAllowed => "query_allowed",
            Self::QueryDenied => "query_denied",
            Self::ConnectionAllowed => "connection_allowed",
            Self::ConnectionDenied => "connection_denied",
            Self::RequestAllowed => "request_allowed",
            Self::RequestDenied => "request_denied",
            Self::Deny => "deny",
            Self::RateLimited => "rate_limited",
            Self::GatewayBooting => "gateway_booting",
            Self::GatewayReady => "gateway_ready",
            Self::PolicyApplied => "policy_applied",
            Self::PolicyUpdated => "policy_updated",
            Self::PolicyResetOnUpgrade => "policy_reset_on_upgrade",
            Self::HealthDegraded => "health_degraded",
            Self::HealthRestored => "health_restored",
            Self::GatewayShutdown => "gateway_shutdown",
        }
    }
}

impl fmt::Display for EventName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// EventsFilter
// ---------------------------------------------------------------------------

/// In-memory predicate over [`Event`]s.
///
/// Built once per request via [`Self::from_query`]; then
/// [`Self::matches`] is called for every candidate event. The struct
/// is [`Clone`] so the HTTP handler can pass it into both a replay
/// iterator and a streaming task.
#[derive(Debug, Clone, Default)]
pub struct EventsFilter {
    /// Empty set = "no constraint on layer".
    pub layers: HashSet<LayerKind>,
    /// Empty set = "no constraint on decision".
    pub decisions: HashSet<DecisionKind>,
    /// Empty set = "no constraint on event name".
    pub events: HashSet<EventName>,
    /// [`None`] = "no constraint on timestamp". When [`Some`], events
    /// with `envelope.timestamp >= since` match.
    pub since: Option<DateTime<Utc>>,
}

impl EventsFilter {
    /// Build a filter from a wire DTO, validating every string value.
    ///
    /// Unknown layer / decision / event strings produce
    /// [`SandboxError::InvalidArgument`] with the offending text in
    /// the error message — the spec explicitly calls out that an
    /// unknown `decision=reset` must fail loud rather than silently
    /// matching nothing.
    ///
    /// A malformed `since` bubbles up the error from
    /// [`EventsQueryDto::parse_since`].
    pub fn from_query(q: &EventsQueryDto) -> Result<Self, SandboxError> {
        let mut layers = HashSet::with_capacity(q.layer.len());
        for raw in &q.layer {
            layers.insert(LayerKind::parse(raw)?);
        }
        let mut decisions = HashSet::with_capacity(q.decision.len());
        for raw in &q.decision {
            decisions.insert(DecisionKind::parse(raw)?);
        }
        let mut events = HashSet::with_capacity(q.event.len());
        for raw in &q.event {
            events.insert(EventName::parse(raw)?);
        }
        let since = q.parse_since()?;
        Ok(Self {
            layers,
            decisions,
            events,
            since,
        })
    }

    /// Does this filter accept `event`?
    ///
    /// AND semantics across axes; an empty axis is "no constraint".
    pub fn matches(&self, event: &Event) -> bool {
        // Layer axis.
        if !self.layers.is_empty() && !self.layers.contains(&layer_of(event)) {
            return false;
        }
        // Decision axis. Events that have no allow/deny decision
        // (e.g., lifecycle events, deny-logger `rate_limited`) can
        // never satisfy a non-empty decision filter.
        if !self.decisions.is_empty() {
            match decision_of(event) {
                Some(d) if self.decisions.contains(&d) => {}
                _ => return false,
            }
        }
        // Event-name axis.
        if !self.events.is_empty() && !self.events.contains(&event_name_of(event)) {
            return false;
        }
        // Since axis.
        if let Some(since) = self.since
            && event.envelope().timestamp < since
        {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Event → classification helpers
// ---------------------------------------------------------------------------

/// Map a domain [`Event`] to its [`LayerKind`].
pub(crate) fn layer_of(event: &Event) -> LayerKind {
    match event {
        Event::Traffic { event, .. } => match event {
            TrafficEvent::Dns(_) => LayerKind::Dns,
            TrafficEvent::Envoy(_) => LayerKind::Envoy,
            TrafficEvent::Mitmproxy(_) => LayerKind::Mitmproxy,
            TrafficEvent::DenyLogger(_) => LayerKind::DenyLogger,
        },
        Event::Lifecycle { .. } => LayerKind::Lifecycle,
    }
}

/// Map a domain [`Event`] to its allow/deny decision, if it has one.
///
/// Events without a decision axis return [`None`]: lifecycle events
/// are pure state changes, and the deny-logger's `rate_limited`
/// summary is a meta-event about dropped events rather than a
/// decision itself.
fn decision_of(event: &Event) -> Option<DecisionKind> {
    match event {
        Event::Traffic { event, .. } => match event {
            TrafficEvent::Dns(e) => Some(match e {
                DnsEvent::QueryAllowed { .. } => DecisionKind::Allow,
                DnsEvent::QueryDenied { .. } => DecisionKind::Deny,
            }),
            TrafficEvent::Envoy(e) => Some(match e {
                EnvoyEvent::ConnectionAllowed(_) => DecisionKind::Allow,
                EnvoyEvent::ConnectionDenied(_) => DecisionKind::Deny,
            }),
            TrafficEvent::Mitmproxy(e) => Some(match e {
                MitmproxyEvent::RequestAllowed { .. } => DecisionKind::Allow,
                MitmproxyEvent::RequestDenied { .. } => DecisionKind::Deny,
            }),
            TrafficEvent::DenyLogger(e) => match e {
                DenyLoggerEvent::Deny(_) => Some(DecisionKind::Deny),
                // `rate_limited` is a summary, not a per-attempt decision.
                DenyLoggerEvent::RateLimited { .. } => None,
            },
        },
        Event::Lifecycle { .. } => None,
    }
}

/// Map a domain [`Event`] to its [`EventName`].
fn event_name_of(event: &Event) -> EventName {
    match event {
        Event::Traffic { event, .. } => match event {
            TrafficEvent::Dns(DnsEvent::QueryAllowed { .. }) => EventName::QueryAllowed,
            TrafficEvent::Dns(DnsEvent::QueryDenied { .. }) => EventName::QueryDenied,
            TrafficEvent::Envoy(EnvoyEvent::ConnectionAllowed(_)) => EventName::ConnectionAllowed,
            TrafficEvent::Envoy(EnvoyEvent::ConnectionDenied(_)) => EventName::ConnectionDenied,
            TrafficEvent::Mitmproxy(MitmproxyEvent::RequestAllowed { .. }) => {
                EventName::RequestAllowed
            }
            TrafficEvent::Mitmproxy(MitmproxyEvent::RequestDenied { .. }) => {
                EventName::RequestDenied
            }
            TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(_)) => EventName::Deny,
            TrafficEvent::DenyLogger(DenyLoggerEvent::RateLimited { .. }) => EventName::RateLimited,
        },
        Event::Lifecycle { event, .. } => match event {
            LifecycleEvent::GatewayBooting => EventName::GatewayBooting,
            LifecycleEvent::GatewayReady => EventName::GatewayReady,
            LifecycleEvent::PolicyApplied { .. } => EventName::PolicyApplied,
            LifecycleEvent::PolicyUpdated { .. } => EventName::PolicyUpdated,
            LifecycleEvent::PolicyResetOnUpgrade { .. } => EventName::PolicyResetOnUpgrade,
            LifecycleEvent::HealthDegraded { .. } => EventName::HealthDegraded,
            LifecycleEvent::HealthRestored { .. } => EventName::HealthRestored,
            LifecycleEvent::GatewayShutdown { .. } => EventName::GatewayShutdown,
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    use chrono::{Duration as ChronoDuration, TimeZone};

    use crate::events::{
        DenyLoggerDeny, DenyLoggerEvent, DenyProtocol, DnsEvent, EnvoyConnection, EnvoyEvent,
        EventEnvelope, GatewayShutdownReason, HealthComponent, LifecycleEvent, MitmproxyEvent,
        PolicyApplyStatus, TrafficEvent,
    };
    use crate::policy::Policy;
    use crate::session::SessionId;

    // ----- Fixture builders ------------------------------------------------

    fn ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 22, 12, 0, 0).unwrap() + ChronoDuration::milliseconds(123)
    }

    fn sid() -> SessionId {
        SessionId::parse("0123456789ab").unwrap()
    }

    fn envelope_at(ts: DateTime<Utc>) -> EventEnvelope {
        EventEnvelope {
            timestamp: ts,
            session: Some(sid()),
        }
    }

    fn envelope() -> EventEnvelope {
        envelope_at(ts())
    }

    fn conn() -> EnvoyConnection {
        EnvoyConnection {
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
        }
    }

    fn dns_allow() -> Event {
        Event::Traffic {
            envelope: envelope(),
            event: TrafficEvent::Dns(DnsEvent::QueryAllowed {
                query: "api.example.com".into(),
                qtype: "A".into(),
                resolved_ips: vec![Ipv4Addr::new(93, 184, 216, 34)],
            }),
        }
    }

    fn dns_deny() -> Event {
        Event::Traffic {
            envelope: envelope(),
            event: TrafficEvent::Dns(DnsEvent::QueryDenied {
                query: "blocked.example.com".into(),
                qtype: "AAAA".into(),
                reason: "policy_deny".into(),
            }),
        }
    }

    fn envoy_allow() -> Event {
        Event::Traffic {
            envelope: envelope(),
            event: TrafficEvent::Envoy(EnvoyEvent::ConnectionAllowed(conn())),
        }
    }

    fn envoy_deny() -> Event {
        Event::Traffic {
            envelope: envelope(),
            event: TrafficEvent::Envoy(EnvoyEvent::ConnectionDenied(conn())),
        }
    }

    fn mitm_allow() -> Event {
        Event::Traffic {
            envelope: envelope(),
            event: TrafficEvent::Mitmproxy(MitmproxyEvent::RequestAllowed {
                host: "api.example.com".into(),
                port: 443,
                method: "GET".into(),
                path: "/v1/widgets".into(),
            }),
        }
    }

    fn mitm_deny() -> Event {
        Event::Traffic {
            envelope: envelope(),
            event: TrafficEvent::Mitmproxy(MitmproxyEvent::RequestDenied {
                host: "api.example.com".into(),
                port: 443,
                method: "DELETE".into(),
                path: "/admin".into(),
                reason: "no_matching_filter".into(),
            }),
        }
    }

    fn deny_logger_deny() -> Event {
        Event::Traffic {
            envelope: envelope(),
            event: TrafficEvent::DenyLogger(DenyLoggerEvent::Deny(DenyLoggerDeny {
                orig_dst_ip: Ipv4Addr::new(203, 0, 113, 1),
                orig_dst_port: 443,
                protocol: DenyProtocol::Tcp,
                src_ip: Ipv4Addr::new(10, 0, 0, 42),
                src_port: 55123,
            })),
        }
    }

    fn deny_logger_rate_limited() -> Event {
        Event::Traffic {
            envelope: envelope(),
            event: TrafficEvent::DenyLogger(DenyLoggerEvent::RateLimited {
                rate_limited_count: 7,
                since_ts: ts(),
            }),
        }
    }

    fn lifecycle_gateway_ready() -> Event {
        Event::Lifecycle {
            envelope: envelope(),
            event: LifecycleEvent::GatewayReady,
        }
    }

    fn lifecycle_gateway_booting() -> Event {
        Event::Lifecycle {
            envelope: EventEnvelope {
                timestamp: ts(),
                session: None,
            },
            event: LifecycleEvent::GatewayBooting,
        }
    }

    fn lifecycle_policy_applied() -> Event {
        Event::Lifecycle {
            envelope: envelope(),
            event: LifecycleEvent::PolicyApplied {
                policy: Policy {
                    version: "2.0.0".into(),
                    rules: vec![],
                },
                source_presets: vec![],
                status: PolicyApplyStatus::Ok,
                error: None,
            },
        }
    }

    fn lifecycle_health_degraded() -> Event {
        Event::Lifecycle {
            envelope: envelope(),
            event: LifecycleEvent::HealthDegraded {
                component: HealthComponent::DenyLogger,
                reason: "timeout".into(),
            },
        }
    }

    fn lifecycle_gateway_shutdown() -> Event {
        Event::Lifecycle {
            envelope: envelope(),
            event: LifecycleEvent::GatewayShutdown {
                reason: GatewayShutdownReason::SessionStopped,
                error: None,
            },
        }
    }

    /// Every fixture variant, in a single vector. Reused across tests so
    /// new event types added in the future surface as test failures.
    fn all_events() -> Vec<Event> {
        vec![
            dns_allow(),
            dns_deny(),
            envoy_allow(),
            envoy_deny(),
            mitm_allow(),
            mitm_deny(),
            deny_logger_deny(),
            deny_logger_rate_limited(),
            lifecycle_gateway_booting(),
            lifecycle_gateway_ready(),
            lifecycle_policy_applied(),
            lifecycle_health_degraded(),
            lifecycle_gateway_shutdown(),
        ]
    }

    // -----------------------------------------------------------------
    // Classification helpers
    // -----------------------------------------------------------------

    #[test]
    fn layer_of_maps_every_variant() {
        assert_eq!(layer_of(&dns_allow()), LayerKind::Dns);
        assert_eq!(layer_of(&dns_deny()), LayerKind::Dns);
        assert_eq!(layer_of(&envoy_allow()), LayerKind::Envoy);
        assert_eq!(layer_of(&envoy_deny()), LayerKind::Envoy);
        assert_eq!(layer_of(&mitm_allow()), LayerKind::Mitmproxy);
        assert_eq!(layer_of(&mitm_deny()), LayerKind::Mitmproxy);
        assert_eq!(layer_of(&deny_logger_deny()), LayerKind::DenyLogger);
        assert_eq!(layer_of(&deny_logger_rate_limited()), LayerKind::DenyLogger);
        assert_eq!(layer_of(&lifecycle_gateway_ready()), LayerKind::Lifecycle);
    }

    #[test]
    fn decision_of_maps_traffic_allow_and_deny() {
        assert_eq!(decision_of(&dns_allow()), Some(DecisionKind::Allow));
        assert_eq!(decision_of(&dns_deny()), Some(DecisionKind::Deny));
        assert_eq!(decision_of(&envoy_allow()), Some(DecisionKind::Allow));
        assert_eq!(decision_of(&envoy_deny()), Some(DecisionKind::Deny));
        assert_eq!(decision_of(&mitm_allow()), Some(DecisionKind::Allow));
        assert_eq!(decision_of(&mitm_deny()), Some(DecisionKind::Deny));
        assert_eq!(decision_of(&deny_logger_deny()), Some(DecisionKind::Deny));
    }

    #[test]
    fn decision_of_is_none_for_meta_and_lifecycle() {
        // `rate_limited` is a summary, not a per-attempt decision.
        assert_eq!(decision_of(&deny_logger_rate_limited()), None);
        // Lifecycle events carry no allow/deny axis.
        for lc in [
            lifecycle_gateway_booting(),
            lifecycle_gateway_ready(),
            lifecycle_policy_applied(),
            lifecycle_health_degraded(),
            lifecycle_gateway_shutdown(),
        ] {
            assert_eq!(decision_of(&lc), None, "lifecycle must have no decision");
        }
    }

    #[test]
    fn event_name_of_matches_spec_literal() {
        assert_eq!(event_name_of(&dns_allow()).as_str(), "query_allowed");
        assert_eq!(event_name_of(&dns_deny()).as_str(), "query_denied");
        assert_eq!(event_name_of(&envoy_allow()).as_str(), "connection_allowed");
        assert_eq!(event_name_of(&envoy_deny()).as_str(), "connection_denied");
        assert_eq!(event_name_of(&mitm_allow()).as_str(), "request_allowed");
        assert_eq!(event_name_of(&mitm_deny()).as_str(), "request_denied");
        assert_eq!(event_name_of(&deny_logger_deny()).as_str(), "deny");
        assert_eq!(
            event_name_of(&deny_logger_rate_limited()).as_str(),
            "rate_limited"
        );
        assert_eq!(
            event_name_of(&lifecycle_gateway_booting()).as_str(),
            "gateway_booting"
        );
        assert_eq!(
            event_name_of(&lifecycle_gateway_ready()).as_str(),
            "gateway_ready"
        );
        assert_eq!(
            event_name_of(&lifecycle_policy_applied()).as_str(),
            "policy_applied"
        );
        assert_eq!(
            event_name_of(&lifecycle_health_degraded()).as_str(),
            "health_degraded"
        );
        assert_eq!(
            event_name_of(&lifecycle_gateway_shutdown()).as_str(),
            "gateway_shutdown"
        );
    }

    // -----------------------------------------------------------------
    // LayerKind / EventName parse + display
    // -----------------------------------------------------------------

    #[test]
    fn layer_kind_parse_round_trip_each_variant() {
        for lk in [
            LayerKind::Dns,
            LayerKind::Envoy,
            LayerKind::Mitmproxy,
            LayerKind::DenyLogger,
            LayerKind::Lifecycle,
        ] {
            let s = lk.as_str();
            assert_eq!(
                LayerKind::parse(s).unwrap(),
                lk,
                "round-trip must preserve variant for `{s}`"
            );
            assert_eq!(lk.to_string(), s, "Display must agree with as_str");
        }
    }

    #[test]
    fn layer_kind_parse_rejects_unknown() {
        let err = LayerKind::parse("quic").expect_err("unknown layer must fail");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("quic"),
                    "layer error must name the offending value; got: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn event_name_parse_round_trip_each_variant() {
        let variants = [
            EventName::QueryAllowed,
            EventName::QueryDenied,
            EventName::ConnectionAllowed,
            EventName::ConnectionDenied,
            EventName::RequestAllowed,
            EventName::RequestDenied,
            EventName::Deny,
            EventName::RateLimited,
            EventName::GatewayBooting,
            EventName::GatewayReady,
            EventName::PolicyApplied,
            EventName::PolicyUpdated,
            EventName::PolicyResetOnUpgrade,
            EventName::HealthDegraded,
            EventName::HealthRestored,
            EventName::GatewayShutdown,
        ];
        for en in variants {
            let s = en.as_str();
            assert_eq!(
                EventName::parse(s).unwrap(),
                en,
                "round-trip must preserve variant for `{s}`"
            );
            assert_eq!(en.to_string(), s, "Display must agree with as_str");
        }
    }

    #[test]
    fn event_name_parse_rejects_unknown() {
        let err = EventName::parse("connection_reset").expect_err("unknown event must fail");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("connection_reset"),
                    "event error must name the offending value; got: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // EventsFilter::matches — golden tests across axis combinations
    // -----------------------------------------------------------------

    #[test]
    fn empty_filter_matches_every_event() {
        let f = EventsFilter::default();
        for e in all_events() {
            assert!(
                f.matches(&e),
                "empty filter must accept every event; failing on {e:?}"
            );
        }
    }

    #[test]
    fn layer_axis_dns_only() {
        let mut f = EventsFilter::default();
        f.layers.insert(LayerKind::Dns);
        assert!(f.matches(&dns_allow()));
        assert!(f.matches(&dns_deny()));
        assert!(!f.matches(&envoy_allow()));
        assert!(!f.matches(&mitm_deny()));
        assert!(!f.matches(&deny_logger_deny()));
        assert!(!f.matches(&lifecycle_gateway_ready()));
    }

    #[test]
    fn layer_axis_union_dns_and_deny_logger() {
        // Mirrors the spec's repeat-param semantics:
        // `?layer=dns&layer=deny-logger`.
        let mut f = EventsFilter::default();
        f.layers.insert(LayerKind::Dns);
        f.layers.insert(LayerKind::DenyLogger);
        assert!(f.matches(&dns_allow()));
        assert!(f.matches(&deny_logger_deny()));
        assert!(f.matches(&deny_logger_rate_limited()));
        assert!(!f.matches(&envoy_allow()));
        assert!(!f.matches(&mitm_allow()));
        assert!(!f.matches(&lifecycle_gateway_ready()));
    }

    #[test]
    fn decision_axis_deny_only() {
        let mut f = EventsFilter::default();
        f.decisions.insert(DecisionKind::Deny);
        // Every per-layer deny matches.
        assert!(f.matches(&dns_deny()));
        assert!(f.matches(&envoy_deny()));
        assert!(f.matches(&mitm_deny()));
        assert!(f.matches(&deny_logger_deny()));
        // Allows and events without a decision axis do not.
        assert!(!f.matches(&dns_allow()));
        assert!(!f.matches(&envoy_allow()));
        assert!(!f.matches(&mitm_allow()));
        assert!(!f.matches(&deny_logger_rate_limited()));
        assert!(!f.matches(&lifecycle_gateway_ready()));
        assert!(!f.matches(&lifecycle_policy_applied()));
    }

    #[test]
    fn decision_axis_allow_only() {
        let mut f = EventsFilter::default();
        f.decisions.insert(DecisionKind::Allow);
        assert!(f.matches(&dns_allow()));
        assert!(f.matches(&envoy_allow()));
        assert!(f.matches(&mitm_allow()));
        assert!(!f.matches(&dns_deny()));
        assert!(!f.matches(&deny_logger_deny()));
        assert!(!f.matches(&deny_logger_rate_limited()));
        assert!(!f.matches(&lifecycle_gateway_ready()));
    }

    #[test]
    fn event_axis_single_value() {
        let mut f = EventsFilter::default();
        f.events.insert(EventName::QueryDenied);
        assert!(f.matches(&dns_deny()));
        assert!(!f.matches(&dns_allow()));
        assert!(!f.matches(&envoy_deny()));
    }

    #[test]
    fn event_axis_lifecycle_pinpoint() {
        let mut f = EventsFilter::default();
        f.events.insert(EventName::PolicyApplied);
        assert!(f.matches(&lifecycle_policy_applied()));
        assert!(!f.matches(&lifecycle_gateway_ready()));
        assert!(!f.matches(&dns_allow()));
    }

    #[test]
    fn axes_are_anded_together() {
        // layer=envoy AND decision=deny → only envoy_deny.
        let mut f = EventsFilter::default();
        f.layers.insert(LayerKind::Envoy);
        f.decisions.insert(DecisionKind::Deny);
        assert!(f.matches(&envoy_deny()));
        assert!(!f.matches(&envoy_allow()));
        assert!(!f.matches(&dns_deny()));
        assert!(!f.matches(&deny_logger_deny()));
    }

    #[test]
    fn three_axes_anded_together_narrow_to_single_variant() {
        // layer=mitmproxy AND decision=allow AND event=request_allowed
        // picks exactly one fixture.
        let mut f = EventsFilter::default();
        f.layers.insert(LayerKind::Mitmproxy);
        f.decisions.insert(DecisionKind::Allow);
        f.events.insert(EventName::RequestAllowed);
        let mut matched = 0;
        for e in all_events() {
            if f.matches(&e) {
                matched += 1;
            }
        }
        assert_eq!(
            matched, 1,
            "narrow 3-axis filter must match exactly one fixture, matched {matched}"
        );
        assert!(f.matches(&mitm_allow()));
    }

    #[test]
    fn since_far_past_matches_every_event() {
        let far_past = Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap();
        let f = EventsFilter {
            since: Some(far_past),
            ..Default::default()
        };
        for e in all_events() {
            assert!(f.matches(&e), "far-past since must match every event");
        }
    }

    #[test]
    fn since_far_future_matches_nothing() {
        let far_future = Utc.with_ymd_and_hms(3000, 1, 1, 0, 0, 0).unwrap();
        let f = EventsFilter {
            since: Some(far_future),
            ..Default::default()
        };
        for e in all_events() {
            assert!(
                !f.matches(&e),
                "far-future since must match nothing; matched on {e:?}"
            );
        }
    }

    #[test]
    fn since_millisecond_boundary_is_inclusive() {
        // Spec intent: `t >= since`. An event whose timestamp equals
        // `since` must match (no off-by-one drop at the boundary).
        let boundary = ts();
        let f = EventsFilter {
            since: Some(boundary),
            ..Default::default()
        };
        let event = dns_allow();
        assert_eq!(
            event.envelope().timestamp,
            boundary,
            "sanity: fixture timestamp matches boundary"
        );
        assert!(
            f.matches(&event),
            "since is inclusive: `t == since` must match"
        );

        // One millisecond before the boundary must not match.
        let earlier_event = Event::Traffic {
            envelope: envelope_at(boundary - ChronoDuration::milliseconds(1)),
            event: TrafficEvent::Dns(DnsEvent::QueryAllowed {
                query: "x".into(),
                qtype: "A".into(),
                resolved_ips: vec![],
            }),
        };
        assert!(
            !f.matches(&earlier_event),
            "`t < since` must not match even by 1 ms"
        );

        // One millisecond after the boundary must match.
        let later_event = Event::Traffic {
            envelope: envelope_at(boundary + ChronoDuration::milliseconds(1)),
            event: TrafficEvent::Dns(DnsEvent::QueryAllowed {
                query: "x".into(),
                qtype: "A".into(),
                resolved_ips: vec![],
            }),
        };
        assert!(
            f.matches(&later_event),
            "`t > since` must match: 1 ms beyond boundary"
        );
    }

    // -----------------------------------------------------------------
    // EventsFilter::from_query
    // -----------------------------------------------------------------

    #[test]
    fn from_query_empty_dto_yields_empty_filter() {
        let q = EventsQueryDto::default();
        let f = EventsFilter::from_query(&q).expect("empty dto is valid");
        assert!(f.layers.is_empty());
        assert!(f.decisions.is_empty());
        assert!(f.events.is_empty());
        assert!(f.since.is_none());
    }

    #[test]
    fn from_query_full_valid_dto() {
        let q = EventsQueryDto {
            follow: true,
            layer: vec!["dns".into(), "deny-logger".into()],
            decision: vec!["deny".into()],
            event: vec!["query_denied".into(), "deny".into()],
            since: Some("2026-04-22T12:00:00Z".into()),
        };
        let f = EventsFilter::from_query(&q).expect("valid dto");
        assert!(f.layers.contains(&LayerKind::Dns));
        assert!(f.layers.contains(&LayerKind::DenyLogger));
        assert!(f.decisions.contains(&DecisionKind::Deny));
        assert!(f.events.contains(&EventName::QueryDenied));
        assert!(f.events.contains(&EventName::Deny));
        assert!(f.since.is_some());
    }

    #[test]
    fn events_filter_from_query_rejects_unknown_decision() {
        let q = EventsQueryDto {
            decision: vec!["reset".into()],
            ..Default::default()
        };
        let err = EventsFilter::from_query(&q).expect_err("unknown decision must fail");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("reset"),
                    "error must name the offending decision; got: {msg}"
                );
                assert!(
                    msg.contains("decision"),
                    "error must identify the rejected axis; got: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn events_filter_from_query_rejects_unknown_layer() {
        let q = EventsQueryDto {
            layer: vec!["dns".into(), "quic".into()],
            ..Default::default()
        };
        let err = EventsFilter::from_query(&q).expect_err("unknown layer must fail");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("quic"),
                    "error must name the offending layer; got: {msg}"
                );
                assert!(
                    msg.contains("layer"),
                    "error must identify the rejected axis; got: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn events_filter_from_query_rejects_unknown_event() {
        let q = EventsQueryDto {
            event: vec!["query_allowed".into(), "connection_reset".into()],
            ..Default::default()
        };
        let err = EventsFilter::from_query(&q).expect_err("unknown event must fail");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("connection_reset"),
                    "error must name the offending event; got: {msg}"
                );
                assert!(
                    msg.contains("event"),
                    "error must identify the rejected axis; got: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn events_filter_from_query_bubbles_malformed_since() {
        let q = EventsQueryDto {
            since: Some("yesterday".into()),
            ..Default::default()
        };
        let err = EventsFilter::from_query(&q).expect_err("malformed since must fail");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("yesterday"),
                    "error must name the offending since; got: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }
}
