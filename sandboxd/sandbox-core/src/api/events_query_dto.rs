//! Wire shape for `GET /sessions/{id}/events` query parameters.
//!
//! Defines the deserialization target for axum's `Query` extractor: a
//! pure, string-typed record of what the caller asked for. No domain
//! coercion happens at the serde boundary — that is the job of
//! [`super::events_filter::EventsFilter::from_query`], which is the
//! single place where unknown layer / decision / event values fail
//! loud as [`crate::error::SandboxError::InvalidArgument`].
//!
//! The query parameter shape follows the HTTP endpoint contract:
//!
//! ```text
//! GET /sessions/{id}/events?follow=true&layer=<name>&decision=<allow|deny>
//!     &event=<name>&since=<ts>
//! ```
//!
//! All fields are optional on the wire. The serde `#[serde(default)]`
//! attributes let callers omit any field they do not care about, which
//! matches the "empty filter matches everything" intuition
//! implemented by [`super::events_filter`].

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::SandboxError;

/// Parsed query string for `GET /sessions/{id}/events`.
///
/// Field semantics mirror the query-string syntax exactly:
///
/// - `follow`: when `true`, the HTTP handler streams chunked JSONL;
///   when `false` (default), it replays the current ring buffer and
///   closes the response.
/// - `layer`, `decision`, `event`: repeatable filter axes. `Vec<String>`
///   preserves axum's repeat semantics (`?layer=a&layer=b` → two
///   entries).
/// - `since`: RFC 3339 timestamp; see [`Self::parse_since`].
///
/// Unknown fields on the query string are ignored by default (serde's
/// standard behaviour) which keeps the wire forward-compatible: a
/// future filter axis added by the server will not break older clients
/// that send an older subset of fields, and vice versa.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventsQueryDto {
    /// When `true`, the response is a live stream; when `false` (default),
    /// the response is a bounded replay of the current ring buffer.
    #[serde(default)]
    pub follow: bool,

    /// Zero-or-more `layer` values to include. Empty means "no
    /// constraint on layer".
    #[serde(default)]
    pub layer: Vec<String>,

    /// Zero-or-more `decision` values to include. Empty means "no
    /// constraint on decision". Valid values are `"allow"` and
    /// `"deny"`; anything else makes
    /// [`super::events_filter::EventsFilter::from_query`] fail with
    /// [`SandboxError::InvalidArgument`].
    #[serde(default)]
    pub decision: Vec<String>,

    /// Zero-or-more `event` values to include. Empty means "no
    /// constraint on event name".
    #[serde(default)]
    pub event: Vec<String>,

    /// Optional lower-bound timestamp in RFC 3339 format. Parsed by
    /// [`Self::parse_since`].
    #[serde(default)]
    pub since: Option<String>,
}

impl EventsQueryDto {
    /// Parse the caller-provided `since` string, if any, into a
    /// [`DateTime<Utc>`].
    ///
    /// Returns:
    ///
    /// - `Ok(None)` when the caller did not provide `since`.
    /// - `Ok(Some(ts))` on successful RFC 3339 parse (both second-
    ///   precision forms like `2026-04-22T12:00:00Z` and fractional
    ///   forms like `2026-04-22T12:00:00.123456789Z` are accepted).
    /// - `Err(SandboxError::InvalidArgument(_))` on malformed input.
    ///   The error message names the offending value so the operator
    ///   can spot the typo in the request log.
    pub fn parse_since(&self) -> Result<Option<DateTime<Utc>>, SandboxError> {
        let Some(raw) = self.since.as_deref() else {
            return Ok(None);
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        DateTime::parse_from_rfc3339(trimmed)
            .map(|dt| Some(dt.with_timezone(&Utc)))
            .map_err(|e| {
                SandboxError::InvalidArgument(format!(
                    "invalid `since` value `{trimmed}`: expected RFC 3339 timestamp: {e}"
                ))
            })
    }
}

/// Canonical DTO-internal representation of a `decision` filter value.
///
/// Kept as a tiny enum rather than a raw string so downstream code
/// (`EventsFilter::matches`) can dispatch without re-parsing. The
/// [`Self::parse`] helper is the single conversion point; it rejects
/// anything other than the two wire-canonical values (`allow` or `deny`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionKind {
    Allow,
    Deny,
}

impl DecisionKind {
    /// Parse a caller-provided decision string into a [`DecisionKind`].
    ///
    /// Accepts `"allow"` and `"deny"` (case-sensitive — the design
    /// prescribes lowercase). Any other value returns
    /// [`SandboxError::InvalidArgument`] with the offending text in
    /// the message.
    pub fn parse(s: &str) -> Result<Self, SandboxError> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            other => Err(SandboxError::InvalidArgument(format!(
                "invalid `decision` value `{other}`: expected `allow` or `deny`"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // EventsQueryDto::parse_since
    // -----------------------------------------------------------------

    #[test]
    fn parse_since_none_when_absent() {
        let q = EventsQueryDto::default();
        assert!(q.parse_since().expect("no since is ok").is_none());
    }

    #[test]
    fn parse_since_none_when_empty_or_whitespace() {
        let q = EventsQueryDto {
            since: Some("   ".into()),
            ..Default::default()
        };
        assert!(
            q.parse_since()
                .expect("whitespace treated as absent")
                .is_none(),
            "an all-whitespace since should parse as absent, not as an error"
        );

        let q = EventsQueryDto {
            since: Some(String::new()),
            ..Default::default()
        };
        assert!(q.parse_since().expect("empty treated as absent").is_none());
    }

    #[test]
    fn parse_since_accepts_rfc3339_with_fractional_seconds() {
        // Both a plain second-precision timestamp and a fractional form
        // must parse successfully. The design says "RFC 3339"; chrono's
        // `parse_from_rfc3339` handles both shapes.
        for raw in [
            "2026-04-22T12:00:00Z",
            "2026-04-22T12:00:00.123Z",
            "2026-04-22T12:00:00.123456789Z",
        ] {
            let q = EventsQueryDto {
                since: Some(raw.into()),
                ..Default::default()
            };
            let parsed = q
                .parse_since()
                .unwrap_or_else(|e| panic!("rfc3339 `{raw}` must parse: {e}"))
                .unwrap_or_else(|| panic!("rfc3339 `{raw}` must produce Some"));
            // Sanity: the UTC date must roll into 2026-04-22.
            assert_eq!(parsed.date_naive().to_string(), "2026-04-22");
        }
    }

    #[test]
    fn parse_since_rejects_garbage() {
        let q = EventsQueryDto {
            since: Some("yesterday".into()),
            ..Default::default()
        };
        let err = q.parse_since().expect_err("garbage `since` must fail loud");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("yesterday"),
                    "error message must carry the offending value; got: {msg}"
                );
                assert!(
                    msg.contains("RFC 3339"),
                    "error message should cite the expected format; got: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // EventsQueryDto serde defaults
    // -----------------------------------------------------------------
    //
    // These tests pin the serde-level contract: every field must be
    // `#[serde(default)]` so an empty/partial object deserializes
    // cleanly. Axum's query-string extraction is verified in the
    // HTTP-layer tests.

    #[test]
    fn deserialize_empty_object_uses_defaults() {
        let q: EventsQueryDto = serde_json::from_str("{}").expect("empty object");
        assert!(!q.follow);
        assert!(q.layer.is_empty());
        assert!(q.decision.is_empty());
        assert!(q.event.is_empty());
        assert!(q.since.is_none());
    }

    #[test]
    fn deserialize_partial_object_fills_in_defaults() {
        let q: EventsQueryDto =
            serde_json::from_str(r#"{"follow": true}"#).expect("partial object");
        assert!(q.follow);
        assert!(q.layer.is_empty());
        assert!(q.decision.is_empty());
        assert!(q.event.is_empty());
        assert!(q.since.is_none());
    }

    // -----------------------------------------------------------------
    // DecisionKind::parse
    // -----------------------------------------------------------------

    #[test]
    fn decision_kind_parse_accepts_spec_values() {
        assert_eq!(DecisionKind::parse("allow").unwrap(), DecisionKind::Allow);
        assert_eq!(DecisionKind::parse("deny").unwrap(), DecisionKind::Deny);
    }

    #[test]
    fn decision_kind_parse_rejects_other_values() {
        for bad in ["Allow", "DENY", "reset", "permit", "", " allow"] {
            match DecisionKind::parse(bad) {
                Err(SandboxError::InvalidArgument(_)) => {}
                Ok(v) => panic!("bad decision `{bad}` should not parse, got {v:?}"),
                Err(other) => {
                    panic!("bad decision `{bad}` should yield InvalidArgument, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn decision_kind_parse_error_carries_offending_value() {
        let err = DecisionKind::parse("reset").expect_err("unknown decision must fail");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("reset"),
                    "decision error must name the offending value; got: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }
}
