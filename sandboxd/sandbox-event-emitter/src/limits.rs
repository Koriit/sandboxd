//! Per-second event rate cap + periodic `rate_limited` summary.
//!
//! Design reference: `2026-04-21-port-explicit-policies-presets-observability-design.md`
//! Part 3 / "Hardening rules".
//!
//! The deny-logger (and the allow-logger that shares this crate)
//! must not spam its JSONL file — a misbehaving VM could open
//! thousands of denied connections per second and drown the ingest
//! pipeline. We cap admitted events at `rate_cap` per rolling 1-second
//! window. Excess attempts are *not* emitted; they are counted and
//! surfaced on a periodic `rate_limited` summary event that carries
//! the drop count and the window start timestamp.
//!
//! ## Design
//!
//! `RateCap` holds four atomics: a window-start epoch (millis), an
//! admission counter, a drop counter, and an emitter handle. Every
//! `try_admit(now)` call either:
//!
//! 1. observes a stale window → atomic CAS to roll forward (single
//!    winner flushes a summary if drops > 0 in the old window);
//! 2. increments the admission counter → `Admit::Ok` if under cap;
//! 3. increments the drop counter → `Admit::RateLimited` otherwise.
//!
//! A background ticker ([`spawn_flush_ticker`]) polls once per second
//! so a storm that ends exactly at a window boundary still flushes its
//! summary promptly even when no further traffic arrives.
//!
//! ## Concurrency
//!
//! Listener threads call `try_admit` on the hot path. The CAS loop
//! guarantees exactly one thread wins the rollover; losers re-read and
//! proceed. The atomics use `Ordering::Relaxed` for the counters (per-
//! window counts don't need cross-thread ordering with any other
//! value) and `Ordering::AcqRel` on the CAS (establishes a
//! happens-before between the summary flush and subsequent increments).

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};

use crate::event::EventEmitter;

/// 1-second rolling window — matches the "1000 events/s per
/// session" shape. Defined here so tests and the flush ticker agree.
pub const WINDOW: Duration = Duration::from_secs(1);

/// Outcome of a single admission attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// The event is under the cap — caller proceeds to emit.
    Ok,
    /// The event exceeds the cap — caller must *not* emit; the drop
    /// has been counted into the current window's summary.
    RateLimited,
}

/// Per-session admission gate. Cloneable via `Arc`.
pub struct RateCap {
    cap: u32,
    window_start_millis: AtomicI64,
    accepted: AtomicU32,
    dropped: AtomicU32,
    emitter: Arc<EventEmitter>,
}

impl RateCap {
    /// Construct a new gate with `cap` events per [`WINDOW`].
    ///
    /// `now` is captured as the initial window start so the first
    /// `try_admit` call doesn't race a zero epoch.
    pub fn new(cap: u32, emitter: Arc<EventEmitter>, now: DateTime<Utc>) -> Self {
        Self {
            cap,
            window_start_millis: AtomicI64::new(now.timestamp_millis()),
            accepted: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
            emitter,
        }
    }

    /// Account for one admission attempt at wall-clock `now`.
    ///
    /// Rolls the window forward if `now` has passed the current
    /// window's end; the rolling thread flushes the prior window's
    /// summary (if any drops occurred) before releasing the CAS.
    pub fn try_admit(&self, now: DateTime<Utc>) -> Admit {
        self.maybe_rollover(now);
        let count = self.accepted.fetch_add(1, Ordering::Relaxed);
        if count < self.cap {
            Admit::Ok
        } else {
            // Undo the speculative admission so the counter never
            // exceeds `cap + N(drops)` and saturates.
            self.accepted.fetch_sub(1, Ordering::Relaxed);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            Admit::RateLimited
        }
    }

    /// Count one drop *without* attempting admission. Used by the TCP
    /// concurrency-cap path, where the refusal happens at accept and
    /// no deny event is ever eligible — the drop still feeds the
    /// periodic summary per.
    pub fn record_drop(&self, now: DateTime<Utc>) {
        self.maybe_rollover(now);
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Roll the window forward if `now` is past the current window's
    /// end. Exactly one caller wins the CAS and is responsible for
    /// flushing a summary for the closing window.
    fn maybe_rollover(&self, now: DateTime<Utc>) {
        let now_ms = now.timestamp_millis();
        let window_ms = WINDOW.as_millis() as i64;
        loop {
            let start = self.window_start_millis.load(Ordering::Acquire);
            if now_ms < start.saturating_add(window_ms) {
                return; // still in the same window
            }
            // Snap the new window to the rolling boundary so small
            // clock skew doesn't drift the window indefinitely.
            let advance = ((now_ms - start) / window_ms) * window_ms;
            let next = start.saturating_add(advance.max(window_ms));
            if self
                .window_start_millis
                .compare_exchange(start, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.flush_window(start);
                return;
            }
            // Lost the CAS — another thread rolled; re-read and check.
        }
    }

    /// Reset the per-window counters and emit a `rate_limited` summary
    /// if any drops occurred.
    fn flush_window(&self, since_ms: i64) {
        // Swap instead of store so we observe the final values
        // deposited by any lingering concurrent increments.
        self.accepted.store(0, Ordering::Relaxed);
        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let since_ts = millis_to_utc(since_ms);
            self.emitter.emit_rate_limited(dropped, since_ts);
        }
    }

    /// Flush the current window unconditionally. Called from the
    /// SIGTERM / SIGINT shutdown path so quiescent-tail drops are
    /// reported before the process exits. Exercised by
    /// `flush_now_emits_pending_summary`.
    pub fn flush_now(&self, now: DateTime<Utc>) {
        // Force a rollover — sets a fresh window and flushes the old
        // one (which may emit). If the current window has no drops,
        // `flush_window` is a no-op beyond the zero-writes.
        let now_ms = now.timestamp_millis();
        let window_ms = WINDOW.as_millis() as i64;
        loop {
            let start = self.window_start_millis.load(Ordering::Acquire);
            // Advance at least one window, even if we're mid-bucket,
            // so the closing flush always runs.
            // Guard against clock regression: we advance by at least one
            // window even if now < start (otherwise `now_ms - start` is
            // negative and `.max(window_ms)` falls back to `window_ms`).
            let next = start.saturating_add(window_ms.max(now_ms - start));
            if self
                .window_start_millis
                .compare_exchange(start, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.flush_window(start);
                return;
            }
        }
    }
}

/// Convert a unix-millis timestamp to a UTC `DateTime`. Values outside
/// chrono's representable range fall back to the unix epoch — the cap
/// itself is bounded to the last ~292M years so this is defensive only.
fn millis_to_utc(ms: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(ms).single().unwrap_or_else(|| {
        tracing::warn!(millis = ms, "rate-cap window start out of range");
        Utc.timestamp_millis_opt(0).single().unwrap_or_default()
    })
}

/// Spawn a 1-second ticker that invokes `RateCap::maybe_rollover`. The
/// ticker exists so a storm that ends exactly at a window boundary
/// still flushes its summary promptly when no further traffic arrives.
///
/// Returns a `JoinHandle` the caller can abort on shutdown.
pub fn spawn_flush_ticker(cap: Arc<RateCap>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(WINDOW);
        // Skip the immediate first tick — nothing to flush at start-up.
        interval.tick().await;
        loop {
            interval.tick().await;
            cap.maybe_rollover(Utc::now());
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::path::Path;

    fn read_lines(path: &Path) -> Vec<String> {
        let file = std::fs::File::open(path).expect("open jsonl");
        BufReader::new(file)
            .lines()
            .map(|l| l.expect("read line"))
            .collect()
    }

    /// Fire `cap + overflow` admissions inside a single window and
    /// assert the drop is counted and surfaced on the next rollover.
    /// Covers plan Phase 3 / `rate_cap_produces_summary_event`.
    #[test]
    fn rate_cap_produces_summary_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = Arc::new(EventEmitter::open(&path, "deny-logger").unwrap());
        let t0 = Utc
            .timestamp_millis_opt(1_700_000_000_000)
            .single()
            .unwrap();
        let cap = RateCap::new(10, Arc::clone(&emitter), t0);

        // 10 under-cap + 5 over-cap admissions, all inside the first
        // window (t0 + 500 ms).
        let mid = t0 + chrono::Duration::milliseconds(500);
        let mut admitted = 0u32;
        let mut dropped = 0u32;
        for _ in 0..15 {
            match cap.try_admit(mid) {
                Admit::Ok => admitted += 1,
                Admit::RateLimited => dropped += 1,
            }
        }
        assert_eq!(admitted, 10, "cap is 10");
        assert_eq!(dropped, 5);

        // Before the window closes, no summary has been emitted.
        let lines_before = read_lines(&path);
        assert!(
            lines_before.is_empty(),
            "summary must wait for window rollover; got {lines_before:?}"
        );

        // Cross the window boundary — the next admission triggers the
        // rollover and flushes the summary for the closing window.
        let after = t0 + chrono::Duration::milliseconds(1_500);
        assert_eq!(cap.try_admit(after), Admit::Ok);

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1, "one summary line; got {lines:?}");
        let json: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(json["event"], "rate_limited");
        assert_eq!(json["layer"], "deny-logger");
        assert_eq!(json["rate_limited_count"], 5);
        // `since_ts` must be the *closing* window's start, not the
        // rollover timestamp. Compare as `DateTime` rather than string
        // so formatting differences (millisecond truncation, `Z` vs
        // `+00:00`) don't leak into the assertion.
        let since_ts: DateTime<Utc> = serde_json::from_value(json["since_ts"].clone()).unwrap();
        assert_eq!(since_ts, t0);
    }

    /// `record_drop` feeds the same counter as `try_admit` over-cap —
    /// exercise the TCP concurrency-cap path.
    #[test]
    fn record_drop_feeds_summary_counter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = Arc::new(EventEmitter::open(&path, "deny-logger").unwrap());
        let t0 = Utc
            .timestamp_millis_opt(1_700_000_000_000)
            .single()
            .unwrap();
        let cap = RateCap::new(1_000, Arc::clone(&emitter), t0);

        for _ in 0..7 {
            cap.record_drop(t0);
        }
        // Cross window boundary → flush.
        let after = t0 + chrono::Duration::milliseconds(1_100);
        cap.try_admit(after);

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1);
        let json: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(json["event"], "rate_limited");
        assert_eq!(json["rate_limited_count"], 7);
    }

    /// `flush_now` is the SIGTERM path — it must emit a pending
    /// summary even if no admission attempt crosses the window.
    #[test]
    fn flush_now_emits_pending_summary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = Arc::new(EventEmitter::open(&path, "deny-logger").unwrap());
        let t0 = Utc
            .timestamp_millis_opt(1_700_000_000_000)
            .single()
            .unwrap();
        let cap = RateCap::new(2, Arc::clone(&emitter), t0);

        // Two admitted, one dropped — all in window 0.
        cap.try_admit(t0);
        cap.try_admit(t0);
        assert_eq!(cap.try_admit(t0), Admit::RateLimited);

        // Call flush_now well inside the same window.
        cap.flush_now(t0 + chrono::Duration::milliseconds(100));

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1);
        let json: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(json["rate_limited_count"], 1);
    }

    /// A silent window (no drops) must not emit a summary.
    #[test]
    fn empty_window_emits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.jsonl");
        let emitter = Arc::new(EventEmitter::open(&path, "deny-logger").unwrap());
        let t0 = Utc
            .timestamp_millis_opt(1_700_000_000_000)
            .single()
            .unwrap();
        let cap = RateCap::new(10, Arc::clone(&emitter), t0);

        cap.try_admit(t0); // 1 admission, 0 drops
        let after = t0 + chrono::Duration::milliseconds(2_500);
        cap.try_admit(after); // crosses two windows

        let lines = read_lines(&path);
        assert!(lines.is_empty(), "no drops → no summary; got {lines:?}");
    }
}
