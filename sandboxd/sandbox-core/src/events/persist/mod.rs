//! Persistent JSONL sink for the event bus.
//!
//! A [`PersistentSink`] subscribes to the [`EventBus`]'s global
//! cross-session stream (see [`EventBus::subscribe_global`]) and
//! writes each event into a per-`(session, layer, UTC date)` JSONL
//! file under
//! `{base_dir}/sessions/{session_id}/events/{layer}-YYYY-MM-DD.jsonl`.
//! A separate pruner task walks the tree hourly and removes files
//! older than `retention_days`.
//!
//! # Task graph
//!
//! [`PersistentSink::spawn`] wires three cooperating tasks:
//!
//! ```text
//!   global broadcast ──► relay ──► bounded mpsc ──► sink ──► rotating writers
//!                                    (100k)
//!                                      │
//!                                      └── drop-oldest on overflow + warn!
//!
//!   timer (hourly) ───► pruner ──► filesystem sweep
//! ```
//!
//! The **relay** task owns the broadcast [`Receiver`][r] and pushes
//! every event into a bounded [`tokio::sync::mpsc`] channel using
//! `try_send`. When the channel is full (the sink task is not draining
//! fast enough), the relay drops the oldest queued event to make room
//! and logs a `warn!` with a running drop counter. The rationale —
//! per Phase 0 Q8 — is that persistent logging must never stall the
//! in-memory bus; a burst that outruns the disk is observable via the
//! counter and the warn stream rather than backpressuring producers.
//!
//! The **sink** task owns the [`RotatingWriterMap`] and is the sole
//! writer — no interior locking is required. For each event it
//! classifies the [`LayerKind`], renders the JSONL line via
//! [`event_to_jsonl_line`], and calls `write` on the rotating map.
//! I/O errors are logged and swallowed; a one-off disk failure does
//! not bring down the sink.
//!
//! The **pruner** task runs on a [`tokio::time::interval`] (hourly by
//! default, overridable in tests via
//! `SANDBOX_TEST_PRUNER_INTERVAL_SECS`) and calls [`prune_once`] each
//! tick. Errors inside the sweep are logged at `warn!`; the task
//! never returns on its own — it is aborted at shutdown.
//!
//! [r]: tokio::sync::broadcast::Receiver
//!
//! # Shutdown
//!
//! [`PersistentSink::shutdown`] aborts all three task handles and
//! awaits their join. Abort is a clean shape here: the sink task may
//! drop a few in-flight events, but the on-disk file is always
//! consistent because every `write` is a full JSONL line terminated
//! by `\n` (see [`super::super::api::event_to_jsonl_line`]) and the
//! kernel flushes the `O_APPEND` buffer on close.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::api::event_to_jsonl_line;
use crate::api::events_filter::layer_of;
use crate::events::{Event, EventBus};

mod pruner;
mod rotator;
mod writer;

pub use pruner::prune_once;

use rotator::{RotatingWriterMap, SystemClock};

/// Bounded capacity of the relay→sink mpsc channel.
///
/// Phase 0 Q8: oversized (100k) so a burst up to ~10 seconds of
/// 10 000 events/s is absorbed without drops. When the buffer
/// genuinely fills, the relay drops the event and logs `warn!` with
/// the running counter — the persistent sink is best-effort and
/// never backpressures the bus.
const RELAY_CHANNEL_CAPACITY: usize = 100_000;

/// Configuration for the persistent sink.
#[derive(Debug, Clone)]
pub struct PersistConfig {
    /// Master switch. When `false`, [`PersistentSink::spawn`] still
    /// returns a handle, but no tasks are launched and `shutdown`
    /// resolves immediately. This keeps the call-site on the daemon
    /// main path uniform regardless of whether persistence is
    /// enabled.
    pub enabled: bool,
    /// Root directory for persistent event files. The full layout is
    /// `{base_dir}/sessions/{session_id}/events/{layer}-YYYY-MM-DD.jsonl`.
    /// Parent directories are created on demand by the writer.
    pub base_dir: PathBuf,
    /// How many days of JSONL files to keep. A file whose filename-
    /// embedded date is strictly older than `today - retention_days`
    /// is removed by the pruner. Phase 0 Q10 pins the default to
    /// 14 days in the daemon-side CLI; this struct stays value-
    /// neutral and accepts whatever operators configure.
    pub retention_days: u32,
}

/// Running persistent sink with handles for its internal tasks.
///
/// The handle set is held until [`Self::shutdown`] is called, at
/// which point every task is aborted and joined. A disabled
/// [`PersistConfig`] produces an `enabled: false` sink whose
/// `shutdown` is a no-op.
pub struct PersistentSink {
    /// `None` when the sink is configured but disabled, or after
    /// [`Self::shutdown`] has consumed the handles.
    tasks: Option<SinkTasks>,
    /// Running count of events the relay dropped because the
    /// bounded mpsc was full. Exposed for tests and future
    /// observability — the daemon does not surface this on the
    /// HTTP API today.
    dropped_events: Arc<AtomicU64>,
}

struct SinkTasks {
    relay: JoinHandle<()>,
    sink: JoinHandle<()>,
    pruner: JoinHandle<()>,
}

impl PersistentSink {
    /// Spawn the relay, sink, and pruner tasks for `config`.
    ///
    /// When `config.enabled == false`, no tasks are spawned; the
    /// returned handle's [`Self::shutdown`] is a no-op. This lets
    /// the daemon wire the call-site unconditionally and toggle
    /// persistence via CLI flag without branching around
    /// `PersistentSink`.
    pub fn spawn(event_bus: &EventBus, config: PersistConfig) -> Self {
        if !config.enabled {
            return Self {
                tasks: None,
                dropped_events: Arc::new(AtomicU64::new(0)),
            };
        }

        info!(
            base_dir = %config.base_dir.display(),
            retention_days = config.retention_days,
            "persistent event sink: starting"
        );

        let (replay, rx) = event_bus.subscribe_global();
        let (mpsc_tx, mpsc_rx) = mpsc::channel::<Arc<Event>>(RELAY_CHANNEL_CAPACITY);

        let dropped_events = Arc::new(AtomicU64::new(0));

        // Relay: broadcast → bounded mpsc. Drops on overflow with
        // warn! + counter. Owns `replay` and `rx`.
        let relay_dropped = Arc::clone(&dropped_events);
        let relay = tokio::spawn(async move {
            relay_loop(replay, rx, mpsc_tx, relay_dropped).await;
        });

        // Sink: bounded mpsc → rotating JSONL writer. Owns the
        // rotating writer map.
        let sink_base_dir = config.base_dir.clone();
        let sink = tokio::spawn(async move {
            sink_loop(mpsc_rx, sink_base_dir).await;
        });

        // Pruner: hourly sweep over the on-disk tree.
        let pruner_base_dir = config.base_dir.clone();
        let pruner = tokio::spawn(async move {
            pruner::run_loop(pruner_base_dir, config.retention_days).await;
        });

        Self {
            tasks: Some(SinkTasks {
                relay,
                sink,
                pruner,
            }),
            dropped_events,
        }
    }

    /// Drop counter — number of events the relay could not enqueue
    /// because the bounded channel was full. Useful for tests;
    /// exposed as a plain `u64` rather than the inner `Arc` so
    /// callers cannot mutate it.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// Abort every internal task and await them.
    ///
    /// Safe to call on a disabled sink (no-op). After this returns,
    /// all three tasks are guaranteed to have finished (either
    /// because they observed the abort or because they had already
    /// exited).
    pub async fn shutdown(mut self) {
        let Some(tasks) = self.tasks.take() else {
            return;
        };
        tasks.relay.abort();
        tasks.sink.abort();
        tasks.pruner.abort();
        // Join-after-abort: an aborted task resolves to `Err(JoinError::Cancelled)`.
        // Treat both Ok and Err as completion; we only care that each task is
        // actually finished before returning so the file handles it owned are
        // dropped (closing the underlying `File` handles deterministically).
        let _ = tasks.relay.await;
        let _ = tasks.sink.await;
        let _ = tasks.pruner.await;
        debug!("persistent event sink: shutdown complete");
    }
}

/// Relay task body: drain `replay` (the global ring snapshot) into
/// the mpsc, then continue pulling from `rx` for live events.
///
/// A broadcast `recv` returning `RecvError::Lagged(n)` means the
/// global buffer overflowed and we skipped `n` events; we log at
/// `warn!` and keep going. `RecvError::Closed` means the [`EventBus`]
/// was dropped (daemon shutdown in progress) — the task exits
/// cleanly.
async fn relay_loop(
    replay: Vec<Arc<Event>>,
    mut rx: tokio::sync::broadcast::Receiver<Arc<Event>>,
    tx: mpsc::Sender<Arc<Event>>,
    dropped: Arc<AtomicU64>,
) {
    // First, drain the replay.
    for ev in replay {
        forward_or_drop(&tx, ev, &dropped);
    }
    // Then live events.
    loop {
        match rx.recv().await {
            Ok(ev) => forward_or_drop(&tx, ev, &dropped),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                warn!(
                    lagged = n,
                    "persistent sink relay: lagged; events skipped"
                );
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                debug!("persistent sink relay: global bus closed; exiting");
                return;
            }
        }
    }
}

/// Push `ev` into the bounded mpsc, or drop it with a logged warn
/// and bumped counter if the channel is full. Uses `try_send` so
/// the relay never blocks.
fn forward_or_drop(tx: &mpsc::Sender<Arc<Event>>, ev: Arc<Event>, dropped: &AtomicU64) {
    if let Err(e) = tx.try_send(ev) {
        match e {
            mpsc::error::TrySendError::Full(_) => {
                let total = dropped.fetch_add(1, Ordering::Relaxed) + 1;
                // Log every drop; operators need to know when persistence is
                // falling behind. tracing's rate-limiting layer (if
                // configured) is expected to coalesce these in hot
                // scenarios; here we prefer to make the signal loud.
                warn!(
                    dropped_total = total,
                    "persistent sink: mpsc full; dropping event"
                );
            }
            mpsc::error::TrySendError::Closed(_) => {
                debug!("persistent sink: mpsc closed; relay exiting on next iteration");
            }
        }
    }
}

/// Sink task body: drain the mpsc and write each event to the
/// rotating writer map. I/O errors are logged and skipped.
async fn sink_loop(mut rx: mpsc::Receiver<Arc<Event>>, base_dir: PathBuf) {
    let clock = SystemClock;
    let mut writers = RotatingWriterMap::new();
    while let Some(event) = rx.recv().await {
        // An event on the global stream always carries a session id
        // (per `EventBus::publish` contract — events with no session
        // are dropped at publish time). Defensive check anyway.
        let Some(session_id) = event.session().copied() else {
            warn!("persistent sink: global stream delivered session-less event; skipping");
            continue;
        };
        let layer = layer_of(&event);
        let line = match event_to_jsonl_line(&event) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "persistent sink: failed to serialize event; skipping");
                continue;
            }
        };
        if let Err(e) = writers
            .write(&clock, &base_dir, &session_id, layer, &line)
            .await
        {
            warn!(
                error = %e,
                session_id = %session_id,
                layer = %layer,
                "persistent sink: failed to append JSONL line; skipping"
            );
        }
    }
    debug!("persistent sink: mpsc closed; sink exiting");
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;
    use std::time::Duration;

    use chrono::Utc;
    use tempfile::tempdir;
    use tokio::fs;
    use tokio::time::{sleep, timeout};

    use crate::api::LayerKind;
    use crate::events::{
        DnsEvent, EventBus, EventBusConfig, EventEnvelope, LifecycleEvent, TrafficEvent,
    };
    use crate::session::SessionId;

    fn dns_allow(sid: SessionId, query: &str) -> Event {
        Event::Traffic {
            envelope: EventEnvelope {
                timestamp: Utc::now(),
                session: Some(sid),
            },
            event: TrafficEvent::Dns(DnsEvent::QueryAllowed {
                query: query.into(),
                qtype: "A".into(),
                resolved_ips: vec![Ipv4Addr::new(10, 0, 0, 1)],
            }),
        }
    }

    fn lifecycle_ready(sid: SessionId) -> Event {
        Event::Lifecycle {
            envelope: EventEnvelope {
                timestamp: Utc::now(),
                session: Some(sid),
            },
            event: LifecycleEvent::GatewayReady,
        }
    }

    /// Helper: wait for at least `n` lines to appear in `path` or
    /// time out. The sink task runs async, so a bare fs read after
    /// `publish` can race.
    async fn wait_for_lines(path: &std::path::Path, at_least: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(s) = fs::read_to_string(path).await {
                let count = s.lines().count();
                if count >= at_least {
                    return;
                }
            }
            if std::time::Instant::now() > deadline {
                let actual = fs::read_to_string(path)
                    .await
                    .unwrap_or_else(|_| "<missing>".into());
                panic!(
                    "timeout waiting for >= {at_least} lines in {}; got:\n{}",
                    path.display(),
                    actual
                );
            }
            sleep(Duration::from_millis(25)).await;
        }
    }

    #[tokio::test]
    async fn disabled_config_is_noop() {
        // With `enabled: false` we still return a handle, but no
        // tasks exist — `dropped_events` starts at 0 and `shutdown`
        // resolves instantly without hanging on a missing abort.
        let dir = tempdir().unwrap();
        let bus = EventBus::default();
        let sink = PersistentSink::spawn(
            &bus,
            PersistConfig {
                enabled: false,
                base_dir: dir.path().to_path_buf(),
                retention_days: 14,
            },
        );
        assert_eq!(sink.dropped_events(), 0);
        assert!(sink.tasks.is_none());
        // Must not hang — the timeout here is generous but will fire
        // if shutdown ever blocks.
        timeout(Duration::from_secs(1), sink.shutdown())
            .await
            .expect("disabled shutdown must not block");
    }

    #[tokio::test]
    async fn events_reach_disk_after_publish() {
        // End-to-end: start sink, publish events on two sessions,
        // confirm the expected files exist and contain the correct
        // number of lines.
        let dir = tempdir().unwrap();
        let bus = EventBus::new(EventBusConfig::default());
        let sid_a = SessionId::parse("aaaaaaaaaaaa").unwrap();
        let sid_b = SessionId::parse("bbbbbbbbbbbb").unwrap();
        bus.register_session(sid_a);
        bus.register_session(sid_b);

        let sink = PersistentSink::spawn(
            &bus,
            PersistConfig {
                enabled: true,
                base_dir: dir.path().to_path_buf(),
                retention_days: 14,
            },
        );

        // Three DNS events on A, one lifecycle on B.
        bus.publish(dns_allow(sid_a, "a1.example.com"));
        bus.publish(dns_allow(sid_a, "a2.example.com"));
        bus.publish(dns_allow(sid_a, "a3.example.com"));
        bus.publish(lifecycle_ready(sid_b));

        let today = Utc::now().date_naive();
        let a_dns_file = writer::file_path(dir.path(), &sid_a, LayerKind::Dns, today);
        let b_life_file = writer::file_path(dir.path(), &sid_b, LayerKind::Lifecycle, today);

        wait_for_lines(&a_dns_file, 3).await;
        wait_for_lines(&b_life_file, 1).await;

        sink.shutdown().await;

        let a_body = fs::read_to_string(&a_dns_file).await.unwrap();
        let b_body = fs::read_to_string(&b_life_file).await.unwrap();
        assert_eq!(a_body.lines().count(), 3, "a body = {a_body:?}");
        assert_eq!(b_body.lines().count(), 1, "b body = {b_body:?}");
        // Each line must be valid JSON terminated with `\n`.
        for line in a_body.lines() {
            let _: serde_json::Value =
                serde_json::from_str(line).expect("each line must round-trip as JSON");
        }
    }

    #[tokio::test]
    async fn sink_segregates_events_by_layer() {
        // Publish a DNS and a lifecycle event on the same session;
        // they must land in distinct files because the sink keys the
        // rotating map by (session, layer).
        let dir = tempdir().unwrap();
        let bus = EventBus::default();
        let sid = SessionId::parse("0123456789ab").unwrap();
        bus.register_session(sid);

        let sink = PersistentSink::spawn(
            &bus,
            PersistConfig {
                enabled: true,
                base_dir: dir.path().to_path_buf(),
                retention_days: 14,
            },
        );

        bus.publish(dns_allow(sid, "mixed.example.com"));
        bus.publish(lifecycle_ready(sid));

        let today = Utc::now().date_naive();
        let dns_file = writer::file_path(dir.path(), &sid, LayerKind::Dns, today);
        let life_file = writer::file_path(dir.path(), &sid, LayerKind::Lifecycle, today);

        wait_for_lines(&dns_file, 1).await;
        wait_for_lines(&life_file, 1).await;

        sink.shutdown().await;

        assert!(dns_file.exists(), "dns file must exist");
        assert!(life_file.exists(), "lifecycle file must exist");
    }
}
