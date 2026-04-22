//! In-process event fan-out with per-session ring buffer + broadcast.
//!
//! The bus is the single sink every event producer — lifecycle emitters
//! in sandboxd, JSONL ingesters tailing the gateway container — writes to,
//! and the single source every event consumer — the HTTP SSE handler at
//! `GET /sessions/{id}/events` — reads from. It is deliberately
//! per-session: a session cannot observe another session's events, and
//! teardown of one session does not affect another.
//!
//! # Semantics
//!
//! - **Per-session sink.** Each registered session owns a
//!   [`SessionEventSink`] containing a bounded [`VecDeque`] ring buffer of
//!   recent events and a [`tokio::sync::broadcast::Sender`] that fans
//!   events out to live subscribers.
//! - **Atomic snapshot + subscribe.** [`EventBus::subscribe`] returns the
//!   current ring contents **and** a broadcast [`Receiver`][r] under a
//!   single read-guard. This guarantees no reconnect gap: a subscriber
//!   that drops the receiver and re-subscribes will see every event that
//!   arrived in between via the ring replay, with an acceptable edge of
//!   seeing an event duplicated at the ring/stream boundary (the SSE
//!   handler dedups on the envelope when needed).
//! - **Bounded ring.** [`EventBusConfig::ring_buffer_size`] caps the per-
//!   session ring. Oldest events are dropped on overflow (push-back,
//!   pop-front). Default [`DEFAULT_RING_BUFFER_SIZE`] = 10 000.
//! - **Broadcast back-pressure.** Lagging consumers receive
//!   [`broadcast::error::RecvError::Lagged`] from the broadcast channel
//!   and can recover by re-subscribing (which replays from the ring).
//! - **Session-less events drop silently.** If
//!   [`crate::events::Event::session`] is [`None`] (pre-session lifecycle
//!   events like `gateway_booting` before session attachment), publishing
//!   is a no-op — there is no per-session sink to route the event to.
//!   Callers that want to persist such events must do so separately (e.g.,
//!   to a daemon-wide log).
//! - **Publishing to an unregistered session drops silently.** This is
//!   the correct shape for racy teardown: if the session was unregistered
//!   between an ingester tailing a JSONL line and [`publish`] being called,
//!   the event is simply discarded. No error surface is returned because
//!   producers have nothing actionable to do.
//!
//! [r]: tokio::sync::broadcast::Receiver
//!
//! # Concurrency
//!
//! The outer `HashMap<SessionId, _>` is guarded by a
//! [`std::sync::RwLock`]. No `.await` happens inside a lock — the ring
//! is a blocking [`std::sync::Mutex`] and the broadcast send is
//! synchronous — so there is no risk of holding a lock across an await
//! point. Reads (publish / subscribe) dominate writes (register /
//! unregister, which happen only at session create/teardown), matching
//! `RwLock`'s bias.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};

use tokio::sync::broadcast;

use crate::events::Event;
use crate::session::SessionId;

/// A subscription handle: `(replay, receiver)`.
///
/// Returned by [`EventBus::subscribe`]. Callers drain `replay` (the
/// events currently in the session's ring, in the order they were
/// published) before switching to `receiver.recv().await` for live
/// events. Returned as a tuple (not a struct) because the SSE handler
/// destructures it immediately; the type alias just quiets
/// `clippy::type_complexity` on the public API.
pub type EventSubscription = (Vec<Arc<Event>>, broadcast::Receiver<Arc<Event>>);

/// Default per-session ring buffer capacity.
///
/// 10 000 events was picked to cover ~10 minutes of high-volume traffic
/// (a session pushing ~15 events/s) without tuning; operators with denser
/// traffic can override via [`EventBusConfig`]. Chosen high enough that a
/// cold SSE consumer reconnecting after a short network blip will still
/// see its full history without hitting the cap in practice. TODO:
/// M10-S6 will revisit this default with measurement-driven tuning.
pub const DEFAULT_RING_BUFFER_SIZE: usize = 10_000;

/// Default broadcast channel capacity.
///
/// Matches the ring buffer: a subscriber that keeps up with the stream
/// will never lag; a subscriber that falls more than this many messages
/// behind receives [`tokio::sync::broadcast::error::RecvError::Lagged`]
/// and is expected to recover via re-subscribe + ring replay.
const BROADCAST_CHANNEL_CAPACITY: usize = DEFAULT_RING_BUFFER_SIZE;

/// Tunables for [`EventBus`].
#[derive(Debug, Clone, Copy)]
pub struct EventBusConfig {
    /// Maximum number of events retained per-session in the replay ring.
    /// Oldest events are dropped when the ring is full.
    pub ring_buffer_size: usize,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            ring_buffer_size: DEFAULT_RING_BUFFER_SIZE,
        }
    }
}

/// A per-session event sink: ring buffer + broadcast sender.
///
/// Kept private: the outer [`EventBus`] is the only creator and the only
/// mutator; tests go through [`EventBus`] too.
struct SessionEventSink {
    tx: broadcast::Sender<Arc<Event>>,
    ring: Mutex<VecDeque<Arc<Event>>>,
    capacity: usize,
}

impl SessionEventSink {
    fn new(ring_capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        Self {
            tx,
            ring: Mutex::new(VecDeque::with_capacity(ring_capacity)),
            capacity: ring_capacity,
        }
    }

    /// Append `event` to the ring (evicting oldest if full) and broadcast
    /// it. The broadcast send intentionally ignores the "no active
    /// subscribers" error (`SendError`): the ring still retains the event
    /// so a future subscriber will see it via snapshot.
    fn publish(&self, event: Arc<Event>) {
        {
            let mut ring = self.ring.lock().expect("event ring mutex poisoned");
            if ring.len() == self.capacity {
                ring.pop_front();
            }
            ring.push_back(Arc::clone(&event));
        }
        // `send` returns Err only when there are no active receivers;
        // that's fine — the event is already in the ring.
        let _ = self.tx.send(event);
    }

    /// Snapshot the current ring and subscribe atomically.
    ///
    /// Order: the `broadcast::Sender::subscribe` call is made **first**,
    /// then the ring is cloned under its mutex. This ordering guarantees
    /// any event published between snapshot and subscribe shows up at
    /// least once: either it's already in the ring when we snapshot, or
    /// it arrives on the freshly-subscribed receiver. The trade-off is
    /// that boundary events can be seen twice; the SSE handler (M10-S2
    /// Phase 8) deduplicates by (timestamp, layer, event) when needed.
    fn snapshot_and_subscribe(&self) -> EventSubscription {
        let rx = self.tx.subscribe();
        let ring = self.ring.lock().expect("event ring mutex poisoned");
        let snapshot: Vec<Arc<Event>> = ring.iter().cloned().collect();
        (snapshot, rx)
    }
}

/// Inner state of [`EventBus`] behind an `Arc`. Private — the public
/// surface is `EventBus`.
struct BusInner {
    config: EventBusConfig,
    sessions: RwLock<HashMap<SessionId, SessionEventSink>>,
}

/// In-process event fan-out facade.
///
/// Clone is shallow — all clones share the same underlying sessions map.
#[derive(Clone)]
pub struct EventBus {
    inner: Arc<BusInner>,
}

impl EventBus {
    /// Construct an empty bus with the given tunables.
    pub fn new(config: EventBusConfig) -> Self {
        Self {
            inner: Arc::new(BusInner {
                config,
                sessions: RwLock::new(HashMap::new()),
            }),
        }
    }

    /// Register a session so events attributed to it can be routed and
    /// retained. Re-registering an already-registered session is a no-op
    /// (the existing sink is kept so in-flight subscribers are not
    /// invalidated).
    pub fn register_session(&self, session_id: SessionId) {
        let mut sessions = self
            .inner
            .sessions
            .write()
            .expect("EventBus sessions lock poisoned");
        sessions
            .entry(session_id)
            .or_insert_with(|| SessionEventSink::new(self.inner.config.ring_buffer_size));
    }

    /// Unregister a session, discarding its ring buffer and closing the
    /// broadcast channel. Any live subscribers get `None` on their next
    /// `recv`.
    pub fn unregister_session(&self, session_id: &SessionId) {
        let mut sessions = self
            .inner
            .sessions
            .write()
            .expect("EventBus sessions lock poisoned");
        sessions.remove(session_id);
    }

    /// Route `event` to its session's sink.
    ///
    /// Silently drops the event when:
    /// - the event has no attributed session ([`Event::session`] is
    ///   [`None`]), or
    /// - the attributed session has not been registered (or was already
    ///   unregistered in a concurrent teardown race).
    ///
    /// Returns `true` if the event was routed to a sink, `false` otherwise.
    pub fn publish(&self, event: Event) -> bool {
        let Some(session_id) = event.session().copied() else {
            return false;
        };
        let sessions = self
            .inner
            .sessions
            .read()
            .expect("EventBus sessions lock poisoned");
        let Some(sink) = sessions.get(&session_id) else {
            return false;
        };
        sink.publish(Arc::new(event));
        true
    }

    /// Atomically snapshot the session's ring and subscribe for future
    /// events. Returns [`None`] if the session is not registered.
    ///
    /// The returned tuple is `(replay, receiver)`; callers should drain
    /// `replay` first (it is the historical order the events were
    /// published in) before switching to `receiver.recv()`.
    pub fn subscribe(&self, session_id: &SessionId) -> Option<EventSubscription> {
        let sessions = self
            .inner
            .sessions
            .read()
            .expect("EventBus sessions lock poisoned");
        let sink = sessions.get(session_id)?;
        Some(sink.snapshot_and_subscribe())
    }

    /// Number of registered sessions. Exposed for tests and future
    /// operator-observability (metric).
    pub fn session_count(&self) -> usize {
        self.inner
            .sessions
            .read()
            .expect("EventBus sessions lock poisoned")
            .len()
    }

    /// Current depth of the session's ring buffer, or [`None`] if the
    /// session is not registered. Exposed for tests.
    pub fn ring_depth(&self, session_id: &SessionId) -> Option<usize> {
        let sessions = self
            .inner
            .sessions
            .read()
            .expect("EventBus sessions lock poisoned");
        sessions
            .get(session_id)
            .map(|s| s.ring.lock().expect("event ring mutex poisoned").len())
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(EventBusConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use chrono::Utc;

    use crate::events::{
        DnsEvent, EnvoyConnection, EnvoyEvent, EventEnvelope, LifecycleEvent, TrafficEvent,
    };

    fn dns_allow(session: Option<SessionId>, query: &str) -> Event {
        Event::Traffic {
            envelope: EventEnvelope {
                timestamp: Utc::now(),
                session,
            },
            event: TrafficEvent::Dns(DnsEvent::QueryAllowed {
                query: query.into(),
                qtype: "A".into(),
                resolved_ips: vec![Ipv4Addr::new(10, 0, 0, 1)],
            }),
        }
    }

    fn envoy_deny(session: Option<SessionId>) -> Event {
        Event::Traffic {
            envelope: EventEnvelope {
                timestamp: Utc::now(),
                session,
            },
            event: TrafficEvent::Envoy(EnvoyEvent::ConnectionDenied(EnvoyConnection {
                src_ip: Ipv4Addr::new(10, 0, 0, 42),
                src_port: 12345,
                dst_ip: Ipv4Addr::new(93, 184, 216, 34),
                dst_port: 443,
                matched_chain: "chain_l1_deny".into(),
                cluster: "deny_all".into(),
                upstream_host: None,
                bytes_sent: 0,
                bytes_received: 0,
                response_flags: "NR".into(),
                duration_ms: 1,
                connect_authority: None,
            })),
        }
    }

    fn lifecycle_gateway_ready(session: Option<SessionId>) -> Event {
        Event::Lifecycle {
            envelope: EventEnvelope {
                timestamp: Utc::now(),
                session,
            },
            event: LifecycleEvent::GatewayReady,
        }
    }

    #[test]
    fn register_then_unregister_is_idempotent() {
        let bus = EventBus::default();
        let sid = SessionId::generate();
        assert_eq!(bus.session_count(), 0);
        bus.register_session(sid);
        bus.register_session(sid); // no-op
        assert_eq!(bus.session_count(), 1);
        bus.unregister_session(&sid);
        bus.unregister_session(&sid); // no-op
        assert_eq!(bus.session_count(), 0);
    }

    #[test]
    fn publish_routes_to_registered_session() {
        let bus = EventBus::default();
        let sid = SessionId::generate();
        bus.register_session(sid);
        assert!(bus.publish(dns_allow(Some(sid), "example.com")));
        assert_eq!(bus.ring_depth(&sid), Some(1));
    }

    #[test]
    fn publish_without_session_attribution_is_dropped() {
        let bus = EventBus::default();
        // No register_session called.
        assert!(!bus.publish(lifecycle_gateway_ready(None)));
        // Even for traffic events with session=None — a defensive case
        // the ingest layer is supposed to prevent by stamping session
        // before publish, but the bus must not panic on it.
        assert!(!bus.publish(dns_allow(None, "pre-attribution.example.com")));
    }

    #[test]
    fn publish_to_unregistered_session_is_dropped() {
        let bus = EventBus::default();
        let sid = SessionId::generate();
        // Note: never registered.
        assert!(!bus.publish(dns_allow(Some(sid), "late.example.com")));
    }

    #[tokio::test]
    async fn subscribe_receives_live_events() {
        let bus = EventBus::default();
        let sid = SessionId::generate();
        bus.register_session(sid);
        let (replay, mut rx) = bus.subscribe(&sid).expect("registered");
        assert!(replay.is_empty(), "no prior events => empty replay");

        // Publish after subscribing → arrives on rx.
        bus.publish(dns_allow(Some(sid), "live.example.com"));
        let got = rx.recv().await.expect("receive live event");
        match &*got {
            Event::Traffic {
                event: TrafficEvent::Dns(DnsEvent::QueryAllowed { query, .. }),
                ..
            } => assert_eq!(query, "live.example.com"),
            other => panic!("unexpected event variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn ring_buffer_replay_on_subscribe() {
        // Exit-gate test per plan: publish N, subscribe, expect N replay.
        let bus = EventBus::default();
        let sid = SessionId::generate();
        bus.register_session(sid);
        for i in 0..5 {
            bus.publish(dns_allow(Some(sid), &format!("q{i}.example.com")));
        }
        let (replay, mut rx) = bus.subscribe(&sid).expect("registered");
        assert_eq!(replay.len(), 5, "ring must replay all prior events");
        // Order preserved: oldest first.
        for (i, ev) in replay.iter().enumerate() {
            match &**ev {
                Event::Traffic {
                    event: TrafficEvent::Dns(DnsEvent::QueryAllowed { query, .. }),
                    ..
                } => assert_eq!(query, &format!("q{i}.example.com")),
                other => panic!("unexpected event variant at {i}: {other:?}"),
            }
        }
        // After replay drain, the receiver is live: publish a 6th and see it.
        bus.publish(envoy_deny(Some(sid)));
        let got = rx.recv().await.expect("live event after replay");
        assert!(matches!(
            &*got,
            Event::Traffic {
                event: TrafficEvent::Envoy(EnvoyEvent::ConnectionDenied(_)),
                ..
            }
        ));
    }

    #[test]
    fn ring_buffer_evicts_oldest_on_overflow() {
        let bus = EventBus::new(EventBusConfig {
            ring_buffer_size: 3,
        });
        let sid = SessionId::generate();
        bus.register_session(sid);
        for i in 0..5 {
            bus.publish(dns_allow(Some(sid), &format!("q{i}.example.com")));
        }
        assert_eq!(bus.ring_depth(&sid), Some(3));
        let (replay, _rx) = bus.subscribe(&sid).unwrap();
        assert_eq!(replay.len(), 3);
        // Oldest two (q0, q1) were evicted; replay starts at q2.
        let expected = ["q2.example.com", "q3.example.com", "q4.example.com"];
        for (i, ev) in replay.iter().enumerate() {
            match &**ev {
                Event::Traffic {
                    event: TrafficEvent::Dns(DnsEvent::QueryAllowed { query, .. }),
                    ..
                } => assert_eq!(query, expected[i]),
                other => panic!("unexpected event variant at {i}: {other:?}"),
            }
        }
    }

    #[test]
    fn subscribe_on_unregistered_session_returns_none() {
        let bus = EventBus::default();
        let sid = SessionId::generate();
        assert!(bus.subscribe(&sid).is_none());
    }

    #[tokio::test]
    async fn per_session_isolation_no_cross_talk() {
        let bus = EventBus::default();
        let sid_a = SessionId::generate();
        let sid_b = SessionId::generate();
        bus.register_session(sid_a);
        bus.register_session(sid_b);

        let (_replay_a, mut rx_a) = bus.subscribe(&sid_a).unwrap();
        let (_replay_b, mut rx_b) = bus.subscribe(&sid_b).unwrap();

        bus.publish(dns_allow(Some(sid_a), "a.example.com"));

        // A sees its own event.
        let got_a = rx_a.recv().await.expect("a sees event");
        match &*got_a {
            Event::Traffic {
                event: TrafficEvent::Dns(DnsEvent::QueryAllowed { query, .. }),
                ..
            } => assert_eq!(query, "a.example.com"),
            other => panic!("unexpected: {other:?}"),
        }

        // B sees nothing (try_recv => Empty).
        use tokio::sync::broadcast::error::TryRecvError;
        match rx_b.try_recv() {
            Err(TryRecvError::Empty) => {}
            other => panic!("expected empty on b; got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unregister_closes_live_subscribers() {
        let bus = EventBus::default();
        let sid = SessionId::generate();
        bus.register_session(sid);
        let (_replay, mut rx) = bus.subscribe(&sid).unwrap();
        bus.unregister_session(&sid);
        // Dropping the sender (via remove) closes the channel => recv
        // returns Closed.
        use tokio::sync::broadcast::error::RecvError;
        match rx.recv().await {
            Err(RecvError::Closed) => {}
            other => panic!("expected Closed; got {other:?}"),
        }
        // And the session is gone.
        assert!(bus.subscribe(&sid).is_none());
    }
}
