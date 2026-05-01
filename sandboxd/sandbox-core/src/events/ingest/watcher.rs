//! Inotify-backed watcher that tails per-layer JSONL files under a
//! single session's events directory and publishes parsed records to
//! the shared [`EventBus`].
//!
//! # Responsibilities
//!
//! For a given `(session_id, events_dir, bus, vm_ip_map)` quadruple:
//!
//! 1. Open a [`notify::RecommendedWatcher`] (inotify on Linux) in
//!    non-recursive mode on `events_dir`. We do not need recursion —
//!    producers only ever write to the directory root.
//! 2. Glob the directory immediately for any of the three known file
//!    names (`envoy.jsonl`, `coredns.jsonl`, `mitmproxy.jsonl`) and
//!    spawn a [`JsonlTailer`] for each already-present file. This is
//!    the "seek-to-EOF at session re-ingest" case (see
//!    [`JsonlTailer::new_at_eof`]).
//! 3. Run a `tokio::select!` loop that:
//!    a. Handles inotify events delivered through an mpsc channel.
//!    On the first [`Create`] / [`Modify`] event for a known file
//!    name we have not already seen, spawn a
//!    [`JsonlTailer::new_at_start`] for it. On any subsequent
//!    event that touches a file we are already tailing, wake the
//!    tailer and drain new bytes.
//!    b. Fires a `tokio::time::interval(2s)` fallback poll that wakes
//!    every active tailer, independent of inotify. This is the
//!    "virtiofs / 9p inotify propagation unreliable under some
//!    hypervisor configurations" safety net called out in the plan.
//! 4. For every parsed line, look up `session_id` via
//!    [`VmIpSessionMap::lookup`] on the per-layer `client_ip` /
//!    `src_ip`. On miss, warn + drop — publishing to a fabricated or
//!    wrong session is worse than dropping (spec Part 3 / plan Phase
//!    7 "drop events on vm_ip miss").
//!
//! # Why mpsc + select, not just `tokio::sync::watch`
//!
//! notify's `RecommendedWatcher` delivers events through a synchronous
//! handler closure running on its own thread. We trampoline those into
//! a `tokio::mpsc::UnboundedSender` so the async loop can select on
//! them alongside the 2s timer and the abort signal.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::events::ingest::coredns::{ParsedDnsEvent, parse_coredns_line};
use crate::events::ingest::envoy::{ParsedEnvoyEvent, parse_envoy_line};
use crate::events::ingest::jsonl_reader::JsonlTailer;
use crate::events::ingest::mitmproxy::{ParsedMitmEvent, parse_mitmproxy_line};
use crate::events::ingest::nft_logger::{ParsedNftLoggerEvent, parse_nft_logger_line};
use crate::events::{Event, EventBus, EventEnvelope, TrafficEvent, VmIpSessionMap};
use crate::session::SessionId;

/// File names of the five producers. Kept private to this module —
/// the producer side (gateway-container Docker image) is the source of
/// truth. If a new layer ships, add it here and a matching parser.
///
/// `nft-allow.jsonl` (M12-S2 Phase 3) shares the `nft_logger` parser
/// with `nft-deny.jsonl`; the per-file `Layer` discriminator is what
/// routes the dispatch arm.
const ENVOY_JSONL: &str = "envoy.jsonl";
const COREDNS_JSONL: &str = "coredns.jsonl";
const MITMPROXY_JSONL: &str = "mitmproxy.jsonl";
const DENY_LOGGER_JSONL: &str = "nft-deny.jsonl";
const ALLOW_LOGGER_JSONL: &str = "nft-allow.jsonl";

const KNOWN_FILES: &[&str] = &[
    ENVOY_JSONL,
    COREDNS_JSONL,
    MITMPROXY_JSONL,
    DENY_LOGGER_JSONL,
    ALLOW_LOGGER_JSONL,
];

/// Fallback-poll interval. Matches the plan's "2-second poll even in
/// the absence of inotify events" requirement. Not configurable — the
/// value is a compromise between responsiveness and idle CPU wake-ups.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Which layer a particular tailer serves. Drives the parse dispatch.
///
/// `DenyLogger` and `AllowLogger` are sibling members of the nft-logger
/// family (M12-S2 Decision 5): both flow through
/// [`crate::events::ingest::nft_logger::parse_nft_logger_line`] and end
/// up as [`crate::events::DenyLoggerEvent`] variants on the bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Layer {
    Envoy,
    Coredns,
    Mitmproxy,
    DenyLogger,
    AllowLogger,
}

impl Layer {
    fn from_file_name(name: &str) -> Option<Self> {
        match name {
            ENVOY_JSONL => Some(Layer::Envoy),
            COREDNS_JSONL => Some(Layer::Coredns),
            MITMPROXY_JSONL => Some(Layer::Mitmproxy),
            DENY_LOGGER_JSONL => Some(Layer::DenyLogger),
            ALLOW_LOGGER_JSONL => Some(Layer::AllowLogger),
            _ => None,
        }
    }

    #[cfg(test)]
    fn file_name(self) -> &'static str {
        match self {
            Layer::Envoy => ENVOY_JSONL,
            Layer::Coredns => COREDNS_JSONL,
            Layer::Mitmproxy => MITMPROXY_JSONL,
            Layer::DenyLogger => DENY_LOGGER_JSONL,
            Layer::AllowLogger => ALLOW_LOGGER_JSONL,
        }
    }
}

/// Top-level entry point for [`crate::events::ingest::SessionIngestor`].
///
/// Runs until the surrounding task is aborted. Any recoverable error
/// (e.g., watcher setup failure, transient read error on a single
/// tailer) is logged and the loop keeps going; unrecoverable errors
/// (e.g., cannot construct the inotify watcher at all) log and then
/// return so the ingestor task exits quietly rather than panicking a
/// whole daemon.
pub async fn run_watcher(
    session_id: SessionId,
    events_dir: PathBuf,
    bus: EventBus,
    vm_ip_map: VmIpSessionMap,
) {
    // Trampoline: notify's sync handler → tokio-owned channel. Every
    // filesystem notification lands here as `notify::Result<Event>`.
    let (tx, mut rx) = mpsc::unbounded_channel::<notify::Result<notify::Event>>();
    let events_dir_for_watcher = events_dir.clone();
    let watcher = tokio::task::spawn_blocking(move || -> notify::Result<RecommendedWatcher> {
        let mut w = notify::recommended_watcher(move |res| {
            // Send failure means the receiver has been dropped
            // (ingestor aborted); ignore and let this closure die
            // when the watcher is dropped.
            let _ = tx.send(res);
        })?;
        w.watch(&events_dir_for_watcher, RecursiveMode::NonRecursive)?;
        Ok(w)
    })
    .await;

    // `_watcher` must stay alive for the duration of the loop — the
    // inotify backend registers watches only while this handle lives.
    let _watcher = match watcher {
        Ok(Ok(w)) => w,
        Ok(Err(e)) => {
            warn!(
                session_id = %session_id,
                events_dir = %events_dir.display(),
                error = %e,
                "ingest: failed to construct inotify watcher; ingestor exiting"
            );
            return;
        }
        Err(join_err) => {
            warn!(
                session_id = %session_id,
                error = %join_err,
                "ingest: spawn_blocking for notify watcher panicked; ingestor exiting"
            );
            return;
        }
    };

    info!(
        session_id = %session_id,
        events_dir = %events_dir.display(),
        "ingest: watcher started"
    );

    let mut tailers: HashMap<Layer, JsonlTailer> = HashMap::new();

    // Bootstrap: any file that already exists at watcher-start time is
    // tailed from EOF (we don't want an avalanche of historical lines
    // from the session's previous incarnation — see the seek-to-EOF
    // rationale in `jsonl_reader.rs`).
    for &name in KNOWN_FILES {
        let path = events_dir.join(name);
        if path.exists() {
            let layer = Layer::from_file_name(name).expect("file name from KNOWN_FILES");
            match JsonlTailer::new_at_eof(&path) {
                Ok(t) => {
                    debug!(
                        session_id = %session_id,
                        path = %path.display(),
                        "ingest: bootstrapped existing tailer at EOF"
                    );
                    tailers.insert(layer, t);
                }
                Err(e) => {
                    warn!(
                        session_id = %session_id,
                        path = %path.display(),
                        error = %e,
                        "ingest: failed to open existing file for tailing"
                    );
                }
            }
        }
    }

    // Drive all bootstrap tailers once immediately so any content that
    // arrived between `exists()` and `new_at_eof` isn't left behind.
    // (For `new_at_eof` the first wake yields nothing by construction,
    // but this keeps the code path unconditional and tested.)
    drain_all(&session_id, &bus, &vm_ip_map, &mut tailers);

    let mut poll = tokio::time::interval(POLL_INTERVAL);
    // We want "fire every 2 seconds from now" rather than "fire
    // immediately at t=0"; `Burst` vs `Delay` matters only for the
    // first tick.
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(Ok(ev)) => {
                        handle_fs_event(
                            &session_id,
                            &events_dir,
                            ev,
                            &mut tailers,
                        );
                        drain_all(&session_id, &bus, &vm_ip_map, &mut tailers);
                    }
                    Some(Err(e)) => {
                        warn!(
                            session_id = %session_id,
                            error = %e,
                            "ingest: notify delivered an error; continuing"
                        );
                    }
                    None => {
                        // Senders dropped — watcher is gone (e.g. it
                        // was itself dropped). This should not happen
                        // while we still hold `_watcher`, but if it
                        // does, exit rather than spin.
                        debug!(
                            session_id = %session_id,
                            "ingest: notify channel closed; watcher loop exiting"
                        );
                        break;
                    }
                }
            }
            _ = poll.tick() => {
                // Fallback poll: if inotify has been silent, drain
                // everything anyway. Also re-scan the directory for
                // any known-name file that appeared without an
                // inotify event reaching us.
                rescan_dir(&session_id, &events_dir, &mut tailers);
                drain_all(&session_id, &bus, &vm_ip_map, &mut tailers);
            }
        }
    }
}

/// Dispatch one notify event: learn about new files, forward modify/
/// create events to existing tailers implicitly (they're drained on
/// the same cycle).
fn handle_fs_event(
    session_id: &SessionId,
    events_dir: &Path,
    ev: notify::Event,
    tailers: &mut HashMap<Layer, JsonlTailer>,
) {
    for path in ev.paths {
        let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(layer) = Layer::from_file_name(file_name) else {
            continue;
        };
        // Events can carry paths outside our watch root when notify
        // reconciles rename operations; only accept paths under the
        // expected directory.
        if path.parent() != Some(events_dir) {
            continue;
        }
        // Already tailing? Nothing to do structurally — the drain pass
        // will pick up the new bytes.
        if tailers.contains_key(&layer) {
            continue;
        }
        // First sighting. Open at byte 0 (the file was just created;
        // there is no historical content to skip).
        match JsonlTailer::new_at_start(&path) {
            Ok(t) => {
                info!(
                    session_id = %session_id,
                    path = %path.display(),
                    "ingest: discovered new layer file; tailing from start"
                );
                tailers.insert(layer, t);
            }
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    path = %path.display(),
                    error = %e,
                    "ingest: failed to open new layer file"
                );
            }
        }
    }
}

/// Re-scan the directory for files we haven't seen yet. Serves two
/// purposes: (1) the fallback poll path when inotify is unreliable
/// (virtiofs/9p), (2) a self-heal path for events dropped during a
/// transient hiccup.
fn rescan_dir(
    session_id: &SessionId,
    events_dir: &Path,
    tailers: &mut HashMap<Layer, JsonlTailer>,
) {
    for &name in KNOWN_FILES {
        let path = events_dir.join(name);
        let layer = Layer::from_file_name(name).expect("file name from KNOWN_FILES");
        if tailers.contains_key(&layer) {
            continue;
        }
        if !path.exists() {
            continue;
        }
        match JsonlTailer::new_at_start(&path) {
            Ok(t) => {
                info!(
                    session_id = %session_id,
                    path = %path.display(),
                    "ingest: poll-detected new layer file; tailing from start"
                );
                tailers.insert(layer, t);
            }
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    path = %path.display(),
                    error = %e,
                    "ingest: failed to open poll-detected layer file"
                );
            }
        }
    }
}

/// Wake every active tailer, parse each delivered line, stamp the
/// envelope, and publish. Errors are logged and dropped per-line so
/// one bad record cannot poison the rest of the stream.
fn drain_all(
    watcher_session: &SessionId,
    bus: &EventBus,
    vm_ip_map: &VmIpSessionMap,
    tailers: &mut HashMap<Layer, JsonlTailer>,
) {
    for (&layer, tailer) in tailers.iter_mut() {
        tailer.read_to_eof(|line| {
            dispatch_line(watcher_session, bus, vm_ip_map, layer, line);
        });
    }
}

/// Parse one line based on its layer, resolve session from the
/// per-layer client / source IP, and publish.
///
/// The per-parser source IP is an [`Option`] because two producer shapes
/// cannot be attributed via `vm_ip_map.lookup`:
///
/// 1. The deny-logger's `rate_limited` summary carries no 5-tuple — it
///    is a per-session aggregate produced when the component's
///    per-session event rate cap is hit (spec Part 3 / "Hardening
///    rules" § 5).
/// 2. Every mitmproxy event's `client_ip` is the kernel-chosen source
///    of Envoy's upstream connect to `127.0.0.1:18080` (typically the
///    gateway's bridge IP), not the VM. Mitmproxy runs on loopback
///    inside the gateway container and never sees the VM's IP on its
///    listening socket, so there is nothing to look up in `vm_ip_map`.
///
/// For both cases we fall back to the ingestor's own `watcher_session`:
/// every [`SessionIngestor`] instance runs for a single session by
/// construction, so the owning session is already known at this layer.
/// Envoy and CoreDNS see the VM as the origin peer on their respective
/// listeners and return `Some(ip)`, going through the normal
/// `vm_ip_map.lookup` path.
///
/// [`SessionIngestor`]: crate::events::ingest::SessionIngestor
fn dispatch_line(
    watcher_session: &SessionId,
    bus: &EventBus,
    vm_ip_map: &VmIpSessionMap,
    layer: Layer,
    line: &str,
) {
    let parsed: Result<(DateTime<Utc>, Option<std::net::Ipv4Addr>, TrafficEvent), _> = match layer {
        Layer::Envoy => parse_envoy_line(line)
            .map(|p: ParsedEnvoyEvent| (p.timestamp, Some(p.src_ip), p.traffic)),
        Layer::Coredns => parse_coredns_line(line)
            .map(|p: ParsedDnsEvent| (p.timestamp, Some(p.client_ip), p.traffic)),
        Layer::Mitmproxy => parse_mitmproxy_line(line)
            // client_ip on mitmproxy events is the gateway's upstream-socket
            // source (set by the kernel for Envoy's connect to 127.0.0.1:18080),
            // not the VM. Since SessionIngestor is per-session by construction,
            // attribute via watcher_session — same treatment as deny-logger's
            // rate_limited summary.
            .map(|p: ParsedMitmEvent| (p.timestamp, None, p.traffic)),
        Layer::DenyLogger | Layer::AllowLogger => parse_nft_logger_line(line)
            .map(|p: ParsedNftLoggerEvent| (p.timestamp, p.src_ip, p.traffic)),
    };
    let (timestamp, maybe_client_ip, traffic) = match parsed {
        Ok(v) => v,
        Err(e) => {
            warn!(
                session_id = %watcher_session,
                layer = ?layer,
                error = %e,
                "ingest: failed to parse line; skipping"
            );
            return;
        }
    };

    let session_id = match maybe_client_ip {
        Some(client_ip) => {
            let Some(sid) = vm_ip_map.lookup(client_ip) else {
                // Dropping unattributable events is a deliberate design
                // choice (spec Part 3, plan Phase 7): a fabricated /
                // wrong session on the envelope would be silently
                // misleading, whereas a dropped event surfaces as a
                // clear gap that operators can investigate via the warn
                // log.
                warn!(
                    watcher_session = %watcher_session,
                    layer = ?layer,
                    client_ip = %client_ip,
                    "ingest: vm_ip not bound to a session; dropping event"
                );
                return;
            };
            sid
        }
        None => {
            // No peer IP to look up. Two producer shapes hit this path:
            // (a) the deny-logger's `rate_limited` summary, which has no
            // 5-tuple (spec Part 3 / "Hardening rules" § 5); and
            // (b) every mitmproxy event, whose `client_ip` reflects the
            // kernel-chosen source of Envoy's loopback connect and is
            // not the VM. Both producers run per-session by
            // construction, so the ingestor's own `watcher_session` is
            // the correct owner. See the function-level doc above.
            *watcher_session
        }
    };

    let envelope = EventEnvelope {
        timestamp,
        session: Some(session_id),
    };
    let event = Event::Traffic {
        envelope,
        event: traffic,
    };
    // `publish` returns false when the session is unregistered —
    // during a teardown race — which is also benign; no need to warn.
    let _ = bus.publish(event);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// End-to-end watcher behaviour is exercised from
// `tests/events_ingest_integration.rs` (which drives a real tempdir,
// writes JSONL, and asserts on the bus). The unit tests here cover the
// pure helpers.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_from_file_name_recognises_known_producers() {
        assert_eq!(Layer::from_file_name("envoy.jsonl"), Some(Layer::Envoy));
        assert_eq!(Layer::from_file_name("coredns.jsonl"), Some(Layer::Coredns));
        assert_eq!(
            Layer::from_file_name("mitmproxy.jsonl"),
            Some(Layer::Mitmproxy)
        );
        assert_eq!(
            Layer::from_file_name("nft-deny.jsonl"),
            Some(Layer::DenyLogger)
        );
        assert_eq!(
            Layer::from_file_name("nft-allow.jsonl"),
            Some(Layer::AllowLogger)
        );
    }

    #[test]
    fn layer_from_file_name_rejects_anything_else() {
        assert_eq!(Layer::from_file_name("unknown.jsonl"), None);
        assert_eq!(Layer::from_file_name("envoy.log"), None);
        assert_eq!(Layer::from_file_name(""), None);
        // Underscore vs. hyphen variant — easy-to-make typo, must not
        // match.
        assert_eq!(Layer::from_file_name("nft_deny.jsonl"), None);
        // Pre-rename legacy filename — must no longer match after the
        // M12-S2 Resolution 6 rename to `nft-deny.jsonl`.
        assert_eq!(Layer::from_file_name("deny-logger.jsonl"), None);
    }

    #[test]
    fn layer_round_trip_through_file_name() {
        for &l in &[
            Layer::Envoy,
            Layer::Coredns,
            Layer::Mitmproxy,
            Layer::DenyLogger,
            Layer::AllowLogger,
        ] {
            assert_eq!(Layer::from_file_name(l.file_name()), Some(l));
        }
    }

    #[test]
    fn poll_interval_is_two_seconds() {
        // Regression guard on a spec-dictated constant. If this test
        // fails someone has changed the fallback poll rate — make sure
        // the corresponding docs + E2E waits get updated too.
        assert_eq!(POLL_INTERVAL, std::time::Duration::from_secs(2));
    }

    // ----- dispatch_line attribution tests -----

    use crate::events::{EventBusConfig, MitmproxyEvent};
    use std::net::Ipv4Addr;

    /// Regression test for the mitmproxy attribution bug (M10-S5 Phase 7).
    ///
    /// Mitmproxy's `client_ip` is the kernel-chosen source of Envoy's
    /// loopback connect — not the VM — so attempting to resolve it via
    /// `vm_ip_map.lookup` always misses. Instead, dispatch_line must
    /// attribute the event to the ingestor's `watcher_session` (the
    /// same fallback the deny-logger's `rate_limited` summary uses),
    /// since every ingestor runs for a single session by construction.
    #[test]
    fn dispatch_line_mitmproxy_attributes_via_watcher_session() {
        let watcher_session = SessionId::parse("aaaaaaaaaaaa").expect("valid fixture session id");
        let bus = EventBus::new(EventBusConfig::default());
        bus.register_session(watcher_session);
        // Deliberately leave `vm_ip_map` empty: the client_ip on the
        // mitmproxy record below is the gateway's bridge IP, which is
        // by design never bound in the map. A vm_ip_map.lookup()-based
        // attribution would drop the event.
        let vm_ip_map = VmIpSessionMap::new();

        // client_ip=10.209.0.2 mimics the real-world failure: that is
        // the gateway container's bridge IP on the VM-facing bridge
        // (see handoff in .tasks/handoffs/20260423-061500-* for the
        // root cause). Not bound, must still be attributed.
        let line = r#"{"timestamp":"2026-04-22T09:45:00.000Z","layer":"mitmproxy","event":"request_allowed","host":"registry.npmjs.org","port":443,"method":"GET","path":"/leftpad","client_ip":"10.209.0.2"}"#;

        dispatch_line(&watcher_session, &bus, &vm_ip_map, Layer::Mitmproxy, line);

        // Snapshot the ring after publish; `subscribe` returns a
        // replay vector seeded from the per-session ring so late
        // consumers still observe the event. If the bug were still
        // present, dispatch_line would drop the event via
        // `vm_ip_map.lookup` miss and the replay would be empty.
        let (mut replay, _rx) = bus.subscribe(&watcher_session).expect("registered");

        assert_eq!(
            replay.len(),
            1,
            "exactly one mitmproxy event must reach the ring; got {}",
            replay.len()
        );
        match &*replay.remove(0) {
            Event::Traffic { envelope, event } => {
                assert_eq!(
                    envelope.session,
                    Some(watcher_session),
                    "mitmproxy event must attribute to the ingestor's watcher_session, \
                     not the gateway bridge ip in client_ip",
                );
                match event {
                    TrafficEvent::Mitmproxy(MitmproxyEvent::RequestAllowed {
                        host, path, ..
                    }) => {
                        assert_eq!(host, "registry.npmjs.org");
                        assert_eq!(path, "/leftpad");
                    }
                    other => panic!("expected RequestAllowed, got {other:?}"),
                }
            }
            Event::Lifecycle { .. } => panic!("expected traffic event"),
        }
    }

    /// Negative control: the envoy branch still relies on
    /// `vm_ip_map.lookup`, so an unbound src_ip must continue to drop
    /// the event. Guards against a change to `Layer::Envoy` that
    /// silently widened the `None`-fallback to the wrong producer.
    #[test]
    fn dispatch_line_envoy_drops_unbound_src_ip() {
        let watcher_session = SessionId::parse("bbbbbbbbbbbb").expect("valid fixture session id");
        let bus = EventBus::new(EventBusConfig::default());
        bus.register_session(watcher_session);
        let vm_ip_map = VmIpSessionMap::new();
        // Bind a different IP so the map is non-empty; 10.0.0.99 below
        // still misses.
        vm_ip_map.bind("10.0.0.1".parse::<Ipv4Addr>().unwrap(), watcher_session);
        let (replay, _rx) = bus.subscribe(&watcher_session).expect("registered");

        let line = r#"{"timestamp":"2026-04-22T09:45:00.000Z","layer":"envoy","event":"connection_allowed","src_ip":"10.0.0.99","src_port":"51234","dst_ip":"93.184.216.34","dst_port":"443","matched_chain":"l3_https","cluster":"upstream_https","upstream_host":"93.184.216.34:443","bytes_sent":"0","bytes_received":"0","response_flags":"-","duration_ms":"1","connect_authority":"api.example.com:443"}"#;

        dispatch_line(&watcher_session, &bus, &vm_ip_map, Layer::Envoy, line);

        assert!(
            replay.is_empty(),
            "envoy events with unbound src_ip must be dropped; \
             found {} published events",
            replay.len(),
        );
    }
}
