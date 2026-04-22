//! VM-IP → session-ID lookup map.
//!
//! The Envoy access log, CoreDNS policy plugin, and mitmproxy addon all
//! identify a client by its VM bridge IP (the `src_ip` field on access-log
//! records) because none of them know the session ID. sandboxd owns the
//! mapping: when a session's `NetworkInfo` is ready, its `vm_ip` is bound
//! here; when the session's networking is torn down, the entry is removed.
//! The ingest layer (M10-S2 Phase 7) calls [`VmIpSessionMap::lookup`] to
//! stamp the `session` field on each [`crate::events::EventEnvelope`]
//! before publishing it to the [`crate::events::EventBus`] — this is the
//! "session-ID attribution is sandboxd's job" concern from spec Part 3.
//!
//! Design notes:
//!
//! - Backed by [`std::sync::RwLock`] rather than
//!   [`tokio::sync::RwLock`]: the critical sections are pure in-memory
//!   `HashMap` operations with no `.await` inside, and a blocking
//!   `std::sync::RwLock` has a much smaller code footprint (no pollers,
//!   no async-drop gotchas). Reads dominate writes (every published
//!   event performs one lookup; binds/unbinds happen only at session
//!   create/teardown).
//! - [`Clone`] is shallow: the inner [`Arc`] is shared so every clone
//!   sees the same map.
//! - A `VmIpSessionMap` is trivially constructable via
//!   [`VmIpSessionMap::new`] or [`Default::default`]; startup code in
//!   `sandboxd` rehydrates the map from
//!   [`crate::store::SessionStore::list_sessions_with_network_info`].

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use crate::session::SessionId;

/// Thread-safe VM-IP → session-ID lookup map.
///
/// Cheaply cloneable: the backing [`HashMap`] lives behind an [`Arc`], so
/// clones share the same storage.
#[derive(Clone, Default)]
pub struct VmIpSessionMap {
    inner: Arc<RwLock<HashMap<Ipv4Addr, SessionId>>>,
}

impl VmIpSessionMap {
    /// Construct an empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `vm_ip` to `session_id`.
    ///
    /// If `vm_ip` was previously bound, the old session mapping is
    /// overwritten; the previous session's binding is returned. Overwriting
    /// is not expected in normal operation (each VM has a unique bridge
    /// IP), but it is safer to tolerate than to panic on — a stale
    /// restart-time hydrate over a live binding is still the correct
    /// outcome.
    pub fn bind(&self, vm_ip: Ipv4Addr, session_id: SessionId) -> Option<SessionId> {
        self.inner
            .write()
            .expect("VmIpSessionMap lock poisoned")
            .insert(vm_ip, session_id)
    }

    /// Remove the binding for `vm_ip`, if any. Returns the session that
    /// was bound.
    pub fn unbind(&self, vm_ip: Ipv4Addr) -> Option<SessionId> {
        self.inner
            .write()
            .expect("VmIpSessionMap lock poisoned")
            .remove(&vm_ip)
    }

    /// Look up the session ID for `vm_ip`.
    ///
    /// [`SessionId`] is [`Copy`], so this returns an owned value; callers
    /// do not need to hold a read guard across the lookup.
    pub fn lookup(&self, vm_ip: Ipv4Addr) -> Option<SessionId> {
        self.inner
            .read()
            .expect("VmIpSessionMap lock poisoned")
            .get(&vm_ip)
            .copied()
    }

    /// Number of active bindings. Exposed for tests and operator
    /// observability (future metric).
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .expect("VmIpSessionMap lock poisoned")
            .len()
    }

    /// Whether the map is currently empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn bind_then_lookup_returns_session() {
        let map = VmIpSessionMap::new();
        let sid = SessionId::generate();
        assert_eq!(map.bind(ip("10.0.0.2"), sid), None);
        assert_eq!(map.lookup(ip("10.0.0.2")), Some(sid));
    }

    #[test]
    fn lookup_unknown_ip_returns_none() {
        let map = VmIpSessionMap::new();
        assert_eq!(map.lookup(ip("192.0.2.1")), None);
    }

    #[test]
    fn unbind_removes_and_returns_previous_session() {
        let map = VmIpSessionMap::new();
        let sid = SessionId::generate();
        map.bind(ip("10.0.0.3"), sid);
        assert_eq!(map.unbind(ip("10.0.0.3")), Some(sid));
        assert_eq!(map.lookup(ip("10.0.0.3")), None);
        // Unbinding again is a no-op.
        assert_eq!(map.unbind(ip("10.0.0.3")), None);
    }

    #[test]
    fn bind_overwrites_previous_session() {
        let map = VmIpSessionMap::new();
        let sid_a = SessionId::generate();
        let sid_b = SessionId::generate();
        assert_eq!(map.bind(ip("10.0.0.4"), sid_a), None);
        assert_eq!(map.bind(ip("10.0.0.4"), sid_b), Some(sid_a));
        assert_eq!(map.lookup(ip("10.0.0.4")), Some(sid_b));
    }

    #[test]
    fn clone_shares_storage() {
        let a = VmIpSessionMap::new();
        let b = a.clone();
        let sid = SessionId::generate();
        a.bind(ip("10.0.0.5"), sid);
        assert_eq!(b.lookup(ip("10.0.0.5")), Some(sid));
    }

    #[test]
    fn len_and_is_empty_track_bindings() {
        let map = VmIpSessionMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        map.bind(ip("10.0.0.6"), SessionId::generate());
        map.bind(ip("10.0.0.7"), SessionId::generate());
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
        map.unbind(ip("10.0.0.6"));
        assert_eq!(map.len(), 1);
    }

    #[tokio::test]
    async fn concurrent_access_smoke() {
        // Contenders write and read concurrently; we don't assert on
        // exact ordering, only that no panic / deadlock / poison occurs.
        let map = VmIpSessionMap::new();
        let mut handles = Vec::new();
        for i in 0..16u8 {
            let m = map.clone();
            handles.push(tokio::task::spawn(async move {
                let addr = Ipv4Addr::new(10, 0, 0, 100 + i);
                let sid = SessionId::generate();
                for _ in 0..64 {
                    m.bind(addr, sid);
                    let _ = m.lookup(addr);
                }
                m.unbind(addr);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(map.is_empty(), "all tasks unbound their IPs: {}", map.len());
    }
}
