//! One [`VmnetPool`] per operator, keyed by uid.
//!
//! The pool's shape and its claim/release semantics are unchanged — there is
//! simply more than one of it, each seeded with a disjoint slot range derived
//! from [`crate::vmnet_assignment`].
//!
//! # The shared remainder
//!
//! Slots still on the shared daemon group are handed out from **one** pool
//! that every unassigned operator draws on. That is what "fall back to
//! current behaviour" has to mean: today a single pool serialises every
//! claim, so no two sessions can land on one L2 segment. Giving each operator
//! their own pool over the same indices would reintroduce exactly that
//! collision, on the hosts least prepared for it.
//!
//! An operator with an assigned range draws only on it, never additionally on
//! the remainder: two ledgers for one operator would let them exceed the
//! quota either one enforces, and a release would have to guess which ledger
//! a slot came from.
//!
//! # Locking
//!
//! One `Mutex<HashMap<u32, _>>`, held only across a lookup or an insert, with
//! the map growing monotonically — the discipline `LimaManagerRegistry` uses.
//! Its *fields* are another matter: that registry carries an executor, a base
//! VM name, an owner pool, a platform flag and an injected provisioner, none
//! of which mean anything here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tracing::{info, warn};

use crate::SessionId;
use crate::error::SandboxError;
use crate::network::{ClaimedSlot, NetworkInfo, VmnetPool};
use crate::vmnet_assignment::SlotAssignment;

/// What a persisted session needs restored.
#[derive(Debug, Clone)]
pub enum RestoreKind {
    /// A Lima session holding a NIC slot; carries the persisted network
    /// info to re-register.
    Slot(Box<NetworkInfo>),
    /// A lite session holding only a session-count token.
    Token,
}

/// One persisted session, as restore sees it.
#[derive(Debug, Clone)]
pub struct RestoreEntry {
    /// The session.
    pub session_id: SessionId,
    /// The account recorded on the session row.
    pub owner_username: String,
    /// The operator uid persisted on the session's `NetworkInfo`, if the
    /// record was written by a daemon that stores it.
    pub operator_uid: Option<u32>,
    /// What it holds.
    pub kind: RestoreKind,
}

/// A claim restore refused to re-register, and why.
///
/// The pool's leak accessor reports slots that *are* claimed, so it cannot
/// surface a claim that was declined — that is the inverse condition and
/// needs its own list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclinedRestore {
    /// The session whose claim was declined.
    pub session_id: SessionId,
    /// The slot it held, when it held one.
    pub slot: Option<u16>,
    /// The account recorded on the session row.
    pub owner_username: String,
    /// Why the claim could not be re-registered.
    pub reason: String,
}

impl DeclinedRestore {
    /// One human-readable line for `/diagnostics`.
    pub fn describe(&self) -> String {
        let slot = match self.slot {
            Some(slot) => format!("slot {slot}"),
            None => "session-count token".to_string(),
        };
        format!(
            "session {} ({}, owner '{}'): {}",
            self.session_id, slot, self.owner_username, self.reason
        )
    }
}

/// Per-operator [`VmnetPool`] instances, keyed by operator uid.
pub struct VmnetPoolRegistry {
    /// Per-operator pool map. Entries are never removed; the map grows as
    /// operators create sessions. Several uids may map to the same `Arc`
    /// when they share the pre-migration remainder.
    pools: Mutex<HashMap<u32, Arc<VmnetPool>>>,
    /// The derived slot assignment this registry partitions by. Read once
    /// at startup: enrollment is privileged, one-time, and does not take
    /// effect on a running daemon.
    assignment: SlotAssignment,
    /// The pool over slots still on the shared group, or `None` on a host
    /// where every slot has been assigned.
    remainder: Option<Arc<VmnetPool>>,
    /// Claims restore declined to re-register.
    declined: Mutex<Vec<DeclinedRestore>>,
}

impl VmnetPoolRegistry {
    /// Build a registry over a derived assignment.
    pub fn new(assignment: SlotAssignment) -> Self {
        let host_slots = assignment.host_slots();
        let legacy = assignment.legacy_slots();
        let remainder =
            (!legacy.is_empty()).then(|| Arc::new(VmnetPool::with_range(&legacy, host_slots)));
        Self {
            pools: Mutex::new(HashMap::new()),
            assignment,
            remainder,
            declined: Mutex::new(Vec::new()),
        }
    }

    /// Slots in the host pool, across every operator.
    ///
    /// This, not any one pool's quota, is what the gateway VM's NIC set and
    /// the host-level diagnostics are sized from: the daemon's gateway VM
    /// carries an interface on every slot regardless of who owns it.
    pub fn host_slots(&self) -> u16 {
        self.assignment.host_slots()
    }

    /// The derived assignment.
    pub fn assignment(&self) -> &SlotAssignment {
        &self.assignment
    }

    /// The pool `operator_uid` claims from.
    ///
    /// Returns [`SandboxError::Conflict`] (409) when the operator has no
    /// assigned range *and* there is no shared remainder left to fall back
    /// on — a configuration conflict that no amount of retrying resolves.
    /// That is deliberately a different shape from
    /// [`SandboxError::SessionQuotaExhausted`] (429), which means the
    /// operator's own share is momentarily full.
    pub fn pool_for(&self, operator_uid: u32) -> Result<Arc<VmnetPool>, SandboxError> {
        {
            let pools = self.pools.lock().map_err(|e| {
                SandboxError::Internal(format!("VmnetPoolRegistry mutex poisoned: {e}"))
            })?;
            if let Some(pool) = pools.get(&operator_uid) {
                return Ok(Arc::clone(pool));
            }
        } // lock released before deriving this operator's range

        let range = self.assignment.range_for(operator_uid);
        let pool = if range.is_empty() {
            match &self.remainder {
                Some(shared) => Arc::clone(shared),
                None => return Err(self.no_range_assigned(operator_uid)),
            }
        } else {
            Arc::new(VmnetPool::with_range(&range, self.host_slots()))
        };

        let mut pools = self.pools.lock().map_err(|e| {
            SandboxError::Internal(format!("VmnetPoolRegistry mutex poisoned: {e}"))
        })?;
        Ok(Arc::clone(
            pools
                .entry(operator_uid)
                .or_insert_with(|| Arc::clone(&pool)),
        ))
    }

    /// Build the "no range assigned" refusal, and log the part the response
    /// must not carry.
    ///
    /// Any enrolled operator can provoke this error, so naming whoever holds
    /// the pool would hand every one of them the roster of sandboxd users on
    /// a shared machine. The response body describes the requester's own
    /// situation and the remedy; the holders go to the daemon log and to
    /// `/diagnostics`, where the audience is the administrator who can act.
    fn no_range_assigned(&self, operator_uid: u32) -> SandboxError {
        let holders: Vec<String> = self
            .assignment
            .describe()
            .into_iter()
            .filter(|line| line.contains("assigned to"))
            .collect();
        warn!(
            operator_uid,
            holders = ?holders,
            "refusing a session: no vmnet slot range is assigned to this operator"
        );

        SandboxError::Conflict(format!(
            "no vmnet slot range is assigned to operator uid {operator_uid}. This host's \
             pool has {} slots; none are assigned to you and none are still shared.\n\
             This is a configuration conflict, not a capacity limit — retrying cannot \
             clear it. An administrator must enroll this operator with a slot range:\n  \
             sudo scripts/darwin-operator-group.sh enroll --operator <name> --slots <range>\n\
             Which operator holds which slots is in the daemon log and in \
             GET /diagnostics.",
            self.host_slots()
        ))
    }

    /// Every distinct pool, once each.
    ///
    /// Operators sharing the remainder map to one `Arc`; aggregating over
    /// the map's values would count its claims once per operator.
    fn distinct_pools(&self) -> Vec<Arc<VmnetPool>> {
        let pools = match self.pools.lock() {
            Ok(pools) => pools,
            Err(e) => e.into_inner(),
        };
        let mut seen: Vec<Arc<VmnetPool>> = Vec::new();
        for pool in pools.values().chain(self.remainder.iter()) {
            if !seen.iter().any(|p| Arc::ptr_eq(p, pool)) {
                seen.push(Arc::clone(pool));
            }
        }
        seen
    }

    /// Every claimed slot on the host, with the operator holding it.
    pub fn claimed_slot_sessions(&self) -> Vec<ClaimedSlot> {
        let mut claims: Vec<ClaimedSlot> = self
            .distinct_pools()
            .iter()
            .flat_map(|pool| pool.claimed_slot_sessions())
            .collect();
        claims.sort_by_key(|c| c.slot);
        claims
    }

    /// Slot indices claimed across every pool.
    pub fn allocated_slot_indices(&self) -> Vec<u16> {
        let mut slots: Vec<u16> = self
            .distinct_pools()
            .iter()
            .flat_map(|pool| pool.allocated_slot_indices())
            .collect();
        slots.sort_unstable();
        slots.dedup();
        slots
    }

    /// Release a session's NIC slot, wherever it is held.
    ///
    /// Idempotent in every pool, so this asks all of them rather than
    /// requiring each teardown path to first work out which operator a
    /// session belonged to — several of them run at startup with no
    /// requester in hand, and a release that guessed wrong would leave a
    /// slot claimed forever.
    pub fn release_lima_slot(&self, session_id: &SessionId) -> Result<(), SandboxError> {
        for pool in self.distinct_pools() {
            pool.release_lima_slot(session_id)?;
        }
        Ok(())
    }

    /// Release one session-count token from `operator_uid`'s pool.
    ///
    /// Unlike a slot, a token carries no identity of its own — it is a
    /// count — so the operator has to be supplied. Session access is
    /// owner-scoped, which is what makes the requesting operator the right
    /// one at every handler that calls this.
    pub fn release_lite_token(&self, operator_uid: u32) -> Result<(), SandboxError> {
        self.pool_for(operator_uid)?.release_lite_token()
    }

    /// Claims restore declined to re-register.
    pub fn declined_restores(&self) -> Vec<DeclinedRestore> {
        match self.declined.lock() {
            Ok(declined) => declined.clone(),
            Err(e) => e.into_inner().clone(),
        }
    }

    /// Record a declined claim.
    fn decline(&self, declined: DeclinedRestore) {
        warn!(
            session_id = %declined.session_id,
            owner = %declined.owner_username,
            reason = %declined.reason,
            "declining to restore a vmnet claim"
        );
        match self.declined.lock() {
            Ok(mut list) => list.push(declined),
            Err(e) => e.into_inner().push(declined),
        }
    }

    /// Re-register persisted claims into their operators' pools.
    ///
    /// Routing is by the persisted operator uid; a record written before
    /// that field existed falls back to resolving its `owner_username`
    /// through `resolve_uid`. When that fails — the account was removed,
    /// renamed, or does not resolve at startup — the claim is **declined**
    /// and listed, never guessed at and never dropped in silence. Guessing
    /// would put a session on some other operator's segment; dropping would
    /// leave a running VM holding a slot the pool believes is free.
    pub fn restore(
        &self,
        entries: &[RestoreEntry],
        resolve_uid: &dyn Fn(&str) -> Option<u32>,
    ) -> RestoreOutcome {
        let mut outcome = RestoreOutcome::default();

        for entry in entries {
            let slot = match &entry.kind {
                RestoreKind::Slot(info) => info.vmnet_slot.as_ref().map(|vs| vs.index),
                RestoreKind::Token => None,
            };

            let Some(operator_uid) = entry
                .operator_uid
                .or_else(|| resolve_uid(&entry.owner_username))
            else {
                self.decline(DeclinedRestore {
                    session_id: entry.session_id,
                    slot,
                    owner_username: entry.owner_username.clone(),
                    reason: format!(
                        "the session carries no operator uid and its owner '{}' does not \
                         resolve to an account on this host, so there is no pool to restore \
                         it into. Stop the session to release its capacity.",
                        entry.owner_username
                    ),
                });
                outcome.declined += 1;
                continue;
            };

            let pool = match self.pool_for(operator_uid) {
                Ok(pool) => pool,
                Err(e) => {
                    self.decline(DeclinedRestore {
                        session_id: entry.session_id,
                        slot,
                        owner_username: entry.owner_username.clone(),
                        reason: format!("operator uid {operator_uid} has no pool: {e}"),
                    });
                    outcome.declined += 1;
                    continue;
                }
            };

            match &entry.kind {
                RestoreKind::Slot(info) => {
                    match pool.restore_from_infos(
                        &[(entry.session_id, info.as_ref().clone())],
                        operator_uid,
                    ) {
                        Ok(()) => outcome.slots += 1,
                        Err(e) => {
                            self.decline(DeclinedRestore {
                                session_id: entry.session_id,
                                slot,
                                owner_username: entry.owner_username.clone(),
                                reason: format!("{e}"),
                            });
                            outcome.declined += 1;
                        }
                    }
                }
                RestoreKind::Token => match pool.restore_lite_tokens(1) {
                    Ok(()) => outcome.tokens += 1,
                    Err(e) => {
                        self.decline(DeclinedRestore {
                            session_id: entry.session_id,
                            slot,
                            owner_username: entry.owner_username.clone(),
                            reason: format!("{e}"),
                        });
                        outcome.declined += 1;
                    }
                },
            }
        }

        info!(
            slots = outcome.slots,
            tokens = outcome.tokens,
            declined = outcome.declined,
            "vmnet pool state restored"
        );
        outcome
    }
}

/// What one restore pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// NIC slots re-registered.
    pub slots: u32,
    /// Session-count tokens re-registered.
    pub tokens: u32,
    /// Claims declined.
    pub declined: u32,
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::VmnetSlot;
    use crate::vmnet_assignment::{
        CandidateOperator, OperatorGroup, SlotDirectory, SocketProbe, derive_slot_assignment,
    };
    use std::collections::HashMap as StdHashMap;

    const LEGACY_GID: u32 = 310;
    const OP_B_GID: u32 = 311;
    const OP_B_UID: u32 = 528;
    const UNENROLLED_UID: u32 = 501;

    struct Host {
        sockets: StdHashMap<u16, SocketProbe>,
        gid_names: StdHashMap<u32, String>,
        groups: Vec<OperatorGroup>,
        candidates: Vec<CandidateOperator>,
        memberships: Vec<(u32, u32)>,
    }

    impl Host {
        fn unmigrated(host_slots: u16) -> Self {
            let mut sockets = StdHashMap::new();
            for slot in 0..host_slots {
                sockets.insert(slot, SocketProbe::Gid(LEGACY_GID));
            }
            Self {
                sockets,
                gid_names: StdHashMap::from([(
                    LEGACY_GID,
                    crate::network::SANDBOXD_ACCOUNT.to_string(),
                )]),
                groups: Vec::new(),
                candidates: Vec::new(),
                memberships: Vec::new(),
            }
        }

        fn enroll(mut self, name: &str, gid: u32, uid: u32, slots: &[u16]) -> Self {
            let group = format!("_sandboxd-op-{name}");
            self.gid_names.insert(gid, group.clone());
            self.groups.push(OperatorGroup {
                name: group,
                gid,
                slots: slots.to_vec(),
            });
            self.candidates.push(CandidateOperator {
                name: name.to_string(),
                uid,
            });
            self.memberships.push((uid, gid));
            self
        }

        fn candidate(mut self, name: &str, uid: u32) -> Self {
            self.candidates.push(CandidateOperator {
                name: name.to_string(),
                uid,
            });
            self
        }

        fn registry(&self, host_slots: u16) -> VmnetPoolRegistry {
            VmnetPoolRegistry::new(derive_slot_assignment(self, host_slots))
        }
    }

    impl SlotDirectory for Host {
        fn socket_probe(&self, slot: u16) -> SocketProbe {
            self.sockets
                .get(&slot)
                .cloned()
                .unwrap_or(SocketProbe::Missing)
        }
        fn group_name(&self, gid: u32) -> Option<String> {
            self.gid_names.get(&gid).cloned()
        }
        fn operator_groups(&self) -> Vec<OperatorGroup> {
            self.groups.clone()
        }
        fn candidate_operators(&self) -> Vec<CandidateOperator> {
            self.candidates.clone()
        }
        fn is_member(&self, operator: &CandidateOperator, gid: u32) -> Option<bool> {
            Some(self.memberships.contains(&(operator.uid, gid)))
        }
    }

    fn slot_info(slot: u16, operator_uid: Option<u32>) -> NetworkInfo {
        NetworkInfo {
            gateway_egress_ip: None,
            operator_uid,
            bridge_name: format!("lima{slot}"),
            subnet: "10.209.128.0/29".to_string(),
            gateway_ip: "10.209.128.3".to_string(),
            vm_ip: "10.209.128.4".to_string(),
            docker_network_name: "sandbox-net-test".to_string(),
            vmnet_slot: Some(VmnetSlot {
                index: slot,
                daemon_label: format!("io.sandboxd.vmnet.{slot}"),
                socket_path: format!("/var/run/sandbox/vmnet/slot-{slot}.sock"),
            }),
        }
    }

    /// The regression that matters most. A host nobody has enrolled — which
    /// is every host that exists — keeps one pool of eight, hands out slot 0
    /// first, and refuses nothing.
    #[test]
    fn an_unmigrated_host_keeps_the_whole_pool_and_todays_concurrency() {
        let registry = Host::unmigrated(8)
            .candidate("olek", UNENROLLED_UID)
            .registry(8);

        let pool = registry
            .pool_for(UNENROLLED_UID)
            .expect("an unmigrated host must not refuse a session");

        assert_eq!(pool.max_slots(), 8);
        assert_eq!(pool.range(), (0..8).collect::<Vec<u16>>());

        let mut claimed = Vec::new();
        for _ in 0..8 {
            let sid = SessionId::generate();
            let (slot, _, _, _) = pool
                .claim_lima_slot(&sid, UNENROLLED_UID)
                .expect("eight concurrent sessions is today's behaviour");
            claimed.push(slot.index);
        }
        claimed.sort_unstable();
        assert_eq!(claimed, (0..8).collect::<Vec<u16>>());

        let ninth = pool.claim_lima_slot(&SessionId::generate(), UNENROLLED_UID);
        assert!(matches!(
            ninth,
            Err(SandboxError::SessionQuotaExhausted { .. })
        ));
    }

    /// The other single-operator shape: enrollment with no `--slots`, which
    /// records the whole pool. Same eight sessions, same indices from zero —
    /// partitioning a pool nobody else uses would be a straight regression.
    #[test]
    fn a_default_single_operator_enrollment_keeps_the_whole_pool() {
        let registry = Host::unmigrated(8)
            .enroll("alice", OP_B_GID, OP_B_UID, &[0, 1, 2, 3, 4, 5, 6, 7])
            .registry(8);

        let pool = registry.pool_for(OP_B_UID).expect("the only operator");
        assert_eq!(pool.range(), (0..8).collect::<Vec<u16>>());
        assert_eq!(pool.max_slots(), 8);

        let mut claimed = Vec::new();
        for _ in 0..8 {
            claimed.push(
                pool.claim_lima_slot(&SessionId::generate(), OP_B_UID)
                    .unwrap()
                    .0
                    .index,
            );
        }
        claimed.sort_unstable();
        assert_eq!(claimed, (0..8).collect::<Vec<u16>>());
        assert!(matches!(
            pool.claim_lima_slot(&SessionId::generate(), OP_B_UID),
            Err(SandboxError::SessionQuotaExhausted { .. })
        ));

        // Nothing is left shared, so this host has no remainder at all.
        assert!(registry.assignment().legacy_slots().is_empty());
    }

    /// The daemon uid is not the operator uid in production. The pool an
    /// operator gets must be keyed on *their* uid, not on whoever the daemon
    /// happens to be — a distinction a host where the two coincide cannot
    /// make.
    #[test]
    fn an_operators_pool_is_keyed_on_the_operator_not_the_daemon() {
        const DAEMON_UID: u32 = 310;
        let registry = Host::unmigrated(8)
            .enroll("operator-b", OP_B_GID, OP_B_UID, &[4, 5, 6, 7])
            .candidate("olek", UNENROLLED_UID)
            .registry(8);

        let operator = registry.pool_for(OP_B_UID).expect("enrolled operator");
        assert_eq!(operator.range(), &[4, 5, 6, 7]);

        // The daemon account is a member of every per-operator group by
        // design, and must still not be handed anyone's range.
        let daemon = registry.pool_for(DAEMON_UID).expect("shared remainder");
        assert_eq!(daemon.range(), &[0, 1, 2, 3]);
        assert!(!Arc::ptr_eq(&operator, &daemon));
    }

    /// Two operators, disjoint ranges, no shared index — asserted by
    /// draining both pools rather than by reading the ranges back.
    #[test]
    fn two_pools_never_hand_out_the_same_slot() {
        let registry = Host::unmigrated(8)
            .enroll("operator-b", OP_B_GID, OP_B_UID, &[0, 1, 2, 3])
            .enroll("operator-c", 312, 529, &[4, 5, 6, 7])
            .registry(8);

        let b = registry.pool_for(OP_B_UID).unwrap();
        let c = registry.pool_for(529).unwrap();

        let mut handed_out = Vec::new();
        for _ in 0..4 {
            handed_out.push(
                b.claim_lima_slot(&SessionId::generate(), OP_B_UID)
                    .unwrap()
                    .0
                    .index,
            );
            handed_out.push(
                c.claim_lima_slot(&SessionId::generate(), 529)
                    .unwrap()
                    .0
                    .index,
            );
        }
        handed_out.sort_unstable();
        let unique = {
            let mut u = handed_out.clone();
            u.dedup();
            u
        };
        assert_eq!(handed_out, unique, "a slot index was handed out twice");
        assert_eq!(handed_out, (0..8).collect::<Vec<u16>>());
    }

    /// Exhausting a share is a 429; having no share at all is a 409. The two
    /// are different conditions with different remedies and must not be
    /// conflated.
    #[test]
    fn a_full_share_and_an_absent_share_are_different_errors() {
        let registry = Host::unmigrated(8)
            .enroll("operator-b", OP_B_GID, OP_B_UID, &[0, 1, 2, 3])
            .enroll("operator-c", 312, 529, &[4, 5, 6, 7])
            .candidate("olek", UNENROLLED_UID)
            .registry(8);

        let b = registry.pool_for(OP_B_UID).unwrap();
        for _ in 0..4 {
            b.claim_lima_slot(&SessionId::generate(), OP_B_UID).unwrap();
        }
        assert!(matches!(
            b.claim_lima_slot(&SessionId::generate(), OP_B_UID),
            Err(SandboxError::SessionQuotaExhausted { .. })
        ));

        // Nothing is left unassigned, so an operator with no range has
        // nothing to fall back on.
        match registry.pool_for(UNENROLLED_UID).err() {
            Some(SandboxError::Conflict(msg)) => {
                assert!(msg.contains("no vmnet slot range is assigned"));
                assert!(
                    msg.contains("8 slots"),
                    "the pool size must be stated: {msg}"
                );
                assert!(msg.contains("enroll"), "the remedy must be stated: {msg}");
                assert!(
                    !msg.contains("operator-b") && !msg.contains("operator-c"),
                    "the body must not name the operators holding the pool: {msg}"
                );
            }
            Some(other) => panic!("expected a 409-shaped conflict, got {other:?}"),
            None => panic!("an operator with no range must be refused, not given a pool"),
        }
    }

    /// Sessions carrying an operator uid land in that operator's pool.
    #[test]
    fn restore_shards_by_the_persisted_operator_uid() {
        let registry = Host::unmigrated(8)
            .enroll("operator-b", OP_B_GID, OP_B_UID, &[4, 5, 6, 7])
            .candidate("olek", UNENROLLED_UID)
            .registry(8);

        let b_session = SessionId::generate();
        let outcome = registry.restore(
            &[RestoreEntry {
                session_id: b_session,
                owner_username: "operator-b".to_string(),
                operator_uid: Some(OP_B_UID),
                kind: RestoreKind::Slot(Box::new(slot_info(5, Some(OP_B_UID)))),
            }],
            &|_| None,
        );

        assert_eq!(outcome.slots, 1);
        assert_eq!(outcome.declined, 0);
        let b = registry.pool_for(OP_B_UID).unwrap();
        assert!(b.allocated_slot_indices().contains(&5));
        assert_eq!(b.running_session_count(), 1);
    }

    /// A record written before the field existed is routed by resolving its
    /// owner name.
    #[test]
    fn restore_falls_back_to_the_owner_username() {
        let registry = Host::unmigrated(8)
            .enroll("operator-b", OP_B_GID, OP_B_UID, &[4, 5, 6, 7])
            .registry(8);

        let outcome = registry.restore(
            &[RestoreEntry {
                session_id: SessionId::generate(),
                owner_username: "operator-b".to_string(),
                operator_uid: None,
                kind: RestoreKind::Slot(Box::new(slot_info(6, None))),
            }],
            &|name| (name == "operator-b").then_some(OP_B_UID),
        );

        assert_eq!(outcome.slots, 1);
        assert!(
            registry
                .pool_for(OP_B_UID)
                .unwrap()
                .allocated_slot_indices()
                .contains(&6)
        );
    }

    /// When neither route resolves, the claim is declined and listed — not
    /// guessed at, and not dropped in silence.
    #[test]
    fn restore_declines_rather_than_guesses_when_identity_is_unresolvable() {
        let registry = Host::unmigrated(8).registry(8);
        let orphan = SessionId::generate();

        let outcome = registry.restore(
            &[RestoreEntry {
                session_id: orphan,
                owner_username: "deleted-account".to_string(),
                operator_uid: None,
                kind: RestoreKind::Slot(Box::new(slot_info(2, None))),
            }],
            &|_| None,
        );

        assert_eq!(outcome.declined, 1);
        assert_eq!(outcome.slots, 0);
        assert!(
            registry.allocated_slot_indices().is_empty(),
            "an unroutable claim must not be guessed into a pool"
        );

        let declined = registry.declined_restores();
        assert_eq!(declined.len(), 1);
        assert_eq!(declined[0].session_id, orphan);
        assert_eq!(declined[0].slot, Some(2));
        assert!(declined[0].describe().contains("deleted-account"));
    }

    /// A persisted claim on a slot outside the operator's range is refused
    /// rather than absorbed — absorbing it would put two operators on one
    /// segment.
    #[test]
    fn restore_refuses_a_slot_outside_the_operators_range() {
        let registry = Host::unmigrated(8)
            .enroll("operator-b", OP_B_GID, OP_B_UID, &[4, 5, 6, 7])
            .enroll("operator-c", 312, 529, &[0, 1, 2, 3])
            .registry(8);

        let outcome = registry.restore(
            &[RestoreEntry {
                session_id: SessionId::generate(),
                owner_username: "operator-b".to_string(),
                operator_uid: Some(OP_B_UID),
                kind: RestoreKind::Slot(Box::new(slot_info(1, Some(OP_B_UID)))),
            }],
            &|_| None,
        );

        assert_eq!(outcome.declined, 1);
        assert!(
            registry
                .pool_for(OP_B_UID)
                .unwrap()
                .allocated_slot_indices()
                .is_empty()
        );
        assert!(registry.declined_restores()[0].reason.contains("outside"));
    }

    /// Lite sessions hold a token and no slot, so their operator cannot be
    /// inferred from a slot index — the persisted uid is what routes them.
    #[test]
    fn restore_routes_lite_tokens_to_their_operators_quota() {
        let registry = Host::unmigrated(8)
            .enroll("operator-b", OP_B_GID, OP_B_UID, &[4, 5])
            .registry(8);

        let outcome = registry.restore(
            &[
                RestoreEntry {
                    session_id: SessionId::generate(),
                    owner_username: "operator-b".to_string(),
                    operator_uid: Some(OP_B_UID),
                    kind: RestoreKind::Token,
                },
                RestoreEntry {
                    session_id: SessionId::generate(),
                    owner_username: "operator-b".to_string(),
                    operator_uid: Some(OP_B_UID),
                    kind: RestoreKind::Token,
                },
            ],
            &|_| None,
        );

        assert_eq!(outcome.tokens, 2);
        let pool = registry.pool_for(OP_B_UID).unwrap();
        assert_eq!(pool.running_session_count(), 2);
        assert!(matches!(
            pool.claim_lite_token(OP_B_UID),
            Err(SandboxError::SessionQuotaExhausted { .. })
        ));
    }

    /// Unassigned operators must share **one** ledger, not get a pool each.
    ///
    /// This is the part of the fallback that is not obvious, and the part
    /// someone will eventually try to "fix" for symmetry — every other
    /// operator has a pool of their own, so why not these. Because a private
    /// pool per operator over the *same* indices has no way to know the other
    /// pool handed out slot 0 a moment ago. Both would hand it out, both VMs
    /// would attach to segment 0, and the two operators would be peers on one
    /// L2 segment — each able to be believed as the other's next hop. That is
    /// the isolation failure this whole partition exists to remove, produced
    /// by the code meant to preserve the status quo.
    ///
    /// The single pre-migration pool could not produce it: one ledger,
    /// serialised claims. So "fall back to current behaviour" means one
    /// shared pool, and a pool each is not a symmetrical variant of it — it
    /// is a different and worse thing. If you are here to split this, that is
    /// what you would be turning back on.
    #[test]
    fn unassigned_operators_share_one_remainder_ledger() {
        let registry = Host::unmigrated(4)
            .candidate("olek", UNENROLLED_UID)
            .candidate("someone-else", 502)
            .registry(4);

        let a = registry.pool_for(UNENROLLED_UID).unwrap();
        let b = registry.pool_for(502).unwrap();
        assert!(
            Arc::ptr_eq(&a, &b),
            "two operators with no assigned range were given separate pools \
             over the same slot indices"
        );

        let first = a
            .claim_lima_slot(&SessionId::generate(), UNENROLLED_UID)
            .unwrap()
            .0
            .index;
        let second = b
            .claim_lima_slot(&SessionId::generate(), 502)
            .unwrap()
            .0
            .index;
        assert_ne!(
            first, second,
            "two operators were handed slot {first} — they are now peers on one \
             L2 segment, which the single pre-migration pool could not produce"
        );

        // And the host-wide view attributes each claim to its own operator.
        let claims = registry.claimed_slot_sessions();
        assert_eq!(claims.len(), 2);
        assert!(claims.iter().any(|c| c.operator_uid == UNENROLLED_UID));
        assert!(claims.iter().any(|c| c.operator_uid == 502));
    }

    /// Repeated lookups return the same pool: the registry grows
    /// monotonically and never rebuilds an operator's ledger underneath a
    /// live claim.
    #[test]
    fn a_pool_lookup_is_stable_for_the_daemons_lifetime() {
        let registry = Host::unmigrated(8)
            .enroll("operator-b", OP_B_GID, OP_B_UID, &[4, 5, 6, 7])
            .registry(8);

        let first = registry.pool_for(OP_B_UID).unwrap();
        first
            .claim_lima_slot(&SessionId::generate(), OP_B_UID)
            .unwrap();
        let second = registry.pool_for(OP_B_UID).unwrap();

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(second.running_session_count(), 1);
    }
}
