//! Range derivation against the live host.
//!
//! The hermetic tests in `vmnet_assignment` and `vmnet_pool_registry` decide
//! every row of the response table against constructed hosts. What they cannot
//! establish is that the *reader* works: that `dscl` output parses the way the
//! parser expects, that `getgrouplist(3)` sees a membership the group record
//! does not list, and — the one that matters most — that a host whose slot
//! sockets still carry the shared group hands an unenrolled operator a working
//! pool rather than a refusal.
//!
//! Integration-tier because it reads Directory Services and stats the live
//! slot sockets. It skips rather than fails on a host with no provisioned
//! pool, since there is nothing there to be right or wrong about.

#![cfg(target_os = "macos")]

use sandbox_core::vmnet_assignment::{
    HostSlotDirectory, SlotDirectory, SocketProbe, derive_slot_assignment,
};
use sandbox_core::vmnet_pool_registry::VmnetPoolRegistry;

/// The provisioned pool size, as the installed plists define it.
const POOL_SLOTS: u16 = 8;

/// A uid that is certainly not enrolled with a slot range anywhere.
const NOBODY_UID: u32 = 65530;

/// How many of the pool's slot sockets exist on this host.
fn provisioned_slots(dir: &HostSlotDirectory) -> u16 {
    (0..POOL_SLOTS)
        .filter(|slot| matches!(dir.socket_probe(*slot), SocketProbe::Gid(_)))
        .count() as u16
}

/// The measurement, printed so a run is also a report.
#[test]
fn integration_derives_the_live_hosts_slot_assignment() {
    let dir = HostSlotDirectory;
    if provisioned_slots(&dir) == 0 {
        eprintln!("skipping: no vmnet slot sockets on this host");
        return;
    }

    let assignment = derive_slot_assignment(&dir, POOL_SLOTS);
    for line in assignment.describe() {
        eprintln!("{line}");
    }
    for warning in assignment.warnings() {
        eprintln!("warning: {warning}");
    }
    eprintln!("legacy slots: {:?}", assignment.legacy_slots());
    for group in dir.operator_groups() {
        eprintln!(
            "group {} (gid {}) records slots {:?}",
            group.name, group.gid, group.slots
        );
    }

    assert_eq!(assignment.host_slots(), POOL_SLOTS);
}

/// The criterion that catches the outage a fail-closed rule would have caused.
///
/// While any slot is still on the shared group, an operator nobody has
/// enrolled must get a pool — not a refusal. Asserted against an arbitrary
/// uid so it holds regardless of who runs it.
#[test]
fn integration_an_unenrolled_operator_is_not_refused_on_a_legacy_host() {
    let dir = HostSlotDirectory;
    if provisioned_slots(&dir) == 0 {
        eprintln!("skipping: no vmnet slot sockets on this host");
        return;
    }

    let assignment = derive_slot_assignment(&dir, POOL_SLOTS);
    let legacy = assignment.legacy_slots();
    if legacy.is_empty() {
        eprintln!("skipping: this host has no unmigrated slots left");
        return;
    }

    let registry = VmnetPoolRegistry::new(assignment);
    let pool = registry.pool_for(NOBODY_UID).unwrap_or_else(|e| {
        panic!(
            "an operator with no enrollment was refused on a host that still has \
             unmigrated slots {legacy:?}. Every host that has not been migrated is \
             this host, so this refusal is a total outage: {e}"
        )
    });

    assert_eq!(
        pool.range(),
        legacy,
        "an unenrolled operator draws on exactly the slots that are still shared"
    );
    assert!(pool.max_slots() > 0);

    // And again for whoever is running this, when they are unenrolled — a
    // real account with a real group list, rather than a uid chosen to have
    // no directory presence at all.
    let me = nix::unistd::getuid().as_raw();
    let registry = VmnetPoolRegistry::new(derive_slot_assignment(&dir, POOL_SLOTS));
    if registry.assignment().range_for(me).is_empty() {
        let mine = registry.pool_for(me).unwrap_or_else(|e| {
            panic!("uid {me} is unenrolled on a host with unmigrated slots and was refused: {e}")
        });
        assert_eq!(mine.range(), legacy);
        eprintln!("uid {me} (unenrolled) draws on slots {:?}", mine.range());
    }
}

/// An operator enrolled with a slot range gets exactly that range — checked
/// against what enrollment actually recorded, not against a constant.
#[test]
fn integration_an_enrolled_operator_gets_exactly_its_recorded_range() {
    let dir = HostSlotDirectory;
    if provisioned_slots(&dir) == 0 {
        eprintln!("skipping: no vmnet slot sockets on this host");
        return;
    }

    let candidates = dir.candidate_operators();
    let assignment = derive_slot_assignment(&dir, POOL_SLOTS);
    let mut checked = 0;

    for group in dir.operator_groups() {
        if group.slots.is_empty() {
            continue;
        }
        // The group's operator members, by the same rule derivation uses:
        // the full group list for each candidate, service accounts excluded.
        let owners: Vec<_> = candidates
            .iter()
            .filter(|c| {
                !sandbox_core::vmnet_assignment::SERVICE_ACCOUNTS.contains(&c.name.as_str())
                    && dir.is_member(c, group.gid) == Some(true)
            })
            .collect();
        if owners.len() != 1 {
            continue;
        }
        let owner = owners[0];

        assert_eq!(
            assignment.range_for(owner.uid),
            group.slots,
            "{} records slots {:?} for {} (uid {}), but derivation gave a \
             different range",
            group.name,
            group.slots,
            owner.name,
            owner.uid
        );

        // And the pool built from it enforces that range as its quota.
        let registry = VmnetPoolRegistry::new(derive_slot_assignment(&dir, POOL_SLOTS));
        let pool = registry
            .pool_for(owner.uid)
            .expect("an operator with a recorded range must get a pool");
        assert_eq!(pool.range(), group.slots);
        assert_eq!(pool.max_slots() as usize, group.slots.len());
        checked += 1;
    }

    if checked == 0 {
        eprintln!("skipping: no singly-owned per-operator group with a recorded range");
    }
}

/// The daemon account is a member of every per-operator group by design.
/// Counting it would make every correctly-enrolled group look contested, so
/// the live host is where that exclusion is worth confirming: its membership
/// is real here, not constructed.
#[test]
fn integration_the_daemon_account_is_not_counted_as_an_operator() {
    let dir = HostSlotDirectory;
    let groups = dir.operator_groups();
    if groups.is_empty() {
        eprintln!("skipping: no per-operator groups on this host");
        return;
    }

    let daemon_uid = nix::unistd::User::from_name(sandbox_core::network::SANDBOXD_ACCOUNT)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw());
    let Some(daemon_uid) = daemon_uid else {
        eprintln!("skipping: the daemon account does not resolve on this host");
        return;
    };

    let assignment = derive_slot_assignment(&dir, POOL_SLOTS);
    assert!(
        assignment.range_for(daemon_uid).is_empty(),
        "the daemon account was awarded a slot range; it is a member of every \
         per-operator group by design and is not an operator"
    );
}
