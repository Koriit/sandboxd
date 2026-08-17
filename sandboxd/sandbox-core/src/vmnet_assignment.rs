//! Which operator each vmnet slot's capacity belongs to.
//!
//! Enrollment is what assigns a slot range: a privileged, one-time act that
//! creates a per-operator Unix group, records the operator's slots on that
//! group record, and puts the operator in it. The daemon does not allocate
//! ranges and does not store them — it *reads* them back, from state only
//! root can write.
//!
//! # Two sources, and which one answers today
//!
//! | | Source of truth | From |
//! |---|---|---|
//! | **Assignment** — which slots are an operator's | the per-operator group's membership | now |
//! | **Enforcement** — who the kernel lets connect | the slot socket's gid | when the sockets move onto those groups |
//!
//! Until the sockets move, every slot socket still carries the shared daemon
//! group, so the socket gid answers "which operator" for no one. The
//! assignment recorded at enrollment is what this module reads. Once the
//! sockets do move the two agree, and the same walk gives the same answer
//! from either direction — a slot socket whose gid is a per-operator group is
//! resolved through that group exactly as a recorded range is.
//!
//! What derivation buys, stated no higher than it is: **the daemon cannot be
//! wrong about what is currently running.** It does not self-heal a host
//! whose slot sockets never came up — in that state there is nothing to
//! `stat`, which is why an absent socket has a diagnosis of its own here
//! rather than being folded into generic lost capacity.
//!
//! # This is bookkeeping, not access control
//!
//! Every enrolled operator can open every slot socket while the sockets stay
//! on the shared group. Partitioning the pool the way this module describes
//! stops the daemon from *handing out* another operator's slot; it does not
//! stop anyone from connecting to one. The kernel-side half is a separate,
//! later change.

use crate::network::SANDBOXD_ACCOUNT;

/// Prefix of every per-operator vmnet slot group.
///
/// The `op-` infix keeps a per-operator group for an operator named `test`
/// from colliding with the `_sandboxd-test` service group.
///
/// Declared here *and* in `scripts/darwin-operator-group.sh`, which is the
/// side that creates these groups — an installer that a host may run from a
/// `curl | sh` pipe cannot read a Rust constant. A drift between the two is
/// silent in the worst way: the groups keep being created and the daemon
/// simply stops finding them, reading as lost capacity rather than as a bug.
/// `vmnet_operator_group_lint.rs` compares the two and fails when they
/// disagree.
pub const OPERATOR_GROUP_PREFIX: &str = "_sandboxd-op-";

/// Native Directory Services attribute on a per-operator group record
/// holding that operator's slot range, e.g. `4-7` or `0-3,6`.
///
/// The group record is where the range belongs: root-owned, and the same
/// store as the membership the range is meaningless without. Kept in step
/// with `scripts/darwin-operator-group.sh` by the same lint.
pub const SLOT_RANGE_ATTRIBUTE: &str = "SandboxdSlots";

/// Accounts that belong to these groups by design and are not operators.
///
/// An explicit list rather than a name prefix. Prefix matching on `_` would
/// absorb a future real operator whose account happens to start with one,
/// and this count is what decides whether a slot is assignable — an operator
/// silently excluded here reads as an unassignable slot, i.e. as lost
/// capacity with no cause attached.
///
/// The daemon account is taken from [`SANDBOXD_ACCOUNT`] rather than
/// re-spelled: it is the same identity the vmnet plists name.
pub const SERVICE_ACCOUNTS: &[&str] = &[SANDBOXD_ACCOUNT, "_sandboxd-test"];

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// A per-operator group as enrollment left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorGroup {
    /// Group name, e.g. `_sandboxd-op-operator-b`.
    pub name: String,
    /// Numeric gid, needed for the membership check.
    pub gid: u32,
    /// Slots recorded against this group, expanded and sorted. Empty when
    /// the group carries no range attribute — a group with an owner but no
    /// recorded range answers nothing, and must not read as the whole pool.
    pub slots: Vec<u16>,
}

/// An account that could be an operator: a member of the shared daemon
/// group, which is the record enrollment maintains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateOperator {
    /// Short account name.
    pub name: String,
    /// Numeric uid.
    pub uid: u32,
}

/// Outcome of looking at one slot socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketProbe {
    /// The socket exists and carries this gid.
    Gid(u32),
    /// No such socket.
    Missing,
    /// The socket could not be examined (permissions, I/O).
    Unreadable(String),
}

/// The host facts range derivation reads.
///
/// A trait so the walk below is exercised against constructed hosts rather
/// than only against whichever host the tests happen to run on — every row
/// of the response table is a host shape, and most of them cannot be
/// produced on a developer's machine on demand.
pub trait SlotDirectory {
    /// Examine slot `slot`'s socket.
    fn socket_probe(&self, slot: u16) -> SocketProbe;

    /// Resolve a gid to a group name.
    fn group_name(&self, gid: u32) -> Option<String>;

    /// Every per-operator group on the host, with its recorded range.
    fn operator_groups(&self) -> Vec<OperatorGroup>;

    /// The candidate operator set — members of the shared daemon group.
    ///
    /// Deliberately *not* the state directory: a newly-enrolled operator has
    /// no `LIMA_HOME` yet, and that is precisely the operator who needs a
    /// definite answer about their range.
    fn candidate_operators(&self) -> Vec<CandidateOperator>;

    /// Whether `operator` is a member of the group with gid `gid`.
    ///
    /// Must consult the full group list for the account, primary gid
    /// included. Reading a group's member list instead would silently miss
    /// any account whose *primary* gid is the group.
    fn is_member(&self, operator: &CandidateOperator, gid: u32) -> Option<bool>;
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

/// Why a slot belongs to no one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unassignable {
    /// The slot socket does not exist.
    ///
    /// Its own diagnosis rather than generic lost capacity: this is the
    /// post-boot state of a slot whose launchd job failed in its preamble
    /// and never exec'd `socket_vmnet` at all. It is the highest-value
    /// message on this list, because the remedy is not "enroll someone".
    SocketMissing,
    /// The slot socket exists but could not be examined.
    SocketUnreadable {
        /// The underlying failure.
        detail: String,
    },
    /// The socket's gid resolves to no group on this host.
    UnresolvableGroup {
        /// The gid that did not resolve.
        gid: u32,
    },
    /// The socket's gid resolves to a group that is neither the shared
    /// daemon group nor one of ours.
    ForeignGroup {
        /// The group holding the socket.
        group: String,
    },
    /// The slot's group has no operator members — only service accounts, or
    /// nobody at all. Normal on a partially-enrolled host; still lost
    /// capacity, so it is logged and surfaced rather than passed over.
    NoOperator {
        /// The group(s) claiming the slot.
        groups: Vec<String>,
    },
    /// Two or more operators share the slot's group.
    ///
    /// The loud case. Two operators on one slot group is the whole defect
    /// the partition exists to remove, in miniature — so the slot is
    /// refused rather than awarded to whichever of them sorts first.
    MultipleOperators {
        /// The group(s) claiming the slot.
        groups: Vec<String>,
        /// The operators found in them.
        operators: Vec<String>,
    },
}

/// What a single slot resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotState {
    /// The slot is still on the shared daemon group and no per-operator
    /// group records it: this install has not been migrated.
    ///
    /// **Not a refusal.** On every host that has not run enrollment, every
    /// slot is in this state; refusing here would take the whole pool away
    /// from hosts that are working today and offer them no upgrade path.
    /// The slot stays assignable under the pre-migration model — shared, as
    /// it has always been — and the daemon warns, naming the migration.
    Legacy,
    /// The slot belongs to exactly one operator. The normal migrated case.
    Assigned {
        /// The owning operator's uid.
        operator_uid: u32,
        /// The owning operator's account name, for diagnostics.
        operator: String,
        /// The group that awarded it.
        group: String,
    },
    /// The slot belongs to no one, for one of several distinguishable
    /// reasons.
    Unassignable(Unassignable),
}

/// Every slot on the host, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAssignment {
    /// Per-slot state, indexed by slot number.
    states: Vec<SlotState>,
    /// Operator-facing warnings raised while deriving, chiefly the
    /// unmigrated-install notice.
    warnings: Vec<String>,
}

impl SlotAssignment {
    /// The pre-migration model over `host_slots` slots: one shared pool,
    /// nothing assigned to anyone.
    ///
    /// The degraded fallback for a derivation that could not run at all.
    /// Refusing instead would be a fail-closed rule over a *probe* fault
    /// rather than a host state, and it would take down a host that was
    /// working — while buying nothing, because at this stage the partition
    /// is the daemon's bookkeeping and not what keeps operators off each
    /// other's segments.
    pub fn all_legacy(host_slots: u16, why: &str) -> Self {
        Self {
            states: vec![SlotState::Legacy; host_slots as usize],
            warnings: vec![format!(
                "vmnet slot assignment could not be derived ({why}); falling back to the \
                 pre-migration model — all {host_slots} slots shared between every operator, \
                 as on an unenrolled host. Per-operator ranges are not in effect."
            )],
        }
    }

    /// Slots in the host pool.
    pub fn host_slots(&self) -> u16 {
        self.states.len() as u16
    }

    /// The state of every slot, in slot order.
    pub fn states(&self) -> &[SlotState] {
        &self.states
    }

    /// Warnings raised while deriving.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The slots assigned to `operator_uid`, sorted.
    pub fn range_for(&self, operator_uid: u32) -> Vec<u16> {
        self.states
            .iter()
            .enumerate()
            .filter_map(|(idx, state)| match state {
                SlotState::Assigned {
                    operator_uid: u, ..
                } if *u == operator_uid => Some(idx as u16),
                _ => None,
            })
            .collect()
    }

    /// The slots still under the pre-migration model, sorted.
    ///
    /// These stay shared, exactly as they are today. Handing each operator
    /// their own pool over the same indices would let two of them claim the
    /// same slot — the collision the single pre-migration pool never had.
    pub fn legacy_slots(&self) -> Vec<u16> {
        self.states
            .iter()
            .enumerate()
            .filter_map(|(idx, state)| matches!(state, SlotState::Legacy).then_some(idx as u16))
            .collect()
    }

    /// `(slot, reason)` for every slot that belongs to no one.
    pub fn unassignable(&self) -> Vec<(u16, &Unassignable)> {
        self.states
            .iter()
            .enumerate()
            .filter_map(|(idx, state)| match state {
                SlotState::Unassignable(reason) => Some((idx as u16, reason)),
                _ => None,
            })
            .collect()
    }

    /// One human-readable line per slot, for `/diagnostics`.
    pub fn describe(&self) -> Vec<String> {
        self.states
            .iter()
            .enumerate()
            .map(|(idx, state)| {
                let detail = match state {
                    SlotState::Legacy => {
                        "legacy shared group — install not migrated, slot stays shared".to_string()
                    }
                    SlotState::Assigned {
                        operator_uid,
                        operator,
                        group,
                    } => format!("assigned to {operator} (uid {operator_uid}) via {group}"),
                    SlotState::Unassignable(reason) => {
                        format!("unassignable: {}", describe(reason))
                    }
                };
                format!("slot {idx}: {detail}")
            })
            .collect()
    }
}

/// Render an [`Unassignable`] as operator-facing text.
fn describe(reason: &Unassignable) -> String {
    match reason {
        Unassignable::SocketMissing => "the slot socket does not exist — its launchd job \
             failed before socket_vmnet started, so this slot has no L2 segment at all. \
             Check `launchctl print system/io.sandboxd.vmnet.<slot>` and the job's stderr"
            .to_string(),
        Unassignable::SocketUnreadable { detail } => {
            format!("the slot socket could not be examined: {detail}")
        }
        Unassignable::UnresolvableGroup { gid } => {
            format!("the slot socket's gid {gid} resolves to no group on this host")
        }
        Unassignable::ForeignGroup { group } => {
            format!("the slot socket is held by group '{group}', which sandboxd did not create")
        }
        Unassignable::NoOperator { groups } => format!(
            "no operator is a member of {} — lost capacity until someone is enrolled into it",
            groups.join(", ")
        ),
        Unassignable::MultipleOperators { groups, operators } => format!(
            "{} operators ({}) share {} — refusing to pick one; de-enroll all but the owner",
            operators.len(),
            operators.join(", "),
            groups.join(", ")
        ),
    }
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

/// Resolve every slot on the host to an owner, a legacy fallback, or a
/// stated reason it belongs to no one.
///
/// Each row is decided on its own. There is no uniform rule across them —
/// applying one is how the unmigrated case became a refusal in an earlier
/// design, and a refusal there takes every host that exists today offline.
pub fn derive_slot_assignment<D: SlotDirectory + ?Sized>(
    dir: &D,
    host_slots: u16,
) -> SlotAssignment {
    let groups = dir.operator_groups();
    let candidates: Vec<CandidateOperator> = dir
        .candidate_operators()
        .into_iter()
        .filter(|c| !SERVICE_ACCOUNTS.contains(&c.name.as_str()))
        .collect();

    // Membership is resolved once per (group, candidate) pair rather than
    // once per slot: a range is several slots wide and the lookup reaches
    // Directory Services.
    let members: Vec<Vec<CandidateOperator>> = groups
        .iter()
        .map(|g| {
            candidates
                .iter()
                .filter(|c| dir.is_member(c, g.gid) == Some(true))
                .cloned()
                .collect()
        })
        .collect();

    let mut states = Vec::with_capacity(host_slots as usize);
    for slot in 0..host_slots {
        states.push(resolve_slot(dir, slot, &groups, &members));
    }

    let mut warnings = Vec::new();
    let legacy: Vec<u16> = states
        .iter()
        .enumerate()
        .filter_map(|(idx, s)| matches!(s, SlotState::Legacy).then_some(idx as u16))
        .collect();
    if !legacy.is_empty() {
        warnings.push(format!(
            "vmnet slots {legacy:?} are still on the shared '{SANDBOXD_ACCOUNT}' group: this \
             install has not been migrated to per-operator slot groups. They stay shared \
             between every enrolled operator, as they are today. Assign them by enrolling \
             operators with slot ranges \
             (`sudo scripts/darwin-operator-group.sh enroll --operator <name> --slots <range>`)."
        ));
    }

    SlotAssignment { states, warnings }
}

/// Decide one slot.
fn resolve_slot<D: SlotDirectory + ?Sized>(
    dir: &D,
    slot: u16,
    groups: &[OperatorGroup],
    members: &[Vec<CandidateOperator>],
) -> SlotState {
    let gid = match dir.socket_probe(slot) {
        SocketProbe::Missing => return SlotState::Unassignable(Unassignable::SocketMissing),
        SocketProbe::Unreadable(detail) => {
            return SlotState::Unassignable(Unassignable::SocketUnreadable { detail });
        }
        SocketProbe::Gid(gid) => gid,
    };
    let socket_group = dir.group_name(gid);

    // Every per-operator group with a claim on this slot: one that recorded
    // it at enrollment, and — once the sockets move onto these groups — the
    // one holding the socket. Both are consulted so the walk keeps working
    // across that move, and so a disagreement between them surfaces as the
    // conflict it is instead of one silently overriding the other.
    let claimants: Vec<usize> = (0..groups.len())
        .filter(|&i| {
            groups[i].slots.contains(&slot)
                || socket_group.as_deref() == Some(groups[i].name.as_str())
        })
        .collect();

    if claimants.is_empty() {
        return match socket_group {
            // The unmigrated case. Warn, fall back, do not refuse.
            Some(name) if name == SANDBOXD_ACCOUNT => SlotState::Legacy,
            Some(group) => SlotState::Unassignable(Unassignable::ForeignGroup { group }),
            None => SlotState::Unassignable(Unassignable::UnresolvableGroup { gid }),
        };
    }

    let names: Vec<String> = claimants.iter().map(|&i| groups[i].name.clone()).collect();
    // Carry the group each operator was found in rather than the first
    // claimant's name: a slot recorded by an empty group *and* by the owner's
    // group would otherwise be reported as awarded by the empty one, which is
    // the group an administrator would then go and look at.
    let mut operators: Vec<(CandidateOperator, String)> = Vec::new();
    for &i in &claimants {
        for op in &members[i] {
            if !operators.iter().any(|(existing, _)| existing.uid == op.uid) {
                operators.push((op.clone(), groups[i].name.clone()));
            }
        }
    }

    match operators.len() {
        1 => SlotState::Assigned {
            operator_uid: operators[0].0.uid,
            operator: operators[0].0.name.clone(),
            group: operators[0].1.clone(),
        },
        0 => SlotState::Unassignable(Unassignable::NoOperator { groups: names }),
        _ => SlotState::Unassignable(Unassignable::MultipleOperators {
            groups: names,
            operators: operators.into_iter().map(|(op, _)| op.name).collect(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Expand a recorded slot range — `4-7`, `0-3,6`, `2` — into sorted,
/// deduplicated slot indices.
///
/// Returns `None` for anything malformed. Both ends of a `lo-hi` part are
/// checked separately: `0-` passes a combined digits-only test and then
/// means whatever the reader assumes it means.
pub fn parse_slot_range(spec: &str) -> Option<Vec<u16>> {
    let mut out: Vec<u16> = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (lo, hi) = match part.split_once('-') {
            Some((lo, hi)) => (lo, hi),
            None => (part, part),
        };
        let lo: u16 = lo.parse().ok()?;
        let hi: u16 = hi.parse().ok()?;
        if lo > hi {
            return None;
        }
        out.extend(lo..=hi);
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

/// Pull the value out of one `dscl . -read <record> <key>` response.
///
/// Two traps, both of which produce a wrong answer rather than an error:
///
/// * `dscl -read` prints `No such key: <key>` and **still exits 0**, so exit
///   status cannot distinguish an absent attribute from a present one. Only
///   the text can.
/// * A native attribute reads back as `dsAttrTypeNative:<key>: <value>`, so
///   the key runs to the *last* colon before the first space. Splitting on
///   the first colon leaves `<key>: <value>` behind, which then compares
///   unequal to everything.
///
/// A long value is wrapped onto continuation lines that begin with a space;
/// those are joined back on.
pub fn parse_dscl_value(output: &str) -> Option<String> {
    let mut lines = output.lines();
    let first = lines.next()?.trim_end();
    if first.is_empty() || first.starts_with("No such key") {
        return None;
    }

    // Strip the longest run of non-space characters ending in ':'.
    let head_end = first.find(' ').unwrap_or(first.len());
    let value_start = match first[..head_end].rfind(':') {
        Some(colon) => colon + 1,
        None => return None,
    };
    let mut value = first[value_start..].trim().to_string();

    for line in lines {
        let cont = line.trim();
        if cont.is_empty() {
            continue;
        }
        if !value.is_empty() {
            value.push(' ');
        }
        value.push_str(cont);
    }

    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

// ---------------------------------------------------------------------------
// The live host
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod live {
    use std::time::Duration;

    use tracing::{debug, warn};

    use super::{
        CandidateOperator, OperatorGroup, SLOT_RANGE_ATTRIBUTE, SlotDirectory, SocketProbe,
        parse_dscl_value, parse_slot_range,
    };
    use crate::network::{SANDBOXD_ACCOUNT, vmnet_slot_socket_path};

    /// Absolute path so the daemon's `PATH` cannot redirect the lookup.
    const DSCL: &str = "/usr/bin/dscl";

    /// Directory Services is local; a read that has not answered in this
    /// long is not going to.
    const DSCL_TIMEOUT: Duration = Duration::from_secs(10);

    /// The live host, read through `dscl(1)` and `stat(2)`.
    ///
    /// Every read here succeeds unprivileged as the daemon account — the
    /// group records are world-readable and the slot sockets sit in a
    /// directory the daemon owns.
    pub struct HostSlotDirectory;

    /// Run `dscl . -read /Groups/<record> <key>` and return its value.
    fn dscl_read(record: &str, key: &str) -> Option<String> {
        let mut cmd = std::process::Command::new(DSCL);
        cmd.args([".", "-read", &format!("/Groups/{record}"), key]);
        let out = crate::process::run_with_timeout(&mut cmd, DSCL_TIMEOUT, "dscl -read")
            .inspect_err(|e| warn!(record, key, error = %e, "dscl read failed"))
            .ok()?;
        // Exit status is deliberately not consulted for absence: `dscl`
        // reports a missing key on stdout and exits 0.
        parse_dscl_value(&String::from_utf8_lossy(&out.stdout))
    }

    impl SlotDirectory for HostSlotDirectory {
        fn socket_probe(&self, slot: u16) -> SocketProbe {
            use std::os::unix::fs::MetadataExt;

            match std::fs::metadata(vmnet_slot_socket_path(slot)) {
                Ok(md) => SocketProbe::Gid(md.gid()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => SocketProbe::Missing,
                Err(e) => SocketProbe::Unreadable(e.to_string()),
            }
        }

        fn group_name(&self, gid: u32) -> Option<String> {
            nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))
                .ok()
                .flatten()
                .map(|g| g.name)
        }

        fn operator_groups(&self) -> Vec<OperatorGroup> {
            let mut cmd = std::process::Command::new(DSCL);
            cmd.args([".", "-list", "/Groups"]);
            let out = match crate::process::run_with_timeout(&mut cmd, DSCL_TIMEOUT, "dscl -list") {
                Ok(out) => out,
                Err(e) => {
                    warn!(error = %e, "listing groups failed; no slot range can be derived");
                    return Vec::new();
                }
            };

            String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::trim)
                .filter(|name| name.starts_with(super::OPERATOR_GROUP_PREFIX))
                .filter_map(|name| {
                    let gid = nix::unistd::Group::from_name(name)
                        .ok()
                        .flatten()
                        .map(|g| g.gid.as_raw())?;
                    // A group with an owner but no recorded range answers
                    // nothing, and must read as unassignable rather than as
                    // the whole pool.
                    let slots = dscl_read(name, SLOT_RANGE_ATTRIBUTE)
                        .and_then(|spec| {
                            parse_slot_range(&spec).or_else(|| {
                                warn!(group = name, spec, "malformed slot range; ignoring it");
                                None
                            })
                        })
                        .unwrap_or_default();
                    Some(OperatorGroup {
                        name: name.to_string(),
                        gid,
                        slots,
                    })
                })
                .collect()
        }

        fn candidate_operators(&self) -> Vec<CandidateOperator> {
            let Some(members) = dscl_read(SANDBOXD_ACCOUNT, "GroupMembership") else {
                debug!("shared daemon group lists no members");
                return Vec::new();
            };
            members
                .split_whitespace()
                .filter_map(|name| {
                    let uid = nix::unistd::User::from_name(name)
                        .ok()
                        .flatten()
                        .map(|u| u.uid.as_raw())?;
                    Some(CandidateOperator {
                        name: name.to_string(),
                        uid,
                    })
                })
                .collect()
        }

        fn is_member(&self, operator: &CandidateOperator, gid: u32) -> Option<bool> {
            group_list_contains(&operator.name, operator.uid, gid)
        }
    }

    /// Whether `getgrouplist(3)` reports `gid` for this account.
    ///
    /// `getgrouplist` consults the directory database and returns the
    /// complete list, primary gid included. Reading the group's own member
    /// list instead would miss any account whose primary gid *is* the group
    /// — which the daemon account's own record demonstrates.
    ///
    /// Mirrors the broker's enrollment gate rather than sharing it: that one
    /// is the privileged path's authorization decision and does not grow a
    /// second caller for a bookkeeping read. `nix` 0.29 does not expose
    /// `getgrouplist` on Apple targets, so `libc` is called directly, as the
    /// doctor's equivalent check also does.
    fn group_list_contains(name: &str, uid: u32, gid: u32) -> Option<bool> {
        let name_c = std::ffi::CString::new(name.as_bytes()).ok()?;
        let primary = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
            .map(|u| u.gid.as_raw())?;

        // On macOS `getgrouplist` takes int for the primary gid and int[]
        // for the buffer, unlike Linux's gid_t.
        let mut ngroups: libc::c_int = 64;
        loop {
            let mut groups: Vec<libc::c_int> = vec![0; ngroups as usize];
            // SAFETY: `name_c` is a valid NUL-terminated C string, `groups`
            // is a correctly-sized mutable buffer, and `primary` came from
            // this account's own passwd record.
            let ret = unsafe {
                libc::getgrouplist(
                    name_c.as_ptr(),
                    primary as libc::c_int,
                    groups.as_mut_ptr(),
                    &mut ngroups,
                )
            };
            if ret == -1 {
                if (ngroups as usize) > groups.len() && ngroups < 65536 {
                    // Buffer too small; `ngroups` now holds the requirement.
                    continue;
                }
                warn!(name, ngroups, "getgrouplist capacity error");
                return None;
            }
            return Some(
                groups
                    .iter()
                    .take(ngroups as usize)
                    .any(|&g| g as libc::gid_t == gid),
            );
        }
    }
}

#[cfg(target_os = "macos")]
pub use live::HostSlotDirectory;

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A host assembled slot by slot.
    #[derive(Default)]
    struct FakeDirectory {
        sockets: HashMap<u16, SocketProbe>,
        gid_names: HashMap<u32, String>,
        groups: Vec<OperatorGroup>,
        candidates: Vec<CandidateOperator>,
        /// (uid, gid) pairs that `getgrouplist` would report.
        memberships: Vec<(u32, u32)>,
    }

    const LEGACY_GID: u32 = 310;

    impl FakeDirectory {
        /// A host whose slot sockets all carry the shared daemon group —
        /// i.e. every host that has not been migrated.
        fn unmigrated(host_slots: u16) -> Self {
            let mut dir = Self {
                gid_names: HashMap::from([(LEGACY_GID, SANDBOXD_ACCOUNT.to_string())]),
                ..Default::default()
            };
            for slot in 0..host_slots {
                dir.sockets.insert(slot, SocketProbe::Gid(LEGACY_GID));
            }
            dir
        }

        fn with_group(mut self, name: &str, gid: u32, slots: &[u16]) -> Self {
            self.gid_names.insert(gid, name.to_string());
            self.groups.push(OperatorGroup {
                name: name.to_string(),
                gid,
                slots: slots.to_vec(),
            });
            self
        }

        fn with_candidate(mut self, name: &str, uid: u32) -> Self {
            self.candidates.push(CandidateOperator {
                name: name.to_string(),
                uid,
            });
            self
        }

        fn with_membership(mut self, uid: u32, gid: u32) -> Self {
            self.memberships.push((uid, gid));
            self
        }

        fn with_socket(mut self, slot: u16, probe: SocketProbe) -> Self {
            self.sockets.insert(slot, probe);
            self
        }
    }

    impl SlotDirectory for FakeDirectory {
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

    /// Row 1 of the response table, and the one that matters most: on a host
    /// whose sockets still carry the shared group, every slot falls back and
    /// nothing is refused. Every host that has not run enrollment is this
    /// host.
    #[test]
    fn legacy_group_falls_back_with_a_warning_and_never_refuses() {
        let dir = FakeDirectory::unmigrated(8).with_candidate("olek", 501);
        let assignment = derive_slot_assignment(&dir, 8);

        assert_eq!(assignment.legacy_slots(), (0..8).collect::<Vec<u16>>());
        assert!(
            assignment.unassignable().is_empty(),
            "an unmigrated install must not produce a single unassignable slot: {:?}",
            assignment.unassignable()
        );
        assert!(
            assignment.warnings().iter().any(|w| w.contains("migrated")),
            "the fallback must warn and name the migration: {:?}",
            assignment.warnings()
        );
    }

    /// Row 2 — the normal migrated case.
    #[test]
    fn a_group_with_one_operator_owns_its_recorded_range() {
        let dir = FakeDirectory::unmigrated(8)
            .with_group("_sandboxd-op-operator-b", 311, &[4, 5, 6, 7])
            .with_candidate("operator-b", 528)
            .with_candidate("olek", 501)
            .with_membership(528, 311);

        let assignment = derive_slot_assignment(&dir, 8);

        assert_eq!(assignment.range_for(528), vec![4, 5, 6, 7]);
        // The unrecorded half is still legacy, and still shared.
        assert_eq!(assignment.legacy_slots(), vec![0, 1, 2, 3]);
        assert!(assignment.range_for(501).is_empty());
    }

    /// Row 3 — a group nobody is in. Lost capacity, not a startup failure:
    /// a partially-enrolled host is a normal state to be in.
    #[test]
    fn a_group_with_no_operators_is_unassignable_not_fatal() {
        let dir = FakeDirectory::unmigrated(8)
            .with_group("_sandboxd-op-departed", 311, &[4, 5, 6, 7])
            .with_candidate("olek", 501);

        let assignment = derive_slot_assignment(&dir, 8);

        let unassignable = assignment.unassignable();
        assert_eq!(unassignable.len(), 4);
        for (slot, reason) in unassignable {
            assert!(
                matches!(reason, Unassignable::NoOperator { .. }),
                "slot {slot} should read as no-operator, got {reason:?}"
            );
        }
        assert_eq!(assignment.legacy_slots(), vec![0, 1, 2, 3]);
    }

    /// Row 4 — the loud case. Two operators in one slot group is the defect
    /// the partition exists to remove, so neither of them gets the slot.
    #[test]
    fn a_group_with_two_operators_is_refused_and_names_both() {
        let dir = FakeDirectory::unmigrated(8)
            .with_group("_sandboxd-op-shared", 311, &[4, 5, 6, 7])
            .with_candidate("operator-b", 528)
            .with_candidate("operator-c", 529)
            .with_membership(528, 311)
            .with_membership(529, 311);

        let assignment = derive_slot_assignment(&dir, 8);

        assert!(assignment.range_for(528).is_empty());
        assert!(assignment.range_for(529).is_empty());
        let (_, reason) = assignment.unassignable()[0];
        match reason {
            Unassignable::MultipleOperators { operators, .. } => {
                assert_eq!(operators.len(), 2);
            }
            other => panic!("expected a multi-operator refusal, got {other:?}"),
        }
        assert!(describe(reason).contains("operator-b"));
    }

    /// Row 5 — an absent socket has its own diagnosis. This is the post-boot
    /// state of a slot whose launchd job never exec'd `socket_vmnet`, and
    /// reporting it as generic lost capacity would send the reader looking
    /// for an operator to enroll.
    #[test]
    fn an_absent_socket_is_diagnosed_as_a_dead_launchd_job() {
        let dir = FakeDirectory::unmigrated(8).with_socket(3, SocketProbe::Missing);
        let assignment = derive_slot_assignment(&dir, 8);

        let unassignable = assignment.unassignable();
        assert_eq!(unassignable.len(), 1);
        assert_eq!(unassignable[0].0, 3);
        assert!(matches!(unassignable[0].1, &Unassignable::SocketMissing));
        let text = describe(unassignable[0].1);
        assert!(
            text.contains("launchd") && text.contains("socket_vmnet"),
            "the absent-socket diagnosis must point at the job, not at enrollment: {text}"
        );
        // The other seven slots are unaffected.
        assert_eq!(assignment.legacy_slots().len(), 7);
    }

    /// A socket that exists but cannot be examined is distinguishable from
    /// one that does not exist — the remedies differ.
    #[test]
    fn an_unreadable_socket_is_distinct_from_a_missing_one() {
        let dir = FakeDirectory::unmigrated(4)
            .with_socket(1, SocketProbe::Unreadable("permission denied".into()));
        let assignment = derive_slot_assignment(&dir, 4);

        match assignment.unassignable()[0].1 {
            Unassignable::SocketUnreadable { detail } => {
                assert!(detail.contains("permission denied"))
            }
            other => panic!("expected an unreadable socket, got {other:?}"),
        }
    }

    /// Service accounts are in these groups by design. Counting them would
    /// turn every correctly-enrolled group into a multi-operator refusal —
    /// and the daemon account is in *every* one of them.
    #[test]
    fn service_accounts_do_not_count_as_operators() {
        let dir = FakeDirectory::unmigrated(8)
            .with_group("_sandboxd-op-operator-b", 311, &[4, 5, 6, 7])
            .with_candidate("operator-b", 528)
            .with_candidate(SANDBOXD_ACCOUNT, 310)
            .with_candidate("_sandboxd-test", 309)
            .with_membership(528, 311)
            .with_membership(310, 311)
            .with_membership(309, 311);

        let assignment = derive_slot_assignment(&dir, 8);

        assert_eq!(
            assignment.range_for(528),
            vec![4, 5, 6, 7],
            "the daemon account and the test account are members by design; \
             counting them makes every enrolled group look contested"
        );
        assert!(assignment.range_for(310).is_empty());
        assert!(assignment.range_for(309).is_empty());
    }

    /// The exclusion is a list, not a prefix: an operator whose account name
    /// happens to start with an underscore is still an operator.
    #[test]
    fn the_service_account_exclusion_is_a_list_not_a_prefix() {
        let dir = FakeDirectory::unmigrated(8)
            .with_group("_sandboxd-op-_ops", 311, &[0, 1])
            .with_candidate("_ops", 601)
            .with_membership(601, 311);

        let assignment = derive_slot_assignment(&dir, 8);

        assert_eq!(assignment.range_for(601), vec![0, 1]);
    }

    /// Once the sockets move onto per-operator groups, the socket gid gives
    /// the same answer the recorded range does — the walk does not change.
    #[test]
    fn a_socket_gid_on_a_per_operator_group_resolves_the_same_way() {
        let mut dir = FakeDirectory::unmigrated(8)
            .with_group("_sandboxd-op-operator-b", 311, &[])
            .with_candidate("operator-b", 528)
            .with_membership(528, 311);
        for slot in 4..8 {
            dir.sockets.insert(slot, SocketProbe::Gid(311));
        }

        let assignment = derive_slot_assignment(&dir, 8);

        assert_eq!(assignment.range_for(528), vec![4, 5, 6, 7]);
        assert_eq!(assignment.legacy_slots(), vec![0, 1, 2, 3]);
    }

    /// A slot socket held by a group sandboxd did not create is refused,
    /// rather than silently treated as the pre-migration default.
    #[test]
    fn a_foreign_group_is_not_mistaken_for_the_legacy_one() {
        let mut dir = FakeDirectory::unmigrated(4);
        dir.gid_names.insert(20, "staff".to_string());
        dir.sockets.insert(2, SocketProbe::Gid(20));

        let assignment = derive_slot_assignment(&dir, 4);

        assert_eq!(assignment.legacy_slots(), vec![0, 1, 3]);
        match assignment.unassignable()[0].1 {
            Unassignable::ForeignGroup { group } => assert_eq!(group, "staff"),
            other => panic!("expected a foreign-group refusal, got {other:?}"),
        }
    }

    /// A group with an owner but no recorded range answers nothing. Reading
    /// the absence as "all of them" is how a group nobody assigned slots to
    /// starts looking like a group that owns the pool.
    #[test]
    fn a_group_with_no_recorded_range_claims_nothing() {
        let dir = FakeDirectory::unmigrated(8)
            .with_group("_sandboxd-op-operator-b", 311, &[])
            .with_candidate("operator-b", 528)
            .with_membership(528, 311);

        let assignment = derive_slot_assignment(&dir, 8);

        assert!(assignment.range_for(528).is_empty());
        assert_eq!(assignment.legacy_slots().len(), 8);
    }

    /// The group named on an assignment is the one the operator was actually
    /// found in — not whichever claimant sorted first. An administrator acts
    /// on that name.
    #[test]
    fn an_assignment_names_the_group_the_operator_is_in() {
        let dir = FakeDirectory::unmigrated(4)
            .with_group("_sandboxd-op-departed", 311, &[2])
            .with_group("_sandboxd-op-operator-b", 312, &[2])
            .with_candidate("operator-b", 528)
            .with_membership(528, 312);

        let assignment = derive_slot_assignment(&dir, 4);

        match &assignment.states()[2] {
            SlotState::Assigned { group, .. } => assert_eq!(group, "_sandboxd-op-operator-b"),
            other => panic!("expected slot 2 assigned to the group with the member: {other:?}"),
        }
    }

    /// Two groups recording the same slot is the multi-operator conflict
    /// wearing a different hat, and gets the same refusal.
    #[test]
    fn two_groups_recording_one_slot_refuse_it() {
        let dir = FakeDirectory::unmigrated(4)
            .with_group("_sandboxd-op-b", 311, &[2])
            .with_group("_sandboxd-op-c", 312, &[2])
            .with_candidate("operator-b", 528)
            .with_candidate("operator-c", 529)
            .with_membership(528, 311)
            .with_membership(529, 312);

        let assignment = derive_slot_assignment(&dir, 4);

        assert!(assignment.range_for(528).is_empty());
        assert!(assignment.range_for(529).is_empty());
        assert!(matches!(
            assignment.unassignable()[0].1,
            Unassignable::MultipleOperators { .. }
        ));
    }

    #[test]
    fn slot_ranges_expand_merge_and_reject() {
        assert_eq!(parse_slot_range("4-7"), Some(vec![4, 5, 6, 7]));
        assert_eq!(parse_slot_range("0-3,6"), Some(vec![0, 1, 2, 3, 6]));
        assert_eq!(parse_slot_range("3,0,1,2"), Some(vec![0, 1, 2, 3]));
        assert_eq!(parse_slot_range("2"), Some(vec![2]));
        assert_eq!(parse_slot_range(""), Some(vec![]));
        // Both ends checked separately — "0-" must not pass as "0".
        assert_eq!(parse_slot_range("0-"), None);
        assert_eq!(parse_slot_range("7-4"), None);
        assert_eq!(parse_slot_range("a-b"), None);
        assert_eq!(parse_slot_range("0-3,x"), None);
    }

    /// `dscl -read` reports a missing attribute on stdout and exits 0, so
    /// the text is the only signal. And a native attribute's key runs to the
    /// *last* colon before the first space.
    #[test]
    fn dscl_values_survive_both_of_the_read_traps() {
        assert_eq!(
            parse_dscl_value("dsAttrTypeNative:SandboxdSlots: 4-7"),
            Some("4-7".to_string()),
            "splitting on the first colon leaves the key glued to the value"
        );
        assert_eq!(
            parse_dscl_value("GroupMembership: olek _sandboxd-test operator-b"),
            Some("olek _sandboxd-test operator-b".to_string())
        );
        assert_eq!(parse_dscl_value("No such key: SandboxdSlots"), None);
        assert_eq!(parse_dscl_value(""), None);
        // Wrapped values are joined back on.
        assert_eq!(
            parse_dscl_value("GroupMembership: alpha\n bravo\n charlie"),
            Some("alpha bravo charlie".to_string())
        );
    }

    /// The whole point of the partition, asserted directly: no slot index is
    /// ever handed to two operators.
    #[test]
    fn derived_ranges_are_disjoint_across_operators() {
        let dir = FakeDirectory::unmigrated(8)
            .with_group("_sandboxd-op-b", 311, &[0, 1, 2, 3])
            .with_group("_sandboxd-op-c", 312, &[4, 5, 6, 7])
            .with_candidate("operator-b", 528)
            .with_candidate("operator-c", 529)
            .with_membership(528, 311)
            .with_membership(529, 312);

        let assignment = derive_slot_assignment(&dir, 8);
        let b = assignment.range_for(528);
        let c = assignment.range_for(529);

        assert_eq!(b, vec![0, 1, 2, 3]);
        assert_eq!(c, vec![4, 5, 6, 7]);
        assert!(b.iter().all(|slot| !c.contains(slot)));
        assert!(
            assignment.legacy_slots().is_empty(),
            "a fully-assigned host has no shared remainder"
        );
    }
}
