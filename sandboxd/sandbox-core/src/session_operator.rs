//! Which operator a persisted session belongs to.
//!
//! A session row records an account *name*; almost everything that acts on a
//! session on macOS needs a *uid* — whose LIMA_HOME, whose agent, whose
//! gateway. Turning one into the other is the same problem the vmnet pools
//! already solve at startup ([`crate::vmnet_pool_registry::RestoreEntry`] and
//! [`crate::vmnet_pool_registry::VmnetPoolRegistry::restore`]), and this is
//! that discipline as a pure function: consult what the record persisted,
//! fall back to resolving the name, and when neither answers, say so in a
//! value rather than picking something.
//!
//! # Why the unresolvable case is a variant and not a default
//!
//! The caller this exists for partitions sessions by operator. A session that
//! silently defaulted to some uid would land in the wrong partition; a
//! session quietly dropped would land in none. Both are the same outcome for
//! a *running* session — it is never reconciled, never recovered, and its
//! sandbox keeps running with whatever network state it had. That is the
//! failure this daemon exists to prevent, so "no answer" is represented, and
//! represented as something a caller has to look at.
//!
//! [`SessionOperator`] is therefore `#[must_use]` and deliberately has no
//! `uid()`, no `unwrap_or`, and no `Option` conversion. Every one of those
//! would be spelled `.unwrap_or(daemon_uid)` at the first call site that
//! found the match inconvenient, which is exactly the silent default this
//! type exists to make unavailable. Reading the uid means matching, and
//! matching means seeing the other arm.
//!
//! # What is deliberately not here
//!
//! What to *do* with an unresolvable session — attribute it to the daemon,
//! decline it and surface the list, or refuse to start — is a policy
//! decision that belongs with the code that recovers sessions, not with the
//! code that resolves them. This module makes the case impossible to lose
//! and leaves the choice to its caller.

use crate::SessionId;
use crate::network::NetworkInfo;
use crate::session::Session;

/// The operator a persisted session belongs to.
///
/// See the module documentation for why the unresolved case is a variant
/// rather than a fallback uid.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum SessionOperator {
    /// The uid to attribute the session to.
    Uid(u32),
    /// Neither the record nor the host's account directory names an
    /// operator for this session.
    Unresolved(UnresolvedSessionOperator),
}

/// A session whose operator could not be determined, and why.
///
/// Carries enough to report the session without holding it: a caller that
/// collects these for `/diagnostics` keeps a small owned value per session
/// rather than a clone of every unresolvable [`Session`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedSessionOperator {
    /// The session that could not be attributed.
    pub session_id: SessionId,
    /// The account recorded on the session row, as recorded — including
    /// empty, which is itself the reason in one of the two cases.
    pub owner_username: String,
    /// Why no uid could be determined.
    pub reason: String,
}

impl UnresolvedSessionOperator {
    /// One human-readable line, matching
    /// [`crate::vmnet_pool_registry::DeclinedRestore::describe`]'s shape so
    /// the two read alike wherever they are surfaced together.
    pub fn describe(&self) -> String {
        format!(
            "session {} (owner '{}'): {}",
            self.session_id, self.owner_username, self.reason
        )
    }
}

/// Resolve the operator uid for one persisted session.
///
/// `network` is the session's persisted [`NetworkInfo`], when the caller has
/// one; passing `None` costs only the weaker of the two persisted hints.
/// `resolve_uid` maps an account name to a uid — in the daemon, an NSS
/// lookup; in a test, a map.
///
/// Pure. It reads no file, resolves no name itself, and logs nothing: what
/// happens to an unresolvable session is its caller's decision, and a
/// warning emitted here would announce a problem before anyone had decided
/// whether it was one.
///
/// # Resolution order
///
/// 1. [`Session::operator_uid`] — the creating operator's uid, captured from
///    `SO_PEERCRED` at `POST /sessions` and persisted in its own column.
///    This is the daemon's own record of who asked, taken from the kernel at
///    the moment they asked.
/// 2. [`NetworkInfo::operator_uid`] — the uid the session's slot or
///    session-count token was drawn against. Present on rows whose network
///    state was written by a daemon that stores it, which is not the same
///    set of rows as (1): a session's `NetworkInfo` is rewritten across its
///    life and dropped when it stops, while the session column is stamped
///    once at create.
/// 3. `resolve_uid(&session.owner_username)` — resolving the name against
///    the host. Last because a name is indirection through a directory that
///    can change underneath the record: an account can be removed, or
///    removed and a new one created reusing the name, and the second case
///    answers confidently with the wrong uid. The two persisted hints cannot
///    go stale that way.
///
/// (1) and (2) both derive from the same identity at create time and are not
/// expected to disagree. If they ever do, (1) wins: it is what the kernel
/// reported about the caller, where (2) is what a later bookkeeping step
/// recorded about a resource. Treating a disagreement as its own outcome
/// would be a policy this function does not make.
///
/// # The empty owner
///
/// An empty `owner_username` is not asked about. It is what a record carries
/// when it has no account on it at all — not a name that might resolve — and
/// the resolver is a caller-supplied function whose answer for `""` is not
/// this module's to assume. A session is attributed to a real operator only
/// on evidence that names one.
pub fn resolve_session_operator(
    session: &Session,
    network: Option<&NetworkInfo>,
    resolve_uid: &dyn Fn(&str) -> Option<u32>,
) -> SessionOperator {
    if let Some(uid) = session
        .operator_uid
        .or_else(|| network.and_then(|info| info.operator_uid))
    {
        return SessionOperator::Uid(uid);
    }

    if session.owner_username.is_empty() {
        return SessionOperator::Unresolved(UnresolvedSessionOperator {
            session_id: session.id,
            owner_username: String::new(),
            reason: "the session carries no operator uid and no owner account, so there is \
                     nothing on the record that names an operator."
                .to_string(),
        });
    }

    match resolve_uid(&session.owner_username) {
        Some(uid) => SessionOperator::Uid(uid),
        None => SessionOperator::Unresolved(UnresolvedSessionOperator {
            session_id: session.id,
            owner_username: session.owner_username.clone(),
            reason: format!(
                "the session carries no operator uid and its owner '{}' does not resolve to \
                 an account on this host, so there is no operator to attribute it to.",
                session.owner_username
            ),
        }),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkInfo;

    /// A resolver that fails the test if it is consulted at all.
    ///
    /// Every persisted hint is supposed to short-circuit the name lookup, and
    /// "it returned the right uid anyway" would not distinguish a hint that
    /// was used from a name that happened to resolve to the same number.
    fn unused_resolver(name: &str) -> Option<u32> {
        unreachable!("the owner name '{name}' must not be resolved when a hint is on the record")
    }

    /// A session owned by `owner`, carrying `operator_uid` if the row has one.
    fn session_owned_by(owner: &str, operator_uid: Option<u32>) -> Session {
        let mut session = Session::new(Some("s".to_string()));
        session.owner_username = owner.to_string();
        session.operator_uid = operator_uid;
        session
    }

    /// Network info carrying `operator_uid`. Every other field is addressing
    /// this function never reads, so it is filled with placeholders rather
    /// than a plausible-looking network.
    fn network_for(operator_uid: Option<u32>) -> NetworkInfo {
        NetworkInfo {
            bridge_name: String::new(),
            subnet: String::new(),
            gateway_ip: String::new(),
            vm_ip: String::new(),
            docker_network_name: String::new(),
            vmnet_slot: None,
            operator_uid,
            gateway_egress_ip: None,
        }
    }

    /// The uid the kernel reported at create time is used as-is.
    #[test]
    fn the_uid_stamped_at_create_time_answers_without_a_name_lookup() {
        let session = session_owned_by("alice", Some(501));

        assert_eq!(
            resolve_session_operator(&session, Some(&network_for(None)), &unused_resolver),
            SessionOperator::Uid(501)
        );
    }

    /// A row predating the session column still resolves from the network
    /// record, without falling through to the name.
    #[test]
    fn a_row_without_the_column_falls_back_to_the_network_records_uid() {
        let session = session_owned_by("alice", None);

        assert_eq!(
            resolve_session_operator(&session, Some(&network_for(Some(502))), &unused_resolver),
            SessionOperator::Uid(502)
        );
    }

    /// The session column wins a disagreement, and the name is still not
    /// consulted.
    ///
    /// The two are not expected to differ; what this pins is that if they
    /// ever do, the answer is the one taken from the kernel rather than
    /// whichever of the two the code happened to read first.
    #[test]
    fn the_session_column_outranks_the_network_record() {
        let session = session_owned_by("alice", Some(501));

        assert_eq!(
            resolve_session_operator(&session, Some(&network_for(Some(502))), &unused_resolver),
            SessionOperator::Uid(501)
        );
    }

    /// With no hint anywhere, the owner name is resolved against the host.
    #[test]
    fn a_record_with_no_hint_resolves_its_owner_name() {
        let session = session_owned_by("alice", None);

        assert_eq!(
            resolve_session_operator(&session, None, &|name| (name == "alice").then_some(503)),
            SessionOperator::Uid(503)
        );
    }

    /// A missing network record is not itself a failure — it removes one
    /// hint, and the name still answers.
    #[test]
    fn an_absent_network_record_is_not_an_unresolvable_session() {
        let session = session_owned_by("alice", None);

        assert_eq!(
            resolve_session_operator(&session, None, &|_| Some(504)),
            SessionOperator::Uid(504)
        );
    }

    /// An owner who does not resolve produces the unresolved variant — never
    /// a uid — and the reason names the account so a report can act on it.
    #[test]
    fn an_owner_the_host_does_not_know_yields_no_uid_at_all() {
        let session = session_owned_by("departed", None);

        let SessionOperator::Unresolved(unresolved) =
            resolve_session_operator(&session, Some(&network_for(None)), &|_| None)
        else {
            panic!("an unresolvable owner must not produce a uid");
        };

        assert_eq!(unresolved.session_id, session.id);
        assert_eq!(unresolved.owner_username, "departed");
        assert!(
            unresolved.reason.contains("departed"),
            "the reason must name the account that failed to resolve: {}",
            unresolved.reason
        );
    }

    /// An empty owner is unresolvable without the resolver being asked, so a
    /// resolver that answers for `""` cannot attribute the session to
    /// whoever that answer names.
    #[test]
    fn an_empty_owner_is_never_put_to_the_resolver() {
        let session = session_owned_by("", None);

        let SessionOperator::Unresolved(unresolved) =
            resolve_session_operator(&session, None, &|_| Some(505))
        else {
            panic!("an empty owner must not be attributed to whatever the resolver returns");
        };

        assert_eq!(unresolved.session_id, session.id);
        assert_eq!(unresolved.owner_username, "");
        assert!(
            unresolved.reason.contains("no owner account"),
            "the reason must say the record carries no account: {}",
            unresolved.reason
        );
    }

    /// The description identifies the session and its owner alongside the
    /// reason, so a diagnostics line is actionable without the record.
    #[test]
    fn the_description_names_the_session_its_owner_and_the_reason() {
        let session = session_owned_by("departed", None);

        let SessionOperator::Unresolved(unresolved) =
            resolve_session_operator(&session, None, &|_| None)
        else {
            panic!("expected an unresolved session");
        };

        let line = unresolved.describe();
        assert!(line.contains(&session.id.to_string()), "{line}");
        assert!(line.contains("owner 'departed'"), "{line}");
        assert!(line.contains(&unresolved.reason), "{line}");
    }
}
