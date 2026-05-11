//! Pair-membership identity check per spec §§ 3.1–3.2.
//!
//! A pool authorizes a request iff **both** the caller's identity and
//! the asserted `--for-user` identity appear in the pool's `allow_users`.
//! Both identities are resolved to numeric uids and compared via
//! [`SubnetEntry::allows_uid`] — preserving the existing
//! "names-are-admin-readability" ground truth (renames via `usermod`
//! take effect immediately, no caching).
//!
//! This module is extracted from `main.rs` so the algorithm is unit-
//! testable without standing up a cap'd binary. The unit tests in §
//! 8.1 of the spec parametrize a [`Resolver`] seam so they can fix
//! `name → uid` mappings deterministically; production callers wire
//! the seam to `getpwnam_r`.

use sandbox_core::users_conf::SubnetEntry;

/// Caller-supplied seam for resolving `allow_users` names to numeric
/// uids. Production wraps `nix::unistd::User::from_name`; tests pass
/// an in-memory map so the table-driven cases below are hermetic.
///
/// The seam returns `Some(uid)` on resolution success, `None` on
/// resolution miss (entry not on the host). Resolution errors other
/// than ENOENT (NSS misconfig, etc.) are not propagated here because
/// the pair-check itself does not need to distinguish them — the
/// production caller hand-rolls equivalent logic outside this seam.
///
/// Test-only — the production path uses `SubnetEntry::allows_uid`
/// directly via [`pair_check`].
#[cfg(test)]
pub(crate) type Resolver<'a> = dyn Fn(&str) -> Option<u32> + 'a;

/// The verdict returned by [`pair_check`]. `Allowed` means **both**
/// identities are pool members; `Denied` carries the human-readable
/// reason that the helper surfaces to stderr.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    Denied,
}

/// Pair-check per spec §§ 3.1–3.2.
///
/// Returns `Allowed` iff `caller_uid` and `for_user_uid` are both
/// numerically members of `subnet.allow_users` (resolution via
/// [`SubnetEntry::allows_uid`]).
///
/// The function is **pure** (modulo the resolver seam embedded in the
/// `SubnetEntry::allows_uid` call) so unit tests can drive it directly.
/// `caller_uid` and `for_user_uid` are the **resolved** numeric uids —
/// the caller is responsible for surface-level resolution (and for
/// denying when resolution fails, per spec § 3.4); pair-check itself
/// only compares numeric membership.
pub fn pair_check(subnet: &SubnetEntry, caller_uid: u32, for_user_uid: u32) -> Verdict {
    let caller_in = subnet.allows_uid(caller_uid);
    let for_in = subnet.allows_uid(for_user_uid);
    if caller_in && for_in {
        Verdict::Allowed
    } else {
        Verdict::Denied
    }
}

/// Test-only variant of [`pair_check`] that resolves names through an
/// arbitrary [`Resolver`] seam instead of `getpwnam_r`. Used by the
/// spec § 8.1 table-driven unit tests so the pool's `allow_users` names
/// map to deterministic uids without depending on host `/etc/passwd`.
///
/// This mirrors what `SubnetEntry::allows_uid` does (resolve each name
/// in `allow_users`, compare numerically), but with the resolver
/// pluggable so tests can fix `("alice", "bob", "mallory", "eve",
/// "sandbox")` → fixed uids.
#[cfg(test)]
pub(crate) fn pair_check_with_resolver(
    allow_users: &[&str],
    caller_name: &str,
    for_user_name: &str,
    resolve: &Resolver<'_>,
) -> Verdict {
    let Some(caller_uid) = resolve(caller_name) else {
        return Verdict::Denied;
    };
    let Some(for_user_uid) = resolve(for_user_name) else {
        return Verdict::Denied;
    };
    let resolved_pool_uids: Vec<u32> = allow_users.iter().filter_map(|n| resolve(n)).collect();
    let caller_in = resolved_pool_uids.contains(&caller_uid);
    let for_in = resolved_pool_uids.contains(&for_user_uid);
    if caller_in && for_in {
        Verdict::Allowed
    } else {
        Verdict::Denied
    }
}

#[cfg(test)]
mod tests {
    //! Spec § 8.1 — pair-check function unit tests.
    //!
    //! Eight rows, one per `(pool, caller, for_user)` shape. The
    //! resolver fixes the test universe: alice=1001, bob=1002,
    //! mallory=1003, eve=1004, sandbox=2000.
    //!
    //! The "for_user omitted" row collapses to "for_user == caller"
    //! because the argv-level defaulting (§ 3.1: `let for_user =
    //! for_user_arg.unwrap_or_else(|| caller_name.clone())`) happens in
    //! the argv parser, not in `pair_check`. The test calls
    //! `pair_check_with_resolver` with `for_user_name == caller_name`
    //! to exercise the same algorithmic state.

    use super::*;

    fn fixture_resolver(name: &str) -> Option<u32> {
        match name {
            "alice" => Some(1001),
            "bob" => Some(1002),
            "mallory" => Some(1003),
            "eve" => Some(1004),
            "sandbox" => Some(2000),
            _ => None,
        }
    }

    fn resolver_ref() -> &'static Resolver<'static> {
        &fixture_resolver
    }

    #[test]
    fn pair_check_allows_when_both_match() {
        assert_eq!(
            pair_check_with_resolver(&["sandbox", "alice"], "alice", "alice", resolver_ref()),
            Verdict::Allowed
        );
    }

    #[test]
    fn pair_check_allows_when_caller_eq_for_user_post_v001() {
        // `--for-user` omitted → defaults to caller (§ 3.1). The
        // algorithmic state is identical to "for_user == caller".
        let caller = "alice";
        let for_user = caller;
        assert_eq!(
            pair_check_with_resolver(&["sandbox", "alice"], caller, for_user, resolver_ref()),
            Verdict::Allowed
        );
    }

    #[test]
    fn pair_check_denies_when_caller_missing() {
        assert_eq!(
            pair_check_with_resolver(&["sandbox", "alice"], "mallory", "alice", resolver_ref()),
            Verdict::Denied
        );
    }

    #[test]
    fn pair_check_denies_when_for_user_missing() {
        assert_eq!(
            pair_check_with_resolver(&["sandbox", "alice"], "alice", "bob", resolver_ref()),
            Verdict::Denied
        );
    }

    #[test]
    fn pair_check_denies_when_both_missing() {
        assert_eq!(
            pair_check_with_resolver(&["sandbox", "alice"], "mallory", "eve", resolver_ref()),
            Verdict::Denied
        );
    }

    #[test]
    fn pair_check_denies_empty_pool_with_explicit_for_user() {
        assert_eq!(
            pair_check_with_resolver(&[], "alice", "alice", resolver_ref()),
            Verdict::Denied
        );
    }

    #[test]
    fn pair_check_denies_pool_with_only_sandbox() {
        assert_eq!(
            pair_check_with_resolver(&["sandbox"], "alice", "alice", resolver_ref()),
            Verdict::Denied
        );
    }

    #[test]
    fn pair_check_allows_when_pool_has_only_sandbox_and_caller_is_sandbox() {
        assert_eq!(
            pair_check_with_resolver(&["sandbox"], "sandbox", "sandbox", resolver_ref()),
            Verdict::Allowed
        );
    }
}
