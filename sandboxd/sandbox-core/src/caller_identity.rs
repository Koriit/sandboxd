//! Operator identity carried through every HTTP request the daemon
//! accepts over its Unix socket.
//!
//! The daemon's listener wraps `tokio::net::UnixListener` with a custom
//! acceptor that reads `SO_PEERCRED` on every connection, resolves the
//! peer uid to a username via `getpwuid_r`, and attaches the resulting
//! [`OperatorIdentity`] to every request through that connection via
//! axum's `Extension`/`ConnectInfo` plumbing. Handlers extract the value
//! through an `Extension<OperatorIdentity>` extractor.
//!
//! The struct lives in `sandbox-core` (rather than the daemon binary)
//! because two specs share it:
//!
//! - Spec 1 (helper identity assertion) threads `OperatorIdentity::name`
//!   through `RuntimeStartArgs::for_user` into the route helper's
//!   `--for-user` argv flag for the pair-membership check.
//! - Spec 2 (API session isolation) stamps `OperatorIdentity::name` as
//!   the `owner_username` column on every newly-created session and uses
//!   it as the per-caller filter on every `SessionStore` read.
//!
//! See the helper-identity-assertion design spec § 6.2 for the wire
//! contract.

/// Resolved identity of an operator on the other end of the daemon's
/// Unix-socket connection.
///
/// Populated by the daemon's `SO_PEERCRED`-aware acceptor immediately
/// after `accept(2)` and attached to every request flowing through the
/// connection. The two fields travel together because some downstream
/// consumers want the uid (e.g. structured logs that prefer
/// `uid=1000`) and some want the name (e.g. the route-helper's
/// `--for-user <name>` argv flag and the `owner_username` session
/// column).
///
/// The struct is deliberately `Clone + Debug` (handlers move clones
/// into background tasks; structured logging dumps the value) but does
/// not derive `Serialize`/`Deserialize` — it is never persisted or
/// emitted on the wire as a unit. Spec 2 stamps the `name` field into
/// the `owner_username` SQL column; the uid is structural-only and
/// never reaches operator-visible surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorIdentity {
    /// Numeric uid of the operator, read from `SO_PEERCRED` on the
    /// accepted connection. Kernel-supplied; cannot be spoofed by the
    /// client.
    pub uid: u32,
    /// Username the daemon resolved `uid` to via `getpwuid_r` at accept
    /// time. Strict resolution: a uid that does not resolve closes the
    /// connection before the value reaches a handler.
    pub name: String,
}

impl OperatorIdentity {
    /// Construct an identity. Useful in tests that need to bypass the
    /// peer-cred read (e.g. by mocking the extension via
    /// `MockConnectInfo`).
    pub fn new(uid: u32, name: impl Into<String>) -> Self {
        Self {
            uid,
            name: name.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_identity_roundtrips_through_new() {
        let id = OperatorIdentity::new(1000, "alice");
        assert_eq!(id.uid, 1000);
        assert_eq!(id.name, "alice");
    }

    /// Pin the `Clone` + structural-equality contract — the acceptor
    /// hands one identity per connection, and `into_make_service_with_connect_info`
    /// clones the value for each accepted stream. A future change that
    /// silently drops `Clone` would break the connect-info layer.
    #[test]
    fn operator_identity_is_clone_and_eq() {
        let id = OperatorIdentity::new(1000, "alice");
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }
}
