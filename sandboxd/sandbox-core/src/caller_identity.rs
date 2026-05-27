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
//! because two subsystems share it:
//!
//! - The helper-identity-assertion subsystem threads `OperatorIdentity::name`
//!   through `RuntimeStartArgs::for_user` into the route helper's
//!   `--for-user` argv flag for the pair-membership check.
//! - The api-session-isolation subsystem stamps `OperatorIdentity::name` as
//!   the `owner_username` column on every newly-created session and uses
//!   it as the per-caller filter on every `SessionStore` read.
//!
//! See the helper-identity-assertion design.2 for the wire
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
/// emitted on the wire as a unit. The design stamps the `name` field into
/// the `owner_username` SQL column; the uid is structural-only and
/// never reaches operator-visible surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorIdentity {
    /// Numeric uid of the operator, read from `SO_PEERCRED` on the
    /// accepted connection. Kernel-supplied; cannot be spoofed by the
    /// client.
    pub uid: u32,
    /// Numeric primary gid of the operator, read from `SO_PEERCRED` on
    /// the accepted connection alongside `uid`. Kernel-supplied; cannot
    /// be spoofed by the client. Used by the supervisor-fork pattern to
    /// align the in-container `--user <uid>:<gid>` flag (and the Lima
    /// cloud-init usermod step) with the operator's primary group on
    /// the host so workspace bind-mount writes land with the expected
    /// ownership.
    pub gid: u32,
    /// Username the daemon resolved `uid` to via `getpwuid_r` at accept
    /// time. Strict resolution: a uid that does not resolve closes the
    /// connection before the value reaches a handler.
    pub name: String,
}

impl OperatorIdentity {
    /// Construct an identity. Useful in tests that need to bypass the
    /// peer-cred read (e.g. by mocking the extension via
    /// `MockConnectInfo`).
    pub fn new(uid: u32, gid: u32, name: impl Into<String>) -> Self {
        Self {
            uid,
            gid,
            name: name.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_identity_roundtrips_through_new() {
        let id = OperatorIdentity::new(1000, 1000, "alice");
        assert_eq!(id.uid, 1000);
        assert_eq!(id.gid, 1000);
        assert_eq!(id.name, "alice");
    }

    /// Pin the `Clone` + structural-equality contract — the acceptor
    /// hands one identity per connection, and `into_make_service_with_connect_info`
    /// clones the value for each accepted stream. A future change that
    /// silently drops `Clone` would break the connect-info layer.
    #[test]
    fn operator_identity_is_clone_and_eq() {
        let id = OperatorIdentity::new(1000, 1000, "alice");
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }

    /// Pin that uid and gid are independent fields — early plumbing
    /// errors that aliased the two (`gid: uid`) would silently produce
    /// an operator identity that misnames its primary group. The
    /// supervisor-fork pattern relies on the distinction whenever the
    /// operator's primary gid differs from their uid (typical on
    /// multi-user hosts).
    #[test]
    fn operator_identity_uid_and_gid_are_independent() {
        let id = OperatorIdentity::new(1000, 2000, "alice");
        assert_eq!(id.uid, 1000);
        assert_eq!(id.gid, 2000);
        assert_ne!(id.uid, id.gid);
    }
}
