use std::fmt;

use thiserror::Error;

use crate::users_conf::UsersConfigError;

/// Top-level error type for sandbox-core operations.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("invalid state transition: {0}")]
    InvalidState(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("network error: {0}")]
    Network(String),

    #[error("CA error: {0}")]
    Ca(String),

    #[error("gateway error: {0}")]
    Gateway(String),

    #[error("lima error: {0}")]
    Lima(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("{operation} timed out after {duration}s")]
    Timeout { operation: String, duration: u64 },

    /// The host's Docker daemon is running in **rootless** mode and
    /// the operator did not opt in via `sandbox create
    /// --force-rootless-docker`. Container-backend session creation
    /// is refused because rootless Docker enables userns-remap, which
    /// shifts ownership of bind-mounted workspace files in ways that
    /// the spec § Workspace UID-alignment contract does not cover.
    ///
    /// Spec reference: § Non-goals line 1195 — "Lite's target is
    /// default-hardened Docker. The daemon refuses session-create on
    /// rootless Docker by default; `sandbox create
    /// --force-rootless-docker` is an explicit per-invocation escape
    /// hatch for users who accept they are operating outside the
    /// supported envelope. Alternative runtimes are a separate
    /// design."
    ///
    /// The variant carries no payload because the rejection text is a
    /// fixed contract message; the `Display` impl renders it
    /// verbatim. The literal token `rootless docker` (lowercase) is
    /// embedded so test assertions can match without depending on
    /// surrounding prose.
    ///
    /// HTTP mapping: `400 Bad Request` (request invalid for the host
    /// environment), per the daemon's `error_response` helper.
    #[error(
        "rootless docker is not supported (spec § Non-goals line 1195 — \
        Lite's target is default-hardened Docker; alternative runtimes \
        are a separate design); pass `sandbox create \
        --force-rootless-docker` to opt in per-invocation if you accept \
        operating outside the supported envelope"
    )]
    RootlessDockerRefused,

    /// The session's persisted `guest_protocol_version` does not match
    /// the daemon's `DAEMON_GUEST_PROTO_VERSION`, and the refresh path
    /// has determined the session is not refreshable in place
    /// (`can_refresh_in_place` returned `false`). The operator must
    /// recreate the session.
    ///
    /// HTTP mapping: `409 Conflict` — the request is well-formed and
    /// authorized but the session's persisted state is incompatible
    /// with the current daemon.
    ///
    /// The literal tokens `refresh is not viable` and
    /// `recreate the session` are load-bearing for the integration
    /// tests pinned in the api-session-isolation spec § 7.5.
    #[error(
        "session {session_id} was created with guest protocol {session_proto}; \
        daemon supports {daemon_proto}; refresh is not viable for this session \
        (reason: {reason}); recreate the session: \
        `sandbox session rm {session_id} && sandbox session create ...`"
    )]
    GuestProtocolIncompatible {
        session_id: String,
        session_proto: u32,
        daemon_proto: u32,
        reason: String,
    },

    /// A request conflicts with the current per-session state.
    ///
    /// Carries the operator-facing message verbatim — the `Display`
    /// impl renders it without any prefix, so call sites have full
    /// control over phrasing (workspace-lock contention names the
    /// active op; lifecycle 409s tell the operator how to recover).
    /// Distinct from [`SandboxError::GuestProtocolIncompatible`],
    /// which is the other 409-mapped variant but carries structured
    /// fields and a fixed-template message; `Conflict(String)` is
    /// the generic 409 channel.
    ///
    /// HTTP mapping: `409 Conflict` via the daemon's
    /// `error_response` helper.
    #[error("{0}")]
    Conflict(String),
}

/// Map a [`UsersConfigError`] into [`SandboxError::InvalidArgument`].
///
/// `UsersConfigError`'s `Display` already includes the file path and
/// (for the `FileNotFound` variant) a pointer to the install docs, so a
/// simple `to_string()` round-trip preserves the operator-facing
/// information without growing `SandboxError` with a new variant. The
/// daemon uses `?` to bubble loader errors out of its startup path; the
/// "no matching subnet" case is constructed at the call site as a
/// `SandboxError::InvalidArgument` directly because it is not a loader
/// error.
impl From<UsersConfigError> for SandboxError {
    fn from(e: UsersConfigError) -> Self {
        SandboxError::InvalidArgument(e.to_string())
    }
}

/// API error response body returned by the daemon.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiError {
    pub error: String,
}

impl ApiError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { error: msg.into() }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_display() {
        let err = SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert_eq!(err.to_string(), "I/O error: file not found");
    }

    #[test]
    fn session_not_found_display() {
        let err = SandboxError::SessionNotFound("abc-123".into());
        assert_eq!(err.to_string(), "session not found: abc-123");
    }

    #[test]
    fn invalid_state_display() {
        let err = SandboxError::InvalidState("cannot transition from stopped to creating".into());
        assert_eq!(
            err.to_string(),
            "invalid state transition: cannot transition from stopped to creating"
        );
    }

    #[test]
    fn internal_error_display() {
        let err = SandboxError::Internal("unexpected failure".into());
        assert_eq!(err.to_string(), "internal error: unexpected failure");
    }

    #[test]
    fn io_error_from_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let sandbox_err: SandboxError = io_err.into();
        assert!(matches!(sandbox_err, SandboxError::Io(_)));
    }

    #[test]
    fn api_error_creation_and_display() {
        let api_err = ApiError::new("not implemented");
        assert_eq!(api_err.error, "not implemented");
        assert_eq!(api_err.to_string(), "not implemented");
    }

    #[test]
    fn api_error_serialization() {
        let api_err = ApiError::new("test error");
        let json = serde_json::to_string(&api_err).unwrap();
        assert_eq!(json, r#"{"error":"test error"}"#);

        let deserialized: ApiError = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.error, "test error");
    }

    #[test]
    fn rootless_docker_refused_display_carries_machine_greppable_token() {
        // The daemon's container-backend gate cites § Non-goals line
        // 1195 and points at `--force-rootless-docker`. Test
        // assertions across waves match on the lowercase
        // `rootless docker` substring, so any rewording of the
        // Display string must keep that token intact.
        let err = SandboxError::RootlessDockerRefused;
        let msg = err.to_string();
        assert!(
            msg.contains("rootless docker"),
            "missing greppable token `rootless docker`: {msg}"
        );
        assert!(
            msg.contains("--force-rootless-docker"),
            "missing escape-hatch flag pointer: {msg}"
        );
        assert!(
            msg.contains("§ Non-goals line 1195"),
            "missing spec citation: {msg}"
        );
    }

    #[test]
    fn guest_protocol_incompatible_display_carries_load_bearing_tokens() {
        // The api-session-isolation spec § 7.5 integration tests assert
        // both `refresh is not viable` and `recreate the session` as
        // substrings of the response body. The full Display string is
        // generated from the `#[error(...)]` template above; this test
        // pins those tokens here so a rewording of the template breaks
        // the unit test long before the HTTP-level integration test.
        let err = SandboxError::GuestProtocolIncompatible {
            session_id: "0123456789ab".into(),
            session_proto: 0,
            daemon_proto: 1,
            reason: "session_proto is 0 (pre-V006 placeholder)".into(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("refresh is not viable"),
            "missing greppable token `refresh is not viable`: {msg}"
        );
        assert!(
            msg.contains("recreate the session"),
            "missing greppable token `recreate the session`: {msg}"
        );
        assert!(msg.contains("0123456789ab"), "missing session id: {msg}");
        assert!(
            msg.contains("guest protocol 0"),
            "missing session_proto: {msg}"
        );
        assert!(
            msg.contains("daemon supports 1"),
            "missing daemon_proto: {msg}"
        );
    }

    #[test]
    fn users_config_schema_too_new_maps_to_invalid_argument_with_clear_display() {
        // Spec 5 § 4.7 + § 13: the daemon-startup validator's two
        // schema-mismatch variants ride through the same
        // `From<UsersConfigError> for SandboxError` mapping the rest of
        // the loader uses (`to_string()` → `InvalidArgument`). The load-
        // bearing substring is `is newer than this binary supports` so
        // the integration test in `integration_daemon_refuses_start_on_schema_too_new`
        // can match without depending on surrounding prose.
        let users_err = UsersConfigError::SchemaTooNew {
            file_version: 99,
            daemon_max: 1,
            hint: "Run `sandbox update`.".to_string(),
        };
        let users_msg = users_err.to_string();
        let sandbox_err: SandboxError = users_err.into();
        match sandbox_err {
            SandboxError::InvalidArgument(msg) => {
                assert_eq!(msg, users_msg, "mapping must be lossless");
                assert!(
                    msg.contains("is newer"),
                    "Display must use the load-bearing `is newer` token; got: {msg}"
                );
                assert!(
                    msg.contains("schema version 99"),
                    "Display must include the file's version; got: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn users_config_schema_too_old_maps_to_invalid_argument_with_clear_display() {
        let users_err = UsersConfigError::SchemaTooOld {
            file_version: 0,
            daemon_min: 1,
            hint: "Run `sandbox update`.".to_string(),
        };
        let users_msg = users_err.to_string();
        let sandbox_err: SandboxError = users_err.into();
        match sandbox_err {
            SandboxError::InvalidArgument(msg) => {
                assert_eq!(msg, users_msg, "mapping must be lossless");
                assert!(
                    msg.contains("is older"),
                    "Display must use the load-bearing `is older` token; got: {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    /// `Conflict(String)`'s `Display` must render the carried
    /// message verbatim with no prefix — the wire body is the
    /// operator-facing message exactly. Workspace-lock contention
    /// and lifecycle 409s both rely on this property to surface
    /// their hint strings unaltered.
    #[test]
    fn conflict_display_renders_carried_message_verbatim() {
        let msg = "session has an active push operation";
        let err = SandboxError::Conflict(msg.to_string());
        assert_eq!(err.to_string(), msg);
    }

    #[test]
    fn users_config_error_maps_to_invalid_argument_preserving_path_and_docs() {
        // The `FileNotFound` variant's Display includes both the file
        // path and the install-docs pointer; both must survive the
        // mapping so operators see them in the daemon's error.
        let path = std::path::PathBuf::from("/etc/sandboxd/users.conf");
        let users_err = UsersConfigError::FileNotFound(path.clone());
        let users_msg = users_err.to_string();

        let sandbox_err: SandboxError = users_err.into();
        match sandbox_err {
            SandboxError::InvalidArgument(msg) => {
                assert_eq!(msg, users_msg, "mapping must be lossless");
                assert!(
                    msg.contains(path.to_str().unwrap()),
                    "mapped message must include the file path, got {msg}"
                );
                assert!(
                    msg.contains("install docs"),
                    "mapped message must point at install docs, got {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }
}
