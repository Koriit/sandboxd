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
