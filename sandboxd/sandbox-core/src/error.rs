use std::fmt;

use thiserror::Error;

/// Top-level error type for sandbox-core operations.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("invalid state transition: {0}")]
    InvalidState(String),

    #[error("internal error: {0}")]
    Internal(String),
}

/// API error response body returned by the daemon.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiError {
    pub error: String,
}

impl ApiError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            error: msg.into(),
        }
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
    fn http_error_display() {
        let err = SandboxError::Http("connection refused".into());
        assert_eq!(err.to_string(), "HTTP error: connection refused");
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
}
