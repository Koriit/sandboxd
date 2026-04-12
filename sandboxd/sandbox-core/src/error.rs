use thiserror::Error;

/// Top-level error type for sandbox-core operations.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("internal error: {0}")]
    Internal(String),
}
