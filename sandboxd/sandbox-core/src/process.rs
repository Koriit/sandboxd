//! Utilities for running external commands with timeout protection.

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use tracing::warn;

use crate::error::SandboxError;

/// Poll interval when waiting for a child process to exit.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Run a [`Command`] with a timeout.
///
/// Equivalent to [`Command::output()`] but with a hard timeout.  Stdout and
/// stderr are captured (piped) automatically.  On timeout the child process
/// is killed, reaped, and a [`SandboxError::Timeout`] is returned.
///
/// `operation` is a human-readable label used in the timeout error message
/// (e.g. `"limactl create"`, `"docker run"`).
pub fn run_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
    operation: &str,
) -> Result<Output, SandboxError> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            SandboxError::Internal(format!("failed to spawn {operation}: {e}"))
        })?;

    let deadline = Instant::now() + timeout;

    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                // Process exited. Use wait_with_output to collect all
                // remaining data from the pipes and get the final status.
                let output = child.wait_with_output().map_err(|e| {
                    SandboxError::Internal(format!(
                        "failed to collect output from {operation}: {e}"
                    ))
                })?;
                return Ok(output);
            }
            Ok(None) => {
                // Still running.
                if Instant::now() >= deadline {
                    warn!(
                        operation = operation,
                        timeout_secs = timeout.as_secs(),
                        "process timed out, killing"
                    );
                    let _ = child.kill();
                    // Reap the child to avoid zombies.
                    let _ = child.wait();
                    return Err(SandboxError::Timeout {
                        operation: operation.to_string(),
                        duration: timeout.as_secs(),
                    });
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                return Err(SandboxError::Internal(format!(
                    "failed to poll {operation}: {e}"
                )));
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_with_timeout_succeeds_within_timeout() {
        let output = run_with_timeout(
            Command::new("echo").arg("hello"),
            Duration::from_secs(5),
            "echo",
        )
        .unwrap();

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("hello"));
    }

    #[test]
    fn run_with_timeout_kills_on_timeout() {
        let result = run_with_timeout(
            Command::new("sleep").arg("60"),
            Duration::from_secs(1),
            "sleep 60",
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        match &err {
            SandboxError::Timeout {
                operation,
                duration,
            } => {
                assert_eq!(operation, "sleep 60");
                assert_eq!(*duration, 1);
            }
            other => panic!("expected Timeout error, got: {other:?}"),
        }
        assert!(
            err.to_string().contains("timed out"),
            "error display should mention timeout: {}",
            err
        );
    }

    #[test]
    fn run_with_timeout_captures_exit_code() {
        let output = run_with_timeout(
            Command::new("sh").args(["-c", "exit 42"]),
            Duration::from_secs(5),
            "exit 42",
        )
        .unwrap();

        assert!(!output.status.success());
        assert_eq!(output.status.code(), Some(42));
    }

    #[test]
    fn run_with_timeout_nonexistent_command() {
        let result = run_with_timeout(
            &mut Command::new("/nonexistent/binary"),
            Duration::from_secs(5),
            "nonexistent",
        );

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("failed to spawn"),
            "error should mention spawn failure: {err}"
        );
    }
}
