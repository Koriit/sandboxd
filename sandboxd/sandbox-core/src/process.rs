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
        .map_err(|e| SandboxError::Internal(format!("failed to spawn {operation}: {e}")))?;

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

/// Run a [`Command`] with a timeout, feeding `body` to its standard input.
///
/// The stdin-fed sibling of [`run_with_timeout`], for the child processes
/// that read their input rather than taking it in argv — `nft -f -` reading
/// a ruleset, `cat` writing a policy file. `body` is written in full and the
/// pipe is then closed, which is what the child reads as EOF.
///
/// # Why writing the whole body before reading output does not deadlock
///
/// The general hazard is real: a child that fills its stdout pipe while the
/// parent is still writing stdin blocks, and so does the parent. It does not
/// apply here because both readers this is used with consume stdin to EOF
/// before producing anything, and what they produce is a short diagnostic —
/// `nft` prints a parse error, `cat` prints nothing. Point this at a filter
/// that streams its input to its output and the reasoning stops holding.
pub fn run_with_timeout_stdin(
    cmd: &mut Command,
    body: &[u8],
    timeout: Duration,
    operation: &str,
) -> Result<Output, SandboxError> {
    use std::io::Write;

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| SandboxError::Internal(format!("failed to spawn {operation}: {e}")))?;

    // Take the handle so the pipe is closed by the drop below rather than
    // staying open on the child struct — a child waiting on EOF would never
    // exit, and the timeout would report a hang whose cause is this parent.
    let write_result = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(body).and_then(|()| stdin.flush()),
        None => Err(std::io::Error::other("child has no stdin pipe")),
    };
    if let Err(e) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(SandboxError::Internal(format!(
            "failed to write stdin for {operation}: {e}"
        )));
    }

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                return child.wait_with_output().map_err(|e| {
                    SandboxError::Internal(format!(
                        "failed to collect output from {operation}: {e}"
                    ))
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    warn!(
                        operation = operation,
                        timeout_secs = timeout.as_secs(),
                        "process timed out, killing"
                    );
                    let _ = child.kill();
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
            "error display should mention timeout: {err}"
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

    /// A body containing newlines, quotes and non-ASCII must arrive at the
    /// child byte-for-byte. This is the local half of the property the
    /// broker channel has to hold too: nothing between the generator and
    /// the process that parses the artifact may reinterpret it.
    #[test]
    fn run_with_timeout_stdin_delivers_the_body_verbatim() {
        let body = "table inet sandbox_dnat {\n  # \"quoted\" — ünïcode\n}\n";
        let output = run_with_timeout_stdin(
            &mut Command::new("cat"),
            body.as_bytes(),
            Duration::from_secs(5),
            "cat",
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), body);
    }

    /// The pipe must be closed after the write, or a child that reads to
    /// EOF never exits and the caller sees a timeout it caused itself.
    #[test]
    fn run_with_timeout_stdin_closes_the_pipe_so_the_child_can_exit() {
        let output = run_with_timeout_stdin(
            Command::new("sh").args(["-c", "cat > /dev/null; echo done"]),
            &b"x".repeat(200_000),
            Duration::from_secs(10),
            "drain",
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "done");
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
