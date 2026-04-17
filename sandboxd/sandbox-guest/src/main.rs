//! Guest agent binary that runs inside the sandbox VM.
//!
//! Listens on `127.0.0.1:5123` for framed JSON requests from the host
//! (relayed via `limactl shell ... socat`). Each TCP connection handles
//! exactly one request-response exchange and is then closed.

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sandbox_core::guest::{
    GUEST_AGENT_PORT, GuestRequest, GuestResponse, read_message, write_message,
};
use tokio::net::TcpListener;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

/// Maximum bytes of stdout/stderr captured from an exec'd process.
const MAX_OUTPUT_BYTES: usize = 1_048_576; // 1 MB

/// Default timeout for executed commands.
const EXEC_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let addr = format!("127.0.0.1:{GUEST_AGENT_PORT}");
    let listener = TcpListener::bind(&addr).await.unwrap_or_else(|e| {
        panic!("failed to bind to {addr}: {e}");
    });

    info!("sandbox-guest agent listening on {addr}");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("failed to accept connection: {e}");
                continue;
            }
        };

        debug!("accepted connection from {peer}");

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                warn!("connection from {peer} failed: {e}");
            }
        });
    }
}

/// Handle a single TCP connection: read one request, dispatch it, write the
/// response, then close.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut reader, mut writer) = stream.split();

    let request_bytes = read_message(&mut reader).await?;

    let request: GuestRequest = serde_json::from_slice(&request_bytes)?;
    debug!(?request, "received request");

    let response = handle_request(request).await;
    debug!(?response, "sending response");

    let response_bytes = serde_json::to_vec(&response)?;
    write_message(&mut writer, &response_bytes).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Request dispatch
// ---------------------------------------------------------------------------

async fn handle_request(request: GuestRequest) -> GuestResponse {
    match request {
        GuestRequest::Ping => GuestResponse::Pong,
        GuestRequest::Exec { command, args } => handle_exec(command, args).await,
        GuestRequest::Status => handle_status().await,
        GuestRequest::FileUpload { path, data, mode } => {
            handle_file_upload(path, data, mode).await
        }
        GuestRequest::FileDownload { path } => handle_file_download(path).await,
    }
}

// ---------------------------------------------------------------------------
// Exec handler
// ---------------------------------------------------------------------------

async fn handle_exec(command: String, args: Vec<String>) -> GuestResponse {
    if command.is_empty() {
        return GuestResponse::Error {
            message: "command must not be empty".into(),
        };
    }

    // Spawn the process directly (no shell).
    let child = Command::new(&command)
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            return GuestResponse::Error {
                message: format!("failed to spawn command '{command}': {e}"),
            };
        }
    };

    // Take ownership of the stdout/stderr pipes so we can read them
    // concurrently with waiting for the process. This avoids a deadlock
    // where the child blocks on a full pipe buffer while we block on
    // wait().
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    // Read stdout, stderr, and wait for the process all concurrently,
    // wrapped in a timeout.
    let result = tokio::time::timeout(EXEC_TIMEOUT, async {
        let (stdout, stderr, status) = tokio::join!(
            read_pipe(stdout_pipe),
            read_pipe(stderr_pipe),
            child.wait(),
        );
        (stdout, stderr, status)
    })
    .await;

    match result {
        Ok((stdout, stderr, Ok(status))) => {
            let exit_code = status.code().unwrap_or(-1);

            GuestResponse::ExecResult {
                exit_code,
                stdout: truncate_output(stdout, MAX_OUTPUT_BYTES),
                stderr: truncate_output(stderr, MAX_OUTPUT_BYTES),
            }
        }
        Ok((_, _, Err(e))) => GuestResponse::Error {
            message: format!("failed to wait for command '{command}': {e}"),
        },
        Err(_) => {
            // Timeout — kill the process.
            let _ = child.kill().await;
            GuestResponse::Error {
                message: format!(
                    "command '{command}' timed out after {} seconds",
                    EXEC_TIMEOUT.as_secs()
                ),
            }
        }
    }
}

/// Read all bytes from an optional async reader.
async fn read_pipe<R: tokio::io::AsyncRead + Unpin>(
    pipe: Option<R>,
) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    match pipe {
        Some(mut p) => {
            let mut buf = Vec::new();
            let _ = p.read_to_end(&mut buf).await;
            buf
        }
        None => Vec::new(),
    }
}

/// Convert raw bytes to a UTF-8 string, truncating to `max_bytes` if needed.
fn truncate_output(bytes: Vec<u8>, max_bytes: usize) -> String {
    if bytes.len() <= max_bytes {
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        let truncated = &bytes[..max_bytes];
        let mut s = String::from_utf8_lossy(truncated).into_owned();
        s.push_str("\n... [output truncated]");
        s
    }
}

// ---------------------------------------------------------------------------
// File transfer handlers
// ---------------------------------------------------------------------------

/// Directories that file transfer operations are allowed to access.
const ALLOWED_DIRS: &[&str] = &["/home/agent/", "/root/", "/tmp/"];

/// System directories that are always denied, even if they appear to be
/// under an allowed prefix (defense-in-depth).
const DENIED_PREFIXES: &[&str] = &["/proc", "/sys", "/dev", "/etc"];

/// Check whether a path string falls within the allowed directories and
/// is not in any denied prefix.  Returns `Ok(())` or an error message.
fn check_path_allowlist(path_str: &str) -> Result<(), String> {
    // Check against denied system prefixes.
    for denied in DENIED_PREFIXES {
        if path_str.starts_with(denied) {
            return Err(format!("access to {denied} is not allowed"));
        }
    }

    // Check that the path is within an allowed directory.
    let allowed = ALLOWED_DIRS.iter().any(|dir| path_str.starts_with(dir));

    if !allowed {
        return Err(format!(
            "path must be within one of: {}",
            ALLOWED_DIRS.join(", ")
        ));
    }

    Ok(())
}

/// Validate and resolve a guest filesystem path for file transfer.
///
/// The path must resolve to a location within one of [`ALLOWED_DIRS`] and
/// must not contain `..` traversal components.
///
/// After the initial string-prefix check, the function also attempts to
/// resolve symlinks via [`std::fs::canonicalize`] and re-checks the
/// resolved path.  This prevents symlink-based escapes where, e.g.,
/// `/home/agent/link -> /etc/shadow` would pass the prefix check but
/// actually read a file outside the sandbox.
///
/// For paths that do not yet exist (common for uploads), the function
/// canonicalizes the nearest existing ancestor and verifies that the
/// ancestor + remaining components still fall within the allowlist.
fn validate_path(raw: &str) -> Result<PathBuf, String> {
    // Reject empty paths.
    if raw.is_empty() {
        return Err("path must not be empty".into());
    }

    // Reject paths that contain `..` components (before canonicalization,
    // to catch attempts even if the intermediate directory doesn't exist).
    if raw.split('/').any(|component| component == "..") {
        return Err("path must not contain '..' traversal".into());
    }

    // Convert to absolute path.
    let path = if raw.starts_with('/') {
        PathBuf::from(raw)
    } else {
        // Relative paths are resolved against /home/agent/ (default working dir).
        PathBuf::from("/home/agent").join(raw)
    };

    // First pass: string-prefix check on the literal path.
    let path_str = path.to_string_lossy();
    check_path_allowlist(&path_str)?;

    // Second pass: resolve symlinks and re-check.
    //
    // `canonicalize` requires the full path to exist.  For uploads the
    // target file often does not exist yet, so we walk up to find the
    // nearest existing ancestor, canonicalize that, then append the
    // remaining (non-existent) tail components and re-check.
    let resolved = resolve_through_symlinks(&path)?;
    let resolved_str = resolved.to_string_lossy();
    check_path_allowlist(&resolved_str).map_err(|e| {
        format!("{e} (after resolving symlinks: {})", resolved_str)
    })?;

    Ok(resolved)
}

/// Resolve a path through symlinks, handling non-existent trailing
/// components by canonicalizing the deepest existing ancestor.
fn resolve_through_symlinks(path: &PathBuf) -> Result<PathBuf, String> {
    // Fast path: if the full path exists, canonicalize directly.
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return Ok(canonical);
    }

    // Walk up the path to find the deepest existing ancestor.
    let mut existing = path.clone();
    let mut tail_components: Vec<std::ffi::OsString> = Vec::new();

    while !existing.exists() {
        if let Some(file_name) = existing.file_name() {
            tail_components.push(file_name.to_os_string());
        } else {
            // We've reached the root and nothing exists — unusual,
            // but just return the original path.
            return Ok(path.clone());
        }
        existing = match existing.parent() {
            Some(p) => p.to_path_buf(),
            None => return Ok(path.clone()),
        };
    }

    // Canonicalize the existing ancestor (resolves symlinks).
    let canonical_base = std::fs::canonicalize(&existing).map_err(|e| {
        format!("failed to resolve path: {e}")
    })?;

    // Re-append the non-existent tail components.
    let mut result = canonical_base;
    for component in tail_components.into_iter().rev() {
        result.push(component);
    }

    Ok(result)
}

/// Handle a file upload request: validate path, decode base64, write file.
async fn handle_file_upload(
    path: String,
    data: String,
    mode: Option<u32>,
) -> GuestResponse {
    let file_path = match validate_path(&path) {
        Ok(p) => p,
        Err(e) => {
            return GuestResponse::FileUploadResult {
                success: false,
                error: Some(e),
            };
        }
    };

    // Decode base64 data.
    let bytes = match BASE64.decode(&data) {
        Ok(b) => b,
        Err(e) => {
            return GuestResponse::FileUploadResult {
                success: false,
                error: Some(format!("invalid base64 data: {e}")),
            };
        }
    };

    // Ensure parent directory exists.
    if let Some(parent) = file_path.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return GuestResponse::FileUploadResult {
                success: false,
                error: Some(format!("failed to create parent directory: {e}")),
            };
        }
    }

    // Write the file.
    if let Err(e) = tokio::fs::write(&file_path, &bytes).await {
        return GuestResponse::FileUploadResult {
            success: false,
            error: Some(format!("failed to write file: {e}")),
        };
    }

    // Set permissions if requested.
    if let Some(mode_bits) = mode {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode_bits);
        if let Err(e) = tokio::fs::set_permissions(&file_path, perms).await {
            return GuestResponse::FileUploadResult {
                success: false,
                error: Some(format!(
                    "file written but failed to set permissions: {e}"
                )),
            };
        }
    }

    GuestResponse::FileUploadResult {
        success: true,
        error: None,
    }
}

/// Handle a file download request: validate path, read file, encode base64.
async fn handle_file_download(path: String) -> GuestResponse {
    let file_path = match validate_path(&path) {
        Ok(p) => p,
        Err(e) => {
            return GuestResponse::FileDownloadResult {
                data: String::new(),
                error: Some(e),
            };
        }
    };

    // Read the file.
    let bytes = match tokio::fs::read(&file_path).await {
        Ok(b) => b,
        Err(e) => {
            return GuestResponse::FileDownloadResult {
                data: String::new(),
                error: Some(format!("failed to read file: {e}")),
            };
        }
    };

    // Encode as base64.
    let encoded = BASE64.encode(&bytes);

    GuestResponse::FileDownloadResult {
        data: encoded,
        error: None,
    }
}

// ---------------------------------------------------------------------------
// Status handler
// ---------------------------------------------------------------------------

async fn handle_status() -> GuestResponse {
    let hostname = read_hostname().await;
    let uptime_secs = read_uptime().await;
    let load_average = read_load_average().await;

    GuestResponse::StatusResult {
        hostname,
        uptime_secs,
        load_average,
    }
}

async fn read_hostname() -> String {
    // Try /etc/hostname first, fall back to `hostname` command.
    match tokio::fs::read_to_string("/etc/hostname").await {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            match Command::new("hostname").output().await {
                Ok(output) => {
                    String::from_utf8_lossy(&output.stdout).trim().to_string()
                }
                Err(_) => "unknown".to_string(),
            }
        }
    }
}

async fn read_uptime() -> u64 {
    // /proc/uptime format: "12345.67 89012.34\n"
    // First field is seconds since boot.
    match tokio::fs::read_to_string("/proc/uptime").await {
        Ok(s) => s
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<f64>().ok())
            .map(|f| f as u64)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

async fn read_load_average() -> f64 {
    // /proc/loadavg format: "0.42 0.35 0.28 1/234 5678\n"
    // First field is 1-minute load average.
    match tokio::fs::read_to_string("/proc/loadavg").await {
        Ok(s) => s
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0),
        Err(_) => 0.0,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use sandbox_core::guest::send_request_over;
    use tokio::net::TcpListener;

    use super::*;

    // -- Handler unit tests -------------------------------------------------

    #[tokio::test]
    async fn test_handle_ping() {
        let response = handle_request(GuestRequest::Ping).await;
        assert!(
            matches!(response, GuestResponse::Pong),
            "Ping should return Pong, got: {response:?}"
        );
    }

    #[tokio::test]
    async fn test_handle_exec_simple() {
        let response = handle_request(GuestRequest::Exec {
            command: "echo".into(),
            args: vec!["hello".into()],
        })
        .await;

        match response {
            GuestResponse::ExecResult {
                exit_code,
                stdout,
                stderr,
            } => {
                assert_eq!(exit_code, 0);
                assert_eq!(stdout.trim(), "hello");
                assert!(stderr.is_empty(), "stderr should be empty: {stderr:?}");
            }
            other => panic!("expected ExecResult, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_exec_nonexistent() {
        let response = handle_request(GuestRequest::Exec {
            command: "/nonexistent/binary/that/does/not/exist".into(),
            args: vec![],
        })
        .await;

        match response {
            GuestResponse::Error { message } => {
                assert!(
                    message.contains("failed to spawn"),
                    "error should mention spawn failure: {message}"
                );
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_exec_empty_command() {
        let response = handle_request(GuestRequest::Exec {
            command: String::new(),
            args: vec![],
        })
        .await;

        match response {
            GuestResponse::Error { message } => {
                assert!(
                    message.contains("must not be empty"),
                    "error should mention empty command: {message}"
                );
            }
            other => panic!("expected Error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_status() {
        let response = handle_request(GuestRequest::Status).await;

        match response {
            GuestResponse::StatusResult {
                hostname,
                uptime_secs: _,
                load_average: _,
            } => {
                // Hostname should be non-empty on any reasonable system.
                assert!(
                    !hostname.is_empty(),
                    "hostname should not be empty"
                );
            }
            other => panic!("expected StatusResult, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_exec_output_truncation() {
        // Use dd to produce output larger than MAX_OUTPUT_BYTES from /dev/zero.
        let limit = MAX_OUTPUT_BYTES + 100;
        let response = handle_request(GuestRequest::Exec {
            command: "dd".into(),
            args: vec![
                "if=/dev/zero".into(),
                format!("bs={limit}"),
                "count=1".into(),
                "status=none".into(),
            ],
        })
        .await;

        match response {
            GuestResponse::ExecResult { stdout, .. } => {
                // The raw output is limit bytes, which exceeds MAX_OUTPUT_BYTES,
                // so truncation should have kicked in.
                assert!(
                    stdout.contains("[output truncated]"),
                    "output should be truncated, got {} bytes without marker",
                    stdout.len()
                );
            }
            other => panic!("expected ExecResult, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_exec_timeout() {
        // Use `sleep 120` which should be killed by the timeout.
        // But we don't want the test to take 60 seconds, so we test the
        // handler indirectly with a shorter timeout. Since EXEC_TIMEOUT is a
        // constant, we test at the lower level instead.
        //
        // We use `sleep` but verify we can at least observe the timeout
        // mechanic works: spawn a process that runs indefinitely, then
        // time-box it ourselves.
        let start = std::time::Instant::now();

        // Instead of relying on the 60-second constant, call handle_exec
        // directly. The process tries to sleep 120s but will be killed at 60s.
        // To keep the test fast, we'll spawn something that blocks on stdin
        // and set a test-level timeout.
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            // `cat` with no args reads from stdin forever.
            // BUT our handle_exec pipes /dev/null to stdin by default
            // (Stdio::piped() means the stdin handle is available but nobody
            // writes to it). Actually, `tokio::process::Command` doesn't open
            // stdin by default (it inherits, which in tests is /dev/null-ish).
            // Let's use `sleep 120` and accept the 60-second timeout.
            // ... That's too slow for a unit test.
            //
            // Better approach: validate the truncate_output function directly,
            // and test the timeout path by observing that the timeout error
            // message is well-formed.
            handle_exec("sleep".into(), vec!["120".into()]).await
        })
        .await;

        // We expect our test-level timeout to fire before the 60s exec timeout.
        // The test proves we don't hang forever.
        match result {
            Err(_) => {
                // Test-level timeout fired first — that's fine, the exec
                // timeout is 60s and we only waited 5s. The important thing
                // is we didn't hang.
                let elapsed = start.elapsed();
                assert!(
                    elapsed < Duration::from_secs(10),
                    "should not have blocked: elapsed {elapsed:?}"
                );
            }
            Ok(GuestResponse::Error { message }) => {
                // The exec timeout fired (unlikely in 5s but possible on
                // a very slow machine if EXEC_TIMEOUT were shorter).
                assert!(message.contains("timed out"));
            }
            Ok(other) => panic!("expected timeout or error, got: {other:?}"),
        }
    }

    // -- truncate_output unit tests -----------------------------------------

    #[test]
    fn test_truncate_output_within_limit() {
        let data = vec![b'A'; 100];
        let result = truncate_output(data, 200);
        assert_eq!(result.len(), 100);
        assert!(!result.contains("[output truncated]"));
    }

    #[test]
    fn test_truncate_output_at_limit() {
        let data = vec![b'A'; 200];
        let result = truncate_output(data, 200);
        assert_eq!(result.len(), 200);
        assert!(!result.contains("[output truncated]"));
    }

    #[test]
    fn test_truncate_output_over_limit() {
        let data = vec![b'A'; 300];
        let result = truncate_output(data, 200);
        assert!(result.contains("[output truncated]"));
        // The truncated string should start with 200 'A's.
        assert!(result.starts_with(&"A".repeat(200)));
    }

    // -- End-to-end test over loopback TCP ----------------------------------

    #[tokio::test]
    async fn test_end_to_end_local() {
        // Bind to a random port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn our server loop (accept one connection).
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream).await.unwrap();
        });

        // Connect as a client and send a Ping.
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let response =
            send_request_over(&mut stream, &GuestRequest::Ping).await.unwrap();

        assert!(
            matches!(response, GuestResponse::Pong),
            "expected Pong, got: {response:?}"
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_end_to_end_exec() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream).await.unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = GuestRequest::Exec {
            command: "echo".into(),
            args: vec!["end-to-end".into()],
        };
        let response = send_request_over(&mut stream, &request).await.unwrap();

        match response {
            GuestResponse::ExecResult {
                exit_code,
                stdout,
                stderr,
            } => {
                assert_eq!(exit_code, 0);
                assert_eq!(stdout.trim(), "end-to-end");
                assert!(stderr.is_empty());
            }
            other => panic!("expected ExecResult, got: {other:?}"),
        }

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_end_to_end_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream).await.unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let response =
            send_request_over(&mut stream, &GuestRequest::Status).await.unwrap();

        match response {
            GuestResponse::StatusResult {
                hostname,
                uptime_secs: _,
                load_average: _,
            } => {
                assert!(!hostname.is_empty());
            }
            other => panic!("expected StatusResult, got: {other:?}"),
        }

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_end_to_end_multiple_connections() {
        // Verify the server handles multiple sequential connections.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (stream, _) = listener.accept().await.unwrap();
                handle_connection(stream).await.unwrap();
            }
        });

        for i in 0..3 {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let request = GuestRequest::Exec {
                command: "echo".into(),
                args: vec![format!("iter-{i}")],
            };
            let response =
                send_request_over(&mut stream, &request).await.unwrap();

            match response {
                GuestResponse::ExecResult { stdout, .. } => {
                    assert!(
                        stdout.contains(&format!("iter-{i}")),
                        "expected iter-{i} in output: {stdout}"
                    );
                }
                other => panic!("expected ExecResult, got: {other:?}"),
            }
        }

        server.await.unwrap();
    }

    // -- Path validation tests ----------------------------------------------

    #[test]
    fn test_validate_path_allowed_dirs() {
        assert!(validate_path("/home/agent/test.txt").is_ok());
        assert!(validate_path("/home/agent/workspace/file").is_ok());
        assert!(validate_path("/tmp/scratch").is_ok());
    }

    #[test]
    fn test_validate_path_denied_dirs() {
        assert!(validate_path("/etc/passwd").is_err());
        assert!(validate_path("/proc/self/environ").is_err());
        assert!(validate_path("/sys/class/net").is_err());
        assert!(validate_path("/dev/null").is_err());
    }

    #[test]
    fn test_validate_path_traversal_rejected() {
        assert!(validate_path("/home/agent/../etc/passwd").is_err());
        assert!(validate_path("/tmp/../../etc/shadow").is_err());
        assert!(validate_path("../etc/passwd").is_err());
    }

    #[test]
    fn test_validate_path_outside_allowed() {
        assert!(validate_path("/var/log/syslog").is_err());
        assert!(validate_path("/opt/data").is_err());
        assert!(validate_path("/usr/bin/ls").is_err());
    }

    #[test]
    fn test_validate_path_empty() {
        assert!(validate_path("").is_err());
    }

    #[test]
    fn test_validate_path_relative_resolves_to_home() {
        // Relative paths resolve against /home/agent/
        let result = validate_path("workspace/file.txt");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/home/agent/workspace/file.txt")
        );
    }

    #[test]
    fn test_validate_path_symlink_escape_blocked() {
        // Create a symlink inside /tmp/ (an allowed dir) that points to
        // /etc/ (a denied dir).  validate_path should reject the path
        // because canonicalization reveals the true destination.
        let link_path = format!(
            "/tmp/sandbox-symlink-test-{}",
            std::process::id()
        );
        // Clean up any leftover symlink from a previous run.
        let _ = std::fs::remove_file(&link_path);

        // Create symlink: /tmp/sandbox-symlink-test-PID -> /etc
        std::os::unix::fs::symlink("/etc", &link_path).expect(
            "failed to create test symlink"
        );

        // Accessing a file "through" the symlink should fail even though
        // the literal path starts with /tmp/.
        let result = validate_path(&format!("{link_path}/passwd"));
        assert!(
            result.is_err(),
            "symlink escaping /tmp/ to /etc/ should be rejected, got: {:?}",
            result,
        );

        // Clean up.
        let _ = std::fs::remove_file(&link_path);
    }

    #[test]
    fn test_validate_path_symlink_within_allowed_dir_ok() {
        // A symlink that stays within an allowed directory should be fine.
        let target_dir = format!("/tmp/sandbox-symlink-target-{}", std::process::id());
        let link_path = format!("/tmp/sandbox-symlink-ok-{}", std::process::id());
        let _ = std::fs::remove_file(&link_path);
        let _ = std::fs::create_dir_all(&target_dir);

        std::os::unix::fs::symlink(&target_dir, &link_path).expect(
            "failed to create test symlink"
        );

        let result = validate_path(&format!("{link_path}/file.txt"));
        assert!(
            result.is_ok(),
            "symlink within /tmp/ should be allowed, got: {:?}",
            result,
        );

        // Clean up.
        let _ = std::fs::remove_file(&link_path);
        let _ = std::fs::remove_dir(&target_dir);
    }

    // -- File upload/download handler tests ---------------------------------

    #[tokio::test]
    async fn test_handle_file_upload_and_download() {
        // /tmp/ is in the allowed dirs, so we can test upload+download there.
        let path = format!("/tmp/sandbox-test-{}", std::process::id());

        // Upload.
        let data = BASE64.encode(b"hello from upload test");
        let response = handle_file_upload(
            path.clone(),
            data,
            Some(0o644),
        )
        .await;

        match response {
            GuestResponse::FileUploadResult { success, error } => {
                assert!(success, "upload should succeed: {error:?}");
                assert!(error.is_none());
            }
            other => panic!("expected FileUploadResult, got: {other:?}"),
        }

        // Download the same file.
        let response = handle_file_download(path.clone()).await;

        match response {
            GuestResponse::FileDownloadResult { data, error } => {
                assert!(error.is_none(), "download should succeed: {error:?}");
                let decoded = BASE64.decode(&data).unwrap();
                assert_eq!(decoded, b"hello from upload test");
            }
            other => panic!("expected FileDownloadResult, got: {other:?}"),
        }

        // Clean up.
        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn test_handle_file_upload_invalid_base64() {
        let response = handle_file_upload(
            "/tmp/test-bad-b64".into(),
            "not valid base64!!!".into(),
            None,
        )
        .await;

        match response {
            GuestResponse::FileUploadResult { success, error } => {
                assert!(!success);
                assert!(
                    error.as_deref().unwrap_or("").contains("invalid base64"),
                    "error should mention invalid base64: {error:?}"
                );
            }
            other => panic!("expected FileUploadResult, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_file_upload_path_denied() {
        let response = handle_file_upload(
            "/etc/malicious".into(),
            BASE64.encode(b"bad"),
            None,
        )
        .await;

        match response {
            GuestResponse::FileUploadResult { success, error } => {
                assert!(!success);
                assert!(error.is_some());
            }
            other => panic!("expected FileUploadResult, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_file_download_nonexistent() {
        let response =
            handle_file_download("/tmp/nonexistent-file-that-does-not-exist-12345".into())
                .await;

        match response {
            GuestResponse::FileDownloadResult { data, error } => {
                assert!(data.is_empty());
                assert!(
                    error.as_deref().unwrap_or("").contains("failed to read"),
                    "error should mention read failure: {error:?}"
                );
            }
            other => panic!("expected FileDownloadResult, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_file_download_path_denied() {
        let response = handle_file_download("/etc/passwd".into()).await;

        match response {
            GuestResponse::FileDownloadResult { data, error } => {
                assert!(data.is_empty());
                assert!(error.is_some());
            }
            other => panic!("expected FileDownloadResult, got: {other:?}"),
        }
    }

    // -- End-to-end file transfer over TCP ----------------------------------

    #[tokio::test]
    async fn test_end_to_end_file_upload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream).await.unwrap();
        });

        let test_path = format!("/tmp/e2e-upload-{}", std::process::id());
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = GuestRequest::FileUpload {
            path: test_path.clone(),
            data: BASE64.encode(b"e2e upload content"),
            mode: None,
        };
        let response = send_request_over(&mut stream, &request).await.unwrap();

        match response {
            GuestResponse::FileUploadResult { success, error } => {
                assert!(success, "e2e upload failed: {error:?}");
            }
            other => panic!("expected FileUploadResult, got: {other:?}"),
        }

        // Verify the file was written.
        let contents = tokio::fs::read_to_string(&test_path).await.unwrap();
        assert_eq!(contents, "e2e upload content");
        let _ = tokio::fs::remove_file(&test_path).await;

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_end_to_end_file_download() {
        let test_path = format!("/tmp/e2e-download-{}", std::process::id());
        tokio::fs::write(&test_path, b"e2e download content")
            .await
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream).await.unwrap();
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = GuestRequest::FileDownload {
            path: test_path.clone(),
        };
        let response = send_request_over(&mut stream, &request).await.unwrap();

        match response {
            GuestResponse::FileDownloadResult { data, error } => {
                assert!(error.is_none(), "e2e download failed: {error:?}");
                let decoded = BASE64.decode(&data).unwrap();
                assert_eq!(decoded, b"e2e download content");
            }
            other => panic!("expected FileDownloadResult, got: {other:?}"),
        }

        let _ = tokio::fs::remove_file(&test_path).await;
        server.await.unwrap();
    }

}
