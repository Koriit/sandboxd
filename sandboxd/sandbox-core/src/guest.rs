//! Host-side client for communicating with the guest agent inside a sandbox VM.
//!
//! The guest agent runs inside the VM and listens for framed JSON messages.
//! This module provides:
//!
//! - **Protocol types** ([`GuestRequest`], [`GuestResponse`]) — the messages
//!   exchanged between host and guest.
//! - **Message framing** ([`write_message`], [`read_message`]) — length-prefixed
//!   binary framing over any async byte stream.
//! - **Transport-agnostic request/response** ([`send_request_over`]) — serialize
//!   a request, send it, read back a response.
//! - **[`GuestConnector`]** — high-level client that establishes a transport to
//!   the guest via `limactl shell` and sends requests.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tracing::debug;

use crate::error::SandboxError;
use crate::lima::LimaManager;
use crate::session::SessionId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Port the guest agent listens on inside the VM.
pub const GUEST_AGENT_PORT: u16 = 5123;

/// Maximum message size (1 MB).
pub const MAX_MESSAGE_SIZE: u32 = 1_048_576;

/// Timeout for a single guest agent request/response cycle.
const GUEST_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

/// A request sent from the host to the guest agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GuestRequest {
    Ping,
    Exec {
        command: String,
        args: Vec<String>,
    },
    Status,
    /// Upload a file to the guest filesystem. `data` is base64-encoded.
    FileUpload {
        path: String,
        data: String,
        mode: Option<u32>,
    },
    /// Download a file from the guest filesystem.
    FileDownload {
        path: String,
    },
}

/// A response sent from the guest agent back to the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GuestResponse {
    Pong,
    ExecResult {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    StatusResult {
        hostname: String,
        uptime_secs: u64,
        load_average: f64,
    },
    /// Result of a file upload operation.
    FileUploadResult {
        success: bool,
        error: Option<String>,
    },
    /// Result of a file download operation. `data` is base64-encoded.
    FileDownloadResult {
        data: String,
        error: Option<String>,
    },
    Error {
        message: String,
    },
}

// ---------------------------------------------------------------------------
// Message framing
// ---------------------------------------------------------------------------

/// Write a length-prefixed message to an async writer.
///
/// Wire format: 4 bytes big-endian u32 length, then the payload bytes.
/// Returns an error if the payload exceeds [`MAX_MESSAGE_SIZE`].
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &[u8],
) -> Result<(), SandboxError> {
    let len: u32 = msg
        .len()
        .try_into()
        .map_err(|_| SandboxError::Internal("message too large for u32 length".into()))?;

    if len > MAX_MESSAGE_SIZE {
        return Err(SandboxError::Internal(format!(
            "message size {len} exceeds maximum {MAX_MESSAGE_SIZE}"
        )));
    }

    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(msg).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed message from an async reader.
///
/// Wire format: 4 bytes big-endian u32 length, then the payload bytes.
/// Returns an error if the declared length exceeds [`MAX_MESSAGE_SIZE`],
/// or if the stream ends before delivering the full payload.
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, SandboxError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            SandboxError::Internal("connection closed while reading message length".into())
        } else {
            SandboxError::Io(e)
        }
    })?;
    let len = u32::from_be_bytes(len_buf);

    if len > MAX_MESSAGE_SIZE {
        return Err(SandboxError::Internal(format!(
            "message length {len} exceeds maximum {MAX_MESSAGE_SIZE}"
        )));
    }

    if len == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            SandboxError::Internal("connection closed while reading message body".into())
        } else {
            SandboxError::Io(e)
        }
    })?;

    Ok(buf)
}

// ---------------------------------------------------------------------------
// Transport-agnostic request/response
// ---------------------------------------------------------------------------

/// Send a [`GuestRequest`] over any bidirectional async stream and read back
/// the [`GuestResponse`].
///
/// This is the core protocol exchange function. It serializes the request to
/// JSON, sends it as a framed message, reads the framed response, and
/// deserializes it.
pub async fn send_request_over<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &GuestRequest,
) -> Result<GuestResponse, SandboxError> {
    let payload = serde_json::to_vec(request).map_err(|e| {
        SandboxError::Internal(format!("failed to serialize request: {e}"))
    })?;

    // Split the stream into read/write halves is not needed when we own &mut S.
    // We write first, then read — the protocol is strictly request-then-response.
    let (reader, writer) = tokio::io::split(stream);
    let mut reader = reader;
    let mut writer = writer;

    write_message(&mut writer, &payload).await?;

    let response_bytes = read_message(&mut reader).await?;

    let response: GuestResponse =
        serde_json::from_slice(&response_bytes).map_err(|e| {
            SandboxError::Internal(format!("failed to deserialize response: {e}"))
        })?;

    Ok(response)
}

// ---------------------------------------------------------------------------
// GuestConnector
// ---------------------------------------------------------------------------

/// High-level client for sending requests to the guest agent inside a sandbox
/// VM.
///
/// Uses `limactl shell` as the transport: spawns
/// `limactl shell sandbox-{id} -- socat - TCP:127.0.0.1:5123`
/// and pipes the framed protocol over the child process's stdin/stdout.
pub struct GuestConnector {
    /// Used to derive the VM name for a session.
    lima_manager: Arc<LimaManager>,
}

impl GuestConnector {
    /// Create a new connector backed by the given Lima manager.
    pub fn new(lima_manager: Arc<LimaManager>) -> Self {
        Self { lima_manager }
    }

    /// Send a request to the guest agent in the VM for `session_id` and return
    /// the response.
    ///
    /// This spawns a `limactl shell` process with `socat` to bridge stdin/stdout
    /// to the guest agent's TCP port. The framed JSON protocol is exchanged over
    /// that pipe.
    pub async fn send_request(
        &self,
        session_id: &SessionId,
        request: GuestRequest,
    ) -> Result<GuestResponse, SandboxError> {
        let vm_name = crate::lima::vm_name(session_id);

        debug!(
            vm = %vm_name,
            request_type = ?std::mem::discriminant(&request),
            "sending request to guest agent"
        );

        let mut child = Command::new(self.lima_manager.limactl_path())
            .args([
                "shell",
                &vm_name,
                "--",
                "socat",
                "-",
                &format!("TCP:127.0.0.1:{GUEST_AGENT_PORT}"),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                SandboxError::Lima(format!(
                    "failed to spawn limactl shell for {vm_name}: {e}"
                ))
            })?;

        let result = tokio::time::timeout(GUEST_REQUEST_TIMEOUT, async {
            let mut stdin = child.stdin.take().ok_or_else(|| {
                SandboxError::Internal("failed to capture stdin of limactl shell".into())
            })?;
            let mut stdout = child.stdout.take().ok_or_else(|| {
                SandboxError::Internal("failed to capture stdout of limactl shell".into())
            })?;

            // Send the request.
            let payload = serde_json::to_vec(&request).map_err(|e| {
                SandboxError::Internal(format!("failed to serialize request: {e}"))
            })?;
            write_message(&mut stdin, &payload).await?;

            // NOTE: we intentionally keep stdin open until after reading the
            // response.  Closing it early causes socat (inside the VM, reached
            // via limactl shell / SSH) to tear down the TCP connection before
            // the guest agent can send its reply — resulting in
            // "connection closed while reading message length".  The flush()
            // inside write_message is sufficient to ensure the data reaches socat.

            // Read the response.
            let response_bytes = read_message(&mut stdout).await?;

            // Now close stdin so socat exits cleanly.
            drop(stdin);

            let response: GuestResponse =
                serde_json::from_slice(&response_bytes).map_err(|e| {
                    SandboxError::Internal(format!(
                        "failed to deserialize guest response: {e}"
                    ))
                })?;

            Ok(response)
        })
        .await;

        match result {
            Ok(response) => {
                // Wait for the child to exit (don't leave zombies).
                let _ = child.wait().await;
                response
            }
            Err(_elapsed) => {
                // Timeout: kill the child process to avoid leaving zombies.
                let _ = child.kill().await;
                let _ = child.wait().await;
                Err(SandboxError::Timeout {
                    operation: format!("guest agent request via {vm_name}"),
                    duration: GUEST_REQUEST_TIMEOUT.as_secs(),
                })
            }
        }
    }

    /// Ping the guest agent. Returns `true` if it responds with `Pong`.
    pub async fn ping(&self, session_id: &SessionId) -> Result<bool, SandboxError> {
        match self.send_request(session_id, GuestRequest::Ping).await {
            Ok(GuestResponse::Pong) => Ok(true),
            Ok(other) => {
                debug!(?other, "unexpected response to Ping");
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Execute a command inside the guest VM.
    pub async fn exec(
        &self,
        session_id: &SessionId,
        command: &str,
        args: &[&str],
    ) -> Result<GuestResponse, SandboxError> {
        self.send_request(
            session_id,
            GuestRequest::Exec {
                command: command.to_string(),
                args: args.iter().map(|s| s.to_string()).collect(),
            },
        )
        .await
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use tokio::io::duplex;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    // -- Message framing tests ----------------------------------------------

    #[tokio::test]
    async fn test_write_read_message() {
        let payload = b"hello, world!";
        let (mut client, mut server) = duplex(4096);

        // Write on one side, read on the other.
        write_message(&mut client, payload).await.unwrap();
        drop(client); // close so read doesn't block forever

        let received = read_message(&mut server).await.unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn test_max_message_size_rejected_on_write() {
        let too_big = vec![0u8; MAX_MESSAGE_SIZE as usize + 1];
        let (mut client, _server) = duplex(64);

        let result = write_message(&mut client, &too_big).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds maximum"),
            "error should mention size limit: {err}"
        );
    }

    #[tokio::test]
    async fn test_max_message_size_rejected_on_read() {
        // Manually write a length prefix that exceeds MAX_MESSAGE_SIZE.
        let bad_len: u32 = MAX_MESSAGE_SIZE + 1;
        let (mut client, mut server) = duplex(4096);

        tokio::io::AsyncWriteExt::write_all(&mut client, &bad_len.to_be_bytes())
            .await
            .unwrap();
        drop(client);

        let result = read_message(&mut server).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds maximum"),
            "error should mention size limit: {err}"
        );
    }

    #[tokio::test]
    async fn test_empty_message() {
        let (mut client, mut server) = duplex(4096);

        write_message(&mut client, &[]).await.unwrap();
        drop(client);

        let received = read_message(&mut server).await.unwrap();
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn test_truncated_frame() {
        // Write a length prefix claiming 100 bytes, but only send 5.
        let (mut client, mut server) = duplex(4096);

        let len: u32 = 100;
        tokio::io::AsyncWriteExt::write_all(&mut client, &len.to_be_bytes())
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut client, &[1, 2, 3, 4, 5])
            .await
            .unwrap();
        drop(client); // close the connection before the full payload

        let result = read_message(&mut server).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("connection closed"),
            "error should mention connection closed: {err}"
        );
    }

    #[tokio::test]
    async fn test_oversized_length_prefix() {
        // Length prefix at u32::MAX.
        let (mut client, mut server) = duplex(4096);

        let bad_len: u32 = u32::MAX;
        tokio::io::AsyncWriteExt::write_all(&mut client, &bad_len.to_be_bytes())
            .await
            .unwrap();
        drop(client);

        let result = read_message(&mut server).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds maximum"),
            "error should mention size limit: {err}"
        );
    }

    // -- Protocol types serialization tests ---------------------------------

    #[test]
    fn test_guest_request_serialization() {
        let ping = GuestRequest::Ping;
        let json = serde_json::to_string(&ping).unwrap();
        assert!(json.contains(r#""type":"Ping"#));

        let exec = GuestRequest::Exec {
            command: "ls".into(),
            args: vec!["-la".into()],
        };
        let json = serde_json::to_string(&exec).unwrap();
        assert!(json.contains(r#""type":"Exec"#));
        assert!(json.contains(r#""command":"ls"#));

        let status = GuestRequest::Status;
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains(r#""type":"Status"#));

        let upload = GuestRequest::FileUpload {
            path: "/tmp/test.txt".into(),
            data: "aGVsbG8=".into(),
            mode: Some(0o644),
        };
        let json = serde_json::to_string(&upload).unwrap();
        assert!(json.contains(r#""type":"FileUpload"#));
        assert!(json.contains(r#""path":"/tmp/test.txt"#));

        let download = GuestRequest::FileDownload {
            path: "/tmp/test.txt".into(),
        };
        let json = serde_json::to_string(&download).unwrap();
        assert!(json.contains(r#""type":"FileDownload"#));
    }

    #[test]
    fn test_guest_response_serialization() {
        let pong = GuestResponse::Pong;
        let json = serde_json::to_string(&pong).unwrap();
        assert!(json.contains(r#""type":"Pong"#));

        let exec_result = GuestResponse::ExecResult {
            exit_code: 0,
            stdout: "hello".into(),
            stderr: String::new(),
        };
        let json = serde_json::to_string(&exec_result).unwrap();
        assert!(json.contains(r#""type":"ExecResult"#));
        assert!(json.contains(r#""exit_code":0"#));

        let status_result = GuestResponse::StatusResult {
            hostname: "sandbox-abc".into(),
            uptime_secs: 3600,
            load_average: 0.5,
        };
        let json = serde_json::to_string(&status_result).unwrap();
        assert!(json.contains(r#""type":"StatusResult"#));

        let upload_result = GuestResponse::FileUploadResult {
            success: true,
            error: None,
        };
        let json = serde_json::to_string(&upload_result).unwrap();
        assert!(json.contains(r#""type":"FileUploadResult"#));
        assert!(json.contains(r#""success":true"#));

        let download_result = GuestResponse::FileDownloadResult {
            data: "aGVsbG8=".into(),
            error: None,
        };
        let json = serde_json::to_string(&download_result).unwrap();
        assert!(json.contains(r#""type":"FileDownloadResult"#));
        assert!(json.contains(r#""data":"aGVsbG8="#));

        let error = GuestResponse::Error {
            message: "something broke".into(),
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains(r#""type":"Error"#));
    }

    #[test]
    fn test_guest_request_roundtrip() {
        let requests = vec![
            GuestRequest::Ping,
            GuestRequest::Exec {
                command: "/bin/sh".into(),
                args: vec!["-c".into(), "echo test".into()],
            },
            GuestRequest::Status,
            GuestRequest::FileUpload {
                path: "/home/agent/test.txt".into(),
                data: "aGVsbG8gd29ybGQ=".into(),
                mode: Some(0o644),
            },
            GuestRequest::FileUpload {
                path: "/tmp/nomode.txt".into(),
                data: "dGVzdA==".into(),
                mode: None,
            },
            GuestRequest::FileDownload {
                path: "/home/agent/test.txt".into(),
            },
        ];

        for req in &requests {
            let json = serde_json::to_vec(req).unwrap();
            let deserialized: GuestRequest = serde_json::from_slice(&json).unwrap();
            // Compare via re-serialization since GuestRequest doesn't impl PartialEq.
            assert_eq!(
                serde_json::to_string(req).unwrap(),
                serde_json::to_string(&deserialized).unwrap(),
            );
        }
    }

    #[test]
    fn test_guest_response_roundtrip() {
        let responses = vec![
            GuestResponse::Pong,
            GuestResponse::ExecResult {
                exit_code: 42,
                stdout: "out".into(),
                stderr: "err".into(),
            },
            GuestResponse::StatusResult {
                hostname: "vm".into(),
                uptime_secs: 100,
                load_average: 1.23,
            },
            GuestResponse::FileUploadResult {
                success: true,
                error: None,
            },
            GuestResponse::FileUploadResult {
                success: false,
                error: Some("permission denied".into()),
            },
            GuestResponse::FileDownloadResult {
                data: "aGVsbG8=".into(),
                error: None,
            },
            GuestResponse::FileDownloadResult {
                data: String::new(),
                error: Some("file not found".into()),
            },
            GuestResponse::Error {
                message: "fail".into(),
            },
        ];

        for resp in &responses {
            let json = serde_json::to_vec(resp).unwrap();
            let deserialized: GuestResponse = serde_json::from_slice(&json).unwrap();
            assert_eq!(
                serde_json::to_string(resp).unwrap(),
                serde_json::to_string(&deserialized).unwrap(),
            );
        }
    }

    // -- Mock server helpers ------------------------------------------------

    /// Spawn a TCP server that reads one framed request, applies `handler`, and
    /// sends back the framed response.
    async fn mock_guest_server<F>(
        listener: &TcpListener,
        handler: F,
    ) where
        F: FnOnce(GuestRequest) -> GuestResponse + Send + 'static,
    {
        let (mut stream, _addr) = listener.accept().await.unwrap();
        let request_bytes = read_message(&mut stream).await.unwrap();
        let request: GuestRequest =
            serde_json::from_slice(&request_bytes).unwrap();
        let response = handler(request);
        let response_bytes = serde_json::to_vec(&response).unwrap();
        write_message(&mut stream, &response_bytes).await.unwrap();
    }

    // -- End-to-end protocol tests over TCP ---------------------------------

    #[tokio::test]
    async fn test_ping_pong() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            mock_guest_server(&listener, |req| {
                assert!(matches!(req, GuestRequest::Ping));
                GuestResponse::Pong
            })
            .await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let response =
            send_request_over(&mut stream, &GuestRequest::Ping).await.unwrap();

        assert!(matches!(response, GuestResponse::Pong));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_exec_request_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            mock_guest_server(&listener, |req| match req {
                GuestRequest::Exec { command, args } => {
                    assert_eq!(command, "ls");
                    assert_eq!(args, vec!["-la".to_string()]);
                    GuestResponse::ExecResult {
                        exit_code: 0,
                        stdout: "total 0\n".into(),
                        stderr: String::new(),
                    }
                }
                _ => panic!("expected Exec request"),
            })
            .await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = GuestRequest::Exec {
            command: "ls".into(),
            args: vec!["-la".into()],
        };
        let response = send_request_over(&mut stream, &request).await.unwrap();

        match response {
            GuestResponse::ExecResult {
                exit_code,
                stdout,
                stderr,
            } => {
                assert_eq!(exit_code, 0);
                assert_eq!(stdout, "total 0\n");
                assert!(stderr.is_empty());
            }
            _ => panic!("expected ExecResult"),
        }

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_status_request_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            mock_guest_server(&listener, |req| {
                assert!(matches!(req, GuestRequest::Status));
                GuestResponse::StatusResult {
                    hostname: "sandbox-test".into(),
                    uptime_secs: 3600,
                    load_average: 0.42,
                }
            })
            .await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let response =
            send_request_over(&mut stream, &GuestRequest::Status).await.unwrap();

        match response {
            GuestResponse::StatusResult {
                hostname,
                uptime_secs,
                load_average,
            } => {
                assert_eq!(hostname, "sandbox-test");
                assert_eq!(uptime_secs, 3600);
                assert!((load_average - 0.42).abs() < f64::EPSILON);
            }
            _ => panic!("expected StatusResult"),
        }

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_malformed_json() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Read the valid request.
            let _ = read_message(&mut stream).await.unwrap();
            // Send back invalid JSON as a framed message.
            let garbage = b"this is not valid json {{{";
            write_message(&mut stream, garbage).await.unwrap();
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let result =
            send_request_over(&mut stream, &GuestRequest::Ping).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("deserialize"),
            "error should mention deserialization: {err}"
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_requests() {
        // Multiple sequential requests to the same mock server (each gets its
        // own connection, as our protocol is one-shot per connection).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            for i in 0..5 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request_bytes = read_message(&mut stream).await.unwrap();
                let request: GuestRequest =
                    serde_json::from_slice(&request_bytes).unwrap();

                let response = match request {
                    GuestRequest::Exec { command, .. } => {
                        GuestResponse::ExecResult {
                            exit_code: i,
                            stdout: format!("output from request {i}: {command}"),
                            stderr: String::new(),
                        }
                    }
                    GuestRequest::Ping => GuestResponse::Pong,
                    GuestRequest::Status => GuestResponse::StatusResult {
                        hostname: "test".into(),
                        uptime_secs: 100,
                        load_average: 0.0,
                    },
                    _ => GuestResponse::Error {
                        message: "unexpected request in test".into(),
                    },
                };

                let response_bytes = serde_json::to_vec(&response).unwrap();
                write_message(&mut stream, &response_bytes).await.unwrap();
            }
        });

        for i in 0..5i32 {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let request = GuestRequest::Exec {
                command: format!("cmd-{i}"),
                args: vec![],
            };
            let response = send_request_over(&mut stream, &request).await.unwrap();

            match response {
                GuestResponse::ExecResult {
                    exit_code, stdout, ..
                } => {
                    assert_eq!(exit_code, i);
                    assert!(stdout.contains(&format!("cmd-{i}")));
                }
                _ => panic!("expected ExecResult for request {i}"),
            }
        }

        server.await.unwrap();
    }
}
