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
//! - **[`GuestConnector`]** — high-level client that dispatches to the
//!   per-session backend (Lima or Container) via the
//!   [`SessionRuntime::guest_transport`] seam, then exchanges framed JSON
//!   over the returned bidirectional stream.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::backend::{BackendKind, RuntimeHandle, SessionRuntime};
use crate::error::SandboxError;
use crate::session::SessionId;
use crate::store::SessionStore;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Port the guest agent listens on inside the VM.
pub const GUEST_AGENT_PORT: u16 = 5123;

/// Maximum message size (1 MB).
pub const MAX_MESSAGE_SIZE: u32 = 1_048_576;

/// Timeout for a single guest agent request/response cycle.
const GUEST_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Wire-protocol version the daemon speaks to `sandbox-guest`. Bumped
/// when a [`GuestRequest`] or [`GuestResponse`] variant is added,
/// removed, renamed, or changes shape — i.e., when an old guest binary
/// would no longer round-trip a message exchanged with a new daemon.
///
/// **Not** bumped for guest-binary changes that don't touch the wire
/// (e.g. an exec timeout adjustment, internal logging change).
pub const DAEMON_GUEST_PROTO_VERSION: u32 = 1;

/// Semver of the embedded `sandbox-guest` binary. Stamped into
/// `sessions.guest_binary_version` on create and on every refresh.
///
/// Sourced at build time from `sandbox-guest/Cargo.toml` via the
/// `sandbox-core` build script so the daemon never has to mirror the
/// guest crate's version by hand.
pub const SANDBOX_GUEST_VERSION: &str = env!("SANDBOX_GUEST_VERSION");

/// `true` when this daemon can drive the wire protocol of a session
/// last touched at `session_proto`.
///
/// For v1 the daemon supports exactly one protocol version (its own);
/// future widening (a multi-version range, e.g.
/// `DAEMON_GUEST_PROTO_VERSION-1 ..= DAEMON_GUEST_PROTO_VERSION`) only
/// requires editing this function.
pub fn is_protocol_compatible(session_proto: u32) -> bool {
    session_proto == DAEMON_GUEST_PROTO_VERSION
}

/// `true` when this daemon's refresh path can realistically install
/// its embedded guest binary into a session at `session_proto`.
///
/// For v1 the answer is "yes for every protocol version we recognise";
/// the seam exists so a future protocol change with an irreconcilable
/// break (e.g. a wire framing change that an old guest cannot
/// understand even to read the "please upgrade yourself" message) can
/// flip its arm to `false` without touching the daemon dispatch.
///
/// `session_proto == 0` is treated as "unknown / pre-V006 record" — but
/// V006 deletes all rows on apply, so this arm is
/// defensive: in practice every row reaches this function with a real
/// proto value. Integration tests construct synthetic `proto = 0` rows
/// to drive the refuse arm of the start-session decision tree.
pub fn can_refresh_in_place(session_proto: u32) -> bool {
    session_proto != 0
}

/// Stage the daemon-side `sandbox-guest` binary into a host tempfile
/// with mode `0o755`, ready to be `docker cp`'d or `limactl copy`'d
/// into a session at refresh time.
///
/// Reads the source bytes from the host filesystem via the
/// [`crate::lima::guest_agent_path`] resolver — production builds find
/// it at the FHS-canonical install path under `/usr/local/libexec/`;
/// dev / test builds fall back to the cargo target directory. The
/// bytes are written into a [`tempfile::NamedTempFile`] so the refresh
/// sequence has a stable host path to hand to the backend command.
/// Dropping the returned handle deletes the tempfile on the host.
pub fn stage_guest_binary_to_tempfile() -> Result<tempfile::NamedTempFile, SandboxError> {
    let agent_src = crate::lima::guest_agent_path()?;
    if !agent_src.exists() {
        return Err(SandboxError::Internal(format!(
            "guest binary not found at {}",
            agent_src.display()
        )));
    }
    let bytes = std::fs::read(&agent_src).map_err(|e| {
        SandboxError::Internal(format!(
            "failed to read guest binary at {}: {e}",
            agent_src.display()
        ))
    })?;

    let mut tempfile = tempfile::NamedTempFile::new()?;
    {
        use std::io::Write;
        tempfile.write_all(&bytes)?;
        tempfile.flush()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(tempfile.path())?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(tempfile.path(), perms)?;
    }
    Ok(tempfile)
}

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
    /// Ask the guest to self-report its compile-time
    /// [`DAEMON_GUEST_PROTO_VERSION`] and [`SANDBOX_GUEST_VERSION`]
    /// constants. Used by diagnostic surfaces (the `sandbox
    /// doctor`, optional post-start cross-checks) to detect drift
    /// between the persisted DB columns and the actually-running guest
    /// binary. Not part of the refresh-on-start decision tree — that
    /// path is DB-driven.
    Version,
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
    Error {
        message: String,
    },
    /// Reply to [`GuestRequest::Version`]; carries the guest's
    /// compile-time protocol and binary versions.
    VersionResult {
        protocol_version: u32,
        binary_version: String,
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
pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, SandboxError> {
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
    let payload = serde_json::to_vec(request)
        .map_err(|e| SandboxError::Internal(format!("failed to serialize request: {e}")))?;

    // Split the stream into read/write halves is not needed when we own &mut S.
    // We write first, then read — the protocol is strictly request-then-response.
    let (reader, writer) = tokio::io::split(stream);
    let mut reader = reader;
    let mut writer = writer;

    write_message(&mut writer, &payload).await?;

    let response_bytes = read_message(&mut reader).await?;

    let response: GuestResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| SandboxError::Internal(format!("failed to deserialize response: {e}")))?;

    Ok(response)
}

// ---------------------------------------------------------------------------
// GuestConnector
// ---------------------------------------------------------------------------

/// High-level client for sending requests to the guest agent inside a sandbox
/// session, regardless of backend.
///
/// At construction time the connector receives the daemon's per-backend
/// dispatch table plus an [`Arc<SessionStore>`]. On every
/// [`Self::send_request`] call it:
///
/// 1. Looks up the session in the store to learn its [`BackendKind`].
/// 2. Dispatches to the matching [`SessionRuntime`] in the registry.
/// 3. Asks that runtime for a [`GuestTransport`][crate::backend::GuestTransport],
///    opens a fresh connection through it, and exchanges the framed JSON
///    request/response over the returned bidirectional stream.
///
/// Backends own their own spawn/teardown logic — this connector is purely a
/// dispatcher and protocol driver.
pub struct GuestConnector {
    /// Backend dispatch table — same `Arc` shared with `AppState::runtimes`.
    runtimes: Arc<HashMap<BackendKind, Arc<dyn SessionRuntime>>>,
    /// Used to look up the session's backend at request time. Without a
    /// stored backend kind we cannot pick the right transport.
    store: Arc<SessionStore>,
}

impl GuestConnector {
    /// Create a new connector backed by the daemon's runtime registry and
    /// session store.
    pub fn new(
        runtimes: Arc<HashMap<BackendKind, Arc<dyn SessionRuntime>>>,
        store: Arc<SessionStore>,
    ) -> Self {
        Self { runtimes, store }
    }

    /// Send a request to the guest agent for `session_id` and return the
    /// response.
    ///
    /// Picks the transport based on the session's persisted [`BackendKind`]:
    /// `Lima` sessions go through `limactl shell ... socat`; `Container`
    /// sessions go through `docker exec ... socat`. Both implementations
    /// expose the same framed JSON protocol on TCP `127.0.0.1:5123` inside
    /// the session.
    pub async fn send_request(
        &self,
        session_id: &SessionId,
        request: GuestRequest,
    ) -> Result<GuestResponse, SandboxError> {
        // Daemon-internal subsystem: the handler boundary already
        // performed the per-caller ownership check before reaching
        // `GuestConnector`, so the bypass is safe (ownership already verified at the handler boundary).
        let session = self
            .store
            .get_session_unfiltered(session_id)?
            .ok_or_else(|| SandboxError::SessionNotFound(session_id.to_string()))?;

        let runtime = self.runtimes.get(&session.backend).ok_or_else(|| {
            SandboxError::Internal(format!(
                "no runtime registered for backend {:?} (session {session_id})",
                session.backend
            ))
        })?;

        let handle = RuntimeHandle::from_session_id(session_id);
        // operator_uid drives sandbox-lima-helper guest-socat --op-uid.
        // Post-V009 every session row carries a non-None operator_uid;
        // fall back to 0 only for test rows (container runtime ignores it).
        let op_uid = session.operator_uid.unwrap_or(0);
        let transport = runtime.guest_transport(&handle, op_uid);

        debug!(
            session_id = %session_id,
            backend = ?session.backend,
            request_type = ?std::mem::discriminant(&request),
            "sending request to guest agent"
        );

        let exchange = async {
            let mut stream = transport.connect().await?;
            send_request_over(&mut stream, &request).await
        };

        match tokio::time::timeout(GUEST_REQUEST_TIMEOUT, exchange).await {
            Ok(result) => result,
            Err(_elapsed) => Err(SandboxError::Timeout {
                operation: format!("guest agent request for {session_id}"),
                duration: GUEST_REQUEST_TIMEOUT.as_secs(),
            }),
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

    /// Execute a command inside the session's guest agent.
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

        let version = GuestRequest::Version;
        let json = serde_json::to_string(&version).unwrap();
        assert!(json.contains(r#""type":"Version"#));
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

        let error = GuestResponse::Error {
            message: "something broke".into(),
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains(r#""type":"Error"#));

        let version = GuestResponse::VersionResult {
            protocol_version: DAEMON_GUEST_PROTO_VERSION,
            binary_version: SANDBOX_GUEST_VERSION.into(),
        };
        let json = serde_json::to_string(&version).unwrap();
        assert!(json.contains(r#""type":"VersionResult"#));
        assert!(json.contains(r#""protocol_version":1"#));
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
            GuestRequest::Version,
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
            GuestResponse::Error {
                message: "fail".into(),
            },
            GuestResponse::VersionResult {
                protocol_version: DAEMON_GUEST_PROTO_VERSION,
                binary_version: SANDBOX_GUEST_VERSION.into(),
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
    async fn mock_guest_server<F>(listener: &TcpListener, handler: F)
    where
        F: FnOnce(GuestRequest) -> GuestResponse + Send + 'static,
    {
        let (mut stream, _addr) = listener.accept().await.unwrap();
        let request_bytes = read_message(&mut stream).await.unwrap();
        let request: GuestRequest = serde_json::from_slice(&request_bytes).unwrap();
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
        let response = send_request_over(&mut stream, &GuestRequest::Ping)
            .await
            .unwrap();

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
        let response = send_request_over(&mut stream, &GuestRequest::Status)
            .await
            .unwrap();

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
        let result = send_request_over(&mut stream, &GuestRequest::Ping).await;

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
                let request: GuestRequest = serde_json::from_slice(&request_bytes).unwrap();

                let response = match request {
                    GuestRequest::Exec { command, .. } => GuestResponse::ExecResult {
                        exit_code: i,
                        stdout: format!("output from request {i}: {command}"),
                        stderr: String::new(),
                    },
                    GuestRequest::Ping => GuestResponse::Pong,
                    GuestRequest::Status => GuestResponse::StatusResult {
                        hostname: "test".into(),
                        uptime_secs: 100,
                        load_average: 0.0,
                    },
                    GuestRequest::Version => GuestResponse::VersionResult {
                        protocol_version: DAEMON_GUEST_PROTO_VERSION,
                        binary_version: SANDBOX_GUEST_VERSION.into(),
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

    // -- GuestConnector dispatch tests --------------------------------------

    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;
    use tempfile::TempDir;

    use crate::backend::{
        AsyncReadWrite, BackendKind, Capabilities, GuestTransport, IsolationLevel, RuntimeHandle,
        RuntimeStartArgs, RuntimeStatus, SessionRuntime, SessionSpec,
    };
    use crate::session::SessionConfig;
    use crate::store::SessionStore;

    /// Records which backend the framework dispatched to and serves a fixed
    /// `Pong` over an in-memory duplex stream — no subprocess, no socket.
    struct StubTransport {
        kind: BackendKind,
        observed: Arc<StdMutex<Vec<BackendKind>>>,
    }

    #[async_trait]
    impl GuestTransport for StubTransport {
        async fn connect(&self) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>, SandboxError> {
            self.observed.lock().unwrap().push(self.kind);

            // One side of the duplex goes to the caller (the connector
            // exchanging the framed protocol); the other side acts as the
            // in-memory "guest agent" that reads the request and replies.
            let (client, mut server) = duplex(4096);

            tokio::spawn(async move {
                let request_bytes = match read_message(&mut server).await {
                    Ok(b) => b,
                    Err(_) => return,
                };
                let _request: GuestRequest = match serde_json::from_slice(&request_bytes) {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let response = GuestResponse::Pong;
                let response_bytes = serde_json::to_vec(&response).unwrap();
                let _ = write_message(&mut server, &response_bytes).await;
            });

            Ok(Box::new(client))
        }
    }

    /// Minimal `SessionRuntime` whose only meaningful behavior is yielding
    /// a `StubTransport` — every other trait method panics so a regression
    /// that calls them surfaces in the test rather than silently succeeding.
    struct StubRuntime {
        kind: BackendKind,
        capabilities: Capabilities,
        observed: Arc<StdMutex<Vec<BackendKind>>>,
    }

    #[async_trait]
    impl SessionRuntime for StubRuntime {
        fn kind(&self) -> BackendKind {
            self.kind
        }

        fn capabilities(&self) -> &Capabilities {
            &self.capabilities
        }

        async fn create(
            &self,
            _session_id: &SessionId,
            _spec: &SessionSpec,
        ) -> Result<RuntimeHandle, SandboxError> {
            unimplemented!("StubRuntime::create — not exercised by guest dispatch tests")
        }

        async fn start(
            &self,
            _handle: &RuntimeHandle,
            _args: &RuntimeStartArgs,
        ) -> Result<(), SandboxError> {
            unimplemented!("StubRuntime::start — not exercised by guest dispatch tests")
        }

        async fn stop(
            &self,
            _handle: &RuntimeHandle,
            _operator_uid: u32,
        ) -> Result<(), SandboxError> {
            unimplemented!("StubRuntime::stop — not exercised by guest dispatch tests")
        }

        async fn delete(
            &self,
            _handle: &RuntimeHandle,
            _operator_uid: u32,
        ) -> Result<(), SandboxError> {
            unimplemented!("StubRuntime::delete — not exercised by guest dispatch tests")
        }

        async fn status(
            &self,
            _handle: &RuntimeHandle,
            _operator_uid: u32,
        ) -> Result<RuntimeStatus, SandboxError> {
            unimplemented!("StubRuntime::status — not exercised by guest dispatch tests")
        }

        fn guest_transport(
            &self,
            _handle: &RuntimeHandle,
            _operator_uid: u32,
        ) -> Arc<dyn GuestTransport> {
            Arc::new(StubTransport {
                kind: self.kind,
                observed: Arc::clone(&self.observed),
            })
        }

        async fn refresh_guest_binary(
            &self,
            _handle: &RuntimeHandle,
            _operator_uid: u32,
        ) -> Result<(), SandboxError> {
            unimplemented!(
                "StubRuntime::refresh_guest_binary — not exercised by guest dispatch tests"
            )
        }
    }

    fn stub_capabilities(kind: BackendKind) -> Capabilities {
        // Field set is irrelevant for these tests — no validation runs.
        let isolation = match kind {
            BackendKind::Lima => IsolationLevel::Vm,
            BackendKind::Container => IsolationLevel::Container,
        };
        Capabilities {
            kind,
            isolation,
            nested_virt: false,
            privileged_ops: false,
            raw_network: false,
            hardening_flag: false,
            per_session_no_cache: false,
            workspace_modes: enumset::EnumSet::empty(),
        }
    }

    type RuntimeRegistry = Arc<HashMap<BackendKind, Arc<dyn SessionRuntime>>>;
    type ObservedDispatches = Arc<StdMutex<Vec<BackendKind>>>;
    type DispatchFixture = (
        TempDir,
        Arc<SessionStore>,
        RuntimeRegistry,
        ObservedDispatches,
    );

    fn build_dispatch_fixture() -> DispatchFixture {
        let temp = TempDir::new().unwrap();
        let (store, _orphans) = SessionStore::new(temp.path().to_path_buf()).unwrap();
        let store = Arc::new(store);

        let observed: Arc<StdMutex<Vec<BackendKind>>> = Arc::new(StdMutex::new(Vec::new()));

        let lima_runtime: Arc<dyn SessionRuntime> = Arc::new(StubRuntime {
            kind: BackendKind::Lima,
            capabilities: stub_capabilities(BackendKind::Lima),
            observed: Arc::clone(&observed),
        });
        let container_runtime: Arc<dyn SessionRuntime> = Arc::new(StubRuntime {
            kind: BackendKind::Container,
            capabilities: stub_capabilities(BackendKind::Container),
            observed: Arc::clone(&observed),
        });

        let mut map: HashMap<BackendKind, Arc<dyn SessionRuntime>> = HashMap::new();
        map.insert(BackendKind::Lima, lima_runtime);
        map.insert(BackendKind::Container, container_runtime);
        let runtimes = Arc::new(map);

        (temp, store, runtimes, observed)
    }

    #[tokio::test]
    async fn guest_connector_dispatches_to_lima_transport_for_lima_session() {
        let (_temp, store, runtimes, observed) = build_dispatch_fixture();
        let session = store
            .create_session_with_backend(
                SessionConfig::default(),
                None,
                BackendKind::Lima,
                "test-operator",
                0,
                "",
                None,
                None,
            )
            .unwrap();

        let connector = GuestConnector::new(runtimes, Arc::clone(&store));
        let response = connector
            .send_request(&session.id, GuestRequest::Ping)
            .await
            .unwrap();

        assert!(matches!(response, GuestResponse::Pong));
        let observed = observed.lock().unwrap();
        assert_eq!(*observed, vec![BackendKind::Lima]);
    }

    #[tokio::test]
    async fn guest_connector_dispatches_to_container_transport_for_container_session() {
        let (_temp, store, runtimes, observed) = build_dispatch_fixture();
        let session = store
            .create_session_with_backend(
                SessionConfig::default(),
                None,
                BackendKind::Container,
                "test-operator",
                0,
                "",
                None,
                None,
            )
            .unwrap();

        let connector = GuestConnector::new(runtimes, Arc::clone(&store));
        let response = connector
            .send_request(&session.id, GuestRequest::Ping)
            .await
            .unwrap();

        assert!(matches!(response, GuestResponse::Pong));
        let observed = observed.lock().unwrap();
        assert_eq!(*observed, vec![BackendKind::Container]);
    }

    #[tokio::test]
    async fn guest_connector_returns_session_not_found_for_unknown_id() {
        let (_temp, store, runtimes, _observed) = build_dispatch_fixture();
        let connector = GuestConnector::new(runtimes, Arc::clone(&store));

        // A well-formed but never-inserted session id.
        let unknown = SessionId::parse("0123456789ab").unwrap();
        let err = connector
            .send_request(&unknown, GuestRequest::Ping)
            .await
            .unwrap_err();

        assert!(
            matches!(err, SandboxError::SessionNotFound(_)),
            "expected SessionNotFound, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn guest_connector_errors_when_runtime_for_session_backend_is_missing() {
        let temp = TempDir::new().unwrap();
        let (store, _orphans) = SessionStore::new(temp.path().to_path_buf()).unwrap();
        let store = Arc::new(store);
        let session = store
            .create_session_with_backend(
                SessionConfig::default(),
                None,
                BackendKind::Container,
                "test-operator",
                0,
                "",
                None,
                None,
            )
            .unwrap();

        // Registry holds Lima only — the container session has no
        // runtime to dispatch to.
        let observed: Arc<StdMutex<Vec<BackendKind>>> = Arc::new(StdMutex::new(Vec::new()));
        let lima_runtime: Arc<dyn SessionRuntime> = Arc::new(StubRuntime {
            kind: BackendKind::Lima,
            capabilities: stub_capabilities(BackendKind::Lima),
            observed: Arc::clone(&observed),
        });
        let mut map: HashMap<BackendKind, Arc<dyn SessionRuntime>> = HashMap::new();
        map.insert(BackendKind::Lima, lima_runtime);
        let runtimes = Arc::new(map);

        let connector = GuestConnector::new(runtimes, Arc::clone(&store));
        let err = connector
            .send_request(&session.id, GuestRequest::Ping)
            .await
            .unwrap_err();

        assert!(
            matches!(err, SandboxError::Internal(ref msg) if msg.contains("no runtime registered")),
            "expected Internal('no runtime registered ...'), got: {err:?}"
        );
        assert!(
            observed.lock().unwrap().is_empty(),
            "no transport should be opened"
        );
    }

    // -- Compatibility-predicate tests -------------------------------------------

    #[test]
    fn is_compatible_matches_current_version() {
        assert!(is_protocol_compatible(DAEMON_GUEST_PROTO_VERSION));
    }

    #[test]
    fn is_compatible_rejects_older_version() {
        // DAEMON_GUEST_PROTO_VERSION is currently `1`; this anchors the
        // "older version" arm. If/when the daemon ever bumps to >=2 the
        // assertion stays well-typed.
        let older = DAEMON_GUEST_PROTO_VERSION.saturating_sub(1);
        if older < DAEMON_GUEST_PROTO_VERSION {
            assert!(!is_protocol_compatible(older));
        }
    }

    #[test]
    fn is_compatible_rejects_future_version() {
        assert!(!is_protocol_compatible(DAEMON_GUEST_PROTO_VERSION + 1));
    }

    #[test]
    fn is_compatible_rejects_zero() {
        assert!(!is_protocol_compatible(0));
    }

    #[test]
    fn can_refresh_in_place_accepts_known_versions() {
        assert!(can_refresh_in_place(1));
        assert!(can_refresh_in_place(DAEMON_GUEST_PROTO_VERSION));
    }

    #[test]
    fn can_refresh_in_place_rejects_zero() {
        assert!(!can_refresh_in_place(0));
    }

    #[test]
    fn sandbox_guest_version_is_non_empty_semver_shape() {
        // Build script sourced the value from sandbox-guest/Cargo.toml.
        // We don't pin the literal here so a bump in that crate doesn't
        // require a parallel edit, but assert the shape so a regression
        // (empty string, garbage) trips loudly. Length check goes via
        // `len` (rather than `is_empty`) because clippy refuses to
        // accept `is_empty` on a `const &str`.
        assert!(
            SANDBOX_GUEST_VERSION.len() >= 3,
            "SANDBOX_GUEST_VERSION should be a non-empty semver string"
        );
        assert!(
            SANDBOX_GUEST_VERSION.contains('.'),
            "SANDBOX_GUEST_VERSION should look semver-ish (contain a dot): {SANDBOX_GUEST_VERSION}"
        );
    }
}
