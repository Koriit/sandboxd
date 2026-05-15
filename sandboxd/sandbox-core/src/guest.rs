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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ring::digest;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info};

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
/// `DAEMON_GUEST_PROTO_VERSION-1 ..= DAEMON_GUEST_PROTO_VERSION`) lands
/// in a follow-up spec and only edits this function.
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
/// V006 deletes all rows on apply (spec § 2.1), so this arm is
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
/// Spec 2 § 3.6 specifies `include_bytes!` for production builds (Spec
/// 4 territory); for Spec 2's dev-mode-only scope, the daemon reads
/// the sibling binary via the existing
/// [`crate::lima::guest_agent_path`] resolver and stages it through
/// [`tempfile::NamedTempFile`] so the refresh sequence has a stable
/// host path to hand to the backend command. The tempfile is preserved
/// across the resulting `NamedTempFile` value; dropping the returned
/// handle deletes it on the host.
pub fn stage_embedded_guest_binary() -> Result<tempfile::NamedTempFile, SandboxError> {
    let agent_src = crate::lima::guest_agent_path()?;
    if !agent_src.exists() {
        return Err(SandboxError::Internal(format!(
            "embedded guest binary not found at {}",
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
// Startup staging — daemon writes `sandbox-guest` into its state dir once
// at startup and every container session bind-mounts that path read-only
// at `/usr/local/bin/sandbox-guest` (api-session-isolation spec § 3.8.1).
// ---------------------------------------------------------------------------

/// Relative path inside `base_dir` where the daemon stages the
/// embedded `sandbox-guest` binary at startup. The path component
/// `guest` matches the subdir [`STAGED_GUEST_SUBDIR`] created by
/// [`crate::backend`]'s daemon-startup layout enforcer; the file
/// component `sandbox-guest` is the canonical executable name shared
/// with the in-image baked copy at `/usr/local/bin/sandbox-guest`.
pub const STAGED_GUEST_FILE_RELPATH: &str = "guest/sandbox-guest";

/// Subdirectory name under the daemon's `base_dir` that holds
/// [`STAGED_GUEST_FILE_RELPATH`]. Owned by the daemon's user at mode
/// `0o700` (daemon-productionization spec § 5.4).
pub const STAGED_GUEST_SUBDIR: &str = "guest";

/// Compose the absolute path to the staged `sandbox-guest` binary
/// inside a given `base_dir`. Pure path arithmetic — does not stat or
/// otherwise touch the filesystem.
pub fn staged_guest_path(base_dir: &Path) -> PathBuf {
    base_dir.join(STAGED_GUEST_FILE_RELPATH)
}

/// Outcome of a [`stage_guest_binary_at`] call. The variants distinguish
/// "the file was absent and we wrote it" from "the file existed with
/// matching sha256 — left alone" from "the file existed with a different
/// sha256 and we atomically rewrote it". Used by both the daemon-startup
/// staging log line and the unit tests so the three idempotency arms
/// stay observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageOutcome {
    /// The destination did not exist; bytes were written into a sibling
    /// tempfile and renamed into place.
    Wrote,
    /// The destination existed with a sha256 matching the embedded bytes;
    /// no write was performed.
    SkippedMatch,
    /// The destination existed with a different sha256; bytes were
    /// rewritten via a sibling-tempfile-and-rename atomic replace.
    Rewrote,
}

/// Compute the SHA-256 digest of `bytes` and return the 32-byte
/// fingerprint. Shared between the on-disk compare and the test
/// fixtures so both sides agree on the byte ordering.
fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// Stage `bytes` at `dst` with mode `0o755`, idempotently:
///
/// - If `dst` does not exist → write via sibling-tempfile-and-rename;
///   return [`StageOutcome::Wrote`].
/// - If `dst` exists with sha256 matching `bytes` → no-op; return
///   [`StageOutcome::SkippedMatch`].
/// - If `dst` exists with a different sha256 → atomically rewrite via
///   the same sibling-tempfile-and-rename pattern; return
///   [`StageOutcome::Rewrote`].
///
/// The sibling tempfile lives in the same directory as `dst` so the
/// `rename` is atomic on POSIX (same-filesystem invariant). The
/// tempfile is created with `O_EXCL` semantics via [`tempfile::Builder`]
/// to avoid a concurrent-daemon collision; if two daemons start
/// simultaneously and stage the same bytes, the second's rename
/// overwrites the first, both observe identical content, and no
/// running session sees a torn binary because the rename is atomic.
///
/// The function is synchronous and CPU-cheap (a few stat / open /
/// hash calls in the happy path) — daemon startup invokes it under
/// `spawn_blocking` for the same reason
/// `ensure_base_dir_layout` does.
pub fn stage_guest_binary_at(dst: &Path, bytes: &[u8]) -> Result<StageOutcome, SandboxError> {
    // 1. Compute the embed-side fingerprint up front so the on-disk
    //    check below has something to compare against.
    let want = sha256_of(bytes);

    // 2. Stat dst. Missing → write; present → compare.
    match std::fs::metadata(dst) {
        Ok(md) if md.is_file() => {
            // Present: compare bytes. We hash the on-disk contents
            // rather than trusting mtime/size because the operator-
            // recovery story for "binary corrupted by a half-failed
            // copy" wants a full content check.
            let have = std::fs::read(dst).map_err(|e| {
                SandboxError::Internal(format!(
                    "stage_guest_binary_at: failed to read {} for sha256 compare: {e}",
                    dst.display()
                ))
            })?;
            if sha256_of(&have) == want {
                return Ok(StageOutcome::SkippedMatch);
            }
            atomic_write_executable(dst, bytes)?;
            Ok(StageOutcome::Rewrote)
        }
        Ok(_) => Err(SandboxError::Internal(format!(
            "stage_guest_binary_at: {} exists but is not a regular file",
            dst.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            atomic_write_executable(dst, bytes)?;
            Ok(StageOutcome::Wrote)
        }
        Err(e) => Err(SandboxError::Internal(format!(
            "stage_guest_binary_at: stat({}) failed: {e}",
            dst.display()
        ))),
    }
}

/// Write `bytes` to a sibling tempfile in `dst`'s parent directory,
/// `fchmod` it to `0o755`, then `rename` it onto `dst`. The rename is
/// atomic on POSIX so concurrent readers of `dst` either see the old
/// inode or the new inode — never a torn write.
///
/// Shape mirrors `sandbox-cli/src/update/backup.rs::write_sandbox_owned_file`
/// — same `NamedTempFile` + chmod + persist sequence — but stays inside
/// `sandbox-core` (the daemon, not the CLI's `sudo install` shim, owns
/// the destination here).
fn atomic_write_executable(dst: &Path, bytes: &[u8]) -> Result<(), SandboxError> {
    let parent = dst.parent().ok_or_else(|| {
        SandboxError::Internal(format!(
            "atomic_write_executable: destination {} has no parent",
            dst.display()
        ))
    })?;
    // `NamedTempFile::new_in(parent)` keeps the tempfile on the same
    // filesystem as `dst`, which is the precondition for the rename
    // below to be atomic.
    let mut tmp = tempfile::Builder::new()
        .prefix(".sandbox-guest-stage-")
        .tempfile_in(parent)
        .map_err(|e| {
            SandboxError::Internal(format!(
                "atomic_write_executable: tempfile in {} failed: {e}",
                parent.display()
            ))
        })?;
    {
        use std::io::Write;
        tmp.write_all(bytes).map_err(|e| {
            SandboxError::Internal(format!(
                "atomic_write_executable: write to tempfile {} failed: {e}",
                tmp.path().display()
            ))
        })?;
        tmp.flush().map_err(|e| {
            SandboxError::Internal(format!(
                "atomic_write_executable: flush tempfile {} failed: {e}",
                tmp.path().display()
            ))
        })?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(tmp.path())
            .map_err(|e| {
                SandboxError::Internal(format!(
                    "atomic_write_executable: stat tempfile {} failed: {e}",
                    tmp.path().display()
                ))
            })?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(tmp.path(), perms).map_err(|e| {
            SandboxError::Internal(format!(
                "atomic_write_executable: chmod 0755 on tempfile {} failed: {e}",
                tmp.path().display()
            ))
        })?;
    }
    // `persist` performs the atomic rename. On success it returns the
    // open `File`; we drop it immediately because the daemon doesn't
    // need to hold the file open after staging.
    tmp.persist(dst).map_err(|e| {
        SandboxError::Internal(format!(
            "atomic_write_executable: rename onto {} failed: {}",
            dst.display(),
            e.error
        ))
    })?;
    Ok(())
}

/// Stage the embedded `sandbox-guest` binary into the daemon's state
/// directory at [`staged_guest_path(base_dir)`][staged_guest_path].
///
/// Reads the bytes via the existing sibling-file resolver
/// ([`crate::lima::guest_agent_path`]) — the same dev-mode source
/// [`stage_embedded_guest_binary`] uses for the per-refresh tempfile.
/// Spec 4 will swap that resolver for compile-time `include_bytes!`
/// (spec § 3.6 option A); the staging contract here is unchanged
/// either way because [`stage_guest_binary_at`] takes raw bytes.
///
/// Idempotent per [`stage_guest_binary_at`]'s contract — safe to call
/// on every daemon startup. Logs at `info!` with the outcome so the
/// startup journal records whether the staged binary changed since the
/// previous boot.
pub fn stage_embedded_guest_binary_into_base_dir(
    base_dir: &Path,
) -> Result<StageOutcome, SandboxError> {
    let src = crate::lima::guest_agent_path()?;
    let bytes = std::fs::read(&src).map_err(|e| {
        SandboxError::Internal(format!(
            "stage_embedded_guest_binary_into_base_dir: failed to read {} : {e}",
            src.display()
        ))
    })?;
    let dst = staged_guest_path(base_dir);
    let outcome = stage_guest_binary_at(&dst, &bytes)?;
    info!(
        src = %src.display(),
        dst = %dst.display(),
        bytes = bytes.len(),
        outcome = ?outcome,
        "sandbox-guest staged into base_dir for bind-mount source"
    );
    Ok(outcome)
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
    /// constants. Used by diagnostic surfaces (Spec 3's `sandbox
    /// doctor`, optional post-start cross-checks) to detect drift
    /// between the persisted DB columns and the actually-running guest
    /// binary. Not part of the refresh-on-start decision tree — that
    /// path is DB-driven (spec § 3.10).
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
        // `GuestConnector`, so the bypass is safe (api-session-isolation
        // spec § 2.4).
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
        let transport = runtime.guest_transport(&handle);

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
        AsyncReadWrite, BackendKind, Capabilities, ExitCode, GuestTransport, IsolationLevel,
        RuntimeHandle, RuntimeStartArgs, RuntimeStatus, SessionRuntime, SessionSpec,
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

        async fn stop(&self, _handle: &RuntimeHandle) -> Result<(), SandboxError> {
            unimplemented!("StubRuntime::stop — not exercised by guest dispatch tests")
        }

        async fn delete(&self, _handle: &RuntimeHandle) -> Result<(), SandboxError> {
            unimplemented!("StubRuntime::delete — not exercised by guest dispatch tests")
        }

        async fn status(&self, _handle: &RuntimeHandle) -> Result<RuntimeStatus, SandboxError> {
            unimplemented!("StubRuntime::status — not exercised by guest dispatch tests")
        }

        fn guest_transport(&self, _handle: &RuntimeHandle) -> Arc<dyn GuestTransport> {
            Arc::new(StubTransport {
                kind: self.kind,
                observed: Arc::clone(&self.observed),
            })
        }

        async fn exec_interactive(
            &self,
            _handle: &RuntimeHandle,
            _cmd: Vec<String>,
            _stdin: Box<dyn AsyncRead + Unpin + Send>,
            _stdout: Box<dyn AsyncWrite + Unpin + Send>,
            _stderr: Box<dyn AsyncWrite + Unpin + Send>,
        ) -> Result<ExitCode, SandboxError> {
            unimplemented!("StubRuntime::exec_interactive — not exercised by guest dispatch tests")
        }

        async fn refresh_guest_binary(&self, _handle: &RuntimeHandle) -> Result<(), SandboxError> {
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

    // -- Compatibility-predicate tests (Spec 2 § 7.3) -----------------------

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

    // -- Startup staging tests (bind-mount design) -------------------------

    /// Helper: prepare a fresh `guest/` subdir inside a tempdir and
    /// return both the subdir path and the destination file path the
    /// staging function will write into. The subdir must exist
    /// because the atomic-write uses `tempfile_in(parent)` and the
    /// daemon's startup `ensure_base_dir_layout` step creates the
    /// subdir before invoking staging.
    fn fresh_guest_subdir() -> (tempfile::TempDir, std::path::PathBuf) {
        let base = tempfile::TempDir::new().expect("tempdir");
        let guest_dir = base.path().join(STAGED_GUEST_SUBDIR);
        std::fs::create_dir(&guest_dir).expect("create guest subdir");
        let dst = base.path().join(STAGED_GUEST_FILE_RELPATH);
        (base, dst)
    }

    #[test]
    fn stage_guest_binary_writes_embedded_bytes_when_path_absent() {
        let (_base, dst) = fresh_guest_subdir();
        assert!(!dst.exists(), "fixture should start absent");

        let bytes = b"#!/bin/echo synthetic-sandbox-guest\n";
        let outcome =
            stage_guest_binary_at(&dst, bytes).expect("stage_guest_binary_at must succeed");

        assert_eq!(
            outcome,
            StageOutcome::Wrote,
            "absent path must take the Wrote arm",
        );
        let on_disk = std::fs::read(&dst).expect("read staged file");
        assert_eq!(on_disk, bytes, "staged contents must match input");

        // Mode 0o755 — the bind-mount target inside the container must
        // be executable by the agent user (uid 1000) reaching it via
        // the kernel's path-traversal. The atomic-write helper pins
        // this on the tempfile before the rename; assert here so a
        // regression in the chmod step trips immediately.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dst)
                .expect("stat staged file")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o755, "staged file must be 0o755; got {mode:o}");
        }
    }

    #[test]
    fn stage_guest_binary_skips_when_sha256_matches() {
        let (_base, dst) = fresh_guest_subdir();
        let bytes = b"identical-bytes-across-two-staging-calls";

        // First call writes; assert the precondition for the second
        // call below (file present + sha matches).
        let first =
            stage_guest_binary_at(&dst, bytes).expect("first stage_guest_binary_at must succeed");
        assert_eq!(first, StageOutcome::Wrote);

        // Capture the inode so we can prove the second call did NOT
        // rewrite — a Rewrote arm replaces the file via rename and
        // produces a fresh inode, so inode equality is a strong
        // signal of the SkippedMatch arm.
        #[cfg(unix)]
        let inode_before = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&dst).expect("stat before").ino()
        };

        let second = stage_guest_binary_at(&dst, bytes)
            .expect("second stage_guest_binary_at must succeed");
        assert_eq!(
            second,
            StageOutcome::SkippedMatch,
            "matching-sha256 path must take the SkippedMatch arm",
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let inode_after = std::fs::metadata(&dst).expect("stat after").ino();
            assert_eq!(
                inode_before, inode_after,
                "SkippedMatch must leave the inode untouched; the bind-mount source \
                 inode is shared across every live container session and replacing it \
                 would break the page-cache-sharing motivation of the design",
            );
        }
    }

    #[test]
    fn stage_guest_binary_rewrites_when_sha256_differs_atomically() {
        let (_base, dst) = fresh_guest_subdir();
        let old_bytes = b"old-guest-binary-v1";
        let new_bytes = b"new-guest-binary-v2-larger-payload";

        // Seed with v1.
        let first = stage_guest_binary_at(&dst, old_bytes).expect("seed write");
        assert_eq!(first, StageOutcome::Wrote);

        // Capture pre-rewrite state. The atomic-rename invariant says
        // a concurrent reader either sees `old_bytes` or `new_bytes`
        // — never a torn write. We can't easily race a reader inside
        // a unit test, but we can check the inode-change signal that
        // proves a `rename(2)` happened (vs an in-place truncate +
        // write, which would not change the inode).
        #[cfg(unix)]
        let inode_before = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&dst).expect("stat before").ino()
        };

        // Re-stage with different bytes.
        let second = stage_guest_binary_at(&dst, new_bytes).expect("rewrite must succeed");
        assert_eq!(
            second,
            StageOutcome::Rewrote,
            "different-sha256 path must take the Rewrote arm",
        );
        let on_disk = std::fs::read(&dst).expect("read rewritten file");
        assert_eq!(on_disk, new_bytes, "rewrite must replace the contents");

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let inode_after = std::fs::metadata(&dst).expect("stat after").ino();
            assert_ne!(
                inode_before, inode_after,
                "Rewrote must produce a fresh inode (proves the rename(2) path \
                 was taken rather than an in-place truncate-and-write that would \
                 race against a concurrent reader)",
            );
            // Mode still 0o755 after the rewrite — the atomic-write
            // helper chmods the tempfile before the rename, so the
            // new inode lands with the same mode the first call set.
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dst)
                .expect("stat rewritten")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode, 0o755,
                "rewrite must preserve mode 0o755; got {mode:o}",
            );
        }
    }

    #[test]
    fn staged_guest_path_composes_under_base_dir() {
        let base = std::path::PathBuf::from("/var/lib/sandbox");
        let staged = staged_guest_path(&base);
        assert_eq!(
            staged,
            std::path::PathBuf::from("/var/lib/sandbox/guest/sandbox-guest"),
        );
    }
}
