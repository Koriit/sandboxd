//! Synchronous DNS-policy gate IPC.
//!
//! This module implements the sandboxd side of the synchronous DNS-policy
//! gate handshake. The
//! CoreDNS plugin holds the VM's DNS answer until sandboxd has applied
//! the corresponding nft / Envoy state and acked.
//!
//! # Wire format
//!
//! Length-prefixed JSON: each frame is one JSON object terminated by
//! a single `\n` byte. UDS delivers in-order; the framing is simple
//! enough for both Go (CoreDNS plugin) and Rust (sandboxd) to use
//! `bufio.Scanner` / [`tokio::io::AsyncBufReadExt::read_line`].
//!
//! # Lifecycle
//!
//! The per-session listener is bound at session start (alongside the
//! existing DNS-propagation loop), accepts client connections from the
//! gateway-side CoreDNS plugin one at a time, and is cancelled at
//! session teardown. Each connection handles a single
//! request/response pair and closes — the plugin opens a fresh socket
//! per query in v1 (see `Pooled / multiplexed UDS connections` under
//! "Known gaps").
//!
//! The IPC wire shape is captured in [`GateRequest`] / [`GateAck`] /
//! [`GateError`]; the orchestration that turns a request into nft +
//! Envoy state lives in the [`GateService`] trait.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};

use crate::events::session_events_host_dir;
use crate::session::SessionId;

/// Wire-protocol version. Bumped on incompatible request/ack changes.
pub const GATE_PROTOCOL_VERSION: u32 = 1;

/// File name of the per-session UDS inside [`session_events_host_dir`].
///
/// The CoreDNS plugin sees this at
/// [`DNS_GATE_SOCKET_IN_CONTAINER`].
pub const DNS_GATE_SOCKET_FILENAME: &str = "dns-gate.sock";

/// Path to the per-session DNS-gate UDS as visible inside the gateway
/// container. The host-side path
/// (`{events_host_root()}/<session>/dns-gate.sock`) is bind-mounted
/// onto the container's `/var/log/gateway/events/` via
/// [`crate::events::EVENTS_DIR_IN_CONTAINER`]; the socket file lives
/// alongside the JSONL producers.
pub const DNS_GATE_SOCKET_IN_CONTAINER: &str = "/var/log/gateway/events/dns-gate.sock";

/// Default deadline a CoreDNS plugin pulls when issuing a gate
/// request. The daemon honours this; if the plugin sets a shorter
/// `deadline_ms` on the wire, that wins.
pub const DEFAULT_DEADLINE_MS: u64 = 1500;

/// Discriminator for the request shape. Reserved for future variants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateRequestKind {
    /// CoreDNS resolved a name and is asking sandboxd to admit the
    /// IPs before the DNS answer is released.
    PropagateAndAck,
}

/// CoreDNS → sandboxd gate request.
///
/// Field shapes mirror the wire-format table; see the
/// "Wire format" section for the full contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateRequest {
    pub kind: GateRequestKind,
    pub version: u32,
    pub correlation_id: String,
    pub domain: String,
    pub qtype: String,
    pub ips: Vec<String>,
    pub ttl_seconds: u32,
    pub deadline_ms: u64,
}

/// Status returned in [`GateAck::status`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    /// nft + Envoy are now admitting the requested IPs.
    Ok,
    /// IPs were already admitted; no work was performed.
    Noop,
    /// Daemon-side application failed (nft / Envoy rejected).
    Rejected,
    /// Daemon does not recognise this session's socket — the gate
    /// fired against a torn-down session.
    UnknownSession,
}

/// sandboxd → CoreDNS gate ack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateAck {
    pub kind: GateAckKind,
    pub version: u32,
    pub correlation_id: String,
    pub status: GateStatus,
    pub elapsed_ms: u64,
    /// Free-form daemon-side reason on `rejected`. `None` on `ok` /
    /// `noop`. The CoreDNS plugin echoes this verbatim into its
    /// `dns_gate_rejected` event so operators see the cause without
    /// having to cross-reference logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Discriminator for the ack shape.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateAckKind {
    PropagateAck,
}

/// Out-of-line error envelope for unrecoverable parse / version
/// mismatches. The plugin treats this as a deadline-equivalent
/// fail-open after emitting a `dns_gate_protocol_error` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateError {
    pub kind: GateErrorKind,
    pub version: u32,
    /// Echoed back when the request parsed far enough to recover the
    /// id; otherwise the empty string.
    pub correlation_id: String,
    pub code: GateErrorCode,
    pub message: String,
}

/// Discriminator for the error shape.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateErrorKind {
    PropagateError,
}

/// Reason a request was rejected outright (without entering the
/// service handler).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateErrorCode {
    /// `version` field not recognised by this daemon build.
    UnsupportedVersion,
    /// `kind` field not recognised by this daemon build.
    UnsupportedKind,
    /// JSON parse failure.
    MalformedRequest,
}

/// Untagged frame produced by the daemon — either a successful ack or
/// an out-of-line error. Serialised as one JSON object on the wire
/// (the `kind` field discriminates).
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum GateResponse {
    Ack(GateAck),
    Error(GateError),
}

/// Per-session DNS-gate socket path on the host.
pub fn dns_gate_socket_host_path(session_id: &SessionId) -> PathBuf {
    session_events_host_dir(session_id).join(DNS_GATE_SOCKET_FILENAME)
}

/// Outcome of [`GateService::service`] — the daemon-side handler
/// reports back which terminal state it reached.
#[derive(Debug, Clone)]
pub struct GateServiceOutcome {
    pub status: GateStatus,
    /// Free-form rejection reason. `None` unless `status == Rejected`.
    pub reason: Option<String>,
}

/// The daemon-side orchestration that the [`serve_gate_listener`]
/// loop hands a parsed request to.
///
/// Production wiring lives in `sandboxd::main` where it joins
/// `generate_domain_ip_rules`, `inject_nftables_ruleset_public`, and
/// `wait_for_lds_ack` into a single per-request flow. The trait is
/// the seam tests substitute a fake at: a unit test can return any
/// [`GateStatus`] without standing up nft / Envoy.
pub trait GateService: Send + Sync + 'static {
    /// Apply the policy effect of one gate request and return the
    /// terminal status. Callers must respect `req.deadline_ms` — the
    /// listener wraps the call in a timeout, so the implementation
    /// can rely on cancellation rather than threading a deadline
    /// through every step.
    fn service(
        &self,
        req: &GateRequest,
    ) -> impl std::future::Future<Output = GateServiceOutcome> + Send;
}

/// Bind a per-session UDS listener at the canonical path and return
/// it. Removes any stale socket file from a prior daemon run.
///
/// The caller (typically `sandboxd::main`) keeps the returned
/// [`UnixListener`] inside a tokio task that calls
/// [`serve_gate_listener`].
pub fn bind_gate_listener(
    session_id: &SessionId,
) -> Result<(UnixListener, PathBuf), std::io::Error> {
    let path = dns_gate_socket_host_path(session_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Drop any stale socket from a crashed prior daemon. UnixListener
    // refuses to bind onto an existing inode otherwise.
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    Ok((listener, path))
}

/// Best-effort cleanup of the per-session socket file. Called from
/// the gateway teardown path.
pub fn remove_gate_socket(session_id: &SessionId) {
    let path = dns_gate_socket_host_path(session_id);
    let _ = std::fs::remove_file(&path);
}

/// Accept connections on `listener` and dispatch each request to
/// `service`, replying on the same connection.
///
/// Loops until cancelled (typically by abort on session stop). One
/// connection handles exactly one request/ack pair; concurrent
/// requests get their own connection and run on their own task. The
/// per-request timeout is the smaller of the plugin's deadline_ms
/// and `max_deadline_ms` so a misbehaving plugin cannot pin daemon
/// resources indefinitely.
pub async fn serve_gate_listener<S: GateService + 'static>(
    listener: UnixListener,
    service: Arc<S>,
    max_deadline_ms: u64,
) {
    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // Bind died (socket file deleted, FD invalid) — a
                // restart of the listener task is the right
                // recovery, which the gateway lifecycle handles.
                warn!(error = %e, "dns-gate listener accept failed; exiting");
                return;
            }
        };

        let svc = Arc::clone(&service);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, svc, max_deadline_ms).await {
                debug!(error = %e, "dns-gate connection handler returned error");
            }
        });
    }
}

async fn handle_connection<S: GateService>(
    stream: UnixStream,
    service: Arc<S>,
    max_deadline_ms: u64,
) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        // Peer closed without sending anything.
        return Ok(());
    }

    let started = Instant::now();
    let response = match parse_request(&line) {
        Ok(req) => {
            let deadline = Duration::from_millis(req.deadline_ms.min(max_deadline_ms));
            // Service the request under the deadline; on timeout we
            // surface the request as Rejected with a synthetic reason
            // so the plugin's correlation_id stays useful. The plugin
            // also enforces its own deadline locally and falls open;
            // returning here is a defence-in-depth path so the daemon
            // does not pin a worker on a misbehaving handler.
            let corr = req.correlation_id.clone();
            let outcome = match tokio::time::timeout(deadline, service.service(&req)).await {
                Ok(o) => o,
                Err(_) => GateServiceOutcome {
                    status: GateStatus::Rejected,
                    reason: Some(format!(
                        "daemon deadline {} ms exceeded",
                        deadline.as_millis()
                    )),
                },
            };
            let elapsed_ms = started.elapsed().as_millis() as u64;
            GateResponse::Ack(GateAck {
                kind: GateAckKind::PropagateAck,
                version: GATE_PROTOCOL_VERSION,
                correlation_id: corr,
                status: outcome.status,
                elapsed_ms,
                reason: outcome.reason,
            })
        }
        Err(err) => GateResponse::Error(err),
    };

    let mut payload = serde_json::to_vec(&response)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    payload.push(b'\n');
    write_half.write_all(&payload).await?;
    write_half.flush().await?;
    write_half.shutdown().await?;
    Ok(())
}

/// Validate and parse one wire-format request line into a
/// [`GateRequest`]; on failure return a [`GateError`] that the caller
/// wraps in a `GateResponse::Error`.
fn parse_request(line: &str) -> Result<GateRequest, GateError> {
    // First parse generously to recover the correlation_id — it's
    // useful in protocol-error replies even when the rest of the
    // request is malformed.
    let value: serde_json::Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(e) => {
            return Err(GateError {
                kind: GateErrorKind::PropagateError,
                version: GATE_PROTOCOL_VERSION,
                correlation_id: String::new(),
                code: GateErrorCode::MalformedRequest,
                message: format!("not valid JSON: {e}"),
            });
        }
    };
    let correlation_id = value
        .get("correlation_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if let Some(version_value) = value.get("version") {
        if let Some(v) = version_value.as_u64() {
            if v as u32 != GATE_PROTOCOL_VERSION {
                return Err(GateError {
                    kind: GateErrorKind::PropagateError,
                    version: GATE_PROTOCOL_VERSION,
                    correlation_id,
                    code: GateErrorCode::UnsupportedVersion,
                    message: format!(
                        "version {v} not supported; daemon speaks v{GATE_PROTOCOL_VERSION}"
                    ),
                });
            }
        }
    }
    match serde_json::from_value::<GateRequest>(value) {
        Ok(req) => {
            if !matches!(req.kind, GateRequestKind::PropagateAndAck) {
                return Err(GateError {
                    kind: GateErrorKind::PropagateError,
                    version: GATE_PROTOCOL_VERSION,
                    correlation_id: req.correlation_id,
                    code: GateErrorCode::UnsupportedKind,
                    message: "kind must be propagate_and_ack".to_string(),
                });
            }
            Ok(req)
        }
        Err(e) => Err(GateError {
            kind: GateErrorKind::PropagateError,
            version: GATE_PROTOCOL_VERSION,
            correlation_id,
            code: GateErrorCode::MalformedRequest,
            message: format!("schema mismatch: {e}"),
        }),
    }
}

/// Send a single request frame on the given UDS path and read the
/// reply frame. Pure helper; primarily used by tests and by tools
/// that drive the gate from outside the CoreDNS plugin.
pub async fn send_request(
    socket: &std::path::Path,
    request: &GateRequest,
) -> std::io::Result<GateAck> {
    let mut stream = UnixStream::connect(socket).await?;
    let mut payload = serde_json::to_vec(request)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    payload.push(b'\n');
    stream.write_all(&payload).await?;
    stream.flush().await?;
    let (read_half, _write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut reply = String::new();
    let n = reader.read_line(&mut reply).await?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "daemon closed connection without ack",
        ));
    }
    let ack: GateAck = serde_json::from_str(reply.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(ack)
}

/// Lightweight diagnostic: log a serviced request at info level. Used
/// by the production wiring after a successful service call.
pub fn log_serviced(req: &GateRequest, ack: &GateAck) {
    info!(
        domain = %req.domain,
        ips = ?req.ips,
        ttl = req.ttl_seconds,
        correlation_id = %req.correlation_id,
        status = ?ack.status,
        elapsed_ms = ack.elapsed_ms,
        "dns gate serviced"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Test fake: returns a scripted [`GateStatus`] for every call,
    /// and records the requests it serviced.
    #[derive(Clone)]
    struct FakeService {
        status: GateStatus,
        reason: Option<String>,
        delay: Duration,
        calls: Arc<Mutex<Vec<GateRequest>>>,
    }

    impl FakeService {
        fn ok() -> Self {
            Self {
                status: GateStatus::Ok,
                reason: None,
                delay: Duration::ZERO,
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn rejected(reason: &str) -> Self {
            Self {
                status: GateStatus::Rejected,
                reason: Some(reason.to_string()),
                delay: Duration::ZERO,
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn slow(delay: Duration) -> Self {
            Self {
                status: GateStatus::Ok,
                reason: None,
                delay,
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl GateService for FakeService {
        async fn service(&self, req: &GateRequest) -> GateServiceOutcome {
            self.calls.lock().unwrap().push(req.clone());
            if self.delay > Duration::ZERO {
                tokio::time::sleep(self.delay).await;
            }
            GateServiceOutcome {
                status: self.status,
                reason: self.reason.clone(),
            }
        }
    }

    fn sample_request() -> GateRequest {
        GateRequest {
            kind: GateRequestKind::PropagateAndAck,
            version: GATE_PROTOCOL_VERSION,
            correlation_id: "01HZTESTCORRELATION".into(),
            domain: "static.crates.io".into(),
            qtype: "A".into(),
            ips: vec!["151.101.194.137".into()],
            ttl_seconds: 2,
            deadline_ms: DEFAULT_DEADLINE_MS,
        }
    }

    #[test]
    fn request_round_trips_through_json() {
        // Codec stability: the on-wire representation must remain
        // backwards-compatible with the design fixture.
        let req = sample_request();
        let s = serde_json::to_string(&req).unwrap();
        // Sanity-check key fields show up snake_case as the design
        // specifies.
        assert!(s.contains("\"kind\":\"propagate_and_ack\""));
        assert!(s.contains("\"version\":1"));
        assert!(s.contains("\"correlation_id\":\"01HZTESTCORRELATION\""));
        assert!(s.contains("\"domain\":\"static.crates.io\""));
        assert!(s.contains("\"qtype\":\"A\""));
        assert!(s.contains("\"ttl_seconds\":2"));
        let back: GateRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.correlation_id, req.correlation_id);
        assert_eq!(back.domain, req.domain);
    }

    #[test]
    fn parse_request_rejects_unsupported_version() {
        let raw = r#"{"kind":"propagate_and_ack","version":2,"correlation_id":"abc",
            "domain":"x.com","qtype":"A","ips":["1.2.3.4"],"ttl_seconds":1,"deadline_ms":100}"#;
        let err = parse_request(raw).expect_err("should reject");
        assert_eq!(err.code, GateErrorCode::UnsupportedVersion);
        assert_eq!(err.correlation_id, "abc");
    }

    #[test]
    fn parse_request_rejects_unknown_kind() {
        // Use a numeric value in `kind` to fail enum matching while still
        // letting `correlation_id` recover. (Strictly testing unknown
        // string variants requires #[serde(other)], which we deliberately
        // omit so the daemon stays strict.)
        let raw = r#"{"kind":"future_variant","version":1,"correlation_id":"abc",
            "domain":"x.com","qtype":"A","ips":["1.2.3.4"],"ttl_seconds":1,"deadline_ms":100}"#;
        let err = parse_request(raw).expect_err("should reject");
        assert_eq!(err.correlation_id, "abc");
        // Either MalformedRequest (serde rejects the variant) or
        // UnsupportedKind — both are acceptable for an unknown kind.
        assert!(matches!(
            err.code,
            GateErrorCode::MalformedRequest | GateErrorCode::UnsupportedKind,
        ));
    }

    #[test]
    fn parse_request_rejects_garbage_json() {
        let err = parse_request("not json").expect_err("should reject");
        assert_eq!(err.code, GateErrorCode::MalformedRequest);
        assert_eq!(err.correlation_id, "");
    }

    #[tokio::test]
    async fn listener_serves_a_single_request_and_returns_ok() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("dns-gate.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let service = Arc::new(FakeService::ok());
        let calls = Arc::clone(&service.calls);
        let handle = tokio::spawn(serve_gate_listener(listener, service, 5_000));

        let req = sample_request();
        let ack = send_request(&socket, &req).await.expect("ack received");
        assert_eq!(ack.status, GateStatus::Ok);
        assert_eq!(ack.correlation_id, req.correlation_id);
        assert_eq!(ack.kind, GateAckKind::PropagateAck);
        assert_eq!(calls.lock().unwrap().len(), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn listener_returns_rejected_with_reason() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("dns-gate.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let service = Arc::new(FakeService::rejected("nft inject failed"));
        let handle = tokio::spawn(serve_gate_listener(listener, service, 5_000));

        let req = sample_request();
        let ack = send_request(&socket, &req).await.expect("ack received");
        assert_eq!(ack.status, GateStatus::Rejected);
        assert_eq!(ack.reason.as_deref(), Some("nft inject failed"));

        handle.abort();
    }

    #[tokio::test]
    async fn listener_enforces_per_request_deadline() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("dns-gate.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        // Service sleeps 500 ms; request deadline is 50 ms.
        let service = Arc::new(FakeService::slow(Duration::from_millis(500)));
        let handle = tokio::spawn(serve_gate_listener(listener, service, 5_000));

        let mut req = sample_request();
        req.deadline_ms = 50;
        let ack = send_request(&socket, &req).await.expect("ack received");
        assert_eq!(ack.status, GateStatus::Rejected);
        assert!(
            ack.reason
                .as_deref()
                .map(|r| r.contains("deadline"))
                .unwrap_or(false)
        );

        handle.abort();
    }

    #[tokio::test]
    async fn listener_returns_protocol_error_on_unsupported_version() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("dns-gate.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let service = Arc::new(FakeService::ok());
        let handle = tokio::spawn(serve_gate_listener(listener, service, 5_000));

        // Single-line wire encoding: the listener uses `read_line`, so an
        // embedded newline would split the frame and force a malformed-
        // request reply rather than an unsupported-version one.
        let raw = "{\"kind\":\"propagate_and_ack\",\"version\":2,\"correlation_id\":\"abc\",\"domain\":\"x.com\",\"qtype\":\"A\",\"ips\":[\"1.2.3.4\"],\"ttl_seconds\":1,\"deadline_ms\":100}\n"
            .to_string();
        let mut stream = UnixStream::connect(&socket).await.unwrap();
        stream.write_all(raw.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let (read_half, _write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut reply = String::new();
        reader.read_line(&mut reply).await.unwrap();
        let value: serde_json::Value = serde_json::from_str(reply.trim()).unwrap();
        assert_eq!(
            value.get("kind").and_then(|v| v.as_str()),
            Some("propagate_error")
        );
        assert_eq!(
            value.get("code").and_then(|v| v.as_str()),
            Some("unsupported_version")
        );
        assert_eq!(
            value.get("correlation_id").and_then(|v| v.as_str()),
            Some("abc")
        );

        handle.abort();
    }

    #[test]
    fn dns_gate_socket_host_path_lives_under_session_events_host_dir() {
        let sid = SessionId::generate();
        let path = dns_gate_socket_host_path(&sid);
        assert!(path.starts_with(session_events_host_dir(&sid)));
        assert_eq!(path.file_name().unwrap(), DNS_GATE_SOCKET_FILENAME);
    }
}
