//! In-memory `GET /backends` cache scoped to one CLI invocation.
//!
//! The CLI fetches the daemon's capability matrix once per invocation,
//! caches it for the invocation's lifetime, and serves subsequent
//! lookups locally. [`BackendsCache`] is that one place — every
//! `Capabilities` lookup the CLI does (client-side validation, future
//! `inspect -v` capability table) goes through this cache so the daemon
//! sees exactly one `/backends` request per `sandbox` invocation.
//!
//! # Concurrency model
//!
//! The cache is owned by the `Create` handler (and any other future
//! consumers) on the local task; lookups are serialised through `&mut
//! self`. There is no shared-state concurrency, no `RwLock`, no
//! `Arc<…>` — a CLI invocation is single-threaded along the
//! capability-fetching axis even though tokio drives I/O.
//!
//! # Errors
//!
//! Failing the fetch is fatal: a CLI invocation that cannot reach the
//! daemon (or whose daemon is too old to expose `/backends`) cannot
//! validate against capabilities. The caller surfaces the error and
//! exits.

use std::time::Duration;

use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use sandbox_core::backend::{BackendInfo, BackendKind, Capabilities};
use tokio::net::UnixStream;

/// Time budget for the single `/backends` request the cache makes per
/// invocation. The endpoint is a static map render on the daemon side
/// (see `sandboxd::backends_http::list_backends`), so it returns in
/// milliseconds; a 5-second budget is generous head-room without
/// hanging the CLI on a wedged daemon.
const BACKENDS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors a [`BackendsCache`] lookup can return.
#[derive(Debug)]
pub enum BackendsCacheError {
    /// The daemon could not be reached over its Unix socket. Carries
    /// the original error message verbatim so the operator sees the
    /// underlying cause.
    Connect(String),
    /// HTTP transport error (handshake, send, receive).
    Transport(String),
    /// The daemon returned a non-2xx status. Carries the status code
    /// and response body.
    HttpStatus { status: u16, body: String },
    /// The response body did not deserialise as `Vec<BackendInfo>`.
    Decode(String),
    /// The fetch timed out.
    Timeout,
}

impl std::fmt::Display for BackendsCacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(msg) => write!(f, "cannot connect to sandboxd: {msg}"),
            Self::Transport(msg) => write!(f, "/backends transport error: {msg}"),
            Self::HttpStatus { status, body } => {
                write!(f, "/backends returned HTTP {status}: {body}")
            }
            Self::Decode(msg) => write!(f, "/backends decode error: {msg}"),
            Self::Timeout => write!(f, "/backends request timed out"),
        }
    }
}

impl std::error::Error for BackendsCacheError {}

/// In-memory cache of `GET /backends` for the lifetime of one CLI
/// invocation.
///
/// Construct via [`BackendsCache::new`] passing the daemon's Unix
/// socket path. The first call to [`BackendsCache::get`] (or
/// [`BackendsCache::list`]) fires the single `/backends` HTTP request
/// the cache will ever make; subsequent calls return references into
/// the cached `Vec<BackendInfo>`.
///
/// `BackendsCache` is intentionally *not* `Clone`. Sharing a cache
/// between independent code paths would tempt callers into thinking
/// the cache is process-global. "One fetch per invocation" is most
/// naturally enforced by passing a single owned `BackendsCache` down
/// the create-handler call chain.
pub struct BackendsCache {
    socket: String,
    cached: Option<Vec<BackendInfo>>,
}

impl BackendsCache {
    /// Construct a fresh, empty cache pointed at the given daemon Unix
    /// socket path.
    ///
    /// Lazy: no I/O until the first [`get`](Self::get) /
    /// [`list`](Self::list) call.
    pub fn new(socket: impl Into<String>) -> Self {
        Self {
            socket: socket.into(),
            cached: None,
        }
    }

    /// Return the [`Capabilities`] for `kind`, fetching `/backends`
    /// once if not yet cached.
    ///
    /// Returns `Ok(None)` when the daemon does not register the
    /// requested backend (e.g. a CLI that knows about the container
    /// backend talking to a daemon that only registers Lima).
    pub async fn get(
        &mut self,
        kind: BackendKind,
    ) -> Result<Option<&Capabilities>, BackendsCacheError> {
        self.ensure_loaded().await?;
        Ok(self
            .cached
            .as_ref()
            .expect("ensure_loaded populates cached")
            .iter()
            .find(|info| info.kind == kind)
            .map(|info| &info.capabilities))
    }

    /// Return the full backend list as the daemon registered it,
    /// fetching `/backends` once if not yet cached.
    ///
    /// Used by the `--no-cache` rejection path that needs to surface
    /// the daemon-advertised set even when validation alone would not
    /// have triggered a fetch.
    pub async fn list(&mut self) -> Result<&[BackendInfo], BackendsCacheError> {
        self.ensure_loaded().await?;
        Ok(self
            .cached
            .as_ref()
            .expect("ensure_loaded populates cached"))
    }

    /// Idempotently populate `self.cached` via a single GET to
    /// `/backends`. The second invocation is a no-op — subsequent
    /// `get`/`list` calls do not re-request.
    async fn ensure_loaded(&mut self) -> Result<(), BackendsCacheError> {
        if self.cached.is_some() {
            return Ok(());
        }
        let infos = fetch_backends(&self.socket).await?;
        self.cached = Some(infos);
        Ok(())
    }
}

/// Issue one `GET /backends` over a Unix-socket HTTP/1.1 connection
/// and decode the response.
///
/// Mirrors the structure of [`crate::send_request_with_timeout`] in
/// `main.rs` but lives here so the cache module is self-contained
/// (and so the integration test can drive it directly without
/// pulling in the rest of `main.rs`).
async fn fetch_backends(socket: &str) -> Result<Vec<BackendInfo>, BackendsCacheError> {
    tokio::time::timeout(BACKENDS_FETCH_TIMEOUT, async {
        let stream = UnixStream::connect(socket)
            .await
            .map_err(|e| BackendsCacheError::Connect(e.to_string()))?;
        let io = TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| BackendsCacheError::Transport(format!("handshake: {e}")))?;
        tokio::spawn(async move {
            // Connection driver: we don't care about its termination
            // status here — once the response body has been read in
            // full the connection naturally winds down.
            let _ = conn.await;
        });

        let request = Request::builder()
            .method("GET")
            .uri("/backends")
            .header("host", "localhost")
            .body(String::new())
            .map_err(|e| BackendsCacheError::Transport(format!("build: {e}")))?;

        let response = sender
            .send_request(request)
            .await
            .map_err(|e| BackendsCacheError::Transport(format!("send: {e}")))?;

        let status = response.status();
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| BackendsCacheError::Transport(format!("read body: {e}")))?
            .to_bytes();
        let body = String::from_utf8_lossy(&body_bytes).into_owned();

        if !status.is_success() {
            return Err(BackendsCacheError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }

        serde_json::from_str(&body).map_err(|e| BackendsCacheError::Decode(e.to_string()))
    })
    .await
    .unwrap_or(Err(BackendsCacheError::Timeout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_starts_empty() {
        let cache = BackendsCache::new("/nonexistent/socket");
        assert!(
            cache.cached.is_none(),
            "fresh cache must not pre-populate; the first get() drives the single fetch"
        );
    }
}
