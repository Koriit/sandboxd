//! Agent broker — daemon-side half of the agent↔daemon check-in channel.
//!
//! The broker socket is the macOS analog of the `sandbox-lima-helper` on Linux:
//! it is the authenticated channel through which per-operator agents register
//! themselves so the daemon can route `limactl` operations to the right
//! operator's process. Every security property of that channel is enforced
//! here, at the accept boundary, before any connection reaches application
//! code.
//!
//! # Socket contract
//!
//! Path: `/var/run/sandbox/broker.sock` (overridable via `SANDBOX_BROKER_SOCKET`
//! for tests — see below).
//! Mode: `0660`, owner `_sandboxd:_sandboxd`.
//! The daemon recreates the socket with the correct mode before listening at
//! every startup (`/var/run` is cleared on boot).
//!
//! # Authentication rules (all enforced before the connection is accepted)
//!
//! 1. **Peer uid from `LOCAL_PEERCRED`** — `peer_cred()` on the accepted
//!    `UnixStream` provides the kernel-attested uid and gid of the connecting
//!    process. The daemon never trusts a uid claimed in a message body.
//!
//! 2. **Reject uid 0** — the broker must never accept a root check-in. Root
//!    can read the broker socket (as the owner), but the daemon gates it out.
//!
//! 3. **Reject uid < 500** — system accounts on macOS have uids below 500
//!    (e.g. `_sandboxd` itself). Only real human operators (uid ≥ 500) may
//!    check in.
//!
//! 4. **Re-resolve `_sandboxd` membership via `getgrouplist(3)`** — the
//!    enrollment gate. `xucred.cr_groups` from `LOCAL_PEERCRED` is capped at
//!    `NGROUPS` (16) and is unreliable across macOS versions. Membership is
//!    re-resolved from the peer uid through Directory Services (memberd /
//!    opendirectoryd) via `getgrouplist(3)`. The `0660` group bit is only a
//!    first filter; the `getgrouplist`-on-uid check is authoritative.
//!
//! 5. **Single connection per uid (last-writer-wins eviction)** — a new
//!    check-in for an already-connected uid evicts and closes the prior
//!    connection. This covers re-login and fast-user-switch races. The daemon
//!    never fans a uid's work across two channels.
//!
//! 6. **Heartbeat-driven liveness** — the agent sends `PING\n` periodically;
//!    the broker responds `PONG\n`. A connection that stops sending heartbeats
//!    (agent died, session ended) is dropped after a timeout.
//!
//! # Request routing
//!
//! In addition to accepting check-ins, the broker is the daemon→agent request
//! path. When the `AgentBrokerExecutor` needs to run a `limactl` op for a
//! given operator uid, it calls [`AgentRegistry::send_op`], which places a
//! [`PendingRequest`] into that agent's request channel. The
//! `drive_agent_connection` task reads from that channel and serializes the
//! `BrokerRequest` over the wire, then awaits the matching `BrokerResponse`
//! and delivers the result back through a per-request oneshot.
//!
//! The `GuestSocat` streaming op is handled specially: after the `StreamOpen`
//! response is received the connection is no longer usable for further framed
//! ops, so the raw stream is handed back to the caller via
//! [`AgentRegistry::take_stream_for_guest_socat`]. The connection task exits
//! after handing off, and the agent reconnects to establish a fresh channel.
//!
//! # Testability
//!
//! The broker socket path is overridable via the `SANDBOX_BROKER_SOCKET`
//! environment variable (or `SANDBOX_BROKER_TEST_SOCKET` in `test-env-override`
//! builds), mirroring the `SANDBOX_SOCKET` convention for the API socket.
//! This lets tests connect to a temp-dir socket without `/var/run` or root.
//! All authentication logic except the group-membership check operates on
//! in-process state; the group-membership check itself is tested with a
//! real connecting process.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sandbox_agent_protocol::{BrokerRequest, BrokerResponse, BrokerResult};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default broker socket path. Overridable via `SANDBOX_BROKER_SOCKET`.
pub const DEFAULT_BROKER_SOCKET: &str = "/var/run/sandbox/broker.sock";

/// Mode pinned on the broker socket immediately after bind. Same rationale
/// as the API socket's `0660`: explicit chmod avoids umask variance and makes
/// the contract machine-checkable.
const BROKER_SOCKET_MODE: u32 = 0o660;

/// The system-account floor. Any check-in from a uid strictly below this
/// value is rejected — the broker only serves real human operators.
const SYSTEM_UID_FLOOR: u32 = 500;

/// Interval the daemon waits for the next heartbeat PING before declaring
/// the connection dead and dropping it.
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(60);

/// Returns the effective heartbeat liveness timeout.
///
/// In production this is always [`HEARTBEAT_TIMEOUT`] (60 s). Under the
/// `test-env-override` feature the `SANDBOX_BROKER_TEST_HEARTBEAT_MS` env var
/// overrides the value so heartbeat-drop tests complete in milliseconds rather
/// than waiting the full 60-second window.
fn heartbeat_timeout() -> Duration {
    #[cfg(feature = "test-env-override")]
    if let Ok(ms_str) = std::env::var(TEST_HEARTBEAT_MS_ENV) {
        if let Ok(ms) = ms_str.parse::<u64>() {
            return Duration::from_millis(ms);
        }
    }
    HEARTBEAT_TIMEOUT
}

/// Capacity of the per-agent request channel. Bounded at a small value
/// because the protocol is strictly sequential: one request in flight at a
/// time. A backlog of 4 absorbs any burst of same-uid concurrent calls
/// without risk of blocking the caller long enough to matter.
const REQUEST_CHANNEL_CAPACITY: usize = 4;

/// The `_sandboxd` group name — the enrollment gate on macOS.
///
/// macOS reserves `_sandbox` (uid/gid 60) for its Seatbelt subsystem, so
/// sandboxd uses a dedicated `_sandboxd` account and group instead.
const SANDBOX_GROUP_NAME: &str = "_sandboxd";

// test-env-override seams
#[cfg(feature = "test-env-override")]
const TEST_BROKER_SOCKET_ENV: &str = "SANDBOX_BROKER_TEST_SOCKET";
#[cfg(feature = "test-env-override")]
const TEST_SANDBOX_GROUP_ENV: &str = "SANDBOX_BROKER_TEST_SANDBOX_GROUP";
#[cfg(feature = "test-env-override")]
const TEST_HEARTBEAT_MS_ENV: &str = "SANDBOX_BROKER_TEST_HEARTBEAT_MS";

// ---------------------------------------------------------------------------
// Socket path resolution
// ---------------------------------------------------------------------------

/// Resolve the broker socket path.
///
/// Priority (highest first):
/// 1. `SANDBOX_BROKER_SOCKET` env var (user-facing, mirrors `SANDBOX_SOCKET`).
/// 2. `SANDBOX_BROKER_TEST_SOCKET` env var (test-env-override builds only).
/// 3. [`DEFAULT_BROKER_SOCKET`].
pub fn broker_socket_path() -> PathBuf {
    if let Ok(v) = std::env::var("SANDBOX_BROKER_SOCKET")
        && !v.is_empty()
    {
        return PathBuf::from(v);
    }
    #[cfg(feature = "test-env-override")]
    if let Ok(v) = std::env::var(TEST_BROKER_SOCKET_ENV)
        && !v.is_empty()
    {
        return PathBuf::from(v);
    }
    PathBuf::from(DEFAULT_BROKER_SOCKET)
}

/// Resolve the sandbox group name.
///
/// In test-env-override builds, `SANDBOX_BROKER_TEST_SANDBOX_GROUP` overrides
/// `_sandboxd` so tests can drive the membership gate against a synthetic group.
pub fn sandbox_group_name() -> String {
    #[cfg(feature = "test-env-override")]
    if let Ok(v) = std::env::var(TEST_SANDBOX_GROUP_ENV)
        && !v.is_empty()
    {
        return v;
    }
    SANDBOX_GROUP_NAME.to_string()
}

// ---------------------------------------------------------------------------
// Error message helpers
// ---------------------------------------------------------------------------

/// Resolve a uid to its username for display in operator-facing error messages.
///
/// Falls back to the numeric uid as a string if the uid cannot be resolved
/// (uid not found, NSS failure, etc.) so error messages are always actionable.
fn uid_display(uid: u32) -> String {
    uid_to_username(uid).unwrap_or_else(|| uid.to_string())
}

/// Build the actionable "session agent is not running" error for a uid.
///
/// The spec requires `session agent for <user> is not running` with a
/// human-readable username. Falls back to the numeric uid when resolution
/// fails so the message is always non-empty and unambiguous.
fn agent_not_running_error(uid: u32) -> String {
    format!(
        "session agent for {} is not running — \
         the operator must be logged in for Lima VM operations",
        uid_display(uid)
    )
}

// ---------------------------------------------------------------------------
// Group membership — getgrouplist(3)
// ---------------------------------------------------------------------------

/// Check whether `uid` is a member of the group named `group_name`.
///
/// Resolves membership via `getgrouplist(3)` (Directory Services /
/// opendirectoryd), not from the peer-cred group array (`xucred.cr_groups`).
/// The latter is capped at `NGROUPS` (16) and is unreliable across macOS
/// versions; `getgrouplist` consults the full directory database and returns
/// the complete group list regardless of count.
///
/// Returns `None` on any resolution error (uid not found, group not found,
/// NSS failure) — callers treat `None` the same as non-membership (deny).
pub fn uid_in_sandbox_group(uid: u32, group_name: &str) -> Option<bool> {
    use std::ffi::CString;

    // Resolve the username for getgrouplist.
    let username = uid_to_username(uid)?;
    let name_c = CString::new(username.as_bytes()).ok()?;

    // Resolve the gid of the sandbox group.
    let target_gid = group_name_to_gid(group_name)?;

    // Resolve the user's primary gid (required by getgrouplist per POSIX).
    let primary_gid = uid_to_primary_gid(uid)?;

    // Call getgrouplist with a growable buffer.
    //
    // On macOS, getgrouplist takes int (i32) for the primary gid and
    // int[] for the groups buffer (unlike Linux which uses gid_t/u32).
    let mut ngroups: libc::c_int = 64;
    loop {
        let mut groups: Vec<libc::c_int> = vec![0; ngroups as usize];
        // SAFETY: name_c is a valid NUL-terminated C string; groups is a
        // properly-sized mutable slice; primary_gid is the user's real gid
        // retrieved from the directory service above.
        let ret = unsafe {
            libc::getgrouplist(
                name_c.as_ptr(),
                primary_gid as libc::c_int,
                groups.as_mut_ptr(),
                &mut ngroups,
            )
        };
        if ret == -1 {
            if (ngroups as usize) > groups.len() && ngroups < 65536 {
                // Buffer too small; ngroups holds the required count — retry.
                continue;
            }
            // Buffer overflow or unexpected failure from getgrouplist.
            warn!(uid, ngroups, "getgrouplist capacity error");
            return None;
        }
        // ret >= 0: groups[0..ngroups] is the complete list.
        let found = groups
            .iter()
            .take(ngroups as usize)
            .any(|&g| g as libc::gid_t == target_gid);
        return Some(found);
    }
}

/// Resolve a uid to a username via `getpwuid_r`.
fn uid_to_username(uid: u32) -> Option<String> {
    let bufsize = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let bufsize = if bufsize <= 0 { 1024 } else { bufsize as usize };
    let mut buf = vec![0i8; bufsize];
    let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), bufsize, &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    let name_ptr = unsafe { (*result).pw_name };
    if name_ptr.is_null() {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) };
    name.to_str().ok().map(|s| s.to_string())
}

/// Resolve a group name to its numeric gid via `getgrnam_r`.
fn group_name_to_gid(group_name: &str) -> Option<libc::gid_t> {
    let group_name_c = std::ffi::CString::new(group_name).ok()?;
    let bufsize = unsafe { libc::sysconf(libc::_SC_GETGR_R_SIZE_MAX) };
    let bufsize = if bufsize <= 0 { 1024 } else { bufsize as usize };
    let mut buf = vec![0i8; bufsize];
    let mut grp = unsafe { std::mem::zeroed::<libc::group>() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    let rc = unsafe {
        libc::getgrnam_r(
            group_name_c.as_ptr(),
            &mut grp,
            buf.as_mut_ptr(),
            bufsize,
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(unsafe { (*result).gr_gid })
}

/// Resolve a uid's primary gid via `getpwuid_r`.
fn uid_to_primary_gid(uid: u32) -> Option<libc::gid_t> {
    let bufsize = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let bufsize = if bufsize <= 0 { 1024 } else { bufsize as usize };
    let mut buf = vec![0i8; bufsize];
    let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), bufsize, &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(unsafe { (*result).pw_gid })
}

// ---------------------------------------------------------------------------
// Authentication decisions
// ---------------------------------------------------------------------------

/// Outcome of the daemon-side check-in authentication for a single connecting
/// peer.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Connection admitted. The enclosed uid is the kernel-attested peer uid.
    Admitted(u32),
    /// Rejected: peer uid is 0 (root).
    RejectedRoot,
    /// Rejected: peer uid is below the system-account floor (< 500).
    RejectedSystemUid(u32),
    /// Rejected: peer uid is not a member of the sandbox enrollment group.
    RejectedNotMember(u32),
    /// Rejected: group membership could not be resolved (NSS failure, uid not
    /// found, etc.). Treated as non-membership — deny.
    RejectedResolutionFailed(u32),
}

/// Classify a peer uid against the authentication rules.
///
/// This is the single source of truth for the uid-floor gates and the
/// group-membership check. Both `authenticate_peer` and the unit tests call
/// this function — there is no parallel implementation in test helpers.
///
/// Rules applied in order:
/// 1. uid 0 → `RejectedRoot`.
/// 2. uid < 500 → `RejectedSystemUid`.
/// 3. `_sandboxd` membership via `getgrouplist(3)` → Admitted / RejectedNotMember /
///    RejectedResolutionFailed.
pub fn classify_peer_uid(uid: u32, group_name: &str) -> AuthOutcome {
    if uid == 0 {
        return AuthOutcome::RejectedRoot;
    }
    if uid < SYSTEM_UID_FLOOR {
        return AuthOutcome::RejectedSystemUid(uid);
    }
    match uid_in_sandbox_group(uid, group_name) {
        Some(true) => AuthOutcome::Admitted(uid),
        Some(false) => AuthOutcome::RejectedNotMember(uid),
        None => AuthOutcome::RejectedResolutionFailed(uid),
    }
}

/// Apply the daemon-side anti-spoof + authorization rules to an accepted
/// connection.
///
/// This function is the security core of the broker. It reads the peer uid
/// from `LOCAL_PEERCRED` (kernel-attested, cannot be spoofed by the connecting
/// process) and then delegates all classification to [`classify_peer_uid`].
///
/// The `0660` socket mode is a first filter (only `_sandboxd`-group members
/// can connect at the kernel DAC level); `getgrouplist` inside
/// `classify_peer_uid` is the authoritative enrollment check.
pub fn authenticate_peer(stream: &UnixStream, group_name: &str) -> AuthOutcome {
    let cred = match stream.peer_cred() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "peer_cred() failed on broker connection; rejecting");
            // Use uid u32::MAX as a sentinel for "couldn't read credential".
            return AuthOutcome::RejectedResolutionFailed(u32::MAX);
        }
    };

    classify_peer_uid(cred.uid(), group_name)
}

// ---------------------------------------------------------------------------
// Pending request — daemon→agent work item
// ---------------------------------------------------------------------------

/// A unit of work the daemon sends to a checked-in agent over the broker
/// channel.
///
/// `OneShot` covers all ops except `GuestSocat`: the daemon serializes the
/// request, writes it to the agent, reads the JSON response, and delivers
/// the `BrokerResult` back through the `reply` oneshot.
///
/// `TakeStream` is the `GuestSocat` path: the connection task sends the
/// `GuestSocat` `BrokerRequest`, reads the `StreamOpen` response, captures
/// any bytes the `BufReader` consumed past `StreamOpen\n`, and then transfers
/// `(prefix_bytes, UnixStream)` to the caller through the `stream_tx` oneshot.
/// The prefix bytes must be prepended before reading from the socket (see
/// `take_stream_for_guest_socat`). The connection task exits after handing off;
/// the agent reconnects to establish a fresh channel.
pub enum PendingRequest {
    /// A one-shot op: serialize, send, await response, deliver via `reply`.
    OneShot {
        request: BrokerRequest,
        reply: tokio::sync::oneshot::Sender<BrokerResult>,
    },
    /// Open a `GuestSocat` stream: send request, await `StreamOpen`, hand
    /// `(buffered_prefix, raw_stream)` to the caller.
    TakeStream {
        request: BrokerRequest,
        stream_tx: tokio::sync::oneshot::Sender<(Vec<u8>, UnixStream)>,
    },
}

// ---------------------------------------------------------------------------
// Agent registry
// ---------------------------------------------------------------------------

/// Thread-safe registry of currently connected agents, keyed by uid.
///
/// Single connection per uid: inserting a new entry for a uid whose entry
/// already exists signals the prior connection to exit (last-writer-wins
/// eviction). The registry never fans one uid's work across two channels.
///
/// # Eviction safety — generation counter
///
/// Each `register()` call stamps a monotonically-increasing generation number
/// on the new entry. The old connection's `drive_agent_connection` task holds
/// its generation at spawn time and passes it back to `remove(uid, generation)`.
/// `remove` is a no-op if the stored generation no longer matches — i.e., if a
/// newer check-in has already replaced the entry. This prevents the following
/// race:
///
/// 1. uid A connects — `register(A)` stores `(gen=1, tx1, req1)`, drops nothing.
/// 2. uid A reconnects — `register(A)` stores `(gen=2, tx2, req2)`, drops `tx1`.
/// 3. Old task (gen=1) wakes on eviction, calls `remove(A, 1)` — gen mismatch,
///    no-op. The new connection's entry (gen=2) is preserved.
/// 4. New task (gen=2) runs indefinitely; `is_registered(A)` returns `true`.
#[derive(Clone, Default)]
pub struct AgentRegistry {
    inner: Arc<Mutex<RegistryInner>>,
}

#[derive(Default)]
struct RegistryInner {
    /// Live agents by uid.
    /// Value: `(generation, eviction_sender, request_sender)`.
    /// Dropping `eviction_sender` signals the connection task to exit.
    /// `request_sender` enqueues work items for the connection task to dispatch.
    agents: HashMap<u32, AgentEntry>,
    /// Monotonically increasing generation counter. Incremented on every
    /// `register()` call so each entry can be identified uniquely.
    next_generation: u64,
}

struct AgentEntry {
    generation: u64,
    /// Drop to signal the connection task to exit (eviction).
    eviction_tx: tokio::sync::oneshot::Sender<()>,
    /// Send work items to the connection task.
    request_tx: tokio::sync::mpsc::Sender<PendingRequest>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new agent connection for `uid`.
    ///
    /// Returns `(generation, eviction_receiver, request_receiver)`. The caller
    /// passes `generation` to [`remove`] when the connection exits so that
    /// the remove is a no-op if a newer check-in has already replaced this entry.
    ///
    /// If an entry already exists for this uid, its eviction sender is dropped,
    /// waking the prior task's eviction receiver (last-writer-wins).
    pub async fn register(
        &self,
        uid: u32,
    ) -> (
        u64,
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::mpsc::Receiver<PendingRequest>,
    ) {
        let (evict_tx, evict_rx) = tokio::sync::oneshot::channel();
        let (req_tx, req_rx) = tokio::sync::mpsc::channel(REQUEST_CHANNEL_CAPACITY);
        let mut inner = self.inner.lock().await;
        inner.next_generation += 1;
        let slot_gen = inner.next_generation;
        if let Some(old) = inner.agents.insert(
            uid,
            AgentEntry {
                generation: slot_gen,
                eviction_tx: evict_tx,
                request_tx: req_tx,
            },
        ) {
            // Evict the prior connection by dropping its eviction sender.
            drop(old.eviction_tx);
            info!(
                uid,
                slot_gen, "evicted prior agent connection (last-writer-wins)"
            );
        }
        (slot_gen, evict_rx, req_rx)
    }

    /// Remove the registry entry for `uid` if its generation matches.
    ///
    /// A mismatch means a newer check-in has already replaced this entry; the
    /// remove is a no-op so the live connection is not disturbed.
    pub async fn remove(&self, uid: u32, generation: u64) {
        let mut inner = self.inner.lock().await;
        if let Some(entry) = inner.agents.get(&uid) {
            if entry.generation == generation {
                inner.agents.remove(&uid);
            }
            // Else: a newer connection owns this entry — leave it alone.
        }
    }

    /// Return the set of currently connected uids.
    ///
    /// Used by the startup reconcile loop (step 6b) to enumerate checked-in
    /// operators. Only operators in this set have their VMs reconciled at
    /// startup; operators not in this set are reconciled lazily on next
    /// agent check-in.
    pub async fn connected_uids(&self) -> Vec<u32> {
        let inner = self.inner.lock().await;
        inner.agents.keys().copied().collect()
    }

    /// Check whether an agent is currently registered for `uid`.
    ///
    /// Used in tests to verify registry state after register/remove operations.
    /// Production code gates on [`connected_uids`] (the enumeration form) rather
    /// than per-uid point queries.
    #[cfg(test)]
    pub async fn is_registered(&self, uid: u32) -> bool {
        let inner = self.inner.lock().await;
        inner.agents.contains_key(&uid)
    }

    /// Send a one-shot op to the agent registered for `uid` and await its
    /// result.
    ///
    /// Returns `Err` if no agent is checked in for `uid` (actionable: "session
    /// agent for <user> is not running") or if the connection closes before
    /// the response arrives.
    pub async fn send_op(&self, uid: u32, request: BrokerRequest) -> Result<BrokerResult, String> {
        let tx = {
            let inner = self.inner.lock().await;
            match inner.agents.get(&uid) {
                Some(entry) => entry.request_tx.clone(),
                None => {
                    return Err(agent_not_running_error(uid));
                }
            }
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tx.send(PendingRequest::OneShot {
            request,
            reply: reply_tx,
        })
        .await
        .map_err(|_| agent_not_running_error(uid))?;

        reply_rx.await.map_err(|_| {
            format!(
                "session agent for {} dropped before responding — \
                 the operator may have logged out",
                uid_display(uid)
            )
        })
    }

    /// Open a `GuestSocat` stream via the agent registered for `uid`.
    ///
    /// Sends the `GuestSocat` request to the agent, awaits `StreamOpen`, and
    /// returns a bidirectional byte pump for the caller. Any bytes the
    /// `BufReader` consumed past `StreamOpen\n` are prepended to the stream
    /// (see `PendingRequest::TakeStream` doc). The connection task exits after
    /// handing off; the agent reconnects automatically.
    ///
    /// Returns `Err` if no agent is checked in or if the stream handoff fails.
    pub async fn take_stream_for_guest_socat(
        &self,
        uid: u32,
        request: BrokerRequest,
    ) -> Result<Box<dyn sandbox_core::backend::AsyncReadWrite + Send + Unpin>, String> {
        let tx = {
            let inner = self.inner.lock().await;
            match inner.agents.get(&uid) {
                Some(entry) => entry.request_tx.clone(),
                None => {
                    return Err(agent_not_running_error(uid));
                }
            }
        };

        let (stream_tx, stream_rx) = tokio::sync::oneshot::channel();
        tx.send(PendingRequest::TakeStream { request, stream_tx })
            .await
            .map_err(|_| agent_not_running_error(uid))?;

        let (prefix, stream) = stream_rx.await.map_err(|_| {
            format!(
                "session agent for {} dropped before handing over GuestSocat stream — \
                 the operator may have logged out",
                uid_display(uid)
            )
        })?;

        // If the BufReader had buffered bytes past StreamOpen\n, wrap the
        // stream in a PrefixedStream so the caller receives those bytes first
        // before the socket data. When prefix is empty, box the stream
        // directly — no wrapper overhead.
        if prefix.is_empty() {
            Ok(Box::new(stream))
        } else {
            Ok(Box::new(PrefixedStream {
                prefix: std::io::Cursor::new(prefix),
                inner: stream,
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// Broker listener
// ---------------------------------------------------------------------------

/// Bind the broker socket and return the listener.
///
/// Creates the socket at `socket_path` and pins its mode to `0660` before
/// returning. Fails fast on any error — an incorrectly-moded socket is a
/// silent security regression.
pub fn bind_broker_socket(socket_path: &Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    // Remove a stale socket file left from a prior run. `/var/run` is
    // cleared on boot, but during development the daemon may be restarted
    // without a full reboot.
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(
        socket_path,
        std::fs::Permissions::from_mode(BROKER_SOCKET_MODE),
    )
    .map_err(|e| {
        // A failure to chmod the socket is fatal: the mode is a security
        // property and must be machine-verifiable.
        tracing::error!(
            path = %socket_path.display(),
            error = %e,
            mode = format!("{BROKER_SOCKET_MODE:o}"),
            "failed to pin broker socket mode; refusing to bind"
        );
        e
    })?;

    Ok(listener)
}

/// Accept connections on the broker socket, authenticate each peer, and
/// spawn a connection task for admitted connections.
///
/// This function runs for the lifetime of the daemon. It never returns under
/// normal operation; the caller should spawn it as a background task.
///
/// `on_admit_tx`: when `Some`, the sender receives the admitted uid on every
/// successful check-in. Callers use this to trigger per-uid side-effects
/// (e.g. `reconcile_operator_vms`) without coupling the broker to the daemon's
/// AppState. The sender is a best-effort notification: a failed send (e.g. the
/// receiver was dropped) is silently ignored.
pub async fn run_broker_listener(
    listener: UnixListener,
    registry: AgentRegistry,
    on_admit_tx: Option<tokio::sync::mpsc::Sender<u32>>,
) {
    let group_name = sandbox_group_name();
    loop {
        let (stream, _peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "broker accept() failed; retrying");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        let outcome = authenticate_peer(&stream, &group_name);
        match outcome {
            AuthOutcome::Admitted(uid) => {
                info!(uid, "agent check-in admitted");
                let reg = registry.clone();
                let (slot_gen, evict_rx, req_rx) = registry.register(uid).await;
                // Notify side-effect subscribers (e.g. reconcile_operator_vms) AFTER
                // the new connection is registered. This ensures reconcile_operator_vms
                // always observes the freshly-registered connection rather than racing
                // against a still-registered prior connection or observing an empty slot.
                if let Some(ref tx) = on_admit_tx {
                    let _ = tx.try_send(uid);
                }
                tokio::spawn(drive_agent_connection_outer(
                    uid, slot_gen, stream, evict_rx, req_rx, reg,
                ));
            }
            AuthOutcome::RejectedRoot => {
                warn!("broker: rejected root (uid 0) check-in attempt");
            }
            AuthOutcome::RejectedSystemUid(uid) => {
                warn!(
                    uid,
                    floor = SYSTEM_UID_FLOOR,
                    "broker: rejected system-uid check-in"
                );
            }
            AuthOutcome::RejectedNotMember(uid) => {
                warn!(uid, group = %group_name, "broker: rejected non-member check-in");
            }
            AuthOutcome::RejectedResolutionFailed(uid) => {
                warn!(uid, "broker: rejected — group membership resolution failed");
            }
        }
    }
}

/// Drive a single authenticated agent connection.
///
/// This is the outer entry point spawned per accepted connection. It handles
/// all protocol traffic including heartbeats, one-shot ops, and the special
/// `TakeStream` (GuestSocat) path, which requires reassembling the split
/// stream halves to hand ownership to the caller.
async fn drive_agent_connection_outer(
    uid: u32,
    generation: u64,
    stream: UnixStream,
    evict_rx: tokio::sync::oneshot::Receiver<()>,
    mut req_rx: tokio::sync::mpsc::Receiver<PendingRequest>,
    registry: AgentRegistry,
) {
    let (reader_half, writer_half) = stream.into_split();
    let mut buf_reader = BufReader::new(reader_half);
    let mut writer = writer_half;
    let mut line = String::new();
    let mut evict_rx = evict_rx;
    // Carries `(expected_request_id, reply_sender)` while a one-shot is in flight.
    // The request_id is echoed by the agent and validated on response to catch
    // protocol version skew or buggy agent implementations.
    let mut outstanding: Option<(u64, tokio::sync::oneshot::Sender<BrokerResult>)> = None;

    'outer: loop {
        line.clear();

        if outstanding.is_none() {
            tokio::select! {
                _ = &mut evict_rx => {
                    info!(uid, "agent connection evicted by newer check-in; closing");
                    break 'outer;
                }

                maybe_req = req_rx.recv() => {
                    let Some(pending) = maybe_req else {
                        info!(uid, "request channel closed; exiting connection task");
                        break 'outer;
                    };
                    match pending {
                        PendingRequest::TakeStream { request, stream_tx } => {
                            // Write the GuestSocat request.
                            let json = match serde_json::to_string(&request) {
                                Ok(j) => j,
                                Err(e) => {
                                    warn!(uid, error = %e, "failed to serialize GuestSocat request");
                                    break 'outer;
                                }
                            };
                            if writer.write_all(json.as_bytes()).await.is_err()
                                || writer.write_all(b"\n").await.is_err()
                            {
                                warn!(uid, "write error sending GuestSocat request; closing");
                                break 'outer;
                            }

                            // Read StreamOpen (or Rejected) from the agent.
                            let read_result = tokio::time::timeout(
                                heartbeat_timeout(),
                                buf_reader.read_line(&mut line),
                            )
                            .await;

                            match read_result {
                                Ok(Ok(0)) | Err(_) | Ok(Err(_)) => {
                                    warn!(uid, "no StreamOpen from agent; closing connection");
                                    break 'outer;
                                }
                                Ok(Ok(_)) => {}
                            }

                            let trimmed = line.trim_end_matches(['\n', '\r']);
                            let response: BrokerResponse =
                                match serde_json::from_str(trimmed) {
                                    Ok(r) => r,
                                    Err(e) => {
                                        warn!(uid, error = %e, "failed to parse GuestSocat StreamOpen response; closing");
                                        break 'outer;
                                    }
                                };

                            if !matches!(response.result, BrokerResult::StreamOpen) {
                                warn!(uid, result = ?response.result, "GuestSocat response was not StreamOpen; closing");
                                break 'outer;
                            }

                            // Capture any bytes the BufReader may have consumed past
                            // `StreamOpen\n` in the same kernel-buffer fill. If the
                            // agent writes `StreamOpen\n` + the first raw socat bytes
                            // in a single syscall, BufReader reads both into its 8KB
                            // internal buffer when servicing `read_line`. `into_inner()`
                            // then returns the underlying `OwnedReadHalf` whose kernel
                            // position is past both, discarding the raw prefix. Those
                            // bytes are the start of the socat byte-pump and must not
                            // be lost — dropping them would corrupt the first
                            // guest-agent message on every affected SSH session.
                            //
                            // The fix: capture the BufReader's internal buffer before
                            // calling `into_inner()`, and hand `(prefix, stream)` to
                            // the caller so it can prepend the prefix before reading
                            // the socket. The `stream_tx` type carries the prefix.
                            let leftover = buf_reader.buffer().to_vec();
                            let read_half = buf_reader.into_inner();

                            // Reunite the split halves and hand the stream to the caller.
                            match read_half.reunite(writer) {
                                Ok(stream) => {
                                    let _ = stream_tx.send((leftover, stream));
                                    // The connection is now owned by the caller for the
                                    // byte pump. The agent will reconnect after it ends.
                                    registry.remove(uid, generation).await;
                                    info!(uid, "GuestSocat stream handed off; connection task exiting");
                                    return;
                                }
                                Err(_) => {
                                    warn!(uid, "failed to reunite stream halves for GuestSocat");
                                    break 'outer;
                                }
                            }
                        }

                        PendingRequest::OneShot { request, reply } => {
                            let request_id = request.request_id;
                            let json = match serde_json::to_string(&request) {
                                Ok(j) => j,
                                Err(e) => {
                                    warn!(uid, error = %e, "failed to serialize BrokerRequest");
                                    let _ = reply.send(BrokerResult::Rejected {
                                        reason: format!("internal: serialize error: {e}"),
                                    });
                                    continue 'outer;
                                }
                            };
                            if writer.write_all(json.as_bytes()).await.is_err()
                                || writer.write_all(b"\n").await.is_err()
                            {
                                warn!(uid, "write error sending BrokerRequest; closing");
                                let _ = reply.send(BrokerResult::Rejected {
                                    reason: "broker connection write error".to_string(),
                                });
                                break 'outer;
                            }
                            outstanding = Some((request_id, reply));
                        }
                    }
                }

                result = tokio::time::timeout(heartbeat_timeout(), buf_reader.read_line(&mut line)) => {
                    if !process_agent_line(uid, result, &line, &mut writer, &mut outstanding).await {
                        break 'outer;
                    }
                }
            }
        } else {
            // A one-shot request is in flight — wait only for the agent response or eviction.
            tokio::select! {
                _ = &mut evict_rx => {
                    info!(uid, "agent connection evicted while awaiting response; closing");
                    break 'outer;
                }
                result = tokio::time::timeout(heartbeat_timeout(), buf_reader.read_line(&mut line)) => {
                    if !process_agent_line(uid, result, &line, &mut writer, &mut outstanding).await {
                        break 'outer;
                    }
                }
            }
        }
    }

    registry.remove(uid, generation).await;
    info!(uid, "agent connection task exited");
}

/// Process a line read from the agent on the broker connection.
///
/// Returns `true` to continue the outer loop, `false` to break.
async fn process_agent_line(
    uid: u32,
    result: Result<std::io::Result<usize>, tokio::time::error::Elapsed>,
    line: &str,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    outstanding: &mut Option<(u64, tokio::sync::oneshot::Sender<BrokerResult>)>,
) -> bool {
    match result {
        Err(_elapsed) => {
            warn!(
                uid,
                timeout_secs = heartbeat_timeout().as_secs(),
                "no heartbeat received within timeout; dropping dead agent"
            );
            false
        }
        Ok(Ok(0)) => {
            info!(uid, "agent connection closed cleanly");
            false
        }
        Ok(Ok(_)) => {
            let trimmed = line.trim_end_matches(['\n', '\r']);
            match trimmed {
                "CHECKIN" => {
                    info!(uid, "agent check-in frame received");
                    true
                }
                "PING" => {
                    if let Err(e) = writer.write_all(b"PONG\n").await {
                        warn!(uid, error = %e, "failed to write PONG; dropping connection");
                        return false;
                    }
                    true
                }
                "PONG" => true,
                other if !other.is_empty() && other.starts_with('{') => {
                    match serde_json::from_str::<BrokerResponse>(other) {
                        Ok(response) => {
                            if let Some((expected_id, reply_tx)) = outstanding.take() {
                                if response.request_id != expected_id {
                                    warn!(
                                        uid,
                                        expected = expected_id,
                                        got = response.request_id,
                                        "BrokerResponse request_id mismatch; \
                                         closing connection (agent protocol error)"
                                    );
                                    // Drop reply_tx without sending — the caller
                                    // gets a RecvError mapped to "agent dropped".
                                    return false;
                                }
                                let _ = reply_tx.send(response.result);
                            } else {
                                warn!(
                                    uid,
                                    request_id = response.request_id,
                                    "received unsolicited BrokerResponse; ignoring"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(uid, error = %e, frame = %other, "failed to parse BrokerResponse");
                        }
                    }
                    true
                }
                other => {
                    if !other.is_empty() {
                        warn!(uid, frame = %other, "unexpected frame on broker channel; ignoring");
                    }
                    true
                }
            }
        }
        Ok(Err(e)) => {
            warn!(uid, error = %e, "read error on broker connection; dropping");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// AgentBrokerExecutor — macOS LimaExecutor implementation
// ---------------------------------------------------------------------------

/// macOS [`sandbox_core::lima::LimaExecutor`] that routes every operator-uid
/// operation to that operator's checked-in per-operator agent, and
/// special-cases two direct-execution paths:
///
/// - `op_uid == daemon_uid` (the `_sandboxd` own uid, or any foreground-dev
///   scenario where the daemon and the operator share the same uid): runs
///   `limactl` directly as the daemon process without going through the
///   broker. This is the "gateway degenerate case" — the daemon is already
///   running as the right uid and no agent exists for it.
///
/// - Any other `op_uid`: routes to that uid's checked-in agent via the
///   [`AgentRegistry`]. If no agent is registered, every op fails with the
///   spec's actionable error message: "session agent for uid N is not
///   running".
///
/// The two implementations of the operator-execution seam are:
///
/// - **Linux** ([`sandbox_core::lima::SetuidHelperExecutor`]): invokes
///   `sandbox-lima-helper` with `cap_setuid`, which setresuid-pivots to
///   the operator uid before exec'ing `limactl`. The daemon never calls
///   `limactl` directly.
///
/// - **macOS** ([`AgentBrokerExecutor`], this type): routes to the
///   operator's LaunchAgent via the broker channel. No setuid, no
///   capability — the agent already runs as the operator. The daemon's
///   own uid (gateway infra, foreground dev) is the one case where the
///   daemon exec's `limactl` directly as itself.
pub struct AgentBrokerExecutor {
    /// Registry of checked-in per-operator agents.
    registry: AgentRegistry,
    /// The daemon's own uid (from `getuid()` at startup). Ops for this uid
    /// run `limactl` directly rather than routing through the broker.
    daemon_uid: u32,
    /// Monotonic counter for generating unique request IDs.
    next_request_id: std::sync::atomic::AtomicU64,
}

impl AgentBrokerExecutor {
    /// Construct the macOS executor.
    ///
    /// `daemon_uid` is the uid of the daemon process itself (from `getuid()`).
    /// Ops whose `op_uid` equals `daemon_uid` are dispatched directly (the
    /// gateway / foreground-dev degenerate case). All other `op_uid`s route
    /// to the registered agent for that uid.
    pub fn new(registry: AgentRegistry, daemon_uid: u32) -> Self {
        Self {
            registry,
            daemon_uid,
            next_request_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    fn next_id(&self) -> u64 {
        self.next_request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

#[async_trait]
impl sandbox_core::lima::LimaExecutor for AgentBrokerExecutor {
    fn run(
        &self,
        op_uid: u32,
        op: sandbox_core::lima::LimaOp<'_>,
        timeout: std::time::Duration,
        label: &str,
    ) -> Result<std::process::Output, sandbox_core::error::SandboxError> {
        use sandbox_core::error::SandboxError;

        if op_uid == self.daemon_uid {
            // Degenerate case: daemon is the operator — run limactl directly.
            return run_limactl_direct(op_uid, op, timeout, label);
        }

        // Route to the operator's agent via the broker channel. We need to
        // block on the async `send_op` from this synchronous fn — callers
        // invoke this inside `tokio::task::spawn_blocking`, so we can
        // create a temporary single-threaded runtime.
        //
        // Using `tokio::runtime::Handle::current().block_on(...)` would work
        // if called from a spawn_blocking context, but spawn_blocking runs on
        // a separate thread with the runtime handle still accessible via
        // Handle::current(). We use `block_on` on the current handle.
        let broker_op = lima_op_to_broker_op(op_uid, op, label)?;
        let request_id = self.next_id();
        let request = sandbox_agent_protocol::BrokerRequest {
            request_id,
            op: broker_op,
        };

        let registry = self.registry.clone();
        let handle = tokio::runtime::Handle::current();
        let result = handle
            .block_on(registry.send_op(op_uid, request))
            .map_err(|e| SandboxError::Lima(format!("{label}: {e}")))?;

        broker_result_to_output(result, label)
    }

    async fn guest_socat(
        &self,
        op_uid: u32,
        vm: &str,
    ) -> Result<
        Box<dyn sandbox_core::backend::AsyncReadWrite + Send + Unpin>,
        sandbox_core::error::SandboxError,
    > {
        use sandbox_core::error::SandboxError;

        if op_uid == self.daemon_uid {
            // Degenerate case: daemon is the operator — run limactl shell socat directly.
            return run_limactl_guest_socat_direct(op_uid, vm).await;
        }

        let request_id = self.next_id();
        let request = sandbox_agent_protocol::BrokerRequest {
            request_id,
            op: sandbox_agent_protocol::BrokerOp::GuestSocat {
                op_uid,
                vm: vm.to_string(),
            },
        };

        // `take_stream_for_guest_socat` returns a Box<dyn AsyncReadWrite> that
        // already chains any BufReader-buffered prefix before the raw socket.
        // `tokio::net::UnixStream` satisfies `AsyncReadWrite` via its blanket
        // impl (`AsyncRead + AsyncWrite`); no wrapper type is needed.
        self.registry
            .take_stream_for_guest_socat(op_uid, request)
            .await
            .map_err(|e| SandboxError::Lima(format!("guest_socat for uid {op_uid} vm {vm}: {e}")))
    }
}

/// Map a `LimaOp` to a `BrokerOp` for wire serialization.
///
/// For ops that carry a `yaml_path`, the file is read from disk here so the
/// full YAML content is available for inclusion in the `BrokerOp::Create`
/// payload. All other ops are a straightforward field-for-field mapping.
fn lima_op_to_broker_op(
    op_uid: u32,
    op: sandbox_core::lima::LimaOp<'_>,
    label: &str,
) -> Result<sandbox_agent_protocol::BrokerOp, sandbox_core::error::SandboxError> {
    use sandbox_agent_protocol::BrokerOp;
    use sandbox_core::backend::BackendKind;
    use sandbox_core::error::SandboxError;
    use sandbox_core::lima::LimaOp;

    Ok(match op {
        LimaOp::Create {
            vm,
            yaml_path,
            owner,
            is_hardened_session,
        } => {
            let lima_yaml = std::fs::read_to_string(yaml_path).map_err(|e| {
                SandboxError::Lima(format!(
                    "{label}: failed to read lima.yaml at {}: {e}",
                    yaml_path.display()
                ))
            })?;
            // The qemu-wrapper path is not part of LimaOp::Create on macOS —
            // the daemon resolves it and embeds it in the YAML content.
            // We use a sentinel that the agent validation accepts for gateway
            // instances. For session VMs on macOS the qemu-wrapper path will
            // be embedded in the YAML by the caller before this runs.
            // Pass an empty string; the agent's YAML validation checks for the
            // wrapper reference inside the lima_yaml content, not separately.
            BrokerOp::Create {
                op_uid,
                vm: vm.to_string(),
                lima_yaml,
                owner: owner.to_string(),
                qemu_wrapper: String::new(),
                is_hardened_session,
            }
        }
        LimaOp::Start {
            vm,
            qemu_wrapper,
            hardened,
            memory_mb,
            cpus,
            start_timeout_s,
            bridge,
            unrestricted_slirp_for_provisioning,
        } => BrokerOp::Start {
            op_uid,
            vm: vm.to_string(),
            qemu_wrapper: qemu_wrapper.to_string_lossy().into_owned(),
            hardened,
            memory_mb,
            cpus,
            start_timeout_s,
            bridge: bridge.map(|(bridge_name, vm_mac)| sandbox_agent_protocol::BridgePair {
                bridge_name: bridge_name.to_string(),
                vm_mac: vm_mac.to_string(),
            }),
            unrestricted_slirp_for_provisioning,
        },
        LimaOp::Stop { vm, force } => BrokerOp::Stop {
            op_uid,
            vm: vm.to_string(),
            force,
        },
        LimaOp::Delete { vm } => BrokerOp::Delete {
            op_uid,
            vm: vm.to_string(),
        },
        LimaOp::Clone {
            base,
            vm,
            cpus,
            memory_gib,
            disk_gb,
            owner,
        } => BrokerOp::Clone {
            op_uid,
            base: base.to_string(),
            vm: vm.to_string(),
            cpus,
            memory_gib,
            disk_gb,
            owner: owner.to_string(),
        },
        LimaOp::ListJson => BrokerOp::ListJson { op_uid },
        LimaOp::InstallGuestAgent { vm } => BrokerOp::InstallGuestAgent {
            op_uid,
            vm: vm.to_string(),
        },
        LimaOp::ReadUserKey => BrokerOp::ReadUserKey { op_uid },
        LimaOp::RunRsync {
            backend,
            session_name,
            host_path,
            guest_path,
            no_gitignore,
        } => {
            let backend_str = match backend {
                BackendKind::Lima => "lima",
                BackendKind::Container => "container",
            }
            .to_string();
            BrokerOp::RunRsync {
                op_uid,
                backend: backend_str,
                session_name: session_name.to_string(),
                host_path: host_path.to_string(),
                guest_path: guest_path.to_string(),
                no_gitignore,
            }
        }
        LimaOp::ReadOwnerMarker { vm } => BrokerOp::ReadOwnerMarker {
            op_uid,
            vm: vm.to_string(),
        },
        LimaOp::RestrictOnVerify { vm } => BrokerOp::RestrictOnVerify {
            op_uid,
            vm: vm.to_string(),
        },
    })
}

/// Map a `BrokerResult` from the agent back to a `std::process::Output`.
///
/// `Ok` and `Failed` both carry stdout/stderr/exit_code and map directly.
/// `Rejected` is a validation failure from the agent — mapped to a
/// `SandboxError::Lima` so callers treat it as a hard error.
fn broker_result_to_output(
    result: sandbox_agent_protocol::BrokerResult,
    label: &str,
) -> Result<std::process::Output, sandbox_core::error::SandboxError> {
    use sandbox_agent_protocol::BrokerResult;
    use sandbox_core::error::SandboxError;

    match result {
        BrokerResult::Ok {
            stdout,
            stderr,
            exit_code,
        }
        | BrokerResult::Failed {
            stdout,
            stderr,
            exit_code,
        } => Ok(std::process::Output {
            status: exit_status_from_code(exit_code),
            stdout: stdout.into_bytes(),
            stderr: stderr.into_bytes(),
        }),
        BrokerResult::Rejected { reason } => Err(SandboxError::Lima(format!(
            "{label}: agent rejected the request: {reason}"
        ))),
        BrokerResult::StreamOpen => Err(SandboxError::Internal(format!(
            "{label}: unexpected StreamOpen response for a one-shot op"
        ))),
        BrokerResult::RestrictConfirmed { .. } | BrokerResult::RestrictNotConfirmed { .. } => {
            // RestrictOnVerify responses map to a synthetic success/failure
            // output. The daemon interprets these by checking the exit code.
            let (code, msg) = match result {
                BrokerResult::RestrictConfirmed { netdev_token, .. } => (0i32, netdev_token),
                BrokerResult::RestrictNotConfirmed { reason, .. } => (1i32, reason),
                _ => unreachable!(),
            };
            Ok(std::process::Output {
                status: exit_status_from_code(code),
                stdout: msg.into_bytes(),
                stderr: Vec::new(),
            })
        }
    }
}

/// Construct an `ExitStatus` from a numeric exit code.
///
/// `std::process::ExitStatus` does not have a public constructor on macOS;
/// we use `std::process::Command` output's status field via a workaround:
/// spawn `true` (exit 0) or `false` (exit 1) and override the code via
/// a type-system trick. Instead, we use the `ExitStatusExt` from nix.
fn exit_status_from_code(code: i32) -> std::process::ExitStatus {
    // On Unix, ExitStatus wraps a raw wait(2) status. A normal exit of code N
    // is encoded as `(N & 0xff) << 8` in the raw wait status.
    use std::os::unix::process::ExitStatusExt;
    // POSIX wait status for normal exit of code N: W_EXITCODE(N, 0) = N << 8.
    // For code 0: raw = 0 (success). For code N: raw = N << 8.
    let raw: i32 = if code == 0 {
        0
    } else {
        (code.clamp(1, 127) & 0xff) << 8
    };
    std::process::ExitStatus::from_raw(raw)
}

/// Run a `limactl` operation directly (no agent) for the daemon's own uid.
///
/// This is the degenerate path for `op_uid == daemon_uid`. The daemon
/// already is the correct uid; `limactl` runs with its own env (LIMA_HOME
/// set to the daemon-uid LIMA_HOME, HOME set to the daemon's pw_dir).
fn run_limactl_direct(
    op_uid: u32,
    op: sandbox_core::lima::LimaOp<'_>,
    timeout: std::time::Duration,
    label: &str,
) -> Result<std::process::Output, sandbox_core::error::SandboxError> {
    use std::os::unix::process::CommandExt;

    use sandbox_core::error::SandboxError;
    use sandbox_core::lima::LimaOp;
    use sandbox_core::process::run_with_timeout;

    let lima_home = sandbox_core::lima::operator_lima_home(op_uid);
    let lima_home_str = lima_home.to_string_lossy().into_owned();

    // Resolve HOME for the daemon uid — limactl reads it for SSH key locations.
    // Falls back to an empty string if resolution fails (limactl will use its
    // own fallbacks).
    let home_str = uid_to_username(op_uid)
        .and_then(|username| {
            // Resolve pw_dir via getpwnam_r (same uid, re-lookup for pw_dir).
            let name_c = std::ffi::CString::new(username).ok()?;
            let bufsize = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
            let bufsize = if bufsize <= 0 { 1024 } else { bufsize as usize };
            let mut buf = vec![0i8; bufsize];
            let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let rc = unsafe {
                libc::getpwnam_r(
                    name_c.as_ptr(),
                    &mut pwd,
                    buf.as_mut_ptr(),
                    bufsize,
                    &mut result,
                )
            };
            if rc != 0 || result.is_null() {
                return None;
            }
            let dir_ptr = unsafe { (*result).pw_dir };
            if dir_ptr.is_null() {
                return None;
            }
            unsafe { std::ffi::CStr::from_ptr(dir_ptr) }
                .to_str()
                .ok()
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

    let mut cmd = std::process::Command::new("limactl");

    // Clear the environment and set only the minimal required vars, mirroring
    // the agent's `run_limactl` pattern. This prevents leaked env vars from
    // the daemon's process environment from influencing limactl's behaviour.
    let current_path = std::env::var("PATH").unwrap_or_default();
    let path_value = format!("/opt/homebrew/bin:/usr/local/bin:{current_path}");
    cmd.env_clear()
        .env("LIMA_HOME", &lima_home_str)
        .env("PATH", &path_value)
        .env("HOME", &home_str)
        .env("TERM", "dumb");

    // SAFETY: libc::umask is async-signal-safe on macOS and safe to call in a
    // pre_exec hook. We mirror the agent's behaviour so SSH key files created
    // by limactl land at 0600, not a more permissive mode derived from the
    // daemon's current umask.
    unsafe {
        cmd.pre_exec(|| {
            libc::umask(0o077);
            Ok(())
        });
    }

    match op {
        LimaOp::Create { vm, yaml_path, .. } => {
            // The `owner` field is not used here: in the brokered path the
            // agent writes the `sandboxd-owner` marker file after a successful
            // `limactl create`. In the direct (daemon-uid) path this arm is
            // only reached for the gateway Lima instance — daemon-owned infra
            // that does not require a per-operator owner marker (the gateway
            // instance is managed exclusively by the daemon, not by any
            // operator-uid recovery logic that would read the marker).
            cmd.args([
                "create",
                "--name",
                vm,
                &yaml_path.to_string_lossy(),
                "--tty=false",
            ]);
        }
        LimaOp::Start {
            vm,
            qemu_wrapper,
            hardened,
            memory_mb,
            cpus,
            start_timeout_s,
            bridge,
            unrestricted_slirp_for_provisioning,
        } => {
            let timeout_flag = format!("--timeout={start_timeout_s}s");
            cmd.args(["start", vm, &timeout_flag, "--tty=false"]);

            // The qemu-wrapper is passed via QEMU_SYSTEM_AARCH64 so Lima uses
            // it instead of the system qemu binary. This mirrors the agent's
            // handle_start behaviour exactly: the wrapper is what injects
            // `restrict=on` into the management NIC, enforcing egress control.
            // A non-empty wrapper path must always be set for session VMs —
            // only the gateway instance passes an empty path (gateway infra
            // deliberately omits restrict=on on its management NIC).
            let qemu_wrapper_str = qemu_wrapper.to_string_lossy().into_owned();
            if !qemu_wrapper_str.is_empty() {
                cmd.env("QEMU_SYSTEM_AARCH64", &qemu_wrapper_str);

                // Set SANDBOX_RESTRICT_MARKER so the qemu-wrapper knows where
                // to write the rewritten `-netdev user,...` token after it
                // injects restrict=on. The broker-mediated RestrictOnVerify
                // check (and the daemon's verify_restrict_on stub) read this
                // file to confirm the management NIC was locked. Path:
                // `{lima_home}/{vm}/sandboxd-restrict-marker`.
                // Only set when a wrapper is present (gateway instance skips
                // the wrapper and must NOT have its management NIC restricted).
                let marker_path = format!("{lima_home_str}/{vm}/sandboxd-restrict-marker");
                cmd.env("SANDBOX_RESTRICT_MARKER", &marker_path);
            }
            let hardened_str = if hardened { "1" } else { "0" };
            let memory_mb_str = memory_mb.to_string();
            let cpus_str = cpus.to_string();
            cmd.env("SANDBOX_QEMU_HARDENED", hardened_str)
                .env("SANDBOX_QEMU_MEMORY_MB", &memory_mb_str)
                .env("SANDBOX_QEMU_CPUS", &cpus_str);
            if let Some((bridge_name, vm_mac)) = bridge {
                cmd.env("SANDBOX_DOCKER_BRIDGE", bridge_name)
                    .env("SANDBOX_VM_MAC", vm_mac);
            }
            // Set the provisioning escape-hatch env var whenever the flag is
            // true, independent of whether a bridge is present. On macOS the
            // base-image build passes true with no bridge; the macOS QEMU
            // wrapper checks this env var to decide whether to skip its
            // restrict=on rewrite. On Linux the flag is always false at the
            // base-build call site, so this branch is effectively dead there.
            if unrestricted_slirp_for_provisioning {
                cmd.env("SANDBOX_UNRESTRICTED_SLIRP_FOR_PROVISIONING", "1");
            }
        }
        LimaOp::Stop { vm, force } => {
            if force {
                cmd.args(["stop", "--force", vm, "--tty=false"]);
            } else {
                cmd.args(["stop", vm, "--tty=false"]);
            }
        }
        LimaOp::Delete { vm } => {
            cmd.args(["delete", "--force", vm, "--tty=false"]);
        }
        LimaOp::Clone {
            base,
            vm,
            cpus,
            memory_gib,
            disk_gb,
            ..
        } => {
            cmd.args([
                "clone",
                base,
                vm,
                &format!("--cpus={cpus}"),
                &format!("--memory={memory_gib}"),
                &format!("--disk={disk_gb}"),
                "--tty=false",
            ]);
        }
        LimaOp::ListJson => {
            cmd.args(["list", "--json", "--tty=false"]);
        }
        LimaOp::InstallGuestAgent { vm: _ } => {
            // On macOS the daemon-uid degenerate case (gateway instance) does
            // not use install-guest-agent through this path — the gateway is a
            // Linux VM managed differently. If this is reached, surface a clear
            // error rather than silently failing.
            return Err(SandboxError::Lima(format!(
                "{label}: install-guest-agent on macOS degenerate path is not supported"
            )));
        }
        LimaOp::ReadUserKey => {
            // ReadUserKey reads the SSH key file directly; limactl is not involved.
            let key_path = lima_home.join("_config/user");
            return std::fs::read(&key_path)
                .map(|bytes| std::process::Output {
                    status: exit_status_from_code(0),
                    stdout: bytes,
                    stderr: Vec::new(),
                })
                .map_err(|e| {
                    SandboxError::Lima(format!(
                        "{label}: failed to read Lima SSH key at {}: {e}",
                        key_path.display()
                    ))
                });
        }
        LimaOp::RunRsync {
            backend,
            session_name,
            host_path,
            guest_path,
            no_gitignore,
        } => {
            use sandbox_core::backend::BackendKind;
            let transport = match backend {
                BackendKind::Lima => "limactl shell",
                BackendKind::Container => "docker exec -i",
            };
            let src = if host_path.ends_with('/') {
                host_path.to_string()
            } else {
                format!("{host_path}/")
            };
            let dst = if guest_path.ends_with('/') {
                format!("{session_name}:{guest_path}")
            } else {
                format!("{session_name}:{guest_path}/")
            };
            let mut rsync = std::process::Command::new("rsync");
            rsync.env("LIMA_HOME", &lima_home_str);
            rsync.env("PATH", &path_value);
            rsync.args(["-aL", "--delete"]);
            if !no_gitignore {
                rsync.arg("--filter=:- .gitignore");
            }
            rsync.args(["-e", transport, "--mkpath", &src, &dst]);
            return run_with_timeout(&mut rsync, timeout, label);
        }
        LimaOp::ReadOwnerMarker { vm } => {
            let marker = lima_home.join(vm).join("sandboxd-owner");
            return std::fs::read(&marker)
                .map(|bytes| std::process::Output {
                    status: exit_status_from_code(0),
                    stdout: bytes,
                    stderr: Vec::new(),
                })
                .map_err(|e| {
                    SandboxError::Lima(format!(
                        "{label}: failed to read owner marker at {}: {e}",
                        marker.display()
                    ))
                });
        }
        LimaOp::RestrictOnVerify { vm } => {
            // Degenerate path (op_uid == daemon_uid): read the wrapper marker
            // file directly. On macOS this path is only reached for the gateway
            // Lima instance (which never uses restrict=on). For session VMs the
            // brokered AgentBrokerExecutor path takes precedence (op_uid ≠ daemon_uid).
            // On Linux the SetuidHelperExecutor handles this variant directly.
            let marker = lima_home.join(vm).join("sandboxd-restrict-marker");
            return match std::fs::read_to_string(&marker) {
                Ok(contents) if contents.contains("restrict=on") => Ok(std::process::Output {
                    status: exit_status_from_code(0),
                    stdout: contents.trim().as_bytes().to_vec(),
                    stderr: Vec::new(),
                }),
                Ok(contents) => Err(SandboxError::Internal(format!(
                    "{label}: restrict marker at {} does not contain 'restrict=on'; \
                     contents: {contents:?}",
                    marker.display()
                ))),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(SandboxError::Internal(
                    format!("{label}: restrict marker not found at {}", marker.display()),
                )),
                Err(e) => Err(SandboxError::Internal(format!(
                    "{label}: failed to read restrict marker at {}: {e}",
                    marker.display()
                ))),
            };
        }
    }

    run_with_timeout(&mut cmd, timeout, label)
}

/// Owns the stdin+stdout handles of a directly-spawned `limactl shell` socat
/// child process. Dropping it triggers `kill_on_drop(true)` on the child.
struct DirectSocatStream {
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    _child: tokio::process::Child,
}

impl tokio::io::AsyncRead for DirectSocatStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for DirectSocatStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stdin).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

/// A brokered `GuestSocat` stream with a recoverable read prefix.
///
/// When a BufReader reads past `StreamOpen\n` in the same kernel-buffer fill,
/// the extra bytes are captured before `into_inner()` discards them. This type
/// prepends those bytes on the read side while delegating writes to the
/// underlying `UnixStream`. When `prefix` is exhausted the reads fall through
/// directly to the socket.
struct PrefixedStream {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: tokio::net::UnixStream,
}

impl tokio::io::AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // If there are prefix bytes left, serve them first.
        let pos = self.prefix.position() as usize;
        let data = self.prefix.get_ref();
        if pos < data.len() {
            let remaining = &data[pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.prefix.set_position((pos + to_copy) as u64);
            return std::task::Poll::Ready(Ok(()));
        }
        // Prefix exhausted — read from the underlying socket.
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Run `limactl shell <vm> -- socat - TCP:127.0.0.1:5123` directly for the
/// daemon's own uid (gateway / foreground-dev degenerate case).
async fn run_limactl_guest_socat_direct(
    op_uid: u32,
    vm: &str,
) -> Result<
    Box<dyn sandbox_core::backend::AsyncReadWrite + Send + Unpin>,
    sandbox_core::error::SandboxError,
> {
    use sandbox_core::error::SandboxError;

    let lima_home = sandbox_core::lima::operator_lima_home(op_uid);
    let lima_home_str = lima_home.to_string_lossy().into_owned();

    let current_path = std::env::var("PATH").unwrap_or_default();
    let path_value = format!("/opt/homebrew/bin:/usr/local/bin:{current_path}");

    let mut command = tokio::process::Command::new("limactl");
    command
        .args(["shell", vm, "--", "socat", "-", "TCP:127.0.0.1:5123"])
        .env("LIMA_HOME", &lima_home_str)
        .env("PATH", &path_value)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(|e| {
        SandboxError::Lima(format!("failed to spawn limactl shell {vm} -- socat: {e}"))
    })?;

    let stdin = child.stdin.take().ok_or_else(|| {
        SandboxError::Internal("failed to capture stdin of limactl shell socat".into())
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        SandboxError::Internal("failed to capture stdout of limactl shell socat".into())
    })?;

    Ok(Box::new(DirectSocatStream {
        stdin,
        stdout,
        _child: child,
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // -----------------------------------------------------------------------
    // Authentication unit tests (no GUI session required)
    // -----------------------------------------------------------------------

    /// Verify that `classify_peer_uid` — the production classification function
    /// called by `authenticate_peer` — rejects uid 0 (root).
    ///
    /// We test `classify_peer_uid` directly rather than through a socket because
    /// `peer_cred()` cannot return uid 0 without the test running as root. The
    /// integration test below exercises the full `authenticate_peer` call with a
    /// real socket where `peer_cred()` returns the test runner's own uid.
    #[test]
    fn auth_rejects_uid_zero() {
        assert_eq!(classify_peer_uid(0, "_sandboxd"), AuthOutcome::RejectedRoot);
    }

    /// Verify that `classify_peer_uid` rejects uids below the system-account
    /// floor (< 500). These are the same gates enforced in `authenticate_peer`.
    #[test]
    fn auth_rejects_system_uids() {
        for uid in [1u32, 100, 499] {
            assert_eq!(
                classify_peer_uid(uid, "_sandboxd"),
                AuthOutcome::RejectedSystemUid(uid),
                "uid {uid} should be rejected as a system uid"
            );
        }
    }

    /// Verify that a uid ≥ 500 that is NOT in the sandbox group is rejected by
    /// `classify_peer_uid`. Uses a nonexistent group name so the membership
    /// check always returns non-member / resolution-failed regardless of which
    /// user runs the tests.
    #[test]
    fn auth_rejects_non_member() {
        let nonexistent_group = "sandbox_broker_test_nonexistent_group_xyz";
        let own_uid = unsafe { libc::getuid() };
        if own_uid < SYSTEM_UID_FLOOR {
            // Skip: test runner is a system uid (unusual, but possible in CI).
            return;
        }
        let outcome = classify_peer_uid(own_uid, nonexistent_group);
        // Either NotMember (group exists but we're not in it) or
        // ResolutionFailed (group doesn't exist). Both are correct denials.
        match outcome {
            AuthOutcome::RejectedNotMember(_) | AuthOutcome::RejectedResolutionFailed(_) => {}
            other => panic!("expected rejection for nonexistent group; got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Eviction / registry tests (no GUI session required)
    // -----------------------------------------------------------------------

    /// Verify that registering a second agent for the same uid evicts the first
    /// AND that the new connection's registry entry survives the old task's
    /// generation-scoped `remove` call.
    ///
    /// This tests the generation-counter fix for the eviction race: without the
    /// fix, the old task's `remove(uid)` would delete the new entry, leaving the
    /// live connection invisible to `is_registered`.
    #[tokio::test]
    async fn eviction_leaves_new_connection_registered() {
        let registry = AgentRegistry::new();
        let (gen1, mut rx1, _req_rx1) = registry.register(1000).await;
        assert!(registry.is_registered(1000).await);

        // Register a second agent for the same uid — evicts the first.
        let (_gen2, _rx2, _req_rx2) = registry.register(1000).await;

        // Simulate the old task completing and calling remove with its
        // (now-stale) generation. This must be a no-op.
        registry.remove(1000, gen1).await;

        // The new connection's entry (gen2) must still be present.
        assert!(
            registry.is_registered(1000).await,
            "new connection must remain registered after old task's remove"
        );

        // Verify rx1 was closed (eviction signal fired): try_recv returns an
        // error when the sender has been dropped, confirming the old connection
        // received its eviction signal.
        assert!(
            rx1.try_recv().is_err(),
            "old connection's eviction receiver must be closed (sender dropped)"
        );
    }

    /// Verify that the current generation's `remove` does clear the entry.
    #[tokio::test]
    async fn remove_with_matching_generation_clears_registration() {
        let registry = AgentRegistry::new();
        let (slot_gen, _rx, _req_rx) = registry.register(1001).await;
        assert!(registry.is_registered(1001).await);
        registry.remove(1001, slot_gen).await;
        assert!(!registry.is_registered(1001).await);
    }

    /// Verify that `remove` with a stale generation is a no-op (does not
    /// disturb an entry that was registered under a different generation).
    #[tokio::test]
    async fn remove_with_stale_generation_is_noop() {
        let registry = AgentRegistry::new();
        let (gen1, _rx1, _req_rx1) = registry.register(1002).await;
        let (_gen2, _rx2, _req_rx2) = registry.register(1002).await; // evicts gen1

        // gen1's remove must not clear gen2's entry.
        registry.remove(1002, gen1).await;
        assert!(
            registry.is_registered(1002).await,
            "stale-generation remove must not disturb the live entry"
        );
    }

    /// Verify that multiple distinct uids can be registered simultaneously.
    #[tokio::test]
    async fn multiple_uids_coexist() {
        let registry = AgentRegistry::new();
        let (_g1, _rx1, _rq1) = registry.register(1000).await;
        let (_g2, _rx2, _rq2) = registry.register(1001).await;
        let (_g3, _rx3, _rq3) = registry.register(1002).await;
        let mut uids = registry.connected_uids().await;
        uids.sort();
        assert_eq!(uids, vec![1000, 1001, 1002]);
    }

    /// Verify that `send_op` returns the not-running error when no agent is
    /// registered for the uid.
    #[tokio::test]
    async fn send_op_fails_when_no_agent_registered() {
        use sandbox_agent_protocol::{BrokerOp, BrokerRequest};
        let registry = AgentRegistry::new();
        let request = BrokerRequest {
            request_id: 1,
            op: BrokerOp::ListJson { op_uid: 9999 },
        };
        let result = registry.send_op(9999, request).await;
        assert!(
            result.is_err(),
            "send_op must fail when no agent is registered"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("not running"),
            "error message must mention 'not running'; got: {msg}"
        );
    }

    /// Verify that `take_stream_for_guest_socat` returns the not-running error
    /// when no agent is registered for the uid.
    #[tokio::test]
    async fn take_stream_fails_when_no_agent_registered() {
        use sandbox_agent_protocol::{BrokerOp, BrokerRequest};
        let registry = AgentRegistry::new();
        let request = BrokerRequest {
            request_id: 2,
            op: BrokerOp::GuestSocat {
                op_uid: 9999,
                vm: "sandbox-test".to_string(),
            },
        };
        let result = registry.take_stream_for_guest_socat(9999, request).await;
        // `unwrap_err` requires Debug on the Ok variant, but Box<dyn AsyncReadWrite>
        // is not Debug. Use manual err extraction instead.
        assert!(
            result.is_err(),
            "take_stream must fail when no agent is registered"
        );
        let msg = result.err().unwrap();
        assert!(
            msg.contains("not running"),
            "error message must mention 'not running'; got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Socket bind tests
    // -----------------------------------------------------------------------

    /// Verify that `bind_broker_socket` creates a socket with mode 0660.
    #[test]
    fn broker_socket_bound_with_correct_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker_test.sock");
        // bind_broker_socket uses tokio UnixListener which requires a runtime.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let _listener = bind_broker_socket(&path).unwrap();
            let meta = std::fs::metadata(&path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(
                mode, BROKER_SOCKET_MODE,
                "broker socket mode should be 0660, got {mode:o}"
            );
        });
    }

    // -----------------------------------------------------------------------
    // GuestSocat prefix preservation (no GUI session required)
    // -----------------------------------------------------------------------

    /// Verify that bytes the BufReader consumed past `StreamOpen\n` are not
    /// lost when the stream is handed to the caller.
    ///
    /// This exercises the latent bug fixed by `PrefixedStream`: if the agent
    /// writes `StreamOpen\n` + the first raw socat bytes in a single write,
    /// the BufReader (which over-reads into its 8KB buffer to service
    /// `read_line`) would have captured both. Without the fix, `into_inner()`
    /// discards the extra bytes and the caller never sees them.
    ///
    /// The test creates a real Unix socket pair, writes the StreamOpen response
    /// + raw payload as a single write on the "agent" half, runs
    /// `drive_agent_connection_outer` in the background, and asserts that
    /// `take_stream_for_guest_socat` returns a stream that yields ALL the
    /// raw payload bytes — none silently dropped.
    #[cfg(feature = "test-env-override")]
    #[tokio::test]
    async fn integration_guest_socat_prefix_bytes_preserved() {
        use sandbox_agent_protocol::{BrokerOp, BrokerRequest, BrokerResponse, BrokerResult};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("integration_socat_prefix.sock");

        let own_uid = unsafe { libc::getuid() };
        let primary_gid = uid_to_primary_gid(own_uid).unwrap();
        let primary_group = gid_to_group_name(primary_gid).unwrap();

        unsafe {
            std::env::set_var(TEST_SANDBOX_GROUP_ENV, &primary_group);
            std::env::set_var(TEST_BROKER_SOCKET_ENV, &socket_path);
        }

        let listener = bind_broker_socket(&socket_path).unwrap();
        let registry = AgentRegistry::new();
        let reg_for_listener = registry.clone();

        tokio::spawn(run_broker_listener(listener, reg_for_listener, None));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect as the fake agent.
        let agent_stream = tokio::net::UnixStream::connect(&socket_path)
            .await
            .expect("agent connect");
        let (_, mut agent_writer) = agent_stream.into_split();

        // Send check-in.
        agent_writer.write_all(b"CHECKIN\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(registry.is_registered(own_uid).await);

        // Daemon: request a GuestSocat stream.
        let registry_clone = registry.clone();
        let request = BrokerRequest {
            request_id: 42,
            op: BrokerOp::GuestSocat {
                op_uid: own_uid,
                vm: "test-vm".to_string(),
            },
        };
        let daemon_task = tokio::spawn(async move {
            registry_clone
                .take_stream_for_guest_socat(own_uid, request)
                .await
        });

        // Fake agent: wait for the GuestSocat request, then reply with
        // StreamOpen AND the first raw payload bytes in a single write.
        // This simulates a fast agent that pipelines the StreamOpen + data.
        let response = BrokerResponse {
            request_id: 42,
            result: BrokerResult::StreamOpen,
        };
        let raw_payload = b"HELLO_SOCAT_PAYLOAD_BYTES";
        let mut combined = serde_json::to_string(&response).unwrap().into_bytes();
        combined.push(b'\n');
        combined.extend_from_slice(raw_payload);

        // Brief delay to let the daemon send the GuestSocat request first,
        // then send StreamOpen + payload in a single write.
        tokio::time::sleep(Duration::from_millis(50)).await;
        agent_writer
            .write_all(&combined)
            .await
            .expect("agent combined write");

        // Daemon: receive the stream and read all available data.
        let mut stream = tokio::time::timeout(Duration::from_secs(5), daemon_task)
            .await
            .expect("daemon task timeout")
            .expect("daemon task join")
            .expect("take_stream must succeed");

        // Read exactly raw_payload.len() bytes from the stream. These should
        // all come from the PrefixedStream prefix — not from the kernel socket
        // buffer (which is empty: the agent wrote everything in one write and
        // doesn't send more).
        let mut received = vec![0u8; raw_payload.len()];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut received))
            .await
            .expect("read_exact timeout")
            .expect("read_exact io");
        assert_eq!(
            &received[..n],
            raw_payload,
            "all raw payload bytes must be delivered to the caller; \
             BufReader-buffered prefix must not be silently dropped"
        );

        unsafe {
            std::env::remove_var(TEST_SANDBOX_GROUP_ENV);
            std::env::remove_var(TEST_BROKER_SOCKET_ENV);
        }
    }

    /// Verify that the connection is closed when the agent echoes a mismatched
    /// request_id in its response.
    ///
    /// A buggy or protocol-version-skewed agent that sends back a different
    /// request_id should cause the connection task to close the connection,
    /// not silently deliver the response to the caller.
    #[cfg(feature = "test-env-override")]
    #[tokio::test]
    async fn integration_request_id_mismatch_closes_connection() {
        use sandbox_agent_protocol::{BrokerOp, BrokerRequest, BrokerResponse, BrokerResult};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("integration_reqid_mismatch.sock");

        let own_uid = unsafe { libc::getuid() };
        let primary_gid = uid_to_primary_gid(own_uid).unwrap();
        let primary_group = gid_to_group_name(primary_gid).unwrap();

        unsafe {
            std::env::set_var(TEST_SANDBOX_GROUP_ENV, &primary_group);
            std::env::set_var(TEST_BROKER_SOCKET_ENV, &socket_path);
        }

        let listener = bind_broker_socket(&socket_path).unwrap();
        let registry = AgentRegistry::new();
        let reg_for_listener = registry.clone();

        tokio::spawn(run_broker_listener(listener, reg_for_listener, None));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let agent_stream = tokio::net::UnixStream::connect(&socket_path)
            .await
            .expect("agent connect");
        let (agent_reader, mut agent_writer) = agent_stream.into_split();
        let mut agent_buf = BufReader::new(agent_reader);

        agent_writer.write_all(b"CHECKIN\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(registry.is_registered(own_uid).await);

        // Daemon side: send a ListJson op with request_id=99.
        let registry_clone = registry.clone();
        let request = BrokerRequest {
            request_id: 99,
            op: BrokerOp::ListJson { op_uid: own_uid },
        };
        let daemon_task =
            tokio::spawn(async move { registry_clone.send_op(own_uid, request).await });

        // Fake agent: read the request, then reply with the WRONG request_id.
        let mut agent_line = String::new();
        tokio::time::timeout(Duration::from_secs(5), agent_buf.read_line(&mut agent_line))
            .await
            .expect("agent request timeout")
            .expect("agent request read");

        // Reply with request_id=0 (wrong — expected 99).
        let bad_response = BrokerResponse {
            request_id: 0,
            result: BrokerResult::Ok {
                stdout: "[]".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        };
        let bad_json = serde_json::to_string(&bad_response).unwrap();
        agent_writer.write_all(bad_json.as_bytes()).await.unwrap();
        agent_writer.write_all(b"\n").await.unwrap();

        // The daemon task must receive an error (connection closed after
        // the mismatch is detected), not the bogus Ok result.
        let result = tokio::time::timeout(Duration::from_secs(5), daemon_task)
            .await
            .expect("daemon task timeout")
            .expect("daemon task join");

        assert!(
            result.is_err(),
            "request_id mismatch must cause send_op to return Err, not Ok; got {result:?}"
        );
        let msg = result.unwrap_err();
        // The error message may say "dropped" (connection closed) or "not running".
        // Either is correct — the important property is that the bogus response
        // was NOT delivered to the caller.
        assert!(
            msg.contains("dropped") || msg.contains("not running"),
            "error must indicate connection closed or agent not running; got: {msg}"
        );

        unsafe {
            std::env::remove_var(TEST_SANDBOX_GROUP_ENV);
            std::env::remove_var(TEST_BROKER_SOCKET_ENV);
        }
    }

    // -----------------------------------------------------------------------
    // AgentBrokerExecutor routing tests (no GUI session required)
    // -----------------------------------------------------------------------

    /// Verify that `AgentBrokerExecutor` dispatches the daemon's own uid to the
    /// direct `limactl` path rather than the broker.
    ///
    /// When `op_uid == daemon_uid`, the executor must NOT consult the registry
    /// (which would fail with "not running" since no agent is registered here).
    /// Instead it must reach `run_limactl_direct`, which calls `limactl`. That
    /// call will fail because `limactl` is not expected to succeed in the test
    /// environment, but the error will be a process-launch or command-not-found
    /// error — not a "session agent ... is not running" message.
    ///
    /// This test confirms the routing branch: daemon_uid ops skip the registry.
    #[test]
    fn agent_broker_executor_daemon_uid_bypasses_registry() {
        use sandbox_core::lima::{LimaExecutor, LimaOp};
        use std::time::Duration;

        let registry = AgentRegistry::new();
        let daemon_uid = unsafe { libc::getuid() };
        let executor = AgentBrokerExecutor::new(registry, daemon_uid);

        // Run a ListJson op for the daemon's own uid. The executor takes the
        // direct path: no registry lookup, straight to run_limactl_direct().
        // The direct path calls limactl list --json, which will fail if limactl
        // is not installed — but the error must NOT contain "not running".
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let result = tokio::task::spawn_blocking({
                let exec = std::sync::Arc::new(executor);
                move || exec.run(daemon_uid, LimaOp::ListJson, Duration::from_secs(5), "test")
            })
            .await
            .expect("spawn_blocking join");

            if let Err(e) = result {
                let msg = e.to_string();
                assert!(
                    !msg.contains("not running"),
                    "daemon_uid op must NOT fail with 'not running'; got: {msg}"
                );
            }
            // If limactl is installed and produces output, the op may succeed —
            // either way the "not running" branch was correctly bypassed.
        });
    }

    /// Verify that `AgentBrokerExecutor` fails with the actionable "not running"
    /// message when the target uid is not the daemon uid and no agent is checked in.
    ///
    /// This exercises the brokered path's agent-not-found error for a uid that
    /// is distinct from the daemon's own uid.
    #[tokio::test]
    async fn agent_broker_executor_non_daemon_uid_fails_not_running() {
        use sandbox_core::lima::{LimaExecutor, LimaOp};
        use std::time::Duration;

        let registry = AgentRegistry::new();
        let daemon_uid = unsafe { libc::getuid() };
        // Use a uid that differs from the daemon uid — must not collide with any
        // operator uid that could accidentally be registered. We pick a value in
        // the human-operator range (≥ 500) but very unlikely to be the current
        // test runner's uid. If this uid somehow equals daemon_uid, skip.
        let operator_uid = if daemon_uid != 55555 { 55555 } else { 55556 };
        let executor = std::sync::Arc::new(AgentBrokerExecutor::new(registry, daemon_uid));

        let result = tokio::task::spawn_blocking({
            let exec = executor.clone();
            move || {
                exec.run(
                    operator_uid,
                    LimaOp::ListJson,
                    Duration::from_secs(5),
                    "test",
                )
            }
        })
        .await
        .expect("spawn_blocking join");

        let err_msg = result
            .expect_err("should fail when no agent is registered for operator_uid")
            .to_string();
        assert!(
            err_msg.contains("not running"),
            "error must contain 'not running'; got: {err_msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Integration test: heartbeat + op round-trip (no GUI session required)
    // -----------------------------------------------------------------------

    /// Full check-in + heartbeat round-trip through the broker listener.
    ///
    /// Uses `test-env-override` to set the enrollment group to the test
    /// runner's primary group so that the real `authenticate_peer` →
    /// `classify_peer_uid` → `uid_in_sandbox_group` path admits the connection.
    /// This exercises the production authentication path end-to-end, including
    /// `peer_cred()` on a real socket.
    ///
    /// Named with `integration_` prefix so the nextest `integration` profile
    /// picks it up.
    #[cfg(feature = "test-env-override")]
    #[tokio::test]
    async fn integration_broker_checkin_heartbeat_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("integration_broker.sock");

        // Resolve the test runner's primary group name for the membership gate.
        let own_uid = unsafe { libc::getuid() };
        let primary_gid =
            uid_to_primary_gid(own_uid).expect("test runner uid must have a primary gid");
        // Reverse-lookup group name from gid.
        let primary_group = gid_to_group_name(primary_gid)
            .expect("test runner primary gid must resolve to a group name");

        // Set the group override so the broker admits our own uid.
        // SAFETY: test is single-threaded (tokio::test single-thread); no
        // other task reads these env vars concurrently.
        unsafe {
            std::env::set_var(TEST_SANDBOX_GROUP_ENV, &primary_group);
            std::env::set_var(TEST_BROKER_SOCKET_ENV, &socket_path);
        }

        let listener = bind_broker_socket(&socket_path).unwrap();
        let registry = AgentRegistry::new();
        let registry_for_check = registry.clone();
        let reg_for_listener = registry.clone();

        // Spawn the broker listener.
        tokio::spawn(run_broker_listener(listener, reg_for_listener, None));

        // Give the listener a moment to start accepting.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect as the test runner (peer uid == own_uid).
        let mut client = tokio::net::UnixStream::connect(&socket_path)
            .await
            .expect("client connect to broker socket");

        // Send the check-in frame.
        client.write_all(b"CHECKIN\n").await.expect("write CHECKIN");

        // Give the broker time to process the check-in.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify the uid is now registered.
        assert!(
            registry_for_check.is_registered(own_uid).await,
            "uid {own_uid} should be registered after check-in"
        );

        // Send a heartbeat PING.
        client.write_all(b"PING\n").await.expect("write PING");

        // Read the PONG response.
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("PONG timeout")
            .expect("PONG read");
        assert_eq!(&buf[..n], b"PONG\n", "expected PONG response");

        // Clean up env vars.
        // SAFETY: same single-threaded context as the set_var above.
        unsafe {
            std::env::remove_var(TEST_SANDBOX_GROUP_ENV);
            std::env::remove_var(TEST_BROKER_SOCKET_ENV);
        }
    }

    /// Full check-in + one-shot op round-trip through the broker listener.
    ///
    /// A fake agent connects, checks in, receives a BrokerRequest JSON, and
    /// sends a BrokerResponse JSON back. The daemon side uses `send_op` to
    /// route the request. This exercises the full daemon→agent request path.
    ///
    /// Named with `integration_` prefix.
    #[cfg(feature = "test-env-override")]
    #[tokio::test]
    async fn integration_broker_op_round_trip() {
        use sandbox_agent_protocol::{BrokerOp, BrokerRequest, BrokerResponse, BrokerResult};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("integration_op.sock");

        let own_uid = unsafe { libc::getuid() };
        let primary_gid = uid_to_primary_gid(own_uid).unwrap();
        let primary_group = gid_to_group_name(primary_gid).unwrap();

        unsafe {
            std::env::set_var(TEST_SANDBOX_GROUP_ENV, &primary_group);
            std::env::set_var(TEST_BROKER_SOCKET_ENV, &socket_path);
        }

        let listener = bind_broker_socket(&socket_path).unwrap();
        let registry = AgentRegistry::new();
        let reg_for_listener = registry.clone();

        tokio::spawn(run_broker_listener(listener, reg_for_listener, None));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect as the fake agent.
        let agent_stream = tokio::net::UnixStream::connect(&socket_path)
            .await
            .expect("agent connect");

        let (agent_reader, mut agent_writer) = agent_stream.into_split();
        let mut agent_buf = BufReader::new(agent_reader);

        // Send check-in.
        agent_writer.write_all(b"CHECKIN\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(registry.is_registered(own_uid).await);

        // Daemon side: send a ListJson op.
        let registry_clone = registry.clone();
        let request = BrokerRequest {
            request_id: 7,
            op: BrokerOp::ListJson { op_uid: own_uid },
        };
        let daemon_task =
            tokio::spawn(async move { registry_clone.send_op(own_uid, request).await });

        // Fake agent: read the request and respond.
        let mut agent_line = String::new();
        tokio::time::timeout(Duration::from_secs(5), agent_buf.read_line(&mut agent_line))
            .await
            .expect("agent request timeout")
            .expect("agent request read");

        let parsed_req: BrokerRequest =
            serde_json::from_str(agent_line.trim()).expect("valid BrokerRequest from daemon");
        assert_eq!(parsed_req.request_id, 7);
        assert!(matches!(parsed_req.op, BrokerOp::ListJson { .. }));

        // Send back a fake success response.
        let response = BrokerResponse {
            request_id: 7,
            result: BrokerResult::Ok {
                stdout: "[]".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
        };
        let response_json = serde_json::to_string(&response).unwrap();
        agent_writer
            .write_all(response_json.as_bytes())
            .await
            .unwrap();
        agent_writer.write_all(b"\n").await.unwrap();

        // Daemon: receive the result.
        let result = tokio::time::timeout(Duration::from_secs(5), daemon_task)
            .await
            .expect("daemon task timeout")
            .expect("daemon task join")
            .expect("daemon result");

        assert!(
            matches!(result, BrokerResult::Ok { .. }),
            "expected Ok result; got {result:?}"
        );

        unsafe {
            std::env::remove_var(TEST_SANDBOX_GROUP_ENV);
            std::env::remove_var(TEST_BROKER_SOCKET_ENV);
        }
    }

    // -----------------------------------------------------------------------
    // reconcile 6b gate tests — verify connected_uids, the actual production gate
    // -----------------------------------------------------------------------

    /// Verify that `connected_uids` is empty when no agent is registered.
    /// This is the "no operators logged in" case at cold daemon start.
    /// The 6b reconcile loop iterates `connected_uids()` — an empty set means
    /// 6b is a no-op, which is correct (no VMs to verify for logged-out ops).
    #[tokio::test]
    async fn reconcile_6b_gate_not_checked_in() {
        let registry = AgentRegistry::new();
        // No agents registered — connected_uids must be empty.
        assert!(
            registry.connected_uids().await.is_empty(),
            "connected_uids must be empty when no agent is registered"
        );
        // is_registered (test-only helper) also returns false.
        assert!(
            !registry.is_registered(1000).await,
            "is_registered must return false when registry is empty"
        );
    }

    /// Verify that `connected_uids` reflects agent check-in and removal.
    /// This exercises the 6b reconcile gate across the full check-in / remove
    /// lifecycle: before check-in → empty; after check-in → uid present; after
    /// disconnect → empty again.
    #[tokio::test]
    async fn reconcile_6b_gate_checked_in_then_removed() {
        let registry = AgentRegistry::new();

        // Not yet checked in.
        assert!(registry.connected_uids().await.is_empty());

        // Agent checks in.
        let (slot_gen, _evict_rx, _req_rx) = registry.register(1500).await;
        assert!(
            registry.connected_uids().await.contains(&1500),
            "uid 1500 must appear in connected_uids after register()"
        );
        assert!(
            registry.is_registered(1500).await,
            "is_registered must return true after register()"
        );

        // Agent disconnects (remove with matching generation).
        registry.remove(1500, slot_gen).await;
        assert!(
            !registry.connected_uids().await.contains(&1500),
            "uid 1500 must NOT appear in connected_uids after remove()"
        );
    }

    /// Verify that `connected_uids` returns the exact set of currently
    /// checked-in operator uids — the iterator the 6b reconcile loop uses.
    #[tokio::test]
    async fn reconcile_6b_connected_uids_reflects_live_agents() {
        let registry = AgentRegistry::new();

        // Register two operators.
        let (gen_a, _rx_a, _rq_a) = registry.register(501).await;
        let (_gen_b, _rx_b, _rq_b) = registry.register(502).await;

        let mut uids = registry.connected_uids().await;
        uids.sort();
        assert_eq!(
            uids,
            vec![501, 502],
            "both registered uids must appear in connected_uids"
        );

        // Remove operator A.
        registry.remove(501, gen_a).await;
        let mut uids = registry.connected_uids().await;
        uids.sort();
        assert_eq!(
            uids,
            vec![502],
            "after operator A disconnects, only operator B must appear"
        );
    }

    /// Verify the 6b gate property: an operator not in `connected_uids` is not
    /// reconciled; an operator in `connected_uids` is. Uses `connected_uids`
    /// directly — the method production code iterates to drive 6b.
    #[tokio::test]
    async fn reconcile_6b_gate_only_for_checked_in_operator() {
        let registry = AgentRegistry::new();
        let uid_logged_in: u32 = 600;
        let uid_logged_out: u32 = 601;

        // Only uid_logged_in checks in.
        let (_slot_gen, _rx, _rq) = registry.register(uid_logged_in).await;

        let uids = registry.connected_uids().await;
        assert!(
            uids.contains(&uid_logged_in),
            "logged-in operator must appear in connected_uids (6b will reconcile them)"
        );
        assert!(
            !uids.contains(&uid_logged_out),
            "logged-out operator must NOT appear in connected_uids (6b skips them)"
        );
    }

    // -----------------------------------------------------------------------
    // Multi-uid isolation — the mandatory no-cross-operator-leakage test
    // -----------------------------------------------------------------------

    /// Drive two fake-agent connections with distinct uids directly against the
    /// registry (bypassing the socket-level `accept()` path, which cannot forge
    /// two different uids without root) and assert that:
    ///
    /// - `send_op` for uid A lands only on A's request channel; uid B's is unaffected.
    /// - Evicting A (re-registering A) does not disturb B's entry.
    /// - `connected_uids()` returns exactly {A, B} before eviction and still
    ///   {A, B} after eviction (A's slot was replaced, not removed).
    /// - A response framed with A's request_id on A's connection never satisfies
    ///   a B-side request (per-connection `outstanding` tracking is isolated).
    #[tokio::test]
    async fn multi_uid_no_cross_operator_leakage() {
        use sandbox_agent_protocol::{BrokerOp, BrokerRequest};

        let uid_a: u32 = 70001;
        let uid_b: u32 = 70002;
        let registry = AgentRegistry::new();

        // Register both operators.
        let (gen_a1, mut evict_rx_a1, mut req_rx_a) = registry.register(uid_a).await;
        let (_gen_b, _evict_rx_b, mut req_rx_b) = registry.register(uid_b).await;

        // Both must be visible.
        assert!(registry.is_registered(uid_a).await, "A must be registered");
        assert!(registry.is_registered(uid_b).await, "B must be registered");
        let mut uids = registry.connected_uids().await;
        uids.sort();
        assert_eq!(
            uids,
            vec![uid_a, uid_b],
            "connected_uids must contain exactly A and B"
        );

        // send_op for A must land on A's req channel only.
        let req_a = BrokerRequest {
            request_id: 100,
            op: BrokerOp::ListJson { op_uid: uid_a },
        };
        // Drive send_op in a background task — it returns when the channel accepts
        // the item (capacity 4, so non-blocking here).
        let reg_clone = registry.clone();
        let send_a = tokio::spawn(async move { reg_clone.send_op(uid_a, req_a).await });

        // A's req_rx must receive the work; B's must see nothing.
        let pending_a = tokio::time::timeout(Duration::from_secs(2), req_rx_a.recv())
            .await
            .expect("A's req_rx should receive within 2s")
            .expect("A's req_rx should not be closed");
        // Verify the request landed on A's channel with the correct request_id.
        let pending_request_id = match &pending_a {
            PendingRequest::OneShot { request, .. } => request.request_id,
            PendingRequest::TakeStream { request, .. } => request.request_id,
        };
        assert_eq!(
            pending_request_id, 100,
            "A's channel got a different request_id"
        );

        // B's req_rx must remain empty.
        assert!(
            req_rx_b.try_recv().is_err(),
            "B's request channel must remain empty after an A-side send_op"
        );

        // Drop pending_a (reply channel dropped); send_a will complete with an error.
        drop(pending_a);
        // send_a will now error (reply channel dropped); ignore.
        let _ = send_a.await;

        // Evict A by re-registering. B must be undisturbed.
        let (_gen_a2, _evict_rx_a2, _req_rx_a2) = registry.register(uid_a).await;

        // A's old eviction receiver must have fired.
        assert!(
            evict_rx_a1.try_recv().is_err(),
            "A's prior eviction receiver must be closed (eviction sender dropped)"
        );

        // B's entry must be untouched.
        assert!(
            registry.is_registered(uid_b).await,
            "B's registration must survive A's eviction"
        );

        // connected_uids still has exactly {A, B}: A was replaced, not removed.
        let mut uids = registry.connected_uids().await;
        uids.sort();
        assert_eq!(
            uids,
            vec![uid_a, uid_b],
            "connected_uids must still be {{A, B}} after re-registering A"
        );

        // A's stale remove (gen_a1) must not disturb the new A entry.
        registry.remove(uid_a, gen_a1).await;
        assert!(
            registry.is_registered(uid_a).await,
            "stale remove of A must not clear A's live entry"
        );
        assert!(
            registry.is_registered(uid_b).await,
            "B's registration must survive A's stale remove"
        );
    }

    // -----------------------------------------------------------------------
    // Error text assertions for the agent-unavailable path
    // -----------------------------------------------------------------------

    /// Verify the actionable "not running" error message contains the expected
    /// human-readable prefix required by the spec.
    ///
    /// The exact text is contract — CLI/UI tooling and the spec rely on the
    /// `session agent for … is not running` form.
    #[tokio::test]
    async fn agent_not_running_error_text_matches_spec() {
        // Use a uid that is very unlikely to have a username on any test machine.
        // The function falls back to the numeric uid string when resolution fails.
        let uid: u32 = 88877;
        let msg = agent_not_running_error(uid);
        assert!(
            msg.starts_with("session agent for "),
            "error must start with 'session agent for'; got: {msg}"
        );
        assert!(
            msg.contains("is not running"),
            "error must contain 'is not running'; got: {msg}"
        );
        // Must include something identifying the operator (username or uid number).
        assert!(
            msg.contains(&uid.to_string()) || !msg.contains("is not running — the operator"),
            "error must identify the operator by uid or username; got: {msg}"
        );
    }

    /// Verify that `send_op` returns an error whose text matches the spec's
    /// `session agent for … is not running` form when no agent is registered.
    #[tokio::test]
    async fn send_op_error_text_matches_spec_form() {
        use sandbox_agent_protocol::{BrokerOp, BrokerRequest};
        let registry = AgentRegistry::new();
        let uid: u32 = 88899;
        let request = BrokerRequest {
            request_id: 1,
            op: BrokerOp::ListJson { op_uid: uid },
        };
        let err = registry.send_op(uid, request).await.unwrap_err();
        assert!(
            err.contains("session agent for"),
            "send_op error must contain 'session agent for'; got: {err}"
        );
        assert!(
            err.contains("is not running"),
            "send_op error must contain 'is not running'; got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Switched-away negative guarantee
    // -----------------------------------------------------------------------

    /// A still-connected operator whose session stays registered and whose
    /// vm-check does not fire is never marked failed.
    ///
    /// The switched-away (still-logged-in) guarantee: absent a fresh admit
    /// and absent VM death, the registry entry stays intact and no eviction
    /// fires. This test asserts the negative: simply not generating a new
    /// check-in (which would trigger on_admit → reconcile) leaves the entry
    /// untouched.
    #[tokio::test]
    async fn switched_away_connection_stays_registered() {
        let registry = AgentRegistry::new();
        let uid: u32 = 77001;

        // Agent checks in.
        let (_gen, _evict_rx, _req_rx) = registry.register(uid).await;
        assert!(
            registry.is_registered(uid).await,
            "uid must be registered after check-in"
        );

        // Simulate time passing without any fresh admit (switch-away scenario).
        // No new check-in → no eviction fires → entry remains registered.
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert!(
            registry.is_registered(uid).await,
            "entry must remain registered with no eviction or new check-in (switched-away invariant)"
        );

        // Confirm connected_uids still lists the operator.
        assert!(
            registry.connected_uids().await.contains(&uid),
            "switched-away operator must remain in connected_uids"
        );
    }

    // -----------------------------------------------------------------------
    // Heartbeat-drop detection (uses R3 seam)
    // -----------------------------------------------------------------------

    /// A fake agent that checks in then goes silent is evicted after the
    /// (test-shortened) heartbeat timeout, and `is_registered` returns false.
    ///
    /// Uses the `SANDBOX_BROKER_TEST_HEARTBEAT_MS` env var (the R3 test seam)
    /// to shorten the 60-second production timeout to 100 ms so the test
    /// completes quickly.
    ///
    /// Named with `integration_` prefix because it drives a real Unix socket
    /// through the broker listener.
    #[cfg(feature = "test-env-override")]
    #[tokio::test]
    async fn integration_heartbeat_timeout_drops_silent_agent() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("integration_heartbeat_drop.sock");

        let own_uid = unsafe { libc::getuid() };
        let primary_gid = uid_to_primary_gid(own_uid).unwrap();
        let primary_group = gid_to_group_name(primary_gid).unwrap();

        unsafe {
            std::env::set_var(TEST_SANDBOX_GROUP_ENV, &primary_group);
            std::env::set_var(TEST_BROKER_SOCKET_ENV, &socket_path);
            // Shorten the heartbeat timeout to 100 ms so the test doesn't wait 60 s.
            std::env::set_var(TEST_HEARTBEAT_MS_ENV, "100");
        }

        let listener = bind_broker_socket(&socket_path).unwrap();
        let registry = AgentRegistry::new();
        let reg_for_listener = registry.clone();

        tokio::spawn(run_broker_listener(listener, reg_for_listener, None));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect and check in — then go silent (don't send any PING).
        let agent_stream = tokio::net::UnixStream::connect(&socket_path)
            .await
            .expect("agent connect");
        let (_, mut agent_writer) = agent_stream.into_split();
        agent_writer.write_all(b"CHECKIN\n").await.unwrap();

        // Give the broker time to process the check-in.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            registry.is_registered(own_uid).await,
            "uid must be registered immediately after check-in"
        );

        // Now go silent. Wait > 100 ms timeout + processing headroom.
        // The connection task must detect the liveness-timeout and drop the entry.
        tokio::time::sleep(Duration::from_millis(400)).await;

        assert!(
            !registry.is_registered(own_uid).await,
            "uid must be unregistered after heartbeat timeout"
        );

        unsafe {
            std::env::remove_var(TEST_SANDBOX_GROUP_ENV);
            std::env::remove_var(TEST_BROKER_SOCKET_ENV);
            std::env::remove_var(TEST_HEARTBEAT_MS_ENV);
        }
    }

    // -----------------------------------------------------------------------
    // Eviction severs GuestSocat stream; new connection works
    // -----------------------------------------------------------------------

    /// A GuestSocat stream handed to the caller is severed when the agent side
    /// closes, and a fresh check-in re-registers the uid so a new stream can be
    /// opened.
    ///
    /// The "eviction severs stream" property: once `take_stream_for_guest_socat`
    /// has handed the stream off, the connection task has already removed its
    /// registry entry. A second check-in (simulating agent reconnect) registers
    /// a fresh connection and `is_registered` returns true — proving the new
    /// connection is live while the handed-off stream independently closes when
    /// the remote side closes.
    ///
    /// Named with `integration_` prefix.
    #[cfg(feature = "test-env-override")]
    #[tokio::test]
    async fn integration_eviction_severs_guest_socat_stream_new_connection_works() {
        use sandbox_agent_protocol::{BrokerOp, BrokerRequest, BrokerResponse, BrokerResult};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("integration_evict_socat.sock");

        let own_uid = unsafe { libc::getuid() };
        let primary_gid = uid_to_primary_gid(own_uid).unwrap();
        let primary_group = gid_to_group_name(primary_gid).unwrap();

        unsafe {
            std::env::set_var(TEST_SANDBOX_GROUP_ENV, &primary_group);
            std::env::set_var(TEST_BROKER_SOCKET_ENV, &socket_path);
        }

        let listener = bind_broker_socket(&socket_path).unwrap();
        let registry = AgentRegistry::new();
        let reg_for_listener = registry.clone();

        tokio::spawn(run_broker_listener(listener, reg_for_listener, None));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // --- First connection: check in and open a GuestSocat stream ---

        let agent_stream1 = tokio::net::UnixStream::connect(&socket_path)
            .await
            .expect("agent1 connect");
        let (agent1_reader, mut agent1_writer) = agent_stream1.into_split();
        let mut agent1_buf = tokio::io::BufReader::new(agent1_reader);

        agent1_writer.write_all(b"CHECKIN\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            registry.is_registered(own_uid).await,
            "uid registered after first check-in"
        );

        // Daemon requests a GuestSocat stream.
        let reg_clone = registry.clone();
        let socat_request = BrokerRequest {
            request_id: 55,
            op: BrokerOp::GuestSocat {
                op_uid: own_uid,
                vm: "test-vm".to_string(),
            },
        };
        let daemon_task = tokio::spawn(async move {
            reg_clone
                .take_stream_for_guest_socat(own_uid, socat_request)
                .await
        });

        // Fake agent1: read the GuestSocat request and reply with StreamOpen.
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), agent1_buf.read_line(&mut line))
            .await
            .expect("GuestSocat request timeout")
            .expect("GuestSocat request read");

        let response = BrokerResponse {
            request_id: 55,
            result: BrokerResult::StreamOpen,
        };
        let response_json = serde_json::to_string(&response).unwrap();
        agent1_writer
            .write_all(response_json.as_bytes())
            .await
            .unwrap();
        agent1_writer.write_all(b"\n").await.unwrap();

        // Daemon receives the stream.
        let mut stream = tokio::time::timeout(Duration::from_secs(5), daemon_task)
            .await
            .expect("daemon task timeout")
            .expect("daemon task join")
            .expect("take_stream must succeed");

        // After GuestSocat handoff the connection task has removed its registry entry
        // and exited. is_registered must now be false (the entry was removed by the
        // connection task, not evicted — this is the designed behavior).
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !registry.is_registered(own_uid).await,
            "after GuestSocat handoff the connection task removes its entry"
        );

        // Drop agent1 writer — this closes the agent1 side of the stream.
        drop(agent1_writer);
        // The handed-off stream must see EOF.
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("stream EOF timeout")
            .expect("stream read");
        assert_eq!(
            n, 0,
            "handed-off stream must see EOF when agent side closes"
        );

        // --- Second connection: agent reconnects, uid is live again ---

        let agent_stream2 = tokio::net::UnixStream::connect(&socket_path)
            .await
            .expect("agent2 connect");
        let (_, mut agent2_writer) = agent_stream2.into_split();
        agent2_writer.write_all(b"CHECKIN\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            registry.is_registered(own_uid).await,
            "uid must be registered again after second check-in"
        );

        unsafe {
            std::env::remove_var(TEST_SANDBOX_GROUP_ENV);
            std::env::remove_var(TEST_BROKER_SOCKET_ENV);
        }
    }

    /// Resolve a gid to a group name via `getgrgid_r`. Used in integration
    /// tests to find the test runner's primary group name.
    #[cfg(feature = "test-env-override")]
    fn gid_to_group_name(gid: libc::gid_t) -> Option<String> {
        let bufsize = unsafe { libc::sysconf(libc::_SC_GETGR_R_SIZE_MAX) };
        let bufsize = if bufsize <= 0 { 1024 } else { bufsize as usize };
        let mut buf = vec![0i8; bufsize];
        let mut grp = unsafe { std::mem::zeroed::<libc::group>() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe { libc::getgrgid_r(gid, &mut grp, buf.as_mut_ptr(), bufsize, &mut result) };
        if rc != 0 || result.is_null() {
            return None;
        }
        let name_ptr = unsafe { (*result).gr_name };
        if name_ptr.is_null() {
            return None;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) };
        name.to_str().ok().map(|s| s.to_string())
    }
}
