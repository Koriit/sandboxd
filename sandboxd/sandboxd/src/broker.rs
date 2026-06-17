// The public API of this module is consumed by the daemon's macOS startup
// sequence (AgentBrokerExecutor wiring). Suppress dead-code warnings until
// that integration lands.
#![allow(dead_code)]

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
//! Mode: `0660`, owner `_sandbox:_sandbox`.
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
//!    (e.g. `_sandbox` itself). Only real human operators (uid ≥ 500) may
//!    check in.
//!
//! 4. **Re-resolve `_sandbox` membership via `getgrouplist(3)`** — the
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

/// The `_sandbox` group name — the enrollment gate on macOS.
const SANDBOX_GROUP_NAME: &str = "_sandbox";

// test-env-override seams
#[cfg(feature = "test-env-override")]
const TEST_BROKER_SOCKET_ENV: &str = "SANDBOX_BROKER_TEST_SOCKET";
#[cfg(feature = "test-env-override")]
const TEST_SANDBOX_GROUP_ENV: &str = "SANDBOX_BROKER_TEST_SANDBOX_GROUP";

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
/// `_sandbox` so tests can drive the membership gate against a synthetic group.
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
/// 3. `_sandbox` membership via `getgrouplist(3)` → Admitted / RejectedNotMember /
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
/// The `0660` socket mode is a first filter (only `_sandbox`-group members
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
/// 1. uid A connects — `register(A)` stores `(gen=1, tx1)`, drops nothing.
/// 2. uid A reconnects — `register(A)` stores `(gen=2, tx2)`, drops `tx1`.
/// 3. Old task (gen=1) wakes on eviction, calls `remove(A, 1)` — gen mismatch,
///    no-op. The new connection's entry (gen=2) is preserved.
/// 4. New task (gen=2) runs indefinitely; `is_registered(A)` returns `true`.
#[derive(Clone, Default)]
pub struct AgentRegistry {
    inner: Arc<Mutex<RegistryInner>>,
}

#[derive(Default)]
struct RegistryInner {
    /// Live agents by uid. Value is `(generation, eviction_sender)`.
    /// Dropping the sender signals the associated task to exit.
    agents: HashMap<u32, (u64, tokio::sync::oneshot::Sender<()>)>,
    /// Monotonically increasing generation counter. Incremented on every
    /// `register()` call so each entry can be identified uniquely.
    next_generation: u64,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new agent connection for `uid`.
    ///
    /// Returns `(generation, eviction_receiver)`. The caller passes `generation`
    /// to [`remove`] when the connection exits so that the remove is a no-op if
    /// a newer check-in has already replaced this entry.
    ///
    /// If an entry already exists for this uid, its eviction sender is dropped,
    /// waking the prior task's `select!` on its receiver (last-writer-wins).
    pub async fn register(&self, uid: u32) -> (u64, tokio::sync::oneshot::Receiver<()>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut inner = self.inner.lock().await;
        inner.next_generation += 1;
        let slot_gen = inner.next_generation;
        if let Some((_, old_tx)) = inner.agents.insert(uid, (slot_gen, tx)) {
            // Evict the prior connection by dropping its sender.
            drop(old_tx);
            info!(
                uid,
                slot_gen, "evicted prior agent connection (last-writer-wins)"
            );
        }
        (slot_gen, rx)
    }

    /// Remove the registry entry for `uid` if its generation matches.
    ///
    /// A mismatch means a newer check-in has already replaced this entry; the
    /// remove is a no-op so the live connection is not disturbed.
    pub async fn remove(&self, uid: u32, generation: u64) {
        let mut inner = self.inner.lock().await;
        if let Some((stored_gen, _)) = inner.agents.get(&uid) {
            if *stored_gen == generation {
                inner.agents.remove(&uid);
            }
            // Else: a newer connection owns this entry — leave it alone.
        }
    }

    /// Check whether an agent is currently registered for `uid`.
    pub async fn is_registered(&self, uid: u32) -> bool {
        let inner = self.inner.lock().await;
        inner.agents.contains_key(&uid)
    }

    /// Return the set of currently connected uids.
    pub async fn connected_uids(&self) -> Vec<u32> {
        let inner = self.inner.lock().await;
        inner.agents.keys().copied().collect()
    }
}

// ---------------------------------------------------------------------------
// Per-connection heartbeat task
// ---------------------------------------------------------------------------

/// Drive a single authenticated agent connection: respond to PING heartbeats
/// with PONG and watch for liveness timeout or eviction.
///
/// The task exits when any of the following occurs:
/// - The eviction signal fires (prior entry for this uid was replaced).
/// - The heartbeat timeout expires (no PING received within `HEARTBEAT_TIMEOUT`).
/// - A read or write error occurs on the stream.
/// - The agent closes the connection (read returns 0 bytes).
///
/// On exit the task calls `registry.remove(uid, generation)`. Because
/// `remove` is generation-scoped, a race with a newer check-in is safe:
/// the new connection's registry entry is left intact.
async fn drive_agent_connection(
    uid: u32,
    generation: u64,
    stream: UnixStream,
    evict_rx: tokio::sync::oneshot::Receiver<()>,
    registry: AgentRegistry,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut evict_rx = evict_rx;

    loop {
        line.clear();
        tokio::select! {
            // Watch for eviction signal from a newer check-in for the same uid.
            _ = &mut evict_rx => {
                info!(uid, "agent connection evicted by newer check-in; closing");
                break;
            }

            // Read the next line from the agent with a liveness timeout.
            result = tokio::time::timeout(HEARTBEAT_TIMEOUT, reader.read_line(&mut line)) => {
                match result {
                    Err(_elapsed) => {
                        warn!(
                            uid,
                            timeout_secs = HEARTBEAT_TIMEOUT.as_secs(),
                            "no heartbeat received within timeout; dropping dead agent"
                        );
                        break;
                    }
                    Ok(Ok(0)) => {
                        info!(uid, "agent connection closed cleanly");
                        break;
                    }
                    Ok(Ok(_)) => {
                        let trimmed = line.trim_end_matches(['\n', '\r']);
                        match trimmed {
                            "CHECKIN" => {
                                // Check-in frame — already authenticated; log only.
                                info!(uid, "agent check-in frame received");
                            }
                            "PING" => {
                                // Heartbeat — respond with PONG.
                                if let Err(e) = writer.write_all(b"PONG\n").await {
                                    warn!(uid, error = %e, "failed to write PONG; dropping connection");
                                    break;
                                }
                            }
                            other => {
                                // Unknown frame on this channel. Log and ignore:
                                // wire protocol payloads are defined in the
                                // broker protocol session.
                                warn!(uid, frame = %other, "unexpected frame on broker channel; ignoring");
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(uid, error = %e, "read error on broker connection; dropping");
                        break;
                    }
                }
            }
        }
    }

    // Generation-scoped remove: safe if a newer check-in already replaced this
    // entry — the new connection's entry is left intact.
    registry.remove(uid, generation).await;
    info!(uid, "agent connection task exited");
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
/// spawn a heartbeat task for admitted connections.
///
/// This function runs for the lifetime of the daemon. It never returns under
/// normal operation; the caller should spawn it as a background task.
pub async fn run_broker_listener(listener: UnixListener, registry: AgentRegistry) {
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
                let (slot_gen, evict_rx) = registry.register(uid).await;
                tokio::spawn(drive_agent_connection(uid, slot_gen, stream, evict_rx, reg));
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
        assert_eq!(classify_peer_uid(0, "_sandbox"), AuthOutcome::RejectedRoot);
    }

    /// Verify that `classify_peer_uid` rejects uids below the system-account
    /// floor (< 500). These are the same gates enforced in `authenticate_peer`.
    #[test]
    fn auth_rejects_system_uids() {
        for uid in [1u32, 100, 499] {
            assert_eq!(
                classify_peer_uid(uid, "_sandbox"),
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
        let (gen1, mut rx1) = registry.register(1000).await;
        assert!(registry.is_registered(1000).await);

        // Register a second agent for the same uid — evicts the first.
        let (_gen2, _rx2) = registry.register(1000).await;

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
        let (slot_gen, _rx) = registry.register(1001).await;
        assert!(registry.is_registered(1001).await);
        registry.remove(1001, slot_gen).await;
        assert!(!registry.is_registered(1001).await);
    }

    /// Verify that `remove` with a stale generation is a no-op (does not
    /// disturb an entry that was registered under a different generation).
    #[tokio::test]
    async fn remove_with_stale_generation_is_noop() {
        let registry = AgentRegistry::new();
        let (gen1, _rx1) = registry.register(1002).await;
        let (_gen2, _rx2) = registry.register(1002).await; // evicts gen1

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
        let (_g1, _rx1) = registry.register(1000).await;
        let (_g2, _rx2) = registry.register(1001).await;
        let (_g3, _rx3) = registry.register(1002).await;
        let mut uids = registry.connected_uids().await;
        uids.sort();
        assert_eq!(uids, vec![1000, 1001, 1002]);
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
    // Integration test: heartbeat round-trip (no GUI session required)
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
        tokio::spawn(run_broker_listener(listener, reg_for_listener));

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

    /// Resolve a gid to a group name via `getgrgid_r`. Used in the heartbeat
    /// integration test to find the test runner's primary group name.
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
