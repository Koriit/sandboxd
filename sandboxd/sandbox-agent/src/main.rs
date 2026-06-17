//! `sandbox-agent` — per-operator LaunchAgent that brokers `limactl`
//! operations on behalf of the sandboxd daemon.
//!
//! # Role
//!
//! On macOS, the daemon runs as `_sandbox` and cannot switch to an
//! operator's uid directly (no `cap_setuid`, no setuid binary). Instead,
//! each enrolled operator runs this agent as a LaunchAgent in their own
//! login session. The agent connects *out* to the daemon's broker socket,
//! identifies itself via the kernel-supplied peer credential, and holds
//! the connection open. The daemon then sends typed `limactl` operation
//! requests over that established channel and reads results back.
//!
//! # Self-gate
//!
//! On startup the agent resolves its own uid (via `getuid()`), looks up
//! the `_sandbox` group membership of that uid via `getgrouplist(3)`
//! (Directory Services — not the runtime group array), and **exits cleanly
//! (code 0) if the uid is not a member**. This prevents a respawn loop for
//! users who are not enrolled operators: the LaunchAgent plist omits
//! `KeepAlive` (or sets `KeepAlive = { SuccessfulExit = false }`), so
//! launchd does not re-trigger the job on a clean exit.
//!
//! # PATH establishment
//!
//! A LaunchAgent does not inherit the operator's interactive-shell PATH
//! (`launchd` does not source `~/.zprofile` / `~/.zshrc`), so Homebrew's
//! `/opt/homebrew/bin` is absent by default. The agent prepends the
//! standard macOS Homebrew prefix before invoking `limactl`.
//!
//! # Wire protocol
//!
//! This session establishes the authenticated channel only. The wire
//! protocol for operation payloads is defined in a subsequent session.
//! Currently the agent sends a check-in frame and then maintains the
//! connection with periodic heartbeat pings; the daemon responds with
//! heartbeat acknowledgements.
//!
//! # Security invariants (enforce at every code-path, do not relax)
//!
//! - The agent's uid is read from `getuid()`, never from a claim in a
//!   message. It acts only for its own uid.
//! - The agent is not setuid and carries no file capabilities. It runs
//!   unprivileged as the operator.
//! - Non-enrolled operators exit cleanly; no respawn loop.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("error: sandbox-agent runs on macOS only");
    std::process::exit(2);
}

#[cfg(target_os = "macos")]
fn main() {
    imp::run();
}

#[cfg(target_os = "macos")]
mod imp {
    use std::path::PathBuf;
    use std::time::Duration;
    use tracing::{info, warn};

    // ---------------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------------

    /// The group name that gates operator enrollment on macOS.
    const SANDBOX_GROUP_NAME: &str = "_sandbox";

    /// Default broker socket path. Overridable via `SANDBOX_BROKER_SOCKET`
    /// (or `SANDBOX_AGENT_TEST_BROKER_SOCKET` in test builds) so tests can
    /// use a temp-dir path without `/var/run` or root.
    const DEFAULT_BROKER_SOCKET: &str = "/var/run/sandbox/broker.sock";

    /// Interval between heartbeat pings sent to the daemon.
    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

    /// PATH prefixes the agent prepends so `limactl` is reachable even
    /// though launchd does not source the operator's shell profile.
    const PATH_PREPEND: &str = "/opt/homebrew/bin:/usr/local/bin";

    // ---------------------------------------------------------------------------
    // test-env-override seams
    // ---------------------------------------------------------------------------

    #[cfg(feature = "test-env-override")]
    const TEST_SANDBOX_GROUP_ENV: &str = "SANDBOX_AGENT_TEST_SANDBOX_GROUP";
    #[cfg(feature = "test-env-override")]
    const TEST_BROKER_SOCKET_ENV: &str = "SANDBOX_AGENT_TEST_BROKER_SOCKET";

    fn resolve_sandbox_group_name() -> String {
        #[cfg(feature = "test-env-override")]
        if let Ok(v) = std::env::var(TEST_SANDBOX_GROUP_ENV)
            && !v.is_empty()
        {
            return v;
        }
        SANDBOX_GROUP_NAME.to_string()
    }

    fn resolve_broker_socket_path() -> PathBuf {
        // The SANDBOX_BROKER_SOCKET env var is the user-facing override
        // (mirrors SANDBOX_SOCKET on the API socket side). The test-specific
        // override is separate so production binaries do not expose an
        // attacker-accessible redirect.
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

    // ---------------------------------------------------------------------------
    // Group membership check via getgrouplist(3)
    // ---------------------------------------------------------------------------

    /// Check whether `uid` is a member of the group named `group_name`
    /// by re-resolving membership via `getgrouplist(3)` (Directory Services).
    ///
    /// This is authoritative: `getgrouplist` consults the full directory
    /// database (memberd / opendirectoryd on macOS), not just the
    /// runtime supplementary group array which is capped at `NGROUPS` (16)
    /// and unreliable across macOS versions. An operator with more than 16
    /// groups (common in corporate / MDM environments) may have `_sandbox`
    /// past position 16 in their full list; `getgrouplist` returns it
    /// regardless.
    ///
    /// Returns `true` if the uid is a member, `false` on non-membership or
    /// any resolution failure. Failure is treated as non-membership so the
    /// agent self-gates conservatively: a uid that cannot be looked up is
    /// not granted access.
    fn uid_in_group(uid: u32, group_name: &str) -> bool {
        use std::ffi::CString;

        // Step 1: resolve the username for getgrouplist.
        let username = match uid_to_name(uid) {
            Some(n) => n,
            None => {
                warn!(
                    uid,
                    "could not resolve uid to username; treating as non-member"
                );
                return false;
            }
        };
        let name_c = match CString::new(username.as_bytes()) {
            Ok(c) => c,
            Err(_) => return false,
        };

        // Step 2: resolve the gid of the target group.
        let target_gid = match group_name_to_gid(group_name) {
            Some(g) => g,
            None => {
                warn!(group_name, "could not resolve group name to gid");
                return false;
            }
        };

        // Step 3: resolve the primary gid of the user (required by getgrouplist).
        let primary_gid = match uid_to_primary_gid(uid) {
            Some(g) => g,
            None => return false,
        };

        // Step 4: call getgrouplist with a growable buffer.
        // The function returns -1 if the buffer is too small and updates
        // ngroups to the required count; double and retry up to a limit.
        //
        // On macOS, getgrouplist takes int (i32) for the primary gid and
        // int[] for the groups buffer (unlike the Linux version which uses
        // gid_t/u32). We cast appropriately.
        let mut ngroups: libc::c_int = 64;
        loop {
            let mut groups: Vec<libc::c_int> = vec![0; ngroups as usize];
            // SAFETY: name_c is a valid NUL-terminated string; groups is a
            // properly-sized mutable buffer; primary_gid is the user's real gid.
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
                    // Buffer was too small; ngroups holds the required count.
                    continue;
                }
                // Overflow or unexpected failure — treat as non-member.
                warn!(
                    uid,
                    ngroups, "getgrouplist overflow or failure; treating as non-member"
                );
                return false;
            }
            // ret >= 0: groups[0..ngroups] is valid.
            return groups
                .iter()
                .take(ngroups as usize)
                .any(|&g| g as libc::gid_t == target_gid);
        }
    }

    /// Resolve a uid to a username via `getpwuid_r`.
    fn uid_to_name(uid: u32) -> Option<String> {
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
    // PATH establishment
    // ---------------------------------------------------------------------------

    /// Prepend the Homebrew and standard macOS bin directories to PATH.
    ///
    /// A LaunchAgent does not inherit the operator's interactive-shell PATH;
    /// `/opt/homebrew/bin` (Apple Silicon Homebrew) and `/usr/local/bin`
    /// (Intel Homebrew / manually installed tools) are absent by default.
    /// The agent resolves `limactl` from this enriched PATH rather than
    /// hardcoding a single absolute path — the operator's Homebrew prefix
    /// varies by architecture, and the agent runs as the operator and just
    /// needs a sane PATH for itself.
    fn establish_path() {
        let current = std::env::var("PATH").unwrap_or_default();
        let new_path = if current.is_empty() {
            format!("{PATH_PREPEND}:/usr/bin:/bin")
        } else {
            format!("{PATH_PREPEND}:{current}")
        };
        // SAFETY: single-threaded at this point (before tokio runtime starts).
        unsafe { std::env::set_var("PATH", &new_path) };
    }

    // ---------------------------------------------------------------------------
    // Broker connection
    // ---------------------------------------------------------------------------

    /// A check-in frame sent from the agent to the daemon on connect.
    /// The daemon reads the peer uid from `LOCAL_PEERCRED` and ignores any
    /// uid field in the message body — this struct exists only to provide a
    /// versioned framing that future protocol additions can extend.
    ///
    /// Format: `"CHECKIN\n"` (newline-delimited ASCII).
    const CHECKIN_FRAME: &[u8] = b"CHECKIN\n";

    /// A heartbeat frame sent periodically to prove the connection is alive.
    /// Format: `"PING\n"` (newline-delimited ASCII).
    const HEARTBEAT_FRAME: &[u8] = b"PING\n";

    /// Expected acknowledgement from the daemon in response to `PING\n`.
    /// The agent reads up to this many bytes per heartbeat exchange.
    const PONG_FRAME: &[u8] = b"PONG\n";

    /// Maximum bytes to read in a single recv call on the broker channel.
    const MAX_RECV: usize = 64;

    /// Connect to the broker socket, send the check-in frame, and then
    /// maintain the connection with periodic heartbeat pings until the
    /// connection closes.
    async fn run_broker_connection(socket_path: PathBuf, own_uid: u32) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        loop {
            info!(
                socket = %socket_path.display(),
                uid = own_uid,
                "connecting to broker socket"
            );

            let mut stream = match UnixStream::connect(&socket_path).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "broker connect failed; retrying in 5s");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            // Send the check-in frame. The daemon authenticates the peer
            // uid from LOCAL_PEERCRED — not from this frame — so the frame
            // is purely a protocol marker.
            if let Err(e) = stream.write_all(CHECKIN_FRAME).await {
                warn!(error = %e, "failed to send check-in frame; reconnecting");
                continue;
            }

            info!(uid = own_uid, "check-in sent; holding broker connection");

            // Heartbeat loop: ping every HEARTBEAT_INTERVAL and expect a PONG.
            let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
            interval.tick().await; // consume the immediate first tick

            loop {
                interval.tick().await;

                if let Err(e) = stream.write_all(HEARTBEAT_FRAME).await {
                    warn!(error = %e, "heartbeat write failed; reconnecting");
                    break;
                }

                let mut buf = [0u8; MAX_RECV];
                match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                    Ok(Ok(0)) => {
                        info!("broker connection closed by daemon; reconnecting");
                        break;
                    }
                    Ok(Ok(n)) => {
                        if &buf[..n] != PONG_FRAME {
                            warn!(
                                received = %String::from_utf8_lossy(&buf[..n]),
                                "unexpected response to PING; reconnecting"
                            );
                            break;
                        }
                        // Heartbeat acknowledged — continue.
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, "heartbeat read error; reconnecting");
                        break;
                    }
                    Err(_elapsed) => {
                        warn!("heartbeat response timed out; reconnecting");
                        break;
                    }
                }
            }

            // Brief pause before reconnect to avoid a tight reconnect loop
            // if the daemon is temporarily unavailable.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    // ---------------------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------------------

    pub fn run() {
        // Establish PATH before the tokio runtime starts (single-threaded
        // here; safe to call set_var).
        establish_path();

        // Set up structured logging.
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("sandbox_agent=info".parse().unwrap()),
            )
            .init();

        let own_uid = unsafe { libc::getuid() };

        // Self-gate: exit cleanly if this uid is not a member of the
        // _sandbox group. launchd is configured with no KeepAlive on
        // successful exit, so this produces no respawn loop for non-enrolled
        // users.
        let sandbox_group = resolve_sandbox_group_name();
        if !uid_in_group(own_uid, &sandbox_group) {
            info!(
                uid = own_uid,
                group = %sandbox_group,
                "uid is not a member of the enrollment group; exiting cleanly"
            );
            std::process::exit(0);
        }

        info!(
            uid = own_uid,
            group = %sandbox_group,
            "enrollment group membership confirmed; starting broker connection"
        );

        let broker_socket = resolve_broker_socket_path();

        // Build the tokio runtime and run the broker connection loop.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");

        rt.block_on(run_broker_connection(broker_socket, own_uid));
    }

    // ---------------------------------------------------------------------------
    // Unit tests
    // ---------------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Verify that a uid below 500 (the system-account floor) is not a
        /// member of the sandbox group. This test drives the `uid_in_group`
        /// logic indirectly: uid 0 (root) should not be in `_sandbox` on
        /// any correctly-configured macOS host, so this is a safe assertion.
        ///
        /// We cannot test actual membership without `_sandbox` existing and
        /// the test user being enrolled; the integration tests in the broker
        /// module cover that path.
        #[test]
        fn uid_zero_not_in_sandbox_group() {
            // On a correctly configured host, uid 0 (root) is never a member
            // of _sandbox. If this fails it means _sandbox is misconfigured.
            // The test is intentionally conservative: if _sandbox doesn't exist
            // on this host, uid_in_group returns false (can't resolve group),
            // which also passes.
            let in_group = uid_in_group(0, "_sandbox");
            assert!(
                !in_group,
                "uid 0 must not be a member of _sandbox — check host configuration"
            );
        }

        /// Verify that `uid_to_name` resolves the current process's own uid
        /// to a non-empty username (the operator running the tests).
        #[test]
        fn own_uid_resolves_to_name() {
            let own_uid = unsafe { libc::getuid() };
            let name = uid_to_name(own_uid);
            assert!(
                name.is_some() && !name.unwrap().is_empty(),
                "own uid must resolve to a non-empty username"
            );
        }

        /// Verify that a clearly-nonexistent uid (u32::MAX) returns None from
        /// uid_to_name without panicking.
        #[test]
        fn nonexistent_uid_returns_none() {
            assert_eq!(uid_to_name(u32::MAX), None);
        }

        /// Verify that group_name_to_gid returns Some for a group that is
        /// guaranteed to exist on macOS (the "staff" group, gid 20).
        #[test]
        fn staff_group_resolves() {
            let gid = group_name_to_gid("staff");
            assert_eq!(gid, Some(20), "staff group should be gid 20 on macOS");
        }

        /// Verify that a nonexistent group returns None without panicking.
        #[test]
        fn nonexistent_group_returns_none() {
            assert_eq!(
                group_name_to_gid("sandbox_agent_test_nonexistent_group_xyz"),
                None
            );
        }

        /// Verify that `uid_in_group` returns false for uid u32::MAX (not
        /// a real user).
        #[test]
        fn uid_max_not_in_any_group() {
            let in_staff = uid_in_group(u32::MAX, "staff");
            assert!(!in_staff, "nonexistent uid must not appear in any group");
        }

        /// Verify that the broker socket path resolves to the default when no
        /// env var is set (or an empty one).
        #[test]
        fn default_broker_socket_path() {
            // Unset the override var to ensure we get the default.
            // SAFETY: single-threaded tests; no other thread reads these vars.
            unsafe {
                std::env::remove_var("SANDBOX_BROKER_SOCKET");
                #[cfg(feature = "test-env-override")]
                std::env::remove_var(TEST_BROKER_SOCKET_ENV);
            }

            let path = resolve_broker_socket_path();
            assert_eq!(path.as_os_str(), DEFAULT_BROKER_SOCKET);
        }

        #[cfg(feature = "test-env-override")]
        #[test]
        fn test_env_override_broker_socket() {
            let tmp = tempfile::tempdir().unwrap();
            let socket_path = tmp.path().join("test_broker.sock");
            // SAFETY: single-threaded tests; no other thread reads this var.
            unsafe {
                std::env::set_var(TEST_BROKER_SOCKET_ENV, socket_path.as_os_str());
            }
            let resolved = resolve_broker_socket_path();
            assert_eq!(resolved, socket_path);
            // SAFETY: single-threaded tests.
            unsafe { std::env::remove_var(TEST_BROKER_SOCKET_ENV) };
        }
    }
}
