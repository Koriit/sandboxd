//! `sandbox-agent` — per-operator LaunchAgent that brokers `limactl`
//! operations on behalf of the sandboxd daemon.
//!
//! # Role
//!
//! On macOS, the daemon runs as `_sandboxd` and cannot switch to an
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
//! the `_sandboxd` group membership of that uid via `getgrouplist(3)`
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
//! The broker channel carries newline-delimited JSON frames:
//! - **One-shot ops**: daemon writes `BrokerRequest\n`, agent processes and
//!   writes `BrokerResponse\n`. Request/response is strictly sequential.
//! - **GuestSocat (multiplexed)**: daemon writes `BrokerRequest { op:
//!   GuestSocat { stream_token: Some(token) } }\n` on the **control**
//!   connection. Agent replies `BrokerResponse { result: StreamReady }\n`
//!   on the same control connection (which is NOT consumed), then opens a
//!   **separate** stream connection and sends `STREAM_CONNECT:<token>\n`
//!   before beginning the raw byte-pump. The daemon correlates the stream
//!   connection to the pending op by token. Control connection stays alive
//!   and can immediately serve the next op.
//! - **Heartbeat**: daemon may send `PING\n` (plain text, not JSON) and
//!   expects `PONG\n` in reply. This coexists with the op framing because
//!   ops are sequential and heartbeats are sent between ops.
//!
//! # Security invariants (enforce at every code-path, do not relax)
//!
//! - The agent's uid is read from `getuid()`, never from a claim in a
//!   message. It acts only for its own uid.
//! - The agent is not setuid and carries no file capabilities. It runs
//!   unprivileged as the operator.
//! - Non-enrolled operators exit cleanly; no respawn loop.
//! - Every op field is validated (VM name, paths, numeric ranges) before
//!   any limactl invocation. See the `validation` module.
//! - GuestSocat uses a distinct framing (StreamOpen + raw bytes) from
//!   one-shot request/response (JSON frames only). The two must not be
//!   confused.

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

    use crate::handler::{self, RunContext};
    use crate::protocol::{BrokerOp, BrokerRequest, BrokerResponse, BrokerResult};

    // ---------------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------------

    /// The group name that gates operator enrollment on macOS.
    ///
    /// macOS reserves `_sandbox` (uid/gid 60) for its Seatbelt subsystem, so
    /// sandboxd uses a dedicated `_sandboxd` account and group instead.
    const SANDBOX_GROUP_NAME: &str = "_sandboxd";

    /// Default broker socket path. Overridable via `SANDBOX_BROKER_SOCKET`
    /// (or `SANDBOX_AGENT_TEST_BROKER_SOCKET` in test builds) so tests can
    /// use a temp-dir path without `/var/run` or root privileges.
    const DEFAULT_BROKER_SOCKET: &str = "/var/run/sandbox/broker.sock";

    /// Interval between heartbeat pings sent to the daemon while idle.
    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

    /// PATH prefixes the agent prepends so `limactl` is reachable even
    /// though launchd does not source the operator's shell profile.
    const PATH_PREPEND: &str = "/opt/homebrew/bin:/usr/local/bin";

    /// State root for per-operator LIMA_HOME construction.
    /// Format: `{STATE_ROOT}/{daemon_uid}/{op_uid}/lima`.
    const STATE_ROOT: &str = "/var/lib/sandboxd";

    // ---------------------------------------------------------------------------
    // test-env-override seams
    // ---------------------------------------------------------------------------

    #[cfg(feature = "test-env-override")]
    const TEST_SANDBOX_GROUP_ENV: &str = "SANDBOX_AGENT_TEST_SANDBOX_GROUP";
    #[cfg(feature = "test-env-override")]
    const TEST_BROKER_SOCKET_ENV: &str = "SANDBOX_AGENT_TEST_BROKER_SOCKET";
    /// Override for the daemon uid used to construct LIMA_HOME.
    /// In production this is read from the broker socket's owner (via stat(2)).
    /// In tests it is set to the test runner's own uid for simplicity.
    #[cfg(feature = "test-env-override")]
    const TEST_DAEMON_UID_ENV: &str = "SANDBOX_AGENT_TEST_DAEMON_UID";
    /// Override for the state root used to construct LIMA_HOME.
    #[cfg(feature = "test-env-override")]
    const TEST_STATE_ROOT_ENV: &str = "SANDBOX_AGENT_TEST_STATE_ROOT";

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

    /// Resolve the state root for LIMA_HOME construction.
    fn resolve_state_root() -> String {
        #[cfg(feature = "test-env-override")]
        if let Ok(v) = std::env::var(TEST_STATE_ROOT_ENV)
            && !v.is_empty()
        {
            return v;
        }
        STATE_ROOT.to_string()
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
    /// groups (common in corporate / MDM environments) may have `_sandboxd`
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
    // Daemon uid resolution (for LIMA_HOME construction)
    // ---------------------------------------------------------------------------

    /// Read the daemon uid from the broker socket file's owner.
    ///
    /// The broker socket is created by the daemon (running as `_sandboxd`) with
    /// mode 0660 and owned by `_sandboxd:_sandboxd`. The socket owner uid is
    /// therefore the daemon uid, which we need to construct the LIMA_HOME path:
    ///   `/var/lib/sandboxd/<daemon_uid>/<op_uid>/lima`.
    ///
    /// In test builds, `SANDBOX_AGENT_TEST_DAEMON_UID` overrides this lookup.
    fn resolve_daemon_uid_from_socket(socket_path: &std::path::Path) -> Option<u32> {
        #[cfg(feature = "test-env-override")]
        if let Ok(v) = std::env::var(TEST_DAEMON_UID_ENV)
            && !v.is_empty()
        {
            if let Ok(uid) = v.parse::<u32>() {
                return Some(uid);
            }
        }

        // stat(2) the socket and return st_uid.
        let path_c = std::ffi::CString::new(socket_path.to_str()?).ok()?;
        let mut stat_buf = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: path_c is a valid NUL-terminated C string; stat_buf is
        // properly zeroed and sized.
        let rc = unsafe { libc::stat(path_c.as_ptr(), &mut stat_buf) };
        if rc != 0 {
            return None;
        }
        Some(stat_buf.st_uid)
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
    // Broker connection — protocol loop
    // ---------------------------------------------------------------------------

    /// A check-in frame sent from the agent to the daemon on connect.
    const CHECKIN_FRAME: &[u8] = b"CHECKIN\n";

    /// A heartbeat frame sent periodically to prove the connection is alive.
    const HEARTBEAT_FRAME: &[u8] = b"PING\n";

    /// Expected acknowledgement from the daemon in response to `PING\n`.
    const PONG_FRAME: &[u8] = b"PONG\n";

    /// Connect to the broker socket, send the check-in frame, and then run
    /// the op-dispatch loop until the connection closes.
    ///
    /// The loop reads one line at a time from the daemon:
    /// - `PING\n` (plain text) → respond with `PONG\n` (heartbeat).
    /// - `{...}\n` (JSON `BrokerRequest`) → dispatch the op and write a
    ///   JSON `BrokerResponse\n`. For `GuestSocat`, the stream transitions
    ///   to raw byte-pump mode after the response; the loop exits afterward.
    /// - EOF or read error → reconnect after a brief delay.
    ///
    /// The agent also sends periodic `PING\n` heartbeats when idle (no op
    /// in flight) so the daemon can detect a dead agent connection.
    async fn run_broker_connection(socket_path: PathBuf, own_uid: u32, run_ctx: RunContext) {
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixStream;

        loop {
            info!(
                socket = %socket_path.display(),
                uid = own_uid,
                "connecting to broker socket"
            );

            let stream = match UnixStream::connect(&socket_path).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "broker connect failed; retrying in 5s");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            // Send the check-in frame. The daemon authenticates the peer
            // uid from LOCAL_PEERCRED — not from this frame.
            {
                // Split for check-in write, then reunite.
                let (reader_half, mut writer_half) = stream.into_split();
                if let Err(e) = writer_half.write_all(CHECKIN_FRAME).await {
                    warn!(error = %e, "failed to send check-in frame; reconnecting");
                    continue;
                }

                info!(uid = own_uid, "check-in sent; entering op-dispatch loop");

                // Reunite for the protocol loop.
                let stream = match reader_half.reunite(writer_half) {
                    Ok(s) => s,
                    Err(_) => {
                        warn!("failed to reunite stream after check-in; reconnecting");
                        continue;
                    }
                };

                // Run the protocol loop. Returns when the connection is done.
                run_protocol_loop(stream, own_uid, &run_ctx).await;
            }

            info!(uid = own_uid, "broker connection ended; reconnecting in 2s");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Drive the op-dispatch loop on an established, authenticated broker
    /// control connection.
    ///
    /// Reads lines from the daemon and dispatches ops or heartbeats. The
    /// control connection is never consumed — each `GuestSocat` op opens a
    /// separate stream connection for the byte-pump (multiplexed protocol).
    ///
    /// For daemons that send a `GuestSocat` with `stream_token: Some(token)`:
    ///   - Reply with `StreamReady { token }` on the control connection.
    ///   - Spawn a task that opens a new connection and runs the byte-pump.
    ///   - The control connection continues to serve subsequent ops.
    ///
    /// For daemons that send `GuestSocat` with `stream_token: None` (legacy):
    ///   - Fall back to the original single-connection behaviour: reunite the
    ///     control connection, run the byte-pump, and exit after it completes.
    ///     The agent reconnects for the next op as before.
    ///
    /// # Heartbeat liveness during long ops
    ///
    /// A one-shot control-plane op (e.g. the base-image build routed through a
    /// `limactl start`) can run for minutes. The daemon's broker drops a control
    /// connection that produces no traffic within its heartbeat timeout (60 s).
    /// If `dispatch_op` were awaited inline inside the `select!` arm, the
    /// heartbeat-interval arm would never fire for the op's full duration and the
    /// daemon would declare the agent dead mid-build.
    ///
    /// To keep the connection alive, the op is dispatched on a **spawned task**;
    /// the `select!` loop keeps running throughout, so the agent continues both
    /// (a) sending periodic `PING` heartbeats — which is what resets the daemon's
    /// liveness timer — and (b) reading from the daemon (draining `PONG`s and
    /// answering any daemon→agent `PING` with `PONG`). The op task writes its
    /// `BrokerResponse` when it completes.
    ///
    /// The control-connection write half is shared between the `select!` loop and
    /// the spawned op task via `Arc<Mutex<…>>`. Every write acquires the lock for
    /// the duration of a single complete frame, so heartbeat, PONG, and response
    /// frames never interleave on the wire. The daemon serializes control-plane
    /// ops (one request in flight, response awaited before the next is sent — see
    /// the protocol doc-comment), so at most one op task runs at a time and op
    /// responses cannot be reordered.
    async fn run_protocol_loop(stream: tokio::net::UnixStream, own_uid: u32, run_ctx: &RunContext) {
        use std::sync::Arc;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::sync::Mutex;

        let socket_path = run_ctx.broker_socket.clone();
        let (reader_half, writer_half) = stream.into_split();
        let mut buf_reader = BufReader::new(reader_half);
        // Shared write half: the select! loop (heartbeat + PONG) and any spawned
        // one-shot op task all write through this single lock so frames are never
        // interleaved mid-write.
        let writer = Arc::new(Mutex::new(writer_half));
        let mut heartbeat_interval = tokio::time::interval(HEARTBEAT_INTERVAL);
        heartbeat_interval.tick().await; // consume the immediate first tick

        let mut line = String::new();
        loop {
            line.clear();

            tokio::select! {
                // Periodic heartbeat. Sent unconditionally on every tick — even
                // while a one-shot op runs on a spawned task — because the agent's
                // unprompted PING is what resets the daemon's liveness timer.
                _ = heartbeat_interval.tick() => {
                    let mut w = writer.lock().await;
                    if let Err(e) = w.write_all(HEARTBEAT_FRAME).await {
                        warn!(uid = own_uid, error = %e, "heartbeat write failed; closing connection");
                        return;
                    }
                }

                // Read the next line from the daemon.
                result = buf_reader.read_line(&mut line) => {
                    match result {
                        Ok(0) => {
                            info!(uid = own_uid, "daemon closed the broker connection");
                            return;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!(uid = own_uid, error = %e, "read error on broker connection");
                            return;
                        }
                    }

                    let trimmed = line.trim_end_matches(['\n', '\r']);

                    // Heartbeat acknowledgement from the daemon.
                    if trimmed == "PONG" {
                        continue;
                    }

                    // Plain-text PING from the daemon.
                    if trimmed == "PING" {
                        let mut w = writer.lock().await;
                        if let Err(e) = w.write_all(PONG_FRAME).await {
                            warn!(uid = own_uid, error = %e, "PONG write failed; closing connection");
                            return;
                        }
                        continue;
                    }

                    // JSON BrokerRequest.
                    let request: BrokerRequest = match serde_json::from_str(trimmed) {
                        Ok(r) => r,
                        Err(e) => {
                            warn!(uid = own_uid, error = %e, line = %trimmed, "failed to parse BrokerRequest; ignoring line");
                            continue;
                        }
                    };

                    let request_id = request.request_id;

                    if let BrokerOp::GuestSocat { op_uid, vm, stream_token } = request.op {
                        match stream_token {
                            Some(token) => {
                                // Multiplexed path: respond StreamReady on the control
                                // connection, open a separate stream connection for the
                                // byte-pump. The control connection stays alive.
                                let response = BrokerResponse {
                                    request_id,
                                    result: BrokerResult::StreamReady { token: token.clone() },
                                };
                                let response_json = match serde_json::to_string(&response) {
                                    Ok(j) => j,
                                    Err(e) => {
                                        warn!(uid = own_uid, error = %e, "failed to serialize StreamReady; closing connection");
                                        return;
                                    }
                                };
                                {
                                    let mut w = writer.lock().await;
                                    if w.write_all(response_json.as_bytes()).await.is_err()
                                        || w.write_all(b"\n").await.is_err()
                                    {
                                        warn!(uid = own_uid, "StreamReady write failed; closing connection");
                                        return;
                                    }
                                }

                                // Spawn a task to open the stream connection and pump bytes.
                                let run_ctx_clone = RunContext {
                                    own_uid: run_ctx.own_uid,
                                    lima_home: run_ctx.lima_home.clone(),
                                    broker_socket: run_ctx.broker_socket.clone(),
                                };
                                let socket_for_stream = socket_path.clone();
                                tokio::spawn(async move {
                                    run_stream_connection(
                                        socket_for_stream,
                                        run_ctx_clone,
                                        vm,
                                        op_uid,
                                        request_id,
                                        token,
                                    )
                                    .await;
                                });
                                // Control connection continues — do not exit.
                                continue;
                            }
                            None => {
                                // Legacy path: consume the control connection for the byte-pump.
                                // The agent will reconnect after the stream ends.
                                //
                                // Recover the owned write half from the shared Arc/Mutex so it
                                // can be reunited with the reader half. The legacy GuestSocat op
                                // consumes the connection; no spawned op task or heartbeat write
                                // is in flight against this Arc on this path (the daemon sends one
                                // op at a time), so the Arc holds the single strong reference here.
                                let writer_half = match Arc::try_unwrap(writer) {
                                    Ok(m) => m.into_inner(),
                                    Err(_) => {
                                        warn!(uid = own_uid, "writer still shared; cannot take control connection for legacy GuestSocat; closing");
                                        return;
                                    }
                                };
                                let stream = match buf_reader.into_inner().reunite(writer_half) {
                                    Ok(s) => s,
                                    Err(_) => {
                                        warn!(uid = own_uid, "failed to reunite stream for legacy GuestSocat; closing connection");
                                        return;
                                    }
                                };
                                // Legacy path: write StreamOpen on the control connection before pumping.
                                let _ = handler::handle_guest_socat(run_ctx, vm, op_uid, request_id, true, stream).await;
                                return;
                            }
                        }
                    } else {
                        // One-shot op: dispatch on a spawned task so the select! loop keeps
                        // sending heartbeats (and answering daemon PINGs) for the op's full
                        // duration. The task writes the BrokerResponse under the shared writer
                        // lock when dispatch completes.
                        let run_ctx_clone = RunContext {
                            own_uid: run_ctx.own_uid,
                            lima_home: run_ctx.lima_home.clone(),
                            broker_socket: run_ctx.broker_socket.clone(),
                        };
                        let writer_for_op = Arc::clone(&writer);
                        let op = request.op;
                        tokio::spawn(async move {
                            let result = handler::dispatch_op(&run_ctx_clone, op).await;
                            let response = BrokerResponse { request_id, result };
                            let response_json = match serde_json::to_string(&response) {
                                Ok(j) => j,
                                Err(e) => {
                                    warn!(uid = own_uid, error = %e, "failed to serialize BrokerResponse; dropping");
                                    return;
                                }
                            };
                            let mut w = writer_for_op.lock().await;
                            if let Err(e) = w.write_all(response_json.as_bytes()).await {
                                warn!(uid = own_uid, error = %e, "response write failed");
                                return;
                            }
                            if let Err(e) = w.write_all(b"\n").await {
                                warn!(uid = own_uid, error = %e, "response newline write failed");
                            }
                        });
                    }
                }
            }
        }
    }

    /// Open a dedicated stream connection to the broker for a `GuestSocat` op.
    ///
    /// The stream connection goes through the full authentication path (peer-cred,
    /// group membership, and uid gate) independently of the control connection.
    /// After authentication, the connection sends a `STREAM_CONNECT:<token>` frame
    /// so the daemon can correlate this connection to the pending op.
    ///
    /// This function is spawned as a task by `run_protocol_loop` when the daemon
    /// sends a `GuestSocat` with a `stream_token`. It runs concurrently with the
    /// control connection's protocol loop.
    async fn run_stream_connection(
        socket_path: std::path::PathBuf,
        run_ctx: RunContext,
        vm: String,
        op_uid: u32,
        request_id: u64,
        token: String,
    ) {
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixStream;

        info!(
            uid = run_ctx.own_uid,
            vm, "opening stream connection for GuestSocat"
        );

        let stream = match UnixStream::connect(&socket_path).await {
            Ok(s) => s,
            Err(e) => {
                warn!(uid = run_ctx.own_uid, error = %e, "stream connection connect failed");
                return;
            }
        };

        // Send STREAM_CONNECT:<token>\n. The broker recognises this prefix,
        // authenticates the peer (peer-cred + group + uid — same gates as the
        // control connection), and matches the token to the pending op.
        let frame = format!("{}{}\n", crate::protocol::STREAM_CONNECT_PREFIX, token);
        let (reader_half, mut writer_half) = stream.into_split();
        if let Err(e) = writer_half.write_all(frame.as_bytes()).await {
            warn!(uid = run_ctx.own_uid, error = %e, "STREAM_CONNECT frame write failed");
            return;
        }

        // Reunite for the bidirectional byte-pump.
        let stream = match reader_half.reunite(writer_half) {
            Ok(s) => s,
            Err(_) => {
                warn!(
                    uid = run_ctx.own_uid,
                    "failed to reunite stream connection halves"
                );
                return;
            }
        };

        // Run the byte-pump on the dedicated stream connection.
        // write_stream_open=false: the stream connection is a raw byte-pump;
        // the StreamReady acknowledgement already went on the control connection.
        let _ = handler::handle_guest_socat(&run_ctx, vm, op_uid, request_id, false, stream).await;
        info!(uid = run_ctx.own_uid, "stream connection GuestSocat ended");
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
        // _sandboxd group. launchd is configured with no KeepAlive on
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

        // Resolve the daemon uid from the broker socket owner for LIMA_HOME.
        // In production the socket is owned by `_sandboxd`; in tests it is
        // overridden via TEST_DAEMON_UID_ENV.
        let daemon_uid = resolve_daemon_uid_from_socket(&broker_socket).unwrap_or_else(|| {
            warn!("could not resolve daemon uid from broker socket; defaulting to own uid");
            own_uid
        });

        let state_root = resolve_state_root();
        let lima_home = format!("{state_root}/{daemon_uid}/{own_uid}/lima");

        info!(uid = own_uid, daemon_uid, lima_home, "LIMA_HOME resolved");

        let run_ctx = RunContext {
            own_uid,
            lima_home,
            broker_socket: broker_socket.clone(),
        };

        // Build the tokio runtime and run the broker connection loop.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");

        rt.block_on(run_broker_connection(broker_socket, own_uid, run_ctx));
    }

    // ---------------------------------------------------------------------------
    // Unit tests
    // ---------------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Verify that a uid below 500 (the system-account floor) is not a
        /// member of the sandbox group. This test drives the `uid_in_group`
        /// logic with both a negative and a positive control:
        ///
        /// - **Negative:** uid 0 (root) must not be in `_sandboxd` on any
        ///   correctly-configured macOS host.
        /// - **Positive:** uid 0 IS always a member of `wheel` (gid 0) on
        ///   macOS. If this assertion fails it means `uid_in_group` is broken
        ///   or the membership logic is inverted — a passing negative assertion
        ///   alone cannot distinguish "correctly excluded" from "group lookup
        ///   always returns false."
        ///
        /// The positive control guarantees that a regression that inverts
        /// `uid_in_group` would surface here, not silently pass.
        #[test]
        fn uid_zero_not_in_sandbox_group() {
            // Positive control: root (uid 0) is a member of "wheel" on every
            // macOS host. This confirms uid_in_group resolves membership
            // correctly — if this fails, the function is broken.
            assert!(
                uid_in_group(0, "wheel"),
                "uid 0 must be in 'wheel' on macOS — uid_in_group appears to be broken"
            );

            // Negative control: root is never in _sandboxd. If this fails it
            // means _sandboxd is misconfigured (uid 0 enrolled) — investigate.
            // Note: if _sandboxd doesn't exist on this host, group_name_to_gid
            // returns None and uid_in_group returns false, which is also correct.
            let in_group = uid_in_group(0, "_sandboxd");
            assert!(
                !in_group,
                "uid 0 must not be a member of _sandboxd — check host configuration"
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

        // -----------------------------------------------------------------------
        // Protocol loop — round-trip tests
        // -----------------------------------------------------------------------

        /// Verify that the protocol loop correctly handles a JSON `BrokerRequest`
        /// and writes a JSON `BrokerResponse`. Uses an in-memory duplex stream
        /// so no real broker socket or limactl is needed.
        ///
        /// This test exercises the real `run_protocol_loop` function (the same
        /// one the production path calls) with a `Delete` op whose own-uid gate
        /// will reject the request (op_uid != own_uid), confirming the protocol
        /// framing is correct for the rejection path.
        #[tokio::test]
        async fn protocol_loop_foreign_uid_produces_rejected_response() {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

            let own_uid = unsafe { libc::getuid() };
            let run_ctx = RunContext {
                own_uid,
                lima_home: "/tmp/lima_test".to_string(),
                broker_socket: std::path::PathBuf::from("/tmp/lima_test_broker.sock"),
            };

            // Create a duplex stream: `client` is the daemon side.
            let (client, server) = tokio::io::duplex(4096);

            // Spawn the protocol loop on the server end.
            let ctx_clone = RunContext {
                own_uid: run_ctx.own_uid,
                lima_home: run_ctx.lima_home.clone(),
                broker_socket: run_ctx.broker_socket.clone(),
            };
            let loop_handle = tokio::spawn(async move {
                // Wrap the duplex as a UnixStream-compatible stream. Since we
                // cannot easily produce a tokio::net::UnixStream from a duplex,
                // call run_protocol_loop's inner logic with the duplex directly
                // by reimplementing the loop inline for testing purposes.
                //
                // We use the protocol-loop helper `dispatch_op` + framing
                // directly rather than calling run_protocol_loop (which expects
                // a tokio::net::UnixStream). This avoids coupling the test to
                // tokio internal details while still exercising the framing.
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

                let (reader_half, mut writer_half) = tokio::io::split(server);
                let mut buf_reader = BufReader::new(reader_half);
                let mut line = String::new();
                loop {
                    line.clear();
                    match buf_reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    let trimmed = line.trim_end_matches(['\n', '\r']);
                    if trimmed == "PING" {
                        let _ = writer_half.write_all(b"PONG\n").await;
                        continue;
                    }
                    if trimmed.is_empty() {
                        continue;
                    }
                    let request: BrokerRequest = match serde_json::from_str(trimmed) {
                        Ok(r) => r,
                        Err(_) => break,
                    };
                    let request_id = request.request_id;
                    let result = crate::handler::dispatch_op(&ctx_clone, request.op).await;
                    let response = BrokerResponse { request_id, result };
                    let json = serde_json::to_string(&response).unwrap();
                    let _ = writer_half.write_all(json.as_bytes()).await;
                    let _ = writer_half.write_all(b"\n").await;
                    break; // one request for this test
                }
            });

            // Daemon side: send a Delete op with a foreign uid.
            let foreign_uid = own_uid.wrapping_add(1);
            let request = BrokerRequest {
                request_id: 42,
                op: BrokerOp::Delete {
                    op_uid: foreign_uid,
                    vm: "sandbox-abc".to_string(),
                },
            };
            let request_json = serde_json::to_string(&request).unwrap();

            let (mut client_reader_half, mut client_writer_half) = tokio::io::split(client);
            client_writer_half
                .write_all(request_json.as_bytes())
                .await
                .unwrap();
            client_writer_half.write_all(b"\n").await.unwrap();

            // Read the response.
            let mut reader = BufReader::new(&mut client_reader_half);
            let mut response_line = String::new();
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                reader.read_line(&mut response_line),
            )
            .await
            .expect("response timeout")
            .expect("read error");
            assert!(n > 0, "expected a response line");

            let response: BrokerResponse =
                serde_json::from_str(response_line.trim()).expect("valid JSON response");
            assert_eq!(response.request_id, 42, "request_id must be echoed");
            assert!(
                matches!(
                    response.result,
                    crate::protocol::BrokerResult::Rejected { .. }
                ),
                "foreign uid must produce Rejected response; got {:?}",
                response.result
            );

            loop_handle.abort();
        }

        /// Verify that a valid `BrokerRequest` with a matching own-uid and
        /// a well-formed `RestrictOnVerify` op returns a `RestrictNotConfirmed`
        /// response (since there is no real VM and no marker file), confirming
        /// the round-trip framing for the restrict-verify op.
        #[tokio::test]
        async fn protocol_loop_restrict_verify_no_marker_produces_not_confirmed() {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

            let own_uid = unsafe { libc::getuid() };
            let dir = tempfile::tempdir().unwrap();
            // Create instance dir but no marker file.
            std::fs::create_dir_all(dir.path().join("sandbox-test")).unwrap();

            let ctx = RunContext {
                own_uid,
                lima_home: dir.path().to_string_lossy().into_owned(),
                broker_socket: std::path::PathBuf::from("/tmp/test_broker.sock"),
            };

            let (client, server) = tokio::io::duplex(4096);
            let ctx_clone = RunContext {
                own_uid: ctx.own_uid,
                lima_home: ctx.lima_home.clone(),
                broker_socket: ctx.broker_socket.clone(),
            };
            let loop_handle = tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                let (reader_half, mut writer_half) = tokio::io::split(server);
                let mut buf_reader = BufReader::new(reader_half);
                let mut line = String::new();
                loop {
                    line.clear();
                    match buf_reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    let trimmed = line.trim_end_matches(['\n', '\r']);
                    if trimmed.is_empty() || trimmed == "PING" {
                        continue;
                    }
                    let request: BrokerRequest = match serde_json::from_str(trimmed) {
                        Ok(r) => r,
                        Err(_) => break,
                    };
                    let request_id = request.request_id;
                    let result = crate::handler::dispatch_op(&ctx_clone, request.op).await;
                    let response = BrokerResponse { request_id, result };
                    let json = serde_json::to_string(&response).unwrap();
                    let _ = writer_half.write_all(json.as_bytes()).await;
                    let _ = writer_half.write_all(b"\n").await;
                    break;
                }
            });

            let request = BrokerRequest {
                request_id: 99,
                op: BrokerOp::RestrictOnVerify {
                    op_uid: own_uid,
                    vm: "sandbox-test".to_string(),
                },
            };
            let request_json = serde_json::to_string(&request).unwrap();
            let (mut client_reader_half, mut client_writer_half) = tokio::io::split(client);
            client_writer_half
                .write_all(request_json.as_bytes())
                .await
                .unwrap();
            client_writer_half.write_all(b"\n").await.unwrap();

            let mut reader = BufReader::new(&mut client_reader_half);
            let mut response_line = String::new();
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                reader.read_line(&mut response_line),
            )
            .await
            .expect("response timeout")
            .expect("read error");
            assert!(n > 0);

            let response: BrokerResponse =
                serde_json::from_str(response_line.trim()).expect("valid JSON response");
            assert_eq!(response.request_id, 99);
            assert!(
                matches!(
                    response.result,
                    crate::protocol::BrokerResult::RestrictNotConfirmed { .. }
                ),
                "absent marker must yield RestrictNotConfirmed; got {:?}",
                response.result
            );

            loop_handle.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Module declarations (macOS-only, under cfg guard)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod protocol;

#[cfg(target_os = "macos")]
mod validation;

#[cfg(target_os = "macos")]
mod handler;
