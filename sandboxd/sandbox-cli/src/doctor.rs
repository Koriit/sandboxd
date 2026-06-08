//! `sandbox doctor` — operator-facing diagnostic surface.
//!
//! `doctor` is the single command an operator runs after install
//! (or when something feels off) to verify every load-bearing
//! invariant the daemon depends on: the systemd unit is active, the
//! socket is reachable, the CLI matches the daemon version, the
//! caller's account is in the `sandbox` group, the socket has the
//! expected mode, KVM is reachable from the daemon's uid, both
//! container images are present, the route-helper has its `setcap`
//! capability, the state-dir has the expected mode, `users.conf`
//! parses + names the daemon's uid, no running session is on a
//! drift'd guest protocol, and no substrate resources are orphaned.
//!
//! The check inventory (C1-C13) is enumerated in the daemon-
//! productionization.2. The output format is pinned in
//! Three exact-text examples pin the output format, and it is
//! load-bearing for the integration tests. Message tokens, glyphs,
//! indentation, and the summary-line wording are byte-for-byte stable.
//!
//! # Execution shape
//!
//! Two phases per.6:
//!
//! 1. Serial — C1 (daemon running) and C2 (socket reachable). If
//!    either fails, every downstream check that requires a running
//!    daemon is short-circuited to `SKIPPED (requires daemon)`. C4
//!    (group membership), C9 (route-helper caps), and C10 (state-dir
//!    mode) can still run because they only consult host state.
//! 2. Parallel — C3-C13 fan out via `tokio::task::JoinSet` so the
//!    HTTP-bound checks (C3, C6-C8, C11-C13) and the host-side checks
//!    (C4, C9, C10) execute concurrently. `GET /diagnostics` is
//!    fetched once before the fan-out and shared via `Arc` so the
//!    daemon-side checks do not refetch. Results are reimposed in
//!    canonical order (C3 first, C13 last) before the formatter
//!    walks the table — fan-out completion order is non-deterministic
//!    but the rendered report is byte-stable.
//!
//! # Exit codes
//!
//! - `0` — every check is `Pass` or `Skip` (skips never fail the run).
//! - `1` — at least one check is `Fail`.
//! - `2` — `doctor` itself could not run (config parse, socket-path
//!   resolution panic, etc.). Distinct from `1` so wrapper scripts
//!   can disambiguate "daemon broken" from "doctor broken".
//!
//! # Dev-mode degradation
//!
//! C4 (current user in `sandbox` group), C5 (socket perms), and
//! C10 (state-dir mode) are system-service-specific. On a dev box
//! (`make setup-dev-env`) there is no `sandbox` system user and no
//! systemd `StateDirectory`, so these checks emit informational
//! `Skip` rather than `Fail` — the dev workflow still passes the
//! summary line.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// Internal-error type
// ---------------------------------------------------------------------------

/// `doctor` itself could not run. Surfaces to `process::exit(2)`, distinct from exit-1 ("daemon-side check failed") so
/// operator scripts can disambiguate "doctor broken" from "deployment
/// broken".
///
/// Sources of internal failure:
/// * `SocketPathUnresolvable` — neither `SANDBOX_SOCKET` nor
///   `XDG_RUNTIME_DIR` nor `HOME` yielded a path. Default fallback
///   to `/tmp` is wrong for diagnostics; we want the operator to
///   see the env-var misconfiguration explicitly.
/// * `Panic` — a check panicked. The renderer or any spawned check
///   that hits an unrecoverable bug should not pretend the rest of
///   the report is valid; we route to exit 2 so CI catches it.
#[derive(Debug)]
pub enum DoctorInternalError {
    /// Neither `SANDBOX_SOCKET`, `XDG_RUNTIME_DIR`, nor `HOME` is set —
    /// the doctor cannot decide which socket to probe.
    SocketPathUnresolvable {
        /// Operator-facing message describing the missing inputs.
        reason: String,
    },
    /// A check or the renderer panicked. The captured payload is best-
    /// effort (panics often carry `&'static str` or `String`).
    Panic {
        /// Best-effort string form of the panic payload.
        message: String,
    },
}

impl std::fmt::Display for DoctorInternalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketPathUnresolvable { reason } => {
                write!(f, "doctor: cannot resolve socket path: {reason}")
            }
            Self::Panic { message } => write!(f, "doctor: internal panic: {message}"),
        }
    }
}

impl std::error::Error for DoctorInternalError {}

/// Strict socket-path resolver for the doctor entry point.
///
/// Matches `default_socket_path` in `main.rs` *except* that it surfaces
/// the "no env vars set" case as a [`DoctorInternalError`] rather than
/// silently falling back to `/tmp`. The fallback is fine for normal CLI
/// commands (they will fail to connect and report a clean error), but
/// doctor's job is to diagnose deployments — guessing a path here
/// would mask the actual misconfiguration.
///
/// Precedence: `SANDBOX_SOCKET` (any non-empty value) >
/// `/run/sandbox/sandboxd.sock` (the system-service daemon, if present) >
/// `XDG_RUNTIME_DIR` > `HOME`. With none set/present, returns `Err`.
pub fn resolve_socket_path_strict() -> Result<String, DoctorInternalError> {
    resolve_socket_path_strict_with(
        |name| std::env::var(name).ok(),
        |p| std::path::Path::new(p).exists(),
    )
}

/// Pure inner of [`resolve_socket_path_strict`], parameterised over the
/// env-var lookup AND an existence predicate so unit tests can drive both
/// without mutating real process env state or touching the filesystem (which
/// would race with other concurrent tests under cargo's threaded runner).
pub(crate) fn resolve_socket_path_strict_with<F, G>(
    get: F,
    exists: G,
) -> Result<String, DoctorInternalError>
where
    F: Fn(&str) -> Option<String>,
    G: Fn(&str) -> bool,
{
    if let Some(sock) = get("SANDBOX_SOCKET")
        && !sock.is_empty()
    {
        return Ok(sock);
    }
    // System-service daemon, probed first (mirrors `default_socket_path` in
    // main.rs) so doctor diagnoses the deployed daemon rather than a stale
    // XDG path that the system daemon never binds.
    if exists(crate::SYSTEM_SOCKET_PATH) {
        return Ok(crate::SYSTEM_SOCKET_PATH.to_string());
    }
    if let Some(runtime_dir) = get("XDG_RUNTIME_DIR")
        && !runtime_dir.is_empty()
    {
        return Ok(format!("{runtime_dir}/sandboxd/sandboxd.sock"));
    }
    if let Some(home) = get("HOME")
        && !home.is_empty()
    {
        return Ok(format!("{home}/.local/share/sandboxd/sandboxd.sock"));
    }
    Err(DoctorInternalError::SocketPathUnresolvable {
        reason: "neither SANDBOX_SOCKET, /run/sandbox/sandboxd.sock, \
                 XDG_RUNTIME_DIR, nor HOME yielded a path"
            .to_string(),
    })
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the full doctor pipeline against the daemon reachable at
/// `socket_path` and write the formatted report to stdout. Returns
/// the process exit code (0 = all pass/skip, 1 = any fail, 2 = doctor itself failed).
///
/// `verbose=false` suppresses passing rows so the operator sees only
/// the actionable failures + skips; `verbose=true` echoes every row.
/// In both modes the summary line is always rendered.
///
/// Returns `Err(DoctorInternalError)` when doctor itself cannot run
/// (socket path unresolvable, renderer panicked, etc.); the caller is
/// responsible for mapping that to `process::exit(2)`.
pub async fn run(socket_path: &str, verbose: bool) -> Result<i32, DoctorInternalError> {
    let outcomes = execute_checks(socket_path).await;
    // The renderer is synchronous and writes to stdout; wrap in
    // `catch_unwind` so a panic in formatting routes to exit-2 rather
    // than aborting the process with code 101. `AssertUnwindSafe` is
    // safe here because nothing the renderer touches is observed after
    // the panic boundary (stdout is line-buffered; on panic we flush
    // best-effort and propagate).
    let render_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut out = std::io::stdout().lock();
        let exit_code = render_report(&mut out, &outcomes, verbose);
        let _ = std::io::Write::flush(&mut out);
        exit_code
    }));
    match render_result {
        Ok(code) => Ok(code),
        Err(payload) => Err(DoctorInternalError::Panic {
            message: panic_payload_to_string(&payload),
        }),
    }
}

/// Best-effort stringification of a `catch_unwind` payload. Panics
/// most commonly carry `&'static str` or `String`; anything else is
/// reported as `<non-string panic payload>`.
fn panic_payload_to_string(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

// ---------------------------------------------------------------------------
// Check trait and outcome shape
// ---------------------------------------------------------------------------

/// One row in the doctor report.
///
/// Each check produces exactly one [`CheckOutcome`]; the formatter
/// translates that into a `✓`/`~`/`✗` prefix, the check's display
/// name, and (for skips/failures) a `detail` and optional `hint` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// Check passed. `detail` is rendered in `--verbose` mode as the
    /// parenthetical after the check name (e.g.
    /// `✓ KVM accessible    (/dev/kvm readable+writable by daemon)`).
    Pass { detail: String },
    /// Check was skipped (informational). Skips do not contribute to
    /// the exit-code-1 condition. `detail` is the bracketed reason
    /// rendered after `SKIPPED`; `hint` is an optional indented
    /// follow-up line.
    Skip {
        detail: String,
        hint: Option<String>,
    },
    /// Check failed. Failures aggregate to exit code `1`. `detail`
    /// is the parenthetical after the check name; `hint` is an
    /// indented follow-up line operators can copy-paste.
    Fail {
        detail: String,
        hint: Option<String>,
    },
}

/// One row's metadata + result. The formatter consumes `Vec<CheckRow>`
/// — `id` orders the output deterministically, `name` is the operator-
/// visible label, and `outcome` is the verdict.
#[derive(Debug, Clone)]
pub struct CheckRow {
    /// Stable identifier, e.g. `"C1"`, used in tests and structured
    /// log fields. The operator-facing output uses `name`, not `id`.
    pub id: &'static str,
    /// Operator-visible label, displayed verbatim in the report.
    pub name: &'static str,
    pub outcome: CheckOutcome,
}

// ---------------------------------------------------------------------------
// Two-phase execution
// ---------------------------------------------------------------------------

/// Default HTTP timeout for daemon probes during doctor. Each parallel
/// check has its own ceiling; the value is deliberately tight so a
/// hung daemon does not stall doctor.
const DOCTOR_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve the `(serial, parallel)` phase outputs in canonical order.
///
/// Public-in-crate so the unit tests in `mod tests` can exercise the
/// runner directly. The wrapper [`run`] composes this with the
/// formatter and stdout sink.
///
/// Phase 1 (serial, gating): C1, C2. If C2 fails the daemon-side
/// checks short-circuit to `SKIPPED (requires daemon)`.
/// Phase 2 (parallel): C3-C13 are spawned concurrently on a
/// [`tokio::task::JoinSet`]; the shared `/diagnostics` payload is
/// fetched once before the fan-out and shared via `Arc`. After all
/// tasks join, results are sorted by check id so the rendered output
/// is byte-stable regardless of completion order.
pub(crate) async fn execute_checks(socket_path: &str) -> Vec<CheckRow> {
    let mut rows: Vec<CheckRow> = Vec::with_capacity(13);

    // Phase 1 — serial gating.
    let c1 = check_daemon_running(socket_path).await;
    let daemon_running = matches!(c1.outcome, CheckOutcome::Pass { .. });
    rows.push(c1);

    let c2 = if daemon_running {
        check_socket_reachable(socket_path).await
    } else {
        CheckRow {
            id: "C2",
            name: "daemon reachable",
            outcome: CheckOutcome::Skip {
                detail: "requires daemon".to_string(),
                hint: None,
            },
        }
    };
    let socket_reachable = matches!(c2.outcome, CheckOutcome::Pass { .. });
    rows.push(c2);

    // Phase 2 — parallel fan-out. Diagnostics payload is fetched once
    // *before* the fan-out so the daemon-side checks (C6, C7, C8, C11,
    // C12, C13) share a single HTTP round-trip via `Arc`.
    let diagnostics: Arc<Option<DiagnosticsPayload>> = Arc::new(if socket_reachable {
        fetch_diagnostics(socket_path).await
    } else {
        None
    });

    let mut set: tokio::task::JoinSet<CheckRow> = tokio::task::JoinSet::new();

    // C3 — async (HTTP).
    {
        let socket = socket_path.to_string();
        set.spawn(async move { check_version_match(&socket, socket_reachable).await });
    }
    // C4 — sync (group lookup); push through `spawn_blocking` so the
    // fan-out is genuinely concurrent rather than parking the runtime.
    set.spawn_blocking(check_group_membership);
    // C5 — sync (stat on the unix socket).
    {
        let socket = socket_path.to_string();
        set.spawn_blocking(move || check_socket_perms(&socket, socket_reachable));
    }
    // C6 — sync transform over the shared diagnostics payload.
    {
        let diag = Arc::clone(&diagnostics);
        set.spawn_blocking(move || check_kvm_accessible(diag.as_ref().as_ref(), socket_reachable));
    }
    // C7
    {
        let diag = Arc::clone(&diagnostics);
        set.spawn_blocking(move || check_gateway_image(diag.as_ref().as_ref(), socket_reachable));
    }
    // C8
    {
        let diag = Arc::clone(&diagnostics);
        set.spawn_blocking(move || check_lite_image(diag.as_ref().as_ref(), socket_reachable));
    }
    // C9 — sync (forks `getcap`).
    set.spawn_blocking(check_route_helper_caps);
    // C10 — sync (stat on per-uid base-dir, legacy fallback).
    set.spawn_blocking(check_state_dir_mode);
    // C11
    {
        let diag = Arc::clone(&diagnostics);
        set.spawn_blocking(move || check_users_conf_pool(diag.as_ref().as_ref(), socket_reachable));
    }
    // C12
    {
        let diag = Arc::clone(&diagnostics);
        set.spawn_blocking(move || {
            check_guest_version_drift(diag.as_ref().as_ref(), socket_reachable)
        });
    }
    // C13
    {
        let diag = Arc::clone(&diagnostics);
        set.spawn_blocking(move || {
            check_substrate_orphans(diag.as_ref().as_ref(), socket_reachable)
        });
    }

    // Drain the JoinSet; a panicking task surfaces as a `JoinError`
    // and is re-raised here so [`run`]'s `catch_unwind` boundary routes
    // it to exit code 2.
    let mut parallel: Vec<CheckRow> = Vec::with_capacity(11);
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(row) => parallel.push(row),
            Err(e) => {
                if e.is_panic() {
                    std::panic::resume_unwind(e.into_panic());
                }
                // Cancelled task (only happens on JoinSet drop or
                // explicit abort, neither applies here). Treat as a
                // panic so it routes to exit 2 rather than silently
                // dropping a check row.
                panic!("doctor parallel check cancelled unexpectedly: {e}");
            }
        }
    }

    // Reimpose canonical order (C3, C4, ..., C13) so the rendered
    // report is byte-stable regardless of completion order.
    parallel.sort_by_key(|row| check_id_ordinal(row.id));
    rows.extend(parallel);

    rows
}

/// Canonical sort key for check ids. Maps `"C3"` -> 3, `"C13"` -> 13.
/// Unknown ids sort to the end so test fixtures with synthetic ids
/// stay deterministic instead of panicking.
fn check_id_ordinal(id: &str) -> u32 {
    id.strip_prefix('C')
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(u32::MAX)
}

// ---------------------------------------------------------------------------
// Individual checks — C1, C2 (serial)
// ---------------------------------------------------------------------------

/// C1 — daemon process running.
///
/// Production deployments run sandboxd via systemd; we first ask
/// `systemctl is-active sandboxd`. On dev boxes (no unit installed),
/// `systemctl` reports `inactive` or `not-found` — both fall through
/// to a `connect()` probe, which succeeds when the developer is
/// running sandboxd by hand in another terminal. The two-step
/// fallback is the dev-mode degradation rule.
async fn check_daemon_running(socket_path: &str) -> CheckRow {
    let systemd_state = systemctl_is_active("sandboxd");
    if let Some(state) = systemd_state.as_deref()
        && state == "active"
    {
        return CheckRow {
            id: "C1",
            name: "daemon process running",
            outcome: CheckOutcome::Pass {
                detail: "sandboxd.service: active".to_string(),
            },
        };
    }

    // `inactive`, `failed`, and `not-found` all
    // fall through to the dev-mode `connect()` probe. The unit may
    // be installed but stopped while the operator is iterating with
    // a hand-launched daemon (typical `cargo run -p sandboxd` dev
    // loop). A reachable socket means a daemon is up regardless of
    // who's running it — that's the operative answer for `doctor`.
    match UnixStream::connect(socket_path).await {
        Ok(_) => {
            // Render a different detail string depending on whether
            // systemd had something to say — the operator should see
            // "we got the answer from the socket, not the unit"
            // without `~/.cli` parsing systemd output themselves.
            let detail = match systemd_state.as_deref() {
                Some("active") => format!("sandboxd.service: active ({socket_path})"),
                Some(other) => format!(
                    "dev mode: socket connectable ({socket_path}); \
                     systemctl reports `{other}`"
                ),
                None => format!("dev mode: socket connectable at {socket_path}"),
            };
            CheckRow {
                id: "C1",
                name: "daemon process running",
                outcome: CheckOutcome::Pass { detail },
            }
        }
        Err(e) => match systemd_state.as_deref() {
            Some(state @ ("inactive" | "failed" | "activating" | "deactivating")) => CheckRow {
                id: "C1",
                name: "daemon process running",
                outcome: CheckOutcome::Fail {
                    detail: format!("sandboxd.service: {state}"),
                    hint: Some(
                        "sudo systemctl status sandboxd; sudo journalctl -u sandboxd -n 50"
                            .to_string(),
                    ),
                },
            },
            _ => CheckRow {
                id: "C1",
                name: "daemon process running",
                outcome: CheckOutcome::Fail {
                    detail: format!("no systemd unit and {socket_path} unreachable: {e}"),
                    hint: Some(
                        "start sandboxd: sudo systemctl start sandboxd (or run \
                         `cargo run -p sandboxd` in dev mode)"
                            .to_string(),
                    ),
                },
            },
        },
    }
}

/// C2 — daemon reachable via its socket.
///
/// Distinct from C1: C1 establishes "a daemon is up somewhere"; C2
/// confirms our resolved socket path is the one accepting connections.
/// The two can disagree on dev boxes where multiple sandboxds run with
/// distinct sockets.
async fn check_socket_reachable(socket_path: &str) -> CheckRow {
    match UnixStream::connect(socket_path).await {
        Ok(_) => CheckRow {
            id: "C2",
            name: "daemon reachable",
            outcome: CheckOutcome::Pass {
                detail: socket_path.to_string(),
            },
        },
        Err(e) => CheckRow {
            id: "C2",
            name: "daemon reachable",
            outcome: CheckOutcome::Fail {
                detail: format!("connect({socket_path}): {e}"),
                hint: Some(
                    "socket missing or wrong perms; restart sandboxd: \
                     sudo systemctl restart sandboxd"
                        .to_string(),
                ),
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Individual checks — C3 (version)
// ---------------------------------------------------------------------------

/// C3 — CLI ↔ daemon version equality.
///
/// Calls `GET /version` and compares against the CLI's own
/// `CARGO_PKG_VERSION`. Doctor runs *through* the strict-equality
/// gate (the doctor subcommand bypasses `send_request_with_timeout`'s
/// version handshake) so the check itself surfaces the skew as a
/// failed row rather than refusing to run.
async fn check_version_match(socket_path: &str, socket_reachable: bool) -> CheckRow {
    let cli_version = env!("CARGO_PKG_VERSION");
    if !socket_reachable {
        return CheckRow {
            id: "C3",
            name: "CLI ↔ daemon version match",
            outcome: CheckOutcome::Skip {
                detail: "requires daemon".to_string(),
                hint: None,
            },
        };
    }
    match fetch_version(socket_path).await {
        Ok(daemon_version) if daemon_version == cli_version => CheckRow {
            id: "C3",
            name: "CLI ↔ daemon version match",
            outcome: CheckOutcome::Pass {
                detail: format!("{cli_version} == {daemon_version}"),
            },
        },
        Ok(daemon_version) => CheckRow {
            id: "C3",
            name: "CLI ↔ daemon version match",
            outcome: CheckOutcome::Fail {
                detail: format!("CLI={cli_version}, daemon={daemon_version}"),
                hint: Some(
                    "versions differ \u{2014} reinstall sandbox-cli and sandboxd together"
                        .to_string(),
                ),
            },
        },
        Err(e) => CheckRow {
            id: "C3",
            name: "CLI ↔ daemon version match",
            outcome: CheckOutcome::Fail {
                detail: format!("/version probe failed: {e}"),
                hint: Some("restart sandboxd: sudo systemctl restart sandboxd".to_string()),
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Individual checks — C4 (group membership)
// ---------------------------------------------------------------------------

/// C4 — current user in `sandbox` group.
///
/// In dev mode there is no `sandbox` system group; we report this as
/// `Skip` rather than `Fail` in dev mode. Production: the
/// operator must be in the group or the unix socket's `0660` mode
/// will refuse them.
pub(crate) fn check_group_membership() -> CheckRow {
    check_group_membership_with(real_group_resolver)
}

/// Pure inner of [`check_group_membership`], parameterised over the
/// "resolve current process's supplementary group names" function so
/// unit tests can drive the predicate without depending on the
/// running user's actual group set.
pub(crate) fn check_group_membership_with<R>(resolver: R) -> CheckRow
where
    R: FnOnce() -> Result<GroupMembership, String>,
{
    match resolver() {
        Ok(GroupMembership::SandboxGroupAbsent) => CheckRow {
            id: "C4",
            name: "current user in 'sandbox' group",
            outcome: CheckOutcome::Skip {
                detail: "no 'sandbox' group; dev mode".to_string(),
                hint: None,
            },
        },
        Ok(GroupMembership::Member {
            user,
            group_names_csv,
        }) => CheckRow {
            id: "C4",
            name: "current user in 'sandbox' group",
            outcome: CheckOutcome::Pass {
                detail: format!("{user} \u{2208} {group_names_csv}"),
            },
        },
        Ok(GroupMembership::NotMember { user }) => CheckRow {
            id: "C4",
            name: "current user in 'sandbox' group",
            outcome: CheckOutcome::Fail {
                detail: format!("{user} is not in the 'sandbox' group"),
                hint: Some("sudo usermod -aG sandbox $USER; log out and back in".to_string()),
            },
        },
        Err(e) => CheckRow {
            id: "C4",
            name: "current user in 'sandbox' group",
            outcome: CheckOutcome::Fail {
                detail: format!("group lookup failed: {e}"),
                hint: Some("sudo usermod -aG sandbox $USER; log out and back in".to_string()),
            },
        },
    }
}

/// Outcome of resolving the current process's group set against the
/// `sandbox` system group. Three states:
///
/// - `SandboxGroupAbsent` — no `sandbox` group on the host (dev mode).
/// - `Member` — sandbox group exists *and* the caller's
///   supplementary GIDs include it.
/// - `NotMember` — sandbox group exists but the caller is not in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GroupMembership {
    SandboxGroupAbsent,
    Member {
        user: String,
        group_names_csv: String,
    },
    NotMember {
        user: String,
    },
}

/// Production implementation of the group-membership resolver. Reads
/// the current process's uid + supplementary GIDs via `nix::unistd`
/// and looks up names via `getpwuid_r` / `getgrgid_r`.
fn real_group_resolver() -> Result<GroupMembership, String> {
    let uid = nix::unistd::Uid::current();
    let user = nix::unistd::User::from_uid(uid)
        .map_err(|e| format!("getpwuid_r: {e}"))?
        .ok_or_else(|| format!("uid {uid} not in passwd"))?;
    let user_name = user.name.clone();

    let sandbox_group =
        nix::unistd::Group::from_name("sandbox").map_err(|e| format!("getgrnam_r: {e}"))?;

    let groups = nix::unistd::getgroups().map_err(|e| format!("getgroups: {e}"))?;
    let mut group_names: Vec<String> = Vec::with_capacity(groups.len());
    for gid in &groups {
        if let Ok(Some(group)) = nix::unistd::Group::from_gid(*gid) {
            group_names.push(group.name);
        }
    }
    // `getgroups` historically may omit the primary group; defend
    // by adding the user's primary gid name when missing.
    if let Ok(Some(primary)) = nix::unistd::Group::from_gid(user.gid)
        && !group_names.iter().any(|n| n == &primary.name)
    {
        group_names.insert(0, primary.name);
    }

    match sandbox_group {
        None => Ok(GroupMembership::SandboxGroupAbsent),
        Some(sg) => {
            if groups.contains(&sg.gid) || user.gid == sg.gid {
                let group_names_csv = group_names.join(",");
                Ok(GroupMembership::Member {
                    user: user_name,
                    group_names_csv,
                })
            } else {
                Ok(GroupMembership::NotMember { user: user_name })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dev-vs-prod classification signal
// ---------------------------------------------------------------------------

/// Canonical signal for "this host was provisioned by install.sh" —
/// the install-state file at its runtime-resolved path (per-uid first,
/// legacy fallback; see `crate::update::resolve_state_path`). When the
/// file is present the install is a system-service install and doctor's
/// environment-aware checks (C5, C10) run their strict-mode comparisons;
/// when it is absent the install is dev mode (or corrupted, same
/// disposition) and the strict-mode comparisons are skipped.
///
/// Pulled into a pure function so it can be unit-tested against
/// synthetic paths; production callers use `resolve_state_path`.
///
/// Earlier revisions of the doctor used `nix::unistd::User::from_name("sandbox")`
/// as the dev-vs-prod heuristic. That signal conflates two
/// independent host facts — "the `sandbox` system user exists" and
/// "the host was installed by install.sh" — and produced misleading
/// hints during the installer window (the user appears before the
/// install-state file, and during uninstall the file disappears
/// before the user). The install-state file's lifecycle is bound to
/// install.sh's two-phase write (atomic move after every other
/// invariant is in place), so it is the single source of truth that
/// other paths already consult (`is_dev_mode` in `update/mod.rs`,
/// the `--check` / `--dry-run` graceful-degradation branches in the
/// same module).
fn is_prod_install_signal(install_state_path: &Path) -> bool {
    install_state_path.exists()
}

// ---------------------------------------------------------------------------
// Individual checks — C5 (socket perms)
// ---------------------------------------------------------------------------

/// C5 — socket permissions.
///
/// Production: `srw-rw---- sandbox:sandbox` (mode `0660`). Dev: the
/// developer owns the socket under `$XDG_RUNTIME_DIR/sandboxd/`; the
/// mode varies; the dev-mode degradation rule specifies a `Skip (dev mode)` row.
/// Dev-vs-prod classification uses the install-state file's presence
/// per [`is_prod_install_signal`]; the strict-mode comparison is
/// applied only on prod installs.
fn check_socket_perms(socket_path: &str, socket_reachable: bool) -> CheckRow {
    if !socket_reachable {
        return CheckRow {
            id: "C5",
            name: "socket perms",
            outcome: CheckOutcome::Skip {
                detail: "requires daemon".to_string(),
                hint: None,
            },
        };
    }
    let path = Path::new(socket_path);
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return CheckRow {
                id: "C5",
                name: "socket perms",
                outcome: CheckOutcome::Fail {
                    detail: format!("stat({socket_path}): {e}"),
                    hint: Some("restart sandboxd: sudo systemctl restart sandboxd".to_string()),
                },
            };
        }
    };

    // Dev-mode signal: absence of the install-state file means there is no
    // system install of sandboxd, so there is no `0660 sandbox:sandbox`
    // invariant to require. The path is runtime-resolved (per-uid or legacy).
    if !is_prod_install_signal(&crate::update::resolve_state_path(".install-state.json")) {
        let mode = metadata.permissions().mode() & 0o777;
        return CheckRow {
            id: "C5",
            name: "socket perms",
            outcome: CheckOutcome::Skip {
                detail: format!("dev mode \u{2014} socket mode {mode:04o}"),
                hint: None,
            },
        };
    }

    let mode = metadata.permissions().mode() & 0o777;
    if mode == 0o660 {
        // Stat-side owner/group is best-effort; for a clean pass we
        // include both so operators see what they'd expect.
        let owner = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(
            std::os::unix::fs::MetadataExt::uid(&metadata),
        ))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| "?".to_string());
        let group = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(
            std::os::unix::fs::MetadataExt::gid(&metadata),
        ))
        .ok()
        .flatten()
        .map(|g| g.name)
        .unwrap_or_else(|| "?".to_string());
        CheckRow {
            id: "C5",
            name: "socket perms",
            outcome: CheckOutcome::Pass {
                detail: format!("srw-rw---- {owner}:{group}"),
            },
        }
    } else {
        CheckRow {
            id: "C5",
            name: "socket perms",
            outcome: CheckOutcome::Fail {
                detail: format!("mode {mode:04o}, expected 0660"),
                hint: Some("restart sandboxd: sudo systemctl restart sandboxd".to_string()),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Individual checks — C6 (KVM accessible from daemon's uid)
// ---------------------------------------------------------------------------

/// C6 — KVM accessible from the daemon's uid.
///
/// The CLI runs as the operator; the operative question is whether
/// the *daemon* can read+write `/dev/kvm`. The answer comes from
/// `GET /diagnostics`, evaluated daemon-side.
fn check_kvm_accessible(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return CheckRow {
            id: "C6",
            name: "KVM accessible",
            outcome: CheckOutcome::Skip {
                detail: "requires daemon".to_string(),
                hint: None,
            },
        };
    }
    match diagnostics {
        Some(d) if d.kvm_readable && d.kvm_writable => CheckRow {
            id: "C6",
            name: "KVM accessible",
            outcome: CheckOutcome::Pass {
                detail: "/dev/kvm readable+writable by daemon".to_string(),
            },
        },
        Some(d) => CheckRow {
            id: "C6",
            name: "KVM accessible",
            outcome: CheckOutcome::Fail {
                detail: format!(
                    "daemon read={} write={} on /dev/kvm",
                    d.kvm_readable, d.kvm_writable
                ),
                hint: Some(
                    "add daemon user to kvm group: sudo usermod -aG kvm sandbox; \
                     sudo systemctl restart sandboxd; verify /dev/kvm exists"
                        .to_string(),
                ),
            },
        },
        None => CheckRow {
            id: "C6",
            name: "KVM accessible",
            outcome: CheckOutcome::Fail {
                detail: "/diagnostics probe failed".to_string(),
                hint: Some("restart sandboxd: sudo systemctl restart sandboxd".to_string()),
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Individual checks — C7 / C8 (image presence)
// ---------------------------------------------------------------------------

/// C7 — gateway image present (hard fail).
///
/// Without the gateway image, every session-create returns an
/// operator-visible error. We surface that as a `Fail` row regardless
/// of how new the install is.
fn check_gateway_image(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return CheckRow {
            id: "C7",
            name: "gateway image present",
            outcome: CheckOutcome::Skip {
                detail: "requires daemon".to_string(),
                hint: None,
            },
        };
    }
    let tag = sandbox_core::gateway::gateway_image_tag_for_version(env!("CARGO_PKG_VERSION"));
    match diagnostics {
        Some(d) if d.gateway_image_present => CheckRow {
            id: "C7",
            name: "gateway image present",
            outcome: CheckOutcome::Pass { detail: tag },
        },
        Some(d) if d.gateway_image_probe_failed => {
            // the documented contract `probe_failed` variant: the daemon's
            // `docker image inspect` could not run to a verdict, so
            // we cannot tell whether the image is loaded. Emit the
            // "restart docker / sandboxd" hint instead of the
            // misleading "run sandbox update to load the image" hint
            // C7 emits when the probe ran and reported absence.
            let detail = match d.gateway_image_probe_error.as_deref() {
                Some(err) if !err.is_empty() => format!("probe failed: {err}"),
                _ => "probe failed".to_string(),
            };
            CheckRow {
                id: "C7",
                name: "gateway image present",
                outcome: CheckOutcome::Fail {
                    detail,
                    hint: Some(
                        "verify docker is reachable from the daemon's uid \
                         (sudo -u sandbox docker info); restart sandboxd \
                         once docker is responsive: sudo systemctl restart sandboxd"
                            .to_string(),
                    ),
                },
            }
        }
        Some(_) => CheckRow {
            id: "C7",
            name: "gateway image present",
            outcome: CheckOutcome::Fail {
                detail: format!("missing {tag}"),
                hint: Some(
                    "sandbox update to load the image; \
                     or in dev: make gateway-image && docker load"
                        .to_string(),
                ),
            },
        },
        None => CheckRow {
            id: "C7",
            name: "gateway image present",
            outcome: CheckOutcome::Fail {
                detail: "/diagnostics probe failed".to_string(),
                hint: Some("restart sandboxd: sudo systemctl restart sandboxd".to_string()),
            },
        },
    }
}

/// C8 — lite image present (informational).
///
/// The lite image is built on first session-create; an absent image
/// is the normal post-install state, not a failure. We render it as
/// a `Skip` with the "not built yet" annotation.
fn check_lite_image(diagnostics: Option<&DiagnosticsPayload>, socket_reachable: bool) -> CheckRow {
    if !socket_reachable {
        return CheckRow {
            id: "C8",
            name: "lite image present",
            outcome: CheckOutcome::Skip {
                detail: "requires daemon".to_string(),
                hint: None,
            },
        };
    }
    let tag = sandbox_core::lite_image_tag_for_version(env!("CARGO_PKG_VERSION"));
    match diagnostics {
        Some(d) if d.lite_image_present => CheckRow {
            id: "C8",
            name: "lite image present",
            outcome: CheckOutcome::Pass { detail: tag },
        },
        Some(d) if d.lite_image_probe_failed => {
            // the documented contract `probe_failed` variant: docker probe did
            // not run to a verdict. C8 is informational (the lite
            // image is built on first session-create), so we render
            // this as `Skip` — but with the probe-failure detail and
            // hint, not the "not built yet" wording C8 emits when
            // the probe genuinely reports absence.
            let detail = match d.lite_image_probe_error.as_deref() {
                Some(err) if !err.is_empty() => format!("probe failed: {err}"),
                _ => "probe failed".to_string(),
            };
            CheckRow {
                id: "C8",
                name: "lite image present",
                outcome: CheckOutcome::Skip {
                    detail,
                    hint: Some(
                        "verify docker is reachable from the daemon's uid \
                         (sudo -u sandbox docker info); restart sandboxd \
                         once docker is responsive: sudo systemctl restart sandboxd"
                            .to_string(),
                    ),
                },
            }
        }
        Some(_) => CheckRow {
            id: "C8",
            name: "lite image present",
            outcome: CheckOutcome::Skip {
                detail: "not built yet".to_string(),
                hint: Some(
                    "image will be built on first session create; or pre-build: \
                     sandbox rebuild-image --backend container"
                        .to_string(),
                ),
            },
        },
        None => CheckRow {
            id: "C8",
            name: "lite image present",
            outcome: CheckOutcome::Skip {
                detail: "/diagnostics probe failed".to_string(),
                hint: None,
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Individual checks — C9 (route-helper caps)
// ---------------------------------------------------------------------------

/// C9 — route-helper has `cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip`.
///
/// Calls `getcap` on `/usr/local/libexec/sandboxd/sandbox-route-helper`.
/// The daemon refuses to start without this so a passing daemon
/// implies a passing check; we still run it explicitly so a
/// not-yet-up daemon doesn't hide the misconfiguration.
///
/// `cap_sys_ptrace` is load-bearing, not optional: the container's PID 1
/// runs as the operator's uid, so the helper (sandbox uid) enters a
/// foreign-uid netns and the `pidfd`+`setns` path hits a cross-uid
/// `ptrace_may_access` check that only `CAP_SYS_PTRACE` satisfies.
/// Without it, container-session egress routing fails — so a helper
/// carrying only the older two-cap set is reported as a hard failure
/// even though that set once sufficed (pre operator-uid alignment).
fn check_route_helper_caps() -> CheckRow {
    const HELPER_PATH: &str = "/usr/local/libexec/sandboxd/sandbox-route-helper";
    if !std::path::Path::new(HELPER_PATH).exists() {
        return CheckRow {
            id: "C9",
            name: "route-helper caps",
            outcome: CheckOutcome::Fail {
                detail: format!("missing: {HELPER_PATH}"),
                hint: Some(
                    "sandbox update re-runs setcap; \
                     or `make install-route-helper-prod-cap` in dev"
                        .to_string(),
                ),
            },
        };
    }
    let output = match std::process::Command::new("getcap")
        .arg(HELPER_PATH)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return CheckRow {
                id: "C9",
                name: "route-helper caps",
                outcome: CheckOutcome::Fail {
                    detail: format!("getcap: {e}"),
                    hint: Some(
                        "install libcap-bin (Debian/Ubuntu) or libcap (Fedora) and retry"
                            .to_string(),
                    ),
                },
            };
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    // `getcap` output shape:
    // `<path> cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip`
    // (the effective bit may render `+ep`/`=ep` on older libcap; we
    // accept any form. Cap order is getcap's own, sorted by capability
    // number, but we only test for substrings so order is irrelevant.)
    let has_sys_admin = stdout.contains("cap_sys_admin");
    let has_net_admin = stdout.contains("cap_net_admin");
    let has_sys_ptrace = stdout.contains("cap_sys_ptrace");
    let effective = stdout.contains("=eip")
        || stdout.contains("+ep")
        || stdout.contains("=ep")
        || stdout.contains("+eip");
    if has_sys_admin && has_net_admin && has_sys_ptrace && effective {
        CheckRow {
            id: "C9",
            name: "route-helper caps",
            outcome: CheckOutcome::Pass {
                detail: "cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip".to_string(),
            },
        }
    } else if has_sys_admin && has_net_admin && effective {
        // The two older caps are present but cap_sys_ptrace is missing —
        // the exact state an install/update predating the cap widening
        // leaves behind. The container runs as the operator's uid, so
        // the cross-uid pidfd+setns ptrace_may_access check fails and
        // container-session egress routing breaks. Hard failure with a
        // targeted hint.
        CheckRow {
            id: "C9",
            name: "route-helper caps",
            outcome: CheckOutcome::Fail {
                detail: format!(
                    "missing cap_sys_ptrace — cross-uid container egress will fail; \
                     getcap reported: {}",
                    stdout.trim()
                ),
                hint: Some(
                    "sandbox update re-runs setcap with the current cap set; \
                     or `make install-route-helper-prod-cap` in dev"
                        .to_string(),
                ),
            },
        }
    } else {
        CheckRow {
            id: "C9",
            name: "route-helper caps",
            outcome: CheckOutcome::Fail {
                detail: format!("getcap reported: {}", stdout.trim()),
                hint: Some(
                    "sandbox update re-runs setcap; \
                     or `make install-route-helper-prod-cap` in dev"
                        .to_string(),
                ),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Individual checks — C10 (state dir mode)
// ---------------------------------------------------------------------------

/// C10 — state dir mode.
///
/// Production: `/var/lib/sandboxd/<daemon-uid>/` is `0750 sandbox:sandbox`.
/// Dev: the operator's own `~/.local/share/sandboxd/` lives at the
/// developer's umask; we skip the strict-mode comparison. Dev-vs-prod
/// classification consults the install-state file via
/// [`is_prod_install_signal`].
///
/// Path resolution: per-uid path first; legacy `/var/lib/sandbox` fallback
/// when only the legacy dir exists (pre-migration host). When only the legacy
/// dir is found, a hint to run install.sh to migrate is emitted alongside
/// the check result.
fn check_state_dir_mode() -> CheckRow {
    // Dev-mode gate: skip all strict checks when no install-state exists.
    if !is_prod_install_signal(&crate::update::resolve_state_path(".install-state.json")) {
        return CheckRow {
            id: "C10",
            name: "state dir mode",
            outcome: CheckOutcome::Skip {
                detail: "dev mode \u{2014} no install-state file / not a system install"
                    .to_string(),
                hint: None,
            },
        };
    }

    // Resolve the expected prod path (per-uid), with legacy fallback.
    // The third tuple element carries the per-uid path when the legacy dir is
    // in use, so the hint below can name the migration target exactly.
    let (path, is_legacy, migrate_to) = match crate::update::prod_base_dir() {
        Some(per_uid) if per_uid.exists() => (per_uid, false, None),
        Some(per_uid) => {
            // Per-uid dir absent: check if legacy dir exists (pre-migration).
            let legacy = PathBuf::from("/var/lib/sandbox");
            if legacy.exists() {
                let target = per_uid.display().to_string();
                (legacy, true, Some(target))
            } else {
                // Neither exists — report the per-uid path as the expected one.
                return CheckRow {
                    id: "C10",
                    name: "state dir mode",
                    outcome: CheckOutcome::Fail {
                        detail: format!("missing: {}", per_uid.display()),
                        hint: Some(format!(
                            "sudo install -d -o sandbox -g sandbox -m 0750 {} \
                             (the daemon corrects subdir modes on next start)",
                            per_uid.display()
                        )),
                    },
                };
            }
        }
        None => {
            // No sandbox user — degrade gracefully (dev host).
            return CheckRow {
                id: "C10",
                name: "state dir mode",
                outcome: CheckOutcome::Skip {
                    detail: "dev mode \u{2014} sandbox user not found".to_string(),
                    hint: None,
                },
            };
        }
    };

    let path_display = path.display().to_string();
    match std::fs::metadata(&path) {
        Ok(md) => {
            let mode = md.permissions().mode() & 0o777;
            let owner = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(
                std::os::unix::fs::MetadataExt::uid(&md),
            ))
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_else(|| "?".to_string());
            let group = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(
                std::os::unix::fs::MetadataExt::gid(&md),
            ))
            .ok()
            .flatten()
            .map(|g| g.name)
            .unwrap_or_else(|| "?".to_string());
            if mode == 0o750 && owner == "sandbox" && group == "sandbox" {
                let detail = if is_legacy {
                    let target = migrate_to.as_deref().unwrap_or("/var/lib/sandboxd/<uid>/");
                    format!(
                        "{path_display} {mode:04o} {owner}:{group} \
                         (legacy path — run install.sh to migrate to {target})"
                    )
                } else {
                    format!("{path_display} {mode:04o} {owner}:{group}")
                };
                CheckRow {
                    id: "C10",
                    name: "state dir mode",
                    outcome: CheckOutcome::Pass { detail },
                }
            } else {
                CheckRow {
                    id: "C10",
                    name: "state dir mode",
                    outcome: CheckOutcome::Fail {
                        detail: format!(
                            "{path_display} {mode:04o} {owner}:{group} \
                             (expected 0750 sandbox:sandbox)"
                        ),
                        hint: Some(format!(
                            "sudo chmod 0750 {path_display}; \
                             sudo chown sandbox:sandbox {path_display} \
                             (the daemon corrects subdirs at next start)"
                        )),
                    },
                }
            }
        }
        Err(e) => CheckRow {
            id: "C10",
            name: "state dir mode",
            outcome: CheckOutcome::Fail {
                detail: format!("stat({path_display}): {e}"),
                hint: Some(format!("ensure {path_display} exists and is readable")),
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Individual checks — C11 (users.conf pool)
// ---------------------------------------------------------------------------

/// C11 — users.conf reachable + parses + daemon's uid resolves to a pool.
///
/// The daemon's startup validation already enforces this — a passing
/// daemon implies a passing check. We surface it on `/diagnostics`'s
/// clean response surface so the report shows the actually-resolved
/// pool rather than expecting operators to grep journald.
fn check_users_conf_pool(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return CheckRow {
            id: "C11",
            name: "users.conf has daemon pool",
            outcome: CheckOutcome::Skip {
                detail: "requires daemon".to_string(),
                hint: None,
            },
        };
    }
    match diagnostics.and_then(|d| d.users_conf_pool.as_ref()) {
        Some(pool) => CheckRow {
            id: "C11",
            name: "users.conf has daemon pool",
            outcome: CheckOutcome::Pass {
                detail: format!("{} \u{2192} {:?}", pool.cidr, pool.allow_users),
            },
        },
        None => CheckRow {
            id: "C11",
            name: "users.conf has daemon pool",
            outcome: CheckOutcome::Fail {
                detail: "daemon reported no resolved pool".to_string(),
                hint: Some(
                    "daemon would have refused to start without one; \
                     restart sandboxd and check journalctl -u sandboxd"
                        .to_string(),
                ),
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Individual checks — C12 (guest version drift) — verbose only
// ---------------------------------------------------------------------------

/// C12 — running sessions guest-version drift.
///
/// Skipped in default mode (kept cheap). Verbose mode would expand
/// this; since the report formatter doesn't materialise the row
/// conditionally on verbose (the design example pins the row in the
/// daemon-down case as well), we emit `Skip` with a "verbose only"
/// annotation and let the verbose path render the drift detail when
/// the diagnostics payload has it.
fn check_guest_version_drift(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return CheckRow {
            id: "C12",
            name: "running sessions guest-version drift",
            outcome: CheckOutcome::Skip {
                detail: "requires daemon".to_string(),
                hint: None,
            },
        };
    }
    match diagnostics {
        Some(d) => {
            let drift_count = d
                .guest_version_drift
                .as_ref()
                .map(|v| v.iter().filter(|e| e.drift).count())
                .unwrap_or(0);
            let total = d.guest_version_drift.as_ref().map(|v| v.len()).unwrap_or(0);
            if drift_count == 0 {
                CheckRow {
                    id: "C12",
                    name: "running sessions guest-version drift",
                    outcome: CheckOutcome::Pass {
                        detail: format!("{total} running session(s); no drift"),
                    },
                }
            } else {
                CheckRow {
                    id: "C12",
                    name: "running sessions guest-version drift",
                    outcome: CheckOutcome::Fail {
                        detail: format!("{drift_count} of {total} running session(s) drifted"),
                        hint: Some(
                            "recreate the session: sandbox session rm <id> && \
                             sandbox session create ..."
                                .to_string(),
                        ),
                    },
                }
            }
        }
        None => CheckRow {
            id: "C12",
            name: "running sessions guest-version drift",
            outcome: CheckOutcome::Skip {
                detail: "/diagnostics probe failed".to_string(),
                hint: None,
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Individual checks — C13 (substrate orphans)
// ---------------------------------------------------------------------------

/// C13 — orphan substrate resources (informational only).
///
/// Lima VMs / docker containers / per-session dirs that name a
/// session-id not in the caller's session list. Does not contribute
/// to exit code `1`.
fn check_substrate_orphans(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return CheckRow {
            id: "C13",
            name: "orphan substrate resources",
            outcome: CheckOutcome::Skip {
                detail: "requires daemon \u{2014} session cross-reference unavailable".to_string(),
                hint: None,
            },
        };
    }
    let orphans = diagnostics.and_then(|d| d.substrate_orphans.as_ref());
    let (lima, containers, dirs) = match orphans {
        Some(o) => (o.lima_vms.len(), o.containers.len(), o.session_dirs.len()),
        None => (0, 0, 0),
    };
    let total = lima + containers + dirs;
    if total == 0 {
        CheckRow {
            id: "C13",
            name: "orphan substrate resources",
            outcome: CheckOutcome::Pass {
                detail: "none detected".to_string(),
            },
        }
    } else {
        let detail =
            format!("{total} orphan(s): {lima} VM(s), {containers} container(s), {dirs} dir(s)");
        CheckRow {
            id: "C13",
            name: "orphan substrate resources",
            outcome: CheckOutcome::Skip {
                detail,
                hint: Some(
                    "remove with: limactl delete <name> / docker rm <name> / \
                     rm -rf {base_dir}/sessions/<id>/"
                        .to_string(),
                ),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP probes
// ---------------------------------------------------------------------------

/// Diagnostics payload returned by `GET /diagnostics`. Both classes
/// of fields live on one struct (system-level always; per-operator
/// scoped optional when the daemon can't compute them) — the CLI
/// reads them with `#[serde(default)]` tolerance.
///
/// `daemon_uid` / `daemon_user` are not consumed by the current
/// check registry but are accepted from the wire so a future check
/// can surface them without breaking on-disk compat — keeping them
/// here silences `dead_code` without losing the parse-time tolerance.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct DiagnosticsPayload {
    #[serde(default)]
    #[allow(dead_code)]
    pub daemon_uid: u32,
    #[serde(default)]
    #[allow(dead_code)]
    pub daemon_user: String,
    #[serde(default)]
    pub kvm_readable: bool,
    #[serde(default)]
    pub kvm_writable: bool,
    #[serde(default)]
    pub gateway_image_present: bool,
    #[serde(default)]
    pub lite_image_present: bool,
    /// `true` when the daemon's `docker image inspect` probe could
    /// not run to a verdict (docker daemon unreachable, fork
    /// failure, unexpected stderr). the documented contract added the variant
    /// so C7 can emit the "restart docker / sandboxd" hint instead
    /// of the misleading "image missing" hint. `#[serde(default)]`
    /// keeps this readable against an older daemon that omits the
    /// field (in which case probe failure was conflated with absence
    /// — the pre-fix behaviour).
    #[serde(default)]
    pub gateway_image_probe_failed: bool,
    /// Operator-facing reason the gateway-image probe failed. `None`
    /// when the probe succeeded or when an older daemon omits the
    /// field.
    #[serde(default)]
    pub gateway_image_probe_error: Option<String>,
    /// Sibling of [`Self::gateway_image_probe_failed`] for the lite
    /// image probe (C8). Same semantics, same fallback shape.
    #[serde(default)]
    pub lite_image_probe_failed: bool,
    /// Sibling of [`Self::gateway_image_probe_error`] for the lite
    /// image probe.
    #[serde(default)]
    pub lite_image_probe_error: Option<String>,
    #[serde(default)]
    pub users_conf_pool: Option<UsersConfPoolDto>,
    #[serde(default)]
    pub guest_version_drift: Option<Vec<GuestVersionDriftEntry>>,
    #[serde(default)]
    pub substrate_orphans: Option<SubstrateOrphans>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct UsersConfPoolDto {
    pub cidr: String,
    pub allow_users: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct GuestVersionDriftEntry {
    #[serde(default)]
    pub drift: bool,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
pub(crate) struct SubstrateOrphans {
    #[serde(default)]
    pub lima_vms: Vec<String>,
    #[serde(default)]
    pub containers: Vec<String>,
    #[serde(default)]
    pub session_dirs: Vec<String>,
}

async fn fetch_version(socket_path: &str) -> Result<String, String> {
    let body_bytes = http_get(socket_path, "/version", DOCTOR_HTTP_TIMEOUT).await?;
    #[derive(serde::Deserialize)]
    struct Resp {
        version: String,
    }
    let parsed: Resp =
        serde_json::from_slice(&body_bytes).map_err(|e| format!("parse /version body: {e}"))?;
    Ok(parsed.version)
}

async fn fetch_diagnostics(socket_path: &str) -> Option<DiagnosticsPayload> {
    let body_bytes = match http_get(socket_path, "/diagnostics", DOCTOR_HTTP_TIMEOUT).await {
        Ok(b) => b,
        Err(_) => return None,
    };
    serde_json::from_slice(&body_bytes).ok()
}

async fn http_get(socket_path: &str, path: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let socket_str = socket_path.to_string();
    let path_str = path.to_string();
    tokio::time::timeout(timeout, async move {
        let stream = UnixStream::connect(&socket_str)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| format!("hyper handshake: {e}"))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method("GET")
            .uri(&path_str)
            .header("host", "localhost")
            .body(String::new())
            .map_err(|e| format!("build request: {e}"))?;
        let response = sender
            .send_request(req)
            .await
            .map_err(|e| format!("send_request: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("non-success status: {}", response.status()));
        }
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("collect body: {e}"))?
            .to_bytes();
        Ok::<Vec<u8>, String>(body_bytes.to_vec())
    })
    .await
    .map_err(|_| format!("timeout after {timeout:?}"))?
}

// ---------------------------------------------------------------------------
// systemctl is-active
// ---------------------------------------------------------------------------

/// Run `systemctl is-active <unit>` and return its stdout trimmed
/// (one of `active`, `inactive`, `failed`, `not-found`, `activating`).
/// `None` means `systemctl` itself is unavailable — most likely a
/// system without systemd, in which case the caller falls back to a
/// direct socket connect.
fn systemctl_is_active(unit: &str) -> Option<String> {
    // `which`-style probe: if `systemctl` is not on PATH, return None
    // so the caller falls through to the connect probe.
    let output = std::process::Command::new("systemctl")
        .args(["is-active", unit])
        .output()
        .ok()?;
    let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if state.is_empty() {
        // `systemctl is-active` is documented to always emit a state
        // word; empty stdout means an exec failure that didn't
        // surface as a launch error. Treat as "no signal".
        return None;
    }
    Some(state)
}

// ---------------------------------------------------------------------------
// Output formatter
// ---------------------------------------------------------------------------

/// ANSI escape for green text. The doctor output is colored on a TTY
/// so the verdict stands out without a parser-friendly machine-
/// readable separator. Non-TTY captures (`> file`, CI logs) see the
/// escapes verbatim; the message text is still readable.
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

/// Pad `name` to the display column width (40 chars after the
/// glyph + space, give or take Unicode wcwidth). The output aligns
/// the detail-or-`SKIPPED` token at roughly column 42. We use 40
/// char-count padding which lands the detail column at column 42
/// for ASCII-only check names.
const NAME_COLUMN_WIDTH: usize = 40;

/// Render the report to `out`. Returns the process exit code.
pub(crate) fn render_report<W: std::io::Write>(
    out: &mut W,
    rows: &[CheckRow],
    verbose: bool,
) -> i32 {
    let _ = writeln!(out, "sandbox doctor \u{2014} checking deployment");
    let _ = writeln!(out);

    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;

    for row in rows {
        match &row.outcome {
            CheckOutcome::Pass { detail } => {
                passed += 1;
                if verbose {
                    let _ = writeln!(
                        out,
                        "{GREEN}\u{2713}{RESET} {name:width$} ({detail})",
                        name = row.name,
                        width = NAME_COLUMN_WIDTH,
                    );
                }
            }
            CheckOutcome::Skip { detail, hint } => {
                skipped += 1;
                // Surface skips when verbose, or when they carry an
                // operator-actionable hint (C13 orphans-detected,
                // C8 lite-not-built). A bare `requires daemon` skip
                // without a hint is noise on default mode (we already
                // showed the C1 failure that caused it).
                if verbose || hint.is_some() {
                    let _ = writeln!(
                        out,
                        "{YELLOW}~{RESET} {name:width$} SKIPPED ({detail})",
                        name = row.name,
                        width = NAME_COLUMN_WIDTH,
                    );
                    if let Some(h) = hint {
                        let _ = writeln!(out, "    hint: {h}");
                    }
                }
            }
            CheckOutcome::Fail { detail, hint } => {
                failed += 1;
                let _ = writeln!(
                    out,
                    "{RED}\u{2717}{RESET} {name:width$} ({detail})",
                    name = row.name,
                    width = NAME_COLUMN_WIDTH,
                );
                if let Some(h) = hint {
                    let _ = writeln!(out, "    hint: {h}");
                }
            }
        }
    }

    // Default mode: when failures are present and we suppressed the
    // dependent-skips, the report can render with only the root-cause
    // failure followed by the summary. The.3 partial-fail
    // example shows the skipped rows present in non-verbose mode
    // *only* for the daemon-down case where they cascade. Emit a
    // blank line between the last printed row and the summary in
    // both modes for readability.
    let printed_any_row = verbose
        || rows.iter().any(|r| {
            matches!(&r.outcome, CheckOutcome::Fail { .. })
                || matches!(&r.outcome, CheckOutcome::Skip { hint: Some(_), .. })
        });
    if printed_any_row {
        let _ = writeln!(out);
    }

    // For the default-mode "daemon-down" output, list every skip on
    // its own line when at least one fail triggered the cascade.
    if !verbose && failed > 0 {
        for row in rows {
            if let CheckOutcome::Skip { detail, .. } = &row.outcome {
                if detail == "requires daemon"
                    || detail == "requires daemon \u{2014} session cross-reference unavailable"
                {
                    let _ = writeln!(
                        out,
                        "{YELLOW}~{RESET} {name:width$} SKIPPED ({detail})",
                        name = row.name,
                        width = NAME_COLUMN_WIDTH,
                    );
                }
            }
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(
        out,
        "{passed} checks passed, {failed} failed, {skipped} skipped"
    );

    if failed > 0 { 1 } else { 0 }
}

// ---------------------------------------------------------------------------
// (Unused import guards — referenced by tests but not by prod yet)
// ---------------------------------------------------------------------------

#[cfg_attr(not(test), allow(dead_code))]
fn _resolve_base_dir() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(runtime_dir).join("sandboxd");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".local/share/sandboxd")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(id: &'static str, name: &'static str, detail: &str) -> CheckRow {
        CheckRow {
            id,
            name,
            outcome: CheckOutcome::Pass {
                detail: detail.to_string(),
            },
        }
    }

    fn fail(id: &'static str, name: &'static str, detail: &str, hint: Option<&str>) -> CheckRow {
        CheckRow {
            id,
            name,
            outcome: CheckOutcome::Fail {
                detail: detail.to_string(),
                hint: hint.map(|s| s.to_string()),
            },
        }
    }

    fn skip(id: &'static str, name: &'static str, detail: &str, hint: Option<&str>) -> CheckRow {
        CheckRow {
            id,
            name,
            outcome: CheckOutcome::Skip {
                detail: detail.to_string(),
                hint: hint.map(|s| s.to_string()),
            },
        }
    }

    /// All-pass report exits 0 and surfaces every check under
    /// `--verbose`. Pins the happy-path output shape.
    #[test]
    fn doctor_exits_0_when_all_pass() {
        let rows = vec![
            pass("C1", "daemon process running", "sandboxd.service: active"),
            pass("C2", "daemon reachable", "/run/sandbox/sandboxd.sock"),
            pass("C3", "CLI ↔ daemon version match", "1.0.3 == 1.0.3"),
        ];
        let mut buf = Vec::new();
        let code = render_report(&mut buf, &rows, true);
        assert_eq!(code, 0, "all-pass must exit 0");
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("3 checks passed, 0 failed, 0 skipped"));
        assert!(out.contains("daemon process running"));
    }

    /// Any failed row trips exit code 1 even when most checks pass.
    #[test]
    fn doctor_exits_1_on_any_failure() {
        let rows = vec![
            pass("C1", "daemon process running", "active"),
            fail(
                "C3",
                "CLI \u{2194} daemon version match",
                "CLI=1.0.4, daemon=1.0.3",
                Some("versions differ \u{2014} reinstall to align"),
            ),
        ];
        let mut buf = Vec::new();
        let code = render_report(&mut buf, &rows, true);
        assert_eq!(code, 1, "any-fail must exit 1");
    }

    /// Skipped checks do not flip exit-code-1;.4 pins this.
    #[test]
    fn doctor_exits_0_when_skips_but_no_fails() {
        let rows = vec![
            pass("C1", "daemon process running", "active"),
            skip(
                "C8",
                "lite image present",
                "not built yet",
                Some("..build hint.."),
            ),
        ];
        let mut buf = Vec::new();
        let code = render_report(&mut buf, &rows, true);
        assert_eq!(code, 0, "skips alone never raise exit code");
    }

    /// Default mode suppresses pass rows but always renders fails +
    /// the summary line.
    #[test]
    fn default_mode_suppresses_passes_renders_fails() {
        let rows = vec![
            pass("C1", "daemon process running", "active"),
            fail("C3", "version match", "skew", Some("reinstall")),
        ];
        let mut buf = Vec::new();
        let code = render_report(&mut buf, &rows, false);
        assert_eq!(code, 1);
        let out = String::from_utf8(buf).unwrap();
        // Pass row's check name should NOT appear when not verbose.
        assert!(
            !out.contains("daemon process running"),
            "default mode must not echo passing rows; got: {out}"
        );
        // Fail row + hint must appear.
        assert!(out.contains("version match"), "fail row must render");
        assert!(out.contains("    hint: reinstall"), "hint line must render");
        // Summary line is always present.
        assert!(out.contains("1 checks passed, 1 failed, 0 skipped"));
    }

    /// Verbose mode echoes pass rows with the parenthetical detail.
    #[test]
    fn verbose_mode_echoes_passes_with_detail() {
        let rows = vec![pass(
            "C1",
            "daemon process running",
            "sandboxd.service: active",
        )];
        let mut buf = Vec::new();
        render_report(&mut buf, &rows, true);
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("daemon process running"),
            "verbose must echo pass row name"
        );
        assert!(
            out.contains("sandboxd.service: active"),
            "verbose must echo pass row detail"
        );
    }

    /// The summary line is always last and counts each bucket once.
    #[test]
    fn summary_line_counts_each_bucket() {
        let rows = vec![
            pass("C1", "daemon process running", "active"),
            fail("C7", "gateway image present", "missing", Some("h")),
            skip("C8", "lite image present", "not built yet", Some("h2")),
            skip("C13", "orphan substrate resources", "requires daemon", None),
        ];
        let mut buf = Vec::new();
        let code = render_report(&mut buf, &rows, true);
        assert_eq!(code, 1);
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("1 checks passed, 1 failed, 2 skipped"),
            "summary must tally each bucket precisely; got: {out}"
        );
    }

    /// Hint lines are indented 4 spaces and prefixed `hint:` per the
    /// output format. The token is load-bearing for the
    /// integration test that greps the failure output.
    #[test]
    fn fail_hint_is_indented_with_hint_prefix() {
        let rows = vec![fail(
            "C3",
            "version match",
            "CLI=1.0.4, daemon=1.0.3",
            Some("versions differ"),
        )];
        let mut buf = Vec::new();
        render_report(&mut buf, &rows, false);
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("    hint: versions differ"),
            "fail hint must be 4-space indented + `hint:` prefix; got: {out}"
        );
    }

    /// C4 — sandbox group absent → Skip with dev-mode annotation
    /// per.2.
    #[test]
    fn group_check_skips_when_sandbox_group_absent() {
        let row = check_group_membership_with(|| Ok(GroupMembership::SandboxGroupAbsent));
        match row.outcome {
            CheckOutcome::Skip { detail, .. } => {
                assert!(
                    detail.contains("no 'sandbox' group"),
                    "skip detail must contain the dev-mode annotation; got: {detail}"
                );
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    /// C4 — operator is in the group → Pass with `user ∈ groups` form.
    #[test]
    fn group_check_passes_when_member() {
        let row = check_group_membership_with(|| {
            Ok(GroupMembership::Member {
                user: "alice".to_string(),
                group_names_csv: "docker,kvm,sandbox".to_string(),
            })
        });
        match row.outcome {
            CheckOutcome::Pass { detail } => {
                assert!(detail.contains("alice"));
                assert!(detail.contains("sandbox"));
            }
            other => panic!("expected Pass, got {other:?}"),
        }
    }

    /// C4 — sandbox group exists but operator isn't in it → Fail with
    /// the `usermod` hint.
    #[test]
    fn group_check_fails_when_not_member_with_hint() {
        let row = check_group_membership_with(|| {
            Ok(GroupMembership::NotMember {
                user: "alice".to_string(),
            })
        });
        match row.outcome {
            CheckOutcome::Fail { hint, .. } => {
                let h = hint.expect("not-member must carry a hint");
                assert!(
                    h.contains("usermod -aG sandbox"),
                    "fail hint must instruct usermod; got: {h}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// Test helper: build a synthetic `DiagnosticsPayload` for the
    /// C7/C8 unit tests. Defaults every field to the "probe ran,
    /// image absent" shape so callers only set the fields they want
    /// to vary.
    fn diag_default() -> DiagnosticsPayload {
        DiagnosticsPayload {
            daemon_uid: 0,
            daemon_user: "sandbox".to_string(),
            kvm_readable: false,
            kvm_writable: false,
            gateway_image_present: false,
            lite_image_present: false,
            gateway_image_probe_failed: false,
            gateway_image_probe_error: None,
            lite_image_probe_failed: false,
            lite_image_probe_error: None,
            users_conf_pool: None,
            guest_version_drift: None,
            substrate_orphans: None,
        }
    }

    /// C7 — probe succeeded, image present → Pass row carries the
    /// tag verbatim. Baseline case before the `probe_failed`
    /// variant.
    #[test]
    fn c7_passes_when_gateway_image_present() {
        let mut d = diag_default();
        d.gateway_image_present = true;
        let row = check_gateway_image(Some(&d), true);
        assert_eq!(row.id, "C7");
        match row.outcome {
            CheckOutcome::Pass { .. } => {}
            other => panic!("expected Pass, got {other:?}"),
        }
    }

    /// C7 — probe ran, image absent → Fail with the "run sandbox
    /// update" hint. The hint must NOT mention docker daemon
    /// reachability — that's the `probe_failed` branch.
    #[test]
    fn c7_fails_with_update_hint_when_gateway_image_absent_but_probe_ok() {
        let d = diag_default();
        let row = check_gateway_image(Some(&d), true);
        match row.outcome {
            CheckOutcome::Fail { detail, hint } => {
                assert!(
                    detail.contains("missing"),
                    "absent-image detail must say 'missing'; got: {detail}"
                );
                let h = hint.expect("absent image must carry a hint");
                assert!(
                    h.contains("sandbox update"),
                    "absent-image hint must reference 'sandbox update'; got: {h}"
                );
                assert!(
                    !h.contains("docker is reachable"),
                    "absent-image hint must not mention docker reachability \
                     (that's the probe_failed branch); got: {h}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// C7 — the documented contract `probe_failed` variant: the daemon could
    /// not run `docker image inspect` to a verdict. The doctor row
    /// must remain Fail (C7 is a hard check) but the hint must
    /// guide the operator toward docker / sandboxd reachability,
    /// not toward loading the image.
    #[test]
    fn c7_fails_with_docker_hint_when_gateway_probe_failed() {
        let mut d = diag_default();
        d.gateway_image_probe_failed = true;
        d.gateway_image_probe_error = Some("Cannot connect to the Docker daemon".to_string());
        let row = check_gateway_image(Some(&d), true);
        match row.outcome {
            CheckOutcome::Fail { detail, hint } => {
                assert!(
                    detail.contains("probe failed"),
                    "probe-failure detail must say 'probe failed'; got: {detail}"
                );
                assert!(
                    detail.contains("Cannot connect to the Docker daemon"),
                    "probe-failure detail must echo the operator-facing reason; got: {detail}"
                );
                let h = hint.expect("probe-failure must carry a hint");
                assert!(
                    h.contains("docker is reachable"),
                    "probe-failure hint must mention docker reachability; got: {h}"
                );
                assert!(
                    !h.contains("sandbox update"),
                    "probe-failure hint must not suggest sandbox update \
                     (that's the absent-image branch); got: {h}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// C8 — probe ran, image absent → Skip with the "built on
    /// first session create" annotation (informational; no failure).
    #[test]
    fn c8_skips_with_first_create_hint_when_lite_image_absent_but_probe_ok() {
        let d = diag_default();
        let row = check_lite_image(Some(&d), true);
        match row.outcome {
            CheckOutcome::Skip { detail, hint } => {
                assert!(
                    detail.contains("not built yet"),
                    "absent-image detail must say 'not built yet'; got: {detail}"
                );
                let h = hint.expect("absent image must carry a hint");
                assert!(
                    h.contains("first session create"),
                    "absent-image hint must reference 'first session create'; got: {h}"
                );
                assert!(
                    !h.contains("docker is reachable"),
                    "absent-image hint must not mention docker reachability; got: {h}"
                );
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    /// C8 — the documented contract `probe_failed`: lite-image probe could
    /// not run to a verdict. C8 stays Skip (informational), but the
    /// hint switches to docker / sandboxd reachability so an
    /// operator doesn't waste time on `sandbox rebuild-image` when
    /// the docker daemon is the actual problem.
    #[test]
    fn c8_skips_with_docker_hint_when_lite_probe_failed() {
        let mut d = diag_default();
        d.lite_image_probe_failed = true;
        d.lite_image_probe_error = Some("docker: exec format error".to_string());
        let row = check_lite_image(Some(&d), true);
        match row.outcome {
            CheckOutcome::Skip { detail, hint } => {
                assert!(
                    detail.contains("probe failed"),
                    "probe-failure detail must say 'probe failed'; got: {detail}"
                );
                assert!(
                    detail.contains("docker: exec format error"),
                    "probe-failure detail must echo the operator-facing reason; got: {detail}"
                );
                let h = hint.expect("probe-failure must carry a hint");
                assert!(
                    h.contains("docker is reachable"),
                    "probe-failure hint must mention docker reachability; got: {h}"
                );
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    /// `DiagnosticsPayload` tolerates a payload written by an older
    /// daemon that does not emit `gateway_image_probe_failed` /
    /// `lite_image_probe_failed` / `*_probe_error`. The bool fields
    /// default to `false` and the optional reasons stay `None`, so
    /// C7/C8 render the legacy "absent-image" branches.
    #[test]
    fn diagnostics_payload_back_compat_omitted_probe_failed_fields() {
        let body = serde_json::json!({
            "daemon_uid": 1003,
            "daemon_user": "sandbox",
            "kvm_readable": true,
            "kvm_writable": true,
            "gateway_image_present": true,
            "lite_image_present": false,
            "users_conf_pool": {
                "cidr": "10.209.0.0/20",
                "allow_users": ["sandbox"]
            }
        });
        let parsed: DiagnosticsPayload =
            serde_json::from_value(body).expect("legacy payload must still parse");
        assert!(parsed.gateway_image_present);
        assert!(!parsed.gateway_image_probe_failed);
        assert!(parsed.gateway_image_probe_error.is_none());
        assert!(!parsed.lite_image_probe_failed);
        assert!(parsed.lite_image_probe_error.is_none());
    }

    /// `is_prod_install_signal` flips on the presence of the
    /// install-state file (runtime-resolved path). Pinned here so a future
    /// refactor can't silently widen the predicate to consult system-user
    /// existence again — that's the conflation #156 fixed.
    #[test]
    fn prod_install_signal_returns_true_when_install_state_file_present() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join(".install-state.json");
        std::fs::write(&path, b"{}").unwrap();
        assert!(is_prod_install_signal(&path));
    }

    #[test]
    fn prod_install_signal_returns_false_when_install_state_file_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join(".install-state.json");
        // Deliberately do not create the file.
        assert!(!is_prod_install_signal(&path));
    }

    /// Daemon-down (C1 fails) → C3-C13 that depend on the daemon must
    /// be Skip, not Fail. The cascade prevents one root cause from
    /// inflating the failure count.
    ///
    /// On hosts where `systemctl is-active sandboxd` happens to report
    /// `active` (a real production install on the CI runner, etc.),
    /// C1 may still pass and the cascade does not fire — that's the
    /// design. We pin the cascade contract here by walking the rows
    /// produced when the phantom socket is genuinely unreachable AND
    /// `systemctl` is unavailable. Inside cargo test, `PATH` may or
    /// may not include systemd; the test asserts the cascade only
    /// when C2 (the socket-reachable gate) reports its phantom-socket
    /// failure, since C2 is the actual `socket_reachable` predicate
    /// the parallel-phase rows branch on.
    #[tokio::test]
    async fn daemon_down_cascade_skips_dependent_checks() {
        // Point at a guaranteed-missing socket so the runner's
        // `connect()` probe fails. The /tmp/<unique> path is never
        // bound by any process.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let phantom_socket = format!("/tmp/doctor-test-{nonce}.sock");
        let rows = execute_checks(&phantom_socket).await;

        let c2 = rows.iter().find(|r| r.id == "C2").expect("C2 present");
        // The cascade is rooted on C2 (socket_reachable) — when C2
        // is not Pass, every daemon-dependent check must Skip.
        if matches!(&c2.outcome, CheckOutcome::Pass { .. }) {
            // A real daemon happens to be listening at the phantom
            // path (impossible by construction). Skip the assertion
            // — the cascade is only testable when C2 is non-Pass.
            return;
        }
        for id in ["C3", "C5", "C6", "C7", "C8", "C11", "C12", "C13"] {
            let row = rows.iter().find(|r| r.id == id).expect("row present");
            assert!(
                matches!(&row.outcome, CheckOutcome::Skip { .. }),
                "{id} must skip when daemon is unreachable; got: {:?}",
                row.outcome
            );
        }
    }

    /// Hint lines in `Skip` rows are surfaced in default mode (not
    /// verbose) when the skip is actionable — e.g. C8 "lite image not
    /// built yet" or C13 "orphans detected". Pure `requires daemon`
    /// skips stay suppressed except in the cascade case.
    #[test]
    fn default_mode_surfaces_skips_with_hints() {
        let rows = vec![
            pass("C1", "daemon process running", "active"),
            skip(
                "C8",
                "lite image present",
                "not built yet",
                Some("image will be built on first session create"),
            ),
        ];
        let mut buf = Vec::new();
        render_report(&mut buf, &rows, false);
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("lite image present"),
            "C8 skip with hint must surface even without verbose; got: {out}"
        );
        assert!(out.contains("hint: image will be built on first session create"));
    }

    ///
    /// (neither `SANDBOX_SOCKET`, `XDG_RUNTIME_DIR`, nor `HOME` is
    /// set), the strict resolver must surface
    /// [`DoctorInternalError::SocketPathUnresolvable`] so the CLI
    /// dispatch in `main.rs` can route it to `process::exit(2)`. This
    /// pins the exit-2 contract at the unit boundary; the matching
    /// CLI-level subprocess assertion lives alongside the other
    /// `integration_doctor_*` tests.
    #[test]
    fn doctor_returns_internal_error_when_socket_path_unresolvable() {
        // No env vars set, no system socket → strict resolver must error.
        let res = resolve_socket_path_strict_with(|_| None, |_| false);
        match res {
            Err(DoctorInternalError::SocketPathUnresolvable { reason }) => {
                assert!(
                    reason.contains("SANDBOX_SOCKET"),
                    "reason must enumerate the missing inputs; got: {reason}"
                );
            }
            other => panic!("expected SocketPathUnresolvable when no env vars set; got: {other:?}"),
        }

        // Empty-string env vars are treated as unset — fall through
        // the full chain (no system socket), then error.
        let res = resolve_socket_path_strict_with(|_| Some(String::new()), |_| false);
        assert!(
            matches!(res, Err(DoctorInternalError::SocketPathUnresolvable { .. })),
            "empty-string env vars must not satisfy the resolver"
        );

        // Precedence: SANDBOX_SOCKET wins outright when populated — even when
        // the system socket exists (exists → true).
        let res = resolve_socket_path_strict_with(
            |name| match name {
                "SANDBOX_SOCKET" => Some("/tmp/explicit.sock".to_string()),
                "XDG_RUNTIME_DIR" => Some("/run/user/1000".to_string()),
                "HOME" => Some("/home/alice".to_string()),
                _ => None,
            },
            |_| true,
        );
        assert_eq!(res.ok().as_deref(), Some("/tmp/explicit.sock"));

        // System socket (if present) wins over XDG/HOME when SANDBOX_SOCKET is unset.
        let res = resolve_socket_path_strict_with(
            |name| match name {
                "XDG_RUNTIME_DIR" => Some("/run/user/1000".to_string()),
                "HOME" => Some("/home/alice".to_string()),
                _ => None,
            },
            |p| p == crate::SYSTEM_SOCKET_PATH,
        );
        assert_eq!(res.ok().as_deref(), Some(crate::SYSTEM_SOCKET_PATH));

        // XDG_RUNTIME_DIR wins over HOME when neither SANDBOX_SOCKET nor a
        // system socket is present.
        let res = resolve_socket_path_strict_with(
            |name| match name {
                "XDG_RUNTIME_DIR" => Some("/run/user/1000".to_string()),
                "HOME" => Some("/home/alice".to_string()),
                _ => None,
            },
            |_| false,
        );
        assert_eq!(
            res.ok().as_deref(),
            Some("/run/user/1000/sandboxd/sandboxd.sock")
        );
    }

    ///
    /// operator-facing message that gets written to stderr before
    /// `process::exit(2)`. Pin the wording so the CLI dispatch stays
    /// diagnosable.
    #[test]
    fn doctor_internal_error_display_is_operator_friendly() {
        let e = DoctorInternalError::SocketPathUnresolvable {
            reason: "no env".to_string(),
        };
        let s = format!("{e}");
        assert!(s.contains("cannot resolve socket path"), "got: {s}");
        assert!(s.contains("no env"), "must echo the inner reason; got: {s}");

        let e = DoctorInternalError::Panic {
            message: "kaboom".to_string(),
        };
        let s = format!("{e}");
        assert!(s.contains("internal panic"), "got: {s}");
        assert!(
            s.contains("kaboom"),
            "must echo the panic payload; got: {s}"
        );
    }
}
