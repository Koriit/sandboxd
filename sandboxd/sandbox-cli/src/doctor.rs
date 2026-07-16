//! `sandbox doctor` — operator-facing diagnostic surface.
//!
//! `doctor` is the single command an operator runs after install
//! (or when something feels off) to verify every load-bearing
//! invariant the daemon depends on: the service is up, the socket is
//! reachable, the CLI matches the daemon version, the caller's account
//! is in the `sandbox` group, the socket has the expected mode, both
//! container images are present, the state-dir has the expected mode,
//! `users.conf` parses + names the daemon's uid, no running session is
//! on a drift'd guest protocol, no substrate resources are orphaned, and
//! the host has free disk space.
//!
//! # Platform split
//!
//! The check registry is numbered `C1..` and partitioned by platform:
//!
//! - **Cross-platform:** C1 (daemon running), C2 (socket reachable),
//!   C3 (version match), C5 (socket perms), C7 (gateway image — host
//!   docker on Linux), C8 (lite image), C10 (state-dir mode), C11
//!   (`users.conf` pool), C12 (guest drift), C13 (orphans), C14 (lima
//!   base image), C15 (disk space).
//! - **Linux-only** (`cfg!(target_os = "linux")`): C4 (group
//!   membership — `getgrouplist(3)` is absent on Apple targets in nix
//!   0.29), C6 (KVM accessible — no `/dev/kvm` on the macOS QEMU+HVF
//!   backend), C9 (route-helper caps — the route install lives inside
//!   the gateway Lima VM on macOS).
//! - **macOS-only** (`cfg!(target_os = "macos")`): C16 (socket_vmnet
//!   installed), C17 (socket_vmnet running), C18 (gateway Lima
//!   instance), C19 (vmnet pool slots), C20 (gateway image inside the
//!   gateway Lima instance — distinct from the Linux host-docker C7),
//!   C21 (lima version), C22 (operator agent checked in), C23 (TCC
//!   workspace access — informational), C24 (host IP forwarding disabled —
//!   `net.inet.ip.forwarding=0` required for egress control; the daemon
//!   refuses to start when non-zero), C25 (current user in `_sandboxd`
//!   group — mirrors the Linux C4 check using direct `libc::getgrouplist`
//!   since nix 0.29 lacks it on Apple targets).
//!
//! The output format is load-bearing for the integration tests:
//! message tokens, glyphs, indentation, and the summary-line wording
//! are byte-for-byte stable.
//!
//! # Execution shape
//!
//! Two phases:
//!
//! 1. Serial — C1 (daemon running) and C2 (socket reachable). If
//!    either fails, every downstream check that requires a running
//!    daemon is short-circuited to `SKIPPED (requires daemon)`. The
//!    host-only checks (C4 group membership, C9 route-helper caps, C10
//!    state-dir mode, C15 disk space) can still run because they only
//!    consult host state.
//! 2. Parallel — the remaining rows fan out via `tokio::task::JoinSet`
//!    so the HTTP-bound checks and host-side checks execute
//!    concurrently. `GET /diagnostics` is fetched once before the
//!    fan-out and shared via `Arc` so the daemon-side checks do not
//!    refetch. Results are reimposed in canonical id order before the
//!    formatter walks the table — fan-out completion order is
//!    non-deterministic but the rendered report is byte-stable.
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
/// Phase 2 (parallel): C3-C14 are spawned concurrently on a
/// [`tokio::task::JoinSet`]; the shared `/diagnostics` payload is
/// fetched once before the fan-out and shared via `Arc`. After all
/// tasks join, results are sorted by check id so the rendered output
/// is byte-stable regardless of completion order.
pub(crate) async fn execute_checks(socket_path: &str) -> Vec<CheckRow> {
    let mut rows: Vec<CheckRow> = Vec::with_capacity(24);

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
    // C12, C13, C14) share a single HTTP round-trip via `Arc`.
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
    // `getgrouplist(3)` is absent on Apple targets in nix 0.29.
    #[cfg(target_os = "linux")]
    set.spawn_blocking(check_group_membership);
    // C5 — sync (stat on the unix socket).
    {
        let socket = socket_path.to_string();
        set.spawn_blocking(move || check_socket_perms(&socket, socket_reachable));
    }
    // C6 — sync transform over the shared diagnostics payload.
    // `/dev/kvm` is a Linux concept (the macOS QEMU+HVF backend has no
    // such device), so the KVM row is Linux-only and absent on macOS.
    #[cfg(target_os = "linux")]
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
    // C9 — sync (forks `getcap`). The route-helper is a Linux container-
    // backend artifact; on macOS the route install happens inside the
    // gateway Lima VM, so this host-side caps check is Linux-only.
    #[cfg(target_os = "linux")]
    set.spawn_blocking(check_route_helper_caps);
    // C10 — sync (stat on per-uid base-dir, legacy fallback).
    set.spawn_blocking(check_state_dir_mode);
    // C11 — `users.conf` is the CIDR-pool allow-list. It is loaded on both
    // platforms (macOS uses it for the lite `/28` allocation), so the row
    // stays on both platforms.
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
    // C14
    {
        let diag = Arc::clone(&diagnostics);
        set.spawn_blocking(move || check_lima_base_image(diag.as_ref().as_ref(), socket_reachable));
    }
    // C15 — disk space (platform-independent). Runs on Linux and macOS.
    // A pure host-side statvfs probe; no daemon dependency.
    set.spawn_blocking(check_disk_space);

    // C16-C23 — macOS-only rows. Each is a thin transform over the
    // macOS `/diagnostics` fields the daemon computes from its existing
    // managers (vmnet pool, gateway Lima manager, agent registry).
    #[cfg(target_os = "macos")]
    {
        {
            let diag = Arc::clone(&diagnostics);
            set.spawn_blocking(move || {
                check_socket_vmnet_installed(diag.as_ref().as_ref(), socket_reachable)
            });
        }
        {
            let diag = Arc::clone(&diagnostics);
            set.spawn_blocking(move || {
                check_socket_vmnet_running(diag.as_ref().as_ref(), socket_reachable)
            });
        }
        {
            let diag = Arc::clone(&diagnostics);
            set.spawn_blocking(move || {
                check_gateway_lima_instance(diag.as_ref().as_ref(), socket_reachable)
            });
        }
        {
            let diag = Arc::clone(&diagnostics);
            set.spawn_blocking(move || {
                check_vmnet_pool_slots(diag.as_ref().as_ref(), socket_reachable)
            });
        }
        {
            let diag = Arc::clone(&diagnostics);
            set.spawn_blocking(move || {
                check_gateway_image_inside_lima(diag.as_ref().as_ref(), socket_reachable)
            });
        }
        {
            let diag = Arc::clone(&diagnostics);
            set.spawn_blocking(move || {
                check_lima_version(diag.as_ref().as_ref(), socket_reachable)
            });
        }
        {
            let diag = Arc::clone(&diagnostics);
            set.spawn_blocking(move || {
                check_operator_agent(diag.as_ref().as_ref(), socket_reachable)
            });
        }
        {
            let diag = Arc::clone(&diagnostics);
            set.spawn_blocking(move || {
                check_tcc_workspace_access(diag.as_ref().as_ref(), socket_reachable)
            });
        }
        // C24 — host IP forwarding disabled. Host-side sysctl read; no
        // daemon dependency. Runs even when the daemon is not yet up.
        set.spawn_blocking(check_ip_forwarding);
        // C25 — operator in '_sandboxd' group. Host-side getgrouplist
        // probe; no daemon dependency. Mirrors the Linux C4 check.
        set.spawn_blocking(check_group_membership_macos);
    }

    // Drain the JoinSet; a panicking task surfaces as a `JoinError`
    // and is re-raised here so [`run`]'s `catch_unwind` boundary routes
    // it to exit code 2.
    let mut parallel: Vec<CheckRow> = Vec::with_capacity(22);
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
///
/// `getgrouplist(3)` is absent on Apple targets in nix 0.29; this
/// check is Linux-only.
#[cfg(target_os = "linux")]
pub(crate) fn check_group_membership() -> CheckRow {
    check_group_membership_with(real_group_resolver)
}

/// Pure inner of [`check_group_membership`], parameterised over the
/// "resolve current process's supplementary group names" function so
/// unit tests can drive the predicate without depending on the
/// running user's actual group set.
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
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

/// Production implementation of the group-membership resolver.
///
/// Determines whether the current user is a member of the `sandbox` group by
/// consulting the user's *configured* group set — the union of the primary
/// group from `/etc/passwd` and the supplementary groups from `/etc/group`,
/// as returned by `getgrouplist(3)`. This is distinct from the live process
/// groups returned by `getgroups(2)`, which reflect only the groups that were
/// in effect when the process's session was established.
///
/// Using the configured set is correct because operators may run `newgrp
/// sandbox`, which promotes `sandbox` to the primary group and silently drops
/// it from the supplementary list — making a `getgroups`-based check
/// false-negative even though the user is genuinely a member.
#[cfg(target_os = "linux")]
fn real_group_resolver() -> Result<GroupMembership, String> {
    resolve_group_membership_with_source(nix::unistd::getgrouplist)
}

/// Inner implementation of the group-membership resolver, parameterised over
/// the `getgrouplist(3)` syscall so unit tests can inject an arbitrary
/// configured-group set without touching `/etc/group`.
///
/// `groups_source` receives the current user's login name (as a C string)
/// and primary GID, and must return the full configured GID list as
/// `getgrouplist(3)` would — that is, the union of the primary GID and every
/// supplementary GID present in `/etc/group` for that user.
#[cfg(target_os = "linux")]
pub(crate) fn resolve_group_membership_with_source<F>(
    groups_source: F,
) -> Result<GroupMembership, String>
where
    F: Fn(&std::ffi::CStr, nix::unistd::Gid) -> Result<Vec<nix::unistd::Gid>, nix::errno::Errno>,
{
    let uid = nix::unistd::Uid::current();
    let user = nix::unistd::User::from_uid(uid)
        .map_err(|e| format!("getpwuid_r: {e}"))?
        .ok_or_else(|| format!("uid {uid} not in passwd"))?;
    let user_name = user.name.clone();

    let sandbox_group =
        nix::unistd::Group::from_name("sandbox").map_err(|e| format!("getgrnam_r: {e}"))?;

    // Build the configured group set via the injected groups_source, which
    // in production wraps getgrouplist(3). Reads /etc/group for supplementary
    // groups and always includes the primary gid.
    let username_c = std::ffi::CString::new(user.name.as_str())
        .map_err(|e| format!("CString conversion: {e}"))?;
    let configured_gids =
        groups_source(&username_c, user.gid).map_err(|e| format!("getgrouplist: {e}"))?;

    let mut group_names: Vec<String> = Vec::with_capacity(configured_gids.len());
    for gid in &configured_gids {
        if let Ok(Some(group)) = nix::unistd::Group::from_gid(*gid) {
            group_names.push(group.name);
        }
    }

    match sandbox_group {
        None => Ok(GroupMembership::SandboxGroupAbsent),
        Some(sg) => {
            if configured_gids.contains(&sg.gid) {
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
///
/// Linux-only: the macOS QEMU+HVF backend has no `/dev/kvm`.
#[cfg(target_os = "linux")]
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
// Individual checks — C14 (lima base image present)
// ---------------------------------------------------------------------------

/// C14 — lima base image present (informational).
///
/// The Lima base VM is built on first lima-backend session-create; an
/// absent base image is the normal post-install state, not a failure.
/// We render it as a `Skip` with the "not built yet" annotation.
///
/// All lima state comes from the daemon's `/diagnostics` payload — the CLI
/// never calls `limactl` or the lima-helper directly.
fn check_lima_base_image(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return CheckRow {
            id: "C14",
            name: "lima base image present",
            outcome: CheckOutcome::Skip {
                detail: "requires daemon".to_string(),
                hint: None,
            },
        };
    }
    match diagnostics {
        Some(d) if d.lima_base_image_present => CheckRow {
            id: "C14",
            name: "lima base image present",
            outcome: CheckOutcome::Pass {
                detail: sandbox_core::DEFAULT_BASE_VM_NAME.to_string(),
            },
        },
        Some(d) if d.lima_base_image_probe_failed => {
            // The probe could not run to a verdict (lima-helper
            // unreachable, limactl missing/timeout, Lima backend not set
            // up). C14 is informational so we render this as Skip — but
            // with the probe-failure detail and hint rather than the
            // "not built yet" wording, so the operator knows the
            // infrastructure is the issue, not the image.
            let detail = match d.lima_base_image_probe_error.as_deref() {
                Some(err) if !err.is_empty() => format!("probe failed: {err}"),
                _ => "probe failed".to_string(),
            };
            CheckRow {
                id: "C14",
                name: "lima base image present",
                outcome: CheckOutcome::Skip {
                    detail,
                    hint: Some(
                        "if you intend to use the Lima (full) backend, verify the \
                         lima-helper is installed and the backend is configured; \
                         otherwise this check is safe to ignore"
                            .to_string(),
                    ),
                },
            }
        }
        Some(_) => CheckRow {
            id: "C14",
            name: "lima base image present",
            outcome: CheckOutcome::Skip {
                detail: "not built yet".to_string(),
                hint: Some(
                    "image is built on first Lima session create; or pre-build: \
                     sandbox rebuild-image --backend lima"
                        .to_string(),
                ),
            },
        },
        None => CheckRow {
            id: "C14",
            name: "lima base image present",
            outcome: CheckOutcome::Skip {
                detail: "/diagnostics probe failed".to_string(),
                hint: None,
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Individual checks — C15 (disk space, platform-independent)
// ---------------------------------------------------------------------------

/// Warn threshold for free space on the filesystem holding
/// `/var/lib/sandboxd/`. Below this the disk-space row warns. This is a
/// first-cut value; the right number depends on measuring real growth.
const DISK_SPACE_WARN_GIB: u64 = 10;

/// C15 — free space on the filesystem containing `/var/lib/sandboxd/`.
///
/// Platform-independent host probe (no daemon dependency). The check
/// **warns** (renders as `Skip` with a hint, so it surfaces in default
/// mode but never flips the exit code to `1`) when free space drops
/// below [`DISK_SPACE_WARN_GIB`]; otherwise `Pass`. The daemon does not
/// enforce a disk budget on `sandbox create` — this is advisory only.
///
/// Reuses the `update` module's `statvfs` helper (with its
/// first-existing-ancestor fallback) so the probe path matches the
/// `sandbox update` pre-flight rather than re-deriving it.
fn check_disk_space() -> CheckRow {
    // Resolve the filesystem the production daemon's state tree lives on.
    // On a dev host where the `sandbox` user is absent, fall back to the
    // state-root mount point.
    let probe_path =
        crate::update::prod_base_dir().unwrap_or_else(|| PathBuf::from("/var/lib/sandboxd"));
    let free_kb = crate::update::free_kb_at(&probe_path);
    let free_gib = free_kb / (1024 * 1024);
    let warn_kb = DISK_SPACE_WARN_GIB * 1024 * 1024;

    if free_kb >= warn_kb {
        CheckRow {
            id: "C15",
            name: "disk space",
            outcome: CheckOutcome::Pass {
                detail: format!("{free_gib} GiB free on {}", probe_path.display()),
            },
        }
    } else {
        CheckRow {
            id: "C15",
            name: "disk space",
            outcome: CheckOutcome::Skip {
                detail: format!(
                    "low: {free_gib} GiB free on {} (< {DISK_SPACE_WARN_GIB} GiB)",
                    probe_path.display()
                ),
                hint: Some(
                    "free space on the sandboxd state filesystem is low; \
                     reclaim with `sandbox rm` of unused sessions or prune \
                     stale VM/image artifacts"
                        .to_string(),
                ),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Individual checks — C16-C23 (macOS-only)
// ---------------------------------------------------------------------------

/// Shared "requires daemon" skip row for the macOS checks.
#[cfg(target_os = "macos")]
fn requires_daemon_skip(id: &'static str, name: &'static str) -> CheckRow {
    CheckRow {
        id,
        name,
        outcome: CheckOutcome::Skip {
            detail: "requires daemon".to_string(),
            hint: None,
        },
    }
}

/// C16 — socket_vmnet binary staged with root-owned ancestry.
///
/// The N socket_vmnet launchd daemons exec this binary as root, so a
/// non-root-writable ancestor would be a privilege-escalation vector.
/// The daemon asserts this at startup; the doctor surfaces the
/// steady-state answer from `/diagnostics`.
#[cfg(target_os = "macos")]
fn check_socket_vmnet_installed(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return requires_daemon_skip("C16", "socket_vmnet installed");
    }
    match diagnostics.and_then(|d| d.socket_vmnet_installed) {
        Some(true) => CheckRow {
            id: "C16",
            name: "socket_vmnet installed",
            outcome: CheckOutcome::Pass {
                detail: sandbox_core::network::STAGED_SOCKET_VMNET_PATH.to_string(),
            },
        },
        Some(false) => CheckRow {
            id: "C16",
            name: "socket_vmnet installed",
            outcome: CheckOutcome::Fail {
                detail: format!(
                    "{} missing or has non-root-writable ancestry",
                    sandbox_core::network::STAGED_SOCKET_VMNET_PATH
                ),
                hint: Some(
                    "re-run the installer to stage socket_vmnet with root-owned \
                     ancestry: sandbox update (or scripts/install.sh)"
                        .to_string(),
                ),
            },
        },
        None => CheckRow {
            id: "C16",
            name: "socket_vmnet installed",
            outcome: CheckOutcome::Skip {
                detail: "/diagnostics probe failed".to_string(),
                hint: None,
            },
        },
    }
}

/// C17 — socket_vmnet slot sockets present.
///
/// Verifies the N `io.sandboxd.vmnet.<n>` daemons' slot sockets exist
/// under `/var/run/sandbox/vmnet/` (functional reachability, mirroring
/// the daemon's startup prereq). Separate row from the binary-present
/// check (C16) per the spec.
#[cfg(target_os = "macos")]
fn check_socket_vmnet_running(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return requires_daemon_skip("C17", "socket_vmnet running");
    }
    let running = diagnostics.and_then(|d| d.socket_vmnet_running);
    let count = diagnostics.and_then(|d| d.socket_vmnet_running_count);
    let expected = diagnostics.and_then(|d| d.socket_vmnet_expected_count);
    match (running, count, expected) {
        (Some(true), Some(c), Some(e)) => CheckRow {
            id: "C17",
            name: "socket_vmnet running",
            outcome: CheckOutcome::Pass {
                detail: format!("{c}/{e} slot sockets present"),
            },
        },
        (Some(false), Some(c), Some(e)) => CheckRow {
            id: "C17",
            name: "socket_vmnet running",
            outcome: CheckOutcome::Fail {
                detail: format!("{c}/{e} slot sockets present"),
                hint: Some(
                    "load the socket_vmnet launchd daemons: re-run the installer \
                     (sandbox update), then restart sandboxd"
                        .to_string(),
                ),
            },
        },
        _ => CheckRow {
            id: "C17",
            name: "socket_vmnet running",
            outcome: CheckOutcome::Skip {
                detail: "/diagnostics probe failed".to_string(),
                hint: None,
            },
        },
    }
}

/// C18 — gateway Lima instance exists, is running, and its forwarded
/// Docker socket is reachable.
#[cfg(target_os = "macos")]
fn check_gateway_lima_instance(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return requires_daemon_skip("C18", "gateway Lima instance");
    }
    match diagnostics.and_then(|d| d.gateway_lima_state.as_deref()) {
        Some("running") => CheckRow {
            id: "C18",
            name: "gateway Lima instance",
            outcome: CheckOutcome::Pass {
                detail: format!("{} running, docker reachable", "sandboxd-gateway"),
            },
        },
        Some(state @ ("stopped" | "absent" | "error")) => {
            let (detail, hint) = match state {
                "stopped" => (
                    "sandboxd-gateway stopped".to_string(),
                    "restart sandboxd to bring up the gateway Lima instance",
                ),
                "absent" => (
                    "sandboxd-gateway absent".to_string(),
                    "restart sandboxd to create the gateway Lima instance",
                ),
                _ => (
                    "sandboxd-gateway running but docker socket unreachable".to_string(),
                    "restart sandboxd; if it persists, inspect the gateway VM's docker daemon",
                ),
            };
            CheckRow {
                id: "C18",
                name: "gateway Lima instance",
                outcome: CheckOutcome::Fail {
                    detail,
                    hint: Some(hint.to_string()),
                },
            }
        }
        _ => CheckRow {
            id: "C18",
            name: "gateway Lima instance",
            outcome: CheckOutcome::Skip {
                detail: "/diagnostics probe failed".to_string(),
                hint: None,
            },
        },
    }
}

/// C19 — vmnet pool has the configured slot count and no leaked slots.
///
/// A leaked slot is one still claimed by a session that no longer exists.
#[cfg(target_os = "macos")]
fn check_vmnet_pool_slots(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return requires_daemon_skip("C19", "vmnet pool slots");
    }
    let size = diagnostics.and_then(|d| d.vmnet_pool_size);
    let claimed = diagnostics.and_then(|d| d.vmnet_pool_claimed);
    let leaked = diagnostics
        .and_then(|d| d.vmnet_pool_leaked_slots.as_ref())
        .cloned()
        .unwrap_or_default();
    match (size, claimed) {
        (Some(size), Some(claimed)) if leaked.is_empty() => CheckRow {
            id: "C19",
            name: "vmnet pool slots",
            outcome: CheckOutcome::Pass {
                detail: format!("{claimed}/{size} slots claimed, no leaks"),
            },
        },
        (Some(size), Some(claimed)) => CheckRow {
            id: "C19",
            name: "vmnet pool slots",
            outcome: CheckOutcome::Fail {
                detail: format!(
                    "{claimed}/{size} slots claimed; leaked slots {leaked:?} (no live session)"
                ),
                hint: Some(
                    "a slot is claimed by a session that no longer exists; \
                     restart sandboxd to reconcile the pool"
                        .to_string(),
                ),
            },
        },
        _ => CheckRow {
            id: "C19",
            name: "vmnet pool slots",
            outcome: CheckOutcome::Skip {
                detail: "/diagnostics probe failed".to_string(),
                hint: None,
            },
        },
    }
}

/// C20 — version-pinned gateway image present inside the gateway Lima
/// instance (probed via the forwarded Docker socket).
///
/// Distinct from the Linux host-docker gateway-image check (C7), which is
/// cfg-gated off on macOS — on macOS the relevant Docker daemon is the
/// gateway Lima instance's, reached over the forwarded socket.
#[cfg(target_os = "macos")]
fn check_gateway_image_inside_lima(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return requires_daemon_skip("C20", "gateway image (inside Lima)");
    }
    let present = diagnostics.and_then(|d| d.gateway_image_inside_lima_present);
    let probe_failed = diagnostics
        .and_then(|d| d.gateway_image_inside_lima_probe_failed)
        .unwrap_or(false);
    let expected = diagnostics
        .and_then(|d| d.gateway_image_inside_lima_expected_tag.clone())
        .unwrap_or_else(|| "sandbox-gateway".to_string());
    if probe_failed {
        let detail =
            match diagnostics.and_then(|d| d.gateway_image_inside_lima_probe_error.as_deref()) {
                Some(err) if !err.is_empty() => format!("probe failed: {err}"),
                _ => "probe failed".to_string(),
            };
        return CheckRow {
            id: "C20",
            name: "gateway image (inside Lima)",
            outcome: CheckOutcome::Fail {
                detail,
                hint: Some(
                    "verify the gateway Lima instance is up and its docker daemon \
                     reachable; restart sandboxd once it is responsive"
                        .to_string(),
                ),
            },
        };
    }
    match present {
        Some(true) => CheckRow {
            id: "C20",
            name: "gateway image (inside Lima)",
            outcome: CheckOutcome::Pass {
                // Prefer the daemon-reported present tag; fall back to the
                // expected tag if (older daemon) it is absent.
                detail: diagnostics
                    .and_then(|d| d.gateway_image_tag_inside_lima.clone())
                    .unwrap_or(expected),
            },
        },
        Some(false) => CheckRow {
            id: "C20",
            name: "gateway image (inside Lima)",
            outcome: CheckOutcome::Fail {
                detail: format!("missing {expected}"),
                hint: Some(
                    "the daemon loads the gateway image into the gateway Lima \
                     instance from its staged tarball at startup; restart sandboxd"
                        .to_string(),
                ),
            },
        },
        None => CheckRow {
            id: "C20",
            name: "gateway image (inside Lima)",
            outcome: CheckOutcome::Skip {
                detail: "/diagnostics probe failed".to_string(),
                hint: None,
            },
        },
    }
}

/// C21 — `limactl` version ≥ [`MIN_LIMA_VERSION`].
#[cfg(target_os = "macos")]
fn check_lima_version(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return requires_daemon_skip("C21", "lima version");
    }
    match diagnostics.and_then(|d| d.lima_version.as_deref()) {
        Some(ver) if lima_version_at_least(ver, sandbox_core::MIN_LIMA_VERSION) => CheckRow {
            id: "C21",
            name: "lima version",
            outcome: CheckOutcome::Pass {
                detail: format!("{ver} (>= {})", sandbox_core::MIN_LIMA_VERSION),
            },
        },
        Some(ver) => CheckRow {
            id: "C21",
            name: "lima version",
            outcome: CheckOutcome::Fail {
                detail: format!("{ver} (< {})", sandbox_core::MIN_LIMA_VERSION),
                hint: Some("upgrade Lima to the required minimum: brew upgrade lima".to_string()),
            },
        },
        None => CheckRow {
            id: "C21",
            name: "lima version",
            outcome: CheckOutcome::Skip {
                detail: "probe failed (limactl not found or version unparsable)".to_string(),
                hint: Some(
                    "ensure limactl is installed and on PATH: brew install lima".to_string(),
                ),
            },
        },
    }
}

/// Compare two dotted-numeric version strings, returning `true` when
/// `have >= want`. Tolerant of differing component counts (missing
/// components are treated as `0`) and non-numeric tails (ignored).
#[cfg(target_os = "macos")]
fn lima_version_at_least(have: &str, want: &str) -> bool {
    fn parts(v: &str) -> Vec<u64> {
        v.trim_start_matches('v')
            .split('.')
            .map(|p| {
                let digits: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
                digits.parse::<u64>().unwrap_or(0)
            })
            .collect()
    }
    let h = parts(have);
    let w = parts(want);
    let n = h.len().max(w.len());
    for i in 0..n {
        let hv = h.get(i).copied().unwrap_or(0);
        let wv = w.get(i).copied().unwrap_or(0);
        if hv != wv {
            return hv > wv;
        }
    }
    true
}

/// C22 — the calling operator's per-operator agent is checked in.
///
/// `limactl` control-plane ops are brokered through the operator's agent
/// on macOS, so an enrolled-but-disconnected agent (typically: operator
/// not logged in) is surfaced as a warning.
#[cfg(target_os = "macos")]
fn check_operator_agent(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return requires_daemon_skip("C22", "operator agent checked in");
    }
    match diagnostics.and_then(|d| d.operator_agent_checked_in) {
        Some(true) => CheckRow {
            id: "C22",
            name: "operator agent checked in",
            outcome: CheckOutcome::Pass {
                detail: "agent connected to broker".to_string(),
            },
        },
        Some(false) => CheckRow {
            id: "C22",
            name: "operator agent checked in",
            outcome: CheckOutcome::Skip {
                detail: "agent not connected".to_string(),
                hint: Some(
                    "the per-operator agent (io.sandboxd.agent) is not checked in; \
                     log in as this operator so limactl ops can be brokered"
                        .to_string(),
                ),
            },
        },
        None => CheckRow {
            id: "C22",
            name: "operator agent checked in",
            outcome: CheckOutcome::Skip {
                detail: "/diagnostics probe failed".to_string(),
                hint: None,
            },
        },
    }
}

/// C23 — TCC workspace access (informational stub).
///
/// Lands the row so operators see the check exists; the real TCC-chain
/// attribution (which protected root denied access) is deferred. Renders
/// as an informational `Skip`.
#[cfg(target_os = "macos")]
fn check_tcc_workspace_access(
    diagnostics: Option<&DiagnosticsPayload>,
    socket_reachable: bool,
) -> CheckRow {
    if !socket_reachable {
        return requires_daemon_skip("C23", "TCC workspace access");
    }
    let detail = diagnostics
        .and_then(|d| d.tcc_workspace_access.clone())
        .unwrap_or_else(|| "informational".to_string());
    CheckRow {
        id: "C23",
        name: "TCC workspace access",
        outcome: CheckOutcome::Skip {
            detail,
            hint: Some(
                "informational only; if session create fails on a TCC-protected \
                 path (Desktop/Documents/Downloads), grant the daemon Full Disk \
                 Access in System Settings > Privacy & Security"
                    .to_string(),
            ),
        },
    }
}

// ---------------------------------------------------------------------------
// Individual checks — C24 (IP forwarding disabled, macOS-only)
// ---------------------------------------------------------------------------

/// Pure verdict helper for C24 — testable without spawning sysctl.
///
/// `v4` is the raw string value of `net.inet.ip.forwarding` (e.g. `"0"` or
/// `"1"`); `v6` the same for `net.inet6.ip6.forwarding`. Both are already
/// treated defensively by the caller: an absent or empty key is passed as
/// `"0"` (off), matching the daemon's `check_host_ip_forwarding_disabled`
/// contract.
#[cfg(target_os = "macos")]
pub(crate) fn forwarding_verdict(v4: &str, v6: &str) -> CheckOutcome {
    if v4 != "0" {
        CheckOutcome::Fail {
            detail: format!("net.inet.ip.forwarding={v4} (must be 0)"),
            hint: Some(
                "sudo sysctl -w net.inet.ip.forwarding=0\n    \
                 (Internet Sharing and sleep/wake can re-enable forwarding)"
                    .to_string(),
            ),
        }
    } else if v6 != "0" {
        CheckOutcome::Fail {
            detail: format!("net.inet6.ip6.forwarding={v6} (must be 0)"),
            hint: Some("sudo sysctl -w net.inet6.ip6.forwarding=0".to_string()),
        }
    } else {
        CheckOutcome::Pass {
            detail: "net.inet.ip.forwarding=0, net.inet6.ip6.forwarding=0".to_string(),
        }
    }
}

/// Read a sysctl value by key via `/usr/sbin/sysctl -n`.
///
/// Returns the trimmed stdout string. An absent or empty key returns `"0"`
/// defensively — identical to the daemon's `check_host_ip_forwarding_disabled`
/// behaviour: a missing forwarding knob cannot be enabled.
#[cfg(target_os = "macos")]
fn read_forwarding_sysctl(key: &str) -> String {
    std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", key])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "0".to_string())
}

/// C24 — host IP forwarding must be 0 on both IPv4 and IPv6.
///
/// When `net.inet.ip.forwarding=1` the daemon refuses to start: host
/// forwarding could route guest traffic around the gateway, voiding the
/// egress guarantee. Internet Sharing and sleep/wake cycles can silently
/// flip this knob. This row surfaces the current value so operators see
/// the problem before puzzling over an opaque daemon-startup failure.
///
/// Host-side only; does not require a running daemon.
#[cfg(target_os = "macos")]
fn check_ip_forwarding() -> CheckRow {
    let v4 = read_forwarding_sysctl("net.inet.ip.forwarding");
    let v6 = read_forwarding_sysctl("net.inet6.ip6.forwarding");
    CheckRow {
        id: "C24",
        name: "IP forwarding disabled",
        outcome: forwarding_verdict(&v4, &v6),
    }
}

// ---------------------------------------------------------------------------
// Individual checks — C25 (operator group membership, macOS-only)
// ---------------------------------------------------------------------------

/// Outcome of checking whether the current user is a member of the
/// `_sandboxd` group on macOS. Three states, mirroring the Linux
/// `GroupMembership` enum for C4:
///
/// - `GroupAbsent` — `_sandboxd` group not found on the host (dev mode or
///   not yet installed).
/// - `Member` — operator's uid is in the `_sandboxd` group.
/// - `NotMember` — group exists but the operator is not in it.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MacGroupMembership {
    GroupAbsent,
    Member { user: String },
    NotMember { user: String },
}

/// C25 — current user is in the `_sandboxd` group.
///
/// On macOS, the daemon (`_sandboxd`) gates operator enrollment at the
/// broker via `getgrouplist(3)` against the `_sandboxd` group. This row
/// checks the same gate from the CLI side so operators see their
/// enrolment status without waiting for a session create to fail.
///
/// Uses `libc::getgrouplist` directly because nix 0.29 does not expose
/// `getgrouplist` on Apple targets. Mirrors `broker.rs:uid_in_sandbox_group`.
///
/// Host-side only; does not require a running daemon.
#[cfg(target_os = "macos")]
pub(crate) fn check_group_membership_macos() -> CheckRow {
    check_group_membership_macos_with(resolve_macos_group_membership)
}

/// Pure inner of [`check_group_membership_macos`], parameterised over the
/// membership resolver so unit tests can drive every verdict path without
/// touching the real directory service.
#[cfg(target_os = "macos")]
pub(crate) fn check_group_membership_macos_with<R>(resolver: R) -> CheckRow
where
    R: FnOnce() -> Result<MacGroupMembership, String>,
{
    const GROUP: &str = "_sandboxd";
    match resolver() {
        Ok(MacGroupMembership::GroupAbsent) => CheckRow {
            id: "C25",
            name: "current user in '_sandboxd' group",
            outcome: CheckOutcome::Skip {
                detail: format!("no '{GROUP}' group; dev mode or not installed"),
                hint: None,
            },
        },
        Ok(MacGroupMembership::Member { user }) => CheckRow {
            id: "C25",
            name: "current user in '_sandboxd' group",
            outcome: CheckOutcome::Pass {
                detail: format!("{user} \u{2208} {GROUP}"),
            },
        },
        Ok(MacGroupMembership::NotMember { user }) => CheckRow {
            id: "C25",
            name: "current user in '_sandboxd' group",
            outcome: CheckOutcome::Fail {
                detail: format!("{user} is not in the '{GROUP}' group"),
                hint: Some(format!(
                    "sudo dseditgroup -o edit -a $USER -t user {GROUP}; log out and back in"
                )),
            },
        },
        Err(e) => CheckRow {
            id: "C25",
            name: "current user in '_sandboxd' group",
            outcome: CheckOutcome::Fail {
                detail: format!("group lookup failed: {e}"),
                hint: Some(format!(
                    "sudo dseditgroup -o edit -a $USER -t user {GROUP}; log out and back in"
                )),
            },
        },
    }
}

/// Production resolver for C25.
///
/// Checks whether the current user's uid is a member of the `_sandboxd`
/// group using `getgrouplist(3)` via libc — the same call and the same
/// group the broker gate in `broker.rs` enforces at check-in time.
///
/// Returns:
/// - `Ok(GroupAbsent)` when `_sandboxd` is not found on the host.
/// - `Ok(Member { user })` / `Ok(NotMember { user })` on a successful lookup.
/// - `Err(reason)` on any uid/group resolution failure other than group-absent.
#[cfg(target_os = "macos")]
fn resolve_macos_group_membership() -> Result<MacGroupMembership, String> {
    use std::ffi::CString;

    let uid = unsafe { libc::getuid() };

    // Step 1: resolve the username for getgrouplist (mirrors broker.rs).
    let bufsize = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let bufsize = if bufsize <= 0 { 1024 } else { bufsize as usize };
    let mut buf = vec![0i8; bufsize];
    let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result_ptr: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), bufsize, &mut result_ptr) };
    if rc != 0 || result_ptr.is_null() {
        return Err(format!("getpwuid_r uid={uid}: rc={rc}"));
    }
    let name_ptr = unsafe { (*result_ptr).pw_name };
    if name_ptr.is_null() {
        return Err(format!("getpwuid_r uid={uid}: pw_name is null"));
    }
    let username = unsafe { std::ffi::CStr::from_ptr(name_ptr) }
        .to_str()
        .map_err(|e| format!("pw_name is invalid UTF-8: {e}"))?
        .to_string();
    let primary_gid = unsafe { (*result_ptr).pw_gid };

    // Step 2: resolve the gid of the _sandboxd group (absent → GroupAbsent).
    let group_name_c = CString::new("_sandboxd").map_err(|e| format!("CString: {e}"))?;
    let gr_bufsize = unsafe { libc::sysconf(libc::_SC_GETGR_R_SIZE_MAX) };
    let gr_bufsize = if gr_bufsize <= 0 {
        1024
    } else {
        gr_bufsize as usize
    };
    let mut gr_buf = vec![0i8; gr_bufsize];
    let mut grp = unsafe { std::mem::zeroed::<libc::group>() };
    let mut grp_result: *mut libc::group = std::ptr::null_mut();
    let rc = unsafe {
        libc::getgrnam_r(
            group_name_c.as_ptr(),
            &mut grp,
            gr_buf.as_mut_ptr(),
            gr_bufsize,
            &mut grp_result,
        )
    };
    if rc != 0 || grp_result.is_null() {
        // Group not found — dev mode or not yet installed.
        return Ok(MacGroupMembership::GroupAbsent);
    }
    let target_gid = unsafe { (*grp_result).gr_gid };

    // Step 3: call getgrouplist with a growable buffer.
    // On macOS, getgrouplist takes int (i32) for the primary gid and
    // int[] for the groups buffer. Mirrors broker.rs:uid_in_sandbox_group.
    let name_c = CString::new(username.as_bytes()).map_err(|e| format!("CString: {e}"))?;
    let mut ngroups: libc::c_int = 64;
    loop {
        let mut groups: Vec<libc::c_int> = vec![0; ngroups as usize];
        // SAFETY: name_c is a valid NUL-terminated C string; groups is a
        // properly-sized mutable buffer; primary_gid is the user's real gid
        // from the directory service.
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
                // Buffer too small; ngroups holds the required count.
                continue;
            }
            return Err(format!(
                "getgrouplist overflow for uid={uid} (ngroups={ngroups})"
            ));
        }
        // ret >= 0: groups[0..ngroups] is the complete list.
        let is_member = groups
            .iter()
            .take(ngroups as usize)
            .any(|&g| g as libc::gid_t == target_gid);
        return Ok(if is_member {
            MacGroupMembership::Member { user: username }
        } else {
            MacGroupMembership::NotMember { user: username }
        });
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
///
/// Linux-only: on macOS the route install happens inside the gateway
/// Lima VM, so there is no host-side route-helper to cap-check.
#[cfg(target_os = "linux")]
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
    // Read only by the Linux-only C6 KVM row; unused on macOS.
    #[serde(default)]
    #[allow(dead_code)]
    pub kvm_readable: bool,
    #[serde(default)]
    #[allow(dead_code)]
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
    /// `true` when the Lima base VM (`sandbox-base`) is present in the
    /// operator's LIMA_HOME. `false` either when the VM has not been
    /// built yet (normal post-install state) or when the probe could
    /// not run to a verdict. `#[serde(default)]` keeps this readable
    /// against an older daemon that omits the field.
    #[serde(default)]
    pub lima_base_image_present: bool,
    /// `true` when the Lima base-image probe could not run to a verdict
    /// (lima-helper unreachable, limactl missing/timeout, lima backend
    /// not set up, etc.). C14 renders this as `Skip` so a probe
    /// infrastructure problem does not masquerade as a missing image.
    #[serde(default)]
    pub lima_base_image_probe_failed: bool,
    /// Operator-facing reason the Lima base-image probe failed. `None`
    /// when the probe succeeded or when an older daemon omits the field.
    #[serde(default)]
    pub lima_base_image_probe_error: Option<String>,
    #[serde(default)]
    pub users_conf_pool: Option<UsersConfPoolDto>,
    #[serde(default)]
    pub guest_version_drift: Option<Vec<GuestVersionDriftEntry>>,
    #[serde(default)]
    pub substrate_orphans: Option<SubstrateOrphans>,

    // -----------------------------------------------------------------
    // macOS-only fields. Absent (not null) on Linux — the daemon omits
    // them entirely; `#[serde(default)]` makes them `None` on any
    // platform. The macOS doctor rows that read them are themselves
    // `#[cfg(target_os = "macos")]`, so the Linux build never consults
    // these (they exist on the struct on both platforms only because the
    // CLI is cross-compiled).
    // -----------------------------------------------------------------
    // Each macOS field is read only by a `#[cfg(target_os = "macos")]`
    // doctor row, so on the Linux build they are dead — `cfg_attr` the
    // `dead_code` allow on for non-macOS targets only.
    /// Gateway Lima instance verdict: `running` / `stopped` / `absent` /
    /// `error`. `running` folds in a successful forwarded-docker probe.
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub gateway_lima_state: Option<String>,
    /// Configured vmnet pool size (max concurrent macOS sessions).
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub vmnet_pool_size: Option<u16>,
    /// Number of vmnet pool slots currently claimed.
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub vmnet_pool_claimed: Option<usize>,
    /// Slot indices claimed by a session that no longer exists (leaks).
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub vmnet_pool_leaked_slots: Option<Vec<u16>>,
    /// Version-pinned gateway image tag present inside the gateway Lima
    /// instance — `Some(tag)` only when the image is actually present.
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub gateway_image_tag_inside_lima: Option<String>,
    /// `true` when the gateway image is present inside the gateway Lima
    /// instance (forwarded-docker probe ran to a positive verdict).
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub gateway_image_inside_lima_present: Option<bool>,
    /// The tag the daemon expects inside the gateway Lima instance
    /// (rendered in the absent/probe-failed verdicts).
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub gateway_image_inside_lima_expected_tag: Option<String>,
    /// `true` when the gateway-image-inside-lima probe could not run to a
    /// verdict (forwarded docker unreachable, etc.).
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub gateway_image_inside_lima_probe_failed: Option<bool>,
    /// Operator-facing reason the gateway-image-inside-lima probe failed.
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub gateway_image_inside_lima_probe_error: Option<String>,
    /// `true` when the staged `socket_vmnet` binary is present with
    /// root-owned, non-writable ancestry.
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub socket_vmnet_installed: Option<bool>,
    /// `true` when all configured slot sockets are present on disk.
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub socket_vmnet_running: Option<bool>,
    /// Number of slot sockets present on disk.
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub socket_vmnet_running_count: Option<u16>,
    /// Number of slot sockets expected (= configured pool size).
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub socket_vmnet_expected_count: Option<u16>,
    /// `limactl --version` of the daemon's own limactl. `None` when the
    /// probe failed.
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub lima_version: Option<String>,
    /// `true` when the calling operator's per-operator agent is currently
    /// checked in to the broker channel.
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub operator_agent_checked_in: Option<bool>,
    /// TCC workspace-access verdict — informational stub. Real TCC-chain
    /// attribution is deferred.
    #[serde(default)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub tcc_workspace_access: Option<String>,
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
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
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

    // ---------------------------------------------------------------------------
    // A2 regression: configured group membership wins over live process groups
    // ---------------------------------------------------------------------------

    /// Verifies that `check_group_membership_with` maps a `Member` resolver
    /// result to a `Pass` check row containing the username and group names.
    /// This covers the outer predicate logic only; for the `getgrouplist`
    /// injection path see `configured_member_not_in_live_groups_resolves_member`.
    #[cfg(target_os = "linux")]
    #[test]
    fn group_check_passes_for_configured_member_not_in_live_groups() {
        let row = check_group_membership_with(|| {
            Ok(GroupMembership::Member {
                user: "bob".to_string(),
                group_names_csv: "sandbox".to_string(),
            })
        });
        match row.outcome {
            CheckOutcome::Pass { detail } => {
                assert!(
                    detail.contains("bob"),
                    "pass detail must include username; got: {detail}"
                );
                assert!(
                    detail.contains("sandbox"),
                    "pass detail must include group name; got: {detail}"
                );
            }
            other => {
                panic!("expected Pass for configured member not in live groups, got {other:?}")
            }
        }
    }

    /// When a user runs `newgrp sandbox`, the shell promotes `sandbox` to the
    /// primary group and drops it from the supplementary list. A live
    /// `getgroups(2)` call would then not include the sandbox GID, giving a
    /// false-negative. `resolve_group_membership_with_source` uses
    /// `getgrouplist(3)` (via the injected `groups_source`) which reads
    /// `/etc/group` regardless of the live session state.
    ///
    /// This test injects a `groups_source` that returns the sandbox GID
    /// (simulating what `getgrouplist` returns for a properly configured user
    /// even after `newgrp` has swapped the group to primary) and asserts that
    /// the resolver produces `Member`, not `NotMember`.
    ///
    /// Requires a `sandbox` group on the host; skips with a message if absent
    /// (such as in a minimal CI container where setup-dev-env has not been run).
    #[cfg(target_os = "linux")]
    #[test]
    fn configured_member_not_in_live_groups_resolves_member() {
        // Resolve the sandbox group's GID using the real system database.
        // On a host where `make setup-dev-env` has been run this will succeed.
        let sandbox_gid = match nix::unistd::Group::from_name("sandbox") {
            Ok(Some(g)) => g.gid,
            Ok(None) => {
                // No sandbox group on this host — not an error in a minimal container.
                eprintln!(
                    "configured_member_not_in_live_groups_resolves_member: \
                     skipped — no 'sandbox' group on this host"
                );
                return;
            }
            Err(e) => panic!("getgrnam_r failed: {e}"),
        };

        // Inject a groups_source that always returns [sandbox_gid], regardless
        // of what getgroups(2) would show for the live process — simulating a
        // user who is configured in /etc/group but whose live supplementary
        // list no longer contains the GID because newgrp promoted it to primary.
        let result =
            resolve_group_membership_with_source(|_username, _primary_gid| Ok(vec![sandbox_gid]));

        match result {
            Ok(GroupMembership::Member { .. }) => {}
            Ok(other) => {
                panic!("expected Member when groups_source returns the sandbox GID, got {other:?}")
            }
            Err(e) => panic!("resolver returned error: {e}"),
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
            lima_base_image_present: false,
            lima_base_image_probe_failed: false,
            lima_base_image_probe_error: None,
            users_conf_pool: None,
            guest_version_drift: None,
            substrate_orphans: None,
            gateway_lima_state: None,
            vmnet_pool_size: None,
            vmnet_pool_claimed: None,
            vmnet_pool_leaked_slots: None,
            gateway_image_tag_inside_lima: None,
            gateway_image_inside_lima_present: None,
            gateway_image_inside_lima_expected_tag: None,
            gateway_image_inside_lima_probe_failed: None,
            gateway_image_inside_lima_probe_error: None,
            socket_vmnet_installed: None,
            socket_vmnet_running: None,
            socket_vmnet_running_count: None,
            socket_vmnet_expected_count: None,
            lima_version: None,
            operator_agent_checked_in: None,
            tcc_workspace_access: None,
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

    /// C14 — probe ran, image present → Pass with the base-VM name.
    #[test]
    fn c14_passes_when_lima_base_image_present() {
        let mut d = diag_default();
        d.lima_base_image_present = true;
        let row = check_lima_base_image(Some(&d), true);
        assert_eq!(row.id, "C14");
        match row.outcome {
            CheckOutcome::Pass { detail } => {
                assert!(
                    detail.contains("sandbox-base"),
                    "pass detail must include the base-VM name; got: {detail}"
                );
            }
            other => panic!("expected Pass, got {other:?}"),
        }
    }

    /// C14 — probe ran, image absent → Skip with the "built on
    /// first Lima session create" annotation (informational; no failure).
    #[test]
    fn c14_skips_with_first_create_hint_when_lima_base_image_absent_but_probe_ok() {
        let d = diag_default();
        let row = check_lima_base_image(Some(&d), true);
        assert_eq!(row.id, "C14");
        match row.outcome {
            CheckOutcome::Skip { detail, hint } => {
                assert!(
                    detail.contains("not built yet"),
                    "absent-image detail must say 'not built yet'; got: {detail}"
                );
                let h = hint.expect("absent image must carry a hint");
                assert!(
                    h.contains("first Lima session create"),
                    "absent-image hint must reference 'first Lima session create'; got: {h}"
                );
                assert!(
                    !h.contains("lima-helper is reachable"),
                    "absent-image hint must not mention lima-helper reachability; got: {h}"
                );
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    /// C14 — the `probe_failed` variant: lima base-image probe could not
    /// run to a verdict. C14 stays Skip (informational), but the hint
    /// switches to lima-helper / sandboxd reachability so an operator
    /// doesn't waste time on `sandbox rebuild-image` when the infrastructure
    /// is the actual problem.
    #[test]
    fn c14_skips_with_lima_hint_when_lima_base_probe_failed() {
        let mut d = diag_default();
        d.lima_base_image_probe_failed = true;
        d.lima_base_image_probe_error = Some("lima-helper: exec format error".to_string());
        let row = check_lima_base_image(Some(&d), true);
        assert_eq!(row.id, "C14");
        match row.outcome {
            CheckOutcome::Skip { detail, hint } => {
                assert!(
                    detail.contains("probe failed"),
                    "probe-failure detail must say 'probe failed'; got: {detail}"
                );
                assert!(
                    detail.contains("lima-helper: exec format error"),
                    "probe-failure detail must echo the operator-facing reason; got: {detail}"
                );
                let h = hint.expect("probe-failure must carry a hint");
                assert!(
                    h.contains("lima-helper"),
                    "probe-failure hint must mention the lima-helper; got: {h}"
                );
                assert!(
                    h.contains("safe to ignore"),
                    "probe-failure hint must note it is safe to ignore on container-only hosts; got: {h}"
                );
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    /// C14 — socket unreachable → Skip "requires daemon".
    #[test]
    fn c14_skips_requires_daemon_when_socket_unreachable() {
        let row = check_lima_base_image(None, false);
        assert_eq!(row.id, "C14");
        match row.outcome {
            CheckOutcome::Skip { detail, .. } => {
                assert!(
                    detail.contains("requires daemon"),
                    "skip detail must say 'requires daemon'; got: {detail}"
                );
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    /// C14 — socket reachable but diagnostics fetch failed → Skip
    /// "/diagnostics probe failed".
    #[test]
    fn c14_skips_diagnostics_probe_failed_when_diagnostics_none_but_socket_reachable() {
        let row = check_lima_base_image(None, true);
        assert_eq!(row.id, "C14");
        match row.outcome {
            CheckOutcome::Skip { detail, hint } => {
                assert!(
                    detail.contains("/diagnostics probe failed"),
                    "skip detail must say '/diagnostics probe failed'; got: {detail}"
                );
                assert!(
                    hint.is_none(),
                    "no hint expected for diagnostics-none branch"
                );
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    /// `DiagnosticsPayload` tolerates a payload written by an older
    /// daemon that does not emit `gateway_image_probe_failed` /
    /// `lite_image_probe_failed` / `lima_base_image_*` / `*_probe_error`.
    /// The bool fields default to `false` and the optional reasons stay
    /// `None`, so C7/C8/C14 render the legacy "absent-image" branches.
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
        assert!(!parsed.lima_base_image_present);
        assert!(!parsed.lima_base_image_probe_failed);
        assert!(parsed.lima_base_image_probe_error.is_none());

        // C14 on an older-daemon payload must render as the "not built yet"
        // Skip — not probe_failed — locking the contract that absent fields
        // parse as false and route through the absent-image branch, not the
        // probe-failure branch.
        let row = check_lima_base_image(Some(&parsed), true);
        assert_eq!(row.id, "C14");
        match row.outcome {
            CheckOutcome::Skip { detail, .. } => assert!(
                detail.contains("not built yet"),
                "older-daemon payload must yield 'not built yet' Skip, got: {detail}"
            ),
            other => panic!("expected Skip for older-daemon payload, got {other:?}"),
        }
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
        // Daemon-dependent rows present on every platform.
        let mut daemon_dependent: Vec<&str> =
            vec!["C3", "C5", "C7", "C8", "C11", "C12", "C13", "C14"];
        // C6 (KVM) is Linux-only; the macOS gateway/vmnet/agent rows are
        // macOS-only. C15 (disk space) and C9/C10 do NOT depend on the
        // daemon, so they are deliberately excluded from this list.
        #[cfg(target_os = "linux")]
        daemon_dependent.push("C6");
        #[cfg(target_os = "macos")]
        daemon_dependent.extend(["C16", "C17", "C18", "C19", "C20", "C21", "C22", "C23"]);
        for id in daemon_dependent {
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

    // -----------------------------------------------------------------
    // C15 — disk space (platform-independent)
    // -----------------------------------------------------------------

    /// `check_disk_space` is a pure host probe with no daemon dependency.
    /// It must always render its row as `Pass` or `Skip` (a warn) — never
    /// `Fail`, since a low-disk advisory must not flip doctor's exit code.
    #[test]
    fn c15_disk_space_is_never_fail() {
        let row = check_disk_space();
        assert_eq!(row.id, "C15");
        assert_eq!(row.name, "disk space");
        match row.outcome {
            CheckOutcome::Pass { .. } | CheckOutcome::Skip { .. } => {}
            CheckOutcome::Fail { .. } => {
                panic!("disk-space row must never Fail (it is advisory only)")
            }
        }
    }

    /// `check_disk_space` runs (and renders C15) on both platforms — it is
    /// not cfg-gated. `execute_checks` against an unreachable socket still
    /// includes a C15 row because the probe is host-side.
    #[tokio::test]
    async fn c15_present_on_all_platforms() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let phantom_socket = format!("/tmp/doctor-disk-test-{nonce}.sock");
        let rows = execute_checks(&phantom_socket).await;
        assert!(
            rows.iter().any(|r| r.id == "C15"),
            "C15 disk-space row must always be present"
        );
    }

    // -----------------------------------------------------------------
    // Platform gating of the Linux-only / macOS-only rows
    // -----------------------------------------------------------------

    /// The Linux-only KVM (C6) and route-helper-caps (C9) rows must be
    /// absent on macOS; the macOS gateway/vmnet/agent rows must be absent
    /// on Linux. Pinned via `execute_checks` so a regression that drops a
    /// cfg gate is caught.
    #[tokio::test]
    async fn platform_rows_are_cfg_gated() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let phantom_socket = format!("/tmp/doctor-gate-test-{nonce}.sock");
        let rows = execute_checks(&phantom_socket).await;
        let ids: std::collections::HashSet<&str> = rows.iter().map(|r| r.id).collect();

        #[cfg(target_os = "macos")]
        {
            assert!(!ids.contains("C6"), "C6 (KVM) must be absent on macOS");
            assert!(
                !ids.contains("C9"),
                "C9 (route-helper caps) must be absent on macOS"
            );
            for id in [
                "C16", "C17", "C18", "C19", "C20", "C21", "C22", "C23", "C24", "C25",
            ] {
                assert!(ids.contains(id), "{id} must be present on macOS");
            }
        }

        #[cfg(target_os = "linux")]
        {
            assert!(ids.contains("C6"), "C6 (KVM) must be present on Linux");
            assert!(
                ids.contains("C9"),
                "C9 (route-helper caps) must be present on Linux"
            );
            for id in [
                "C16", "C17", "C18", "C19", "C20", "C21", "C22", "C23", "C24", "C25",
            ] {
                assert!(!ids.contains(id), "{id} must be absent on Linux");
            }
        }
    }

    // -----------------------------------------------------------------
    // macOS-only check logic (hermetic, over synthetic diagnostics)
    // -----------------------------------------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn lima_version_at_least_compares_dotted_numeric() {
        assert!(lima_version_at_least("1.2.0", "1.2.0"));
        assert!(lima_version_at_least("1.3.0", "1.2.0"));
        assert!(lima_version_at_least("2.0.0", "1.2.0"));
        assert!(lima_version_at_least("1.2.1", "1.2.0"));
        assert!(!lima_version_at_least("1.1.9", "1.2.0"));
        assert!(!lima_version_at_least("1.2", "1.2.1"));
        // tolerant of a `v` prefix and trailing non-numerics
        assert!(lima_version_at_least("v1.2.0-rc1", "1.2.0"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn c21_lima_version_pass_fail_skip() {
        let mut d = diag_default();
        d.lima_version = Some(sandbox_core::MIN_LIMA_VERSION.to_string());
        assert!(matches!(
            check_lima_version(Some(&d), true).outcome,
            CheckOutcome::Pass { .. }
        ));

        d.lima_version = Some("1.0.0".to_string());
        assert!(matches!(
            check_lima_version(Some(&d), true).outcome,
            CheckOutcome::Fail { .. }
        ));

        d.lima_version = None;
        assert!(matches!(
            check_lima_version(Some(&d), true).outcome,
            CheckOutcome::Skip { .. }
        ));

        // socket unreachable → requires-daemon skip
        assert!(matches!(
            check_lima_version(None, false).outcome,
            CheckOutcome::Skip { .. }
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn c18_gateway_lima_instance_verdicts() {
        let mut d = diag_default();
        d.gateway_lima_state = Some("running".to_string());
        assert!(matches!(
            check_gateway_lima_instance(Some(&d), true).outcome,
            CheckOutcome::Pass { .. }
        ));

        for state in ["stopped", "absent", "error"] {
            d.gateway_lima_state = Some(state.to_string());
            assert!(
                matches!(
                    check_gateway_lima_instance(Some(&d), true).outcome,
                    CheckOutcome::Fail { .. }
                ),
                "state {state} must Fail"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn c19_vmnet_pool_flags_leaks() {
        let mut d = diag_default();
        d.vmnet_pool_size = Some(8);
        d.vmnet_pool_claimed = Some(2);
        d.vmnet_pool_leaked_slots = Some(vec![]);
        assert!(matches!(
            check_vmnet_pool_slots(Some(&d), true).outcome,
            CheckOutcome::Pass { .. }
        ));

        d.vmnet_pool_leaked_slots = Some(vec![3]);
        match check_vmnet_pool_slots(Some(&d), true).outcome {
            CheckOutcome::Fail { detail, .. } => {
                assert!(detail.contains("leaked"), "got: {detail}")
            }
            other => panic!("expected Fail on leak, got {other:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn c20_gateway_image_inside_lima_three_state() {
        let mut d = diag_default();
        d.gateway_image_inside_lima_present = Some(true);
        d.gateway_image_tag_inside_lima = Some("sandbox-gateway:1.2.3".to_string());
        match check_gateway_image_inside_lima(Some(&d), true).outcome {
            CheckOutcome::Pass { detail } => {
                assert!(detail.contains("sandbox-gateway:1.2.3"), "got: {detail}")
            }
            other => panic!("expected Pass, got {other:?}"),
        }

        let mut d = diag_default();
        d.gateway_image_inside_lima_present = Some(false);
        d.gateway_image_inside_lima_expected_tag = Some("sandbox-gateway:1.2.3".to_string());
        match check_gateway_image_inside_lima(Some(&d), true).outcome {
            CheckOutcome::Fail { detail, hint } => {
                assert!(detail.contains("missing"), "got: {detail}");
                let h = hint.expect("absent must carry hint");
                assert!(h.contains("restart sandboxd"), "got: {h}");
            }
            other => panic!("expected Fail on absent, got {other:?}"),
        }

        let mut d = diag_default();
        d.gateway_image_inside_lima_probe_failed = Some(true);
        d.gateway_image_inside_lima_probe_error = Some("docker unreachable".to_string());
        match check_gateway_image_inside_lima(Some(&d), true).outcome {
            CheckOutcome::Fail { detail, .. } => {
                assert!(detail.contains("probe failed"), "got: {detail}")
            }
            other => panic!("expected Fail on probe failure, got {other:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn c16_c17_socket_vmnet_rows() {
        let mut d = diag_default();
        d.socket_vmnet_installed = Some(true);
        assert!(matches!(
            check_socket_vmnet_installed(Some(&d), true).outcome,
            CheckOutcome::Pass { .. }
        ));
        d.socket_vmnet_installed = Some(false);
        assert!(matches!(
            check_socket_vmnet_installed(Some(&d), true).outcome,
            CheckOutcome::Fail { .. }
        ));

        let mut d = diag_default();
        d.socket_vmnet_running = Some(true);
        d.socket_vmnet_running_count = Some(8);
        d.socket_vmnet_expected_count = Some(8);
        assert!(matches!(
            check_socket_vmnet_running(Some(&d), true).outcome,
            CheckOutcome::Pass { .. }
        ));
        d.socket_vmnet_running = Some(false);
        d.socket_vmnet_running_count = Some(3);
        assert!(matches!(
            check_socket_vmnet_running(Some(&d), true).outcome,
            CheckOutcome::Fail { .. }
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn c22_operator_agent_warns_when_disconnected() {
        let mut d = diag_default();
        d.operator_agent_checked_in = Some(true);
        assert!(matches!(
            check_operator_agent(Some(&d), true).outcome,
            CheckOutcome::Pass { .. }
        ));
        // enrolled but not connected → warn (Skip with hint), never Fail
        d.operator_agent_checked_in = Some(false);
        match check_operator_agent(Some(&d), true).outcome {
            CheckOutcome::Skip { hint, .. } => {
                assert!(hint.is_some(), "disconnected agent must carry a hint")
            }
            other => panic!("expected Skip (warn), got {other:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn c23_tcc_is_informational_skip() {
        let d = diag_default();
        match check_tcc_workspace_access(Some(&d), true).outcome {
            CheckOutcome::Skip { .. } => {}
            other => panic!("TCC row must be an informational Skip, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // C24 — forwarding_verdict (pure helper, hermetic)
    // -----------------------------------------------------------------

    /// Both sysctls are "0" → Pass.
    #[cfg(target_os = "macos")]
    #[test]
    fn forwarding_verdict_pass_when_both_zero() {
        match forwarding_verdict("0", "0") {
            CheckOutcome::Pass { detail } => {
                assert!(
                    detail.contains("net.inet.ip.forwarding=0"),
                    "pass detail must name the IPv4 key; got: {detail}"
                );
            }
            other => panic!("expected Pass, got {other:?}"),
        }
    }

    /// IPv4 forwarding is 1 → Fail with the sysctl remediation hint.
    #[cfg(target_os = "macos")]
    #[test]
    fn forwarding_verdict_fail_when_v4_nonzero_carries_sysctl_hint() {
        match forwarding_verdict("1", "0") {
            CheckOutcome::Fail { detail, hint } => {
                assert!(
                    detail.contains("net.inet.ip.forwarding=1"),
                    "fail detail must name the key + value; got: {detail}"
                );
                let h = hint.expect("IPv4 Fail must carry a remediation hint");
                assert!(
                    h.contains("sysctl -w net.inet.ip.forwarding=0"),
                    "hint must include the reset command; got: {h}"
                );
                assert!(
                    h.contains("Internet Sharing") || h.contains("sleep"),
                    "hint must note what re-enables forwarding; got: {h}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// IPv6 forwarding is 1 (IPv4 already 0) → Fail with the IPv6 hint.
    #[cfg(target_os = "macos")]
    #[test]
    fn forwarding_verdict_fail_when_v6_nonzero_carries_sysctl_hint() {
        match forwarding_verdict("0", "1") {
            CheckOutcome::Fail { detail, hint } => {
                assert!(
                    detail.contains("net.inet6.ip6.forwarding=1"),
                    "fail detail must name the IPv6 key; got: {detail}"
                );
                let h = hint.expect("IPv6 Fail must carry a remediation hint");
                assert!(
                    h.contains("sysctl -w net.inet6.ip6.forwarding=0"),
                    "hint must include the IPv6 reset command; got: {h}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// The row struct has the correct id and name.
    #[cfg(target_os = "macos")]
    #[test]
    fn c24_row_has_correct_id_and_name() {
        // Use the verdict helper rather than spawning sysctl — host-value
        // doesn't matter for the metadata check.
        let outcome = forwarding_verdict("0", "0");
        let row = CheckRow {
            id: "C24",
            name: "IP forwarding disabled",
            outcome,
        };
        assert_eq!(row.id, "C24");
        assert_eq!(row.name, "IP forwarding disabled");
    }

    // -----------------------------------------------------------------
    // C25 — check_group_membership_macos_with (pure helper, hermetic)
    // -----------------------------------------------------------------

    /// _sandboxd group absent → Skip with dev-mode annotation.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_group_check_skips_when_group_absent() {
        let row = check_group_membership_macos_with(|| Ok(MacGroupMembership::GroupAbsent));
        assert_eq!(row.id, "C25");
        match row.outcome {
            CheckOutcome::Skip { detail, hint } => {
                assert!(
                    detail.contains("_sandboxd"),
                    "skip detail must name the group; got: {detail}"
                );
                assert!(hint.is_none(), "absent-group skip must carry no hint");
            }
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    /// Operator is in _sandboxd → Pass with `user ∈ _sandboxd` form.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_group_check_passes_when_member() {
        let row = check_group_membership_macos_with(|| {
            Ok(MacGroupMembership::Member {
                user: "alice".to_string(),
            })
        });
        assert_eq!(row.id, "C25");
        match row.outcome {
            CheckOutcome::Pass { detail } => {
                assert!(
                    detail.contains("alice"),
                    "pass detail must name the user; got: {detail}"
                );
                assert!(
                    detail.contains("_sandboxd"),
                    "pass detail must name the group; got: {detail}"
                );
            }
            other => panic!("expected Pass, got {other:?}"),
        }
    }

    /// _sandboxd group exists but operator not in it → Fail with dseditgroup hint.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_group_check_fails_when_not_member_with_dseditgroup_hint() {
        let row = check_group_membership_macos_with(|| {
            Ok(MacGroupMembership::NotMember {
                user: "alice".to_string(),
            })
        });
        assert_eq!(row.id, "C25");
        match row.outcome {
            CheckOutcome::Fail { detail, hint } => {
                assert!(
                    detail.contains("alice"),
                    "fail detail must name the user; got: {detail}"
                );
                let h = hint.expect("not-member must carry a hint");
                assert!(
                    h.contains("dseditgroup"),
                    "fail hint must instruct dseditgroup; got: {h}"
                );
                assert!(
                    h.contains("_sandboxd"),
                    "fail hint must name the group; got: {h}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// Resolver error → Fail (lookup failure surfaced, not silently swallowed).
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_group_check_fails_on_lookup_error() {
        let row =
            check_group_membership_macos_with(|| Err("getpwuid_r: no such process".to_string()));
        assert_eq!(row.id, "C25");
        match row.outcome {
            CheckOutcome::Fail { detail, .. } => {
                assert!(
                    detail.contains("group lookup failed"),
                    "error must surface as lookup-failed detail; got: {detail}"
                );
            }
            other => panic!("expected Fail on lookup error, got {other:?}"),
        }
    }
}
