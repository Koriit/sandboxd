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
//! productionization spec § 6.2. The output format is pinned in
//! § 6.3 — three exact-text examples — and is load-bearing for the
//! integration tests in § 11.6. Message tokens, glyphs, indentation,
//! and the summary-line wording are byte-for-byte stable.
//!
//! # Execution shape
//!
//! Two phases per spec § 13.6:
//!
//! 1. Serial — C1 (daemon running) and C2 (socket reachable). If
//!    either fails, every downstream check that requires a running
//!    daemon is short-circuited to `SKIPPED (requires daemon)`. C4
//!    (group membership), C9 (route-helper caps), and C10 (state-dir
//!    mode) can still run because they only consult host state.
//! 2. Parallel — C3-C13 fan out via `tokio::task::spawn` and join
//!    before the formatter walks the result table.
//!
//! # Exit codes (§ 6.4)
//!
//! - `0` — every check is `Pass` or `Skip` (skips never fail the run).
//! - `1` — at least one check is `Fail`.
//! - `2` — `doctor` itself could not run (config parse, socket-path
//!   resolution panic, etc.). Distinct from `1` so wrapper scripts
//!   can disambiguate "daemon broken" from "doctor broken".
//!
//! # Dev-mode degradation (§ 12.2)
//!
//! C4 (current user in `sandbox` group), C5 (socket perms), and
//! C10 (state-dir mode) are system-service-specific. On a dev box
//! (`make setup-dev-env`) there is no `sandbox` system user and no
//! systemd `StateDirectory`, so these checks emit informational
//! `Skip` rather than `Fail` — the dev workflow still passes the
//! summary line.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the full doctor pipeline against the daemon reachable at
/// `socket_path` and write the formatted report to stdout. Returns
/// the process exit code per § 6.4.
///
/// `verbose=false` suppresses passing rows so the operator sees only
/// the actionable failures + skips; `verbose=true` echoes every row.
/// In both modes the summary line is always rendered.
pub async fn run(socket_path: &str, verbose: bool) -> i32 {
    let outcomes = execute_checks(socket_path).await;
    let mut out = std::io::stdout().lock();
    let exit_code = render_report(&mut out, &outcomes, verbose);
    let _ = std::io::Write::flush(&mut out);
    exit_code
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

/// Resolve the `(serial, parallel)` phase outputs, in spec § 13.6 order.
///
/// Public-in-crate so the unit tests in `mod tests` can exercise the
/// runner directly. The wrapper [`run`] composes this with the
/// formatter and stdout sink.
pub(crate) async fn execute_checks(socket_path: &str) -> Vec<CheckRow> {
    let mut rows: Vec<CheckRow> = Vec::with_capacity(13);

    // Serial phase: C1, C2.
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

    // Parallel phase. Checks that don't depend on the daemon (C4, C9,
    // C10) still run unconditionally; checks that do (C3, C5, C6, C7,
    // C8, C11, C12, C13) short-circuit to `SKIPPED (requires daemon)`
    // when the serial phase failed.

    // Diagnostics payload fetched once and shared across the
    // daemon-side checks (C6, C7, C8, C11, C12, C13).
    let diagnostics = if socket_reachable {
        fetch_diagnostics(socket_path).await
    } else {
        None
    };

    rows.push(check_version_match(socket_path, socket_reachable).await);
    rows.push(check_group_membership());
    rows.push(check_socket_perms(socket_path, socket_reachable));
    rows.push(check_kvm_accessible(diagnostics.as_ref(), socket_reachable));
    rows.push(check_gateway_image(diagnostics.as_ref(), socket_reachable));
    rows.push(check_lite_image(diagnostics.as_ref(), socket_reachable));
    rows.push(check_route_helper_caps());
    rows.push(check_state_dir_mode());
    rows.push(check_users_conf_pool(
        diagnostics.as_ref(),
        socket_reachable,
    ));
    rows.push(check_guest_version_drift(
        diagnostics.as_ref(),
        socket_reachable,
    ));
    rows.push(check_substrate_orphans(
        diagnostics.as_ref(),
        socket_reachable,
    ));

    rows
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
/// fallback is the spec's § 12.2 dev-mode degradation rule.
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

    // Per spec § 12.2: `inactive`, `failed`, and `not-found` all
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
                    "versions differ \u{2014} reinstall to align \
                     (Spec 5 sandbox update \u{2014} both at once)"
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
/// `Skip` rather than `Fail` per spec § 12.2. Production: the
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
// Individual checks — C5 (socket perms)
// ---------------------------------------------------------------------------

/// C5 — socket permissions.
///
/// Production: `srw-rw---- sandbox:sandbox` (mode `0660`). Dev: the
/// developer owns the socket under `$XDG_RUNTIME_DIR/sandboxd/`; the
/// mode varies and the spec § 12.2 specifies a `Skip (dev mode)` row.
/// We classify dev mode as "no `sandbox` user on the host"; on that
/// signal, we skip the strict-mode comparison.
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

    // Dev-mode signal: no `sandbox` user on the host means no
    // `0660 sandbox:sandbox` to require.
    let sandbox_user_exists = nix::unistd::User::from_name("sandbox")
        .ok()
        .flatten()
        .is_some();
    if !sandbox_user_exists {
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
/// `GET /diagnostics`, evaluated daemon-side per spec § 13.2.
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
        Some(_) => CheckRow {
            id: "C7",
            name: "gateway image present",
            outcome: CheckOutcome::Fail {
                detail: format!("missing {tag}"),
                hint: Some(
                    "sandbox update to load the image (Spec 5); \
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

/// C9 — route-helper has `cap_net_admin,cap_sys_admin=eip`.
///
/// Calls `getcap` on `/usr/local/libexec/sandboxd/sandbox-route-helper`.
/// The daemon refuses to start without this so a passing daemon
/// implies a passing check; we still run it explicitly so a
/// not-yet-up daemon doesn't hide the misconfiguration.
fn check_route_helper_caps() -> CheckRow {
    const HELPER_PATH: &str = "/usr/local/libexec/sandboxd/sandbox-route-helper";
    if !std::path::Path::new(HELPER_PATH).exists() {
        return CheckRow {
            id: "C9",
            name: "route-helper caps",
            outcome: CheckOutcome::Fail {
                detail: format!("missing: {HELPER_PATH}"),
                hint: Some(
                    "sandbox update re-runs setcap (Spec 5); \
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
    // `getcap` output shape: `<path> cap_net_admin,cap_sys_admin=eip`
    // (or `cap_sys_admin+ep` on older libcap; we accept either).
    let has_sys_admin = stdout.contains("cap_sys_admin");
    let has_net_admin = stdout.contains("cap_net_admin");
    let effective = stdout.contains("=eip")
        || stdout.contains("+ep")
        || stdout.contains("=ep")
        || stdout.contains("+eip");
    if has_sys_admin && has_net_admin && effective {
        CheckRow {
            id: "C9",
            name: "route-helper caps",
            outcome: CheckOutcome::Pass {
                detail: "cap_net_admin,cap_sys_admin=eip".to_string(),
            },
        }
    } else if has_sys_admin && effective {
        // Legacy install: cap_sys_admin only, no cap_net_admin yet.
        CheckRow {
            id: "C9",
            name: "route-helper caps",
            outcome: CheckOutcome::Pass {
                detail: "cap_sys_admin=eip".to_string(),
            },
        }
    } else {
        CheckRow {
            id: "C9",
            name: "route-helper caps",
            outcome: CheckOutcome::Fail {
                detail: format!("getcap reported: {}", stdout.trim()),
                hint: Some(
                    "sandbox update re-runs setcap (Spec 5); \
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
/// Production: `/var/lib/sandbox/` is `0750 sandbox:sandbox` (the
/// systemd unit's `StateDirectory` invariant). Dev: the operator's
/// own `~/.local/share/sandboxd/` lives at the developer's umask;
/// we skip the strict-mode comparison with the dev-mode annotation
/// per spec § 12.2.
fn check_state_dir_mode() -> CheckRow {
    const PROD_PATH: &str = "/var/lib/sandbox";
    let path = Path::new(PROD_PATH);
    let sandbox_user_exists = nix::unistd::User::from_name("sandbox")
        .ok()
        .flatten()
        .is_some();
    if !sandbox_user_exists {
        return CheckRow {
            id: "C10",
            name: "state dir mode",
            outcome: CheckOutcome::Skip {
                detail: "dev mode \u{2014} no sandbox user/systemd StateDirectory".to_string(),
                hint: None,
            },
        };
    }
    if !path.exists() {
        return CheckRow {
            id: "C10",
            name: "state dir mode",
            outcome: CheckOutcome::Fail {
                detail: format!("missing: {PROD_PATH}"),
                hint: Some(
                    "sudo install -d -o sandbox -g sandbox -m 0750 /var/lib/sandbox \
                     (the daemon corrects subdir modes on next start)"
                        .to_string(),
                ),
            },
        };
    }
    match std::fs::metadata(path) {
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
                CheckRow {
                    id: "C10",
                    name: "state dir mode",
                    outcome: CheckOutcome::Pass {
                        detail: format!("{PROD_PATH} {mode:04o} {owner}:{group}"),
                    },
                }
            } else {
                CheckRow {
                    id: "C10",
                    name: "state dir mode",
                    outcome: CheckOutcome::Fail {
                        detail: format!("{PROD_PATH} {mode:04o} {owner}:{group} (expected 0750 sandbox:sandbox)"),
                        hint: Some(
                            "sudo chmod 0750 /var/lib/sandbox; sudo chown sandbox:sandbox /var/lib/sandbox \
                             (the daemon corrects subdirs at next start)"
                                .to_string(),
                        ),
                    },
                }
            }
        }
        Err(e) => CheckRow {
            id: "C10",
            name: "state dir mode",
            outcome: CheckOutcome::Fail {
                detail: format!("stat({PROD_PATH}): {e}"),
                hint: Some("ensure /var/lib/sandbox exists and is readable".to_string()),
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
/// conditionally on verbose (the spec example pins the row in the
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

/// Pad `name` to the spec's display column width (40 chars after the
/// glyph + space, give or take Unicode wcwidth). The spec's examples
/// align the detail-or-`SKIPPED` token at roughly column 42. We use
/// 40 char-count padding which lands the detail column at column 42
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
    // failure followed by the summary. The spec § 6.3 partial-fail
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

    // For the default-mode "daemon-down" output (spec § 6.3 third
    // example) the spec lists every skip on its own line. Emit them
    // here to mirror that example when at least one fail triggered
    // the cascade.
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
    /// `--verbose`. Pins the spec § 6.3 happy-path shape.
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

    /// Skipped checks do not flip exit-code-1; spec § 6.4 pins this.
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
    /// spec § 6.3 example. The token is load-bearing for the
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
    /// per spec § 12.2.
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
}
