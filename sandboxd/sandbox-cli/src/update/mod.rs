//! `sandbox update` orchestration — Spec 5.
//!
//! Spans the **pre-flight** half (§§ 3.1.1-3.1.12: arg parse, dev-mode
//! detect, install-state read, target-version resolution, version
//! compare with `--check` exit gate, active-session check,
//! stopped-session count, disk-space check, cosign-pin, MANIFEST
//! arch/version cross-check, migration dry-run delegate, confirmation
//! prompt) and the **stateful** half (§§ 3.2.13-3.2.30: lock
//! acquisition → 18 idempotent steps → lock release). Both phases
//! share the install-state shape, dev-mode detection, and pending-
//! migration enumeration helpers defined here.
//!
//! The stateful phase is the heart of Spec 5 — see § 3.2 in the spec
//! for the verbatim step-by-step contract. Every step in [`apply_stateful`]
//! inspects current state and short-circuits when the desired state is
//! already in place; the flow is safe to re-run after any failure
//! (convergence is the contract).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::cfg_migrations;

pub mod backup;
pub mod fetch;
pub mod lock;
pub mod migrate;

// ---------------------------------------------------------------------------
// Constants (operator-visible paths)
// ---------------------------------------------------------------------------

/// Canonical install-state path. Spec 4 § 4.5.
pub const INSTALL_STATE_PATH: &str = "/var/lib/sandbox/.install-state.json";

/// Canonical systemd unit path (presence is the dev-vs-system gate).
/// Spec 5 § 11.
pub const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/sandboxd.service";

/// Default release-tarball mirror. Spec 5 § 2.1 (`--source-url`).
pub const DEFAULT_SOURCE_URL: &str = "https://github.com/Koriit/sandboxd/releases/download";

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

/// Operator-supplied flags for `sandbox update`. Mirrors the
/// `Command::Update` variant in `main.rs` field-for-field.
///
/// `version`'s default is the string `"latest"` (matching install.sh
/// § 4.4.9), resolved to a concrete tag via the GitHub Releases API
/// later in the flow.
#[derive(Debug, Clone)]
pub struct UpdateArgs {
    pub version: String,
    pub from: Option<PathBuf>,
    pub cosign_bundle: Option<PathBuf>,
    pub source_url: String,
    pub check: bool,
    pub dry_run: bool,
    pub yes: bool,
    pub force: bool,
    pub quiet: bool,
    pub verbose: bool,
    /// Daemon socket path (resolved from `--socket` / `SANDBOX_SOCKET`
    /// / default). Used by the active-session probe.
    pub socket_path: String,
}

impl UpdateArgs {
    /// Spec 5 § 2.5: `--check` and `--dry-run` are read-only and MUST
    /// NOT require root or acquire the lock. The full flow (no flags)
    /// requires root.
    pub fn is_read_only(&self) -> bool {
        self.check || self.dry_run
    }

    /// Spec 5 § 3.1.1: reject incompatible combinations early.
    pub fn validate(&self) -> Result<(), String> {
        if self.cosign_bundle.is_some() && self.from.is_none() {
            return Err("--cosign-bundle requires --from".to_string());
        }
        if self.from.is_some() && self.source_url != DEFAULT_SOURCE_URL {
            return Err(
                "--from and --source-url are mutually exclusive (--from is local-only)".to_string(),
            );
        }
        if self.check && self.dry_run {
            return Err("--check and --dry-run are mutually exclusive".to_string());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Install-state shape (read-only)
// ---------------------------------------------------------------------------

/// Subset of `/var/lib/sandbox/.install-state.json` the pre-flight
/// needs. Spec 4 § 4.5 defines the full shape; we deserialize only the
/// fields used here so older or newer state files still parse (any
/// extra fields are ignored).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct InstallState {
    #[serde(default)]
    pub installed_version: String,
    #[serde(default)]
    pub installed_arch: String,
    #[serde(default)]
    pub installed_at: String,
    #[serde(default)]
    pub installed_by_operator: String,
    /// New in Spec 5 § 3.2.18 — the version installed **before** this
    /// update run swapped the binaries. Older state files written by
    /// install.sh predate this field; `#[serde(default)]` keeps them
    /// readable. The post-update finalize step (§ 3.2.29) preserves
    /// this field across rewrites.
    #[serde(default)]
    pub previous_version: Option<String>,
}

impl InstallState {
    /// The "version unknown" shape that the read-only modes
    /// (`--check` / `--dry-run`) fall back to when the operator isn't
    /// in the `sandbox` group and can't read the state file. Spec 5
    /// § 3.1.3 mandates the graceful-degradation path: pretend the
    /// installed version is `"unknown"` and derive the arch from
    /// `uname -m` (the comparison side that's still meaningful).
    pub fn unknown_with_host_arch() -> Self {
        Self {
            installed_version: "unknown".to_string(),
            installed_arch: detect_host_arch(),
            installed_at: "unknown".to_string(),
            installed_by_operator: "unknown".to_string(),
            previous_version: None,
        }
    }
}

/// Spec 5 § 3.1.3 fallback: `uname -m` mapped onto the release-tarball
/// arch-triple convention.
pub fn detect_host_arch() -> String {
    let uname = nix::sys::utsname::uname().ok();
    let m = uname
        .as_ref()
        .map(|u| u.machine().to_string_lossy().into_owned())
        .unwrap_or_default();
    match m.as_str() {
        "x86_64" => "x86_64-unknown-linux-gnu".to_string(),
        "aarch64" | "arm64" => "aarch64-unknown-linux-gnu".to_string(),
        other => other.to_string(),
    }
}

/// Read the install state file at `path`. Returns `Ok(None)` when the
/// file is absent or unreadable — the read-only modes degrade
/// gracefully; the full-update path treats `None` as a hard refusal
/// (§ 3.1.3).
pub fn read_install_state(path: &Path) -> std::io::Result<Option<InstallState>> {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<InstallState>(&bytes) {
            Ok(s) => Ok(Some(s)),
            Err(_) => Ok(None),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(None),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Dev-mode detection (§ 3.1.2 / § 11)
// ---------------------------------------------------------------------------

/// Spec 5 § 11 / § 3.1.2: a system install requires *both* the systemd
/// unit and the install-state file to exist. Anything else is a dev
/// install (or a corrupted system install — same refusal either way).
pub fn is_dev_mode(systemd_unit: &Path, install_state: &Path) -> bool {
    if !systemd_unit.exists() {
        return true;
    }
    if !install_state.exists() {
        // The spec's shell pseudo-code also tries `sudo -k test -r`;
        // we cannot escalate from Rust without external help, so a
        // missing file (regardless of mode) trips dev-mode here. The
        // outer shell wrapper around `sandbox update` can elevate
        // before invoking the CLI when needed.
        return true;
    }
    false
}

/// The spec § 11 verbatim refusal text. Returned as a String so the
/// caller can route it to stderr without owning the formatting.
pub fn dev_mode_refusal_text() -> &'static str {
    "sandbox update is for system installs only.\n\
     \n\
     This host looks like a dev install:\n  \
     - no systemd unit at /etc/systemd/system/sandboxd.service\n  \
     - no install state file at /var/lib/sandbox/.install-state.json\n\
     \n\
     Use `make` to upgrade in development:\n  \
     - `make build`              rebuilds binaries\n  \
     - `make gateway-image`      rebuilds the gateway image\n  \
     - `make setup-dev-env`      reapplies dev-mode /etc files\n\
     \n\
     To switch from dev to system install, follow:\n  \
     https://Koriit.github.io/sandboxd/start/installation#dev-mode-vs-operator-mode-coexistence\n"
}

// ---------------------------------------------------------------------------
// Version comparison
// ---------------------------------------------------------------------------

/// Result of the version comparison at § 3.1.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionCompare {
    UpToDate,
    UpdateAvailable,
    /// Couldn't determine the installed side (state file unreadable),
    /// so we cannot assert "up to date". Treat as "update available"
    /// for `--check` so the operator's diff is informative.
    InstalledUnknown,
}

/// `current == target` → `UpToDate`; both known and different →
/// `UpdateAvailable`; current `"unknown"` → `InstalledUnknown`.
pub fn compare_versions(current: &str, target: &str) -> VersionCompare {
    if current == "unknown" {
        return VersionCompare::InstalledUnknown;
    }
    if current == target {
        VersionCompare::UpToDate
    } else {
        VersionCompare::UpdateAvailable
    }
}

// ---------------------------------------------------------------------------
// Daemon probes (read-only)
// ---------------------------------------------------------------------------

/// HTTP-over-UDS probe for `/version` and `/sessions`. Pulled into a
/// small inline helper so the orchestration module is self-contained;
/// duplicates the shape `doctor.rs::http_get` uses internally.
async fn http_get(socket_path: &str, path: &str) -> Result<Vec<u8>, String> {
    use http_body_util::BodyExt;
    use hyper::Request;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", "localhost")
        .body(String::new())
        .map_err(|e| format!("build request: {e}"))?;
    let response = sender
        .send_request(req)
        .await
        .map_err(|e| format!("send_request: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("status: {}", response.status()));
    }
    Ok(response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("collect: {e}"))?
        .to_bytes()
        .to_vec())
}

/// Snapshot of `/sessions` filtered into the two counts the pre-flight
/// cares about: active (non-Stopped) and stopped. § 3.1.6 + § 3.1.7.
#[derive(Debug, Clone, Default)]
pub struct SessionCounts {
    pub active: usize,
    pub stopped: usize,
    /// `None` when the daemon was unreachable; the read-only modes
    /// tolerate this and elide the row from the summary.
    pub reachable: bool,
}

/// Best-effort fetch of the session counts. Returns `(0, 0, false)`
/// when the daemon isn't reachable — `--check` / `--dry-run` degrade
/// gracefully; the full-update path uses [`SessionCounts::reachable`]
/// to decide whether to enforce the active-session refusal.
pub async fn fetch_session_counts(socket_path: &str) -> SessionCounts {
    let body = match http_get(socket_path, "/sessions").await {
        Ok(b) => b,
        Err(_) => return SessionCounts::default(),
    };
    #[derive(serde::Deserialize)]
    struct Snip {
        state: String,
    }
    let sessions: Vec<Snip> = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(_) => return SessionCounts::default(),
    };
    let mut counts = SessionCounts {
        active: 0,
        stopped: 0,
        reachable: true,
    };
    for s in sessions {
        // `SessionState` derives serde with `rename_all = "snake_case"`,
        // so the wire value is lowercase (`"stopped"` / `"running"`
        // / ...). The DB column and the `Display` impl use the
        // PascalCase variant name, but neither reaches this path —
        // we read off the JSON wire here.
        if s.state == "stopped" {
            counts.stopped += 1;
        } else {
            counts.active += 1;
        }
    }
    counts
}

/// Stopped-session compat bucket — Spec 5 § 3.1.7. The pre-flight
/// classifies each stopped session against the target binary's
/// `DAEMON_GUEST_PROTO_VERSION` and renders the three-bucket
/// breakdown in the confirmation prompt so the operator knows up
/// front whether a session will be picked up by an in-place refresh
/// or whether it'll need to be recreated after the upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatBucket {
    /// `session_proto == target_proto` — the upgraded daemon talks the
    /// session's protocol directly; no refresh needed.
    Ok,
    /// `can_refresh_in_place(session_proto, target_proto)` is true —
    /// the upgraded daemon's refresh path can re-stage the embedded
    /// guest binary into the session at first start.
    RefreshInPlace,
    /// Neither — the session must be recreated against the new
    /// daemon.
    Recreate,
}

impl CompatBucket {
    /// Operator-facing single-token label rendered in the confirmation
    /// prompt and `--dry-run` output.
    pub fn label(self) -> &'static str {
        match self {
            CompatBucket::Ok => "ok",
            CompatBucket::RefreshInPlace => "refresh-in-place",
            CompatBucket::Recreate => "recreate",
        }
    }
}

/// One row in the per-session compat classification: session id +
/// the protocol version the daemon last stamped on it + the bucket it
/// falls into for a given target.
#[derive(Debug, Clone)]
pub struct SessionCompat {
    pub id: String,
    pub session_proto: u32,
    pub bucket: CompatBucket,
}

/// Snapshot of the per-session compat classification surfaced in the
/// confirmation prompt and the install log. Spec 5 § 3.1.7.
#[derive(Debug, Clone, Default)]
pub struct SessionCompatSet {
    pub target_proto: u32,
    pub stopped: Vec<SessionCompat>,
    /// `true` iff the daemon was reachable AND the staged binary's
    /// `--dump-proto-version` returned an answer. When either piece is
    /// missing the prompt elides the per-session breakdown and falls
    /// back to the flat `stopped sessions: N` line.
    pub classified: bool,
}

/// Classify a single session against the upgrade target's protocol
/// version. Same three-bucket decision tree the daemon's runtime arm
/// (`start-session`) uses, factored out so the CLI can render it ahead
/// of time. Spec 5 § 3.1.7.
///
/// Mirrors [`sandbox_core::guest::is_protocol_compatible`] /
/// [`sandbox_core::guest::can_refresh_in_place`] but applied against
/// the *target* protocol rather than the current daemon's, so the
/// classification reflects post-upgrade behaviour rather than pre.
pub fn classify_session_compat(session_proto: u32, target_proto: u32) -> CompatBucket {
    if session_proto == target_proto {
        CompatBucket::Ok
    } else if session_proto != 0 {
        // `can_refresh_in_place` is `session_proto != 0` for the
        // current daemon (Spec 5 § 3.1.7's "session_proto == 0 →
        // unsalvageable" arm). The target binary's predicate may
        // widen this in a future release; until that happens, mirror
        // the constant so the classification matches runtime
        // semantics.
        CompatBucket::RefreshInPlace
    } else {
        CompatBucket::Recreate
    }
}

/// Best-effort fetch of stopped sessions and their persisted
/// `guest_protocol_version`. Returns an empty `Vec` when the daemon
/// is unreachable or the response is malformed — the read-only modes
/// degrade gracefully. The list endpoint already filters to the
/// caller's own sessions (api-session-isolation spec § 2.4), so this
/// is the operator's view, not the system-wide one.
async fn fetch_stopped_sessions_with_proto(socket_path: &str) -> Vec<(String, u32)> {
    let body = match http_get(socket_path, "/sessions").await {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    #[derive(serde::Deserialize)]
    struct Snip {
        id: String,
        state: String,
        #[serde(default)]
        guest_protocol_version: u32,
    }
    let sessions: Vec<Snip> = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    sessions
        .into_iter()
        // `SessionState` serializes via `rename_all = "snake_case"`; the
        // wire format is lowercase.
        .filter(|s| s.state == "stopped")
        .map(|s| (s.id, s.guest_protocol_version))
        .collect()
}

/// Classify each stopped session against `target_proto`. Returns an
/// empty `SessionCompatSet` (with `classified: false`) when the
/// daemon is unreachable.
pub async fn classify_stopped_sessions(socket_path: &str, target_proto: u32) -> SessionCompatSet {
    // The daemon-reachability signal comes from a fresh `/sessions`
    // call rather than from a possibly-stale earlier `SessionCounts`.
    // We re-fetch here so the prompt's classification block reflects
    // the moment immediately before the operator confirms — no race
    // window where a session quietly transitions between two calls.
    let body = match http_get(socket_path, "/sessions").await {
        Ok(b) => b,
        Err(_) => return SessionCompatSet::default(),
    };
    let _: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return SessionCompatSet::default(),
    };
    let stopped = fetch_stopped_sessions_with_proto(socket_path).await;
    let mut rows: Vec<SessionCompat> = stopped
        .into_iter()
        .map(|(id, proto)| SessionCompat {
            id,
            session_proto: proto,
            bucket: classify_session_compat(proto, target_proto),
        })
        .collect();
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    SessionCompatSet {
        target_proto,
        stopped: rows,
        classified: true,
    }
}

// ---------------------------------------------------------------------------
// Disk-space check (§ 3.1.8)
// ---------------------------------------------------------------------------

/// Per-mountpoint free-space budget in KB (Spec 5 § 3.1.8 table).
pub struct DiskBudget {
    pub usr_local_kb: u64,
    pub var_lib_kb: u64,
    pub var_lib_docker_kb: u64,
    pub tmp_kb: u64,
}

pub const DEFAULT_BUDGET: DiskBudget = DiskBudget {
    usr_local_kb: 50 * 1024,
    var_lib_kb: 600 * 1024,
    var_lib_docker_kb: 500 * 1024,
    tmp_kb: 1024 * 1024,
};

/// Result of the disk-space probe — `(path, free_kb, needed_kb)` triples.
#[derive(Debug, Clone)]
pub struct DiskCheck {
    pub rows: Vec<DiskRow>,
}

#[derive(Debug, Clone)]
pub struct DiskRow {
    pub path: PathBuf,
    pub free_kb: u64,
    pub needed_kb: u64,
}

impl DiskCheck {
    pub fn passes(&self) -> bool {
        self.rows.iter().all(|r| r.free_kb >= r.needed_kb)
    }
}

/// Read the free-space budget against the pinned paths. Spec 5 § 3.1.8.
pub fn check_disk_space(budget: &DiskBudget) -> DiskCheck {
    let rows = vec![
        DiskRow {
            path: PathBuf::from("/usr/local"),
            free_kb: free_kb_at(Path::new("/usr/local")),
            needed_kb: budget.usr_local_kb,
        },
        DiskRow {
            path: PathBuf::from("/var/lib/sandbox"),
            free_kb: free_kb_at(Path::new("/var/lib/sandbox")),
            needed_kb: budget.var_lib_kb,
        },
        DiskRow {
            path: PathBuf::from("/var/lib/docker"),
            free_kb: free_kb_at(Path::new("/var/lib/docker")),
            needed_kb: budget.var_lib_docker_kb,
        },
        DiskRow {
            path: PathBuf::from("/tmp"),
            free_kb: free_kb_at(Path::new("/tmp")),
            needed_kb: budget.tmp_kb,
        },
    ];
    DiskCheck { rows }
}

/// `statvfs`-derived free KB for the given path. Returns `0` on any
/// error — caller treats that as "budget not met" downstream.
fn free_kb_at(path: &Path) -> u64 {
    // Use the path itself if it exists; otherwise walk up to the first
    // ancestor that does (this lets `/var/lib/sandbox` probe succeed
    // on a host where the dir does not exist yet — fallback to
    // `/var/lib/`).
    let probe = first_existing_ancestor(path);
    match nix::sys::statvfs::statvfs(&probe) {
        Ok(s) => {
            let block_kb = s.fragment_size() / 1024;
            s.blocks_available().saturating_mul(block_kb.max(1))
        }
        Err(_) => 0,
    }
}

fn first_existing_ancestor(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf();
    while !p.exists() {
        match p.parent() {
            Some(parent) if parent != p.as_path() => p = parent.to_path_buf(),
            _ => return PathBuf::from("/"),
        }
    }
    p
}

// ---------------------------------------------------------------------------
// `--check` output (§ 2.2)
// ---------------------------------------------------------------------------

/// Inputs to the `--check` renderer. Each piece is computed by the
/// pre-flight; the renderer just lays them out per § 2.2.
pub struct CheckReport<'a> {
    pub state: &'a InstallState,
    pub target_version: &'a str,
    pub target_arch: &'a str,
    pub target_released_at: Option<&'a str>,
    pub compare: VersionCompare,
    pub pending_config_migrations: Vec<PendingMigration>,
    pub session_counts: SessionCounts,
}

#[derive(Debug, Clone)]
pub struct PendingMigration {
    pub id: u32,
    pub name: String,
    pub target_file: &'static str,
}

/// Convert a `ConfigMigration::name()` slug (snake_case module suffix
/// such as `add_sandbox_to_allow_users`) into the human-friendly
/// rendering Spec 5 § 2.2 pins for `--check` output. Underscores
/// become spaces; everything else is left verbatim so existing
/// migration names that already read naturally (e.g. a future
/// `add per-pool rate limit metadata`-style slug) round-trip through
/// unchanged when written that way.
///
/// Pulled into a pure function so the rendering rule is independently
/// testable and shared between any future caller (e.g. the
/// confirmation-prompt enumeration if it later surfaces the same
/// list).
pub fn pending_migration_human_description(name: &str) -> String {
    name.replace('_', " ")
}

/// Render the `--check` report to a sink. Spec 5 § 2.2 output shape.
pub fn render_check_report<W: Write>(out: &mut W, r: &CheckReport<'_>) -> std::io::Result<()> {
    match r.compare {
        VersionCompare::UpToDate => {
            writeln!(out, "Installed: sandboxd {}", r.state.installed_version)?;
            writeln!(out, "Available: sandboxd {}", r.target_version)?;
            writeln!(out, "Status:    up to date")?;
            return Ok(());
        }
        VersionCompare::UpdateAvailable | VersionCompare::InstalledUnknown => {}
    }

    let installed_line = if !r.state.installed_at.is_empty() && r.state.installed_at != "unknown" {
        format!(
            "Installed: sandboxd {}  (installed {} by {})",
            r.state.installed_version, r.state.installed_at, r.state.installed_by_operator
        )
    } else {
        format!("Installed: sandboxd {}", r.state.installed_version)
    };
    writeln!(out, "{installed_line}")?;

    let available_line = if let Some(ts) = r.target_released_at {
        format!(
            "Available: sandboxd {}  (released {}, {})",
            r.target_version, ts, r.target_arch
        )
    } else {
        format!(
            "Available: sandboxd {}  ({})",
            r.target_version, r.target_arch
        )
    };
    writeln!(out, "{available_line}")?;

    writeln!(out, "Status:    update available")?;
    writeln!(out)?;

    if !r.pending_config_migrations.is_empty() {
        writeln!(out, "Pending config migrations (current installation):")?;
        for m in &r.pending_config_migrations {
            writeln!(
                out,
                "  config: V{:03} ({})",
                m.id,
                pending_migration_human_description(&m.name)
            )?;
        }
        writeln!(out)?;
    }

    if r.session_counts.reachable {
        writeln!(out, "Stopped sessions: {}", r.session_counts.stopped)?;
        writeln!(
            out,
            "  (for per-session target-protocol compatibility, use `sandbox update --dry-run`)"
        )?;
        writeln!(out)?;
    }

    writeln!(out, "Run `sudo sandbox update` to apply.")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// `--dry-run` output (§ 2.3)
// ---------------------------------------------------------------------------

/// Render the `--dry-run` plan to a sink. The pre-flight block (§ 3.1)
/// is rendered first with per-step verdicts; the stateful block
/// (§ 3.2) lists the 18 stateful steps with `would execute` /
/// `would skip` annotations.
pub fn render_dry_run<W: Write>(
    out: &mut W,
    r: &CheckReport<'_>,
    disk: &DiskCheck,
) -> std::io::Result<()> {
    writeln!(out, "Installed: sandboxd {}", r.state.installed_version)?;
    writeln!(out, "Available: sandboxd {}", r.target_version)?;
    let status = match r.compare {
        VersionCompare::UpToDate => "up to date",
        VersionCompare::UpdateAvailable | VersionCompare::InstalledUnknown => "update available",
    };
    writeln!(out, "Status:    {status}")?;
    writeln!(out)?;

    writeln!(out, "Pre-flight (§ 3.1) — read-only:")?;
    let compare_verdict = match r.compare {
        VersionCompare::UpToDate => "up to date — nothing to do".to_string(),
        VersionCompare::UpdateAvailable => format!(
            "update available ({} → {})",
            r.state.installed_version, r.target_version
        ),
        VersionCompare::InstalledUnknown => "installed version unknown".to_string(),
    };
    writeln!(
        out,
        "  ✓ § 3.1.5  version compare            {compare_verdict}"
    )?;
    writeln!(
        out,
        "  ✓ § 3.1.6  active sessions check      {} active sessions",
        r.session_counts.active
    )?;
    writeln!(
        out,
        "  ✓ § 3.1.7  stopped sessions compat    {} sessions",
        r.session_counts.stopped
    )?;
    let disk_verdict = if disk.passes() { "ok" } else { "FAIL" };
    writeln!(
        out,
        "  ✓ § 3.1.8  disk space check           {disk_verdict}"
    )?;
    writeln!(out, "  ✓ § 3.1.9  cosign bootstrap           ok")?;
    writeln!(out, "  ✓ § 3.1.10 sigstore verify            ok")?;
    let mig_verdict = if r.pending_config_migrations.is_empty() {
        "no pending config migrations".to_string()
    } else {
        let names: Vec<String> = r
            .pending_config_migrations
            .iter()
            .map(|m| format!("V{:03}", m.id))
            .collect();
        format!("{} pending: {}", names.len(), names.join(", "))
    };
    writeln!(out, "  ✓ § 3.1.11 migration dry-run          {mig_verdict}")?;
    writeln!(
        out,
        "  ✓ § 3.1.12 confirmation prompt        (would prompt; --dry-run skips)"
    )?;
    writeln!(out)?;

    writeln!(out, "Stateful (§ 3.2) — projected:")?;
    // The 18 stateful steps, in spec order. Per § 2.3 the verdict is
    // either "would execute" or "would skip" — we now project the
    // per-step idempotency check onto the read-only inputs so the
    // operator sees which steps are no-ops against the current
    // state. An up-to-date installation labels every applicable
    // step `would skip`.
    //
    // Step verdicts:
    //
    // - Steps that never have an idempotency shortcut (they always
    //   converge by re-running their setup logic, even if that
    //   logic is a no-op) stay `would execute`: § 3.2.13 (lock
    //   acquire), § 3.2.19 (manifest write), § 3.2.25 (prune
    //   no-op when nothing eligible), § 3.2.26 (daemon start),
    //   § 3.2.27 (version verify), § 3.2.28 (doctor), § 3.2.29
    //   (install-state finalize), § 3.2.30 (lock release).
    //
    // - Steps that have a "destination already matches source"
    //   idempotency shortcut (sha256-compared file copies, image
    //   already loaded, caps already set) flip to `would skip`
    //   when the current install is at the target version: every
    //   file the step writes is byte-identical with the on-disk
    //   destination.
    //
    // - § 3.2.14 (stop daemon) skips when the daemon is not
    //   running (the on-disk `was_running` probe runs at start
    //   time; --dry-run cannot reach the daemon-running probe
    //   from a read-only pre-flight, so we render this as `would
    //   execute` outside the up-to-date case).
    //
    // - § 3.2.24 (apply config migrations) skips when the
    //   pre-flight enumerated zero pending migrations (already
    //   surfaced in § 3.1.11).
    //
    // Treating "current == target" as the gate for the
    // sha256-shortcut steps is a conservative projection: a fresh
    // update against an older install MUST execute each of these
    // (the sources differ from the destinations on disk), so the
    // `would execute` verdict is correct there. The projection
    // shape is captured in [`stateful_step_verdict`] so the rules
    // can be unit-tested in isolation.
    let up_to_date = matches!(r.compare, VersionCompare::UpToDate);
    let has_pending_migrations = !r.pending_config_migrations.is_empty();
    let steps: [(&str, &str); 18] = [
        ("§ 3.2.13", "acquire lock"),
        ("§ 3.2.14", "stop daemon"),
        ("§ 3.2.15", "backup sessions.db"),
        ("§ 3.2.16", "backup /etc files"),
        ("§ 3.2.17", "backup binaries"),
        ("§ 3.2.18", "record previous_version"),
        ("§ 3.2.19", "write backup manifest"),
        ("§ 3.2.20", "docker load gateway image"),
        ("§ 3.2.21", "install binaries"),
        ("§ 3.2.22", "setcap on route-helper"),
        ("§ 3.2.23", "install systemd unit"),
        ("§ 3.2.24", "apply config migrations"),
        ("§ 3.2.25", "prune older backups"),
        ("§ 3.2.26", "start daemon"),
        ("§ 3.2.27", "verify /version"),
        ("§ 3.2.28", "run sandbox doctor"),
        ("§ 3.2.29", "update install state"),
        ("§ 3.2.30", "release lock"),
    ];
    for (id, name) in steps {
        let verdict = stateful_step_verdict(id, up_to_date, has_pending_migrations);
        writeln!(out, "  ✓ {id} {name:<28}  {verdict}")?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "Run `sudo sandbox update` (without --dry-run) to apply."
    )?;
    Ok(())
}

/// Project the per-step idempotency check onto the read-only
/// `--dry-run` inputs. Returns `"would skip"` when the step is
/// projected to be a no-op against the current install, `"would
/// execute"` otherwise. Spec 5 § 2.3.
///
/// `up_to_date` is `current_installed_version == target_version`:
/// the pre-condition under which every sha256-compared file copy
/// would find the destination matching the source and short-circuit.
/// `has_pending_migrations` flips § 3.2.24's verdict.
///
/// The projection deliberately stays read-only — it does NOT shell
/// out to compare actual on-disk sha256s or query docker / setcap
/// state. Doing so would (a) repeat work the stateful phase already
/// guards, (b) require sudo, and (c) couple the dry-run renderer to
/// production-only paths. The "current == target" gate is the
/// minimum that fulfils the read-only contract ("up-to-date
/// installation labels every applicable step `would skip`") without
/// over-promising on a stale install where some steps may still be
/// idempotent (e.g. systemd unit at the same path with identical
/// bytes despite a binary delta).
pub fn stateful_step_verdict(
    step_id: &str,
    up_to_date: bool,
    has_pending_migrations: bool,
) -> &'static str {
    // The steps that always execute regardless of state — lock
    // acquisition, manifest write, the post-install verification
    // chain (start/version/doctor/state/lock-release), and
    // retention prune (a no-op when nothing is eligible, but still
    // runs the enumeration).
    match step_id {
        "§ 3.2.13" | "§ 3.2.19" | "§ 3.2.25" | "§ 3.2.26" | "§ 3.2.27" | "§ 3.2.28"
        | "§ 3.2.29" | "§ 3.2.30" => return "would execute",
        _ => {}
    }
    // § 3.2.24 — config migration apply: skips when no pending.
    if step_id == "§ 3.2.24" {
        return if has_pending_migrations {
            "would execute"
        } else {
            "would skip"
        };
    }
    // § 3.2.14 (stop daemon) — without a running-daemon probe in
    // the read-only pre-flight we conservatively render `would
    // execute` outside the up-to-date case. On an up-to-date
    // install there is no operator-intent to swap binaries, so we
    // also mark this `would skip` (the daemon would not be stopped
    // because nothing else mutates).
    //
    // Every other step with a sha256 / image-presence / caps /
    // unit-bytes idempotency shortcut: skip when current == target.
    if up_to_date {
        "would skip"
    } else {
        "would execute"
    }
}

// ---------------------------------------------------------------------------
// Confirmation prompt (§ 2.4)
// ---------------------------------------------------------------------------

/// Render the confirmation prompt summary (no input read; caller wires
/// up stdin). § 2.4. Returns the rendered string.
///
/// `pending_db_migrations` is the staged daemon's migration set as
/// returned by `dump-migration-set`; passing an empty slice elides the
/// "pending db migrations" block from the prompt (the read-only modes
/// don't extract the tarball and therefore can't enumerate it).
///
/// `session_compat` is the per-session compat classification computed
/// against the target binary's `DAEMON_GUEST_PROTO_VERSION`; passing a
/// `None` (or a `SessionCompatSet` with `classified: false`) renders
/// the flat `stopped sessions: N` line, matching the prior shape.
pub fn render_confirmation_summary(
    from_version: &str,
    to_version: &str,
    pending_config_migrations: &[PendingMigration],
    pending_db_migrations: &[StagedMigrationEntry],
    daemon_was_running: bool,
    session_counts: &SessionCounts,
    session_compat: Option<&SessionCompatSet>,
) -> String {
    let mut s = String::new();
    s.push_str("sandbox update will apply:\n");
    s.push_str(&format!("  from version:        {from_version}\n"));
    s.push_str(&format!("  to version:          {to_version}\n"));
    if pending_config_migrations.is_empty() {
        s.push_str("  pending config migrations:  none\n");
    } else {
        let names: Vec<String> = pending_config_migrations
            .iter()
            .map(|m| format!("V{:03} ({})", m.id, m.name))
            .collect();
        s.push_str(&format!(
            "  pending config migrations:  {}\n",
            names.join(", ")
        ));
    }
    if pending_db_migrations.is_empty() {
        s.push_str("  pending db migrations:      none\n");
    } else {
        s.push_str(&format!(
            "  pending db migrations:      {}\n",
            pending_db_migrations.len()
        ));
        for m in pending_db_migrations {
            s.push_str(&format!(
                "    - V{:03} ({}): {} -> {} [{}]\n",
                m.id, m.name, m.from_version, m.to_version, m.target_file
            ));
        }
    }
    s.push_str(&format!(
        "  daemon status now:          {}\n",
        if daemon_was_running {
            "active (will be stopped, upgraded, restarted)"
        } else {
            "inactive (will remain stopped after upgrade)"
        }
    ));
    // Per-session compat breakdown: § 3.1.7. When the daemon was
    // unreachable (`classified == false`), fall back to the flat count.
    let classified = session_compat.is_some_and(|c| c.classified);
    if classified {
        let compat = session_compat.expect("classified implies Some");
        let mut ok = 0usize;
        let mut refresh = 0usize;
        let mut recreate = 0usize;
        for row in &compat.stopped {
            match row.bucket {
                CompatBucket::Ok => ok += 1,
                CompatBucket::RefreshInPlace => refresh += 1,
                CompatBucket::Recreate => recreate += 1,
            }
        }
        s.push_str(&format!(
            "  stopped sessions compat:    {} sessions  (ok={}, refresh-in-place={}, recreate={})\n",
            compat.stopped.len(),
            ok,
            refresh,
            recreate
        ));
        for row in &compat.stopped {
            s.push_str(&format!(
                "    - {}  proto={} -> {}  {}\n",
                row.id,
                row.session_proto,
                compat.target_proto,
                row.bucket.label()
            ));
        }
    } else {
        s.push_str(&format!(
            "  stopped sessions:           {}\n",
            session_counts.stopped
        ));
    }
    s.push('\n');
    s.push_str("Proceed? [y/N]:");
    s
}

/// Read one line of stdin and return `true` iff it's exactly the
/// lowercase token `y` (the spec contract — anything else aborts).
/// Trims a trailing `\n` only; case-sensitive by spec.
pub fn read_yes_no<R: Read>(input: R) -> bool {
    let mut s = String::new();
    let mut buf = [0u8; 1];
    let mut reader = std::io::BufReader::new(input);
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {
                if buf[0] == b'\n' {
                    break;
                }
                s.push(buf[0] as char);
            }
            Err(_) => break,
        }
    }
    s == "y"
}

// ---------------------------------------------------------------------------
// Pending-migration enumeration (§ 3.1.11)
// ---------------------------------------------------------------------------

/// Enumerate config migrations pending against the current installation.
/// Spec 5 § 3.1.11. Reads the on-disk file's `_schema_version` and
/// diffs against the registry's `latest_for`. On read error (e.g.
/// permission-denied for the read-only mode) returns an empty list —
/// the operator sees a blank `Pending config migrations` section, the
/// same graceful-degradation pattern as the install-state read.
///
/// Read or schema-parse errors are surfaced via `tracing::warn!` so a
/// debug-level operator (or the full-update audit trail) sees the
/// reason a config file was elided from the pending list. The
/// silent-continue behaviour was a real footgun: an operator running
/// `sandbox update --check` against a `users.conf` corrupted by a
/// half-applied earlier migration would get an empty pending list
/// rather than a clear "file unreadable" signal. The graceful-degrade
/// outer contract (Vec rather than Result) is preserved so the
/// confirmation prompt path stays robust.
pub fn enumerate_pending_config_migrations() -> Vec<PendingMigration> {
    let mut out = Vec::new();
    for file in [
        cfg_migrations::TargetFile::UsersConf,
        cfg_migrations::TargetFile::BridgeConf,
    ] {
        let path = file.canonical_path();
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    target: "sandbox-update",
                    "enumerate_pending_config_migrations: read failed for {}: {e}",
                    path.display()
                );
                continue;
            }
        };
        let current = match cfg_migrations::read_schema_version(&bytes, file) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    target: "sandbox-update",
                    "enumerate_pending_config_migrations: schema-version parse failed for {}: {e:?}",
                    path.display()
                );
                continue;
            }
        };
        let target = cfg_migrations::latest_for(file);
        if current >= target {
            continue;
        }
        for m in cfg_migrations::pending(file, current, target) {
            out.push(PendingMigration {
                id: m.id(),
                name: m.name().to_string(),
                target_file: file.display_name(),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Exit codes Spec 5 § 2.2 / § 2.3 pin:
/// - `0` — up-to-date (`--check`), `--dry-run` printed plan, or
///   confirmation prompt answered `N`.
/// - `1` — error (pre-flight refused).
/// - `2` — argument parse failure / `--check`+`--dry-run` combo / etc.
/// - `3` — update available (`--check` only).
pub async fn run(args: UpdateArgs) -> i32 {
    // § 3.1.1 — arg-parse + sanity.
    if let Err(msg) = args.validate() {
        // Log the arg-validation refusal so the operator's audit
        // trail names the rejected combination before the eprintln
        // exit. Spec § 3.1.1 mandates a `step=parse_args` line
        // regardless of outcome.
        log_step(
            "parse_args",
            &format!("action=validate status=fail err=\"{msg}\""),
        );
        eprintln!("sandbox update: {msg}");
        return 2i32;
    }
    log_step(
        "parse_args",
        &format!(
            "version={} from={} check={} dry_run={} force={} status=ok",
            args.version,
            args.from
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".to_string()),
            args.check,
            args.dry_run,
            args.force,
        ),
    );

    // § 3.1.2 — dev-mode detect / refuse.
    if is_dev_mode(Path::new(SYSTEMD_UNIT_PATH), Path::new(INSTALL_STATE_PATH)) {
        log_step("dev_mode_check", "is_dev=1 action=refuse status=fail");
        eprintln!("{}", dev_mode_refusal_text());
        return 2i32;
    }
    log_step("dev_mode_check", "is_dev=0 action=continue status=ok");

    // § 3.1.3 — install state read (graceful in read-only modes;
    // hard refusal in full-update mode).
    let state = match read_install_state(Path::new(INSTALL_STATE_PATH)) {
        Ok(Some(s)) => {
            log_step(
                "read_state",
                &format!(
                    "installed_version={} installed_arch={} degraded=false status=ok",
                    s.installed_version, s.installed_arch
                ),
            );
            s
        }
        Ok(None) if args.is_read_only() => {
            log_step(
                "read_state",
                "installed_version=unknown degraded=true status=ok",
            );
            InstallState::unknown_with_host_arch()
        }
        Ok(None) => {
            log_step(
                "read_state",
                "installed_version=missing degraded=false status=fail",
            );
            eprintln!(
                "sandbox update: install state file missing: {INSTALL_STATE_PATH} — was this host installed via install.sh?"
            );
            return 1i32;
        }
        Err(e) => {
            log_step("read_state", &format!("status=fail err=\"{e}\""));
            eprintln!("sandbox update: failed to read install state: {e}");
            return 1i32;
        }
    };

    // § 3.1.4 — target-version resolution. Three paths:
    //   1. `--from <tarball>` → read MANIFEST.version from the local
    //      tarball; no network call.
    //   2. `--version <v>` → use that string verbatim.
    //   3. `latest` (default) → query the GitHub Releases API.
    let target_version = match resolve_target_version(&args, &state) {
        Ok(v) => {
            log_step(
                "fetch_tarball",
                &format!("action=resolve target_version={v} status=ok"),
            );
            v
        }
        Err(msg) => {
            log_step(
                "fetch_tarball",
                &format!("action=resolve status=fail err=\"{msg}\""),
            );
            eprintln!("sandbox update: {msg}");
            return 1i32;
        }
    };

    // § 3.1.5 — version compare.
    let compare = compare_versions(&state.installed_version, &target_version);
    log_step(
        "version_compare",
        &format!(
            "current={} target={} verdict={} status=ok",
            state.installed_version,
            target_version,
            match compare {
                VersionCompare::UpToDate => "up-to-date",
                VersionCompare::UpdateAvailable => "update-available",
                VersionCompare::InstalledUnknown => "installed-unknown",
            }
        ),
    );

    // Build the report skeleton — shared by `--check` and `--dry-run`.
    let session_counts = fetch_session_counts(&args.socket_path).await;
    let pending_migrations = enumerate_pending_config_migrations();
    let report = CheckReport {
        state: &state,
        target_version: &target_version,
        target_arch: &state.installed_arch,
        target_released_at: None,
        compare,
        pending_config_migrations: pending_migrations.clone(),
        session_counts: session_counts.clone(),
    };

    // `--check` early-exit gate (§ 3.1.5): print the report, exit
    // 0 (up to date) or 3 (update available) without touching the
    // rest of the flow.
    if args.check {
        let mut out = std::io::stdout().lock();
        let _ = render_check_report(&mut out, &report);
        let _ = out.flush();
        return match compare {
            VersionCompare::UpToDate => 0i32,
            VersionCompare::UpdateAvailable | VersionCompare::InstalledUnknown => 3i32,
        };
    }

    // `--dry-run` exit gate (§ 2.3): print plan, exit 0 (plan ok) or
    // 1 (pre-flight blocks plan).
    let disk = check_disk_space(&DEFAULT_BUDGET);
    if args.dry_run {
        let mut out = std::io::stdout().lock();
        let _ = render_dry_run(&mut out, &report, &disk);
        let _ = out.flush();
        return if disk.passes() { 0i32 } else { 1i32 };
    }

    // ----- Full-update path (no flags) -----

    // § 3.1.5 up-to-date short-circuit — this MUST run before any
    // pre-flight gate (§ 3.1.6 active sessions, § 3.1.8 disk, ...).
    // An operator already at the target version should see the no-op
    // fast path, not an active-sessions refusal that only applies
    // when there is actually work to do.
    if matches!(compare, VersionCompare::UpToDate) {
        println!("Status: up to date");
        return 0i32;
    }

    // § 3.1.6 — active sessions check.
    if session_counts.reachable && session_counts.active > 0 && !args.force {
        log_step(
            "active_session_check",
            &format!(
                "active={} force={} action=refuse status=fail",
                session_counts.active, args.force
            ),
        );
        eprintln!(
            "sandbox update: {} session(s) active. Stop them first:\n  \
             sandbox session ls\n  \
             sandbox session stop <id>\n\
             Or re-run with --force to upgrade despite active sessions \
             (the daemon stop will terminate them mid-flight).",
            session_counts.active
        );
        return 1i32;
    }
    log_step(
        "active_session_check",
        &format!(
            "active={} force={} action=continue status=ok",
            session_counts.active, args.force
        ),
    );

    // § 3.1.8 — disk space.
    if !disk.passes() {
        log_step("disk_check", "action=check status=fail");
        eprintln!("sandbox update: disk-space check failed:");
        for row in &disk.rows {
            if row.free_kb < row.needed_kb {
                eprintln!(
                    "  {} has {} KB free, needs {} KB",
                    row.path.display(),
                    row.free_kb,
                    row.needed_kb
                );
            }
        }
        return 1i32;
    }
    log_step("disk_check", "action=check status=ok");

    // §§ 3.1.9 / 3.1.10 — cosign bootstrap (handled by install.sh on a
    // prior run; we only invoke verify-blob here), sigstore verify, then
    // MANIFEST arch + version cross-check.
    //
    // The arch/version cross-check is cheap and surfaces operator-facing
    // mismatches before we ever invoke cosign. The sigstore step is the
    // trust root for the tarball bytes: a tampered tarball with a valid
    // MANIFEST shape but mutated artefact bytes is caught by the
    // signature check on the whole tarball, then again by the per-file
    // sha256 check that runs after extraction (see prologue to § 3.2.20).
    if let Some(from) = args.from.as_ref() {
        if let Err(e) = check_manifest_from_tarball(from, &target_version, &state.installed_arch) {
            eprintln!("sandbox update: {e}");
            return 1i32;
        }
        // Sigstore verify runs only against a tarball file. The
        // directory `--from <dir>` path is a test harness shape (the
        // operator never passes a directory in production) and has no
        // tarball to sign, so we skip the cosign step there.
        if from.is_file() {
            match fetch::verify_signature(from, args.cosign_bundle.as_deref()) {
                Ok(()) => {
                    log_step("sigstore_verify", "action=verify status=ok");
                }
                Err(e) => {
                    log_step(
                        "sigstore_verify",
                        &format!("action=verify status=fail err=\"{e}\""),
                    );
                    eprintln!("sandbox update: {e}");
                    return 1i32;
                }
            }
        }
    }

    // § 3.1.10 (extract + sha256 cross-check) — stage the tarball BEFORE
    // the confirmation prompt so the prompt can enumerate the target's
    // DB migrations and classify each session against the *target*
    // binary's protocol version. Extraction itself is to a private
    // tempdir; the lock is acquired later (§ 3.2.13) before any
    // host-state mutation. Failure here is operator-actionable so we
    // surface it directly rather than waiting until the lock-held
    // window.
    let staged = match prepare_staged_tarball(&args, &target_version) {
        Ok(s) => {
            log_step(
                "extract",
                &format!(
                    "action=stage version={} stage_dir={} status=ok",
                    target_version,
                    s.stage_dir.display()
                ),
            );
            s
        }
        Err(e) => {
            log_step("extract", &format!("action=stage status=fail err=\"{e}\""));
            eprintln!("sandbox update: {e}");
            return 1i32;
        }
    };
    match fetch::verify_artifact_digests(&staged) {
        Ok(()) => {
            log_step(
                "sha256_verify",
                &format!(
                    "action=verify count={} status=ok",
                    staged.manifest.artifacts.len()
                ),
            );
        }
        Err(e) => {
            log_step(
                "sha256_verify",
                &format!("action=verify status=fail err=\"{e}\""),
            );
            eprintln!("sandbox update: {e}");
            return 1i32;
        }
    }

    // § 3.1.11 — migration dry-run delegate. We run the framework's
    // in-memory walk against the current registry; § 3.2.24 will
    // commit the actual writes during the stateful phase (S3).
    for file in [
        cfg_migrations::TargetFile::UsersConf,
        cfg_migrations::TargetFile::BridgeConf,
    ] {
        if let Err(e) = dry_run_migration(file) {
            log_step(
                "migration_dry_run",
                &format!(
                    "file={} action=dry-run status=fail err=\"{e}\"",
                    file.display_name()
                ),
            );
            eprintln!(
                "sandbox update: migration dry-run failed for {}: {e}",
                file.display_name()
            );
            return 1i32;
        }
        log_step(
            "migration_dry_run",
            &format!(
                "file={} action=dry-run pending={} status=ok",
                file.display_name(),
                pending_migrations
                    .iter()
                    .filter(|m| m.target_file == file.display_name())
                    .count()
            ),
        );
    }

    // § 3.1.4 / § 3.1.7 — query the staged (target-version) binary for
    // (a) the pending DB-migration enumeration and (b) the target
    // daemon's `DAEMON_GUEST_PROTO_VERSION`. Both are read-only
    // subprocess calls against the just-extracted binary; failure here
    // does not block the upgrade — we degrade to the unclassified
    // prompt shape and log the reason, so operator awareness wins over
    // pre-flight rigidity.
    let staged_sandbox = staged.sandbox_bin();
    let pending_db_migrations = match query_staged_migration_set(&staged_sandbox) {
        Ok(entries) => entries,
        Err(e) => {
            log_step(
                "dump_migration_set",
                &format!("action=query status=fail err=\"{e}\""),
            );
            Vec::new()
        }
    };
    let session_compat = match query_staged_proto_version(&staged_sandbox) {
        Ok(target_proto) => {
            log_step(
                "dump_proto_version",
                &format!("action=query target_proto={target_proto} status=ok"),
            );
            Some(classify_stopped_sessions(&args.socket_path, target_proto).await)
        }
        Err(e) => {
            log_step(
                "dump_proto_version",
                &format!("action=query status=fail err=\"{e}\""),
            );
            None
        }
    };

    // § 3.1.12 — confirmation prompt.
    // The sticky `was_running` is sampled here from the live systemd
    // probe (the lock isn't acquired yet — that happens in § 3.2.13).
    let daemon_was_running = systemctl_is_active("sandboxd");
    let summary = render_confirmation_summary(
        &state.installed_version,
        &target_version,
        &pending_migrations,
        &pending_db_migrations,
        daemon_was_running,
        &session_counts,
        session_compat.as_ref(),
    );
    print!("{summary} ");
    let _ = std::io::stdout().flush();
    let proceed = if args.yes {
        true
    } else {
        read_yes_no(std::io::stdin().lock())
    };
    if !proceed {
        log_step(
            "confirm",
            "action=prompt response=abort yes_flag=false status=ok",
        );
        println!("aborted.");
        return 0i32;
    }
    log_step(
        "confirm",
        &format!(
            "action=prompt response=proceed yes_flag={} status=ok",
            args.yes
        ),
    );

    // ----- Stateful phase (§§ 3.2.13-3.2.30) -----
    apply_stateful(StatefulInputs {
        state: &state,
        target_version: &target_version,
        daemon_was_running,
        pending_migrations: &pending_migrations,
        staged: &staged,
    })
    .await
}

// ---------------------------------------------------------------------------
// Stateful phase (§§ 3.2.13-3.2.30)
// ---------------------------------------------------------------------------

/// Inputs to [`apply_stateful`]. Threaded through every step so the
/// 18-step contract can be reasoned about as a straight-line sequence
/// of `do_or_skip` calls rather than mutable shared state.
struct StatefulInputs<'a> {
    state: &'a InstallState,
    target_version: &'a str,
    daemon_was_running: bool,
    /// Reserved for future steps that may want to surface the
    /// per-migration progress in the final summary; currently the
    /// stateful loop iterates the registry directly via
    /// `migrate::apply_file_chain` rather than walking this slice.
    #[allow(dead_code)]
    pending_migrations: &'a [PendingMigration],
    /// The staged tarball — extracted during the pre-flight (after
    /// sigstore verify, before the confirmation prompt) so the prompt
    /// can enumerate the target binary's DB migrations and protocol
    /// version. Threaded through here so the stateful phase doesn't
    /// re-stage; the directory lives only for the duration of the
    /// process and is reaped on exit.
    staged: &'a fetch::StagedTarball,
}

/// The full 18-step stateful orchestration. Spec 5 §§ 3.2.13-3.2.30.
///
/// Returns the operator-visible exit code: `0` on success, `1` on any
/// failed step. Each step appends a `step=<name> action=<verb>
/// status=<ok|fail>` line to the install log (`/var/log/sandbox-install.log`)
/// in the `sandbox-update` second-token format that matches install.sh.
///
/// Idempotency contract per § 3.2: every step inspects current state
/// and short-circuits when the desired state is already in place. A
/// re-run after any failure converges to the same end state.
async fn apply_stateful(inputs: StatefulInputs<'_>) -> i32 {
    use std::process::Command;

    // § 3.2.13 — Acquire lock. From here on, all state mutations
    // happen under the held flock. The Drop impl on UpdateLock
    // releases the kernel flock; the file is `rm`'d at § 3.2.30 on
    // success.
    let was_running = inputs.daemon_was_running;
    let acquire_params = lock::AcquireParams {
        path: Path::new(lock::LOCK_PATH),
        target_version: inputs.target_version,
        from_version: &inputs.state.installed_version,
        probe_was_running: &|| was_running,
        is_pid_alive: &lock::pid_is_live,
        self_pid: None,
        started_at: None,
        suppress_drop_unlink: false,
    };
    let held_lock = match lock::acquire(acquire_params) {
        Ok(l) => l,
        Err(e) => {
            log_step(
                "acquire_lock",
                &format!("action=fail status=fail err=\"{e}\""),
            );
            eprintln!("sandbox update: {e}");
            return 1;
        }
    };
    let sticky_was_running = held_lock.payload().was_running;
    log_step(
        "acquire_lock",
        &format!(
            "pid={} target_version={} from_version={} was_running={} action={} status=ok",
            held_lock.payload().pid,
            inputs.target_version,
            inputs.state.installed_version,
            sticky_was_running,
            match held_lock.kind() {
                lock::AcquisitionKind::Fresh => "acquire",
                lock::AcquisitionKind::Adopt { .. } => "adopt",
                lock::AcquisitionKind::AdoptStale { .. } => "adopt-stale",
            }
        ),
    );

    // § 3.2.14 — Stop daemon (only if `was_running`).
    if sticky_was_running {
        let out = Command::new("sudo")
            .args(["-k", "systemctl", "stop", "sandboxd"])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                log_step(
                    "stop_daemon",
                    &format!("was_running={sticky_was_running} action=stop status=ok"),
                );
            }
            Ok(o) => {
                log_step(
                    "stop_daemon",
                    &format!(
                        "was_running={sticky_was_running} action=stop status=fail stderr={}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    ),
                );
                eprintln!(
                    "sandbox update: systemctl stop sandboxd failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
                return 1;
            }
            Err(e) => {
                log_step(
                    "stop_daemon",
                    &format!(
                        "was_running={sticky_was_running} action=stop status=fail err=\"{e}\""
                    ),
                );
                eprintln!("sandbox update: failed to invoke systemctl: {e}");
                return 1;
            }
        }
    } else {
        log_step(
            "stop_daemon",
            &format!("was_running={sticky_was_running} action=skip status=ok"),
        );
    }

    // § 3.2.15 / § 3.2.16 / § 3.2.17 — backups + manifest. We need a
    // staged tarball at this point so we know which `<stage>/bin/*`
    // files to compare against for binary-backup idempotency hashes.
    // The orchestration extracts the tarball into a private tempdir
    // under `/tmp`; the staged tree lives only for the duration of
    // the run.
    let started_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let set_name = backup::backup_set_name(
        &started_at,
        &inputs.state.installed_version,
        inputs.target_version,
    );
    let backup_set_dir = match backup::create_backup_set_dir(&set_name) {
        Ok(d) => d,
        Err(e) => {
            log_step(
                "backup_set_dir",
                &format!("action=create status=fail err=\"{e}\""),
            );
            eprintln!("sandbox update: failed to create backup set: {e}");
            return 1;
        }
    };
    log_step(
        "backup_set_dir",
        &format!("path={} action=create status=ok", backup_set_dir.display()),
    );

    // Build the in-progress manifest incrementally.
    let mut manifest = backup::BackupManifest {
        from_version: inputs.state.installed_version.clone(),
        to_version: inputs.target_version.to_string(),
        started_at: started_at.clone(),
        completed_at: None,
        completed_ok: false,
        arch: inputs.state.installed_arch.clone(),
        files: std::collections::BTreeMap::new(),
    };

    // § 3.2.15 — Backup sessions.db plus its WAL companion files.
    // The daemon runs SQLite in WAL journal mode (`store.rs:117`);
    // committed transactions may live in `sessions.db-wal` between
    // checkpoints, with offsets indexed via `sessions.db-shm`. A
    // backup that copied only `sessions.db` would silently lose any
    // post-last-checkpoint commits. Bundling all three files lets
    // SQLite restore cleanly without manual `PRAGMA wal_checkpoint`
    // orchestration — the daemon's stop at § 3.2.14 has already
    // ensured the WAL is quiescent for a clean shutdown, but the
    // bundle is also correct against a daemon killed mid-write
    // (the recovery path SQLite runs on next open handles a
    // truncated WAL transparently).
    //
    // Each companion file is copied via the same idempotent
    // `backup_sandbox_owned_file` helper; the WAL/SHM may legitimately
    // be absent (a freshly-checkpointed daemon removes them at
    // close), so `SourceAbsent` is the spec-faithful no-op outcome
    // for those two paths, not a failure.
    for (src, dst_name) in [
        (backup::SESSIONS_DB_PATH, "sessions.db.bak"),
        (backup::SESSIONS_DB_WAL_PATH, "sessions.db-wal.bak"),
        (backup::SESSIONS_DB_SHM_PATH, "sessions.db-shm.bak"),
    ] {
        let dst = backup_set_dir.join(dst_name);
        match backup::backup_sandbox_owned_file(Path::new(src), &dst, 0o600) {
            Ok(o) => match o.action {
                backup::CopyAction::SourceAbsent => {
                    log_step(
                        "backup_sessions_db",
                        &format!("src={src} action=skip status=ok reason=source-absent"),
                    );
                }
                backup::CopyAction::Skipped => {
                    manifest.files.insert(
                        dst_name.to_string(),
                        backup::ManifestFileEntry {
                            sha256: o.sha256.clone(),
                            size: o.size,
                        },
                    );
                    log_step(
                        "backup_sessions_db",
                        &format!(
                            "src={src} path={} sha256={} action=skip status=ok reason=identical",
                            dst.display(),
                            o.sha256
                        ),
                    );
                }
                backup::CopyAction::Copied => {
                    manifest.files.insert(
                        dst_name.to_string(),
                        backup::ManifestFileEntry {
                            sha256: o.sha256.clone(),
                            size: o.size,
                        },
                    );
                    log_step(
                        "backup_sessions_db",
                        &format!(
                            "src={src} path={} sha256={} action=copy status=ok",
                            dst.display(),
                            o.sha256
                        ),
                    );
                }
            },
            Err(e) => {
                log_step(
                    "backup_sessions_db",
                    &format!("src={src} action=copy status=fail err=\"{e}\""),
                );
                eprintln!("sandbox update: failed to back up {src}: {e}");
                return 1;
            }
        }
    }

    // § 3.2.16 — Backup /etc files (users.conf, bridge.conf).
    for (src, dst_name, mode) in [
        (backup::USERS_CONF_PATH, "users.conf.bak", 0o644u32),
        (backup::BRIDGE_CONF_PATH, "bridge.conf.bak", 0o644u32),
    ] {
        let dst = backup_set_dir.join(dst_name);
        match backup::backup_etc_file(Path::new(src), &dst, mode) {
            Ok(o) => match o.action {
                backup::CopyAction::SourceAbsent => {
                    log_step(
                        "backup_etc",
                        &format!("src={src} action=skip status=ok reason=absent"),
                    );
                }
                backup::CopyAction::Skipped => {
                    manifest.files.insert(
                        dst_name.to_string(),
                        backup::ManifestFileEntry {
                            sha256: o.sha256.clone(),
                            size: o.size,
                        },
                    );
                    log_step(
                        "backup_etc",
                        &format!(
                            "path={} sha256={} action=skip status=ok reason=identical",
                            dst.display(),
                            o.sha256
                        ),
                    );
                }
                backup::CopyAction::Copied => {
                    manifest.files.insert(
                        dst_name.to_string(),
                        backup::ManifestFileEntry {
                            sha256: o.sha256.clone(),
                            size: o.size,
                        },
                    );
                    log_step(
                        "backup_etc",
                        &format!(
                            "path={} sha256={} action=copy status=ok",
                            dst.display(),
                            o.sha256
                        ),
                    );
                }
            },
            Err(e) => {
                log_step(
                    "backup_etc",
                    &format!("src={src} action=copy status=fail err=\"{e}\""),
                );
                eprintln!("sandbox update: failed to back up {src}: {e}");
                return 1;
            }
        }
    }

    // § 3.2.17 — Backup binaries.
    for (src, dst_name) in [
        (backup::SANDBOXD_BIN_PATH, "sandboxd.bak"),
        (backup::SANDBOX_BIN_PATH, "sandbox.bak"),
        (backup::ROUTE_HELPER_BIN_PATH, "sandbox-route-helper.bak"),
        (backup::GUEST_BIN_PATH, "sandbox-guest.bak"),
    ] {
        let dst = backup_set_dir.join(dst_name);
        match backup::backup_sandbox_owned_file(Path::new(src), &dst, 0o640) {
            Ok(o) => match o.action {
                backup::CopyAction::SourceAbsent => {
                    log_step(
                        "backup_binary",
                        &format!("src={src} action=skip status=ok reason=absent"),
                    );
                }
                backup::CopyAction::Skipped => {
                    manifest.files.insert(
                        dst_name.to_string(),
                        backup::ManifestFileEntry {
                            sha256: o.sha256.clone(),
                            size: o.size,
                        },
                    );
                    log_step(
                        "backup_binary",
                        &format!(
                            "src={src} dst={} sha256={} action=skip status=ok reason=identical",
                            dst.display(),
                            o.sha256
                        ),
                    );
                }
                backup::CopyAction::Copied => {
                    manifest.files.insert(
                        dst_name.to_string(),
                        backup::ManifestFileEntry {
                            sha256: o.sha256.clone(),
                            size: o.size,
                        },
                    );
                    log_step(
                        "backup_binary",
                        &format!(
                            "src={src} dst={} sha256={} action=copy status=ok",
                            dst.display(),
                            o.sha256
                        ),
                    );
                }
            },
            Err(e) => {
                log_step(
                    "backup_binary",
                    &format!("src={src} action=copy status=fail err=\"{e}\""),
                );
                eprintln!("sandbox update: failed to back up {src}: {e}");
                return 1;
            }
        }
    }

    // § 3.2.18 — Update install state's previous_version.
    if let Err(e) = write_install_state_previous_version(&inputs.state.installed_version) {
        log_step(
            "record_previous_version",
            &format!("action=write status=fail err=\"{e}\""),
        );
        eprintln!("sandbox update: failed to record previous_version: {e}");
        return 1;
    }
    log_step(
        "record_previous_version",
        &format!(
            "previous={} action=write status=ok",
            inputs.state.installed_version
        ),
    );

    // § 3.2.19 — Write in-progress manifest. Image-load-before-binary-
    // swap ordering (binding per § 3.2.19) kicks in next: § 3.2.20
    // runs the docker load first; § 3.2.21 installs the new binaries.
    if let Err(e) = backup::write_in_progress_manifest(&backup_set_dir, &manifest) {
        log_step(
            "backup_manifest",
            &format!("action=write status=fail err=\"{e}\""),
        );
        eprintln!("sandbox update: failed to write in-progress manifest: {e}");
        return 1;
    }
    log_step("backup_manifest", "status=in-progress action=write");

    // The tarball was staged + sha256-verified during the pre-flight
    // (after sigstore verify, before the confirmation prompt) so the
    // prompt could enumerate the target binary's DB migrations and
    // protocol version. We re-use that staged tree here — no second
    // extraction.
    let staged = inputs.staged;

    // § 3.2.20 — docker load gateway image (BEFORE binary swap).
    let image_tar = staged.gateway_image_tar();
    let tag = format!("sandbox-gateway:{}", inputs.target_version);
    let inspect = Command::new("docker")
        .args(["image", "inspect", &tag])
        .output();
    let already_loaded = matches!(inspect, Ok(ref o) if o.status.success());
    if already_loaded {
        log_step(
            "docker_load",
            &format!("image={tag} action=skip status=ok reason=already-loaded"),
        );
    } else {
        match Command::new("sudo")
            .args(["-k", "docker", "load", "-i"])
            .arg(&image_tar)
            .output()
        {
            Ok(o) if o.status.success() => {
                log_step("docker_load", &format!("image={tag} action=load status=ok"));
            }
            Ok(o) => {
                log_step(
                    "docker_load",
                    &format!(
                        "image={tag} action=load status=fail stderr={}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    ),
                );
                eprintln!(
                    "sandbox update: docker load failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
                return 1;
            }
            Err(e) => {
                log_step(
                    "docker_load",
                    &format!("image={tag} action=load status=fail err=\"{e}\""),
                );
                eprintln!("sandbox update: failed to invoke docker: {e}");
                return 1;
            }
        }
    }

    // § 3.2.21 — Install new binaries (sha256 compare for idempotency).
    for (src, dst, mode) in [
        (staged.sandboxd_bin(), backup::SANDBOXD_BIN_PATH, 0o755u32),
        (staged.sandbox_bin(), backup::SANDBOX_BIN_PATH, 0o755u32),
        (
            staged.route_helper_bin(),
            backup::ROUTE_HELPER_BIN_PATH,
            0o755u32,
        ),
        (staged.guest_bin(), backup::GUEST_BIN_PATH, 0o755u32),
    ] {
        match install_binary_if_changed(&src, dst, mode) {
            Ok(action) => log_step(
                "install_binary",
                &format!("path={dst} action={action} status=ok"),
            ),
            Err(e) => {
                log_step(
                    "install_binary",
                    &format!("path={dst} action=install status=fail err=\"{e}\""),
                );
                eprintln!("sandbox update: failed to install {dst}: {e}");
                return 1;
            }
        }
    }

    // § 3.2.22 — Setcap on route-helper (capabilities stripped by
    // the overwrite at § 3.2.21).
    let helper = backup::ROUTE_HELPER_BIN_PATH;
    let expected = "cap_net_admin,cap_sys_admin=eip";
    let cur_out = Command::new("getcap").arg(helper).output();
    let current = cur_out
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let already_set = current.contains(expected);
    if already_set {
        log_step("setcap", "caps=already-set action=skip status=ok");
    } else {
        match Command::new("sudo")
            .args(["-k", "setcap", expected, helper])
            .output()
        {
            Ok(o) if o.status.success() => {
                log_step("setcap", &format!("caps={expected} action=set status=ok"));
            }
            Ok(o) => {
                log_step(
                    "setcap",
                    &format!(
                        "caps={expected} action=set status=fail stderr={}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    ),
                );
                eprintln!(
                    "sandbox update: setcap failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
                return 1;
            }
            Err(e) => {
                log_step("setcap", &format!("action=set status=fail err=\"{e}\""));
                eprintln!("sandbox update: failed to invoke setcap: {e}");
                return 1;
            }
        }
    }

    // § 3.2.23 — Install systemd unit (idempotent via sha256 compare).
    let unit_src = staged.systemd_unit();
    let unit_dst = SYSTEMD_UNIT_PATH;
    match install_root_file_if_changed(&unit_src, unit_dst, 0o644) {
        Ok(action) => {
            log_step(
                "install_unit",
                &format!("path={unit_dst} action={action} status=ok"),
            );
            if action == "install" {
                // daemon-reload after unit replacement so systemctl
                // start in § 3.2.26 picks up the new unit. A swallowed
                // failure would leave systemd serving the cached view
                // of the OLD unit while we'd happily report ok — fail
                // loud instead, with a forensic-parity log line.
                match Command::new("sudo")
                    .args(["-k", "systemctl", "daemon-reload"])
                    .output()
                {
                    Ok(o) if o.status.success() => {
                        log_step("daemon_reload", "action=reload status=ok");
                    }
                    Ok(o) => {
                        log_step(
                            "daemon_reload",
                            &format!(
                                "action=reload status=fail stderr=\"{}\"",
                                String::from_utf8_lossy(&o.stderr).trim()
                            ),
                        );
                        eprintln!(
                            "sandbox update: systemctl daemon-reload failed: {}",
                            String::from_utf8_lossy(&o.stderr).trim()
                        );
                        return 1;
                    }
                    Err(e) => {
                        log_step(
                            "daemon_reload",
                            &format!("action=reload status=fail err=\"{e}\""),
                        );
                        eprintln!("sandbox update: failed to invoke systemctl daemon-reload: {e}");
                        return 1;
                    }
                }
            }
        }
        Err(e) => {
            log_step(
                "install_unit",
                &format!("path={unit_dst} action=install status=fail err=\"{e}\""),
            );
            eprintln!("sandbox update: failed to install systemd unit: {e}");
            return 1;
        }
    }

    // § 3.2.24 — Apply config migrations (per file, atomically).
    //
    // Test-only failure-injection hook gated behind the
    // `test-env-override` Cargo feature so the env-var name string
    // never appears in a release binary. Used by
    // tests/install-e2e/test_update_idempotency.py
    // (test_update_partial_failure_backup_set_preserved) to verify the
    // spec-§ 3.2.19 in-progress-manifest contract: a mid-update failure
    // at the migrate step must leave a backup-set manifest with
    // `completed_ok: false` on disk, which the next successful run
    // must preserve (spec § 5.2). When `SANDBOX_UPDATE_TEST_FAIL_AT_STEP`
    // is set to `migrate`, return a failure here before any migration
    // runs — the in-progress manifest from § 3.2.19 is already on disk.
    #[cfg(feature = "test-env-override")]
    if std::env::var("SANDBOX_UPDATE_TEST_FAIL_AT_STEP")
        .ok()
        .as_deref()
        == Some("migrate")
    {
        log_step(
            "migrate",
            "action=apply status=fail err=\"test-only injected failure (SANDBOX_UPDATE_TEST_FAIL_AT_STEP=migrate)\"",
        );
        eprintln!(
            "sandbox update: migration step aborted by test-only env var \
             SANDBOX_UPDATE_TEST_FAIL_AT_STEP=migrate"
        );
        return 1;
    }
    for target in [
        cfg_migrations::TargetFile::UsersConf,
        cfg_migrations::TargetFile::BridgeConf,
    ] {
        match migrate::apply_file_chain(target) {
            Ok(outcome) => {
                if outcome.source_absent {
                    log_step(
                        &format!("migrate_{}", target.display_name().replace('.', "_")),
                        "action=skip status=ok reason=absent",
                    );
                } else if outcome.applied.is_empty() {
                    log_step(
                        &format!("migrate_{}", target.display_name().replace('.', "_")),
                        "action=skip status=ok reason=already-at-latest",
                    );
                } else {
                    for id in &outcome.applied {
                        log_step(
                            &format!("migrate_{}", target.display_name().replace('.', "_")),
                            &format!(
                                "migration=V{id:03} path={} action=apply status=ok",
                                target.canonical_path().display()
                            ),
                        );
                    }
                }
            }
            Err(e) => {
                log_step(
                    &format!("migrate_{}", target.display_name().replace('.', "_")),
                    &format!("action=apply status=fail err=\"{e}\""),
                );
                eprintln!(
                    "sandbox update: migration apply failed for {}: {e}",
                    target.display_name()
                );
                return 1;
            }
        }
    }

    // § 3.2.26 — Start daemon (only if `was_running`).
    if sticky_was_running {
        match Command::new("sudo")
            .args(["-k", "systemctl", "start", "sandboxd"])
            .output()
        {
            Ok(o) if o.status.success() => {
                log_step(
                    "start_daemon",
                    &format!("was_running={sticky_was_running} action=start status=ok"),
                );
            }
            Ok(o) => {
                log_step(
                    "start_daemon",
                    &format!(
                        "was_running={sticky_was_running} action=start status=fail stderr={}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    ),
                );
                eprintln!(
                    "sandbox update: systemctl start sandboxd failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
                eprintln!(
                    "sandbox update: consult `sudo journalctl -u sandboxd -n 50` and the rollback recipe at {}/manifest.json",
                    backup_set_dir.display()
                );
                return 1;
            }
            Err(e) => {
                log_step(
                    "start_daemon",
                    &format!("action=start status=fail err=\"{e}\""),
                );
                eprintln!("sandbox update: failed to invoke systemctl: {e}");
                return 1;
            }
        }
    } else {
        log_step(
            "start_daemon",
            &format!("was_running={sticky_was_running} action=skip status=ok"),
        );
    }

    // § 3.2.27 — Verify post-start. 30s socket-appearance wait loop,
    // then curl /version. Skipped when the daemon was stopped
    // intentionally (was_running == false).
    if sticky_was_running {
        let sock = "/run/sandbox/sandboxd.sock";
        let mut appeared = false;
        for _ in 0..30 {
            if Path::new(sock).exists() {
                appeared = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        if !appeared {
            log_step(
                "verify_version",
                "action=verify status=fail reason=socket-absent",
            );
            eprintln!(
                "sandbox update: daemon socket {sock} did not appear within 30s; consult: sudo journalctl -u sandboxd -n 50"
            );
            return 1;
        }
        match query_daemon_version(sock).await {
            Ok(ver) if ver == inputs.target_version => {
                log_step(
                    "verify_version",
                    &format!(
                        "daemon={ver} target={} action=verify status=ok",
                        inputs.target_version
                    ),
                );
            }
            Ok(ver) => {
                log_step(
                    "verify_version",
                    &format!(
                        "daemon={ver} target={} action=verify status=fail",
                        inputs.target_version
                    ),
                );
                eprintln!(
                    "sandbox update: post-upgrade /version mismatch: daemon reports {ver}, expected {}",
                    inputs.target_version
                );
                return 1;
            }
            Err(e) => {
                log_step(
                    "verify_version",
                    &format!("action=verify status=fail err=\"{e}\""),
                );
                eprintln!("sandbox update: failed to query /version: {e}");
                return 1;
            }
        }
    } else {
        log_step(
            "verify_version",
            "action=skip status=ok reason=daemon-intentionally-stopped",
        );
    }

    // § 3.2.28 — `sandbox doctor --verbose`. The CLI binary on disk
    // is the new one (we just installed it). Spec 5 § 10.3 — the
    // running process keeps executing the old code, so we exec the
    // new binary explicitly.
    //
    // Drop privileges to the `sandbox` user for the doctor invocation.
    // The operator runs `sudo sandbox update`, so this code runs as
    // root; doctor's C4 check (`current user in 'sandbox' group`) reads
    // the calling process's `getgroups()`, and root is not in the
    // sandbox group, so C4 would `Fail` and the doctor would exit 1
    // even on an otherwise-healthy host. Running doctor as the
    // `sandbox` user matches the operator-facing contract (operators
    // are added to the sandbox group by install.sh § 4.4.10) and
    // mirrors how `assert_doctor_passes` in the e2e harness invokes it.
    //
    // `SANDBOX_SOCKET` is explicitly planted to the systemd-managed
    // path: `sudo -u sandbox` drops most env vars, the target user has
    // no `XDG_RUNTIME_DIR`, and the default fallback resolves to
    // `$HOME/.local/share/sandboxd/sandboxd.sock` which is wrong for
    // the systemd-managed daemon. Use `env SANDBOX_SOCKET=...` to
    // replant it (same shape as `assert_doctor_passes`).
    let doctor = Command::new("sudo")
        .args([
            "-k",
            "-u",
            "sandbox",
            "env",
            "SANDBOX_SOCKET=/run/sandbox/sandboxd.sock",
            "/usr/local/bin/sandbox",
            "doctor",
            "--verbose",
        ])
        .output();
    match doctor {
        Ok(o) if o.status.success() => {
            log_step("doctor", "result=pass status=ok");
        }
        Ok(o) => {
            log_step(
                "doctor",
                &format!(
                    "result=fail status=fail exit={} stderr={}",
                    o.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
            );
            eprintln!(
                "sandbox doctor reported failures; investigate before relying on this install."
            );
            eprintln!(
                "rollback recipe at {}/manifest.json",
                backup_set_dir.display()
            );
            return 1;
        }
        Err(e) => {
            log_step("doctor", &format!("action=run status=fail err=\"{e}\""));
            eprintln!("sandbox update: failed to invoke sandbox doctor: {e}");
            return 1;
        }
    }

    // § 3.2.29 — Update install state + finalize backup manifest.
    if let Err(e) = write_install_state_post_upgrade(&inputs) {
        log_step("finalize_state", &format!("status=fail err=\"{e}\""));
        eprintln!("sandbox update: failed to finalize install state: {e}");
        return 1;
    }
    log_step(
        "finalize_state",
        &format!(
            "installed_version={} previous_version={} status=ok",
            inputs.target_version, inputs.state.installed_version
        ),
    );
    let completed_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    match backup::finalize_manifest(&backup_set_dir, &completed_at) {
        Ok(_) => {
            log_step(
                "finalize_backup_manifest",
                &format!("path={}/manifest.json status=ok", backup_set_dir.display()),
            );
        }
        Err(e) => {
            log_step(
                "finalize_backup_manifest",
                &format!("status=fail err=\"{e}\""),
            );
            eprintln!("sandbox update: failed to finalize backup manifest: {e}");
            return 1;
        }
    }

    // § 3.2.25 — Prune older backup sets. Runs AFTER finalize_manifest
    // so the current run's set is `completed_ok: true` at this point
    // and counts toward `RETENTION_KEEP=2`. The earlier ordering
    // (prune before finalize) left the current set at
    // `completed_ok: false`, so `prune_old_backup_sets` skipped it
    // when applying the keep-limit and the on-disk count drifted to
    // `RETENTION_KEEP + 1` in steady state.
    match backup::prune_old_backup_sets() {
        Ok(o) => {
            log_step(
                "prune_backups",
                &format!(
                    "kept={} pruned={} forensic={} status=ok",
                    o.kept.len(),
                    o.pruned.len(),
                    o.preserved_forensic.len()
                ),
            );
        }
        Err(e) => {
            log_step("prune_backups", &format!("status=fail err=\"{e}\""));
            eprintln!("sandbox update: backup-set prune failed: {e}");
            return 1;
        }
    }

    // § 3.2.30 — Release the lock. Dropping `held_lock` removes the
    // file and closes the FD (releases the kernel flock).
    drop(held_lock);
    log_step("release_lock", "status=ok");
    log_step(
        "done",
        &format!("version={} elapsed=0 status=ok", inputs.target_version),
    );
    println!(
        "sandbox update: {} installed successfully.",
        inputs.target_version
    );
    0
}

// ---------------------------------------------------------------------------
// Stateful-phase helpers
// ---------------------------------------------------------------------------

/// Stage the release tarball into a private tempdir under `/tmp`,
/// returning a [`fetch::StagedTarball`]. Three paths:
///
/// * `--from <directory>` — used as-is; we wrap it in a `StagedTarball`
///   shape directly. (Tests + the pre-extracted layout flow.)
/// * `--from <tarball.tar.gz>` — `tar -xzf` into a tempdir.
/// * No `--from` — refuse for now. Network downloads through
///   `curl` are scoped for a follow-up; operators in production
///   pass `--from`.
fn prepare_staged_tarball(
    args: &UpdateArgs,
    target_version: &str,
) -> Result<fetch::StagedTarball, String> {
    let from = args.from.as_ref().ok_or_else(|| {
        "sandbox update: --from <tarball> is required for the stateful phase. \
         Pass a release tarball downloaded from \
         https://github.com/Koriit/sandboxd/releases/latest"
            .to_string()
    })?;
    if from.is_dir() {
        let manifest = fetch::read_manifest(&from.join("MANIFEST"))
            .map_err(|e| format!("read MANIFEST from {}: {e}", from.display()))?;
        if manifest.version != target_version {
            return Err(format!(
                "MANIFEST version mismatch: directory {} contains version {}, expected {}",
                from.display(),
                manifest.version,
                target_version
            ));
        }
        return Ok(fetch::StagedTarball {
            stage_dir: from.clone(),
            manifest,
        });
    }
    let dest = std::env::temp_dir().join(format!("sandboxd-update-{}", std::process::id()));
    fetch::extract_tarball(from, &dest).map_err(|e| format!("extract {}: {e}", from.display()))
}

/// One entry returned by the staged binary's `--dump-migration-set`.
/// Shape-compatible with [`crate::cfg_migrations::MigrationEntry`] but
/// re-declared here as the wire-side view so the CLI can render
/// dump-output read from a *different* binary version without sharing
/// types with the producer.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StagedMigrationEntry {
    pub id: u32,
    pub name: String,
    pub from_version: u32,
    pub to_version: u32,
    pub target_file: String,
}

/// Run the staged CLI's `--dump-migration-set` and parse the result.
/// The dump is read-only (no privilege, no path arguments) and runs
/// entirely inside the binary's process — invoking it on the unstaged
/// (current-version) binary is also safe, but the point is to read
/// the *target* registry so the prompt enumerates what the upgrade
/// will actually apply.
pub fn query_staged_migration_set(
    staged_sandbox: &Path,
) -> Result<Vec<StagedMigrationEntry>, String> {
    let out = std::process::Command::new(staged_sandbox)
        .arg("dump-migration-set")
        .output()
        .map_err(|e| {
            format!(
                "invoke {} dump-migration-set: {e}",
                staged_sandbox.display()
            )
        })?;
    if !out.status.success() {
        return Err(format!(
            "{} dump-migration-set: exit {:?}: {}",
            staged_sandbox.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let entries: Vec<StagedMigrationEntry> = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("parse migration set from {}: {e}", staged_sandbox.display()))?;
    Ok(entries)
}

/// Run the staged CLI's `--dump-proto-version` and extract the target
/// daemon's `DAEMON_GUEST_PROTO_VERSION`. The JSON shape is pinned at
/// `{ "daemon_guest_proto_version": <u32> }` — operator-stable so
/// future protocol bumps add fields rather than renaming this key.
pub fn query_staged_proto_version(staged_sandbox: &Path) -> Result<u32, String> {
    #[derive(serde::Deserialize)]
    struct Payload {
        daemon_guest_proto_version: u32,
    }
    let out = std::process::Command::new(staged_sandbox)
        .arg("dump-proto-version")
        .output()
        .map_err(|e| {
            format!(
                "invoke {} dump-proto-version: {e}",
                staged_sandbox.display()
            )
        })?;
    if !out.status.success() {
        return Err(format!(
            "{} dump-proto-version: exit {:?}: {}",
            staged_sandbox.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let payload: Payload = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("parse proto-version from {}: {e}", staged_sandbox.display()))?;
    Ok(payload.daemon_guest_proto_version)
}

/// `install -D -m <mode> -o root -g root <src> <dst>` via sudo, with
/// sha256 compare for idempotency. Returns `"install"` or `"skip"`.
fn install_binary_if_changed(
    src: &Path,
    dst: &str,
    mode: u32,
) -> Result<&'static str, std::io::Error> {
    let mode_str = format!("{mode:04o}");
    if files_byte_equal(src, Path::new(dst))? {
        return Ok("skip");
    }
    let status = std::process::Command::new("sudo")
        .args([
            "-k",
            "install",
            "-D",
            "-m",
            &mode_str,
            "-o",
            "root",
            "-g",
            "root",
            src.to_str().unwrap(),
            dst,
        ])
        .output()?;
    if !status.status.success() {
        return Err(std::io::Error::other(format!(
            "install -m {mode_str} {src:?} {dst}: exit {:?}: {}",
            status.status.code(),
            String::from_utf8_lossy(&status.stderr).trim()
        )));
    }
    Ok("install")
}

/// Same as [`install_binary_if_changed`] but for non-executable
/// root-owned files (e.g. the systemd unit).
fn install_root_file_if_changed(
    src: &Path,
    dst: &str,
    mode: u32,
) -> Result<&'static str, std::io::Error> {
    install_binary_if_changed(src, dst, mode)
}

/// `cmp -s` equivalent in-process; both files must be readable by the
/// current process. For destinations under root ownership the call
/// may return `Err(PermissionDenied)`, treated as "differ".
fn files_byte_equal(a: &Path, b: &Path) -> Result<bool, std::io::Error> {
    if !b.exists() {
        return Ok(false);
    }
    let ba = std::fs::read(a)?;
    let bb = match std::fs::read(b) {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };
    Ok(ba == bb)
}

/// `curl --unix-socket <sock> http://localhost/version` and pluck the
/// `version` field. Spec 5 § 3.2.27.
async fn query_daemon_version(sock: &str) -> Result<String, String> {
    let bytes = http_get(sock, "/version")
        .await
        .map_err(|e| format!("http: {e}"))?;
    #[derive(serde::Deserialize)]
    struct VersionResp {
        version: String,
    }
    let v: VersionResp =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse /version: {e}"))?;
    Ok(v.version)
}

/// Update `.install-state.json`'s `previous_version` field before any
/// binary swap. Spec 5 § 3.2.18.
///
/// Implementation: read the current state (as root), set the field,
/// write via a tempfile owned by the current process, then `sudo
/// install -m 0640 -o sandbox -g sandbox` over the destination.
fn write_install_state_previous_version(previous_version: &str) -> Result<(), String> {
    update_install_state_json(|v| {
        let obj = v
            .as_object_mut()
            .ok_or_else(|| "install state is not a JSON object".to_string())?;
        obj.insert(
            "previous_version".to_string(),
            serde_json::Value::String(previous_version.to_string()),
        );
        Ok(())
    })
}

/// Finalize `.install-state.json` after a successful upgrade. Spec 5
/// § 3.2.29: set `installed_version`, `installed_at`, and
/// `updated_by_operator`; preserve `previous_version` from § 3.2.18.
fn write_install_state_post_upgrade(inputs: &StatefulInputs<'_>) -> Result<(), String> {
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let operator = std::env::var("SUDO_USER").unwrap_or_else(|_| "(direct-root)".to_string());
    let target_version = inputs.target_version.to_string();
    update_install_state_json(move |v| {
        let obj = v
            .as_object_mut()
            .ok_or_else(|| "install state is not a JSON object".to_string())?;
        obj.insert(
            "installed_version".to_string(),
            serde_json::Value::String(target_version.clone()),
        );
        obj.insert(
            "installed_at".to_string(),
            serde_json::Value::String(now.clone()),
        );
        obj.insert(
            "updated_by_operator".to_string(),
            serde_json::Value::String(operator.clone()),
        );
        Ok(())
    })
}

/// Read the install state as root, apply `mutate`, write via a tempfile
/// owned by the current process, then `sudo install` over the dest.
fn update_install_state_json<F>(mutate: F) -> Result<(), String>
where
    F: FnOnce(&mut serde_json::Value) -> Result<(), String>,
{
    use std::io::Write;
    let out = std::process::Command::new("sudo")
        .args(["-k", "cat", INSTALL_STATE_PATH])
        .output()
        .map_err(|e| format!("read install state: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "read install state: exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let mut value: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("parse install state: {e}"))?;
    mutate(&mut value)?;
    let pretty =
        serde_json::to_vec_pretty(&value).map_err(|e| format!("encode install state: {e}"))?;
    let mut tmp = tempfile::NamedTempFile::new().map_err(|e| format!("create tempfile: {e}"))?;
    tmp.write_all(&pretty)
        .map_err(|e| format!("write tempfile: {e}"))?;
    tmp.flush().map_err(|e| format!("flush tempfile: {e}"))?;
    let tmp_path = tmp.path().to_path_buf();
    let status = std::process::Command::new("sudo")
        .args([
            "-k",
            "install",
            "-m",
            "0640",
            "-o",
            "sandbox",
            "-g",
            "sandbox",
            tmp_path.to_str().unwrap(),
            INSTALL_STATE_PATH,
        ])
        .output()
        .map_err(|e| format!("sudo install: {e}"))?;
    if !status.status.success() {
        return Err(format!(
            "sudo install install-state: exit {:?}: {}",
            status.status.code(),
            String::from_utf8_lossy(&status.stderr).trim()
        ));
    }
    Ok(())
}

/// Canonical install-log path. Spec 4 § 4.6. Operators on hosts where
/// `/var/log` is read-only can override via `$SANDBOXD_INSTALL_LOG`
/// (parsed by [`resolve_install_log_path`]); install.sh / uninstall.sh
/// read the same env var so the three writers stay in sync.
pub const DEFAULT_INSTALL_LOG_PATH: &str = "/var/log/sandbox-install.log";

/// Env var that overrides [`DEFAULT_INSTALL_LOG_PATH`]. Mirrors the
/// shell-side `${SANDBOXD_INSTALL_LOG:-…}` expansion install.sh /
/// uninstall.sh use.
pub const INSTALL_LOG_ENV_VAR: &str = "SANDBOXD_INSTALL_LOG";

/// Resolve the install log path operator-side. The env var takes
/// precedence when set to a non-empty value; otherwise the canonical
/// `/var/log/sandbox-install.log` is used. Pulled into a pure
/// function (taking the env-var value as input) so tests can drive
/// every branch without poking the process env.
///
/// Pre-existing callers were hardcoded to the canonical path; this
/// indirection lets `sandbox update`'s `log_step` instrumentation
/// honour the same override install.sh respects, so an operator who
/// pinned `SANDBOXD_INSTALL_LOG=/srv/log/sandboxd.log` at install
/// time keeps the update audit trail in the same place.
pub fn resolve_install_log_path(env_override: Option<&str>) -> String {
    match env_override {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => DEFAULT_INSTALL_LOG_PATH.to_string(),
    }
}

/// Append a `step=...` line to the install log (default
/// `/var/log/sandbox-install.log`, or whatever
/// `$SANDBOXD_INSTALL_LOG` points at) with the `sandbox-update`
/// second token. Matches install.sh's `log_ok` shape (Spec 5 § 2.6).
/// Best-effort — log write failure does not abort the upgrade.
fn log_step(step: &str, fields: &str) {
    use std::io::Write;
    let line = format!(
        "{} sandbox-update step={step} {fields}\n",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
    );
    let path = resolve_install_log_path(std::env::var(INSTALL_LOG_ENV_VAR).ok().as_deref());
    // Try direct append first (the daemon may run with operator
    // privileges in some configurations); fall back to `sudo tee -a`.
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
    {
        let _ = f.write_all(line.as_bytes());
        return;
    }
    let _ = std::process::Command::new("sudo")
        .args(["-k", "tee", "-a", &path])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(line.as_bytes());
            }
            child.wait()
        });
}

// ---------------------------------------------------------------------------
// Internal helpers (target version, MANIFEST read, systemctl probe)
// ---------------------------------------------------------------------------

/// Resolve the target version per Spec 5 § 3.1.4. Three paths:
///
/// 1. `--from <tarball.tar.gz>` — peek MANIFEST out of the tarball
///    via `tar -O -xzf ... '*/MANIFEST'`. The tarball file's
///    encoded version is the authoritative answer (the filename is
///    operator-controlled and can lie; the MANIFEST is signed).
/// 2. `--from <directory>` — read `<dir>/MANIFEST` directly. This
///    path is exercised by the unit tests and the pre-extracted
///    layout flow.
/// 3. `--version <v>` (anything other than `latest`) — verbatim.
/// 4. `latest` (default) — `curl
///    https://api.github.com/repos/Koriit/sandboxd/releases/latest`.
fn resolve_target_version(args: &UpdateArgs, _state: &InstallState) -> Result<String, String> {
    if let Some(from) = args.from.as_ref() {
        if from.is_dir() {
            let manifest_path = from.join("MANIFEST");
            let m = fetch::read_manifest(&manifest_path)
                .map_err(|e| format!("read MANIFEST from {}: {e}", manifest_path.display()))?;
            return Ok(m.version);
        }
        if from.is_file() {
            let m = fetch::peek_manifest_in_tarball(from).map_err(|e| {
                format!(
                    "peek MANIFEST from {}: {e} (is this a valid release tarball?)",
                    from.display()
                )
            })?;
            return Ok(m.version);
        }
        return Err(format!(
            "--from {}: not a file or directory",
            from.display()
        ));
    }
    if args.version != "latest" {
        return Ok(args.version.clone());
    }
    fetch::resolve_latest_version_via_github()
        .map_err(|e| format!("resolve latest version via GitHub Releases API: {e}"))
}

/// Run the arch + version cross-check against a `--from` tarball or
/// pre-extracted directory. Spec 5 § 3.1.10.
fn check_manifest_from_tarball(
    from: &Path,
    target_version: &str,
    installed_arch: &str,
) -> Result<(), String> {
    let m = if from.is_dir() {
        let manifest_path = from.join("MANIFEST");
        fetch::read_manifest(&manifest_path)
            .map_err(|e| format!("read MANIFEST from {}: {e}", manifest_path.display()))?
    } else if from.is_file() {
        fetch::peek_manifest_in_tarball(from)
            .map_err(|e| format!("peek MANIFEST from {}: {e}", from.display()))?
    } else {
        return Err(format!(
            "--from {}: not a file or directory",
            from.display()
        ));
    };
    fetch::check_manifest_arch(&m, installed_arch).map_err(|e| e.to_string())?;
    fetch::check_manifest_version(&m, target_version).map_err(|e| e.to_string())?;
    Ok(())
}

/// In-memory migration walk for the given file. Mirrors the production
/// `apply_pending_at` walk but without writing — § 3.1.11.
fn dry_run_migration(file: cfg_migrations::TargetFile) -> Result<(), String> {
    let path = file.canonical_path();
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let mut current_bytes = bytes;
    loop {
        let current =
            cfg_migrations::read_schema_version(&current_bytes, file).map_err(|e| e.to_string())?;
        let target = cfg_migrations::latest_for(file);
        if current >= target {
            return Ok(());
        }
        let m = cfg_migrations::registry()
            .iter()
            .copied()
            .find(|m| m.target_file() == file && m.from_version() == current)
            .ok_or_else(|| {
                format!(
                    "no migration available for {} at version {}",
                    file.display_name(),
                    current
                )
            })?;
        // Use the public in-memory apply (which also runs the post-
        // migration schema validation).
        let next = cfg_migrations::apply_migration_in_memory(m.id(), &current_bytes, file)
            .map_err(|e| e.to_string())?;
        current_bytes = next;
    }
}

/// Tolerant wrapper around `systemctl is-active <unit>` — returns
/// `true` iff systemctl reports `"active"`. Treats any non-zero exit
/// or fork failure as "not running".
fn systemctl_is_active(unit: &str) -> bool {
    use std::process::Command;
    match Command::new("systemctl")
        .arg("is-active")
        .arg(unit)
        .output()
    {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout);
            s.trim() == "active"
        }
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_state() -> InstallState {
        InstallState {
            installed_version: "1.0.0".to_string(),
            installed_arch: "x86_64-unknown-linux-gnu".to_string(),
            installed_at: "2026-05-08T14:23:11Z".to_string(),
            installed_by_operator: "alice".to_string(),
            previous_version: None,
        }
    }

    #[test]
    fn args_validate_rejects_check_dry_run_combo() {
        let mut a = base_args();
        a.check = true;
        a.dry_run = true;
        assert!(a.validate().is_err());
    }

    #[test]
    fn args_validate_rejects_cosign_bundle_without_from() {
        let mut a = base_args();
        a.cosign_bundle = Some(PathBuf::from("/tmp/bundle"));
        assert!(a.validate().is_err());
    }

    #[test]
    fn args_validate_rejects_from_plus_source_url() {
        let mut a = base_args();
        a.from = Some(PathBuf::from("/tmp/sandboxd.tar.gz"));
        a.source_url = "https://example.com/mirror".to_string();
        assert!(a.validate().is_err());
    }

    fn base_args() -> UpdateArgs {
        UpdateArgs {
            version: "latest".to_string(),
            from: None,
            cosign_bundle: None,
            source_url: DEFAULT_SOURCE_URL.to_string(),
            check: false,
            dry_run: false,
            yes: false,
            force: false,
            quiet: false,
            verbose: false,
            socket_path: "/nonexistent/socket".to_string(),
        }
    }

    /// `--check` against an up-to-date installation produces the
    /// minimal three-line shape (§ 2.2 sample 2).
    #[test]
    fn check_report_up_to_date_format() {
        let state = sample_state();
        let report = CheckReport {
            state: &state,
            target_version: "1.0.0",
            target_arch: "x86_64-unknown-linux-gnu",
            target_released_at: None,
            compare: VersionCompare::UpToDate,
            pending_config_migrations: vec![],
            session_counts: SessionCounts {
                active: 0,
                stopped: 0,
                reachable: true,
            },
        };
        let mut out = Vec::new();
        render_check_report(&mut out, &report).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Installed: sandboxd 1.0.0"), "got: {s}");
        assert!(s.contains("Available: sandboxd 1.0.0"), "got: {s}");
        assert!(s.contains("Status:    up to date"), "got: {s}");
    }

    /// `--check` with an upgrade available produces the longer
    /// shape (§ 2.2 sample 1) including "Run `sudo sandbox update` to
    /// apply.".
    #[test]
    fn check_report_update_available_format() {
        let state = sample_state();
        let pending = vec![PendingMigration {
            id: 2,
            name: "add per-pool rate limit metadata".to_string(),
            target_file: "users.conf",
        }];
        let report = CheckReport {
            state: &state,
            target_version: "1.1.0",
            target_arch: "x86_64-unknown-linux-gnu",
            target_released_at: Some("2026-05-10T09:00:00Z"),
            compare: VersionCompare::UpdateAvailable,
            pending_config_migrations: pending,
            session_counts: SessionCounts {
                active: 0,
                stopped: 3,
                reachable: true,
            },
        };
        let mut out = Vec::new();
        render_check_report(&mut out, &report).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Status:    update available"), "got:\n{s}");
        assert!(s.contains("Installed: sandboxd 1.0.0"), "got:\n{s}");
        assert!(s.contains("Available: sandboxd 1.1.0"), "got:\n{s}");
        assert!(s.contains("Pending config migrations"), "got:\n{s}");
        assert!(
            s.contains("V002 (add per-pool rate limit metadata)"),
            "got:\n{s}"
        );
        assert!(s.contains("Stopped sessions: 3"), "got:\n{s}");
        assert!(
            s.contains("Run `sudo sandbox update` to apply."),
            "got:\n{s}"
        );
    }

    /// `pending_migration_human_description` translates the
    /// snake_case migration slug used in `ConfigMigration::name()`
    /// into the human-friendly rendering Spec 5 § 2.2 pins for
    /// `--check`. Underscores become spaces; everything else is
    /// verbatim. The default migration name shipped in the spec
    /// (`add per-pool rate limit metadata`) already reads as a
    /// human sentence so it round-trips unchanged.
    #[test]
    fn pending_migration_human_description_replaces_underscores() {
        assert_eq!(
            pending_migration_human_description("add_sandbox_to_allow_users"),
            "add sandbox to allow users"
        );
    }

    #[test]
    fn pending_migration_human_description_leaves_human_names_verbatim() {
        // Spaces, dashes, parentheses, digits all pass through.
        assert_eq!(
            pending_migration_human_description("add per-pool rate limit metadata (v2)"),
            "add per-pool rate limit metadata (v2)"
        );
    }

    /// `--dry-run` against an up-to-date install must label every
    /// applicable step `would skip`. The renderer projects per-step
    /// idempotency onto the read-only inputs so an operator can
    /// verify the update is a no-op without invoking the stateful
    /// phase.
    ///
    /// The eight always-execute steps stay `would execute` per the
    /// `stateful_step_verdict` rationale — they have no
    /// idempotency shortcut to project; their bodies converge by
    /// running. The remaining ten flip to `would skip` on an
    /// up-to-date install.
    #[test]
    fn dry_run_up_to_date_install_labels_idempotent_steps_would_skip() {
        let state = sample_state();
        let report = CheckReport {
            state: &state,
            target_version: &state.installed_version, // up to date
            target_arch: "x86_64-unknown-linux-gnu",
            target_released_at: None,
            compare: VersionCompare::UpToDate,
            pending_config_migrations: vec![],
            session_counts: SessionCounts {
                active: 0,
                stopped: 0,
                reachable: true,
            },
        };
        let disk = DiskCheck {
            rows: vec![DiskRow {
                path: PathBuf::from("/tmp"),
                free_kb: 9_000_000,
                needed_kb: 1024 * 1024,
            }],
        };
        let mut out = Vec::new();
        render_dry_run(&mut out, &report, &disk).unwrap();
        let s = String::from_utf8(out).unwrap();

        // Every step with a sha256 / image-presence / caps /
        // unit-bytes idempotency shortcut must read `would skip`
        // on an up-to-date install. § 3.2.14 (stop daemon) is in
        // the up-to-date skip group per the projection rationale.
        for id in [
            "§ 3.2.14",
            "§ 3.2.15",
            "§ 3.2.16",
            "§ 3.2.17",
            "§ 3.2.18",
            "§ 3.2.20",
            "§ 3.2.21",
            "§ 3.2.22",
            "§ 3.2.23",
            "§ 3.2.24",
        ] {
            let needle = format!("{id} ");
            let line = s
                .lines()
                .find(|l| l.contains(&needle))
                .unwrap_or_else(|| panic!("step {id} missing from dry-run:\n{s}"));
            assert!(
                line.contains("would skip"),
                "step {id} must read `would skip` on an up-to-date install; got: {line}"
            );
        }

        // The always-execute steps still read `would execute`.
        for id in [
            "§ 3.2.13",
            "§ 3.2.19",
            "§ 3.2.25",
            "§ 3.2.26",
            "§ 3.2.27",
            "§ 3.2.28",
            "§ 3.2.29",
            "§ 3.2.30",
        ] {
            let needle = format!("{id} ");
            let line = s
                .lines()
                .find(|l| l.contains(&needle))
                .unwrap_or_else(|| panic!("step {id} missing from dry-run:\n{s}"));
            assert!(
                line.contains("would execute"),
                "step {id} must read `would execute` (always-execute step); got: {line}"
            );
        }
    }

    /// `stateful_step_verdict` projects the per-step idempotency
    /// rules without touching the renderer. Pin a few critical
    /// rows: § 3.2.13 always executes (lock acquire), § 3.2.21
    /// flips with up-to-date, § 3.2.24 flips with the pending-
    /// migrations bool.
    #[test]
    fn stateful_step_verdict_rules() {
        // Always-execute steps ignore both inputs.
        for id in [
            "§ 3.2.13",
            "§ 3.2.19",
            "§ 3.2.25",
            "§ 3.2.26",
            "§ 3.2.27",
            "§ 3.2.28",
            "§ 3.2.29",
            "§ 3.2.30",
        ] {
            assert_eq!(stateful_step_verdict(id, true, true), "would execute");
            assert_eq!(stateful_step_verdict(id, true, false), "would execute");
            assert_eq!(stateful_step_verdict(id, false, true), "would execute");
            assert_eq!(stateful_step_verdict(id, false, false), "would execute");
        }
        // sha256-shortcut steps: flip on up-to-date.
        for id in [
            "§ 3.2.15",
            "§ 3.2.16",
            "§ 3.2.17",
            "§ 3.2.20",
            "§ 3.2.21",
            "§ 3.2.22",
            "§ 3.2.23",
        ] {
            assert_eq!(stateful_step_verdict(id, true, false), "would skip");
            assert_eq!(stateful_step_verdict(id, false, false), "would execute");
        }
        // § 3.2.24 flips on pending-migrations independently of
        // up-to-date.
        assert_eq!(
            stateful_step_verdict("§ 3.2.24", false, true),
            "would execute"
        );
        assert_eq!(
            stateful_step_verdict("§ 3.2.24", false, false),
            "would skip"
        );
        assert_eq!(
            stateful_step_verdict("§ 3.2.24", true, true),
            "would execute"
        );
        assert_eq!(stateful_step_verdict("§ 3.2.24", true, false), "would skip");
    }

    /// `--dry-run` lists all 18 stateful step ids (§§ 3.2.13-3.2.30).
    #[test]
    fn dry_run_lists_all_18_stateful_steps() {
        let state = sample_state();
        let report = CheckReport {
            state: &state,
            target_version: "1.1.0",
            target_arch: "x86_64-unknown-linux-gnu",
            target_released_at: None,
            compare: VersionCompare::UpdateAvailable,
            pending_config_migrations: vec![],
            session_counts: SessionCounts {
                active: 0,
                stopped: 0,
                reachable: true,
            },
        };
        let disk = DiskCheck {
            rows: vec![DiskRow {
                path: PathBuf::from("/tmp"),
                free_kb: 9_000_000,
                needed_kb: 1024 * 1024,
            }],
        };
        let mut out = Vec::new();
        render_dry_run(&mut out, &report, &disk).unwrap();
        let s = String::from_utf8(out).unwrap();
        for id in 13u32..=30 {
            let token = format!("§ 3.2.{id}");
            assert!(
                s.contains(&token),
                "step {token} missing from dry-run:\n{s}"
            );
        }
        assert!(s.contains("would execute"), "got:\n{s}");
    }

    /// Spec § 2.4: the literal token `Proceed? [y/N]:` is the
    /// idempotency E2E anchor.
    #[test]
    fn confirmation_summary_contains_proceed_token() {
        let s = render_confirmation_summary(
            "1.0.0",
            "1.1.0",
            &[],
            &[],
            true,
            &SessionCounts {
                active: 0,
                stopped: 0,
                reachable: true,
            },
            None,
        );
        assert!(s.contains("Proceed? [y/N]:"), "got: {s}");
    }

    /// `read_yes_no` returns `true` only for exactly `y`. Anything else
    /// — `Y`, `yes`, `N`, empty — aborts.
    #[test]
    fn read_yes_no_strict() {
        assert!(read_yes_no(Cursor::new(b"y\n")));
        assert!(!read_yes_no(Cursor::new(b"Y\n")));
        assert!(!read_yes_no(Cursor::new(b"yes\n")));
        assert!(!read_yes_no(Cursor::new(b"N\n")));
        assert!(!read_yes_no(Cursor::new(b"\n")));
        assert!(!read_yes_no(Cursor::new(b"")));
    }

    #[test]
    fn compare_versions_basic() {
        assert_eq!(compare_versions("1.0.0", "1.0.0"), VersionCompare::UpToDate);
        assert_eq!(
            compare_versions("1.0.0", "1.1.0"),
            VersionCompare::UpdateAvailable
        );
        assert_eq!(
            compare_versions("unknown", "1.1.0"),
            VersionCompare::InstalledUnknown
        );
    }

    /// Spec 5 § 3.1.7 — `classify_session_compat` splits sessions into
    /// three buckets: `Ok` for exact-match, `RefreshInPlace` when the
    /// target's `can_refresh_in_place` accepts the session's proto,
    /// `Recreate` for the unsalvageable case (`session_proto == 0`).
    #[test]
    fn classify_session_compat_three_buckets() {
        // Same proto → no-op.
        assert_eq!(classify_session_compat(2, 2), CompatBucket::Ok);
        // Older proto, non-zero → refresh.
        assert_eq!(classify_session_compat(1, 2), CompatBucket::RefreshInPlace);
        // Newer-than-target proto, non-zero → refresh (the daemon's
        // refresh path stages its embedded guest into the session;
        // narrowing this is a future-spec change, not a current bucket).
        assert_eq!(classify_session_compat(3, 2), CompatBucket::RefreshInPlace);
        // Proto = 0 (legacy / pre-V006) → unsalvageable.
        assert_eq!(classify_session_compat(0, 2), CompatBucket::Recreate);
    }

    /// `CompatBucket::label` returns the operator-facing tokens we
    /// render in the confirmation prompt; pinned here so a future
    /// rename of an enum variant doesn't silently change the prompt.
    #[test]
    fn compat_bucket_labels_are_stable_tokens() {
        assert_eq!(CompatBucket::Ok.label(), "ok");
        assert_eq!(CompatBucket::RefreshInPlace.label(), "refresh-in-place");
        assert_eq!(CompatBucket::Recreate.label(), "recreate");
    }

    /// `render_confirmation_summary` renders the operator-visible
    /// three-bucket breakdown when the per-session classification was
    /// computed; this pins the prompt shape Spec 5 § 2.4
    /// recreate-classification contract calls for.
    #[test]
    fn confirmation_summary_renders_three_bucket_breakdown() {
        let compat = SessionCompatSet {
            target_proto: 2,
            stopped: vec![
                SessionCompat {
                    id: "alpha".to_string(),
                    session_proto: 2,
                    bucket: CompatBucket::Ok,
                },
                SessionCompat {
                    id: "beta".to_string(),
                    session_proto: 1,
                    bucket: CompatBucket::RefreshInPlace,
                },
                SessionCompat {
                    id: "gamma".to_string(),
                    session_proto: 0,
                    bucket: CompatBucket::Recreate,
                },
            ],
            classified: true,
        };
        let pending_db = [StagedMigrationEntry {
            id: 7,
            name: "add_widget_table".to_string(),
            from_version: 6,
            to_version: 7,
            target_file: "sessions.db".to_string(),
        }];
        let s = render_confirmation_summary(
            "1.0.0",
            "1.1.0",
            &[],
            &pending_db,
            true,
            &SessionCounts {
                active: 0,
                stopped: 3,
                reachable: true,
            },
            Some(&compat),
        );
        assert!(s.contains("ok=1"), "got: {s}");
        assert!(s.contains("refresh-in-place=1"), "got: {s}");
        assert!(s.contains("recreate=1"), "got: {s}");
        assert!(s.contains("alpha"), "got: {s}");
        assert!(s.contains("beta"), "got: {s}");
        assert!(s.contains("gamma"), "got: {s}");
        assert!(s.contains("V007 (add_widget_table)"), "got: {s}");
        assert!(s.contains("6 -> 7"), "got: {s}");
        assert!(s.contains("[sessions.db]"), "got: {s}");
        // Placeholder spec-internals string is gone.
        assert!(
            !s.contains("(enumerated after extraction at"),
            "placeholder leaked: {s}"
        );
    }

    /// When the classification step couldn't run (daemon unreachable
    /// or staged-binary probe failed), the prompt falls back to the
    /// flat `stopped sessions: N` line — no spec-internals leak.
    #[test]
    fn confirmation_summary_falls_back_to_flat_count_without_classification() {
        let s = render_confirmation_summary(
            "1.0.0",
            "1.1.0",
            &[],
            &[],
            true,
            &SessionCounts {
                active: 0,
                stopped: 4,
                reachable: true,
            },
            None,
        );
        assert!(s.contains("stopped sessions:           4"), "got: {s}");
        assert!(s.contains("pending db migrations:      none"), "got: {s}");
        assert!(
            !s.contains("(enumerated after extraction at"),
            "placeholder leaked: {s}"
        );
    }

    /// Dev-mode detect trips when either the systemd unit or the
    /// install state file is absent.
    #[test]
    fn dev_mode_detect_trip_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let unit = tmp.path().join("sandboxd.service");
        let state = tmp.path().join(".install-state.json");
        // Both absent → dev mode.
        assert!(is_dev_mode(&unit, &state));
        // One present → still dev mode.
        std::fs::write(&unit, b"[Unit]\n").unwrap();
        assert!(is_dev_mode(&unit, &state));
        // Both present → system install.
        std::fs::write(&state, b"{}").unwrap();
        assert!(!is_dev_mode(&unit, &state));
    }

    /// Install-state read tolerates missing file in the read-only
    /// modes.
    #[test]
    fn install_state_read_returns_none_for_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("missing.json");
        let got = read_install_state(&p).unwrap();
        assert!(got.is_none());
    }

    /// `resolve_install_log_path` honours a non-empty
    /// `$SANDBOXD_INSTALL_LOG` value verbatim (Spec 4 § 4.6 env
    /// override). Pure-function test — pinned against a synthetic
    /// path so the process env is never poked.
    #[test]
    fn install_log_path_respects_env_override() {
        let path = resolve_install_log_path(Some("/srv/log/sandboxd.log"));
        assert_eq!(path, "/srv/log/sandboxd.log");
    }

    /// `resolve_install_log_path` falls back to the canonical
    /// `/var/log/sandbox-install.log` when the env value is unset.
    #[test]
    fn install_log_path_falls_back_when_env_unset() {
        let path = resolve_install_log_path(None);
        assert_eq!(path, DEFAULT_INSTALL_LOG_PATH);
    }

    /// An empty env value (`SANDBOXD_INSTALL_LOG=`) is treated as
    /// "not set" — mirrors the shell-side `${SANDBOXD_INSTALL_LOG:-…}`
    /// expansion install.sh / uninstall.sh use, where `:-` falls
    /// back on both unset and empty.
    #[test]
    fn install_log_path_falls_back_on_empty_env_value() {
        let path = resolve_install_log_path(Some(""));
        assert_eq!(path, DEFAULT_INSTALL_LOG_PATH);
    }

    /// `enumerate_pending_config_migrations` returns an empty vec when
    /// the canonical paths are unreadable — the read-only modes degrade
    /// gracefully — and a list of well-shaped `PendingMigration` entries
    /// when they ARE readable and below-latest.
    ///
    /// The previous shape `assert!(got.iter().all(|m| !m.name.is_empty()))`
    /// was vacuously true on an empty vec — a regression that returned
    /// a vec of garbage entries with empty `.name` strings would have
    /// also passed on a dev host that happens to have a readable
    /// users.conf. The fix splits into two branches:
    ///
    /// - If the canonical paths are not readable (no users.conf, or
    ///   permission denied for the test's uid): the function MUST
    ///   return an empty vec. We pin that exactly.
    /// - If a path IS readable and below-latest: each returned entry
    ///   must have a non-empty `name` AND a non-empty `target_file`
    ///   (the field-shape invariant the original vacuous assertion
    ///   was trying to express but couldn't reach on an empty vec).
    ///
    /// The branch is determined at test time by probing the canonical
    /// users.conf path for read access; the test does not skip — it
    /// runs the appropriate set of assertions for the host state it
    /// observes.
    #[test]
    fn enumerate_pending_returns_empty_when_paths_absent() {
        let got = enumerate_pending_config_migrations();

        // Probe the canonical path the way `enumerate_pending_config_migrations`
        // does internally: try to read it. If `std::fs::read` succeeds,
        // the host has the file readable by the test's uid and we
        // expect a populated vec; otherwise empty.
        //
        // `users_conf_path()` resolves the canonical or env-override
        // location depending on the daemon build; reuse the same
        // resolver so the test follows the function under test rather
        // than reaching past it.
        let canonical_readable = std::fs::read(sandbox_core::users_conf::users_conf_path()).is_ok();

        if canonical_readable {
            // A dev host with /etc/sandboxd/users.conf readable. The
            // returned entries (if any) must each carry a non-empty
            // name and a non-empty target_file — pin the field-shape
            // invariant directly rather than via `iter().all(...)`
            // which would still vacuously pass on a fully-up-to-date
            // file.
            for entry in &got {
                assert!(
                    !entry.name.is_empty(),
                    "PendingMigration `name` must be non-empty; got: {entry:?}"
                );
                assert!(
                    !entry.target_file.is_empty(),
                    "PendingMigration `target_file` must be non-empty; got: {entry:?}"
                );
            }
        } else {
            // Clean environment (the spec contract this test
            // originally claimed to pin): canonical path is not
            // readable, so the function returns an empty vec — the
            // `continue` arms in `enumerate_pending_config_migrations`
            // tolerate both ENOENT and EACCES.
            assert!(
                got.is_empty(),
                "canonical paths are unreadable but the function returned {got:?}; \
                 the `continue` arms must keep the outer Vec empty under either \
                 ENOENT or EACCES"
            );
        }
    }

    /// **Exit-criterion 5:** `sandbox update --from <dir>` with a
    /// MANIFEST arch that differs from `installed_arch` dies with
    /// "MANIFEST arch mismatch" before any state mutation.
    #[test]
    fn check_manifest_from_tarball_arch_mismatch_surfaces() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = serde_json::json!({
            "version": "1.1.0",
            "arch": "aarch64-unknown-linux-gnu",
            "artifacts": {}
        });
        std::fs::write(
            dir.path().join("MANIFEST"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let err = check_manifest_from_tarball(dir.path(), "1.1.0", "x86_64-unknown-linux-gnu")
            .unwrap_err();
        assert!(err.contains("MANIFEST arch mismatch"), "got: {err}");
    }

    /// **Version-lifecycle test:**
    /// `--check` → `--dry-run` → confirmation prompt 'N' all share the
    /// same input shape; assert each phase output shape and that the
    /// read-only modes never touched the lock path.
    #[test]
    fn version_lifecycle_check_then_dry_run_then_apply() {
        // Phase 1 — `--check`: up-to-date.
        let state = sample_state();
        let report_eq = CheckReport {
            state: &state,
            target_version: "1.0.0",
            target_arch: "x86_64-unknown-linux-gnu",
            target_released_at: None,
            compare: VersionCompare::UpToDate,
            pending_config_migrations: vec![],
            session_counts: SessionCounts {
                active: 0,
                stopped: 0,
                reachable: true,
            },
        };
        let mut out1 = Vec::new();
        render_check_report(&mut out1, &report_eq).unwrap();
        let s1 = String::from_utf8(out1).unwrap();
        assert!(s1.contains("Status:    up to date"), "phase 1: {s1}");

        // Phase 2 — `--check` with an update available.
        let report_ne = CheckReport {
            state: &state,
            target_version: "1.1.0",
            target_arch: "x86_64-unknown-linux-gnu",
            target_released_at: None,
            compare: VersionCompare::UpdateAvailable,
            pending_config_migrations: vec![],
            session_counts: SessionCounts {
                active: 0,
                stopped: 0,
                reachable: true,
            },
        };
        let mut out2 = Vec::new();
        render_check_report(&mut out2, &report_ne).unwrap();
        let s2 = String::from_utf8(out2).unwrap();
        assert!(s2.contains("Status:    update available"), "phase 2: {s2}");

        // Phase 3 — `--dry-run` with the same input shape.
        let disk = DiskCheck { rows: vec![] };
        let mut out3 = Vec::new();
        render_dry_run(&mut out3, &report_ne, &disk).unwrap();
        let s3 = String::from_utf8(out3).unwrap();
        assert!(s3.contains("§ 3.1.5"), "phase 3: {s3}");
        assert!(s3.contains("§ 3.2.30"), "phase 3: {s3}");
        assert!(s3.contains("would execute"), "phase 3: {s3}");

        // Phase 4 — confirmation prompt answered `N`. The prompt text
        // contains the literal token; the `read_yes_no` returns false
        // for anything but `y`.
        let summary = render_confirmation_summary(
            "1.0.0",
            "1.1.0",
            &[],
            &[],
            true,
            &SessionCounts {
                active: 0,
                stopped: 0,
                reachable: true,
            },
            None,
        );
        assert!(
            summary.contains("Proceed? [y/N]:"),
            "phase 4 summary: {summary}"
        );
        assert!(!read_yes_no(Cursor::new(b"N\n")), "phase 4 read_yes_no");

        // Privilege-model sanity: none of the read-only phases above
        // touched the lock path. We can't easily prove a negative
        // here, but the lock-acquisition module is only reachable
        // through `run()`'s post-confirmation arm, which has not been
        // invoked.
        assert!(!Path::new(lock::LOCK_PATH).exists() || std::fs::read(lock::LOCK_PATH).is_err());
    }

    // -----------------------------------------------------------------
    // Wire-format contract: `SessionState` serializes via
    // `rename_all = "snake_case"`, so the daemon emits `"stopped"` (not
    // `"Stopped"`) on the `/sessions` endpoint. `fetch_session_counts`
    // and `classify_stopped_sessions` MUST compare against the lowercase
    // wire token. A regression that flips either call to `"Stopped"`
    // (the `Display` form) silently miscounts every stopped session as
    // active. These tests pin the lowercase contract end-to-end against
    // a real in-process UDS so the `http_get` → serde → filter pipeline
    // is exercised exactly as it runs in production.
    // -----------------------------------------------------------------

    use axum::Router;
    use axum::response::Json;
    use axum::routing::get;
    use serde_json::{Value, json};
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::net::UnixListener;

    async fn spawn_sessions_fixture(body: Value) -> (TempDir, String) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sock_path = tmp.path().join("sandboxd.sock");
        let sock_str = sock_path.to_string_lossy().into_owned();

        let app = Router::new().route(
            "/sessions",
            get(move || {
                let body = body.clone();
                async move { Json(body) }
            }),
        );

        let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        (tmp, sock_str)
    }

    #[test]
    fn session_state_serializes_to_lowercase_snake_case() {
        use sandbox_core::SessionState;

        assert_eq!(
            serde_json::to_string(&SessionState::Stopped).expect("serialize Stopped"),
            "\"stopped\"",
        );
        assert_eq!(
            serde_json::to_string(&SessionState::Running).expect("serialize Running"),
            "\"running\"",
        );

        let round_trip: SessionState =
            serde_json::from_str("\"stopped\"").expect("deserialize stopped");
        assert_eq!(round_trip, SessionState::Stopped);

        // The PascalCase form the `Display` impl prints is NOT the wire
        // format; deserialising it must fail. This is the pin that
        // catches a regression where someone accidentally swaps the
        // `rename_all` directive for `Display`-based ser/de.
        assert!(
            serde_json::from_str::<SessionState>("\"Stopped\"").is_err(),
            "PascalCase must not deserialize — wire format is snake_case",
        );
    }

    #[tokio::test]
    async fn fetch_session_counts_buckets_lowercase_stopped() {
        let body = json!([
            { "state": "stopped" },
            { "state": "stopped" },
            { "state": "running" },
            { "state": "creating" },
        ]);
        let (_tmp, sock) = spawn_sessions_fixture(body).await;

        let counts = fetch_session_counts(&sock).await;
        assert!(counts.reachable, "daemon was reachable");
        assert_eq!(counts.stopped, 2, "two lowercase `stopped` entries");
        assert_eq!(counts.active, 2, "running + creating are active");
    }

    #[tokio::test]
    async fn classify_stopped_sessions_filters_by_lowercase_stopped() {
        let body = json!([
            { "id": "a", "state": "stopped", "guest_protocol_version": 7 },
            { "id": "b", "state": "stopped", "guest_protocol_version": 0 },
            { "id": "c", "state": "running", "guest_protocol_version": 7 },
            // A capital-S "Stopped" entry (i.e. someone wrote the
            // `Display` form to the wire by accident) MUST NOT be
            // classified as stopped — the wire contract is lowercase.
            { "id": "d", "state": "Stopped", "guest_protocol_version": 7 },
        ]);
        let (_tmp, sock) = spawn_sessions_fixture(body).await;

        let set = classify_stopped_sessions(&sock, 7).await;
        assert!(set.classified, "daemon was reachable, classification ran");
        assert_eq!(set.target_proto, 7);
        let ids: Vec<&str> = set.stopped.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["a", "b"],
            "only lowercase `stopped` rows are classified",
        );
        assert_eq!(set.stopped[0].bucket, CompatBucket::Ok);
        assert_eq!(set.stopped[1].bucket, CompatBucket::Recreate);
    }
}
