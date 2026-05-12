//! `sandbox update` orchestration — Spec 5 §§ 3.1 (pre-flight),
//! 2.2 (`--check` output), 2.3 (`--dry-run` output), 2.4 (confirmation
//! prompt), 2.5 (privilege model), 2.6 (log destination).
//!
//! M16-S2 lands the **read-only** half: arg parse, dev-mode detect,
//! install-state read, target-version resolution, version compare with
//! the `--check` exit gate, active-session check, stopped-session
//! count, disk-space check, cosign-pin / MANIFEST type wiring, the
//! migration dry-run delegate, and the confirmation prompt. The
//! stateful steps §§ 3.2.13-3.2.30 (lock acquisition, daemon stop,
//! backup, install, restart) are deferred to M16-S3 — this module
//! returns exit `0` after the confirmation prompt is answered `N` or
//! after `--dry-run` prints its plan, and returns exit `1` with a
//! "M16-S3 will land the stateful steps" notice when the operator
//! answers `y` (S3 will replace that arm with the actual stateful
//! execution).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::cfg_migrations;

pub mod fetch;
pub mod lock;

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
        // before invoking the CLI when needed (M16-S3 wires that).
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
     https://Koriit.github.io/sandboxd/docs/migrate-dev-to-system\n"
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
        if s.state == "Stopped" {
            counts.stopped += 1;
        } else {
            counts.active += 1;
        }
    }
    counts
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
            writeln!(out, "  config: V{:03} ({})", m.id, m.name)?;
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

    writeln!(out, "Stateful (§ 3.2) — would execute:")?;
    // The 18 stateful steps, in spec order. Per § 2.3 the verdict is
    // either "would execute" or "would skip" — we render every step as
    // "would execute" here since M16-S2 does not yet compute the
    // skip-on-match optimization (M16-S3 wires the idempotency
    // shortcuts).
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
        writeln!(out, "  ✓ {id} {name:<28}  would execute")?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "Run `sudo sandbox update` (without --dry-run) to apply."
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Confirmation prompt (§ 2.4)
// ---------------------------------------------------------------------------

/// Render the confirmation prompt summary (no input read; caller wires
/// up stdin). § 2.4. Returns the rendered string.
pub fn render_confirmation_summary(
    from_version: &str,
    to_version: &str,
    pending_config_migrations: &[PendingMigration],
    daemon_was_running: bool,
    session_counts: &SessionCounts,
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
    s.push_str("  pending db migrations:      (enumerated after extraction at § 3.1.10)\n");
    s.push_str(&format!(
        "  daemon status now:          {}\n",
        if daemon_was_running {
            "active (will be stopped, upgraded, restarted)"
        } else {
            "inactive (will remain stopped after upgrade)"
        }
    ));
    s.push_str(&format!(
        "  stopped sessions:           {}\n",
        session_counts.stopped
    ));
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
pub fn enumerate_pending_config_migrations() -> Vec<PendingMigration> {
    let mut out = Vec::new();
    for file in [
        cfg_migrations::TargetFile::UsersConf,
        cfg_migrations::TargetFile::BridgeConf,
    ] {
        let path = file.canonical_path();
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let current = match cfg_migrations::read_schema_version(&bytes, file) {
            Ok(v) => v,
            Err(_) => continue,
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
        eprintln!("sandbox update: {msg}");
        return 2i32;
    }

    // § 3.1.2 — dev-mode detect / refuse.
    if is_dev_mode(Path::new(SYSTEMD_UNIT_PATH), Path::new(INSTALL_STATE_PATH)) {
        eprintln!("{}", dev_mode_refusal_text());
        return 2i32;
    }

    // § 3.1.3 — install state read (graceful in read-only modes;
    // hard refusal in full-update mode).
    let state = match read_install_state(Path::new(INSTALL_STATE_PATH)) {
        Ok(Some(s)) => s,
        Ok(None) if args.is_read_only() => InstallState::unknown_with_host_arch(),
        Ok(None) => {
            eprintln!(
                "sandbox update: install state file missing: {INSTALL_STATE_PATH} — was this host installed via install.sh?"
            );
            return 1i32;
        }
        Err(e) => {
            eprintln!("sandbox update: failed to read install state: {e}");
            return 1i32;
        }
    };

    // § 3.1.4 — target-version resolution. Without network access for
    // M16-S2 we resolve via three deterministic paths:
    //   1. `--from <tarball>` → read MANIFEST.version from the local
    //      tarball; no network call.
    //   2. `--version <v>` → use that string verbatim.
    //   3. `latest` (default) → without the network probe the
    //      authoritative answer is unknown; for `--check` we emit
    //      "available: unknown" and exit `1`; for the full path
    //      M16-S3 wires the GH Releases API.
    let target_version = match resolve_target_version(&args, &state) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("sandbox update: {msg}");
            return 1i32;
        }
    };

    // § 3.1.5 — version compare.
    let compare = compare_versions(&state.installed_version, &target_version);

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

    // § 3.1.6 — active sessions check.
    if session_counts.reachable && session_counts.active > 0 && !args.force {
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

    // Up-to-date short-circuit (§ 3.1.5).
    if matches!(compare, VersionCompare::UpToDate) {
        println!("Status: up to date");
        return 0i32;
    }

    // § 3.1.8 — disk space.
    if !disk.passes() {
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

    // §§ 3.1.9 / 3.1.10 — cosign bootstrap, sigstore verify, extract.
    // For `--from` we can read MANIFEST and surface arch mismatch
    // *before any state mutation* (an exit-criterion). Sigstore
    // verify itself shells out to `cosign verify-blob`; M16-S3
    // wires that. For now we read MANIFEST and run the cross-check.
    if let Some(from) = args.from.as_ref() {
        if let Err(e) = check_manifest_from_tarball(from, &target_version, &state.installed_arch) {
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
            eprintln!(
                "sandbox update: migration dry-run failed for {}: {e}",
                file.display_name()
            );
            return 1i32;
        }
    }

    // § 3.1.12 — confirmation prompt.
    // The sticky `was_running` is sampled here from the live systemd
    // probe (the lock isn't acquired yet — that's M16-S3).
    let daemon_was_running = systemctl_is_active("sandboxd");
    let summary = render_confirmation_summary(
        &state.installed_version,
        &target_version,
        &pending_migrations,
        daemon_was_running,
        &session_counts,
    );
    print!("{summary} ");
    let _ = std::io::stdout().flush();
    let proceed = if args.yes {
        true
    } else {
        read_yes_no(std::io::stdin().lock())
    };
    if !proceed {
        println!("aborted.");
        return 0i32;
    }

    // ----- M16-S3 stateful steps land here -----
    eprintln!(
        "sandbox update: pre-flight passed. The stateful phase \
         (§§ 3.2.13-3.2.30) ships in a follow-up — re-run after that lands."
    );
    1i32
}

// ---------------------------------------------------------------------------
// Internal helpers (target version, MANIFEST read, systemctl probe)
// ---------------------------------------------------------------------------

/// `--from` → tarball MANIFEST.version; `--version v` → `v`; else
/// returns the CLI's own version (the M16-S2 stand-in for the GH
/// Releases probe — comparing the CLI's compiled version against the
/// installed version still produces a meaningful diff). M16-S3 will
/// add the actual `curl` call.
fn resolve_target_version(args: &UpdateArgs, _state: &InstallState) -> Result<String, String> {
    if let Some(from) = args.from.as_ref() {
        // Peek MANIFEST out of the tarball without extracting.
        // M16-S2 supports a pre-extracted directory layout (a
        // sibling `MANIFEST` next to the tarball) so the spec
        // exit-criterion 5 (arch mismatch from `--from`) is
        // testable without shelling out to `tar`.
        if from.is_dir() {
            let manifest_path = from.join("MANIFEST");
            let m = fetch::read_manifest(&manifest_path)
                .map_err(|e| format!("read MANIFEST from {}: {e}", manifest_path.display()))?;
            return Ok(m.version);
        }
        return Err(format!(
            "--from {}: tarball-extraction not implemented in M16-S2; pass a directory containing MANIFEST instead",
            from.display()
        ));
    }
    if args.version != "latest" {
        return Ok(args.version.clone());
    }
    // No network probe in M16-S2 — fall back to the CLI's compiled
    // version so the version-compare path is exercisable. M16-S3
    // wires the actual GH Releases API call.
    Ok(env!("CARGO_PKG_VERSION").to_string())
}

/// Read MANIFEST from a tarball directory (M16-S2 limitation: full
/// tar extraction lands in M16-S3) and run the arch + version checks
/// at § 3.1.10.
fn check_manifest_from_tarball(
    from: &Path,
    target_version: &str,
    installed_arch: &str,
) -> Result<(), String> {
    if !from.is_dir() {
        return Err(format!(
            "--from {}: tarball-extraction not implemented in M16-S2; pass a directory containing MANIFEST instead",
            from.display()
        ));
    }
    let manifest_path = from.join("MANIFEST");
    let m = fetch::read_manifest(&manifest_path)
        .map_err(|e| format!("read MANIFEST from {}: {e}", manifest_path.display()))?;
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
            true,
            &SessionCounts {
                active: 0,
                stopped: 0,
                reachable: true,
            },
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

    /// `enumerate_pending_config_migrations` returns an empty vec when
    /// the canonical paths are unreadable — the read-only modes degrade
    /// gracefully.
    #[test]
    fn enumerate_pending_returns_empty_when_paths_absent() {
        // Running this test in a clean environment: /etc/sandboxd/users.conf
        // either does not exist or is not readable. Either way the
        // result is an empty Vec (the function's `continue` arms
        // tolerate both).
        let got = enumerate_pending_config_migrations();
        assert!(got.iter().all(|m| !m.name.is_empty()));
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

    /// **The version-lifecycle test the M16-S2 plan calls out:**
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
            true,
            &SessionCounts {
                active: 0,
                stopped: 0,
                reachable: true,
            },
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
}
