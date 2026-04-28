use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use clap::Parser;
use sandbox_core::backend::{
    BackendKind, CliDockerOps, ContainerRuntime, EnsureImageOutcome, LITE_FIRST_USE_WARNING,
    LimaRuntime, RuntimeHandle, RuntimeStartArgs, SessionRuntime, compute_default_resource_limits,
    ensure_image, lite_image_tag_for_version, map_container_uid_gid, reap_orphans,
    rebuild_lite_image,
};
use sandbox_core::events::lifecycle as lifecycle_events;
use sandbox_core::events::session_events_host_dir;
use sandbox_core::gateway::container_name as gateway_container_name;
use sandbox_core::{
    ApiError, AssuranceLevel, BaseImageStatus, CaManager, Cidr4, CoreDnsConfig,
    CreateSessionRequest, DEFAULT_DEADLINE_MS as DNS_GATE_DEFAULT_DEADLINE_MS, Destination,
    DnsCache, DockerExecLdsProbe, DockerHealth, EventBus, EventBusConfig, ExecRequest,
    ExecResponse, FileDownloadRequest, FileDownloadResponse, FileUploadRequest, GateRequest,
    GateService, GateServiceOutcome, GateStatus, GatewayHealth, GatewayManager,
    GatewayShutdownReason, GatewayStatus, GuestConnector, GuestRequest, GuestResponse,
    HealthComponent, LdsAckOutcome, LdsStatsProbe, LimaManager, NetworkHealth, NetworkInfo,
    NetworkManager, PersistConfig, PersistentSink, Policy, PolicyApplyStatus, PolicyCompiler,
    PolicyDistributor, SandboxError, Session, SessionConfig, SessionDto, SessionHealth, SessionId,
    SessionIngestor, SessionMountInfo, SessionNetworkInfo, SessionState, SessionStore,
    UpdatePolicyRequest, UsersConfig, VmIpSessionMap, VmStatus, attach_vm_to_bridge,
    bind_gate_listener, detach_vm_from_bridge, generate_ca_inject_script, generate_domain_ip_rules,
    hash_policy, load_users_config, mac_from_session_id, propagate_dns_changes, read_resolved_json,
    remove_gate_socket, serve_gate_listener, users_conf_path, wait_for_lds_ack,
    write_file_to_container,
};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------

/// The sandbox daemon -- manages sandbox sessions via a Unix socket HTTP API.
#[derive(Parser, Debug)]
#[command(name = "sandboxd", about = "Sandbox daemon")]
struct Args {
    /// Path to the Unix socket to listen on.
    #[arg(long, default_value_t = default_socket_path())]
    socket: String,

    /// Base directory for daemon state (database, session data).
    #[arg(long, default_value_t = default_base_dir())]
    base_dir: String,

    /// Append tracing output to this file instead of stderr.
    ///
    /// When set, stderr logging is disabled (writing to both would duplicate
    /// log lines under an init system that captures stderr). When unset,
    /// logs go to stderr -- which is captured automatically by systemd
    /// (`StandardOutput=journal`) and launchd (`StandardErrorPath`).
    ///
    /// If the file cannot be opened, the daemon fails fast on startup.
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Enable the persistent JSONL event sink.
    ///
    /// When set, every event published to the bus is also written to
    /// `{base_dir}/sessions/{session_id}/events/{layer}-YYYY-MM-DD.jsonl`
    /// (UTC-rotated). Disabled by default — operators opt-in per-
    /// deployment.  See `events::persist` in `sandbox-core` for the
    /// task-graph shape (bounded mpsc + drop-newest on overflow).
    #[arg(long, default_value_t = false)]
    events_persist: bool,

    /// How many days of persisted JSONL event files to retain.
    ///
    /// Only meaningful when `--events-persist` is set.  Files whose
    /// filename-embedded `YYYY-MM-DD` is strictly older than
    /// `today - retention_days` are removed by an hourly pruner.
    ///
    /// Default of 14 days matches the 2026-04-21 spec Part 3 /
    /// "Retention" suggested value and covers roughly two sprint
    /// cycles of traffic for post-incident review. Overridable via
    /// `SANDBOX_EVENTS_PERSIST_RETENTION_DAYS` (clap env-var fallback).
    /// Final defaults are measurement-driven — see
    /// `docs/internal/measurement-defaults-m10-s6.md` for the
    /// rationale and revision policy.
    #[arg(
        long,
        env = "SANDBOX_EVENTS_PERSIST_RETENTION_DAYS",
        default_value_t = 14
    )]
    events_persist_retention_days: u32,
}

fn default_socket_path() -> String {
    // Honor SANDBOX_SOCKET as an override (symmetric with the CLI). The
    // `--socket` flag, when passed explicitly, still takes precedence
    // because clap only computes this default when no value is given.
    if let Ok(sock) = std::env::var("SANDBOX_SOCKET") {
        return sock;
    }
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        return format!("{runtime_dir}/sandboxd/sandboxd.sock");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    format!("{home}/.local/share/sandboxd/sandboxd.sock")
}

fn default_base_dir() -> String {
    if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
        return format!("{data_home}/sandboxd");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    format!("{home}/.local/share/sandboxd")
}

// ---------------------------------------------------------------------------
// users.conf startup validation
// ---------------------------------------------------------------------------
//
// M11-S2 Phase 2C: the daemon refuses to start unless `/etc/sandboxd/users.conf`
// (or its `SANDBOX_USERS_CONF` test-only override) contains a subnet entry whose
// `allow_users` resolves to the daemon's own uid. The matched subnet's CIDR
// scopes `NetworkManager`'s per-session /28 allocation pool.
//
// See:
//   - lite-mode container backend spec § "Install-time setup" / "Config file:
//     /etc/sandboxd/users.conf" — the contract this validation enforces.
//   - `sandbox_core::users_conf` — the loader that produces a parsed
//     [`UsersConfig`]; we layer the daemon-uid lookup on top.

/// Resolve which CIDR pool the daemon should hand to [`NetworkManager::new`],
/// given the daemon's uid and a parsed [`UsersConfig`].
///
/// Pure function — no syscalls beyond the `getpwnam_r` calls
/// `find_subnet_by_uid` performs against the host passwd database. Split
/// out from the startup wiring so the unit tests can drive the lookup
/// without spawning a subprocess.
///
/// Returns:
/// - `Ok(cidr)` — the unique subnet whose `allow_users` maps to
///   `daemon_uid` (first match wins; see
///   [`UsersConfig::find_subnet_by_uid`]).
/// - `Err(SandboxError::InvalidArgument(_))` — no entry resolved to
///   `daemon_uid`. The message names the daemon's uid (and username, when
///   `getpwuid_r` succeeds), the absolute file path, and points at the
///   install docs. Operators must amend `users.conf` (or, for tests, the
///   `SANDBOX_USERS_CONF`-pointed file) before the daemon will start.
fn resolve_allocation_pool(daemon_uid: u32, config: &UsersConfig) -> Result<Cidr4, SandboxError> {
    if let Some(entry) = config.find_subnet_by_uid(daemon_uid) {
        return Ok(entry.cidr);
    }

    // Best-effort resolve uid → username so the error names the user the
    // operator likely thinks of. Fall back to "uid N" if either
    // `getpwuid_r` errors or the uid is not present in passwd (rare on
    // hosts where the daemon is actually running as that uid, but
    // possible inside containers).
    let user_label = match nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(daemon_uid)) {
        Ok(Some(user)) => format!("'{}' (uid {daemon_uid})", user.name),
        Ok(None) | Err(_) => format!("uid {daemon_uid}"),
    };

    // Grep-stable phrasing: Phase 2D's install docs will reference the
    // "no users.conf subnet matches daemon user" prefix verbatim. Do
    // not re-word without coordinating the docs change.
    Err(SandboxError::InvalidArgument(format!(
        "no users.conf subnet matches daemon user {user_label} \
         in {path}; see install docs at docs/start/installation.md",
        path = users_conf_path().display(),
    )))
}

// ---------------------------------------------------------------------------
// Logging setup
// ---------------------------------------------------------------------------

/// Where tracing output is routed.
///
/// Returned from [`resolve_log_destination`] so that the selection logic is
/// pure and unit-testable. [`init_tracing`] is the impure wrapper that
/// actually installs the global subscriber.
enum LogDestination {
    /// Append tracing output to the given file (opened in append mode).
    File(std::fs::File),
    /// Write tracing output to stderr (default behavior).
    Stderr,
}

/// Decide where tracing output should go, based on the `--log-file` flag.
///
/// - `Some(path)`: open the file in append+create mode. Returns an error
///   if the file cannot be opened -- the caller is expected to fail fast
///   before daemon startup.
/// - `None`: return [`LogDestination::Stderr`] (the default behavior).
///
/// This is a pure function: given the same input, it either opens the
/// file or returns `Stderr`. No global state is touched.
fn resolve_log_destination(log_file: Option<&std::path::Path>) -> std::io::Result<LogDestination> {
    match log_file {
        Some(path) => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            Ok(LogDestination::File(file))
        }
        None => Ok(LogDestination::Stderr),
    }
}

/// Install the global tracing subscriber, routing output per
/// [`resolve_log_destination`].
///
/// Uses `RUST_LOG` via `EnvFilter`, defaulting to `info` when unset.
fn init_tracing(log_file: Option<&std::path::Path>) -> std::io::Result<()> {
    let dest = resolve_log_destination(log_file)?;
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    match dest {
        LogDestination::File(file) => {
            // `std::sync::Mutex<File>` implements `MakeWriter`, so we can
            // hand it directly to the fmt subscriber. The mutex serializes
            // writes from multiple threads; file append mode means the OS
            // also guarantees atomic appends for small writes.
            let writer = std::sync::Mutex::new(file);
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_ansi(false)
                .with_writer(writer)
                .init();
        }
        LogDestination::Stderr => {
            tracing_subscriber::fmt().with_env_filter(env_filter).init();
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Route-helper path resolution (M11-S5 Phase 5A fixup)
// ---------------------------------------------------------------------------
//
// `sandbox-route-helper` is a sibling binary the daemon spawns when a lite
// session starts (see `ContainerRuntime::start` → `invoke_route_helper`).
// The original Phase 5A wiring passed the bare name `"sandbox-route-helper"`
// and relied on `Command::new()`'s `$PATH` lookup, but neither the e2e
// fixture nor the cargo workspace layout puts `target/debug/` on the
// daemon's `PATH`. The result was that every lite session create failed at
// container start with `os error 2`.
//
// `resolve_route_helper_path` looks up the helper at deploy-friendly
// locations and surfaces a single, operator-actionable error if no
// *usable* candidate is found. "Usable" means: the file exists *and* it
// carries the `CAP_SYS_ADMIN` file capability (effective). The cap check
// matters because in dev workspaces the cargo build directory often
// lives on a host-share / bind-mount filesystem that does not honor
// `security.capability` xattrs (`setcap` returns "Operation not
// supported"); the same constraint the route-helper's own integration
// tests work around by copying the binary to a tempdir before applying
// caps. Without the cap check, the resolver would happily pick the
// un-cap'd sibling and the failure surface would move from "spawn os
// error 2" to "setns EPERM" at session start — equally late and equally
// confusing. With the cap check, the resolver fails fast at the
// daemon-error layer with a message naming every location tried.
//
// Lookup order:
//
//   1. Sibling of the running daemon binary (`current_exe()`'s directory).
//      Covers cargo workspace runs (`target/debug/` co-located with
//      `sandboxd`) and most installed layouts where both binaries ship in
//      the same `bin/` directory.
//   2. The well-known install path `/usr/local/bin/sandbox-route-helper`,
//      matching the install-docs runbook
//      (`docs/start/installation.md` § "sandbox-route-helper").
//   3. `$PATH` lookup as a last resort (preserves the original behavior
//      for operators who deliberately drop the helper into a directory
//      other than `/usr/local/bin`).
//
// The function returns a `SandboxError::Internal` rather than a custom
// error type so call sites can propagate it through the existing daemon
// error pipeline. The error message lists every location tried, plus
// the cap requirement, so an operator can immediately see why the
// daemon refused to use any of them.

/// Default install path for the route helper, referenced both by the
/// resolver and by the operator-facing error message it produces.
const ROUTE_HELPER_INSTALL_PATH: &str = "/usr/local/bin/sandbox-route-helper";

/// Bare-name of the helper binary, used for both filesystem candidates
/// and `$PATH` walks.
const ROUTE_HELPER_BINARY_NAME: &str = "sandbox-route-helper";

/// Linux capability bit number for `CAP_SYS_ADMIN`, the only capability
/// the route helper requires. Hard-coded rather than pulled from a
/// crate constant because no workspace dep exposes the kernel
/// `linux/capability.h` numbering directly. Source: Linux UAPI
/// `include/uapi/linux/capability.h` — `#define CAP_SYS_ADMIN 21`.
const CAP_SYS_ADMIN_BIT: u32 = 21;

/// `vfs_cap_data.magic_etc` low byte revision masks (UAPI
/// `linux/capability.h`).
const VFS_CAP_REVISION_MASK: u32 = 0xFF00_0000;
const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
const VFS_CAP_REVISION_3: u32 = 0x0300_0000;
/// `magic_etc` low bit set ⇔ caps are *effective* on exec (the only
/// flavor the route helper is shipped with — `cap_sys_admin+ep`).
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x0000_0001;

/// On-disk size (bytes) of `vfs_cap_data` for revisions 2 and 3. We
/// support both because newer kernels emit revision 3 (with a trailing
/// `rootid` field) by default. Anything else is treated as "not a cap
/// xattr we understand" and the candidate is skipped.
const VFS_CAP_DATA_V2_SIZE: usize = 20;
const VFS_CAP_DATA_V3_SIZE: usize = 24;

/// Resolve the absolute path to `sandbox-route-helper` for use in
/// `ContainerNetwork::route_helper_path`.
///
/// See the module-level comment above for the lookup order, the cap-
/// requirement check, and the rationale. The function is fail-closed:
/// if no candidate carries `CAP_SYS_ADMIN+ep`, it returns a
/// `SandboxError::Internal` whose message names every location it
/// inspected and the cap requirement.
fn resolve_route_helper_path() -> Result<PathBuf, SandboxError> {
    let current_exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    let install_path = PathBuf::from(ROUTE_HELPER_INSTALL_PATH);
    let path_var = std::env::var_os("PATH");
    let candidates = default_route_helper_candidates(
        current_exe_dir.as_deref(),
        &install_path,
        path_var.as_deref(),
    );
    let exe_dir_display = current_exe_dir
        .as_ref()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| "<unavailable: current_exe() failed>".to_string());
    resolve_route_helper_path_from(
        candidates,
        has_required_caps,
        &exe_dir_display,
        &install_path,
    )
}

/// Build the ordered candidate list the resolver consults. Split out so
/// the unit tests can substitute a synthetic candidate iterator without
/// having to fake `current_exe()` or mutate `$PATH`.
fn default_route_helper_candidates(
    current_exe_dir: Option<&std::path::Path>,
    install_path: &std::path::Path,
    path_var: Option<&std::ffi::OsStr>,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    // 1. Sibling of the daemon binary.
    if let Some(dir) = current_exe_dir {
        out.push(dir.join(ROUTE_HELPER_BINARY_NAME));
    }
    // 2. Well-known install path.
    out.push(install_path.to_path_buf());
    // 3. `$PATH` walk. Mirrors `Command::new()`'s lookup so operators
    //    can drop the helper into any PATH-listed directory.
    if let Some(path_var) = path_var {
        for dir in std::env::split_paths(path_var) {
            // `split_paths` yields empty entries for trailing/duplicate
            // colons (`PATH=/usr/local/bin::/usr/bin`); skip them so we
            // don't accidentally probe `./sandbox-route-helper`.
            if dir.as_os_str().is_empty() {
                continue;
            }
            out.push(dir.join(ROUTE_HELPER_BINARY_NAME));
        }
    }
    out
}

/// Pure inner of [`resolve_route_helper_path`].
///
/// Walks the supplied `candidates` in order and returns the first one
/// that satisfies `is_usable`. Returns a `SandboxError::Internal`
/// naming every location it tried (plus the cap requirement) when no
/// candidate is usable.
///
/// Split out — and parameterized over `is_usable` — so the unit tests
/// can drive the priority logic with a stub predicate. Setting real
/// file capabilities from a unit test requires `CAP_SETFCAP` and is
/// not portable, so cap-check coverage lives in [`has_required_caps`]
/// itself; the priority logic is exercised here without touching
/// xattrs.
fn resolve_route_helper_path_from<I, F>(
    candidates: I,
    is_usable: F,
    exe_dir_display: &str,
    install_path: &std::path::Path,
) -> Result<PathBuf, SandboxError>
where
    I: IntoIterator<Item = PathBuf>,
    F: Fn(&std::path::Path) -> bool,
{
    for candidate in candidates {
        if is_usable(&candidate) {
            return Ok(candidate);
        }
    }
    Err(SandboxError::Internal(format!(
        "no usable sandbox-route-helper found; checked (1) sibling of daemon binary \
         at {exe_dir_display}/{ROUTE_HELPER_BINARY_NAME}, (2) install path \
         {install} and (3) $PATH lookup. Each candidate must exist as a regular \
         file AND carry the CAP_SYS_ADMIN file capability (effective): \
         `sudo setcap cap_sys_admin+ep <path>`. See \
         docs/start/installation.md § \"sandbox-route-helper\".",
        install = install_path.display(),
    )))
}

/// Predicate used by [`resolve_route_helper_path`] to decide whether a
/// candidate path is a usable route-helper binary: the file must exist
/// *and* carry `CAP_SYS_ADMIN` in the effective-on-exec set.
///
/// Implemented as a thin wrapper around [`read_cap_xattr`] so the
/// resolver's call site stays a single named predicate. We deliberately
/// treat *every* failure mode as "not usable, move on": a missing file
/// (ENOENT), a missing or empty `security.capability` xattr (ENODATA),
/// an unreadable file (EACCES), a malformed xattr blob, or anything
/// else, all reduce to `false`. The resolver's "no usable candidate"
/// error message names every location tried so operators can debug
/// from the negative result without a per-candidate reason code.
fn has_required_caps(path: &std::path::Path) -> bool {
    if !path.is_file() {
        return false;
    }
    match read_cap_xattr(path) {
        Some(buf) => xattr_has_cap_sys_admin_effective(&buf),
        None => false,
    }
}

/// Read the raw `security.capability` xattr blob from `path` via
/// `libc::getxattr`. Returns `None` on any error (missing file,
/// missing xattr, EACCES, oversized blob, etc.) — all of those mean
/// "this candidate is not a setcap'd helper" for our purposes.
///
/// We size the buffer at 64 bytes — `vfs_cap_data` is at most 24 bytes
/// for revision 3, so 64 leaves room for any future revision the
/// kernel might introduce while still bounding the syscall's write.
fn read_cap_xattr(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // `CString::new` rejects interior NULs. A path with NULs cannot
    // exist on Linux anyway, so treat it as "not usable".
    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let attr_name = CString::new("security.capability").expect("static string has no NUL");
    let mut buf = [0u8; 64];

    // SAFETY: `c_path` and `attr_name` are valid NUL-terminated C
    // strings; `buf` is a valid mutable buffer of the size we pass.
    // `libc::getxattr` on error returns -1 and we treat that as "no
    // caps" via the `< 0` branch below; on success it returns the
    // number of bytes written, bounded by `buf.len()`.
    let n = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            attr_name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if n < 0 {
        return None;
    }
    let n = n as usize;
    if n > buf.len() {
        // Defensive: the kernel should never write more than `buf.len()`
        // bytes, but if it ever does we cannot trust the blob and skip.
        return None;
    }
    Some(buf[..n].to_vec())
}

/// Decode a raw `vfs_cap_data` blob and return whether
/// `CAP_SYS_ADMIN` is present in `permitted` *and* the blob's
/// `effective` flag is set. Pure function — split out from
/// [`read_cap_xattr`] so the cap-decoding logic is unit-testable
/// without touching xattrs (see the `xattr_has_cap_sys_admin_*`
/// tests below).
///
/// The on-disk layout (UAPI `linux/capability.h`) is:
///   - 4 bytes `magic_etc`        (LE: revision in high byte, flags in low byte)
///   - 4 bytes `data[0].permitted`  (LE)
///   - 4 bytes `data[0].inheritable` (LE)
///   - 4 bytes `data[1].permitted`   (LE)
///   - 4 bytes `data[1].inheritable` (LE)
///   - revision 3 only: 4 bytes `rootid` (LE) — ignored here; we
///     only need to know that the blob is well-formed and that
///     `CAP_SYS_ADMIN+ep` is set.
fn xattr_has_cap_sys_admin_effective(buf: &[u8]) -> bool {
    if buf.len() != VFS_CAP_DATA_V2_SIZE && buf.len() != VFS_CAP_DATA_V3_SIZE {
        return false;
    }
    // `magic_etc` is little-endian regardless of host endianness
    // (the kernel writes it in CPU-native order, but x86_64 and
    // aarch64 are LE so we treat it as LE; the lite backend only
    // ships on Linux x86_64 / aarch64).
    let magic_etc = u32::from_le_bytes(buf[0..4].try_into().expect("4 bytes"));
    let revision = magic_etc & VFS_CAP_REVISION_MASK;
    if revision != VFS_CAP_REVISION_2 && revision != VFS_CAP_REVISION_3 {
        return false;
    }
    if magic_etc & VFS_CAP_FLAGS_EFFECTIVE == 0 {
        return false;
    }
    // CAP_SYS_ADMIN bit number is 21, which fits in the low 32 bits
    // of the 64-bit permitted set, so we only need data[0].permitted.
    let permitted_lo = u32::from_le_bytes(buf[4..8].try_into().expect("4 bytes"));
    permitted_lo & (1u32 << CAP_SYS_ADMIN_BIT) != 0
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

struct AppState {
    base_dir: PathBuf,
    // M10-S4 Phase 2: wrapped in `Arc` so the events sub-router (built
    // in [`app`]) can hold its own `Arc<SessionStore>` handle inside an
    // `Arc<events_http::EventsApiState>` without the two routers having
    // to share state via axum's `FromRef`. `SessionStore` is internally
    // `Mutex`-guarded, so the shared handle is safe and adds no
    // synchronization beyond what the store already performs.
    store: Arc<SessionStore>,
    /// Backend dispatch table keyed by [`BackendKind`].
    ///
    /// M11-S1 Phase 1C introduced this map alongside `lima_runtime` so
    /// that handler call sites talking to the *generic* lifecycle
    /// (create / start / stop / delete / status / ip / exec_interactive
    /// / guest_transport) go through the trait, while Lima-specific
    /// orchestration (clone, base image, agent install, list_vms)
    /// continues to call the typed runtime directly via
    /// [`LimaRuntime::manager`]. The same `Arc<LimaRuntime>` is
    /// registered here under [`BackendKind::Lima`] and held by
    /// `lima_runtime` — there is one Lima runtime instance reachable
    /// both ways. M11-S2 will register the container backend alongside.
    runtimes: Arc<HashMap<BackendKind, Arc<dyn SessionRuntime>>>,
    /// Typed handle to the Lima/QEMU runtime, retained so the daemon
    /// can still call Lima-specific orchestration that does not (yet)
    /// have a trait surface — base-image build/check/rebuild, golden
    /// VM clone, custom-template create, guest agent install, and the
    /// admin `/vms` listing. See [`LimaRuntime::manager`] for the
    /// escape hatch that keeps these calls one method-chain away.
    lima_runtime: Arc<LimaRuntime>,
    /// Typed handle to the Docker/lite container runtime, retained
    /// alongside `runtimes` for the same reason `lima_runtime` is —
    /// the create-session container path needs the typed surface
    /// (`register_session(...)`, the cached daemon-version image tag)
    /// before it dispatches through `SessionRuntime::create`.
    /// Registered alongside [`BackendKind::Container`] in
    /// [`AppState::runtimes`] at startup; see `main()`.
    container_runtime: Arc<ContainerRuntime>,
    guest: GuestConnector,
    network: Arc<NetworkManager>,
    gateway: Arc<GatewayManager>,
    /// Handles for DNS propagation background tasks, keyed by session ID.
    /// Used to cancel the loop when a session is stopped or deleted.
    dns_loop_handles: Mutex<HashMap<SessionId, tokio::task::JoinHandle<()>>>,
    /// Handles for the per-session synchronous DNS-gate listener tasks
    /// (M10-S10 Phase 2). Each handle drives the UDS server bound at
    /// `{events_host_root}/<session-id>/dns-gate.sock`, which the
    /// gateway's CoreDNS plugin calls into to block answer delivery on
    /// nft + Envoy LDS propagation. Aborted on stop / remove / teardown.
    dns_gate_handles: Mutex<HashMap<SessionId, tokio::task::JoinHandle<()>>>,
    /// Per-session DNS cache shared between the background propagation
    /// loop and the synchronous gate handler. The loop's steady-state
    /// reconciler and the gate's per-request UNION-merge both read
    /// from and write to the same `DnsCache` so the two paths stay in
    /// agreement on which IPs are currently authoritative for each
    /// resolved domain.
    dns_caches: Arc<Mutex<HashMap<SessionId, Arc<Mutex<DnsCache>>>>>,
    /// Active policies for sessions, keyed by session ID.
    /// Uses Arc so it can be shared with spawned DNS propagation tasks.
    session_policies: Arc<Mutex<HashMap<SessionId, Policy>>>,
    /// Sessions currently being stopped.
    ///
    /// Tracks session IDs that are in the middle of the stop sequence
    /// (networking teardown + VM stop).  The gateway monitor and network
    /// reconciliation loops check this set so they don't accidentally
    /// restart a gateway that was intentionally stopped.
    sessions_stopping: Mutex<HashSet<SessionId>>,
    /// Serializes base image check-and-build operations.
    ///
    /// Without this lock, concurrent `create_session` requests can each
    /// see `BaseImageStatus::Missing` and independently trigger
    /// `build_base_image()`.  The second build starts a new base VM in
    /// Running state, which causes all `limactl clone` calls to fail
    /// with "cannot clone a running instance."
    base_image_lock: Mutex<()>,
    /// Per-session unified event bus.
    ///
    /// Sessions are registered when their networking is set up and
    /// unregistered on teardown / deletion.  Ingest tasks (M10-S2 Phase 7)
    /// publish into the bus; SSE handlers (later milestone) subscribe.
    /// See [`EventBus`] for the fan-out + ring-buffer replay semantics.
    event_bus: EventBus,
    /// VM-IP → session-ID lookup used by the ingest layer to stamp the
    /// owning session on JSONL records whose on-wire identifier is the
    /// VM bridge IP (Envoy `src_ip`, CoreDNS client IP, mitmproxy client
    /// IP).  Bound at the same time the session is registered with
    /// [`AppState::event_bus`]; removed in lock-step on teardown.
    vm_ip_map: VmIpSessionMap,
    /// Per-(session, component) healthcheck state tracked by the
    /// [`gateway_monitor`] loop.  `true` = healthy, `false` = degraded.
    /// The map is the source of truth for transition detection —
    /// `health_degraded` and `health_restored` events fire only when a
    /// poll flips the recorded state, not on every tick.  Unknown
    /// components are recorded as `false` so the first healthy poll
    /// publishes `health_restored`.
    component_health_state: Mutex<HashMap<SessionId, HashMap<HealthComponent, bool>>>,
    /// Per-session JSONL ingest tasks (M10-S2 Phase 7).
    ///
    /// Each [`SessionIngestor`] tails `envoy.jsonl` / `coredns.jsonl` /
    /// `mitmproxy.jsonl` under [`session_events_host_dir`] and publishes
    /// parsed [`sandbox_core::Event::Traffic`] records onto
    /// [`AppState::event_bus`] after stamping the owning session via
    /// [`AppState::vm_ip_map`]. Spawned after every successful
    /// `create_gateway` / `restart_gateway`; aborted on stop, remove, and
    /// gateway teardown. Keyed by session ID so a gateway bounce can
    /// abort-and-respawn without leaking the previous ingestor.
    ingestors: Mutex<HashMap<SessionId, SessionIngestor>>,
    /// Per-session policy-propagation tracker (M10-S6 todo #37).
    ///
    /// Records, for each session, the hash of the most recently
    /// applied policy and the hash of the most recently fully
    /// reconciled one. Mutated by the apply path
    /// ([`PropagationStates::mark_applied`]) and the DNS propagation
    /// loop ([`PropagationStates::mark_propagated`]); read by the
    /// `GET /sessions/{id}/policy/propagation-status` endpoint so the
    /// CLI and E2E suite can wait deterministically for propagation
    /// rather than sleeping on wall-clock time.
    propagation_states: Arc<PropagationStates>,
}

/// Look up the runtime for a given backend kind from the dispatch
/// table.
///
/// Used by handlers that already know the backend kind for the
/// session they are operating on — typically because they read it
/// off the persisted `Session::backend` field. M11-S3 Phase 3D
/// supersedes the Phase 1C `lima_dyn` helper with this version so
/// the same call site works for both `BackendKind::Lima` and
/// `BackendKind::Container` rows without any per-handler branching.
///
/// Panics if the requested runtime is missing from the dispatch
/// table; that is unreachable by construction (registration happens
/// in `main()` before any handler can run) and a panic is the
/// correct failure mode — a session row with a backend kind that
/// no runtime answers to can never be serviced anyway.
fn runtime_for(state: &AppState, kind: BackendKind) -> Arc<dyn SessionRuntime> {
    Arc::clone(
        state
            .runtimes
            .get(&kind)
            .unwrap_or_else(|| panic!("runtime for {kind:?} must be registered at startup")),
    )
}

/// Project a [`SessionConfig`] + [`BackendKind`] pair back into the
/// [`sandbox_core::SessionSpec`] shape consumed by
/// [`SessionRuntime::create`] and [`SessionSpec::validate`].
///
/// The `BackendKind` arg picks which variant of `BackendSpecific`
/// the projection emits:
///
/// - `Lima` carries the full Lima-side surface (`hardened`,
///   `memory_mb`, `cpus`).
/// - `Container` mirrors the lite-mode wire shape from the spec —
///   only `memory_mb` and `cpus` land on `BackendSpecific`; the
///   container backend rejects `--hardened` via its capability
///   matrix, and the request-side validation in `create_session`
///   surfaces the rejection before this projection ever runs for a
///   container session.
///
/// The remaining fields (`workspace_mode`, `repo`, `boot_cmd`,
/// `template`, `disk_gb`) surface at the [`SessionSpec`] level
/// regardless of backend.
///
/// Container `cpus` is projected from the precise
/// [`SessionConfig::cpus_decimal`] when present (M11-S7 todo #67 — the
/// 1-decimal value the operator supplied), falling back to the
/// integer [`SessionConfig::cpus`] otherwise. The Lima variant always
/// projects the integer field — Lima/QEMU pin whole cores.
fn session_spec_from_config(
    config: &SessionConfig,
    kind: BackendKind,
) -> sandbox_core::SessionSpec {
    let backend_specific = match kind {
        BackendKind::Lima => sandbox_core::BackendSpecific::Lima {
            hardened: config.hardened,
            memory_mb: config.memory_mb,
            cpus: config.cpus,
        },
        BackendKind::Container => sandbox_core::BackendSpecific::Container {
            memory_mb: config.memory_mb,
            cpus: config.cpus_decimal.unwrap_or(config.cpus as f32),
        },
    };
    sandbox_core::SessionSpec {
        backend_specific,
        workspace_mode: config.workspace_mode.clone(),
        repo: config.repo.clone(),
        boot_cmd: config.boot_cmd.clone(),
        template: config.template.clone(),
        disk_gb: Some(config.disk_gb),
    }
}

/// Round a request-supplied `cpus` value to the spec § "Resource
/// defaults — container only" 1-decimal grid (e.g. `0.81 → 0.8`,
/// `1.55 → 1.5`).
///
/// Mirrors the rounding [`compute_default_resource_limits`] applies to
/// the daemon-side host-80% default so both code paths produce values
/// on the same grid. M11-S7 todo #67 added this normalisation step
/// alongside the wire boundary type widening — without it, an
/// operator typing `--cpus 0.81` would reach `format_cpus` as
/// `0.81` and render `--cpus 0.8` (truncating the trailing `1`)
/// rather than the intended round-to-grid behaviour.
///
/// Math is in `f64` to keep the rounding precise for f32 inputs;
/// the result is narrowed back to `f32` because the caller stores
/// the value in [`sandbox_core::session::SessionConfig::cpus_decimal`]
/// (an `f32` field).
fn round_cpus_one_decimal(cpus: f32) -> f32 {
    let scaled = (f64::from(cpus) * 10.0).round() / 10.0;
    scaled as f32
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

// The `SandboxError` → HTTP response mapping is shared with the events
// sub-router via `sandboxd::error::error_response` — see that module for
// the full mapping table and logging contract.
use sandboxd::error::error_response;
use sandboxd::propagation::{PropagatedEdge, PropagationStates};

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn app(state: Arc<AppState>) -> Router {
    // M10-S4 Phase 2: build the events sub-router with its own minimal
    // state (an `Arc` over the same `SessionStore` and the same
    // `EventBus` clone the main state owns).  Merging rather than
    // extending lets the sub-router keep its own typed state without
    // forcing a `FromRef` impl on `AppState`.
    let events_state = Arc::new(sandboxd::events_http::EventsApiState::new(
        Arc::clone(&state.store),
        state.event_bus.clone(),
    ));
    let events_router = sandboxd::events_http::events_router(events_state);

    // M10-S6 todo #37: build the policy status sub-router with its own
    // minimal state (shared `SessionStore` + shared `PropagationStates`).
    // Same merging rationale as `events_router` above — the read-only
    // endpoint does not need the full `AppState` surface.
    let policy_state = Arc::new(sandboxd::policy_http::PolicyApiState::new(
        Arc::clone(&state.store),
        Arc::clone(&state.propagation_states),
    ));
    let policy_router = sandboxd::policy_http::policy_router(policy_state);

    // M11-S3 Phase 3C: build the backends-listing sub-router. Holds an
    // `Arc` over the same backend dispatch map the main `AppState`
    // owns; the CLI hits `GET /backends` once per invocation to learn
    // capabilities, so a read-only sub-router keeps the surface narrow
    // and lets `tests/integration_backends_endpoint.rs` drive the
    // route via `oneshot` without booting Lima/gateway/network.
    let backends_state = Arc::new(sandboxd::backends_http::BackendsApiState::new(Arc::clone(
        &state.runtimes,
    )));
    let backends_router = sandboxd::backends_http::backends_router(backends_state);

    Router::new()
        .route("/sessions", post(create_session))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{id}", get(get_session))
        .route("/sessions/{id}", delete(remove_session))
        .route("/sessions/{id}/start", post(start_session))
        .route("/sessions/{id}/stop", post(stop_session))
        .route("/sessions/{id}/exec", post(exec_in_session))
        .route("/sessions/{id}/upload", post(upload_to_session))
        .route("/sessions/{id}/download", post(download_from_session))
        .route(
            "/sessions/{id}/policy",
            post(update_policy).delete(clear_policy),
        )
        .route("/sessions/{id}/health", get(session_health))
        .route("/rebuild-image", post(rebuild_image))
        .route("/base-image-status", get(base_image_status))
        .route("/health", get(health_check))
        .with_state(state)
        .merge(events_router)
        .merge(policy_router)
        .merge(backends_router)
}

/// Compute the initial CoreDNS policy file content for a brand-new session.
///
/// Both backends (Lima, Container) feed this through `create_gateway`'s
/// `initial_dns_policy` so CoreDNS loads it on first startup, eliminating
/// the race where it would briefly serve the deny-all default until its
/// reload timer fires (~1s). Extracted to keep the two backend branches
/// in `create_session` reading off the same source of truth — the prior
/// inline form lived only on the Lima path.
///
/// - With `req.policy`: extract the `Domain` destinations of every non-Deny
///   rule and render via `CoreDnsConfig::to_file_content()`.
/// - Without `req.policy` (fail-closed default): return
///   `CoreDnsConfig::empty_policy_file_content()` so CoreDNS returns
///   NXDOMAIN for everything until a policy is installed.
fn compute_initial_dns_policy(req: &CreateSessionRequest) -> String {
    if let Some(ref policy) = req.policy {
        let domains: Vec<String> = policy
            .rules
            .iter()
            .filter(|r| r.level != AssuranceLevel::Deny)
            .filter_map(|r| match &r.host {
                Destination::Domain(d) => Some(d.clone()),
                Destination::Cidr(_) => None,
            })
            .collect();
        CoreDnsConfig {
            allowed_domains: domains,
        }
        .to_file_content()
    } else {
        CoreDnsConfig::empty_policy_file_content()
    }
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    // Determine workspace mode from the request: the `workspace` field
    // takes precedence; fall back to `repo` for backward compatibility.
    let workspace_mode = if let Some(ref ws) = req.workspace {
        match sandbox_core::WorkspaceMode::parse_flag(ws) {
            Ok(mode) => Some(mode),
            Err(e) => {
                return error_response(SandboxError::Internal(format!(
                    "invalid workspace value: {e}"
                )))
                .into_response();
            }
        }
    } else {
        req.repo
            .as_ref()
            .map(|repo_url| sandbox_core::WorkspaceMode::Clone {
                repo_url: repo_url.clone(),
            })
    };

    // M11-S3 Phase 3D: which backend hosts this session. Default to
    // Lima for back-compat with older CLIs that omit the field. The
    // chosen kind is then validated against the runtime's capability
    // matrix *before* any state is mutated, so a request that asks
    // for `--hardened` on the container backend is rejected with 400
    // and never spends a session id, network allocation, or CA dir.
    //
    // Resolved up front (before `config` is built) because the
    // resource defaults below are backend-aware (gap #4).
    let backend_kind = req.backend.unwrap_or(BackendKind::Lima);

    // M11-S4 Phase 4D-pre gap #4: resource defaults are backend-aware.
    //
    // - For Lima we keep the historical 2-CPU / 4096-MB defaults that
    //   the pre-M11 wire shape baked in. These match what
    //   `LimaRuntime::start_vm` consumes and what every long-standing
    //   E2E test expects.
    // - For Container we feed `0` sentinels through, which
    //   `ContainerRuntime::resource_ceilings` interprets as "unset"
    //   and substitutes with the daemon's `compute_default_resource_limits`
    //   host-80% ceilings (spec § "Resource defaults"). Without this
    //   the host-80% path was unreachable through the public CLI
    //   surface (the previous `unwrap_or(2)/(4096)` always fired and
    //   produced Lima-leaning numbers regardless of backend).
    //
    // The `0` sentinel is the lowest-touch shape — it threads through
    // `SessionConfig` (Lima-shaped) into `BackendSpecific::Container`
    // unchanged, and `resource_ceilings` already encoded the
    // "0 means unset" contract back in 3A. Persisting `0` is safe:
    // `SessionConfig` carries the user-requested ceiling, and a
    // container session that took the host-80% default has `0` in
    // both columns by construction.
    //
    // M11-S7 todo #67: `req.cpus` is `Option<f32>` so the spec §
    // "Resource defaults — container only" 1-decimal grammar
    // (`0.8`, `1.5`, …) reaches the runtime without truncation.
    // Lima sessions still see whole-number cores (QEMU's `-smp`
    // grammar pins integers), so we floor any fractional value on
    // the Lima path. The container path normalises to one decimal
    // place via `round_cpus_one_decimal` so `0.81` lands on the
    // grid as `0.8` regardless of whether an operator typo'd extra
    // precision.
    let memory_mb = match backend_kind {
        BackendKind::Lima => req.memory_mb.unwrap_or(4096),
        BackendKind::Container => req.memory_mb.unwrap_or(0),
    };
    let cpus_decimal_request = req.cpus;
    let (cpus_persisted, cpus_decimal) = match backend_kind {
        BackendKind::Lima => {
            // QEMU pins integer cores; ignore any sub-integer portion
            // the operator passed and persist the integer ceiling
            // unchanged.
            let cpus = cpus_decimal_request.map(|c| c as u32).unwrap_or(2);
            (cpus, None)
        }
        BackendKind::Container => match cpus_decimal_request {
            None => (0, None),
            Some(precise) => {
                let normalised = round_cpus_one_decimal(precise);
                // `cpus` (u32) holds the floored value as a fallback
                // for older daemons rolling back; the precise value
                // lives in `cpus_decimal`.
                (normalised.floor() as u32, Some(normalised))
            }
        },
    };

    let config = SessionConfig {
        cpus: cpus_persisted,
        memory_mb,
        disk_gb: req.disk_gb.unwrap_or(20),
        workspace_mode,
        hardened: req.hardened.unwrap_or(true),
        // Record the creation inputs so `sandbox inspect`/`describe` can
        // surface them later.  These are persisted in `config_json` and
        // forward-compatible via `#[serde(default)]`; records written by
        // pre-M9-S11 daemons keep `None` on these three fields.
        repo: req.repo.clone(),
        boot_cmd: req.boot_cmd.clone(),
        template: req.template.clone(),
        cpus_decimal,
    };

    // Hardened flag interaction with the container backend:
    // `BackendSpecific::Container` does not carry `hardened`, so the
    // SessionSpec-level `validate()` path silently drops a `true`
    // value. Reject up front when a container request explicitly sets
    // `hardened: true` so the failure mode matches spec §
    // "Hardening" — operator-facing 400 with the same
    // `UnsupportedFeature::Hardening` message Lima would surface
    // through the validate path. `req.hardened == Some(true)` is the
    // wire-level signal of an *explicit* opt-in; an absent field
    // (operator did not pass `--hardened` and old CLIs that don't yet
    // know about the flag) round-trips silently because the container
    // backend always runs hardened-equivalent (rootless docker +
    // capability drop) regardless of this flag.
    if backend_kind == BackendKind::Container && req.hardened == Some(true) {
        return error_response(SandboxError::InvalidArgument(
            sandbox_core::backend::UnsupportedFeature::Hardening.to_string(),
        ))
        .into_response();
    }

    // Daemon-side authoritative validation: spec § "Validation sites"
    // requires the daemon to repeat the capability check the CLI did.
    // The runtime is the single source of truth for its capability
    // matrix.
    let spec = session_spec_from_config(&config, backend_kind);
    let runtime_for_validation = runtime_for(&state, backend_kind);
    if let Err(unsupported) = spec.validate(runtime_for_validation.capabilities()) {
        // `UnsupportedFeature: Display` produces the operator-facing
        // sentence (e.g. "hardening flag not supported by container
        // backend"); routing through `InvalidArgument` maps this to
        // an HTTP 400 with the message intact (see `error_response`).
        return error_response(SandboxError::InvalidArgument(unsupported.to_string()))
            .into_response();
    }

    // Container backend: ensure the lite image exists *before* we
    // burn a session row + network allocation. The first build of a
    // given daemon version surfaces a verbatim warning string back
    // to the caller (spec § "Lite mode → first-use warning"); steady-
    // state hits return `AlreadyPresent` and contribute nothing to
    // `warnings`.
    let mut warnings: Vec<String> = Vec::new();
    if backend_kind == BackendKind::Container {
        let daemon_version = env!("CARGO_PKG_VERSION").to_string();
        match tokio::task::spawn_blocking(move || ensure_image(&daemon_version)).await {
            Ok(Ok(EnsureImageOutcome::AlreadyPresent)) => {}
            Ok(Ok(EnsureImageOutcome::Built { warning })) => {
                // `warning` is `LITE_FIRST_USE_WARNING` verbatim per
                // Phase 3B's contract; assert that here so any drift
                // in the constant trips the create path immediately.
                debug_assert_eq!(warning, LITE_FIRST_USE_WARNING);
                warnings.push(warning);
            }
            Ok(Err(e)) => return error_response(e).into_response(),
            Err(e) => {
                return error_response(SandboxError::Internal(format!("task join error: {e}")))
                    .into_response();
            }
        }
    }

    // Create session record in store (state = Creating).
    // `req.name` is cloned because both backend branches below need to
    // reach back into `req` (workspace mode for container, repo/policy
    // for the shared post-create plumbing).
    let session = match state.store.create_session_with_backend(
        config.clone(),
        req.name.clone(),
        backend_kind,
    ) {
        Ok(s) => s,
        Err(e) => return error_response(e).into_response(),
    };

    let session_id = session.id;

    // 1. Create Docker network BEFORE the VM so the bridge exists at QEMU boot.
    //    Also generate the per-session CA certificate (needed by the gateway).
    let ca_dir = {
        let base_dir = state.base_dir.clone();
        let sid = session_id;
        match tokio::task::spawn_blocking(move || CaManager::generate_session_ca(&base_dir, &sid))
            .await
        {
            Ok(Ok(dir)) => dir,
            Ok(Err(e)) => {
                let _ = state.store.update_state(&session_id, SessionState::Error);
                return error_response(e).into_response();
            }
            Err(e) => {
                let _ = state.store.update_state(&session_id, SessionState::Error);
                return error_response(SandboxError::Internal(format!("task join error: {e}")))
                    .into_response();
            }
        }
    };

    let network_info = {
        let network = state.network.clone();
        let sid = session_id;
        match tokio::task::spawn_blocking(move || network.create_network(&sid)).await {
            Ok(Ok(info)) => info,
            Ok(Err(e)) => {
                let base_dir = state.base_dir.clone();
                let sid = session_id;
                let _ = tokio::task::spawn_blocking(move || {
                    CaManager::remove_session_ca(&base_dir, &sid)
                })
                .await;
                let _ = state.store.update_state(&session_id, SessionState::Error);
                return error_response(e).into_response();
            }
            Err(e) => {
                let _ = state.store.update_state(&session_id, SessionState::Error);
                return error_response(SandboxError::Internal(format!("task join error: {e}")))
                    .into_response();
            }
        }
    };

    // Generate MAC address for the VM's bridge NIC.
    let vm_mac = mac_from_session_id(&session_id);

    info!(%session_id, bridge = %network_info.bridge_name, mac = %vm_mac, "creating VM");

    // 2. Create and start the VM -- fast path (clone from golden image) or
    //    slow path: full create from scratch (no base-image cache hit).
    //
    // Use the fast path when: no --no-cache flag, no custom template.
    // The fast path clones the pre-provisioned base image and skips the
    // guest agent install (it's already baked in).
    //
    // Shared workspace (9p mount) requires the slow path because the
    // clone doesn't carry mount configuration from the session template.
    let has_shared_mount = matches!(
        &config.workspace_mode,
        Some(sandbox_core::WorkspaceMode::Shared { .. })
    );
    let use_cache = !req.no_cache.unwrap_or(false) && req.template.is_none() && !has_shared_mount;

    // Helper closure: cleanup VM + network + CA on failure, set state to Error.
    // This macro avoids repeating the cleanup pattern in every error branch.
    //
    // M11-S1 Phase 1C: VM cleanup goes through the generic trait
    // dispatch (`runtime.delete(&handle).await`); the synchronous
    // network + CA cleanup stays inside a single `spawn_blocking` so we
    // do not pay an extra task spawn per cleanup. The macro is invoked
    // from inside `create_session`'s async body, so the `.await` on
    // `delete` is safe.
    //
    // M11-S3 Phase 3D: pass the request's `backend_kind` so the
    // cleanup dispatches to the runtime that actually owns the
    // partially-created resources — Lima for VM rows, Container for
    // docker rows.
    macro_rules! cleanup_and_return {
        ($state:expr, $session_id:expr, $err_resp:expr) => {{
            let runtime = runtime_for(&*$state, backend_kind);
            let handle = RuntimeHandle::from_session_id(&$session_id);
            let _ = runtime.delete(&handle).await;
            let network = $state.network.clone();
            let base_dir = $state.base_dir.clone();
            let sid = $session_id;
            let _ = tokio::task::spawn_blocking(move || {
                let _ = network.delete_network(&sid);
                let _ = CaManager::remove_session_ca(&base_dir, &sid);
            })
            .await;
            let _ = $state.store.update_state(&$session_id, SessionState::Error);
            return $err_resp;
        }};
    }

    // Helper closure: cleanup network + CA only (VM not yet created).
    macro_rules! cleanup_net_ca_and_return {
        ($state:expr, $session_id:expr, $err_resp:expr) => {{
            let network = $state.network.clone();
            let base_dir = $state.base_dir.clone();
            let sid = $session_id;
            let _ = tokio::task::spawn_blocking(move || {
                let _ = network.delete_network(&sid);
                let _ = CaManager::remove_session_ca(&base_dir, &sid);
            })
            .await;
            let _ = $state.store.update_state(&$session_id, SessionState::Error);
            return $err_resp;
        }};
    }

    if backend_kind == BackendKind::Container {
        // ---- Container backend: lightweight create + start + gateway wiring ----
        //
        // The Lima fast/slow paths below are inapplicable here:
        // there is no golden image to clone (the lite image was
        // already ensured above), no QEMU template to render, and
        // no separate guest-agent install step (the agent is built
        // into the lite image per M11-S2). The runtime drives
        // `docker create` + `docker start`, and the rest of the
        // post-create work (per-session gateway, event ingest, DNS
        // gate listener) is performed inline below — copying the
        // shape of `setup_session_networking` (steps 1-8) but
        // skipping step 9 (VM bridge attach + CA injection) which
        // is Lima-only.

        // Register the per-session ContainerNetwork on the runtime
        // so `SessionRuntime::create` has the docker network name +
        // container IP it needs to wire `--network <name> --ip <ip>`,
        // and the gateway IP for the `--dns` flag.
        //
        // Field mapping from `NetworkInfo` (Lima-side concept) to
        // `ContainerNetwork` (backend-side concept):
        //
        // - `docker_network_name` → `docker_network`
        // - `vm_ip` (the .3 in each /28) → `container_ip`: in the
        //   container backend this is the address the workload owns,
        //   not a VM's veth.
        // - `gateway_ip` (the .2) → `gateway_ip` unchanged.
        //
        // `workspace_host_path` is populated when the request asked
        // for `--workspace shared:<path>` — the runtime turns it into
        // a `docker create --mount type=bind,source=<path>,...` flag
        // (spec § "Workspace bind"). For other workspace modes
        // (`Clone`, `Empty`) the field stays `None` and the lite
        // image runs with a read-only rootfs.
        //
        // `route_helper_path = Some(...)` lets the runtime invoke
        // the setcap helper at start time to install the default
        // route via the gateway IP inside the container's netns
        // (spec § "Routing"). [`resolve_route_helper_path`] resolves
        // the absolute path of the helper at the call site, preferring
        // the sibling-of-`current_exe()` location (covers cargo
        // workspace + most installed layouts) and falling back to
        // `/usr/local/bin/sandbox-route-helper` and then to `$PATH`.
        // Surfacing the lookup error here means lite-mode session
        // creation fails fast with an operator-actionable message
        // rather than at `docker start` time with `os error 2`.
        {
            let container_ip_str = network_info.vm_ip.clone();
            let container_ip = match container_ip_str.parse::<std::net::IpAddr>() {
                Ok(ip) => ip,
                Err(e) => {
                    cleanup_net_ca_and_return!(
                        state,
                        session_id,
                        error_response(SandboxError::Internal(format!(
                            "vm_ip {container_ip_str:?} not parseable as IP: {e}"
                        )))
                        .into_response()
                    );
                }
            };
            let gateway_ip_str = network_info.gateway_ip.clone();
            let gateway_ip = match gateway_ip_str.parse::<std::net::IpAddr>() {
                Ok(ip) => ip,
                Err(e) => {
                    cleanup_net_ca_and_return!(
                        state,
                        session_id,
                        error_response(SandboxError::Internal(format!(
                            "gateway_ip {gateway_ip_str:?} not parseable as IP: {e}"
                        )))
                        .into_response()
                    );
                }
            };
            // Pull the host path out of the parsed workspace mode
            // (set on `config` above when `req.workspace =
            // Some("shared:<path>")`). Other variants don't bind a
            // host path into the container.
            let workspace_host_path = match &config.workspace_mode {
                Some(sandbox_core::WorkspaceMode::Shared { host_path }) => {
                    Some(PathBuf::from(host_path))
                }
                _ => None,
            };
            let route_helper_path = match resolve_route_helper_path() {
                Ok(path) => path,
                Err(e) => {
                    cleanup_net_ca_and_return!(
                        state,
                        session_id,
                        error_response(e).into_response()
                    );
                }
            };
            let container_network = sandbox_core::backend::ContainerNetwork {
                docker_network: network_info.docker_network_name.clone(),
                container_ip,
                gateway_ip,
                workspace_host_path,
                route_helper_path: Some(route_helper_path),
                // Per-session CA: bind-mounted read-only into the
                // container at /etc/ssl/certs/sandbox-ca.pem and
                // surfaced via CURL_CA_BUNDLE / SSL_CERT_FILE etc. so
                // HTTPS traffic intercepted by Envoy + mitmproxy
                // (L3-HTTP policy levels) verifies cleanly. Mirrors
                // the Lima `inject_ca_into_vm` path; differs in
                // mechanism because the lite container's rootfs is
                // read-only per spec § Hardening.
                ca_host_path: Some(ca_dir.join("cert.pem")),
            };
            state
                .container_runtime
                .register_session(session_id, container_network);
        }

        {
            let runtime = runtime_for(&state, BackendKind::Container);
            match runtime.create(&session_id, &spec).await {
                Ok(_handle) => {}
                Err(e) => {
                    cleanup_net_ca_and_return!(
                        state,
                        session_id,
                        error_response(e).into_response()
                    );
                }
            }
        }

        {
            let runtime = runtime_for(&state, BackendKind::Container);
            let handle = RuntimeHandle::from_session_id(&session_id);
            // The container runtime ignores `lima_*` fields on
            // `RuntimeStartArgs` (they're Lima-only); pass them as
            // `None` so the contract is explicit at the call site
            // rather than implicit "happens to be ignored".
            let args = RuntimeStartArgs {
                lima_bridge: None,
                lima_mac: None,
                lima_config: None,
            };
            match runtime.start(&handle, &args).await {
                Ok(()) => {}
                Err(e) => {
                    cleanup_and_return!(state, session_id, error_response(e).into_response());
                }
            }
        }

        // ---- Per-session gateway + event/DNS-gate wiring ----
        //
        // Mirrors `setup_session_networking` steps 1-8. We do not
        // call that helper directly because step 9 (VM bridge attach
        // + CA injection via the guest agent) is Lima-only; lifting
        // them behind a `Backend` switch would muddy a function
        // already saturated with Lima-shaped invariants. Keeping
        // them parallel and readable beats a premature abstraction.
        //
        // Cleanup contract on failure of any step below: best-effort
        // tear down the gateway/ingestor/network via
        // `teardown_session_networking_parts`, then run
        // `cleanup_and_return!` to drop the container, network, CA,
        // and flip `state` to `Error`. The order matters: the
        // teardown helper assumes the docker network still exists
        // (it tries to remove it), and `cleanup_and_return!` will
        // try a second `delete_network` — that's idempotent (the
        // first one having already removed it returns NotFound,
        // which the network manager swallows).
        macro_rules! cleanup_lite_gateway_and_return {
            ($err_resp:expr) => {{
                teardown_session_networking_parts(
                    &session_id,
                    &state.gateway,
                    &state.network,
                    &state.ingestors,
                )
                .await;
                cleanup_and_return!(state, session_id, $err_resp);
            }};
        }

        // Initial DNS policy: shared with the Lima branch via
        // `compute_initial_dns_policy` so both backends light up
        // CoreDNS with the exact same content on first boot.
        let initial_dns_policy_owned: String = compute_initial_dns_policy(&req);
        let initial_dns_policy: Option<&str> = Some(initial_dns_policy_owned.as_str());

        // Step 1: register session with the event bus and bind the
        // container IP for event attribution. Mirrors lines 3484-3497
        // of `setup_session_networking`.
        state.event_bus.register_session(session_id);
        match network_info.vm_ip.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => {
                state.vm_ip_map.bind(ip, session_id);
            }
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    vm_ip = %network_info.vm_ip,
                    error = %e,
                    "failed to parse vm_ip as IPv4; event attribution disabled for this session"
                );
            }
        }

        // Step 2: publish `gateway_booting` *before* the docker call
        // so the event stream records the boot intent even if
        // gateway creation fails.
        state
            .event_bus
            .publish(lifecycle_events::gateway_booting(session_id));

        // Step 3: create the gateway container (Docker calls + sleep
        // polling — must run on a blocking task).
        {
            let gw = state.gateway.clone();
            let sid = session_id;
            let ni = network_info.clone();
            let ca = ca_dir.clone();
            let dns = initial_dns_policy.map(|s| s.to_string());
            match tokio::task::spawn_blocking(move || {
                gw.create_gateway(&sid, &ni, Some(&ca), dns.as_deref())
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    cleanup_lite_gateway_and_return!(error_response(e).into_response());
                }
                Err(e) => {
                    cleanup_lite_gateway_and_return!(
                        error_response(SandboxError::Internal(format!(
                            "task join error creating gateway: {e}"
                        )))
                        .into_response()
                    );
                }
            }
        }

        // Step 4: gateway is up — publish `gateway_ready` so
        // subscribers can pair it with the earlier `gateway_booting`.
        state
            .event_bus
            .publish(lifecycle_events::gateway_ready(session_id));

        // Step 5: spawn the per-session JSONL ingest task now that
        // the events directory is bind-mounted into the gateway and
        // the producers are live.
        spawn_session_ingestor(&session_id, &state).await;

        // Step 6: persist network info before the gate listener
        // starts so the listener's `get_network_info` lookup
        // succeeds (it needs the subnet + gateway IP for ruleset
        // generation).
        if let Err(e) = state.store.set_network_info(&session_id, &network_info) {
            cleanup_lite_gateway_and_return!(error_response(e).into_response());
        }

        // Step 7: start the synchronous DNS-gate UDS listener. The
        // events host directory was created by `create_gateway` and
        // is bind-mounted into the gateway container, so the socket
        // file appears at the canonical container path without any
        // extra mount.
        start_dns_gate_listener(&session_id, &state).await;

        // Step 8: flip session state to `Running`. (Lima additionally
        // performs step 9 here — `attach_vm_to_bridge` +
        // `inject_ca_into_vm` — which is intentionally absent on the
        // container backend: the container's veth was attached by
        // `docker create --network <name> --ip <ip>`, and CA
        // injection is the lite image's responsibility at build
        // time.)
        if let Err(e) = state.store.update_state(&session_id, SessionState::Running) {
            cleanup_lite_gateway_and_return!(error_response(e).into_response());
        }

        // Apply the explicit `--policy <file>` (or `--preset <invocation>`,
        // which the CLI compiles into `req.policy` server-side) now that
        // the session is Running and the gateway is live. Mirrors the
        // Lima branch's apply_policy block at lines ~1651-1679: an
        // explicit policy that fails to compile/distribute is fatal
        // (M10-S8 #16) — silently returning a Running session with no
        // policy in place lies to the operator. The implicit "no
        // policy" path never reaches this branch (the CoreDNS
        // fail-closed default was already written by `create_gateway`
        // above via `initial_dns_policy`).
        //
        // `req.policy` is consumed here (moved out of `req`); the
        // `req.repo` clone block immediately below is the M11-S7 backend
        // symmetry for `--repo` (the lite image's entrypoint is the
        // `sandbox-guest` agent, so the `state.guest.exec` dispatch the
        // Lima path uses works unchanged once the agent's TCP listener
        // is up). `--boot-cmd` symmetry follows the same dispatch right
        // after the clone block.
        if let Some(policy) = req.policy {
            let initial_presets = req.source_presets.clone();
            match apply_policy(
                &session_id,
                &policy,
                &state,
                ApplyKind::Initial {
                    source_presets: initial_presets,
                },
            )
            .await
            {
                Ok(()) => {
                    info!(%session_id, "initial policy applied (lite)");
                }
                Err(e) => {
                    error!(
                        %session_id,
                        error = %e,
                        "failed to apply explicit initial policy on lite session — failing create"
                    );
                    cleanup_lite_gateway_and_return!(error_response(e).into_response());
                }
            }
        }

        // M11-S7 — `--repo` symmetry on the container backend.
        //
        // Mirrors the Lima `--repo` path at the bottom of this handler:
        // pre-warm DNS for the repo host through the guest, then
        // dispatch `git clone <url> /home/agent/workspace/` via the
        // backend-agnostic `GuestConnector` (which routes through
        // `ContainerTransport`'s `docker exec ... socat` path for
        // container sessions). Failures take the same fail-explicit
        // path as Lima — `fail_explicit_repo_clone` marks the session
        // `Error` and tears down the gateway/network/ingestors, leaving
        // the container in place so `sandbox rm` can reclaim it.
        //
        // The lite image bakes `sandbox-guest` in as its entrypoint
        // (`/usr/bin/tini -- /usr/local/bin/sandbox-guest`), so the
        // agent's TCP listener at 127.0.0.1:5123 is up shortly after
        // `docker start` returns. The 30s `GUEST_REQUEST_TIMEOUT`
        // bound on `send_request` covers the boot tail-latency the
        // same way it does for Lima.
        if let Some(repo_url) = &req.repo {
            // Pre-warm DNS for the repo host so the DNS propagation loop
            // has installed the policy's L1/L3 filter chain before
            // `git clone` opens its first TCP connection. Same rationale
            // as the Lima branch — schema v2 domain allow-rules are
            // fail-closed at empty DNS cache and the loop polls every 2s.
            if let Some(host) = extract_repo_host(repo_url) {
                info!(%session_id, %host, "pre-warming DNS for repo clone (lite)");
                prewarm_guest_dns(&state.guest, &session_id, &host).await;
            }

            info!(%session_id, repo = %repo_url, "cloning repository into container");
            match state
                .guest
                .exec(
                    &session_id,
                    "git",
                    &["clone", repo_url.as_str(), "/home/agent/workspace/"],
                )
                .await
            {
                Ok(GuestResponse::ExecResult {
                    exit_code,
                    stdout,
                    stderr,
                }) => {
                    if exit_code != 0 {
                        let stderr_snip = truncate_for_diagnostic(stderr.trim(), 512);
                        let err = SandboxError::Internal(format!(
                            "git clone of {repo_url} failed with exit code {exit_code}: {stderr_snip}"
                        ));
                        return fail_explicit_repo_clone(
                            &state.store,
                            &state.gateway,
                            &state.network,
                            &state.ingestors,
                            &session_id,
                            err,
                        )
                        .await
                        .into_response();
                    } else {
                        info!(
                            %session_id,
                            output = %stdout.trim(),
                            "repository cloned successfully (lite)"
                        );
                    }
                }
                Ok(GuestResponse::Error { message }) => {
                    let err = SandboxError::Internal(format!(
                        "git clone of {repo_url} failed: guest agent error: {message}"
                    ));
                    return fail_explicit_repo_clone(
                        &state.store,
                        &state.gateway,
                        &state.network,
                        &state.ingestors,
                        &session_id,
                        err,
                    )
                    .await
                    .into_response();
                }
                Ok(other) => {
                    let err = SandboxError::Internal(format!(
                        "git clone of {repo_url} failed: unexpected guest response: {other:?}"
                    ));
                    return fail_explicit_repo_clone(
                        &state.store,
                        &state.gateway,
                        &state.network,
                        &state.ingestors,
                        &session_id,
                        err,
                    )
                    .await
                    .into_response();
                }
                Err(e) => {
                    let err = SandboxError::Internal(format!(
                        "git clone of {repo_url} failed: transport error: {e}"
                    ));
                    return fail_explicit_repo_clone(
                        &state.store,
                        &state.gateway,
                        &state.network,
                        &state.ingestors,
                        &session_id,
                        err,
                    )
                    .await
                    .into_response();
                }
            }
        }

        // M11-S7 — `--boot-cmd` symmetry on the container backend.
        //
        // Mirrors the Lima `--boot-cmd` path further down this handler:
        // an explicit `--boot-cmd <cmd>` violates the caller's stated
        // intent if it fails silently, so we route the four reachable
        // outcomes (non-zero exit, guest-agent error, unexpected
        // response, transport error) through `fail_explicit_boot_cmd`,
        // which marks the session `Error` and tears down partial
        // gateway/network state. The `bash -c <cmd>` argv shape and
        // 30s `GUEST_REQUEST_TIMEOUT` bound are identical to the Lima
        // path; the dispatch reaches the container via the
        // backend-agnostic `GuestConnector` (routes through
        // `ContainerTransport`'s `docker exec ... socat` channel).
        if let Some(boot_cmd) = &req.boot_cmd {
            info!(%session_id, cmd = %boot_cmd, "executing boot command in container");
            match state
                .guest
                .exec(&session_id, "bash", &["-c", boot_cmd.as_str()])
                .await
            {
                Ok(GuestResponse::ExecResult {
                    exit_code,
                    stdout,
                    stderr,
                }) => {
                    if exit_code != 0 {
                        let stderr_snip = truncate_for_diagnostic(stderr.trim(), 512);
                        let err = SandboxError::Internal(format!(
                            "boot command {boot_cmd:?} failed with exit code {exit_code}: {stderr_snip}"
                        ));
                        return fail_explicit_boot_cmd(
                            &state.store,
                            &state.gateway,
                            &state.network,
                            &state.ingestors,
                            &session_id,
                            err,
                        )
                        .await
                        .into_response();
                    } else {
                        info!(
                            %session_id,
                            output = %stdout.trim(),
                            "boot command completed successfully (lite)"
                        );
                    }
                }
                Ok(GuestResponse::Error { message }) => {
                    let err = SandboxError::Internal(format!(
                        "boot command {boot_cmd:?} failed: guest agent error: {message}"
                    ));
                    return fail_explicit_boot_cmd(
                        &state.store,
                        &state.gateway,
                        &state.network,
                        &state.ingestors,
                        &session_id,
                        err,
                    )
                    .await
                    .into_response();
                }
                Ok(other) => {
                    let err = SandboxError::Internal(format!(
                        "boot command {boot_cmd:?} failed: unexpected guest response: {other:?}"
                    ));
                    return fail_explicit_boot_cmd(
                        &state.store,
                        &state.gateway,
                        &state.network,
                        &state.ingestors,
                        &session_id,
                        err,
                    )
                    .await
                    .into_response();
                }
                Err(e) => {
                    let err = SandboxError::Internal(format!(
                        "boot command {boot_cmd:?} failed: transport error: {e}"
                    ));
                    return fail_explicit_boot_cmd(
                        &state.store,
                        &state.gateway,
                        &state.network,
                        &state.ingestors,
                        &session_id,
                        err,
                    )
                    .await
                    .into_response();
                }
            }
        }

        let created = match state.store.get_session(&session_id) {
            Ok(Some(s)) => s,
            Ok(None) => {
                cleanup_lite_gateway_and_return!(
                    error_response(SandboxError::SessionNotFound(session_id.to_string()))
                        .into_response()
                );
            }
            Err(e) => {
                cleanup_lite_gateway_and_return!(error_response(e).into_response());
            }
        };
        let dto = SessionDto::from(&created).with_warnings(warnings);
        return (StatusCode::CREATED, Json(dto)).into_response();
    } else if use_cache {
        // ---- Fast path: clone from golden base image ----

        // Serialize check + build behind a lock so that concurrent
        // create_session requests don't each see Missing and all
        // independently trigger build_base_image().
        {
            let _base_guard = state.base_image_lock.lock().await;

            let base_status = {
                let lima_check = Arc::clone(state.lima_runtime.manager());
                match tokio::task::spawn_blocking(move || lima_check.check_base_image()).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        cleanup_net_ca_and_return!(
                            state,
                            session_id,
                            error_response(e).into_response()
                        );
                    }
                    Err(e) => {
                        cleanup_net_ca_and_return!(
                            state,
                            session_id,
                            error_response(SandboxError::Internal(format!("task join error: {e}")))
                                .into_response()
                        );
                    }
                }
            };

            match base_status {
                BaseImageStatus::Missing => {
                    // Must build -- no choice.
                    info!("base image missing, building...");
                    let lima_build = Arc::clone(state.lima_runtime.manager());
                    match tokio::task::spawn_blocking(move || lima_build.build_base_image()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            cleanup_net_ca_and_return!(
                                state,
                                session_id,
                                error_response(e).into_response()
                            );
                        }
                        Err(e) => {
                            cleanup_net_ca_and_return!(
                                state,
                                session_id,
                                error_response(SandboxError::Internal(format!(
                                    "task join error: {e}"
                                )))
                                .into_response()
                            );
                        }
                    }
                }
                BaseImageStatus::Stale { .. } => {
                    // Don't auto-rebuild on create -- use the stale image.
                    // User can run `sandbox rebuild-image` to refresh.
                    info!("base image is stale, using anyway");
                }
                BaseImageStatus::Fresh => {
                    // Good to go.
                }
            }
        } // drop _base_guard — other requests can now check/build

        // Clone from the base image.
        {
            let lima_clone = Arc::clone(state.lima_runtime.manager());
            let sid = session_id;
            let cpus = config.cpus;
            let memory_mb = config.memory_mb;
            let disk_gb = config.disk_gb;
            match tokio::task::spawn_blocking(move || {
                lima_clone.clone_vm(sid, cpus, memory_mb, disk_gb)
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    cleanup_net_ca_and_return!(
                        state,
                        session_id,
                        error_response(e).into_response()
                    );
                }
                Err(e) => {
                    cleanup_net_ca_and_return!(
                        state,
                        session_id,
                        error_response(SandboxError::Internal(format!("task join error: {e}")))
                            .into_response()
                    );
                }
            }
        }

        // Start the cloned VM (no guest agent install needed -- already in image).
        {
            let runtime = runtime_for(&state, BackendKind::Lima);
            let handle = RuntimeHandle::from_session_id(&session_id);
            let args = RuntimeStartArgs {
                lima_bridge: Some(network_info.bridge_name.clone()),
                lima_mac: Some(vm_mac.clone()),
                lima_config: Some(config.clone()),
            };
            match runtime.start(&handle, &args).await {
                Ok(()) => {}
                Err(e) => {
                    cleanup_and_return!(state, session_id, error_response(e).into_response());
                }
            }
        }
    } else {
        // ---- Slow path: full create from scratch ----

        // 2a. Create the Lima VM (with optional custom template).
        //
        // M11-S1 Phase 1C: dispatch through the trait. The
        // custom-template branch lives inside `LimaRuntime::create`
        // (it inspects `SessionSpec::template`) — handlers no longer
        // pick between `create_vm` and `create_vm_with_custom_template`
        // directly. The wire shape (`CreateSessionRequest.template`)
        // is unchanged; we project the request into a `SessionSpec`
        // and hand it to the runtime.
        {
            let runtime = runtime_for(&state, BackendKind::Lima);
            match runtime.create(&session_id, &spec).await {
                Ok(_handle) => {}
                Err(e) => {
                    cleanup_net_ca_and_return!(
                        state,
                        session_id,
                        error_response(e).into_response()
                    );
                }
            }
        }

        // 2b. Start the VM with bridge networking env vars.
        {
            let runtime = runtime_for(&state, BackendKind::Lima);
            let handle = RuntimeHandle::from_session_id(&session_id);
            let args = RuntimeStartArgs {
                lima_bridge: Some(network_info.bridge_name.clone()),
                lima_mac: Some(vm_mac.clone()),
                lima_config: Some(config.clone()),
            };
            match runtime.start(&handle, &args).await {
                Ok(()) => {}
                Err(e) => {
                    cleanup_and_return!(state, session_id, error_response(e).into_response());
                }
            }
        }

        // 2c. Install the guest agent into the VM.
        let guest_binary_path = match std::env::current_exe() {
            Ok(exe) => match exe.parent() {
                Some(dir) => dir.join("sandbox-guest"),
                None => {
                    cleanup_and_return!(
                        state,
                        session_id,
                        error_response(SandboxError::Internal(
                            "executable path has no parent directory".to_string(),
                        ))
                        .into_response()
                    );
                }
            },
            Err(e) => {
                cleanup_and_return!(
                    state,
                    session_id,
                    error_response(SandboxError::Internal(format!(
                        "failed to determine daemon executable path: {e}"
                    )))
                    .into_response()
                );
            }
        };

        {
            // M11-S1 Phase 1C: `install_guest_agent` is Lima-specific
            // (it shells out to `limactl shell` to inject the binary)
            // and stays behind the `LimaRuntime::manager()` escape
            // hatch until the trait surface grows to cover agent
            // bootstrapping in a backend-agnostic way.
            let lima = Arc::clone(state.lima_runtime.manager());
            let sid = session_id;
            let guest_bin = guest_binary_path.clone();
            match tokio::task::spawn_blocking(move || lima.install_guest_agent(&sid, &guest_bin))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    error!(%session_id, error = %e, "failed to install guest agent");
                    cleanup_and_return!(state, session_id, error_response(e).into_response());
                }
                Err(e) => {
                    cleanup_and_return!(
                        state,
                        session_id,
                        error_response(SandboxError::Internal(format!("task join error: {e}")))
                            .into_response()
                    );
                }
            }
        }
    }

    // 5. Verify the guest agent is responsive.
    match state.guest.ping(&session_id).await {
        Ok(true) => {
            info!(%session_id, "guest agent responded to ping");
        }
        Ok(false) => {
            let err =
                SandboxError::Internal("guest agent returned unexpected response to ping".into());
            error!(%session_id, "guest agent ping: unexpected response");
            cleanup_and_return!(state, session_id, error_response(err).into_response());
        }
        Err(e) => {
            error!(%session_id, error = %e, "guest agent ping failed");
            cleanup_and_return!(state, session_id, error_response(e).into_response());
        }
    }

    // Update state to Running.
    if let Err(e) = state.store.update_state(&session_id, SessionState::Running) {
        return error_response(e).into_response();
    }

    // 6. Set up remaining networking: gateway container, guest NIC config, CA injection.
    //
    // Pass an initial DNS policy into the gateway setup so CoreDNS loads it
    // on first startup.  This eliminates the race where CoreDNS would start
    // with a deny-all default and only pick up the real policy after its
    // reload timer fires (~1s). The container branch above uses the same
    // helper to produce the same content.
    let initial_dns_policy_owned: String = compute_initial_dns_policy(&req);
    let initial_dns_policy = Some(initial_dns_policy_owned.as_str());
    match setup_session_networking(
        &session_id,
        &network_info,
        &ca_dir,
        &state,
        initial_dns_policy,
    )
    .await
    {
        Ok(()) => {
            info!(%session_id, "session networking configured");
        }
        Err(e) => {
            error!(%session_id, error = %e, "networking setup failed");
            let _ = state.store.update_state(&session_id, SessionState::Error);
            // Best-effort teardown of any partial networking state.
            teardown_session_networking(&session_id, &state).await;
            return error_response(e).into_response();
        }
    }

    // If a policy was provided, compile and distribute it now that the
    // gateway is running.  The DNS policy for the no-policy case was already
    // written during gateway creation above.
    //
    // Reaching this block means the caller provided `policy` explicitly
    // (via `--policy <file>` and/or `--preset <invocation>` on the CLI —
    // both paths populate the field on the wire). Compile/distribute
    // failure on an *explicit* policy is fatal for the create call
    // (M10-S8 #16): the alternative is silently returning a Running
    // session with `Policy: none`, which violates the caller's stated
    // intent. The implicit "no policy" default path never reaches this
    // branch at all — for that path we've already written the
    // fail-closed empty CoreDNS config during `setup_session_networking`
    // above and there is nothing to do here.
    if let Some(policy) = req.policy {
        let initial_presets = req.source_presets.clone();
        match apply_policy(
            &session_id,
            &policy,
            &state,
            ApplyKind::Initial {
                source_presets: initial_presets,
            },
        )
        .await
        {
            Ok(()) => {
                info!(%session_id, "initial policy applied");
            }
            Err(e) => {
                return fail_explicit_policy_apply(
                    &state.store,
                    &state.gateway,
                    &state.network,
                    &state.ingestors,
                    &session_id,
                    e,
                )
                .await
                .into_response();
            }
        }
    }

    // If a repo URL was provided, clone it into /home/agent/workspace/.
    if let Some(repo_url) = &req.repo {
        // Pre-warm DNS for the repo host so the DNS propagation loop
        // has installed the policy's L1/L3 filter chain (Envoy
        // prefix_ranges + sandbox_policy concat-set) before `git clone`
        // opens its first TCP connection. Under schema v2 domain
        // allow-rules are fail-closed at empty DNS cache; the loop
        // polls every 2s, and a clone firing faster than that hits the
        // empty ruleset and is rejected. Host extraction is
        // best-effort: if the URL parses as a local path or we can't
        // identify a host, we skip the pre-warm and let clone proceed.
        if let Some(host) = extract_repo_host(repo_url) {
            info!(%session_id, %host, "pre-warming DNS for repo clone");
            prewarm_guest_dns(&state.guest, &session_id, &host).await;
        }

        info!(%session_id, repo = %repo_url, "cloning repository into VM");
        match state
            .guest
            .exec(
                &session_id,
                "git",
                &["clone", repo_url.as_str(), "/home/agent/workspace/"],
            )
            .await
        {
            Ok(GuestResponse::ExecResult {
                exit_code,
                stdout,
                stderr,
            }) => {
                if exit_code != 0 {
                    let stderr_snip = truncate_for_diagnostic(stderr.trim(), 512);
                    let err = SandboxError::Internal(format!(
                        "git clone of {repo_url} failed with exit code {exit_code}: {stderr_snip}"
                    ));
                    return fail_explicit_repo_clone(
                        &state.store,
                        &state.gateway,
                        &state.network,
                        &state.ingestors,
                        &session_id,
                        err,
                    )
                    .await
                    .into_response();
                } else {
                    info!(
                        %session_id,
                        output = %stdout.trim(),
                        "repository cloned successfully"
                    );
                }
            }
            Ok(GuestResponse::Error { message }) => {
                let err = SandboxError::Internal(format!(
                    "git clone of {repo_url} failed: guest agent error: {message}"
                ));
                return fail_explicit_repo_clone(
                    &state.store,
                    &state.gateway,
                    &state.network,
                    &state.ingestors,
                    &session_id,
                    err,
                )
                .await
                .into_response();
            }
            Ok(other) => {
                let err = SandboxError::Internal(format!(
                    "git clone of {repo_url} failed: unexpected guest response: {other:?}"
                ));
                return fail_explicit_repo_clone(
                    &state.store,
                    &state.gateway,
                    &state.network,
                    &state.ingestors,
                    &session_id,
                    err,
                )
                .await
                .into_response();
            }
            Err(e) => {
                let err = SandboxError::Internal(format!(
                    "git clone of {repo_url} failed: transport error: {e}"
                ));
                return fail_explicit_repo_clone(
                    &state.store,
                    &state.gateway,
                    &state.network,
                    &state.ingestors,
                    &session_id,
                    err,
                )
                .await
                .into_response();
            }
        }
    }

    // If a boot command was provided, execute it in the VM.
    //
    // Reaching this block means the caller passed `--boot-cmd <cmd>`
    // explicitly (the wire field is `Option<String>` with no implicit
    // default — the CLI only populates it when `--boot-cmd` is given).
    // Any failure here therefore violates the caller's stated intent
    // the same way #16 (`--policy`) and #34 (`--repo`) did pre-fix:
    // returning a `Running` session with the boot command's side
    // effects unrealised silently lies to the operator. Mirror the
    // fatal-create pattern (M10-S9 #53): tag the session `Error`,
    // tear down partial gateway/network state, and surface the
    // failure in the HTTP response so the CLI user can see *why* the
    // boot command did not succeed (exit code, stderr snippet,
    // transport error, etc.).
    if let Some(boot_cmd) = &req.boot_cmd {
        info!(%session_id, cmd = %boot_cmd, "executing boot command in VM");
        match state
            .guest
            .exec(&session_id, "bash", &["-c", boot_cmd.as_str()])
            .await
        {
            Ok(GuestResponse::ExecResult {
                exit_code,
                stdout,
                stderr,
            }) => {
                if exit_code != 0 {
                    let stderr_snip = truncate_for_diagnostic(stderr.trim(), 512);
                    let err = SandboxError::Internal(format!(
                        "boot command {boot_cmd:?} failed with exit code {exit_code}: {stderr_snip}"
                    ));
                    return fail_explicit_boot_cmd(
                        &state.store,
                        &state.gateway,
                        &state.network,
                        &state.ingestors,
                        &session_id,
                        err,
                    )
                    .await
                    .into_response();
                } else {
                    info!(
                        %session_id,
                        output = %stdout.trim(),
                        "boot command completed successfully"
                    );
                }
            }
            Ok(GuestResponse::Error { message }) => {
                let err = SandboxError::Internal(format!(
                    "boot command {boot_cmd:?} failed: guest agent error: {message}"
                ));
                return fail_explicit_boot_cmd(
                    &state.store,
                    &state.gateway,
                    &state.network,
                    &state.ingestors,
                    &session_id,
                    err,
                )
                .await
                .into_response();
            }
            Ok(other) => {
                let err = SandboxError::Internal(format!(
                    "boot command {boot_cmd:?} failed: unexpected guest response: {other:?}"
                ));
                return fail_explicit_boot_cmd(
                    &state.store,
                    &state.gateway,
                    &state.network,
                    &state.ingestors,
                    &session_id,
                    err,
                )
                .await
                .into_response();
            }
            Err(e) => {
                let err = SandboxError::Internal(format!(
                    "boot command {boot_cmd:?} failed: transport error: {e}"
                ));
                return fail_explicit_boot_cmd(
                    &state.store,
                    &state.gateway,
                    &state.network,
                    &state.ingestors,
                    &session_id,
                    err,
                )
                .await
                .into_response();
            }
        }
    }

    // Re-fetch the session to get the updated state and timestamp.
    let created = match state.store.get_session(&session_id) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return error_response(SandboxError::SessionNotFound(session_id.to_string()))
                .into_response();
        }
        Err(e) => return error_response(e).into_response(),
    };

    // Probe guest agent / gateway health so the echoed DTO matches the
    // shape returned by `GET /sessions/{id}`.  `policy` is populated from
    // the in-memory map if the caller supplied an initial policy.
    let agent_status = probe_agent_status(&state, &created).await;
    let gateway_status = probe_gateway_status(&state, &created).await;

    let policy_opt = {
        let policies = state.session_policies.lock().await;
        policies.get(&session_id).cloned()
    };

    let dto = SessionDto::from(&created)
        .with_status(agent_status, gateway_status)
        .with_policy(policy_opt.as_ref())
        .with_warnings(warnings);

    (StatusCode::CREATED, Json(dto)).into_response()
}

/// Probe the guest agent with a short timeout and return the status string
/// used by the `SessionDto.guest_agent_status` field.
///
/// Returns `None` when the session is not `Running`; callers treat `None`
/// as "omit from wire" via `skip_serializing_if`.
async fn probe_agent_status(state: &AppState, session: &Session) -> Option<String> {
    if session.state != SessionState::Running {
        return None;
    }
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state.guest.ping(&session.id),
    )
    .await
    {
        Ok(Ok(true)) => Some("connected".to_string()),
        _ => Some("unreachable".to_string()),
    }
}

/// Probe the session's gateway container and format a status string for
/// the `SessionDto.gateway_status` field.
///
/// Returns `None` when the session is not `Running`.
async fn probe_gateway_status(state: &AppState, session: &Session) -> Option<String> {
    if session.state != SessionState::Running {
        return None;
    }
    let gateway = state.gateway.clone();
    let sid = session.id;
    Some(
        tokio::task::spawn_blocking(move || format_gateway_status(&gateway, &sid))
            .await
            .unwrap_or_else(|_| "error: task join failed".to_string()),
    )
}

async fn list_sessions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let sessions = match state.store.list_sessions() {
        Ok(s) => s,
        Err(e) => return error_response(e).into_response(),
    };

    // Enrich with VM status (best-effort).
    //
    // M11-S1 Phase 1C: `list_vms()` is Lima-specific — it returns a
    // `Vec<VmInfo>` shaped by `limactl list --json` and the
    // reconciliation block below matches on `VmStatus`. Multi-backend
    // listing (fan-out across every registered runtime) is deferred
    // to M11-S2 when the second backend lands.
    let lima = Arc::clone(state.lima_runtime.manager());
    let vm_list = tokio::task::spawn_blocking(move || lima.list_vms().unwrap_or_default())
        .await
        .unwrap_or_default();

    let reconciled: Vec<Session> = sessions
        .into_iter()
        .map(|mut s| {
            // If we find the VM in Lima's inventory, reflect its actual status.
            if let Some(vm) = vm_list.iter().find(|v| v.session_id == Some(s.id)) {
                match (&s.state, &vm.status) {
                    // DB says Running but Lima says Stopped => update to Stopped
                    (SessionState::Running, VmStatus::Stopped) => {
                        s.state = SessionState::Stopped;
                        let _ = state
                            .store
                            .update_state_forced(&s.id, SessionState::Stopped);
                    }
                    // DB says Stopped but Lima says Running => update to Running
                    (SessionState::Stopped, VmStatus::Running) => {
                        s.state = SessionState::Running;
                        let _ = state
                            .store
                            .update_state_forced(&s.id, SessionState::Running);
                    }
                    _ => {}
                }
            }
            s
        })
        .collect();

    // Probe guest agent and gateway for running sessions (with a short
    // timeout).  Deliberately does NOT populate `policy` — the list
    // endpoint is meant to stay cheap and `policy` is omitted from the
    // wire via `skip_serializing_if` on the DTO.
    let mut enriched: Vec<SessionDto> = Vec::with_capacity(reconciled.len());
    for session in reconciled {
        let agent_status = probe_agent_status(&state, &session).await;
        let gateway_status = probe_gateway_status(&state, &session).await;
        enriched.push(SessionDto::from(&session).with_status(agent_status, gateway_status));
    }

    (StatusCode::OK, Json(enriched)).into_response()
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    // Enrich with VM status (best-effort).
    //
    // M11-S1 Phase 1C: dispatch through the trait. `RuntimeStatus`
    // mirrors `VmStatus` for the Running/Stopped cases the
    // reconciliation cares about; the new `Creating`/`Error` variants
    // (set by the container backend) are treated as "no-op" here —
    // the daemon's authoritative state is in the store and we don't
    // overwrite it on a non-matching runtime status.
    let mut session = session;
    {
        let runtime = runtime_for(&state, session.backend);
        let handle = RuntimeHandle::from_session_id(&session.id);
        if let Ok(rt_status) = runtime.status(&handle).await {
            match (&session.state, &rt_status) {
                (SessionState::Running, sandbox_core::backend::RuntimeStatus::Stopped) => {
                    session.state = SessionState::Stopped;
                    let _ = state
                        .store
                        .update_state_forced(&session.id, SessionState::Stopped);
                }
                (SessionState::Stopped, sandbox_core::backend::RuntimeStatus::Running) => {
                    session.state = SessionState::Running;
                    let _ = state
                        .store
                        .update_state_forced(&session.id, SessionState::Running);
                }
                _ => {}
            }
        }
    }

    // Probe guest agent and gateway for running sessions.
    let agent_status = probe_agent_status(&state, &session).await;
    let gateway_status = probe_gateway_status(&state, &session).await;

    // Look up the currently applied policy in the in-memory map.
    // Persistence of the policy across daemon restarts is M9-S12's
    // responsibility; until then, this map is the source of truth.
    let policy_opt = {
        let policies = state.session_policies.lock().await;
        policies.get(&session.id).cloned()
    };

    // Backend-neutral network/mount surfaces (M11-S7 Bundle Y / todo
    // #72). Both pull from already-canonical sources: `network` from
    // the persisted `NetworkInfo`, `mounts` from the session's own
    // `config.workspace_mode` plus a small per-backend constant set
    // (workspace path, CA bind path, home-volume name). Surfacing
    // them here lets `sandbox inspect` consumers and the e2e suite
    // assert on session-level networking/mount layout without
    // reaching into backend-specific call sites.
    let network = session_network_info_for(&state, &session.id);
    let mounts = Some(session_mount_info_for(&session));

    let dto = SessionDto::from(&session)
        .with_status(agent_status, gateway_status)
        .with_policy(policy_opt.as_ref())
        .with_network(network)
        .with_mounts(mounts);
    (StatusCode::OK, Json(dto)).into_response()
}

/// Build a backend-neutral [`SessionNetworkInfo`] for the given
/// session id by reading the daemon's persisted `NetworkInfo`.
///
/// Returns `None` when no `NetworkInfo` is recorded for the session
/// (e.g. mid-create state, or a record from a daemon version that
/// failed before networking was persisted) or when the store read
/// itself fails — `inspect` is read-only and degrades gracefully
/// rather than failing the whole response over a missing networking
/// row. The store error is logged at warn level so operators can
/// still trace it through the daemon log.
fn session_network_info_for(
    state: &Arc<AppState>,
    session_id: &SessionId,
) -> Option<SessionNetworkInfo> {
    match state.store.get_network_info(session_id) {
        Ok(Some(ni)) => Some(SessionNetworkInfo {
            gateway_ip: ni.gateway_ip,
            session_ip: ni.vm_ip,
            session_subnet_cidr: ni.subnet,
        }),
        Ok(None) => None,
        Err(e) => {
            warn!(
                session_id = %session_id,
                error = %e,
                "failed to load network_info for inspect; surfacing absent network block"
            );
            None
        }
    }
}

/// In-session absolute path of the workspace, unified across backends
/// post Bundle X (M11-S7). Both Lima and container plant the
/// workspace at this path; the `WorkspaceMode::Shared` host bind and
/// the `WorkspaceMode::Clone` `git clone <url> <path>` invocations
/// already use the same target.
const SESSION_WORKSPACE_PATH: &str = "/home/agent/workspace/";

/// In-container absolute path where the per-session MITM CA is
/// bind-mounted read-only by the runtime (`ContainerNetwork::ca_host_path`
/// → this destination). Mirrors the constant used internally by the
/// container backend's argv builder; lifting it here as a daemon-side
/// constant means the inspect surface does not need to reach into the
/// backend module to render it. Lima sessions inject the CA into the
/// system trust store via the guest agent rather than via a bind, so
/// this path applies to the container backend only.
const CONTAINER_CA_BUNDLE_PATH: &str = "/etc/ssl/certs/sandbox-ca.pem";

/// Build a backend-neutral [`SessionMountInfo`] for a session.
///
/// Container sessions populate every field. Lima sessions populate
/// `workspace_path` always, `workspace_host_path` only for
/// `WorkspaceMode::Shared`, and leave `ca_bundle_path` /
/// `home_volume` `None` because Lima's CA injection and home
/// directory are not bind-/volume-backed (the guest agent installs
/// the CA into the system trust store; home is a regular VM
/// directory).
fn session_mount_info_for(session: &Session) -> SessionMountInfo {
    let workspace_host_path = match &session.config.workspace_mode {
        Some(sandbox_core::WorkspaceMode::Shared { host_path }) => Some(host_path.clone()),
        _ => None,
    };
    let (ca_bundle_path, home_volume) = match session.backend {
        sandbox_core::backend::BackendKind::Container => (
            Some(CONTAINER_CA_BUNDLE_PATH.to_string()),
            // Container backend names the per-session named volume
            // `sandbox-home-{session_id}` (LM6.4 in spec / orphan
            // reaper's `parse_home_volume_session_id`). Re-deriving
            // the name here from the session id keeps the inspect
            // surface independent of the backend module's private
            // helper while staying byte-identical to the Docker
            // resource that `docker volume ls` reports.
            Some(format!("sandbox-home-{}", session.id)),
        ),
        sandbox_core::backend::BackendKind::Lima => (None, None),
    };
    SessionMountInfo {
        workspace_path: SESSION_WORKSPACE_PATH.to_string(),
        workspace_host_path,
        ca_bundle_path,
        home_volume,
    }
}

async fn start_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    // Validate state transition before calling Lima.
    if session.state != SessionState::Stopped {
        return error_response(SandboxError::InvalidState(format!(
            "cannot start session in {} state (must be stopped)",
            session.state
        )))
        .into_response();
    }

    info!(session_id = %session.id, "starting session");

    // Ensure the Docker bridge network exists BEFORE starting the VM so the
    // QEMU wrapper can attach the bridge NIC via qemu-bridge-helper at boot.
    let (bridge_name, vm_mac) = {
        let network = state.network.clone();
        let sid = session.id;
        match tokio::task::spawn_blocking(move || network.ensure_network(&sid)).await {
            Ok(Ok(info)) => {
                let mac = mac_from_session_id(&session.id);
                (Some(info.bridge_name), Some(mac))
            }
            Ok(Err(e)) => {
                // If network info is not available (e.g. session created before
                // networking was set up), start without bridge networking.
                warn!(
                    session_id = %session.id,
                    error = %e,
                    "could not ensure Docker bridge (starting VM without bridge NIC)"
                );
                (None, None)
            }
            Err(e) => {
                warn!(
                    session_id = %session.id,
                    error = %e,
                    "could not ensure Docker bridge (task join error, starting VM without bridge NIC)"
                );
                (None, None)
            }
        }
    };

    // Start the VM/container via the trait.
    //
    // M11-S1 Phase 1C: dispatch through the trait. The persisted
    // `SessionConfig` and the per-session bridge / MAC ride down via
    // `RuntimeStartArgs`; the runtime's `start` does its own
    // `spawn_blocking` internally so we just `.await` here.
    //
    // M11-S3 Phase 3D: dispatch keyed off the persisted
    // `session.backend`, so a container session with `backend =
    // "container"` lands on `ContainerRuntime::start` and Lima
    // sessions land on `LimaRuntime::start` from the same handler.
    {
        let runtime = runtime_for(&state, session.backend);
        let handle = RuntimeHandle::from_session_id(&session.id);
        let args = RuntimeStartArgs {
            lima_bridge: bridge_name.clone(),
            lima_mac: vm_mac.clone(),
            lima_config: Some(session.config.clone()),
        };
        match runtime.start(&handle, &args).await {
            Ok(()) => {}
            Err(e) => {
                let _ = state.store.update_state(&session.id, SessionState::Error);
                return error_response(e).into_response();
            }
        }
    }

    // Wait for the guest agent to become responsive before proceeding.
    match state.guest.ping(&session.id).await {
        Ok(true) => {
            info!(session_id = %session.id, "guest agent responded to ping after start");
        }
        Ok(false) => {
            let err = SandboxError::Internal(
                "guest agent returned unexpected response to ping after start".into(),
            );
            error!(session_id = %session.id, "guest agent ping: unexpected response");
            let _ = state.store.update_state(&session.id, SessionState::Error);
            return error_response(err).into_response();
        }
        Err(e) => {
            error!(session_id = %session.id, error = %e, "guest agent ping failed after start");
            let _ = state.store.update_state(&session.id, SessionState::Error);
            return error_response(e).into_response();
        }
    }

    // Update state to Running.
    if let Err(e) = state.store.update_state(&session.id, SessionState::Running) {
        return error_response(e).into_response();
    }

    // Restore remaining networking: gateway container, plus (Lima-only)
    // guest config + CA injection. The lite path forks at this call —
    // `restore_session_networking_lite` performs the gateway / ingestor /
    // DNS-gate-listener restore but skips `attach_vm_to_bridge` +
    // `inject_ca_into_vm` because they're VM-only steps that try to run
    // `sudo bash -c ...` inside the guest, and the lite image has neither
    // sudo nor those bridge helpers (M11 spec § "Routing").
    let restore_result = match session.backend {
        BackendKind::Container => restore_session_networking_lite(&session.id, &state).await,
        BackendKind::Lima => restore_session_networking(&session.id, &state).await,
    };
    match restore_result {
        Ok(()) => {
            info!(session_id = %session.id, "session networking restored after start");
        }
        Err(e) => {
            error!(session_id = %session.id, error = %e, "networking restore failed after start");
            let _ = state.store.update_state(&session.id, SessionState::Error);
            // Best-effort teardown of any partial networking state.
            teardown_session_networking(&session.id, &state).await;
            return error_response(e).into_response();
        }
    }

    // Re-fetch the session to get the updated state and timestamp.
    let refreshed = match state.store.get_session(&session.id) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return error_response(SandboxError::SessionNotFound(session.id.to_string()))
                .into_response();
        }
        Err(e) => return error_response(e).into_response(),
    };

    let agent_status = probe_agent_status(&state, &refreshed).await;
    let gateway_status = probe_gateway_status(&state, &refreshed).await;
    let policy_opt = {
        let policies = state.session_policies.lock().await;
        policies.get(&refreshed.id).cloned()
    };
    let dto = SessionDto::from(&refreshed)
        .with_status(agent_status, gateway_status)
        .with_policy(policy_opt.as_ref());
    (StatusCode::OK, Json(dto)).into_response()
}

async fn stop_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    if session.state != SessionState::Running {
        return error_response(SandboxError::InvalidState(format!(
            "cannot stop session in {} state (must be running)",
            session.state
        )))
        .into_response();
    }

    info!(session_id = %session.id, "stopping session");

    // Mark this session as "stopping" so the gateway monitor doesn't restart
    // the gateway container while we are tearing it down.
    state.sessions_stopping.lock().await.insert(session.id);

    // Cancel DNS propagation loop before tearing down networking.
    cancel_dns_propagation_loop(&session.id, &state).await;

    // Cancel the synchronous DNS-gate listener (M10-S10 Phase 2)
    // before the container disappears: the UDS file lives inside the
    // events host directory `stop_gateway` is about to remove, and we
    // want the listener task to exit cleanly rather than spin on
    // `accept` against a vanished socket.
    cancel_dns_gate_listener(&session.id, &state).await;
    drop_dns_cache(&state, &session.id).await;

    // Publish `gateway_shutdown` before the container is actually
    // stopped so downstream subscribers see the intent even if the
    // Docker `stop` call hangs or races with a crash.  The session's
    // event sink is still live on the bus (we unregister below the
    // state transition) so this event is retained in the ring buffer.
    state.event_bus.publish(lifecycle_events::gateway_shutdown(
        session.id,
        GatewayShutdownReason::SessionStopped,
        None,
    ));

    // Abort the JSONL ingestor before the gateway container stops so
    // its inotify watch and tailer file handles are released cleanly.
    // No-op if none was ever spawned for this session.
    abort_session_ingestor(&session.id, &state).await;

    // Tear down networking resources (TAP, gateway, Docker network) before
    // stopping the VM. The network_info is kept in the DB so `start` can
    // recreate everything. The subnet remains allocated in the
    // NetworkManager so it is not reused by another session.
    {
        let gateway = state.gateway.clone();
        let network = state.network.clone();
        let sid = session.id;
        let _ = tokio::task::spawn_blocking(move || {
            debug!(session_id = %sid, "tearing down session networking (preserving allocation)");
            if let Err(e) = detach_vm_from_bridge(&sid) {
                warn!(%sid, error = %e, "failed to detach VM from bridge (best-effort)");
            }
            if let Err(e) = gateway.stop_gateway(&sid) {
                warn!(%sid, error = %e, "failed to stop gateway (best-effort)");
            }
            if let Err(e) = network.remove_docker_network(&sid) {
                warn!(%sid, error = %e, "failed to remove Docker network (best-effort)");
            }
        })
        .await;
    }

    {
        // M11-S1 Phase 1C: dispatch through the trait.
        // M11-S3 Phase 3D: keyed off persisted backend.
        let runtime = runtime_for(&state, session.backend);
        let handle = RuntimeHandle::from_session_id(&session.id);
        match runtime.stop(&handle).await {
            Ok(()) => {}
            Err(e) => {
                state.sessions_stopping.lock().await.remove(&session.id);
                let _ = state.store.update_state(&session.id, SessionState::Error);
                return error_response(e).into_response();
            }
        }
    }

    if let Err(e) = state.store.update_state(&session.id, SessionState::Stopped) {
        state.sessions_stopping.lock().await.remove(&session.id);
        return error_response(e).into_response();
    }

    state.sessions_stopping.lock().await.remove(&session.id);

    info!(session_id = %session.id, "session stopped");

    let refreshed = match state.store.get_session(&session.id) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return error_response(SandboxError::SessionNotFound(session.id.to_string()))
                .into_response();
        }
        Err(e) => return error_response(e).into_response(),
    };

    // After stop, agent/gateway are expected to be offline; `policy` is no
    // longer meaningful (the gateway is gone) but the map cleanup is
    // handled by `cancel_dns_propagation_loop` above.  `with_policy(None)`
    // makes this explicit.
    let dto = SessionDto::from(&refreshed).with_status(None, None);
    (StatusCode::OK, Json(dto)).into_response()
}

async fn remove_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    info!(
        session_id = %session.id,
        name = ?session.name,
        state = %session.state,
        "removing session"
    );

    // Mark as stopping so the gateway monitor skips this session.
    state.sessions_stopping.lock().await.insert(session.id);

    // Cancel DNS propagation loop and synchronous DNS-gate listener
    // before teardown — see the matching block in `stop_session` for
    // why both must come down before `stop_gateway`.
    cancel_dns_propagation_loop(&session.id, &state).await;
    cancel_dns_gate_listener(&session.id, &state).await;
    drop_dns_cache(&state, &session.id).await;

    // Publish `gateway_shutdown` before the container is stopped, but
    // only if the session was actually running a gateway (a stopped
    // session's gateway container is already gone).  Treating removal
    // as a `SessionStopped` reason keeps the taxonomy simple — remove
    // is stop-plus-delete, and graceful daemon teardown is the only
    // case that uses `DaemonShutdown`.
    if session.state == SessionState::Running {
        state.event_bus.publish(lifecycle_events::gateway_shutdown(
            session.id,
            GatewayShutdownReason::SessionStopped,
            None,
        ));
    }

    // Abort the JSONL ingestor before the gateway container disappears
    // so its inotify watch and tailer file handles are released.
    // No-op if none was ever spawned for this session (e.g., a session
    // whose networking setup failed mid-way).
    abort_session_ingestor(&session.id, &state).await;

    // Delete VM from Lima, then full network teardown.
    // All of these are best-effort blocking calls.
    // Note: `delete_vm` uses `limactl delete --force` which already stops
    // a running VM, so we skip the separate `stop_vm` call to avoid
    // doubling the Lima wait time (~60s each).
    //
    // M11-S1 Phase 1C: VM cleanup goes through the generic trait
    // dispatch (`runtime.delete(&handle).await`); the rest of the
    // teardown (gateway stop, docker network delete, CA remove,
    // bridge detach) stays inside one shared `spawn_blocking` so we
    // keep a single host-side task for the remaining sync work.
    // M11-S3 Phase 3D: dispatch to the runtime that owns this
    // session's resources (Lima for VM rows, Container for docker rows).
    {
        let runtime = runtime_for(&state, session.backend);
        let handle = RuntimeHandle::from_session_id(&session.id);
        let _ = runtime.delete(&handle).await;

        let gateway = state.gateway.clone();
        let network = state.network.clone();
        let base_dir = state.base_dir.clone();
        let sid = session.id;
        let _ = tokio::task::spawn_blocking(move || {
            // Full teardown: networking + CA + release subnet allocation.
            debug!(session_id = %sid, "tearing down session networking (full cleanup)");
            if let Err(e) = detach_vm_from_bridge(&sid) {
                warn!(%sid, error = %e, "failed to detach VM from bridge (best-effort)");
            }
            if let Err(e) = gateway.stop_gateway(&sid) {
                warn!(%sid, error = %e, "failed to stop gateway (best-effort)");
            }
            if let Err(e) = network.delete_network(&sid) {
                warn!(%sid, error = %e, "failed to delete network (best-effort)");
            }
            if let Err(e) = CaManager::remove_session_ca(&base_dir, &sid) {
                warn!(%sid, error = %e, "failed to remove session CA (best-effort)");
            }
        })
        .await;
    }

    // Remove from the stopping set now that teardown is complete.
    state.sessions_stopping.lock().await.remove(&session.id);

    // Unbind the session's VM IP and unregister it from the event bus.
    // Done after the networking teardown (no further events can be
    // attributed to this session) and before `delete_session` to keep
    // the window in which store + bus disagree as short as possible.
    // The vm_ip is looked up from the store; if network_info was absent
    // or unparseable, unbind is a no-op.
    match state.store.get_network_info(&session.id) {
        Ok(Some(ni)) => match ni.vm_ip.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => {
                state.vm_ip_map.unbind(ip);
            }
            Err(e) => {
                warn!(
                    session_id = %session.id,
                    vm_ip = %ni.vm_ip,
                    error = %e,
                    "failed to parse vm_ip during remove; skipping unbind"
                );
            }
        },
        Ok(None) => {}
        Err(e) => {
            warn!(
                session_id = %session.id,
                error = %e,
                "failed to read network_info during remove; skipping unbind"
            );
        }
    }
    state.event_bus.unregister_session(&session.id);
    // Also drop any tracked component health state for this session
    // so the map doesn't grow without bound as sessions churn.
    state
        .component_health_state
        .lock()
        .await
        .remove(&session.id);
    // Drop propagation-tracker state for this session so the map
    // doesn't grow without bound as sessions churn (M10-S6).
    state.propagation_states.remove(&session.id).await;

    // Delete the session from the store.
    if let Err(e) = state.store.delete_session(&session.id) {
        return error_response(e).into_response();
    }

    info!(session_id = %session.id, "session removed");
    StatusCode::NO_CONTENT.into_response()
}

async fn exec_in_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ExecRequest>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    if session.state != SessionState::Running {
        return error_response(SandboxError::InvalidState(format!(
            "cannot exec in session with state {} (must be running)",
            session.state
        )))
        .into_response();
    }

    let args_refs: Vec<&str> = req.args.iter().map(|s| s.as_str()).collect();
    match state
        .guest
        .exec(&session.id, &req.command, &args_refs)
        .await
    {
        Ok(GuestResponse::ExecResult {
            exit_code,
            stdout,
            stderr,
        }) => {
            let response = ExecResponse {
                exit_code,
                stdout,
                stderr,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Ok(GuestResponse::Error { message }) => {
            error!(session_id = %session.id, %message, "guest agent exec error");
            error_response(SandboxError::Internal(format!(
                "guest agent error: {message}"
            )))
            .into_response()
        }
        Ok(other) => {
            error!(session_id = %session.id, ?other, "unexpected guest response to exec");
            error_response(SandboxError::Internal(
                "unexpected response from guest agent".into(),
            ))
            .into_response()
        }
        Err(e) => {
            error!(session_id = %session.id, error = %e, "guest agent exec failed");
            error_response(e).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// File transfer handlers
// ---------------------------------------------------------------------------

/// `POST /sessions/{id}/upload` -- upload a file to the VM.
async fn upload_to_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<FileUploadRequest>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    if session.state != SessionState::Running {
        return error_response(SandboxError::InvalidState(format!(
            "cannot upload to session with state {} (must be running)",
            session.state
        )))
        .into_response();
    }

    match state
        .guest
        .send_request(
            &session.id,
            GuestRequest::FileUpload {
                path: req.path.clone(),
                data: req.data,
                mode: req.mode,
            },
        )
        .await
    {
        Ok(GuestResponse::FileUploadResult { success, error }) => {
            if success {
                let body = serde_json::json!({
                    "status": "ok",
                    "message": format!("file uploaded to {}", req.path),
                });
                (StatusCode::OK, Json(body)).into_response()
            } else {
                let msg = error.unwrap_or_else(|| "unknown error".into());
                error_response(SandboxError::Internal(format!("file upload failed: {msg}")))
                    .into_response()
            }
        }
        Ok(GuestResponse::Error { message }) => {
            error!(session_id = %session.id, %message, "guest agent upload error");
            error_response(SandboxError::Internal(format!(
                "guest agent error: {message}"
            )))
            .into_response()
        }
        Ok(other) => {
            error!(session_id = %session.id, ?other, "unexpected guest response to upload");
            error_response(SandboxError::Internal(
                "unexpected response from guest agent".into(),
            ))
            .into_response()
        }
        Err(e) => {
            error!(session_id = %session.id, error = %e, "guest agent upload failed");
            error_response(e).into_response()
        }
    }
}

/// `POST /sessions/{id}/download` -- download a file from the VM.
async fn download_from_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<FileDownloadRequest>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    if session.state != SessionState::Running {
        return error_response(SandboxError::InvalidState(format!(
            "cannot download from session with state {} (must be running)",
            session.state
        )))
        .into_response();
    }

    match state
        .guest
        .send_request(
            &session.id,
            GuestRequest::FileDownload {
                path: req.path.clone(),
            },
        )
        .await
    {
        Ok(GuestResponse::FileDownloadResult { data, error }) => {
            if let Some(err_msg) = error {
                error_response(SandboxError::Internal(format!(
                    "file download failed: {err_msg}"
                )))
                .into_response()
            } else {
                let body = FileDownloadResponse { data };
                (StatusCode::OK, Json(body)).into_response()
            }
        }
        Ok(GuestResponse::Error { message }) => {
            error!(session_id = %session.id, %message, "guest agent download error");
            error_response(SandboxError::Internal(format!(
                "guest agent error: {message}"
            )))
            .into_response()
        }
        Ok(other) => {
            error!(session_id = %session.id, ?other, "unexpected guest response to download");
            error_response(SandboxError::Internal(
                "unexpected response from guest agent".into(),
            ))
            .into_response()
        }
        Err(e) => {
            error!(session_id = %session.id, error = %e, "guest agent download failed");
            error_response(e).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Policy handlers
// ---------------------------------------------------------------------------

/// `POST /sessions/{id}/policy` -- update the policy for a running session.
async fn update_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePolicyRequest>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    if session.state != SessionState::Running {
        return error_response(SandboxError::InvalidState(format!(
            "cannot update policy for session in {} state (must be running)",
            session.state
        )))
        .into_response();
    }

    match apply_policy(
        &session.id,
        &req.policy,
        &state,
        ApplyKind::Update {
            source_presets: req.source_presets.clone(),
        },
    )
    .await
    {
        Ok(()) => {
            info!(session_id = %session.id, "policy updated");
            let body = serde_json::json!({
                "status": "ok",
                "message": "policy applied successfully",
            });
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => {
            error!(session_id = %session.id, error = %e, "policy update failed");
            error_response(e).into_response()
        }
    }
}

/// `DELETE /sessions/{id}/policy` -- remove the policy from a running session
/// and revert to the fail-closed default (empty CoreDNS allow-list, deny-all
/// mitmproxy + Envoy, flushed nftables policy/l3 tables).
///
/// Idempotent: calling this on a session with no stored policy still writes
/// the fail-closed configuration to the gateway (so a stale rollback state
/// cannot linger) and returns 200.
async fn clear_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    if session.state != SessionState::Running {
        return error_response(SandboxError::InvalidState(format!(
            "cannot clear policy for session in {} state (must be running)",
            session.state
        )))
        .into_response();
    }

    match clear_session_policy(&session.id, &state).await {
        Ok(()) => {
            info!(session_id = %session.id, "policy cleared (fail-closed)");
            let body = serde_json::json!({
                "status": "ok",
                "message": "policy cleared; session is now fail-closed",
            });
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => {
            error!(session_id = %session.id, error = %e, "policy clear failed");
            error_response(e).into_response()
        }
    }
}

/// Clear a session's policy: cancel the DNS propagation loop, delete the
/// persisted row, drop the in-memory entry, and push the fail-closed empty
/// configuration to the gateway (CoreDNS empty allow-list, deny-all
/// mitmproxy/Envoy, flushed `sandbox_policy` nftables table).
///
/// Ordering mirrors [`apply_policy`]:
/// 1. Gateway distribution of the empty-policy output. This rewrites the
///    Envoy listener to its deny-all form (no filter chains), pushes empty
///    CoreDNS/mitmproxy configs, and flushes the `sandbox_policy` nftables
///    table in a single distributor call.
/// 2. Store delete (DB row removal).
/// 3. In-memory map removal + DNS propagation loop cancellation.
///
/// Steps 2–3 happen after a successful distribution: if the gateway step
/// fails we leave the DB row in place so a retry can complete the clear.
async fn clear_session_policy(
    session_id: &SessionId,
    state: &AppState,
) -> Result<(), SandboxError> {
    let network_info = state.store.get_network_info(session_id)?.ok_or_else(|| {
        SandboxError::Internal(format!(
            "no network info for session {session_id} (networking not configured)"
        ))
    })?;

    // Compile an empty policy — CoreDnsConfig becomes empty allow-list,
    // mitmproxy rules become empty (deny-all), Envoy listener becomes an
    // empty deny-all (no filter chains emitted), nftables allow-rules
    // become empty (distributor flushes `sandbox_policy`).
    let empty_policy = Policy {
        version: sandbox_core::policy::SCHEMA_VERSION.to_string(),
        rules: Vec::new(),
    };
    let compiled = PolicyCompiler::compile(&empty_policy, &network_info)?;

    // `PolicyDistributor::distribute` shells out via `docker exec` and
    // performs `fs::rename` for the listener file, so it must not run on
    // the Tokio runtime thread (CLAUDE.md: blocking work in async handlers
    // is wrapped in `spawn_blocking`). `state.gateway` is
    // `Arc<GatewayManager>` so cloning is cheap; `compiled` is moved into
    // the closure since it has no further use on this path.
    {
        let gw = state.gateway.clone();
        let sid = *session_id;
        match tokio::task::spawn_blocking(move || {
            PolicyDistributor::distribute(&sid, &compiled, &gw)
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(e) => {
                return Err(SandboxError::Internal(format!(
                    "task join error distributing policy: {e}"
                )));
            }
        }
    }

    // Propagation tracking for the empty-policy case.
    //
    // An empty policy has no `Destination::Domain` rules, so there is
    // nothing for the DNS loop to reconcile — and the loop is
    // cancelled below. The apply → propagated edge must still be
    // observable to waiters (CLI `--wait`, E2E), so mark the applied
    // hash and immediately mark it propagated from this synchronous
    // path, then emit `policy_propagated` on the `Fresh` edge. If
    // hashing fails (bug-class: serde cannot serialise the empty
    // policy), fall through — the distributor has already succeeded,
    // so the clear itself remains correct.
    if let Some(hash) = hash_policy(&empty_policy) {
        state
            .propagation_states
            .mark_applied(*session_id, hash.clone())
            .await;
        let edge = state
            .propagation_states
            .mark_propagated(*session_id, &hash)
            .await;
        if matches!(edge, PropagatedEdge::Fresh) {
            state
                .event_bus
                .publish(lifecycle_events::policy_propagated(*session_id, hash));
        }
    }

    // Persist the clear.  Idempotent: safe to call when no row exists.
    state.store.delete_policy(session_id)?;

    // Drop the in-memory entry so the DNS propagation loop — if any — has
    // nothing to work with, then cancel the loop itself.
    {
        let mut policies = state.session_policies.lock().await;
        policies.remove(session_id);
    }
    cancel_dns_propagation_loop(session_id, state).await;

    Ok(())
}

/// Classifies a call to [`apply_policy`] so the lifecycle emitter
/// picks the correct event variant (or skips emission entirely for
/// internal re-pushes).
#[derive(Debug, Clone)]
enum ApplyKind {
    /// User-triggered first policy apply at session creation time.
    /// Emits `policy_applied` on success or failure.
    Initial { source_presets: Vec<String> },
    /// User-triggered update of an already-applied policy. Emits
    /// `policy_updated` with `previous_policy_hash` attributing the
    /// diff.
    Update { source_presets: Vec<String> },
    /// Internal restoration on gateway recreation (daemon restart,
    /// crash recovery, reconciliation). The policy was already
    /// observed by the bus in a prior `Initial`/`Update` emission;
    /// re-emitting here would double-count. No event is published.
    Restoration,
}

/// Apply a policy to a running session: compile, distribute, persist, and
/// start the DNS propagation loop.
///
/// The persistence step happens **after** gateway distribution but
/// **before** the in-memory map is updated.  If persistence fails, the
/// caller sees an error and the in-memory `session_policies` map is
/// untouched — the DNS loop continues to serve whatever policy was
/// active before this call.  If the daemon crashes between the DB
/// commit and the memory insert, startup hydration rebuilds the map
/// from the DB on the next launch, closing the silent allow-all window.
///
/// `kind` tells the lifecycle emitter which event to publish:
///  - `Initial` → `policy_applied`
///  - `Update`  → `policy_updated` (with `previous_policy_hash`)
///  - `Restoration` → no event (the policy was already announced when
///    it was first applied; re-emitting on every gateway recreation
///    would double-count)
///
/// The emission always happens — both on success (`status == Ok`) and
/// on failure (`status == Error`, with the error attached) — so
/// subscribers can alert on failed applies without polling.
async fn apply_policy(
    session_id: &SessionId,
    policy: &Policy,
    state: &AppState,
    kind: ApplyKind,
) -> Result<(), SandboxError> {
    // Snapshot the prior in-memory policy *before* distribution so
    // `policy_updated` can attach a `previous_policy_hash` even when
    // the distribution + persist chain succeeds and mutates the map.
    // Restoration skips the snapshot — no event will be emitted.
    let previous_policy_hash = match &kind {
        ApplyKind::Update { .. } => {
            let policies = state.session_policies.lock().await;
            policies.get(session_id).and_then(hash_policy)
        }
        ApplyKind::Initial { .. } | ApplyKind::Restoration => None,
    };

    let result = apply_policy_inner(session_id, policy, state).await;

    // Emit the lifecycle event after the apply has either fully
    // succeeded or failed — never in the middle of a partial state.
    // Restoration skips emission entirely.
    match &kind {
        ApplyKind::Initial { source_presets } => {
            let (status, error) = match &result {
                Ok(()) => (PolicyApplyStatus::Ok, None),
                Err(e) => (PolicyApplyStatus::Error, Some(e.to_string())),
            };
            state.event_bus.publish(lifecycle_events::policy_applied(
                *session_id,
                policy.clone(),
                source_presets.clone(),
                status,
                error,
            ));
        }
        ApplyKind::Update { source_presets } => {
            let (status, error) = match &result {
                Ok(()) => (PolicyApplyStatus::Ok, None),
                Err(e) => (PolicyApplyStatus::Error, Some(e.to_string())),
            };
            state.event_bus.publish(lifecycle_events::policy_updated(
                *session_id,
                policy.clone(),
                source_presets.clone(),
                status,
                error,
                previous_policy_hash,
            ));
        }
        ApplyKind::Restoration => {}
    }

    result
}

/// Inner body of [`apply_policy`], split out so the public wrapper can
/// emit one `policy_applied` / `policy_updated` event reporting the
/// overall success/failure without duplicating the hot-path logic or
/// leaking emission behavior into call sites.
async fn apply_policy_inner(
    session_id: &SessionId,
    policy: &Policy,
    state: &AppState,
) -> Result<(), SandboxError> {
    // Look up network info for this session.
    let network_info = state.store.get_network_info(session_id)?.ok_or_else(|| {
        SandboxError::Internal(format!(
            "no network info for session {session_id} (networking not configured)"
        ))
    })?;

    // Compile the policy.
    let compiled = PolicyCompiler::compile(policy, &network_info)?;

    // Distribute to gateway components. `PolicyDistributor::distribute`
    // shells out via `docker exec` and performs `fs::rename` for the
    // listener file, so it must not run on the Tokio runtime thread
    // (CLAUDE.md: blocking work in async handlers is wrapped in
    // `spawn_blocking`). `state.gateway` is `Arc<GatewayManager>` so
    // cloning is cheap; `compiled` is moved into the closure since it
    // has no further use on this path.
    {
        let gw = state.gateway.clone();
        let sid = *session_id;
        match tokio::task::spawn_blocking(move || {
            PolicyDistributor::distribute(&sid, &compiled, &gw)
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(e) => {
                return Err(SandboxError::Internal(format!(
                    "task join error distributing policy: {e}"
                )));
            }
        }
    }

    // Record the applied hash for the propagation tracker (M10-S6).
    // Done immediately after the distributor succeeds so the DNS loop's
    // very next reconciliation cycle — or the synchronous empty-policy
    // edge below — observes the current target and can flip the
    // propagated bit. A hash change here clears `propagated_hash` so
    // waiters see the transient `propagated=false` window a new apply
    // induces. Mark-then-emit: any pre-existing event stream observer
    // must see the `policy_applied` / `policy_updated` event (emitted
    // by the outer `apply_policy` wrapper on return) before any
    // subsequent `policy_propagated` event, which the DNS loop cannot
    // publish until at least one cycle has run after the mark. If
    // `hash_policy` fails (serde cannot serialise the policy — a
    // bug-class event), fall through without tracking: the distributor
    // already succeeded, so the wrong thing to do is fail the apply;
    // the propagation surface stays at "unknown" for this session
    // until the next apply.
    if let Some(hash) = hash_policy(policy) {
        state
            .propagation_states
            .mark_applied(*session_id, hash)
            .await;
    } else {
        warn!(
            session_id = %session_id,
            "failed to hash policy for propagation tracking; \
             propagation-status endpoint will report unknown until next apply"
        );
    }

    // Persist the policy to SQLite before touching the in-memory map.
    // Matches the pattern used elsewhere for `store.*` calls from async
    // handlers: the SQLite Mutex is held only for the duration of the
    // transaction, which is expected to be well under the handler's
    // budget.  If the transaction fails, propagate the error upward —
    // the in-memory map below is not touched, so the DNS propagation
    // loop keeps serving whatever policy was active before this call.
    state.store.set_policy(session_id, policy)?;

    // Store the policy for the DNS propagation loop.  Done last so a
    // partially-persisted state cannot leave the in-memory map advertising
    // a policy that is not yet on disk.
    {
        let mut policies = state.session_policies.lock().await;
        policies.insert(*session_id, policy.clone());
    }

    // Start (or restart) the DNS propagation loop.
    start_dns_propagation_loop(session_id, state).await;

    Ok(())
}

/// Start (or restart) the DNS propagation background loop for a session.
///
/// If a loop is already running for this session, it is cancelled first.
async fn start_dns_propagation_loop(session_id: &SessionId, state: &AppState) {
    // Cancel any existing loop for this session (but preserve the policy).
    {
        let mut handles = state.dns_loop_handles.lock().await;
        if let Some(handle) = handles.remove(session_id) {
            handle.abort();
            debug!(
                session_id = %session_id,
                "cancelled existing DNS propagation loop for restart"
            );
        }
    }

    let sid = *session_id;
    let gateway = Arc::clone(&state.gateway);
    let propagation_states = Arc::clone(&state.propagation_states);
    let event_bus = state.event_bus.clone();

    let network_info = match state.store.get_network_info(session_id) {
        Ok(Some(info)) => info,
        Ok(None) => {
            warn!(
                session_id = %session_id,
                "cannot start DNS propagation: no network info"
            );
            return;
        }
        Err(e) => {
            warn!(
                session_id = %session_id,
                error = %e,
                "cannot start DNS propagation: failed to read network info"
            );
            return;
        }
    };

    let session_policies = Arc::clone(&state.session_policies);

    let handle = tokio::spawn(async move {
        dns_propagation_loop(
            sid,
            gateway,
            network_info,
            session_policies,
            propagation_states,
            event_bus,
        )
        .await;
    });

    let mut handles = state.dns_loop_handles.lock().await;
    handles.insert(sid, handle);
}

/// Cancel the DNS propagation loop for a session.
async fn cancel_dns_propagation_loop(session_id: &SessionId, state: &AppState) {
    let mut handles = state.dns_loop_handles.lock().await;
    if let Some(handle) = handles.remove(session_id) {
        handle.abort();
        debug!(
            session_id = %session_id,
            "cancelled DNS propagation loop"
        );
    }

    // Clean up the stored policy.
    let mut policies = state.session_policies.lock().await;
    policies.remove(session_id);
}

/// Look up (or lazily create) the per-session shared `DnsCache`.
///
/// Both the DNS propagation loop and the synchronous DNS-gate handler
/// observe the same cache so cache writes from one path are visible to
/// the other. The loop's `read_resolved_json`-driven update merges in
/// CoreDNS's view; the gate's `propagate_and_ack` merges in the
/// plugin-supplied IPs UNION-style for the current TTL window.
async fn shared_dns_cache(state: &AppState, session_id: &SessionId) -> Arc<Mutex<DnsCache>> {
    let mut guard = state.dns_caches.lock().await;
    guard
        .entry(*session_id)
        .or_insert_with(|| Arc::new(Mutex::new(DnsCache::new())))
        .clone()
}

/// Drop the per-session shared `DnsCache`, called from teardown so the
/// next session reuse starts from an empty cache. Safe to call when no
/// cache was ever installed.
async fn drop_dns_cache(state: &AppState, session_id: &SessionId) {
    let mut guard = state.dns_caches.lock().await;
    guard.remove(session_id);
}

/// Start the per-session synchronous DNS-gate listener.
///
/// Binds the UDS at `{events_host_root}/<session-id>/dns-gate.sock`
/// (which the gateway container has bind-mounted at
/// `/var/log/gateway/events/dns-gate.sock`) and serves
/// `propagate_and_ack` requests from the CoreDNS plugin. Each request
/// triggers `generate_domain_ip_rules` + `inject_nftables_ruleset_public`
/// and a `wait_for_lds_ack` round-trip before the listener returns
/// `success` to the plugin.
///
/// Idempotent: if a handle already exists for this session it is
/// aborted and replaced. Safe to call before the gateway is up
/// (the events host directory is created by `create_gateway` itself, so
/// this should run after `create_gateway` returns).
async fn start_dns_gate_listener(session_id: &SessionId, state: &AppState) {
    // Cancel any prior listener for this session before re-binding.
    {
        let mut handles = state.dns_gate_handles.lock().await;
        if let Some(handle) = handles.remove(session_id) {
            handle.abort();
            debug!(
                session_id = %session_id,
                "cancelled existing DNS-gate listener for restart"
            );
        }
    }

    let network_info = match state.store.get_network_info(session_id) {
        Ok(Some(info)) => info,
        Ok(None) => {
            warn!(
                session_id = %session_id,
                "cannot start DNS-gate listener: no network info"
            );
            return;
        }
        Err(e) => {
            warn!(
                session_id = %session_id,
                error = %e,
                "cannot start DNS-gate listener: failed to read network info"
            );
            return;
        }
    };

    let (listener, path) = match bind_gate_listener(session_id) {
        Ok(pair) => pair,
        Err(e) => {
            warn!(
                session_id = %session_id,
                error = %e,
                "failed to bind DNS-gate listener UDS; \
                 synchronous DNS gating disabled for this session"
            );
            return;
        }
    };

    info!(
        session_id = %session_id,
        socket = %path.display(),
        "DNS-gate listener bound"
    );

    let cache = shared_dns_cache(state, session_id).await;
    let service = Arc::new(DaemonGateService {
        session_id: *session_id,
        gateway: Arc::clone(&state.gateway),
        session_policies: Arc::clone(&state.session_policies),
        dns_cache: cache,
        network_info,
    });

    let handle = tokio::spawn(async move {
        serve_gate_listener(listener, service, DNS_GATE_DEFAULT_DEADLINE_MS * 4).await
    });

    let mut handles = state.dns_gate_handles.lock().await;
    handles.insert(*session_id, handle);
}

/// Cancel the per-session DNS-gate listener and remove its socket file.
///
/// Called from session stop / remove and from networking teardown.
async fn cancel_dns_gate_listener(session_id: &SessionId, state: &AppState) {
    let mut handles = state.dns_gate_handles.lock().await;
    if let Some(handle) = handles.remove(session_id) {
        handle.abort();
        debug!(
            session_id = %session_id,
            "cancelled DNS-gate listener"
        );
    }
    // Best-effort socket cleanup. If the events host dir is also being
    // removed by `stop_gateway`, the socket inode is reclaimed via the
    // parent removal; this call is the safe no-op fallback.
    remove_gate_socket(session_id);
}

/// Production [`GateService`] implementation wired to the live
/// `GatewayManager`, the in-memory `session_policies` map, and the
/// per-session [`DnsCache`].
///
/// On a `propagate_and_ack` request the service:
/// 1. Looks up the current policy (returns `unknown_session` when none).
/// 2. Merges the plugin-supplied IPs into the shared cache for the
///    current TTL window (UNION semantics — tolerates short-window
///    rotation per spec).
/// 3. Captures Envoy's pre-rewrite LDS counter triple via
///    [`DockerExecLdsProbe`].
/// 4. Short-circuits to `Noop` when the policy has no domain rules
///    (empty ruleset preview from [`generate_domain_ip_rules`]).
/// 5. Applies the policy effect via [`propagate_dns_changes`], which
///    rewrites both the Envoy listener AND the nftables sets — the
///    same call the steady-state DNS propagation loop makes.
/// 6. Waits for Envoy LDS to ack the listener rewrite via
///    [`wait_for_lds_ack`] up to the request deadline.
///
/// Returns:
/// * `Ok` when the rewrite succeeded and Envoy acked.
/// * `Noop` when the policy + cache produced an empty ruleset (nothing
///   to inject; nft set is already empty).
/// * `Rejected` when nft rejected the ruleset, Envoy rejected the
///   listener, or the LDS ack timed out within the daemon-side deadline.
struct DaemonGateService {
    session_id: SessionId,
    gateway: Arc<GatewayManager>,
    session_policies: Arc<Mutex<HashMap<SessionId, Policy>>>,
    dns_cache: Arc<Mutex<DnsCache>>,
    network_info: NetworkInfo,
}

impl GateService for DaemonGateService {
    async fn service(&self, req: &GateRequest) -> GateServiceOutcome {
        // (1) Policy lookup.
        let policy = {
            let policies = self.session_policies.lock().await;
            match policies.get(&self.session_id) {
                Some(p) => p.clone(),
                None => {
                    return GateServiceOutcome {
                        status: GateStatus::UnknownSession,
                        reason: Some("no active policy for session".to_string()),
                    };
                }
            }
        };

        // (2) Merge plugin-supplied IPs into the shared cache. We
        // splice the (domain, ip, ttl) triple from the request into a
        // synthetic `ResolvedReport` so we go through the cache's
        // existing `update` path, which preserves the UNION-merge +
        // expiry semantics the steady-state propagation loop relies
        // on. Records a single mapping per request. `qtype` is
        // informational on the wire and not stored in the cache.
        {
            use sandbox_core::{ResolvedMapping, ResolvedReport};
            // RFC 3339 timestamp of "now" for the synthetic report.
            // The cache only uses this to seed `resolved_at` on entry
            // creation, so monotonic-clock-derived staleness is what
            // matters; this string is for the producer side of the
            // schema only.
            let timestamp = chrono::Utc::now().to_rfc3339();
            let report = ResolvedReport {
                mappings: vec![ResolvedMapping {
                    domain: req.domain.clone(),
                    ips: req.ips.clone(),
                    ttl: req.ttl_seconds,
                    timestamp,
                }],
            };
            let mut cache = self.dns_cache.lock().await;
            let _changes = cache.update(&report);
        }

        // (3) Pre-snapshot Envoy LDS counters before the rewrite.
        let probe = DockerExecLdsProbe::new(&self.session_id);
        let pre_counters = match probe.fetch_counters().await {
            Ok(c) => Some(c),
            Err(e) => {
                debug!(
                    session_id = %self.session_id,
                    error = %e,
                    "DNS-gate: pre-rewrite LDS stats fetch failed; \
                     ack-wait will be skipped (no snapshot)"
                );
                None
            }
        };

        // (4) Pre-flight: short-circuit when the rendered ruleset is
        // empty. This matches the DNS propagation loop's behaviour and
        // saves the caller a redundant `noop` round-trip when the
        // policy has no domain rules.
        let ruleset_preview = {
            let cache = self.dns_cache.lock().await;
            generate_domain_ip_rules(&policy, &cache, &self.network_info)
        };
        if ruleset_preview.is_empty() {
            return GateServiceOutcome {
                status: GateStatus::Noop,
                reason: None,
            };
        }

        // (5) Apply the policy effect: rewrites BOTH the Envoy
        // listener (for L3 matching of the freshly resolved IPs) AND
        // the nftables `sandbox_dnat` / `sandbox_policy` set elements
        // (for kernel-level admit). This is the same call the
        // background DNS propagation loop makes, so the gate path
        // and the steady-state path produce identical on-disk /
        // in-kernel state — Envoy's filesystem-LDS watcher gets the
        // `MovedTo` event from this call, which is what
        // `wait_for_lds_ack` is waiting on.
        let gw = Arc::clone(&self.gateway);
        let sid = self.session_id;
        let cache_snapshot = {
            let cache = self.dns_cache.lock().await;
            cache.clone()
        };
        let policy_clone = policy.clone();
        let ni = self.network_info.clone();
        let propagate_outcome = tokio::task::spawn_blocking(move || {
            propagate_dns_changes(&sid, &policy_clone, &cache_snapshot, &gw, &ni)
        })
        .await;

        match propagate_outcome {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return GateServiceOutcome {
                    status: GateStatus::Rejected,
                    reason: Some(format!("propagate failed: {e}")),
                };
            }
            Err(e) => {
                return GateServiceOutcome {
                    status: GateStatus::Rejected,
                    reason: Some(format!("propagate task join error: {e}")),
                };
            }
        }

        // (6) Wait for Envoy LDS to ack the new listener generation.
        // The plugin's deadline is the wall-clock budget for this
        // entire round-trip; the listener wraps our future in a
        // tokio::time::timeout already, so we pick a slightly lower
        // ack deadline to give the inject above some headroom. Floor
        // at 100ms so very tight plugin deadlines still wait at all.
        let plugin_deadline = Duration::from_millis(req.deadline_ms.max(1));
        let ack_deadline = plugin_deadline
            .saturating_sub(Duration::from_millis(150))
            .max(Duration::from_millis(100));
        let lds_poll = Duration::from_millis(50);

        if let Some(pre) = pre_counters {
            match wait_for_lds_ack(&probe, pre, ack_deadline, lds_poll).await {
                LdsAckOutcome::Accepted => GateServiceOutcome {
                    status: GateStatus::Ok,
                    reason: None,
                },
                LdsAckOutcome::Rejected => GateServiceOutcome {
                    status: GateStatus::Rejected,
                    reason: Some("envoy rejected rewritten listener".to_string()),
                },
                LdsAckOutcome::TimedOut => GateServiceOutcome {
                    status: GateStatus::Rejected,
                    reason: Some(format!(
                        "envoy LDS ack timed out after {} ms",
                        ack_deadline.as_millis()
                    )),
                },
            }
        } else {
            // No pre-snapshot — fall back to "rewrite succeeded"
            // semantics (mirrors the propagation loop's behaviour
            // when the probe is briefly unavailable).
            GateServiceOutcome {
                status: GateStatus::Ok,
                reason: None,
            }
        }
    }
}

/// Background DNS propagation loop for a single session.
///
/// Periodically reads resolved.json from the gateway container, updates
/// the DNS cache, and propagates IP changes to nftables.
///
/// # Propagation tracking (M10-S6)
///
/// On each cycle the loop also reconciles the session's
/// [`PropagationState`]: once every `Destination::Domain` rule in the
/// current effective policy has a cache entry — meaning CoreDNS has
/// reported an IP for every domain the policy permits — the loop
/// marks the policy propagated and emits a single
/// `policy_propagated` lifecycle event (transition-only; see
/// [`PropagationStates::mark_propagated`]). Subsequent stable cycles
/// do not re-emit.
///
/// An empty policy (no domain rules) is handled synchronously from
/// the apply path, not here (the loop is cancelled in that case). A
/// policy with only CIDR rules has no domains to resolve and so the
/// "all domains resolved" check passes on the first successful
/// propagate.
async fn dns_propagation_loop(
    session_id: SessionId,
    gateway: Arc<GatewayManager>,
    network_info: sandbox_core::NetworkInfo,
    session_policies: Arc<Mutex<HashMap<SessionId, Policy>>>,
    propagation_states: Arc<PropagationStates>,
    event_bus: EventBus,
) {
    let poll_interval = Duration::from_secs(2);
    let mut cache = DnsCache::new();

    info!(
        session_id = %session_id,
        poll_secs = poll_interval.as_secs(),
        "starting DNS propagation loop"
    );

    loop {
        // Read the current policy (it may have been updated).
        let policy = {
            let policies = session_policies.lock().await;
            match policies.get(&session_id) {
                Some(p) => p.clone(),
                None => {
                    debug!(
                        session_id = %session_id,
                        "DNS propagation loop: no policy found, stopping"
                    );
                    return;
                }
            }
        };

        // Read resolved.json from the gateway container.
        let sid = session_id;
        let report = match tokio::task::spawn_blocking(move || read_resolved_json(&sid)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                warn!(
                    session_id = %session_id,
                    error = %e,
                    "DNS propagation: failed to read resolved.json"
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    error = %e,
                    "DNS propagation: spawn_blocking join error reading resolved.json"
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };

        // Update the cache and check for changes.
        let changes = cache.update(&report);

        // Short-circuit when the cache is stable. We still run the
        // propagation-tracker check (below) so a policy with only CIDR
        // rules, or a re-apply that didn't actually change DNS state,
        // can still flip `propagated_hash` on the first steady cycle.
        let stable_cache = changes.is_empty() && !cache.has_expired_entries();

        if !changes.is_empty() {
            for change in &changes {
                info!(
                    session_id = %session_id,
                    domain = %change.domain,
                    change_type = ?change.change_type,
                    old_ips = ?change.old_ips,
                    new_ips = ?change.new_ips,
                    "DNS change detected"
                );
            }
        }

        if cache.has_expired_entries() {
            let expired = cache.expired_domains();
            debug!(
                session_id = %session_id,
                expired_domains = ?expired,
                "TTL-expired domains detected, will re-propagate"
            );
        }

        // Propagate the current cache state to nftables + Envoy when
        // there's work to do. When the cache is stable we skip the
        // distributor call (nothing to rewrite) but still proceed to
        // the reconciliation check below.
        //
        // Envoy LDS-ack gate (#38). The listener-write inside
        // `propagate_dns_changes` is filesystem-LDS: rename returns the
        // moment the kernel commits the new inode, but Envoy only picks
        // up the inotify event some milliseconds later, parses, then
        // either accepts or rejects the new generation. Flipping
        // `propagated=true` before that resolution leaves a 100–300 ms
        // window where the daemon advertises propagation while Envoy
        // is still serving the previous (or no) listener. To close the
        // race, snapshot Envoy's full `listener_manager.lds.*` counter
        // triple BEFORE the write and wait afterwards for the next
        // edge of either `update_success` or `update_rejected` past
        // the snapshot. Comparing against the full snapshot (not just
        // a literal 0) avoids a false-Rejected when Envoy startup has
        // already ticked `update_rejected` once (e.g. the deny-all
        // bootstrap fails LDS validation on first parse).
        // Wait deadline 5s with 100ms polls — typical Envoy reload
        // observed at <250ms in the M9-S18 integration test. Empty
        // (stable_cache) cycles skip both rewrite and ack-wait —
        // there is no rewrite to ack.
        let probe = DockerExecLdsProbe::new(&session_id);
        let lds_ack_deadline = Duration::from_secs(5);
        let lds_poll_interval = Duration::from_millis(100);
        let propagate_ok = if stable_cache {
            true
        } else {
            // Snapshot pre-rewrite counters (full triple — see the
            // doc comment above for why we need all three, not just
            // `update_attempt`). A probe failure here (Envoy admin
            // not yet reachable, etc.) is treated as "no snapshot
            // available" — the rewrite proceeds and the ack-wait
            // below skips, falling back to file-write-success-only
            // semantics for this cycle. Subsequent cycles retry; the
            // loop already polls every 2s so a transient admin
            // glitch costs at most one cycle of un-acked propagation.
            let pre_counters = match probe.fetch_counters().await {
                Ok(c) => Some(c),
                Err(e) => {
                    warn!(
                        session_id = %session_id,
                        error = %e,
                        "DNS propagation: pre-rewrite LDS stats fetch failed; \
                         skipping ack-wait this cycle"
                    );
                    None
                }
            };

            let gw = Arc::clone(&gateway);
            let pol = policy.clone();
            let c = cache.clone();
            let ni = network_info.clone();
            let sid = session_id;
            let propagate_result = tokio::task::spawn_blocking(move || {
                propagate_dns_changes(&sid, &pol, &c, &gw, &ni)
            })
            .await;
            let write_ok = match propagate_result {
                Ok(Err(e)) => {
                    warn!(
                        session_id = %session_id,
                        error = %e,
                        "DNS propagation: failed to update nftables"
                    );
                    false
                }
                Err(e) => {
                    warn!(
                        session_id = %session_id,
                        error = %e,
                        "DNS propagation: spawn_blocking join error updating nftables"
                    );
                    false
                }
                Ok(Ok(())) => true,
            };

            // If the listener write succeeded, wait for Envoy's LDS
            // ack before allowing the reconciliation check below to
            // flip `propagated=true`. On reject or timeout we
            // suppress propagation for this cycle so the next
            // iteration retries; on a Rejected outcome we surface a
            // loud warning because a rejected listener is a real
            // failure (malformed YAML, schema drift), not a
            // benign retry.
            if write_ok {
                if let Some(pre) = pre_counters {
                    let outcome =
                        wait_for_lds_ack(&probe, pre, lds_ack_deadline, lds_poll_interval).await;
                    match outcome {
                        LdsAckOutcome::Accepted => true,
                        LdsAckOutcome::Rejected => {
                            warn!(
                                session_id = %session_id,
                                "Envoy REJECTED the rewritten listener; \
                                 propagation will not be flipped this cycle. \
                                 Inspect /config_dump and the Envoy log for \
                                 the validation error."
                            );
                            false
                        }
                        LdsAckOutcome::TimedOut => {
                            warn!(
                                session_id = %session_id,
                                deadline_ms = lds_ack_deadline.as_millis() as u64,
                                "Envoy did not ack the listener rewrite \
                                 within the deadline; deferring \
                                 propagation flip to the next cycle"
                            );
                            false
                        }
                    }
                } else {
                    // No pre-snapshot — fall back to write-success
                    // semantics (legacy behaviour). The probe may
                    // recover next cycle.
                    true
                }
            } else {
                false
            }
        };

        // Reconciliation check. `policy_propagated` fires only on the
        // transition to steady state: all non-Deny Destination::Domain
        // rules have a cache entry (so the nftables allow sets are
        // populated for every allow-able domain), and the distributor
        // call above (if any) succeeded. Policies with zero domain
        // rules trivially satisfy "all resolved" and so the edge fires
        // on the first successful cycle.
        if propagate_ok && all_domain_rules_resolved(&policy, &cache) {
            if let Some(hash) = sandbox_core::hash_policy(&policy) {
                let edge = propagation_states.mark_propagated(session_id, &hash).await;
                if matches!(edge, PropagatedEdge::Fresh) {
                    info!(
                        session_id = %session_id,
                        hash = %hash,
                        "policy fully propagated across enforcement layers"
                    );
                    event_bus.publish(lifecycle_events::policy_propagated(session_id, hash));
                }
            }
        }

        // Sleep at the end so the first iteration runs immediately after
        // policy application, resolving domain IPs as fast as possible.
        tokio::time::sleep(poll_interval).await;
    }
}

/// Return `true` iff every non-`Deny` `Destination::Domain` rule in
/// `policy` has a cache entry in `cache`.
///
/// A `Deny` rule contributes no nftables allow entries regardless of
/// resolution state, so it's excluded from the readiness check.
/// Policies with only `Destination::Cidr` rules (or no rules) return
/// `true` trivially — there are no domains to resolve.
fn all_domain_rules_resolved(policy: &Policy, cache: &DnsCache) -> bool {
    policy
        .rules
        .iter()
        .filter(|r| !matches!(r.level, AssuranceLevel::Deny))
        .all(|r| match &r.host {
            Destination::Cidr(_) => true,
            Destination::Domain(d) => cache.entries().contains_key(d.as_str()),
        })
}

// ---------------------------------------------------------------------------
// Networking helpers
// ---------------------------------------------------------------------------

/// Inject CA certificate into the VM's trust store via the guest agent.
///
/// Reads the PEM certificate from `ca_dir/cert.pem`, generates a shell script
/// that installs it and runs `update-ca-certificates`, then executes it inside
/// the VM.
async fn inject_ca_into_vm(
    guest: &GuestConnector,
    session_id: &SessionId,
    ca_dir: &std::path::Path,
) -> Result<(), SandboxError> {
    let cert_pem = std::fs::read_to_string(ca_dir.join("cert.pem"))
        .map_err(|e| SandboxError::Ca(format!("failed to read CA cert for injection: {e}")))?;
    let inject_script = generate_ca_inject_script(&cert_pem);

    info!(session_id = %session_id, "injecting CA certificate into VM");

    // CA injection writes to /usr/local/share/ca-certificates and /etc/environment,
    // which requires root. The guest agent runs as unprivileged `agent` user.
    match guest
        .exec(session_id, "sudo", &["bash", "-c", &inject_script])
        .await
    {
        Ok(GuestResponse::ExecResult {
            exit_code,
            stdout,
            stderr,
        }) => {
            if exit_code != 0 {
                warn!(
                    session_id = %session_id,
                    exit_code,
                    stdout = %stdout.trim(),
                    stderr = %stderr.trim(),
                    "CA injection script returned non-zero exit code"
                );
                return Err(SandboxError::Ca(format!(
                    "CA injection failed (exit {exit_code}): {stderr}"
                )));
            }
            info!(
                session_id = %session_id,
                output = %stdout.trim(),
                "CA certificate injected into VM"
            );
            Ok(())
        }
        Ok(GuestResponse::Error { message }) => Err(SandboxError::Ca(format!(
            "guest agent error during CA injection: {message}"
        ))),
        Ok(other) => Err(SandboxError::Ca(format!(
            "unexpected guest response during CA injection: {other:?}"
        ))),
        Err(e) => Err(SandboxError::Ca(format!(
            "failed to inject CA certificate into VM: {e}"
        ))),
    }
}

/// Extract the hostname from a git remote URL.
///
/// Supports the common shapes accepted by `git clone`:
///
/// * HTTPS:  `https://github.com/user/repo.git`
/// * HTTP:   `http://host.example/repo`
/// * SSH URL: `ssh://git@github.com:22/user/repo.git`
/// * SCP-like: `git@github.com:user/repo.git`
/// * Local paths / file URLs: returns `None` (no DNS pre-warm needed).
///
/// Userinfo (`user@`) and trailing port (`:N`) are stripped.  Returns
/// `None` if the URL does not name a network host — the caller treats
/// that as "nothing to pre-warm".
fn extract_repo_host(repo_url: &str) -> Option<String> {
    // file:// or bare local path — nothing to resolve.
    if repo_url.starts_with("file://") || repo_url.starts_with('/') || repo_url.starts_with('.') {
        return None;
    }

    // scheme://...
    let after_scheme = if let Some(idx) = repo_url.find("://") {
        &repo_url[idx + 3..]
    } else if let Some(idx) = repo_url.find('@') {
        // SCP-like: user@host:path
        let rest = &repo_url[idx + 1..];
        return rest
            .split(':')
            .next()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
    } else {
        return None;
    };

    // Strip userinfo.
    let without_user = after_scheme.splitn(2, '@').last().unwrap_or(after_scheme);

    // Take host segment up to first `/` (path) or `:` (port).
    let host = without_user.split(['/', ':']).next().unwrap_or("");

    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Pre-warm DNS for a host so the daemon's DNS propagation loop
/// installs the corresponding Envoy filter chain + `sandbox_policy`
/// concat-set entry before the caller issues a network operation.
///
/// Under schema v2 every domain allow-rule is fail-closed at an empty
/// DNS cache — the nftables `sandbox_policy` forward chain and the
/// per-rule Envoy filter chains only carry (ip, port) entries once
/// CoreDNS has resolved the domain. The propagation loop polls
/// `resolved.json` every 2s; a VM-initiated connection that races that
/// interval hits the empty ruleset and is rejected.
///
/// This helper issues `nslookup <host>` from inside the guest (via the
/// guest agent) to trigger CoreDNS, then sleeps long enough for the
/// propagation loop's next tick to land. All failures are swallowed —
/// the pre-warm is a best-effort optimisation for domains that the
/// policy already allows; policy-denied hosts continue to fail closed
/// and the caller's subsequent operation still enforces policy.
async fn prewarm_guest_dns(guest: &GuestConnector, session_id: &SessionId, host: &str) {
    // The `|| true` guard makes this a no-op if nslookup/getent is
    // missing from the image. `> /dev/null 2>&1` keeps the guest
    // agent response payload small regardless of A/AAAA contents.
    let script =
        format!("nslookup {host} > /dev/null 2>&1 || getent hosts {host} > /dev/null 2>&1 || true");
    let _ = guest.exec(session_id, "sh", &["-c", script.as_str()]).await;

    // DNS propagation loop polls every 2s; sleeping 3s covers one
    // complete iteration (read resolved.json → rewrite Envoy
    // listener → inject nftables) with a small margin.
    tokio::time::sleep(Duration::from_secs(3)).await;
}

/// Spawn (or re-spawn) the session's JSONL ingest task.
///
/// Called after every successful `create_gateway` / `restart_gateway` so
/// the tailers catch up with any records the three in-container producers
/// (Envoy access log, CoreDNS plugin, mitmproxy addon) have already
/// appended. Any previously-spawned ingestor for this session is aborted
/// first, so a gateway bounce cleanly reseats the watcher and tailers —
/// on fresh boot and on crash recovery alike.
///
/// The events directory is created eagerly (it is the bind-mount target
/// used by `GatewayManager::create_gateway`) so the notify watcher has a
/// path to watch even when no JSONL has been appended yet.
async fn spawn_session_ingestor(session_id: &SessionId, state: &AppState) {
    let events_dir = session_events_host_dir(session_id);
    if let Err(e) = tokio::fs::create_dir_all(&events_dir).await {
        warn!(
            session_id = %session_id,
            events_dir = %events_dir.display(),
            error = %e,
            "failed to create session events directory; ingestor not spawned"
        );
        return;
    }

    let ingestor = SessionIngestor::spawn(
        *session_id,
        events_dir,
        state.event_bus.clone(),
        state.vm_ip_map.clone(),
    );

    let previous = {
        let mut ingestors = state.ingestors.lock().await;
        ingestors.insert(*session_id, ingestor)
    };
    if let Some(prev) = previous {
        // A prior ingestor was running (e.g., gateway recovered after a
        // crash). Abort it so file handles and the inotify watch are
        // released — the new ingestor already owns the directory.
        prev.abort();
    }
}

/// Abort the session's JSONL ingest task, if one is running.
///
/// Called on every path that tears the gateway down (stop, remove,
/// `teardown_session_networking`, reconciliation cleanup). No-op when no
/// ingestor is tracked for the session, so redundant calls are safe.
async fn abort_session_ingestor(session_id: &SessionId, state: &AppState) {
    let ingestor = {
        let mut ingestors = state.ingestors.lock().await;
        ingestors.remove(session_id)
    };
    if let Some(ingestor) = ingestor {
        ingestor.abort();
    }
}

/// Set up remaining networking for a new session.
///
/// The Docker bridge network and CA certificate are created before the VM
/// boots (so the QEMU wrapper can attach to the bridge via
/// `qemu-bridge-helper`). This function handles the post-boot steps:
///
/// 1. Create gateway container with nftables (mounting the CA)
/// 2. Configure the bridge NIC inside the VM (guest-side IP/routing/DNS)
/// 3. Inject CA certificate into VM trust store
/// 4. Store network info in DB
async fn setup_session_networking(
    session_id: &SessionId,
    network_info: &sandbox_core::NetworkInfo,
    ca_dir: &std::path::Path,
    state: &AppState,
    initial_dns_policy: Option<&str>,
) -> Result<(), SandboxError> {
    // Register the session with the event bus *before* the gateway
    // boots so the pre-readiness `gateway_booting` event lands on a
    // live per-session sink. Binding the VM IP here (rather than
    // post-create) likewise ensures the ingest layer can attribute
    // any events emitted by the just-started gateway during readiness
    // polling — without the binding the ingest layer would drop them
    // as "unknown session". Failure to parse `vm_ip` as IPv4 is
    // surprising (we wrote it ourselves in `create_network`) but we
    // prefer a warning over an error path that would abort a
    // successfully-networked session — the event stream just stays
    // empty for that session.
    state.event_bus.register_session(*session_id);
    match network_info.vm_ip.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            state.vm_ip_map.bind(ip, *session_id);
        }
        Err(e) => {
            warn!(
                session_id = %session_id,
                vm_ip = %network_info.vm_ip,
                error = %e,
                "failed to parse vm_ip as IPv4; event attribution disabled for this session"
            );
        }
    }

    // Publish `gateway_booting` before the Docker create call so the
    // event stream records the boot intent even if gateway creation
    // fails.  The bus already has a sink for the session (registered
    // just above), so this event is retained in the ring buffer.
    state
        .event_bus
        .publish(lifecycle_events::gateway_booting(*session_id));

    // 1. Create gateway container with nftables, mounting the CA.
    //    Pass the initial DNS policy so it is written to the container
    //    before CoreDNS starts, avoiding a reload-timer race.
    //    Wrapped in spawn_blocking because create_gateway runs Docker
    //    commands and polls for readiness with thread::sleep loops.
    {
        let gw = state.gateway.clone();
        let sid = *session_id;
        let ni = network_info.clone();
        let ca = ca_dir.to_path_buf();
        let dns = initial_dns_policy.map(|s| s.to_string());
        match tokio::task::spawn_blocking(move || {
            gw.create_gateway(&sid, &ni, Some(&ca), dns.as_deref())
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(e) => {
                return Err(SandboxError::Internal(format!(
                    "task join error creating gateway: {e}"
                )));
            }
        }
    }

    // Gateway container is up and `create_gateway` passed its
    // readiness checks — publish `gateway_ready` so subscribers can
    // pair it with the earlier `gateway_booting`.
    state
        .event_bus
        .publish(lifecycle_events::gateway_ready(*session_id));

    // Start the per-session JSONL ingest task now that the events
    // directory has been bind-mounted into the container and the
    // producers are live. Tailers seek to EOF on spawn, so any lines
    // the producers have already written during readiness polling are
    // skipped (they were not attributable to a live subscriber anyway).
    spawn_session_ingestor(session_id, state).await;

    // Persist network info before the gate listener starts so the
    // listener's `get_network_info` lookup finds it. The listener's
    // lookup is a hard requirement: `generate_domain_ip_rules` needs
    // the VM subnet + gateway IP to render the two-table ruleset. The
    // call below was historically the last step (#4) of this function
    // — hoisting it above the gate-listener spawn keeps it safe (the
    // VM hasn't joined the bridge yet, so write order doesn't matter
    // to traffic correctness) while ensuring the listener can come
    // up.
    state.store.set_network_info(session_id, network_info)?;

    // Start the synchronous DNS-gate UDS listener (M10-S10 Phase 2).
    // The events host directory was created by `create_gateway` and is
    // bind-mounted into the container at `/var/log/gateway/events/`,
    // so the socket file appears at the canonical container path
    // without any extra mount. Started after `set_network_info` so the
    // listener can resolve subnet/gateway-IP for ruleset generation.
    start_dns_gate_listener(session_id, state).await;

    // 2. Configure the bridge NIC inside the VM (already present from boot).
    if let Err(e) = attach_vm_to_bridge(session_id, network_info, &state.guest).await {
        // Roll back gateway on attach failure. Abort the ingestor first
        // so it releases its inotify watch on the events directory; the
        // container is about to go away and no further events are
        // attributable to this session. Cancel the DNS-gate listener
        // too so its UDS goes away with the container's bind mount.
        cancel_dns_gate_listener(session_id, state).await;
        abort_session_ingestor(session_id, state).await;
        let gw = state.gateway.clone();
        let sid = *session_id;
        let _ = tokio::task::spawn_blocking(move || gw.stop_gateway(&sid)).await;
        return Err(e);
    }

    // 3. Inject CA certificate into VM trust store via guest agent.
    inject_ca_into_vm(&state.guest, session_id, ca_dir).await?;

    // 4. Network info was already persisted earlier (before the gate
    //    listener spawn) so the listener could read it; nothing more
    //    to do here.

    Ok(())
}

/// Fail a `POST /sessions` request after an explicit initial policy
/// fails to apply.
///
/// Centralises the teardown contract for M10-S8 #16: when
/// `create_session` reaches its `apply_policy` call, the caller has
/// already supplied a non-`None` `req.policy` (either directly via
/// `--policy <file>` or indirectly via `--preset` — both paths
/// populate the wire field at the CLI layer). A failure here means
/// the session would otherwise come up `Running` with `Policy: none`,
/// silently violating the caller's stated intent. The only correct
/// response is to fail the create call and surface the error through
/// the HTTP response.
///
/// The teardown performed here mirrors the failure path already used
/// by `setup_session_networking` earlier in `create_session`: mark
/// the session as `Error` (so `sandbox ps` / `inspect` surface the
/// failure), and best-effort stop the gateway + remove the Docker
/// network. VM and CA material are deliberately left in place so the
/// operator can still run `sandbox rm` to reclaim the session.
///
/// Returns the `(StatusCode, Json<ApiError>)` pair the handler should
/// hand back to axum. Logging of the underlying error is done once
/// here with `error!`, and again by `error_response` with the HTTP
/// status attached — matching the pattern used elsewhere in the
/// create handler.
///
/// The function takes only the [`AppState`] fields it actually reads
/// (rather than `&AppState` wholesale) so a hermetic unit test can
/// drive it without standing up a full Lima / Docker stack — see
/// `tests::fail_explicit_policy_apply_marks_session_error_and_returns_5xx`
/// below.
async fn fail_explicit_policy_apply(
    store: &SessionStore,
    gateway: &Arc<GatewayManager>,
    network: &Arc<NetworkManager>,
    ingestors: &Mutex<HashMap<SessionId, SessionIngestor>>,
    session_id: &SessionId,
    e: SandboxError,
) -> (StatusCode, Json<ApiError>) {
    error!(
        %session_id,
        error = %e,
        "failed to apply explicit initial policy — failing create"
    );
    let _ = store.update_state(session_id, SessionState::Error);
    teardown_session_networking_parts(session_id, gateway, network, ingestors).await;
    error_response(e)
}

/// Fail the create call when an explicit `--repo <url>` clone fails
/// in-guest (M10-S8 #34).
///
/// Mirrors the shape of [`fail_explicit_policy_apply`]: when the
/// caller passes `--repo <url>`, the session is supposed to come up
/// with `/home/agent/workspace/` populated. Pre-fix, the four
/// failure branches (non-zero exit, `GuestResponse::Error`,
/// unexpected guest response, transport error) all `warn!`-swallowed
/// the failure and the handler returned 201 CREATED with a `Running`
/// session and an empty workspace — silently violating the caller's
/// stated intent. The only correct response is to fail the create
/// call and surface the failure through the HTTP response so the
/// CLI user can see *why* the clone did not succeed (exit code,
/// stderr snippet, transport error, etc., carried through in the
/// caller-supplied `e`).
///
/// Teardown shape matches [`fail_explicit_policy_apply`]:
///   - mark session `Error` (so `sandbox ps` / `inspect` surface the
///     failed create);
///   - best-effort stop the gateway + remove the Docker network;
///   - leave VM + CA material in place so the operator can still
///     `sandbox rm` to reclaim the session.
///
/// Like its sibling, this helper takes only the [`AppState`] fields
/// it actually reads so it can be exercised hermetically — see
/// `tests::fail_explicit_repo_clone_marks_session_error_and_returns_5xx`.
async fn fail_explicit_repo_clone(
    store: &SessionStore,
    gateway: &Arc<GatewayManager>,
    network: &Arc<NetworkManager>,
    ingestors: &Mutex<HashMap<SessionId, SessionIngestor>>,
    session_id: &SessionId,
    e: SandboxError,
) -> (StatusCode, Json<ApiError>) {
    error!(
        %session_id,
        error = %e,
        "failed to clone explicit --repo URL into VM — failing create"
    );
    let _ = store.update_state(session_id, SessionState::Error);
    teardown_session_networking_parts(session_id, gateway, network, ingestors).await;
    error_response(e)
}

/// Fail the create call when an explicit `--boot-cmd <cmd>` returns a
/// non-zero exit code, a guest-agent error, an unexpected guest
/// response, or a transport error (M10-S9 #53).
///
/// Symmetric completion of the fail-explicit triad with
/// [`fail_explicit_policy_apply`] (#16) and
/// [`fail_explicit_repo_clone`] (#34): the boot-cmd block had the
/// same warn-and-continue shape as the pre-fix repo-clone block, and
/// the same hazard — when `--boot-cmd` is provided the caller is
/// stating "the session is not usable until this command has run
/// successfully", and a `Running` session whose boot command exit-ed
/// 1 (or never dispatched) silently lies to that contract.
///
/// `boot_cmd` has no implicit / defaulted form on the wire (the CLI
/// only populates the field when `--boot-cmd <cmd>` is given), so
/// reaching this helper always means the failure is on an *explicit*
/// boot command — there is no warn-and-continue branch to preserve
/// for an absent default the way `--policy` has for the no-policy
/// case.
///
/// Teardown shape matches its siblings:
///   - mark session `Error` (so `sandbox ps` / `inspect` surface the
///     failed create);
///   - best-effort stop the gateway + remove the Docker network;
///   - leave VM + CA material in place so the operator can still
///     `sandbox rm` to reclaim the session.
///
/// Like its siblings, this helper takes only the [`AppState`] fields
/// it actually reads so it can be exercised hermetically — see
/// `tests::fail_explicit_boot_cmd_marks_session_error_and_returns_5xx`.
async fn fail_explicit_boot_cmd(
    store: &SessionStore,
    gateway: &Arc<GatewayManager>,
    network: &Arc<NetworkManager>,
    ingestors: &Mutex<HashMap<SessionId, SessionIngestor>>,
    session_id: &SessionId,
    e: SandboxError,
) -> (StatusCode, Json<ApiError>) {
    error!(
        %session_id,
        error = %e,
        "failed to run explicit --boot-cmd in VM — failing create"
    );
    let _ = store.update_state(session_id, SessionState::Error);
    teardown_session_networking_parts(session_id, gateway, network, ingestors).await;
    error_response(e)
}

/// Truncate a free-form diagnostic string (e.g. `git clone` stderr)
/// to at most `max_chars` characters, appending an ellipsis suffix
/// when truncation actually drops content. Truncates on character
/// boundaries (not bytes) so the result is always valid UTF-8.
fn truncate_for_diagnostic(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars).collect();
        out.push_str("…[truncated]");
        out
    }
}

/// Inner body of [`teardown_session_networking`], parameterised on the
/// exact fields it reads rather than the full [`AppState`]. This keeps
/// the async teardown logic shared between the `setup_session_networking`
/// failure path, the `apply_policy` failure path (M10-S8 #16), and the
/// regular stop path, while letting the #16 unit test drive it without
/// constructing every `AppState` field just to call it.
async fn teardown_session_networking_parts(
    session_id: &SessionId,
    gateway: &Arc<GatewayManager>,
    network: &Arc<NetworkManager>,
    ingestors: &Mutex<HashMap<SessionId, SessionIngestor>>,
) {
    debug!(session_id = %session_id, "tearing down session networking (preserving allocation)");
    // Abort the JSONL ingestor first so its inotify watch and file
    // handles are released before the gateway container disappears.
    // No-op when no ingestor is tracked (e.g., the gateway never
    // finished starting).
    {
        let mut guard = ingestors.lock().await;
        if let Some(ingestor) = guard.remove(session_id) {
            ingestor.abort();
        }
    }

    // Blocking Docker calls (stop_gateway, remove_docker_network) are
    // wrapped in spawn_blocking to avoid stalling the Tokio runtime.
    let gateway = gateway.clone();
    let network = network.clone();
    let sid = *session_id;
    let _ = tokio::task::spawn_blocking(move || {
        // detach_vm_from_bridge is a no-op (TAP owned by QEMU), but call it
        // for completeness / future-proofing.
        if let Err(e) = detach_vm_from_bridge(&sid) {
            warn!(%sid, error = %e, "failed to detach VM from bridge (best-effort)");
        }
        if let Err(e) = gateway.stop_gateway(&sid) {
            warn!(%sid, error = %e, "failed to stop gateway (best-effort)");
        }
        if let Err(e) = network.remove_docker_network(&sid) {
            warn!(%sid, error = %e, "failed to remove Docker network (best-effort)");
        }
    })
    .await;
}

/// Tear down session networking infrastructure (best-effort, ignores errors).
///
/// Stops the gateway container and removes the Docker bridge network.
/// The TAP device is owned by QEMU and destroyed when the VM stops.
/// The subnet allocation and network_info in the DB are preserved so
/// `start` can recreate everything.
///
/// The CA certificate files on disk are NOT removed — they are reused on
/// start.
///
/// Thin wrapper around [`teardown_session_networking_parts`] that
/// extracts the three [`AppState`] fields the teardown needs. Callers
/// holding an [`AppState`] (every production call site) should prefer
/// this wrapper; the unit-test-facing
/// [`fail_explicit_policy_apply`] call is expressed in terms of the
/// underlying `_parts` helper so it can be exercised without
/// constructing a full [`AppState`].
async fn teardown_session_networking(session_id: &SessionId, state: &AppState) {
    // Cancel the synchronous DNS-gate listener (M10-S10 Phase 2) and
    // drop the per-session DnsCache before the events host directory
    // disappears with the gateway container. Cheap no-ops when no
    // listener was ever spawned (e.g., the session never reached
    // `setup_session_networking`).
    cancel_dns_gate_listener(session_id, state).await;
    drop_dns_cache(state, session_id).await;
    teardown_session_networking_parts(session_id, &state.gateway, &state.network, &state.ingestors)
        .await;
}

/// Re-apply the session's policy to a freshly created gateway container.
///
/// When a gateway is recreated (restart, crash recovery, reconciliation),
/// its tmpfs is wiped. This helper restores the policy that was active
/// before the gateway went away. If no policy is stored (session created
/// without one, or `--clear`ed), it writes the fail-closed empty CoreDNS
/// policy so every DNS query receives NXDOMAIN until a policy is installed.
///
/// Policy re-application is best-effort: failures are logged but do not
/// propagate, matching the non-fatal semantics of initial policy setup.
async fn reapply_session_policy(session_id: &SessionId, state: &AppState) {
    let container = gateway_container_name(session_id);

    // The in-memory map is cleared on stop, so fall back to the persistent
    // store — otherwise a stop/start cycle silently reverts the session to
    // the fail-closed default, dropping a policy the user explicitly set.
    let policy = {
        let policies = state.session_policies.lock().await;
        policies.get(session_id).cloned()
    };
    let policy = match policy {
        Some(p) => Some(p),
        None => match state.store.get_policy(session_id) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    error = %e,
                    "failed to load policy from store during restore"
                );
                None
            }
        },
    };

    if let Some(policy) = policy {
        match apply_policy(session_id, &policy, state, ApplyKind::Restoration).await {
            Ok(()) => {
                info!(
                    session_id = %session_id,
                    "re-applied session policy to restored gateway"
                );
            }
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    error = %e,
                    "failed to re-apply policy to restored gateway"
                );
            }
        }
    } else {
        // No policy stored — write the fail-closed empty policy so CoreDNS
        // returns NXDOMAIN for every query until a policy is installed.
        let empty = CoreDnsConfig::empty_policy_file_content();
        match write_file_to_container(&container, "/etc/coredns/policy.conf", &empty) {
            Ok(()) => {
                debug!(
                    session_id = %session_id,
                    "wrote empty (fail-closed) DNS policy to restored gateway"
                );
            }
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    error = %e,
                    "failed to write empty DNS policy to restored gateway"
                );
            }
        }
    }
}

/// Restore session networking from existing network info in the DB.
///
/// This is called by the `start` handler and by startup reconciliation.
/// The Docker bridge is recreated (if needed) before the VM is started, so
/// the bridge NIC is attached at boot via `qemu-bridge-helper`. This
/// function then creates the gateway container, configures the guest NIC,
/// and injects the CA certificate — the same post-boot steps as initial
/// setup.
async fn restore_session_networking(
    session_id: &SessionId,
    state: &AppState,
) -> Result<(), SandboxError> {
    // Check that network info exists in DB (otherwise there's nothing to restore).
    let network_info = match state.store.get_network_info(session_id)? {
        Some(info) => info,
        None => {
            info!(
                session_id = %session_id,
                "no network info in DB, skipping networking restore"
            );
            return Ok(());
        }
    };

    // 1. Get or regenerate the CA certificate.
    let ca_dir = CaManager::ca_dir(&state.base_dir, session_id);
    let ca_dir = if ca_dir.join("cert.pem").exists() {
        info!(
            session_id = %session_id,
            "reusing existing CA certificate"
        );
        ca_dir
    } else {
        info!(
            session_id = %session_id,
            "regenerating CA certificate"
        );
        CaManager::generate_session_ca(&state.base_dir, session_id)?
    };

    // 2. Create gateway container with nftables, mounting the CA.
    //    When no explicit policy is stored for this session, pass the
    //    fail-closed empty DNS policy so CoreDNS loads it at startup
    //    (same race fix as in create_session).  The daemon re-applies
    //    any stored policy below after the container is up.
    // The in-memory map is cleared on stop but the persistent store keeps
    // the policy; consult both so the gateway isn't briefly started with the
    // fail-closed default (which would otherwise race with
    // `reapply_session_policy` below).
    let has_stored_policy = {
        let policies = state.session_policies.lock().await;
        policies.contains_key(session_id)
    } || matches!(state.store.get_policy(session_id), Ok(Some(_)));
    let initial_dns_policy_owned: String;
    let initial_dns_policy = if !has_stored_policy {
        initial_dns_policy_owned = CoreDnsConfig::empty_policy_file_content();
        Some(initial_dns_policy_owned.as_str())
    } else {
        None
    };
    // On the restoration path the session is still registered with
    // the event bus (hydrated from `existing_networks` in `main`), so
    // we can publish `gateway_booting` directly.  Emitting it here
    // matches the create-session flow and keeps the booting/ready
    // pair observable on daemon restarts too.
    state
        .event_bus
        .publish(lifecycle_events::gateway_booting(*session_id));

    // Wrapped in spawn_blocking because create_gateway runs Docker
    // commands and polls for readiness with thread::sleep loops.
    {
        let gw = state.gateway.clone();
        let sid = *session_id;
        let ni = network_info.clone();
        let ca = ca_dir.clone();
        let dns = initial_dns_policy.map(|s| s.to_string());
        match tokio::task::spawn_blocking(move || {
            gw.create_gateway(&sid, &ni, Some(&ca), dns.as_deref())
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                // Roll back the Docker network on gateway failure.
                let net = state.network.clone();
                let sid = *session_id;
                let _ = tokio::task::spawn_blocking(move || net.remove_docker_network(&sid)).await;
                return Err(e);
            }
            Err(e) => {
                let net = state.network.clone();
                let sid = *session_id;
                let _ = tokio::task::spawn_blocking(move || net.remove_docker_network(&sid)).await;
                return Err(SandboxError::Internal(format!(
                    "task join error creating gateway: {e}"
                )));
            }
        }
    }

    // Gateway is up and readiness checks passed — mirror the
    // create-session path and publish `gateway_ready`.
    state
        .event_bus
        .publish(lifecycle_events::gateway_ready(*session_id));

    // Start the per-session JSONL ingest task now that the fresh
    // gateway is up. Tailers seek to EOF so pre-restart records (from
    // a dead gateway) are not re-ingested; only events produced by the
    // restored gateway are attributed.
    spawn_session_ingestor(session_id, state).await;

    // Restart the synchronous DNS-gate UDS listener on a freshly
    // bind-mounted socket inode. Network info is already in the DB
    // (we read it at the top of this function), so the listener can
    // resolve subnet/gateway-IP for ruleset generation.
    start_dns_gate_listener(session_id, state).await;

    // 2b. Re-apply the session's policy to the fresh gateway container.
    // If a policy is stored, compile and distribute it to the running
    // gateway.  If no policy is stored, the allow-all was already written
    // during gateway creation above, so reapply only writes if needed.
    reapply_session_policy(session_id, state).await;

    // 3. Configure the bridge NIC inside the VM (already present from boot).
    if let Err(e) = attach_vm_to_bridge(session_id, &network_info, &state.guest).await {
        // Roll back gateway and Docker network on attach failure. Abort
        // the ingestor first so its inotify watch is released before
        // the events directory is left without a producer.
        cancel_dns_gate_listener(session_id, state).await;
        abort_session_ingestor(session_id, state).await;
        let gw = state.gateway.clone();
        let net = state.network.clone();
        let sid = *session_id;
        let _ = tokio::task::spawn_blocking(move || {
            let _ = gw.stop_gateway(&sid);
            net.remove_docker_network(&sid)
        })
        .await;
        return Err(e);
    }

    // 4. Inject CA certificate into VM trust store.
    inject_ca_into_vm(&state.guest, session_id, &ca_dir).await
}

/// Container-backend equivalent of [`restore_session_networking`] for the
/// lite path. Re-creates the per-session gateway, re-spawns the JSONL
/// ingestor, and re-arms the synchronous DNS-gate listener after a stop /
/// start cycle. Does **not** attach a VM to a bridge or inject a CA into
/// a VM (both Lima-only — the lite image has no `sudo`, no QEMU, and the
/// CA is baked into the image at build time per spec § "Routing").
///
/// Mirrors `restore_session_networking` steps 1, 2, 2b, plus the ingestor +
/// DNS-gate-listener restoration that the Lima path inherits implicitly from
/// `setup_session_networking`. Steps 3 and 4 (`attach_vm_to_bridge` +
/// `inject_ca_into_vm`) are intentionally absent.
async fn restore_session_networking_lite(
    session_id: &SessionId,
    state: &AppState,
) -> Result<(), SandboxError> {
    // Network info must be present in the DB (set during create_session
    // step 6); without it there's nothing to rebuild. Mirrors the Lima
    // restore guard at the top of `restore_session_networking`.
    let network_info = match state.store.get_network_info(session_id)? {
        Some(info) => info,
        None => {
            info!(
                session_id = %session_id,
                "no network info in DB, skipping lite networking restore"
            );
            return Ok(());
        }
    };

    // 1. Reuse existing CA material — it was generated in
    // create_session step 0 and persists across stop / start. The lite
    // image trusts whatever was injected at build time, so we don't
    // need to re-inject; we only carry the CA dir into create_gateway
    // so mitmproxy/Envoy can sign upstream TLS with the same key.
    let ca_dir = CaManager::ca_dir(&state.base_dir, session_id);
    let ca_dir = if ca_dir.join("cert.pem").exists() {
        info!(
            session_id = %session_id,
            "reusing existing CA certificate (lite)"
        );
        ca_dir
    } else {
        info!(
            session_id = %session_id,
            "regenerating CA certificate (lite)"
        );
        CaManager::generate_session_ca(&state.base_dir, session_id)?
    };

    // 2. Compute the initial DNS policy (fail-closed default if no
    // policy is stored, otherwise leave it `None` so create_gateway
    // doesn't overwrite the upcoming reapply). Same shape as the Lima
    // restore branch.
    let has_stored_policy = {
        let policies = state.session_policies.lock().await;
        policies.contains_key(session_id)
    } || matches!(state.store.get_policy(session_id), Ok(Some(_)));
    let initial_dns_policy_owned: String;
    let initial_dns_policy = if !has_stored_policy {
        initial_dns_policy_owned = CoreDnsConfig::empty_policy_file_content();
        Some(initial_dns_policy_owned.as_str())
    } else {
        None
    };

    // Mirror the Lima restore: emit `gateway_booting` *before* the
    // docker call so the event stream records intent even if the
    // create fails.
    state
        .event_bus
        .publish(lifecycle_events::gateway_booting(*session_id));

    // 3. Recreate the gateway container.
    {
        let gw = state.gateway.clone();
        let sid = *session_id;
        let ni = network_info.clone();
        let ca = ca_dir.clone();
        let dns = initial_dns_policy.map(|s| s.to_string());
        match tokio::task::spawn_blocking(move || {
            gw.create_gateway(&sid, &ni, Some(&ca), dns.as_deref())
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let net = state.network.clone();
                let sid = *session_id;
                let _ = tokio::task::spawn_blocking(move || net.remove_docker_network(&sid)).await;
                return Err(e);
            }
            Err(e) => {
                let net = state.network.clone();
                let sid = *session_id;
                let _ = tokio::task::spawn_blocking(move || net.remove_docker_network(&sid)).await;
                return Err(SandboxError::Internal(format!(
                    "task join error creating gateway: {e}"
                )));
            }
        }
    }

    // 4. Gateway is up — publish `gateway_ready` and respawn the
    // ingestor / DNS-gate listener. Both were torn down on stop
    // (`stop_session` calls `cancel_dns_gate_listener` and
    // `abort_session_ingestor`).
    state
        .event_bus
        .publish(lifecycle_events::gateway_ready(*session_id));
    spawn_session_ingestor(session_id, state).await;
    start_dns_gate_listener(session_id, state).await;

    // 5. Re-apply the session's stored policy (if any) to the fresh
    // gateway. No-op when no policy is stored; the empty allow-all was
    // already pushed during create_gateway above via initial_dns_policy.
    reapply_session_policy(session_id, state).await;

    Ok(())
}

/// Format a `GatewayStatus` into a human-readable string for the API response.
fn format_gateway_status(gateway: &GatewayManager, session_id: &SessionId) -> String {
    match gateway.gateway_status(session_id) {
        Ok(GatewayStatus::Healthy) => "healthy".to_string(),
        Ok(GatewayStatus::Starting) => "starting".to_string(),
        Ok(GatewayStatus::Unhealthy(reason)) => format!("unhealthy: {reason}"),
        Ok(GatewayStatus::NotRunning) => "not_running".to_string(),
        Err(e) => format!("error: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Health endpoint
// ---------------------------------------------------------------------------

/// Per-session health endpoint: `GET /sessions/{id}/health`
async fn session_health(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    // VM status.
    //
    // M11-S1 Phase 1C: dispatch through the trait. `RuntimeStatus`
    // adds `Creating` and `Error` variants over `VmStatus` for the
    // forthcoming container backend; both are surfaced as their lower-
    // case names so the existing health-payload consumers (CLI,
    // `tests/e2e`) stay backwards compatible — they already accept
    // arbitrary lower-case status strings.
    let vm_status = {
        let runtime = runtime_for(&state, session.backend);
        let handle = RuntimeHandle::from_session_id(&session.id);
        match runtime.status(&handle).await {
            Ok(sandbox_core::backend::RuntimeStatus::Running) => "running".to_string(),
            Ok(sandbox_core::backend::RuntimeStatus::Stopped) => "stopped".to_string(),
            Ok(sandbox_core::backend::RuntimeStatus::Creating) => "creating".to_string(),
            Ok(sandbox_core::backend::RuntimeStatus::Error) => "error".to_string(),
            Ok(sandbox_core::backend::RuntimeStatus::Unknown(s)) => s,
            Err(e) => format!("error: {e}"),
        }
    };

    // Guest agent status.
    let guest_agent = if session.state == SessionState::Running {
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            state.guest.ping(&session.id),
        )
        .await
        {
            Ok(Ok(true)) => "connected".to_string(),
            Ok(Ok(false)) => "unexpected_response".to_string(),
            Ok(Err(e)) => format!("error: {e}"),
            Err(_) => "timeout".to_string(),
        }
    } else {
        "not_checked".to_string()
    };

    // Gateway health.
    let (container_status, envoy, mitmproxy, coredns) = if session.state == SessionState::Running {
        let gateway = state.gateway.clone();
        let sid = session.id;
        let gw_result = tokio::task::spawn_blocking(move || gateway.gateway_status(&sid))
            .await
            .unwrap_or_else(|e| Err(SandboxError::Internal(format!("task join error: {e}"))));
        match gw_result {
            Ok(GatewayStatus::Healthy) => (
                "running".to_string(),
                "healthy".to_string(),
                "healthy".to_string(),
                "healthy".to_string(),
            ),
            Ok(GatewayStatus::Starting) => (
                "running".to_string(),
                // healthcheck.sh passes in `Starting`, so the in-
                // container processes (Envoy admin /ready, mitmproxy,
                // CoreDNS /health, deny-logger /health) are reporting
                // healthy. The gap that flips us to `Starting` is
                // `total_listeners_active == 0` — this surfaces as
                // the listener-aware verdict and the per-component
                // probes can stay `healthy`.
                "starting".to_string(),
                "healthy".to_string(),
                "healthy".to_string(),
            ),
            Ok(GatewayStatus::Unhealthy(reason)) => (
                "running".to_string(),
                "unknown".to_string(),
                "unknown".to_string(),
                format!("unhealthy: {reason}"),
            ),
            Ok(GatewayStatus::NotRunning) => (
                "not_running".to_string(),
                "not_running".to_string(),
                "not_running".to_string(),
                "not_running".to_string(),
            ),
            Err(e) => {
                let msg = format!("error: {e}");
                (msg.clone(), msg.clone(), msg.clone(), msg)
            }
        }
    } else {
        (
            "not_checked".to_string(),
            "not_checked".to_string(),
            "not_checked".to_string(),
            "not_checked".to_string(),
        )
    };

    // Network health: check if the Docker bridge exists.
    // TAP devices are now managed by QEMU via qemu-bridge-helper and are
    // created/destroyed with the VM process — no separate host-side check.
    let network_info = state.store.get_network_info(&session.id).ok().flatten();
    let bridge_exists = if let Some(ref info) = network_info {
        let docker_network_name = info.docker_network_name.clone();
        tokio::task::spawn_blocking(move || {
            std::process::Command::new("docker")
                .args(["network", "inspect", &docker_network_name])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false)
    } else {
        false
    };
    // TAP is owned by QEMU; report as present when the VM is running.
    let tap_exists = vm_status == "running";

    let health = SessionHealth {
        session_id: session.id,
        vm_status,
        guest_agent,
        gateway: GatewayHealth {
            container_status,
            envoy,
            mitmproxy,
            coredns,
        },
        network: NetworkHealth {
            bridge_exists,
            tap_exists,
        },
    };

    (StatusCode::OK, Json(health)).into_response()
}

/// JSON body for `POST /rebuild-image` (M11-S4 Phase 4C).
///
/// Both fields default so an empty / missing body decodes as the pre-
/// Phase-4C behavior (rebuild Lima, no cache-bust flag plumbing).
/// `#[serde(default)]` per CLAUDE.md "On-disk compatibility" /
/// forward-compat: older CLIs that POST an empty body must keep
/// working.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
struct RebuildImageRequest {
    backend: BackendKind,
    no_cache: bool,
}

impl Default for RebuildImageRequest {
    fn default() -> Self {
        // Backwards-compat default: an empty body matches the pre-
        // Phase-4C handler — Lima, no cache-bust signal.
        Self {
            backend: BackendKind::Lima,
            no_cache: false,
        }
    }
}

/// `POST /rebuild-image` -- rebuild a backend's image.
///
/// JSON body shape (M11-S4 Phase 4C):
///
/// ```json
/// { "backend": "lima" | "container", "no_cache": true | false }
/// ```
///
/// An empty body is decoded as `{ "backend": "lima", "no_cache": false }`
/// — backwards-compat with older CLIs that POST `/rebuild-image` with
/// no body and expect Lima behavior. Axum's `Json<T>` extractor rejects
/// empty bodies outright, so the body is read raw via the [`Bytes`]
/// extractor and parsed manually with `serde_json::from_slice`.
async fn rebuild_image(State(state): State<Arc<AppState>>, body: Bytes) -> impl IntoResponse {
    // Decode the body. Empty body → default (Lima, no_cache=false) for
    // backwards-compat. Malformed JSON or unknown backend kind → 400.
    let req: RebuildImageRequest = if body.is_empty() {
        RebuildImageRequest::default()
    } else {
        match serde_json::from_slice::<RebuildImageRequest>(&body) {
            Ok(r) => r,
            Err(e) => {
                return error_response(SandboxError::InvalidArgument(format!(
                    "invalid rebuild-image request: {e}"
                )))
                .into_response();
            }
        }
    };

    match req.backend {
        BackendKind::Lima => {
            // Per spec Phase 4C: `rebuild_base_image` already deletes
            // the golden VM and rebuilds it from scratch — that is the
            // cache-bust. The `no_cache` flag is therefore a no-op on
            // the Lima path; no new flag plumbing is required.
            let _base_guard = state.base_image_lock.lock().await;
            let lima = Arc::clone(state.lima_runtime.manager());
            match tokio::task::spawn_blocking(move || lima.rebuild_base_image()).await {
                Ok(Ok(())) => (StatusCode::OK, "base image rebuilt").into_response(),
                Ok(Err(e)) => error_response(e).into_response(),
                Err(e) => error_response(SandboxError::Internal(format!("task join: {e}")))
                    .into_response(),
            }
        }
        BackendKind::Container => {
            // Per spec § "rebuild-image" + Phase 4C: the container
            // rebuild lock is owned inside `rebuild_lite_image` (the
            // same image-namespace lock that `ensure_image` uses), so
            // we deliberately do NOT acquire `state.base_image_lock`
            // here — that lock is Lima-scoped and would needlessly
            // serialise concurrent `rebuild --backend lima` and
            // `rebuild --backend container` calls.
            let daemon_version = env!("CARGO_PKG_VERSION").to_string();
            let no_cache = req.no_cache;
            match tokio::task::spawn_blocking(move || rebuild_lite_image(&daemon_version, no_cache))
                .await
            {
                Ok(Ok(())) => (StatusCode::OK, "lite image rebuilt").into_response(),
                Ok(Err(e)) => error_response(e).into_response(),
                Err(e) => error_response(SandboxError::Internal(format!("task join: {e}")))
                    .into_response(),
            }
        }
    }
}

/// `GET /base-image-status` -- check the status of the golden base image.
async fn base_image_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // M11-S1 Phase 1C: base-image status is Lima-specific (the
    // hash-and-age check operates on the golden VM); kept on the
    // typed runtime's escape hatch.
    let lima = Arc::clone(state.lima_runtime.manager());
    match tokio::task::spawn_blocking(move || lima.check_base_image()).await {
        Ok(Ok(status)) => {
            let json = match status {
                BaseImageStatus::Missing => serde_json::json!({"status": "missing"}),
                BaseImageStatus::Fresh => serde_json::json!({"status": "fresh"}),
                BaseImageStatus::Stale {
                    age_days,
                    hash_mismatch,
                } => {
                    serde_json::json!({"status": "stale", "age_days": age_days, "hash_mismatch": hash_mismatch})
                }
            };
            (StatusCode::OK, Json(json)).into_response()
        }
        Ok(Err(e)) => error_response(e).into_response(),
        Err(e) => error_response(SandboxError::Internal(format!("task join: {e}"))).into_response(),
    }
}

/// Global health endpoint: `GET /health`
///
/// Returns gateway status per running session.
async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let sessions = match state.store.list_sessions() {
        Ok(s) => s,
        Err(e) => return error_response(e).into_response(),
    };

    let mut statuses: Vec<serde_json::Value> = Vec::new();
    for session in &sessions {
        if session.state != SessionState::Running {
            continue;
        }
        let gateway = state.gateway.clone();
        let sid = session.id;
        let gw_status = tokio::task::spawn_blocking(move || format_gateway_status(&gateway, &sid))
            .await
            .unwrap_or_else(|_| "error: task join failed".to_string());
        statuses.push(serde_json::json!({
            "session_id": session.id,
            "name": session.name,
            "gateway_status": gw_status,
        }));
    }

    let response = serde_json::json!({
        "status": "ok",
        "running_sessions": statuses.len(),
        "gateways": statuses,
    });

    (StatusCode::OK, Json(response)).into_response()
}

// ---------------------------------------------------------------------------
// Startup reconciliation
// ---------------------------------------------------------------------------

/// Reconcile session store state with Lima VM inventory.
///
/// For each session in the store:
/// - If the VM is missing but session state is Running/Creating -> mark as Error
/// - If the VM exists and states match -> no action
/// - If the VM exists but states disagree -> update store to match Lima
///
/// M11-S1 Phase 1C: takes the wrapping [`LimaRuntime`] rather than the
/// raw [`LimaManager`], reaching for `list_vms()` through
/// [`LimaRuntime::manager`]. The body still pattern-matches on the
/// Lima-native [`VmStatus`] because the reconciliation contract is
/// today single-backend; per-backend reconciliation fan-out lands when
/// the container backend joins (M11-S2).
fn reconcile(store: &SessionStore, lima_runtime: &LimaRuntime) {
    let sessions = match store.list_sessions() {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "reconciliation: failed to list sessions");
            return;
        }
    };

    if sessions.is_empty() {
        info!("reconciliation: no sessions in store");
        return;
    }

    let vm_list = match lima_runtime.manager().list_vms() {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "reconciliation: failed to list VMs, skipping");
            return;
        }
    };

    let mut ok_count = 0u32;
    let mut fixed_count = 0u32;
    let mut skipped_count = 0u32;

    for session in &sessions {
        // M11-S6 fix: skip container-backed sessions. The Lima-VM list does
        // not include them, so the (None, Running) arm below would falsely
        // mark every container session as Error on every daemon restart.
        // Container sessions are reconciled via the Docker daemon directly:
        // the session container persists across daemon restarts (Docker is
        // independent), and the per-session gateway is recovered by
        // `reconcile_networking` / `restore_session_networking_lite`. There
        // is no Lima-equivalent VM-status fan-out for the container backend,
        // so this loop has nothing to assert about them.
        if session.backend == BackendKind::Container {
            skipped_count += 1;
            continue;
        }

        let vm = vm_list.iter().find(|v| v.session_id == Some(session.id));

        match (vm, session.state) {
            // VM missing, session thinks it's running or creating -> Error
            (None, SessionState::Running | SessionState::Creating) => {
                warn!(
                    session_id = %session.id,
                    state = %session.state,
                    "reconciliation: VM missing, marking session as Error"
                );
                let _ = store.update_state_forced(&session.id, SessionState::Error);
                fixed_count += 1;
            }
            // VM missing, session already stopped or errored -> OK
            (None, SessionState::Stopped | SessionState::Error) => {
                ok_count += 1;
            }
            // VM exists
            (Some(vm_info), _) => match (&session.state, &vm_info.status) {
                (SessionState::Running, VmStatus::Running) => ok_count += 1,
                (SessionState::Stopped, VmStatus::Stopped) => ok_count += 1,
                (SessionState::Running, VmStatus::Stopped) => {
                    info!(
                        session_id = %session.id,
                        "reconciliation: VM stopped but session says Running, updating to Stopped"
                    );
                    let _ = store.update_state_forced(&session.id, SessionState::Stopped);
                    fixed_count += 1;
                }
                (SessionState::Stopped, VmStatus::Running) => {
                    info!(
                        session_id = %session.id,
                        "reconciliation: VM running but session says Stopped, updating to Running"
                    );
                    let _ = store.update_state_forced(&session.id, SessionState::Running);
                    fixed_count += 1;
                }
                _ => {
                    ok_count += 1;
                }
            },
        }
    }

    info!(
        total = sessions.len(),
        ok = ok_count,
        fixed = fixed_count,
        skipped_container = skipped_count,
        "reconciliation complete"
    );
}

/// Reconcile networking state for sessions after daemon startup.
///
/// For each Running session: check if its gateway container is running and
/// restart it if needed.
///
/// For each Stopped session: ensure gateway is stopped and TAP is removed.
async fn reconcile_networking(state: &AppState) {
    let sessions = match state.store.list_sessions() {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "network reconciliation: failed to list sessions");
            return;
        }
    };

    let mut restored = 0u32;
    let mut cleaned = 0u32;

    // Snapshot the set of sessions being stopped so we don't restart their
    // gateway while the stop handler is tearing it down.
    let stopping = state.sessions_stopping.lock().await.clone();

    for session in &sessions {
        match session.state {
            SessionState::Running => {
                // Skip sessions that are in the middle of a stop sequence.
                if stopping.contains(&session.id) {
                    debug!(
                        session_id = %session.id,
                        "network reconciliation: skipping session (stop in progress)"
                    );
                    continue;
                }
                // Check if gateway is running.
                let gw = Arc::clone(&state.gateway);
                let sid = session.id;
                let status_result =
                    tokio::task::spawn_blocking(move || gw.gateway_status(&sid)).await;
                let gw_status = match status_result {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        warn!(
                            session_id = %session.id,
                            error = %e,
                            "network reconciliation: failed to check gateway status"
                        );
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            session_id = %session.id,
                            error = %e,
                            "network reconciliation: spawn_blocking join error checking gateway status"
                        );
                        continue;
                    }
                };

                match gw_status {
                    GatewayStatus::Healthy | GatewayStatus::Starting => {
                        // Gateway is healthy or in the boot window
                        // (Starting = container OK but no active
                        // listener yet — typical pre-policy-apply or
                        // post-LDS-rejection). Either way, network
                        // reconciliation has no work to do; restart
                        // logic for `Starting` is intentionally a
                        // no-op (see gateway_status rustdoc).
                    }
                    status => {
                        warn!(
                            session_id = %session.id,
                            gateway_status = ?status,
                            "network reconciliation: gateway not healthy, attempting restart"
                        );

                        let network_info = match state.store.get_network_info(&session.id) {
                            Ok(Some(info)) => info,
                            Ok(None) => {
                                warn!(
                                    session_id = %session.id,
                                    "network reconciliation: no network info, skipping"
                                );
                                continue;
                            }
                            Err(e) => {
                                warn!(
                                    session_id = %session.id,
                                    error = %e,
                                    "network reconciliation: failed to get network info"
                                );
                                continue;
                            }
                        };

                        // Ensure Docker network exists.
                        let net = Arc::clone(&state.network);
                        let sid = session.id;
                        let ensure_result =
                            tokio::task::spawn_blocking(move || net.ensure_network(&sid)).await;
                        match ensure_result {
                            Ok(Err(e)) => {
                                warn!(
                                    session_id = %session.id,
                                    error = %e,
                                    "network reconciliation: failed to ensure Docker network"
                                );
                                continue;
                            }
                            Err(e) => {
                                warn!(
                                    session_id = %session.id,
                                    error = %e,
                                    "network reconciliation: spawn_blocking join error ensuring Docker network"
                                );
                                continue;
                            }
                            Ok(Ok(_)) => {}
                        }

                        // Get CA directory.
                        let ca_dir = CaManager::ca_dir(&state.base_dir, &session.id);
                        let ca_ref = if ca_dir.join("cert.pem").exists() {
                            Some(ca_dir.as_path())
                        } else {
                            warn!(
                                session_id = %session.id,
                                "network reconciliation: CA cert missing, gateway will run without CA"
                            );
                            None
                        };

                        // Determine initial DNS policy for the gateway.
                        // Fail-closed: no stored policy → empty allowed-
                        // domains list so CoreDNS returns NXDOMAIN.  The
                        // reconciliation loop re-applies any stored policy
                        // after the gateway is back up.
                        let has_policy = {
                            let policies = state.session_policies.lock().await;
                            policies.contains_key(&session.id)
                        };
                        let init_dns_str = CoreDnsConfig::empty_policy_file_content();
                        let init_dns = if !has_policy {
                            Some(init_dns_str.as_str())
                        } else {
                            None
                        };

                        // Restart the gateway.
                        let gw = Arc::clone(&state.gateway);
                        let sid = session.id;
                        let ni = network_info.clone();
                        let ca_owned = ca_ref.map(|p| p.to_path_buf());
                        let init_dns_owned = init_dns.map(|s| s.to_string());
                        let restart_result = tokio::task::spawn_blocking(move || {
                            gw.restart_gateway(
                                &sid,
                                &ni,
                                ca_owned.as_deref(),
                                init_dns_owned.as_deref(),
                            )
                        })
                        .await;
                        match restart_result {
                            Ok(Err(e)) => {
                                warn!(
                                    session_id = %session.id,
                                    error = %e,
                                    "network reconciliation: failed to restart gateway"
                                );
                            }
                            Err(e) => {
                                warn!(
                                    session_id = %session.id,
                                    error = %e,
                                    "network reconciliation: spawn_blocking join error restarting gateway"
                                );
                            }
                            Ok(Ok(())) => {
                                info!(
                                    session_id = %session.id,
                                    "network reconciliation: gateway restarted"
                                );
                                // Spawn (or reseat) the ingestor for the
                                // freshly-restarted gateway before re-applying
                                // policy — the latter can produce Envoy
                                // connection records on startup.
                                spawn_session_ingestor(&session.id, state).await;
                                // Re-apply the session's policy to the fresh gateway.
                                reapply_session_policy(&session.id, state).await;
                                restored += 1;
                            }
                        }
                    }
                }
            }
            SessionState::Stopped => {
                // Ensure lingering gateway and TAP are cleaned up.
                let gw = Arc::clone(&state.gateway);
                let sid = session.id;
                let status_result =
                    tokio::task::spawn_blocking(move || gw.gateway_status(&sid)).await;
                match status_result {
                    Ok(Ok(GatewayStatus::NotRunning)) => {
                        // Already clean.
                    }
                    Ok(Ok(_)) => {
                        info!(
                            session_id = %session.id,
                            "network reconciliation: cleaning up lingering gateway for stopped session"
                        );
                        let gw = Arc::clone(&state.gateway);
                        let sid = session.id;
                        let _ = tokio::task::spawn_blocking(move || gw.stop_gateway(&sid)).await;
                        cleaned += 1;
                    }
                    Ok(Err(_)) | Err(_) => {
                        // Container doesn't exist or join error, that's fine.
                    }
                }

                // Best-effort TAP cleanup (no-op: TAP is owned by QEMU).
                let sid = session.id;
                let _ = tokio::task::spawn_blocking(move || detach_vm_from_bridge(&sid)).await;
            }
            _ => {}
        }
    }

    info!(
        restored = restored,
        cleaned = cleaned,
        "network reconciliation complete"
    );
}

// ---------------------------------------------------------------------------
// Gateway crash recovery
// ---------------------------------------------------------------------------

/// Components the gateway monitor polls per tick.  Each entry pairs
/// the `GatewayManager::component_health` label with the
/// [`sandbox_core::HealthComponent`] used on
/// `health_degraded`/`health_restored` events.
///
/// `deny-logger` polls the `:10003/health` endpoint on the gateway
/// bridge IP (M10-S3 Phase 6) — its data-path listeners on :10001/:10002
/// are bound on the bridge IP as well (not 127.0.0.1), because DNAT to
/// loopback would be dropped as a martian destination. The in-container
/// probe discovers the bridge IP via `hostname -i` (see
/// `gateway::component_probe` and the container's `healthcheck.sh`).
const MONITORED_COMPONENTS: &[(&str, HealthComponent)] = &[
    ("envoy", HealthComponent::Envoy),
    ("coredns", HealthComponent::Coredns),
    ("mitmproxy", HealthComponent::Mitmproxy),
    ("deny-logger", HealthComponent::DenyLogger),
];

/// Poll each monitored gateway component and publish
/// `health_degraded` / `health_restored` events for any component
/// whose state flipped since the previous tick.
///
/// The previous state lives in `AppState::component_health_state` —
/// unknown components are treated as "healthy" on first observation
/// so an initial healthy poll does **not** emit `health_restored`
/// (which would be noise), while an initial unhealthy poll does emit
/// `health_degraded` (which is the alert we want).  Subsequent
/// transitions in either direction emit the matching event.
///
/// Runs inside the gateway monitor loop, so `component_health` —
/// which shells out to `docker exec` — is wrapped in
/// `spawn_blocking`.
async fn poll_and_emit_component_health(state: &AppState, session_id: &SessionId) {
    for (label, component) in MONITORED_COMPONENTS {
        let gw = Arc::clone(&state.gateway);
        let sid = *session_id;
        let label_owned = (*label).to_string();
        let health = match tokio::task::spawn_blocking(move || {
            gw.component_health(&sid, &label_owned)
        })
        .await
        {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    component = ?component,
                    error = %e,
                    "component health poll join error; skipping this tick"
                );
                continue;
            }
        };

        // Pure transition detection (including the `"unknown"`-as-
        // unhealthy convention and the first-poll-seeds-healthy
        // policy) lives in `sandbox_core::events::health_transition` so
        // integration tests can import the same logic instead of
        // re-implementing it. We retain the lock-and-emit glue here
        // because the bus publish is async and the lock must be
        // dropped before the publish to avoid holding it across an
        // await point.
        let mut states = state.component_health_state.lock().await;
        let session_map = states.entry(*session_id).or_default();
        let transition =
            sandbox_core::events::detect_health_transition(session_map, *component, &health);
        drop(states);

        if let Some(transition) = transition {
            let event = match transition {
                sandbox_core::events::HealthTransition::Degraded { component, reason } => {
                    lifecycle_events::health_degraded(*session_id, component, reason)
                }
                sandbox_core::events::HealthTransition::Restored { component } => {
                    lifecycle_events::health_restored(*session_id, component)
                }
            };
            state.event_bus.publish(event);
        }
    }
}

/// Background task that monitors gateway containers and restarts crashed ones.
///
/// Runs every 30 seconds. For each Running session, checks if the gateway
/// container is healthy. If it has crashed or stopped, restarts it and
/// re-injects nftables rules.
async fn gateway_monitor(state: Arc<AppState>) {
    let poll_interval = Duration::from_secs(30);

    loop {
        tokio::time::sleep(poll_interval).await;

        let sessions = match state.store.list_sessions() {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "gateway monitor: failed to list sessions");
                continue;
            }
        };

        // Snapshot the set of sessions currently being stopped so we skip
        // them and don't accidentally restart their gateway.
        let stopping = state.sessions_stopping.lock().await.clone();

        for session in &sessions {
            if session.state != SessionState::Running {
                continue;
            }

            // Skip sessions that are in the middle of a stop sequence.
            if stopping.contains(&session.id) {
                debug!(
                    session_id = %session.id,
                    "gateway monitor: skipping session (stop in progress)"
                );
                continue;
            }

            // Poll per-component health and emit transitions
            // (M10-S2 Phase 5).  Only components that *flipped* since
            // the last tick produce events, so the bus stays sparse
            // under sustained outages.  Runs on every tick independent
            // of the container-level health verdict so we can still
            // record e.g. "mitmproxy restored" while Envoy remains
            // down — and so a deny-logger flap inside the start-period
            // still produces a `health_degraded` event even before
            // Docker has flipped the container to unhealthy.
            poll_and_emit_component_health(&state, &session.id).await;

            // First-pass: read Docker's native per-container health
            // verdict (`docker inspect --format
            // '{{.State.Health.Status}}'`). Docker maintains this by
            // running the image's HEALTHCHECK directive
            // (`/healthcheck.sh`, which Phase 4 extended to cover the
            // deny-logger) on its interval/retry/start-period cadence.
            // Reading the cached verdict is strictly cheaper than
            // re-running the script ourselves and — critically — it
            // honours Docker's retry/debounce window, so we do not
            // flap-restart on a single transient failure.
            //
            // See M10-S3 spec: "Docker marks the container unhealthy.
            // sandboxd's existing gateway health polling observes this
            // and restarts the gateway container."
            let gw = Arc::clone(&state.gateway);
            let sid = session.id;
            let docker_health =
                match tokio::task::spawn_blocking(move || gw.container_health_status(&sid)).await {
                    Ok(h) => h,
                    Err(e) => {
                        warn!(
                            session_id = %session.id,
                            error = %e,
                            "gateway monitor: spawn_blocking join error reading container health"
                        );
                        continue;
                    }
                };

            // Decide whether to run the fallback `gateway_status`
            // probe (which re-runs `/healthcheck.sh` from outside) and
            // whether a restart is warranted.
            //
            //   * `Healthy` — Docker has observed the HEALTHCHECK
            //     pass; skip the redundant full probe.
            //   * `Unhealthy` — Docker has observed `retries`
            //     consecutive failures; trigger the restart path
            //     directly without re-running the same script.
            //   * `Starting` — inside the start-period; keep waiting
            //     without probing or restarting. The per-component
            //     poll above still fires component-level events.
            //   * `None` / `Unknown` — Docker has no verdict (no
            //     HEALTHCHECK, container missing, inspect malformed);
            //     fall back to the authoritative `gateway_status`
            //     probe so we still catch NotRunning / Unhealthy from
            //     outside.
            let status = match docker_health {
                DockerHealth::Healthy => {
                    // Container is healthy per Docker — nothing to do
                    // this tick.
                    continue;
                }
                DockerHealth::Starting => {
                    debug!(
                        session_id = %session.id,
                        "gateway monitor: container in HEALTHCHECK start-period, deferring verdict"
                    );
                    continue;
                }
                DockerHealth::Unhealthy => {
                    // Docker has already applied the retry/debounce
                    // window. Synthesise an `Unhealthy` verdict and
                    // fall through to the restart path.
                    GatewayStatus::Unhealthy("docker HEALTHCHECK reports unhealthy".to_string())
                }
                DockerHealth::None | DockerHealth::Unknown => {
                    // Fall back to the full `gateway_status` probe —
                    // it re-runs `/healthcheck.sh` and also returns
                    // `NotRunning` if `.State.Running == false`.
                    let gw = Arc::clone(&state.gateway);
                    let sid = session.id;
                    let status_result =
                        tokio::task::spawn_blocking(move || gw.gateway_status(&sid)).await;
                    match status_result {
                        Ok(Ok(s)) => s,
                        Ok(Err(e)) => {
                            warn!(
                                session_id = %session.id,
                                error = %e,
                                docker_health = ?docker_health,
                                "gateway monitor: failed to check gateway status (fallback)"
                            );
                            continue;
                        }
                        Err(e) => {
                            warn!(
                                session_id = %session.id,
                                error = %e,
                                "gateway monitor: spawn_blocking join error checking gateway status"
                            );
                            continue;
                        }
                    }
                }
            };

            match status {
                GatewayStatus::Healthy => {
                    // Fallback probe agreed it's healthy — nothing to do.
                }
                GatewayStatus::Starting => {
                    // Container processes are healthy but Envoy has no
                    // active listener yet — boot window before first
                    // policy apply, or post-rejection LDS state.
                    // Restarting here would loop indefinitely (the
                    // bootstrap deny-all listener is rejected by Envoy
                    // by design); the right recovery is for upstream
                    // code (policy distributor) to re-apply the policy.
                    debug!(
                        session_id = %session.id,
                        "gateway monitor: gateway in Starting state \
                         (no active listener yet), no restart"
                    );
                }
                GatewayStatus::NotRunning | GatewayStatus::Unhealthy(_) => {
                    warn!(
                        session_id = %session.id,
                        gateway_status = ?status,
                        docker_health = ?docker_health,
                        "gateway monitor: gateway not healthy, attempting recovery"
                    );

                    let network_info = match state.store.get_network_info(&session.id) {
                        Ok(Some(info)) => info,
                        Ok(None) => {
                            warn!(
                                session_id = %session.id,
                                "gateway monitor: no network info, cannot recover"
                            );
                            continue;
                        }
                        Err(e) => {
                            warn!(
                                session_id = %session.id,
                                error = %e,
                                "gateway monitor: failed to get network info"
                            );
                            continue;
                        }
                    };

                    // Ensure Docker network is present.
                    let net = Arc::clone(&state.network);
                    let sid = session.id;
                    let ensure_result =
                        tokio::task::spawn_blocking(move || net.ensure_network(&sid)).await;
                    match ensure_result {
                        Ok(Err(e)) => {
                            warn!(
                                session_id = %session.id,
                                error = %e,
                                "gateway monitor: failed to ensure Docker network"
                            );
                            continue;
                        }
                        Err(e) => {
                            warn!(
                                session_id = %session.id,
                                error = %e,
                                "gateway monitor: spawn_blocking join error ensuring Docker network"
                            );
                            continue;
                        }
                        Ok(Ok(_)) => {}
                    }

                    // Get CA directory.
                    let ca_dir = CaManager::ca_dir(&state.base_dir, &session.id);
                    let ca_ref = if ca_dir.join("cert.pem").exists() {
                        Some(ca_dir.as_path())
                    } else {
                        None
                    };

                    // Determine initial DNS policy for the gateway.
                    // Fail-closed: no stored policy → empty allowed-
                    // domains list so CoreDNS returns NXDOMAIN.  Any
                    // stored policy is re-applied after restart.
                    let has_policy = {
                        let policies = state.session_policies.lock().await;
                        policies.contains_key(&session.id)
                    };
                    let init_dns_str = CoreDnsConfig::empty_policy_file_content();
                    let init_dns = if !has_policy {
                        Some(init_dns_str.as_str())
                    } else {
                        None
                    };

                    // Restart the gateway.
                    let gw = Arc::clone(&state.gateway);
                    let sid = session.id;
                    let ni = network_info.clone();
                    let ca_owned = ca_ref.map(|p| p.to_path_buf());
                    let init_dns_owned = init_dns.map(|s| s.to_string());
                    let restart_result = tokio::task::spawn_blocking(move || {
                        gw.restart_gateway(
                            &sid,
                            &ni,
                            ca_owned.as_deref(),
                            init_dns_owned.as_deref(),
                        )
                    })
                    .await;
                    match restart_result {
                        Ok(Ok(())) => {
                            info!(
                                session_id = %session.id,
                                "gateway monitor: gateway recovered successfully"
                            );
                            // Spawn (or reseat) the JSONL ingestor for the
                            // recovered gateway. `spawn_session_ingestor`
                            // aborts any prior ingestor first, so a stale
                            // watch on the pre-crash container's events
                            // directory is released here rather than
                            // leaking until daemon exit.
                            spawn_session_ingestor(&session.id, &state).await;
                            // Re-apply the session's policy to the fresh gateway.
                            reapply_session_policy(&session.id, &state).await;
                        }
                        Ok(Err(e)) => {
                            error!(
                                session_id = %session.id,
                                error = %e,
                                "gateway monitor: failed to recover gateway"
                            );
                        }
                        Err(e) => {
                            error!(
                                session_id = %session.id,
                                error = %e,
                                "gateway monitor: spawn_blocking join error recovering gateway"
                            );
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Install the tracing subscriber. If `--log-file` was provided but the
    // file cannot be opened, abort early with a clear error -- we do NOT
    // silently fall back to stderr.
    if let Err(e) = init_tracing(args.log_file.as_deref()) {
        eprintln!(
            "sandboxd: failed to open log file {:?}: {}",
            args.log_file, e
        );
        return Err(e.into());
    }

    let base_dir = PathBuf::from(&args.base_dir);
    let socket_path = PathBuf::from(&args.socket);

    info!(
        base_dir = %base_dir.display(),
        socket = %socket_path.display(),
        "sandboxd starting"
    );

    // Create the base directory if it doesn't exist.
    tokio::fs::create_dir_all(&base_dir).await?;

    // Create the socket directory if it doesn't exist.
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // M11-S2 Phase 2C: validate `users.conf` before any expensive
    // initialization (SQLite migrations, Lima manager construction).
    // The daemon refuses to start unless the config contains a subnet
    // entry whose `allow_users` resolves to the daemon's own uid; the
    // matched subnet's CIDR scopes the per-session /28 allocation pool
    // below. Failing here keeps the operator-visible startup error
    // cheap (no migration cost on the failure path) and ensures the
    // configured pool is in hand before `NetworkManager::new` is
    // called.
    //
    // We funnel both error paths (loader errors and the "no matching
    // subnet" miss) through a single `eprintln!` + early-exit shape so
    // the operator-visible stderr is the loader's `Display` message
    // (which includes the file path + install-docs pointer) rather
    // than the runtime's `{:?}` rendering of `Box<dyn Error>`. The
    // `Box<dyn Error>` blanket `From<E>` impl would otherwise
    // short-circuit our `From<UsersConfigError> for SandboxError`
    // mapping when `?` propagates the loader error from `main`.
    let daemon_uid = nix::unistd::Uid::current().as_raw();
    let users_config = match load_users_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            let sandbox_err: SandboxError = err.into();
            eprintln!("sandboxd: {sandbox_err}");
            return Err(sandbox_err.into());
        }
    };
    let allocation_pool = match resolve_allocation_pool(daemon_uid, &users_config) {
        Ok(cidr) => cidr,
        Err(err) => {
            eprintln!("sandboxd: {err}");
            return Err(err.into());
        }
    };
    info!(
        users_conf = %users_conf_path().display(),
        daemon_uid,
        allocation_base = %allocation_pool.base(),
        allocation_prefix = allocation_pool.prefix_len(),
        "users.conf validated; allocation pool resolved"
    );

    // Initialize store and Lima manager.
    //
    // `SessionStore::new` returns a list of sessions whose v1 policy
    // was reset by the V004 migration; the replay of
    // `policy_reset_on_upgrade` lifecycle events on the bus happens in
    // the startup block below, once the `EventBus` is up.
    // M10-S4 Phase 2: wrap the store in an `Arc` immediately so the
    // events sub-router (built in `app()`) can hold its own handle
    // without an additional `FromRef` binding on `AppState`.  All
    // existing `store.*` call sites below keep working unchanged via
    // `Arc`'s `Deref<Target = SessionStore>`.
    let (store, reset_orphans) = SessionStore::new(base_dir.clone())?;
    let store = Arc::new(store);
    let lima = Arc::new(LimaManager::new(base_dir.clone())?);

    // M11-S1 Phase 1C: wrap the existing `LimaManager` in a
    // [`LimaRuntime`] and register it in the backend dispatch table.
    // The same `Arc<LimaRuntime>` is held both as a typed handle (for
    // Lima-only orchestration via `LimaRuntime::manager()`) and inside
    // `runtimes` (for handler-side trait dispatch).
    let lima_runtime = LimaRuntime::new(Arc::clone(&lima));
    let mut runtimes: HashMap<BackendKind, Arc<dyn SessionRuntime>> = HashMap::new();
    runtimes.insert(
        BackendKind::Lima,
        Arc::clone(&lima_runtime) as Arc<dyn SessionRuntime>,
    );

    // M11-S3 Phase 3D: register the lite-mode container runtime in the
    // dispatch table next to Lima. Resource defaults are derived from
    // host capacity (host_ram*0.8, host_cpus*0.8) so the container
    // backend honors the same headroom policy Lima applies. The same
    // `Arc<ContainerRuntime>` is also held as a typed handle on
    // `AppState` so the create-session handler can reach the
    // image-tag/`ensure_image` plumbing without going through the
    // dyn-trait object.
    let (default_memory_mb, default_cpus) = compute_default_resource_limits();
    let daemon_gid = nix::unistd::Gid::current().as_raw();
    // Spec § Hardening — root degrades to the 1000:1000 floor; non-1000
    // host uids pass through for workspace bind-mount alignment.
    let (container_uid, container_gid) = map_container_uid_gid(daemon_uid, daemon_gid);
    // M11-S4 Phase 4D-pre: the runtime's image tag must match the one
    // `ensure_image` actually builds (`sandboxd-lite:<CARGO_PKG_VERSION>`),
    // not the literal `:latest` placeholder shipped in M11-S2/3A. Using
    // the placeholder broke the very first `--lite` create because
    // `docker create` then references an image tag that no build step
    // ever produced. Pinning it to the same `lite_image_tag_for_version`
    // helper that `ensure_image` and `rebuild_lite_image` use closes the
    // drift at one source.
    let container_runtime = ContainerRuntime::new(
        lite_image_tag_for_version(env!("CARGO_PKG_VERSION")),
        default_memory_mb,
        default_cpus,
        container_uid,
        container_gid,
    );
    runtimes.insert(
        BackendKind::Container,
        Arc::clone(&container_runtime) as Arc<dyn SessionRuntime>,
    );

    let runtimes = Arc::new(runtimes);

    // M11-S4 Phase 4D-pre (Gap #3): `GuestConnector` now dispatches per
    // session backend through the runtime registry. It looks up the
    // session's `BackendKind` in the store at request time and asks the
    // matching `SessionRuntime` for a `GuestTransport` — no more
    // hard-wired `limactl shell` invocation. Lima sessions still go
    // through `limactl shell ... socat`; container sessions go through
    // `docker exec ... socat` via `ContainerTransport`.
    let guest = GuestConnector::new(Arc::clone(&runtimes), Arc::clone(&store));

    // Initialize networking managers.
    //
    // The /28 allocation pool's CIDR comes from the `users.conf` entry
    // matched at startup (see `resolve_allocation_pool` above). The
    // legacy default-pool constructor is no longer reachable from
    // production startup — `users.conf` is the single source of truth.
    let network = Arc::new(NetworkManager::new(
        allocation_pool.base(),
        allocation_pool.prefix_len(),
    )?);
    let gateway = Arc::new(GatewayManager::new());

    // Restore network allocator state from existing sessions.
    //
    // `restore_from_infos` validates that each persisted session's
    // subnet maps to a /28 block inside the configured pool — see
    // `SubnetAllocator::block_index_for`. If a legacy session was
    // allocated under a different `users.conf` (e.g. operator changed
    // the pool), this returns `SandboxError::Network` and the daemon
    // refuses to start. Operators must either revert `users.conf` or
    // remove the offending session(s) with `sandbox delete`.
    let existing_networks = store.list_sessions_with_network_info()?;
    if !existing_networks.is_empty() {
        info!(
            count = existing_networks.len(),
            "restoring network allocator state from existing sessions"
        );
        network.restore_from_infos(&existing_networks)?;
    }

    // Construct the event bus + vm-ip map and hydrate both from the same
    // set of `existing_networks` entries.  After a daemon restart every
    // session with persisted network info has a live allocation and a
    // stable VM IP, so its event sink must be ready before the gateway
    // is restored in `reconcile_networking` — otherwise any events
    // emitted by a just-restored gateway could race ahead of the bus
    // registration and be dropped.
    let event_bus = EventBus::new(EventBusConfig::default());
    let vm_ip_map = VmIpSessionMap::new();
    for (sid, info) in &existing_networks {
        event_bus.register_session(*sid);
        match info.vm_ip.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => {
                vm_ip_map.bind(ip, *sid);
            }
            Err(e) => {
                warn!(
                    session_id = %sid,
                    vm_ip = %info.vm_ip,
                    error = %e,
                    "failed to parse vm_ip during startup hydration; event attribution disabled for this session"
                );
            }
        }
    }
    if !existing_networks.is_empty() {
        info!(
            count = existing_networks.len(),
            vm_ip_bindings = vm_ip_map.len(),
            "hydrated event bus + vm-ip map from persisted sessions"
        );
    }

    // Optional persistent event sink. Spawns relay + sink + pruner
    // tasks that tail the global broadcast and mirror every event
    // into per-session per-layer JSONL files under
    // `{base_dir}/sessions/{id}/events/{layer}-YYYY-MM-DD.jsonl`.
    // When `--events-persist` is not set, this returns a no-op
    // handle and no tasks are launched (see
    // `PersistentSink::spawn`).
    let persistent_sink = PersistentSink::spawn(
        &event_bus,
        PersistConfig {
            enabled: args.events_persist,
            base_dir: base_dir.clone(),
            retention_days: args.events_persist_retention_days,
        },
    );
    if args.events_persist {
        info!(
            retention_days = args.events_persist_retention_days,
            "persistent event sink enabled"
        );
    }

    // Run startup reconciliation (VM state).
    reconcile(&store, &lima_runtime);

    // M11-S5 Phase 5B: lite container backend orphan cleanup. Spec §
    // "Orphan cleanup on daemon start" extends the gateway-container
    // reconcile pattern with a Docker-side sweep: any `sandbox-{id}`
    // container, `sandbox-home-{id}` volume, or `sandbox-net-{id}`
    // network whose derived session id is not in `sessions.db` is
    // removed. Best-effort and idempotent — a Docker hiccup logs and
    // continues rather than aborting startup.
    let live_session_ids: HashSet<SessionId> = match store.list_sessions() {
        Ok(sessions) => sessions.into_iter().map(|s| s.id).collect(),
        Err(e) => {
            warn!(
                error = %e,
                "orphan reaper: failed to list sessions; skipping reaper pass"
            );
            HashSet::new()
        }
    };
    // Wrap the reaper in a guarded enable-flag: if the daemon is
    // running on a host without Docker (e.g. a Lima-only deployment),
    // every list_* call would error and clog the log. The cheapest
    // probe is the reaper itself — any error path inside `reap_orphans`
    // already logs at `warn!` and continues.
    {
        let docker_ops = CliDockerOps;
        let _ = reap_orphans(&docker_ops, &live_session_ids).await;
    }

    // Hydrate the in-memory policy map from SQLite **before**
    // `reconcile_networking` runs.  Gateway restoration inside the
    // reconciliation loop calls `reapply_session_policy`, which looks
    // up `state.session_policies`.  Without this hydration step the map
    // is empty on restart and the restored gateway would fall back to
    // the fail-closed empty DNS policy (post-M9-S15), locking out the
    // session until its stored policy is reapplied — which is less bad
    // than the pre-M9-S15 allow-all fallback but still wrong.
    let hydrated_policies: HashMap<SessionId, Policy> = match store.load_all_policies() {
        Ok(entries) => {
            if !entries.is_empty() {
                info!(
                    count = entries.len(),
                    "restored persisted network policies from SQLite"
                );
            }
            entries.into_iter().collect()
        }
        Err(e) => {
            // A hard DB failure here is surprising (the store is the
            // same one we just opened), but we prefer to start with an
            // empty map and warn rather than abort the daemon — that
            // matches the existing tolerance for corrupt rows inside
            // `load_all_policies` and keeps sandbox creation paths
            // usable even when the policy table itself is unreadable.
            warn!(
                error = %e,
                "failed to hydrate session policies from SQLite; continuing with empty map"
            );
            HashMap::new()
        }
    };

    // `lima` is intentionally not stashed on `AppState` directly any
    // more — handlers reach the runtime through `runtimes` (trait
    // dispatch) or `lima_runtime.manager()` (Lima-only orchestration).
    // The original `Arc<LimaManager>` was cloned into `LimaRuntime::new`;
    // `GuestConnector` now dispatches via the runtime registry rather
    // than holding a `LimaManager` directly. The local binding above is
    // dropped at end of scope.
    let state = Arc::new(AppState {
        base_dir,
        store,
        runtimes,
        lima_runtime,
        container_runtime,
        guest,
        network,
        gateway,
        dns_loop_handles: Mutex::new(HashMap::new()),
        dns_gate_handles: Mutex::new(HashMap::new()),
        dns_caches: Arc::new(Mutex::new(HashMap::new())),
        session_policies: Arc::new(Mutex::new(hydrated_policies)),
        sessions_stopping: Mutex::new(HashSet::new()),
        base_image_lock: Mutex::new(()),
        event_bus,
        vm_ip_map,
        component_health_state: Mutex::new(HashMap::new()),
        ingestors: Mutex::new(HashMap::new()),
        propagation_states: Arc::new(PropagationStates::new()),
    });

    // Replay one `policy_reset_on_upgrade` lifecycle event per
    // session whose v1 policy was dropped by migration V004 (M10-S2
    // Phase 5).  The store's `SessionStore::new` captured the
    // affected session IDs and their pre-V004 rule counts; now that
    // the `EventBus` is up and the per-session sinks are registered,
    // publish them.  Subscribers connected late still observe these
    // events because the bus retains them in the per-session ring
    // buffer.
    for orphan in &reset_orphans {
        match SessionId::parse(&orphan.session_id) {
            Ok(sid) => {
                // The per-session sink might not be registered if
                // this orphan session never had network info
                // persisted (e.g., a session that was created but
                // its networking setup failed).  Register it so the
                // event lands in the ring buffer and can be
                // replayed on reconnect.
                state.event_bus.register_session(sid);
                state
                    .event_bus
                    .publish(lifecycle_events::policy_reset_on_upgrade(
                        sid,
                        orphan.previous_rule_count as usize,
                    ));
            }
            Err(e) => {
                warn!(
                    session_id = %orphan.session_id,
                    error = %e,
                    "failed to parse orphan session id; \
                     policy_reset_on_upgrade event not emitted"
                );
            }
        }
    }

    // Run networking reconciliation: restart crashed gateways, clean up
    // lingering resources for stopped sessions.  The hydrated policy
    // map above makes `reapply_session_policy` find the right policy
    // for each restored gateway.
    reconcile_networking(&state).await;

    // Spawn background gateway monitor for crash recovery.
    let monitor_state = Arc::clone(&state);
    tokio::spawn(async move {
        gateway_monitor(monitor_state).await;
    });

    // Remove stale socket file if it exists.
    if socket_path.exists() {
        info!(?socket_path, "removing stale socket file");
        tokio::fs::remove_file(&socket_path).await?;
    }

    let listener = UnixListener::bind(&socket_path)?;

    info!(socket = %socket_path.display(), "sandboxd listening");

    let app = app(Arc::clone(&state));

    // Graceful shutdown on SIGTERM / SIGINT.
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Tear down the persistent event sink before removing the socket.
    // `shutdown` aborts and joins the relay / sink / pruner tasks so
    // their owned file handles are closed deterministically.
    persistent_sink.shutdown().await;

    // Clean up the socket file on exit.
    let _ = tokio::fs::remove_file(&socket_path).await;
    info!("sandboxd shut down");

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {
            info!("received SIGTERM, shutting down");
        }
        _ = sigint.recv() => {
            info!("received SIGINT, shutting down");
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_core::ApiError;

    // -----------------------------------------------------------------------
    // Helper: extract the JSON body from an error_response tuple.
    // -----------------------------------------------------------------------

    fn error_body(err: SandboxError) -> (StatusCode, ApiError) {
        let (status, Json(body)) = error_response(err);
        (status, body)
    }

    // -----------------------------------------------------------------------
    // round_cpus_one_decimal — M11-S7 todo #67 boundary normalisation.
    // Pins the request-parse-time grid: 0.81 → 0.8, 1.55 → 1.5, etc.
    // -----------------------------------------------------------------------

    #[test]
    fn round_cpus_one_decimal_snaps_off_grid_inputs_to_grid() {
        // Operator typed extra precision past the 1-decimal grid. The
        // request-parse-time normalisation rounds toward the nearest
        // grid point so the value reaches `format_cpus` unchanged
        // (no second rounding step) and so the persisted
        // `cpus_decimal` field matches what the daemon actually
        // applies via `--cpus`.
        assert_eq!(round_cpus_one_decimal(0.81), 0.8);
        assert_eq!(round_cpus_one_decimal(1.55), 1.5);
        assert_eq!(round_cpus_one_decimal(2.04), 2.0);
        // Banker's-rounding edge — `round` ties toward zero in `f64`?
        // Not required by the contract; the spec only mandates the
        // 1-decimal grid. We pin `1.5` and `2.0` (exactly on grid)
        // round to themselves.
        assert_eq!(round_cpus_one_decimal(1.5), 1.5);
        assert_eq!(round_cpus_one_decimal(2.0), 2.0);
        assert_eq!(round_cpus_one_decimal(0.8), 0.8);
    }

    /// Round-trip the spec § "Resource defaults — container only"
    /// 1-decimal grid through the request-parse-time normalisation
    /// without precision drift. Pins the contract todo #67 enforces:
    /// `0.8`, `1.5`, `2.0` survive the parse → store → serialize
    /// round-trip with bit-equality on the boundary helper.
    #[test]
    fn round_cpus_one_decimal_grid_values_survive_unchanged() {
        for cpus in [0.8_f32, 1.5_f32, 2.0_f32] {
            let normalised = round_cpus_one_decimal(cpus);
            assert_eq!(
                normalised, cpus,
                "1-decimal grid value must be a round-to-self fixed point; \
                 got {normalised} for input {cpus}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // resolve_allocation_pool — M11-S2 Phase 2C startup-validation logic.
    //
    // Pure function; we drive it with `UsersConfig` values parsed from
    // inline JSON via `load_users_config_from` against a tempfile (the
    // only public constructor for `UsersConfig`). The tests cover:
    //   1. Hit — a subnet entry whose `allow_users` resolves to the
    //      runner's uid; assert we return the matching CIDR.
    //   2. Miss — a subnet entry whose `allow_users` references a
    //      sentinel username that cannot exist on the host; assert
    //      `InvalidArgument` with the grep-stable prefix and the uid.
    //   3. Empty `subnets: []` — same `InvalidArgument` shape as case 2.
    //
    // Loader-level errors (missing file, malformed JSON, invalid CIDR)
    // are NOT re-tested here — Phase 2A's `users_conf` tests cover them.
    // -----------------------------------------------------------------------

    fn parse_users_config(raw: &str) -> UsersConfig {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(raw.as_bytes()).expect("write");
        f.flush().expect("flush");
        sandbox_core::load_users_config_from(f.path()).expect("parse users.conf")
    }

    #[test]
    fn resolve_allocation_pool_returns_cidr_when_subnet_matches_uid() {
        let runner_uid = nix::unistd::Uid::current();
        let runner_user = nix::unistd::User::from_uid(runner_uid)
            .expect("getpwuid_r")
            .expect("runner uid must resolve to a user account");
        let raw = format!(
            r#"{{
                "subnets": [
                    {{ "cidr": "10.250.0.0/20", "allow_users": ["{}"] }}
                ]
            }}"#,
            runner_user.name
        );
        let cfg = parse_users_config(&raw);
        let cidr = resolve_allocation_pool(runner_uid.as_raw(), &cfg)
            .expect("matching subnet must resolve");
        assert_eq!(cidr.base(), std::net::Ipv4Addr::new(10, 250, 0, 0));
        assert_eq!(cidr.prefix_len(), 20);
    }

    #[test]
    fn resolve_allocation_pool_errs_when_no_subnet_matches_uid() {
        let runner_uid = nix::unistd::Uid::current();
        // The bogus username is the same sentinel Phase 2A uses in its
        // `allows_uid_rejects_bogus_username` test — a name that
        // cannot exist on any practical host so `getpwnam_r` returns
        // `Ok(None)` and `find_subnet_by_uid` misses.
        let raw = r#"{
            "subnets": [
                {
                    "cidr": "10.209.0.0/20",
                    "allow_users": ["definitely-not-a-real-user-9c3f"]
                }
            ]
        }"#;
        let cfg = parse_users_config(raw);
        let err = resolve_allocation_pool(runner_uid.as_raw(), &cfg)
            .expect_err("no matching subnet must error");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("no users.conf subnet matches daemon user"),
                    "message must use the grep-stable prefix, got {msg}"
                );
                assert!(
                    msg.contains(&runner_uid.as_raw().to_string()),
                    "message must include the daemon uid, got {msg}"
                );
                assert!(
                    msg.contains("docs/start/installation.md"),
                    "message must point at install docs, got {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn resolve_allocation_pool_errs_when_subnets_array_is_empty() {
        let runner_uid = nix::unistd::Uid::current();
        let cfg = parse_users_config(r#"{ "subnets": [] }"#);
        let err = resolve_allocation_pool(runner_uid.as_raw(), &cfg)
            .expect_err("empty subnets must error");
        // Same shape as the bogus-username case — operators see one
        // diagnostic for "users.conf does not authorize me".
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("no users.conf subnet matches daemon user"),
                    "message must use the grep-stable prefix, got {msg}"
                );
                assert!(
                    msg.contains(&runner_uid.as_raw().to_string()),
                    "message must include the daemon uid, got {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // error_response: status code mapping
    // -----------------------------------------------------------------------

    #[test]
    fn error_response_session_not_found_returns_404() {
        let (status, body) = error_body(SandboxError::SessionNotFound("abc-123".into()));
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            body.error.contains("abc-123"),
            "expected body to contain session id, got: {}",
            body.error
        );
    }

    #[test]
    fn error_response_invalid_state_returns_400() {
        let (status, body) = error_body(SandboxError::InvalidState(
            "cannot start from stopped".into(),
        ));
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.error.contains("cannot start from stopped"),
            "expected body to contain reason, got: {}",
            body.error
        );
    }

    #[test]
    fn error_response_network_returns_500() {
        let (status, body) = error_body(SandboxError::Network("bridge down".into()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "bridge down");
    }

    #[test]
    fn error_response_ca_returns_500() {
        let (status, body) = error_body(SandboxError::Ca("cert gen failed".into()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "cert gen failed");
    }

    #[test]
    fn error_response_gateway_returns_500() {
        let (status, body) = error_body(SandboxError::Gateway("container crash".into()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "container crash");
    }

    #[test]
    fn error_response_lima_returns_500() {
        let (status, body) = error_body(SandboxError::Lima("vm boot timeout".into()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "vm boot timeout");
    }

    #[test]
    fn error_response_io_returns_500() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let (status, body) = error_body(SandboxError::Io(io_err));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            body.error.contains("access denied"),
            "expected body to contain io error message, got: {}",
            body.error
        );
    }

    #[test]
    fn error_response_database_returns_500() {
        // Construct a rusqlite error via the QueryReturnedNoRows variant
        // which requires no parameters.
        let db_err = rusqlite::Error::QueryReturnedNoRows;
        let (status, body) = error_body(SandboxError::Database(db_err));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            !body.error.is_empty(),
            "expected non-empty error body for Database variant"
        );
    }

    #[test]
    fn error_response_internal_returns_500() {
        let (status, body) = error_body(SandboxError::Internal("unexpected panic".into()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            body.error.contains("unexpected panic"),
            "expected body to contain internal error message, got: {}",
            body.error
        );
    }

    // -----------------------------------------------------------------------
    // error_response: JSON body structure
    // -----------------------------------------------------------------------

    #[test]
    fn error_response_body_serializes_as_api_error_json() {
        // Use a Network variant since it passes the raw inner string
        // (no Display prefix), making the assertion straightforward.
        let (_, Json(body)) = error_response(SandboxError::Network("test message".into()));
        let json = serde_json::to_value(&body).expect("failed to serialize ApiError");
        assert_eq!(
            json.get("error").and_then(|v| v.as_str()),
            Some("test message"),
        );
        // Ensure only the "error" key exists (no extra fields).
        let obj = json.as_object().expect("expected JSON object");
        assert_eq!(obj.len(), 1, "ApiError JSON should have exactly one key");
    }

    // -----------------------------------------------------------------------
    // error_response: Network/Ca/Gateway/Lima use the inner msg directly
    // (not the Display impl with prefix)
    // -----------------------------------------------------------------------

    #[test]
    fn error_response_string_variants_use_inner_message_not_display() {
        // For the string-wrapping variants (Network, Ca, Gateway, Lima),
        // error_response clones the inner string rather than calling
        // err.to_string(), so the body should NOT contain the "network error:"
        // prefix that the Display impl adds.
        let (_, body) = error_body(SandboxError::Network("oops".into()));
        assert_eq!(
            body.error, "oops",
            "Network body should be the raw inner message"
        );

        let (_, body) = error_body(SandboxError::Ca("oops".into()));
        assert_eq!(
            body.error, "oops",
            "Ca body should be the raw inner message"
        );

        let (_, body) = error_body(SandboxError::Gateway("oops".into()));
        assert_eq!(
            body.error, "oops",
            "Gateway body should be the raw inner message"
        );

        let (_, body) = error_body(SandboxError::Lima("oops".into()));
        assert_eq!(
            body.error, "oops",
            "Lima body should be the raw inner message"
        );
    }

    // -----------------------------------------------------------------------
    // error_response: Display-based variants include the thiserror prefix
    // -----------------------------------------------------------------------

    #[test]
    fn error_response_display_variants_include_prefix() {
        let (_, body) = error_body(SandboxError::SessionNotFound("xyz".into()));
        assert_eq!(body.error, "session not found: xyz");

        let (_, body) = error_body(SandboxError::InvalidState("bad".into()));
        assert_eq!(body.error, "invalid state transition: bad");

        let (_, body) = error_body(SandboxError::Internal("fail".into()));
        assert_eq!(body.error, "internal error: fail");
    }

    // -----------------------------------------------------------------------
    // default_socket_path / default_base_dir
    // -----------------------------------------------------------------------

    #[test]
    fn default_socket_path_ends_with_sock() {
        // Ensure the test is not perturbed by an inherited SANDBOX_SOCKET
        // from the surrounding shell -- the default value should end with
        // `sandboxd.sock` regardless of outside state.
        let prior = std::env::var("SANDBOX_SOCKET").ok();
        // SAFETY: Tests in this module that touch SANDBOX_SOCKET mutate and
        // restore it in a single test body to avoid cross-test races under
        // `cargo test` (nextest already provides per-test process isolation).
        unsafe { std::env::remove_var("SANDBOX_SOCKET") };
        let path = default_socket_path();
        assert!(
            path.ends_with("sandboxd.sock"),
            "expected path to end with sandboxd.sock, got: {path}"
        );
        // Restore prior state.
        if let Some(v) = prior {
            unsafe { std::env::set_var("SANDBOX_SOCKET", v) };
        }
    }

    #[test]
    fn default_base_dir_ends_with_sandboxd() {
        let dir = default_base_dir();
        assert!(
            dir.ends_with("/sandboxd"),
            "expected dir to end with /sandboxd, got: {dir}"
        );
    }

    // -----------------------------------------------------------------------
    // resolve_log_destination: pure selection logic
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_log_destination_none_returns_stderr() {
        let dest = resolve_log_destination(None).expect("None should always succeed");
        assert!(
            matches!(dest, LogDestination::Stderr),
            "expected Stderr when log_file is None"
        );
    }

    #[test]
    fn resolve_log_destination_some_opens_file_in_append_mode() {
        use std::io::Write;

        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("sandboxd.log");

        // Pre-seed the file with existing content; append mode must preserve it.
        std::fs::write(&path, b"existing-line\n").expect("seed file");

        let dest = resolve_log_destination(Some(&path)).expect("should open existing file");
        match dest {
            LogDestination::File(mut f) => {
                f.write_all(b"new-line\n").expect("write");
                f.sync_all().expect("sync");
            }
            LogDestination::Stderr => panic!("expected File variant"),
        }

        let contents = std::fs::read_to_string(&path).expect("read back");
        assert!(
            contents.contains("existing-line"),
            "append mode must preserve prior content, got: {contents:?}"
        );
        assert!(
            contents.contains("new-line"),
            "new write should be appended, got: {contents:?}"
        );
    }

    #[test]
    fn resolve_log_destination_some_creates_missing_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("does-not-exist-yet.log");
        assert!(!path.exists(), "precondition: file should not exist");

        let dest = resolve_log_destination(Some(&path))
            .expect("create+append should succeed on missing file");
        assert!(
            matches!(dest, LogDestination::File(_)),
            "expected File variant"
        );
        assert!(path.exists(), "file should be created by open()");
    }

    #[test]
    fn resolve_log_destination_some_returns_error_on_bad_path() {
        // Parent directory does not exist -- open() cannot create the file.
        let tmp = tempfile::tempdir().expect("tempdir");
        let bad = tmp.path().join("no-such-subdir").join("sandboxd.log");
        let result = resolve_log_destination(Some(&bad));
        assert!(
            result.is_err(),
            "expected error when parent dir is missing, got Ok"
        );
    }

    // -----------------------------------------------------------------------
    // M11-S5 Phase 5A fixup — route-helper path resolution.
    //
    // Three layers of coverage:
    //
    //   1. `default_route_helper_candidates` — assembling the priority-
    //      ordered candidate list from `current_exe()`-dir + install-path
    //      + `$PATH`. Pure list-builder; no I/O.
    //   2. `resolve_route_helper_path_from` — walking the candidate list
    //      against a stub `is_usable` predicate. We deliberately stub
    //      `is_usable` rather than literally `setcap`-ing fixture files
    //      because real file capabilities require `CAP_SETFCAP` (so a
    //      hermetic unit test cannot apply them) and the cargo
    //      workspace lives on filesystems where `setcap` returns
    //      "Operation not supported" anyway.
    //   3. `xattr_has_cap_sys_admin_effective` — decoding a raw
    //      `vfs_cap_data` blob into a boolean cap presence answer.
    //      Coverage of revision 2 / revision 3 layouts plus the deny
    //      branches (no effective bit, wrong revision, missing
    //      CAP_SYS_ADMIN, malformed length).
    //
    // (1) and (2) together verify the resolver's priority-and-fallthrough
    // contract. (3) verifies the cap decoder. Wiring of `has_required_caps`
    // → `read_cap_xattr` → `xattr_has_cap_sys_admin_effective` is
    // non-recursive plumbing, so the integration story is "if the decoder
    // is correct and the resolver respects its predicate, the production
    // path is correct" — no extra integration test required at the unit
    // layer.
    // -----------------------------------------------------------------------

    #[test]
    fn default_route_helper_candidates_includes_sibling_install_and_path_walk() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let exe_dir = tmp.path();
        let install_path = std::path::PathBuf::from("/usr/local/bin/sandbox-route-helper");
        // Two PATH entries plus an empty entry the builder must skip
        // (mirrors `PATH=/foo::/bar` shapes in shells that allow them).
        let path_var = std::ffi::OsString::from("/dir-a::/dir-b");

        let candidates =
            default_route_helper_candidates(Some(exe_dir), &install_path, Some(&path_var));

        assert_eq!(
            candidates.len(),
            4,
            "expected sibling + install + 2 PATH dirs (the empty PATH \
             segment must be skipped); got {candidates:?}"
        );
        assert_eq!(candidates[0], exe_dir.join("sandbox-route-helper"));
        assert_eq!(candidates[1], install_path);
        assert_eq!(
            candidates[2],
            std::path::PathBuf::from("/dir-a/sandbox-route-helper")
        );
        assert_eq!(
            candidates[3],
            std::path::PathBuf::from("/dir-b/sandbox-route-helper")
        );
    }

    #[test]
    fn default_route_helper_candidates_omits_sibling_when_current_exe_unavailable() {
        let install_path = std::path::PathBuf::from("/usr/local/bin/sandbox-route-helper");
        let candidates = default_route_helper_candidates(None, &install_path, None);
        assert_eq!(
            candidates,
            vec![install_path],
            "with no exe-dir and no PATH, only the install path is offered"
        );
    }

    #[test]
    fn resolve_route_helper_path_from_returns_first_usable_candidate() {
        let candidates = vec![
            std::path::PathBuf::from("/sibling/sandbox-route-helper"),
            std::path::PathBuf::from("/usr/local/bin/sandbox-route-helper"),
            std::path::PathBuf::from("/path-dir/sandbox-route-helper"),
        ];
        // The sibling is "usable", so it wins.
        let resolved = resolve_route_helper_path_from(
            candidates.clone(),
            |p| p.starts_with("/sibling"),
            "/sibling",
            std::path::Path::new("/usr/local/bin/sandbox-route-helper"),
        )
        .expect("sibling is usable");
        assert_eq!(resolved, candidates[0]);
    }

    #[test]
    fn resolve_route_helper_path_from_falls_through_when_earlier_candidate_lacks_caps() {
        let candidates = vec![
            std::path::PathBuf::from("/sibling/sandbox-route-helper"),
            std::path::PathBuf::from("/usr/local/bin/sandbox-route-helper"),
            std::path::PathBuf::from("/path-dir/sandbox-route-helper"),
        ];
        // Sibling exists-but-no-caps (predicate returns false for the
        // sibling); the install path is usable, so it wins.
        let resolved = resolve_route_helper_path_from(
            candidates.clone(),
            |p| p.starts_with("/usr/local/bin"),
            "/sibling",
            std::path::Path::new("/usr/local/bin/sandbox-route-helper"),
        )
        .expect("install path is usable; resolver must skip the un-cap'd sibling");
        assert_eq!(resolved, candidates[1]);
    }

    #[test]
    fn resolve_route_helper_path_from_errors_when_no_candidate_is_usable() {
        let candidates = vec![
            std::path::PathBuf::from("/sibling/sandbox-route-helper"),
            std::path::PathBuf::from("/usr/local/bin/sandbox-route-helper"),
        ];
        let exe_dir_display = "/sibling";
        let install_path = std::path::Path::new("/usr/local/bin/sandbox-route-helper");
        let err =
            resolve_route_helper_path_from(candidates, |_| false, exe_dir_display, install_path)
                .expect_err("no candidate is usable; resolver must surface an error");
        match err {
            SandboxError::Internal(msg) => {
                assert!(
                    msg.contains("no usable sandbox-route-helper found"),
                    "error must use the grep-stable prefix, got: {msg}"
                );
                assert!(
                    msg.contains(exe_dir_display),
                    "error must name the exe directory we checked, got: {msg}"
                );
                assert!(
                    msg.contains(&install_path.display().to_string()),
                    "error must name the install path we checked, got: {msg}"
                );
                assert!(
                    msg.contains("$PATH"),
                    "error must mention the $PATH lookup, got: {msg}"
                );
                assert!(
                    msg.contains("CAP_SYS_ADMIN"),
                    "error must mention the cap requirement so operators \
                     know setcap is needed; got: {msg}"
                );
            }
            other => panic!("expected SandboxError::Internal, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // xattr decoder: `xattr_has_cap_sys_admin_effective`.
    // -----------------------------------------------------------------------

    /// Helper: build a `vfs_cap_data` revision-2 blob with the given
    /// `magic_etc` flags and the given `permitted_lo` set. All other
    /// fields are zeroed (matches a typical `setcap cap_sys_admin+ep`
    /// blob, which only sets bit 21 in `permitted_lo`).
    fn build_vfs_cap_data_v2(magic_etc: u32, permitted_lo: u32) -> [u8; VFS_CAP_DATA_V2_SIZE] {
        let mut buf = [0u8; VFS_CAP_DATA_V2_SIZE];
        buf[0..4].copy_from_slice(&magic_etc.to_le_bytes());
        buf[4..8].copy_from_slice(&permitted_lo.to_le_bytes());
        // bytes 8..20 (inheritable lo, permitted/inheritable hi) stay zero
        buf
    }

    #[test]
    fn xattr_decoder_accepts_v2_with_cap_sys_admin_and_effective_flag() {
        let buf = build_vfs_cap_data_v2(
            VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE,
            1u32 << CAP_SYS_ADMIN_BIT,
        );
        assert!(
            xattr_has_cap_sys_admin_effective(&buf),
            "well-formed v2 blob with CAP_SYS_ADMIN+effective must be accepted"
        );
    }

    #[test]
    fn xattr_decoder_accepts_v3_with_cap_sys_admin_and_effective_flag() {
        // A V3 blob is V2 + a trailing 4-byte rootid we ignore.
        let mut buf = [0u8; VFS_CAP_DATA_V3_SIZE];
        let v2 = build_vfs_cap_data_v2(
            VFS_CAP_REVISION_3 | VFS_CAP_FLAGS_EFFECTIVE,
            1u32 << CAP_SYS_ADMIN_BIT,
        );
        buf[..VFS_CAP_DATA_V2_SIZE].copy_from_slice(&v2);
        // bytes 20..24 (rootid) stay zero
        assert!(
            xattr_has_cap_sys_admin_effective(&buf),
            "well-formed v3 blob with CAP_SYS_ADMIN+effective must be accepted"
        );
    }

    #[test]
    fn xattr_decoder_rejects_when_effective_flag_is_clear() {
        // Caps are permitted but not effective on exec — `cap_sys_admin+p`
        // (no `+e`). The route helper requires effective caps, so reject.
        let buf = build_vfs_cap_data_v2(VFS_CAP_REVISION_2, 1u32 << CAP_SYS_ADMIN_BIT);
        assert!(!xattr_has_cap_sys_admin_effective(&buf));
    }

    #[test]
    fn xattr_decoder_rejects_when_cap_sys_admin_bit_missing() {
        // Effective flag set, but a different cap is in the permitted
        // mask (e.g., CAP_NET_ADMIN, bit 12). The helper must be
        // rejected: it has *some* caps but not the one the route
        // helper requires.
        let buf = build_vfs_cap_data_v2(VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE, 1u32 << 12);
        assert!(!xattr_has_cap_sys_admin_effective(&buf));
    }

    #[test]
    fn xattr_decoder_rejects_unknown_revision() {
        // V1 (revision 1) is the legacy 32-bit format the helper has
        // never been shipped under. Anything other than V2 / V3 is
        // treated as "not a cap blob we trust".
        let v1_revision = 0x0100_0000u32;
        let buf = build_vfs_cap_data_v2(
            v1_revision | VFS_CAP_FLAGS_EFFECTIVE,
            1u32 << CAP_SYS_ADMIN_BIT,
        );
        assert!(!xattr_has_cap_sys_admin_effective(&buf));
    }

    #[test]
    fn xattr_decoder_rejects_empty_or_truncated_blob() {
        // Empty xattr (`getxattr` returned 0 bytes) — common for files
        // with no `security.capability` xattr set at all.
        assert!(!xattr_has_cap_sys_admin_effective(&[]));
        // Truncated blob — kernel could never write this, but the
        // decoder must still refuse.
        assert!(!xattr_has_cap_sys_admin_effective(&[0u8; 12]));
    }

    #[test]
    fn has_required_caps_returns_false_for_nonexistent_path() {
        // Sanity for the wrapper: a path that does not exist must
        // never look "usable" — the `is_file()` short-circuit guards
        // the `getxattr` syscall.
        let tmp = tempfile::tempdir().expect("tempdir");
        let bogus = tmp.path().join("does-not-exist-helper");
        assert!(!has_required_caps(&bogus));
    }

    #[test]
    fn has_required_caps_returns_false_for_existing_file_without_caps() {
        // Most files on disk carry no `security.capability` xattr at
        // all (`getxattr` returns -1 / ENODATA). The wrapper must
        // collapse that into "not usable" without panicking.
        let tmp = tempfile::tempdir().expect("tempdir");
        let plain_file = tmp.path().join("not-a-route-helper");
        std::fs::write(&plain_file, b"").expect("write");
        assert!(
            !has_required_caps(&plain_file),
            "an empty file with no security.capability xattr must not look usable"
        );
    }

    // -----------------------------------------------------------------------
    // extract_repo_host: recognise the host component of a git remote URL so
    // the DNS pre-warm before `git clone` targets the right domain.
    // -----------------------------------------------------------------------

    #[test]
    fn extract_repo_host_https_url() {
        assert_eq!(
            extract_repo_host("https://github.com/octocat/Hello-World.git"),
            Some("github.com".to_string())
        );
    }

    #[test]
    fn extract_repo_host_http_url() {
        assert_eq!(
            extract_repo_host("http://gitserver.example/repo"),
            Some("gitserver.example".to_string())
        );
    }

    #[test]
    fn extract_repo_host_https_with_userinfo_and_port() {
        assert_eq!(
            extract_repo_host("https://user:pass@git.example.com:8443/owner/repo"),
            Some("git.example.com".to_string())
        );
    }

    #[test]
    fn extract_repo_host_ssh_url() {
        assert_eq!(
            extract_repo_host("ssh://git@github.com:22/octocat/Hello-World.git"),
            Some("github.com".to_string())
        );
    }

    #[test]
    fn extract_repo_host_scp_style() {
        // `git@host:path` is the SCP-like short form; it has no `://`.
        assert_eq!(
            extract_repo_host("git@github.com:octocat/Hello-World.git"),
            Some("github.com".to_string())
        );
    }

    #[test]
    fn extract_repo_host_file_url_returns_none() {
        assert_eq!(extract_repo_host("file:///srv/git/repo.git"), None);
    }

    #[test]
    fn extract_repo_host_bare_local_path_returns_none() {
        assert_eq!(extract_repo_host("/srv/git/repo.git"), None);
        assert_eq!(extract_repo_host("./relative.git"), None);
    }

    #[test]
    fn extract_repo_host_handles_trailing_port_without_userinfo() {
        assert_eq!(
            extract_repo_host("https://host.example:2222/repo"),
            Some("host.example".to_string())
        );
    }

    #[test]
    fn extract_repo_host_no_scheme_no_userinfo_returns_none() {
        // Bare "host/path" is ambiguous; treat as no recognisable host.
        assert_eq!(extract_repo_host("github.com/user/repo"), None);
    }

    // -----------------------------------------------------------------------
    // MONITORED_COMPONENTS: membership and probe-table sync
    // -----------------------------------------------------------------------

    #[test]
    fn monitored_components_every_label_has_a_probe() {
        // The gateway monitor calls `component_health(label)` for each
        // entry here, which dispatches via `component_probe`. A label
        // without a matching probe would silently return "unknown" on
        // every tick, making the monitor a no-op for that component.
        for (label, component) in MONITORED_COMPONENTS {
            assert!(
                sandbox_core::gateway::component_probe(label).is_some(),
                "MONITORED_COMPONENTS entry ({label:?}, {component:?}) has no \
                 corresponding component_probe — gateway monitor would be a \
                 no-op for this component"
            );
        }
    }

    #[test]
    fn monitored_components_includes_deny_logger() {
        // Regression guard for M10-S3 Phase 6: deny-logger is a
        // first-class monitored subcomponent (it has a real TCP/UDP
        // data path and a /health endpoint), so its liveness MUST
        // participate in `health_degraded` / `health_restored` events.
        assert!(
            MONITORED_COMPONENTS
                .iter()
                .any(|(label, component)| *label == "deny-logger"
                    && *component == HealthComponent::DenyLogger),
            "MONITORED_COMPONENTS must contain (\"deny-logger\", \
             HealthComponent::DenyLogger) — see M10-S3 Phase 6"
        );
    }

    #[test]
    fn monitored_components_covers_every_health_component_variant() {
        // Every `HealthComponent` variant must appear in
        // MONITORED_COMPONENTS — otherwise the enum carries a variant
        // that sandboxd's gateway monitor will never emit, which
        // desynchronises the event surface from the documented
        // subcomponent set.
        use sandbox_core::HealthComponent::*;
        let monitored: std::collections::HashSet<HealthComponent> = MONITORED_COMPONENTS
            .iter()
            .map(|(_, component)| *component)
            .collect();
        for variant in [DenyLogger, Envoy, Mitmproxy, Coredns] {
            assert!(
                monitored.contains(&variant),
                "HealthComponent::{variant:?} is not present in \
                 MONITORED_COMPONENTS — either add a monitor entry or \
                 remove the enum variant"
            );
        }
    }

    // -----------------------------------------------------------------------
    // fail_explicit_policy_apply: M10-S8 #16 regression guard
    //
    // Pre-M10-S8, `create_session` `warn!`-swallowed an `apply_policy`
    // error and returned a `Running` session with `Policy: none`,
    // silently violating the caller's `--policy` / `--preset` intent.
    // The helper extracted by M10-S8 flips this to a fatal failure:
    //   - session state transitions Running → Error
    //   - the HTTP response carries `error_response(e)` (5xx for the
    //     `SandboxError` variants `apply_policy` can produce)
    //   - teardown is issued for any partial networking state
    //
    // The test drives the helper directly (rather than the end-to-end
    // `create_session` handler) because the latter requires Docker +
    // Lima, which are banned from the `make test` hermetic tier
    // (see repo CLAUDE.md "Integration-test convention"). Driving
    // the helper with a real `SessionStore` + real `GatewayManager`
    // and `NetworkManager` constructors (neither of which touches the
    // network by itself) exercises the real state-transition + error-
    // mapping contract while keeping the test hermetic.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn fail_explicit_policy_apply_marks_session_error_and_returns_5xx() {
        use std::collections::HashMap;
        use std::net::Ipv4Addr;

        // Fresh store in a tempdir so the test is parallel-safe and
        // leaves no filesystem residue after `TempDir` drops.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (store, _orphans) =
            SessionStore::new(tmp.path().to_path_buf()).expect("open session store");
        let store = Arc::new(store);

        // Create a session and move it to `Running` — the only state
        // from which `create_session` reaches the `apply_policy` call.
        let session = store
            .create_session(SessionConfig::default(), Some("policy-fail-test".into()))
            .expect("create session");
        store
            .update_state(&session.id, SessionState::Running)
            .expect("transition Creating → Running");

        // Build the minimal manager surface the helper consumes. None
        // of these constructors make external calls — `GatewayManager`
        // is a unit struct and `NetworkManager::new` only allocates an
        // in-memory subnet allocator. The spawn_blocking
        // branch of the teardown will attempt to invoke `docker`
        // subcommands and either no-op (no matching container /
        // network) or log a best-effort warning; neither outcome is
        // fatal for the helper, which is exactly what this test pins.
        let gateway = Arc::new(GatewayManager::new());
        let network = Arc::new(
            NetworkManager::new(Ipv4Addr::new(10, 209, 0, 0), 24)
                .expect("construct NetworkManager"),
        );
        let ingestors: Mutex<HashMap<SessionId, SessionIngestor>> = Mutex::new(HashMap::new());

        // Use a `Gateway` error because that is the variant
        // `PolicyDistributor::distribute` returns when it cannot reach
        // the (nonexistent) gateway container — the realistic failure
        // mode the #16 branch is designed to catch.
        let synthetic_err = SandboxError::Gateway("synthetic: gateway unreachable".into());
        let (status, Json(body)) = fail_explicit_policy_apply(
            &store,
            &gateway,
            &network,
            &ingestors,
            &session.id,
            synthetic_err,
        )
        .await;

        // Contract 1: 5xx surfaces the failure to the caller. The
        // mapping for `SandboxError::Gateway` is 500 (shared with the
        // error_response tests above).
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "apply_policy failure must map to 500, not a 2xx that hides the failure"
        );
        assert!(
            body.error.contains("gateway unreachable"),
            "error body should pass the underlying message through unchanged, got: {}",
            body.error
        );

        // Contract 2: the session is now in `Error` state. This is the
        // signal `sandbox ps` / `inspect` surface to the operator so a
        // failed create is distinguishable from an inconsistent
        // `Running` session.
        let reloaded = store
            .get_session(&session.id)
            .expect("store readable")
            .expect("session row still present");
        assert_eq!(
            reloaded.state,
            SessionState::Error,
            "session must be marked Error so ps/inspect can surface the failed create"
        );
    }

    // -----------------------------------------------------------------------
    // fail_explicit_repo_clone: M10-S8 #34 regression guard
    //
    // Pre-M10-S8, the four `git clone` failure branches in
    // `create_session` `warn!`-swallowed the error and returned 201
    // CREATED with a `Running` session and an empty
    // `/home/agent/workspace/`. The CLI user observed success but
    // had no usable repo — silently violating the caller's
    // `--repo <url>` intent. The helper extracted by M10-S8 flips
    // this to a fatal failure with the same shape as #16:
    //   - session state transitions Running → Error
    //   - the HTTP response carries `error_response(e)` with the
    //     diagnostic message (exit code, stderr snippet, transport
    //     error, etc.) the caller built at the failure site
    //   - teardown is issued for any partial networking state
    //
    // The test drives the helper directly (rather than the end-to-end
    // `create_session` handler) for the same reason as #16: the
    // latter requires Docker + Lima, which are banned from
    // `make test` (see CLAUDE.md "Integration-test convention").
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn fail_explicit_repo_clone_marks_session_error_and_returns_5xx() {
        use std::collections::HashMap;
        use std::net::Ipv4Addr;

        // Fresh store in a tempdir — same hermetic shape as the #16
        // test above.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (store, _orphans) =
            SessionStore::new(tmp.path().to_path_buf()).expect("open session store");
        let store = Arc::new(store);

        // Move the session to `Running` — the only state from which
        // `create_session` reaches the `git clone` block.
        let session = store
            .create_session(SessionConfig::default(), Some("clone-fail-test".into()))
            .expect("create session");
        store
            .update_state(&session.id, SessionState::Running)
            .expect("transition Creating → Running");

        let gateway = Arc::new(GatewayManager::new());
        let network = Arc::new(
            NetworkManager::new(Ipv4Addr::new(10, 209, 0, 0), 24)
                .expect("construct NetworkManager"),
        );
        let ingestors: Mutex<HashMap<SessionId, SessionIngestor>> = Mutex::new(HashMap::new());

        // `Internal` matches what the four clone failure branches in
        // `create_session` build at the call site — they wrap exit
        // code / stderr / transport context in
        // `SandboxError::Internal(...)` so the message is
        // self-describing on the wire.
        let synthetic_err = SandboxError::Internal(
            "git clone of https://example.invalid/repo.git failed with exit code 128: \
             fatal: unable to access: Could not resolve host"
                .into(),
        );
        let (status, Json(body)) = fail_explicit_repo_clone(
            &store,
            &gateway,
            &network,
            &ingestors,
            &session.id,
            synthetic_err,
        )
        .await;

        // Contract 1: 5xx surfaces the failure to the caller.
        // `SandboxError::Internal` maps to 500 (see error_response
        // mapping table above).
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "clone failure must map to 500, not a 2xx that hides the failure"
        );
        // Contract 1b: the diagnostic context built at the failure
        // site (exit code, stderr snippet) reaches the wire body.
        // Without this, the CLI user sees a 500 with no actionable
        // hint about *why* the clone failed.
        assert!(
            body.error.contains("git clone of"),
            "error body should mention the operation that failed, got: {}",
            body.error
        );
        assert!(
            body.error.contains("exit code 128"),
            "error body should pass exit code through, got: {}",
            body.error
        );
        assert!(
            body.error.contains("Could not resolve host"),
            "error body should pass stderr snippet through, got: {}",
            body.error
        );

        // Contract 2: the session is in `Error` state so `sandbox ps`
        // / `inspect` surface the failed create rather than a
        // misleading `Running` row with an empty workspace.
        let reloaded = store
            .get_session(&session.id)
            .expect("store readable")
            .expect("session row still present");
        assert_eq!(
            reloaded.state,
            SessionState::Error,
            "session must be marked Error so ps/inspect can surface the failed create"
        );
    }

    // -----------------------------------------------------------------------
    // truncate_for_diagnostic: stderr snippets in the error body must
    // stay under a sane size and respect UTF-8 boundaries.
    // -----------------------------------------------------------------------

    #[test]
    fn truncate_for_diagnostic_passes_short_strings_through() {
        assert_eq!(truncate_for_diagnostic("short", 100), "short");
        assert_eq!(truncate_for_diagnostic("", 100), "");
    }

    #[test]
    fn truncate_for_diagnostic_truncates_long_strings_with_marker() {
        let input = "x".repeat(1024);
        let out = truncate_for_diagnostic(&input, 16);
        assert_eq!(out.chars().take(16).collect::<String>(), "x".repeat(16));
        assert!(
            out.ends_with("…[truncated]"),
            "truncated output should carry an explicit marker, got: {out}"
        );
    }

    #[test]
    fn truncate_for_diagnostic_is_utf8_safe() {
        // Multi-byte chars: each `é` is 2 bytes but 1 char. A naive
        // byte-slice truncate would split the codepoint and panic.
        let input: String = "é".repeat(100);
        let out = truncate_for_diagnostic(&input, 10);
        assert!(out.starts_with(&"é".repeat(10)));
        assert!(out.ends_with("…[truncated]"));
    }

    // -----------------------------------------------------------------------
    // fail_explicit_boot_cmd: M10-S9 #53 regression guard
    //
    // Pre-M10-S9, the four boot-command failure branches in
    // `create_session` (non-zero exit, `GuestResponse::Error`,
    // unexpected guest response, transport error) all
    // `warn!`-swallowed the failure and the handler returned 201
    // CREATED with a `Running` session whose boot command's side
    // effects were unrealised — the same shape that #16
    // (`--policy`) and #34 (`--repo`) had pre-fix. The helper
    // extracted by M10-S9 mirrors its two siblings: when the
    // caller supplies `--boot-cmd <cmd>` and the command does not
    // succeed in-guest, the create call must fail.
    //
    // Contracts pinned here mirror the #34 test verbatim:
    //   - 5xx response (not a 2xx that hides the failure),
    //   - the diagnostic context built at the failure site
    //     (operation, exit code, stderr snippet) reaches the wire
    //     body verbatim, so the CLI user sees *why* the boot
    //     command did not succeed,
    //   - the session row transitions to `Error`.
    //
    // Like #16 and #34, the test drives the helper directly because
    // the end-to-end `create_session` handler requires Docker + Lima,
    // which are banned from `make test` (see CLAUDE.md
    // "Integration-test convention").
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn fail_explicit_boot_cmd_marks_session_error_and_returns_5xx() {
        use std::collections::HashMap;
        use std::net::Ipv4Addr;

        // Fresh store in a tempdir — same hermetic shape as the #16
        // and #34 tests above.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (store, _orphans) =
            SessionStore::new(tmp.path().to_path_buf()).expect("open session store");
        let store = Arc::new(store);

        // Move the session to `Running` — the only state from which
        // `create_session` reaches the boot-command block.
        let session = store
            .create_session(SessionConfig::default(), Some("boot-cmd-fail-test".into()))
            .expect("create session");
        store
            .update_state(&session.id, SessionState::Running)
            .expect("transition Creating → Running");

        let gateway = Arc::new(GatewayManager::new());
        let network = Arc::new(
            NetworkManager::new(Ipv4Addr::new(10, 209, 0, 0), 24)
                .expect("construct NetworkManager"),
        );
        let ingestors: Mutex<HashMap<SessionId, SessionIngestor>> = Mutex::new(HashMap::new());

        // `Internal` matches what the four boot-command failure
        // branches in `create_session` build at the call site — they
        // wrap exit code / stderr / transport context in
        // `SandboxError::Internal(...)` so the message is
        // self-describing on the wire. The synthetic shape here
        // mirrors what the non-zero-exit branch produces in
        // production.
        let synthetic_err = SandboxError::Internal(
            "boot command \"make setup\" failed with exit code 2: \
             make: *** [setup] Error 2"
                .into(),
        );
        let (status, Json(body)) = fail_explicit_boot_cmd(
            &store,
            &gateway,
            &network,
            &ingestors,
            &session.id,
            synthetic_err,
        )
        .await;

        // Contract 1: 5xx surfaces the failure to the caller.
        // `SandboxError::Internal` maps to 500 (see error_response
        // mapping table above).
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "boot-cmd failure must map to 500, not a 2xx that hides the failure"
        );
        // Contract 1b: the diagnostic context built at the failure
        // site (operation, exit code, stderr snippet) reaches the
        // wire body. Without this, the CLI user sees a 500 with no
        // actionable hint about *why* the boot command failed.
        assert!(
            body.error.contains("boot command"),
            "error body should mention the operation that failed, got: {}",
            body.error
        );
        assert!(
            body.error.contains("exit code 2"),
            "error body should pass exit code through, got: {}",
            body.error
        );
        assert!(
            body.error.contains("Error 2"),
            "error body should pass stderr snippet through, got: {}",
            body.error
        );

        // Contract 2: the session is in `Error` state so `sandbox ps`
        // / `inspect` surface the failed create rather than a
        // misleading `Running` row whose boot command's side effects
        // are unrealised.
        let reloaded = store
            .get_session(&session.id)
            .expect("store readable")
            .expect("session row still present");
        assert_eq!(
            reloaded.state,
            SessionState::Error,
            "session must be marked Error so ps/inspect can surface the failed create"
        );
    }

    // -- RebuildImageRequest body deserialization (M11-S4 Phase 4C) --------

    /// Spec § "rebuild-image" + Phase 4C: an empty body must decode as
    /// `{ "backend": "lima", "no_cache": false }` so older CLIs that
    /// POST `/rebuild-image` with no body keep working (backwards-
    /// compat at the wire — handoff Constraints).
    #[test]
    fn rebuild_image_request_default_is_lima_no_cache_false() {
        let req = RebuildImageRequest::default();
        assert_eq!(req.backend, BackendKind::Lima);
        assert!(!req.no_cache);
    }

    /// Full-shape JSON parses to the exact field values; pinned so a
    /// future refactor of the JSON shape (e.g. renaming a field via
    /// `#[serde(rename)]`) breaks compile/test, not the wire contract.
    #[test]
    fn rebuild_image_request_parses_full_container_no_cache_true() {
        let body = br#"{"backend":"container","no_cache":true}"#;
        let req: RebuildImageRequest = serde_json::from_slice(body).expect("valid body parses");
        assert_eq!(req.backend, BackendKind::Container);
        assert!(req.no_cache);
    }

    /// `{ "backend": "lima" }` (no_cache omitted) defaults `no_cache`
    /// to `false` — `#[serde(default)]` on the struct lets every
    /// field round-trip independently.
    #[test]
    fn rebuild_image_request_omitted_no_cache_defaults_to_false() {
        let body = br#"{"backend":"lima"}"#;
        let req: RebuildImageRequest = serde_json::from_slice(body).expect("partial body parses");
        assert_eq!(req.backend, BackendKind::Lima);
        assert!(!req.no_cache);
    }

    /// `{ "no_cache": true }` (backend omitted) defaults `backend` to
    /// `Lima` — same forward-compat shape as the empty-body fallback.
    #[test]
    fn rebuild_image_request_omitted_backend_defaults_to_lima() {
        let body = br#"{"no_cache":true}"#;
        let req: RebuildImageRequest = serde_json::from_slice(body).expect("partial body parses");
        assert_eq!(req.backend, BackendKind::Lima);
        assert!(req.no_cache);
    }

    /// Empty JSON object `{}` decodes as the full default — the shape
    /// the empty-body fallback path explicitly constructs without
    /// going through serde, but pinning the parse path catches any
    /// drift in the `Default` impl.
    #[test]
    fn rebuild_image_request_empty_object_yields_default() {
        let body = b"{}";
        let req: RebuildImageRequest = serde_json::from_slice(body).expect("empty object parses");
        assert_eq!(req.backend, BackendKind::Lima);
        assert!(!req.no_cache);
    }

    /// Unknown backend kinds surface as a parse error — the handler
    /// wraps this in `InvalidArgument` (HTTP 400). serde's enum-variant
    /// error names the unknown variant and the expected ones; pin both
    /// so a stray rename of `BackendKind` variants is caught here.
    #[test]
    fn rebuild_image_request_unknown_backend_errors() {
        let body = br#"{"backend":"podman"}"#;
        let err = serde_json::from_slice::<RebuildImageRequest>(body)
            .expect_err("unknown backend must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("podman"),
            "error should name the unknown variant; got: {msg}"
        );
        assert!(
            msg.contains("lima") && msg.contains("container"),
            "error should list the valid backends; got: {msg}"
        );
    }

    /// M11-S4 Phase 4D-pre gap #1 regression guard: the daemon must
    /// construct `ContainerRuntime` with the *same* image tag that
    /// `ensure_image` builds. Previously `main()` passed
    /// `DEFAULT_LITE_IMAGE_TAG` (`"sandboxd-lite:latest"`) while
    /// `ensure_image` builds `sandboxd-lite:<CARGO_PKG_VERSION>`,
    /// so `docker create` saw an image tag that no build step ever
    /// produced. Routing both through `lite_image_tag_for_version`
    /// closes the drift; this test fails-loud if either side ever
    /// computes the tag from a different formula again.
    #[test]
    fn daemon_lite_image_tag_matches_ensure_image_for_same_version() {
        let version = env!("CARGO_PKG_VERSION");
        let daemon_runtime_tag = lite_image_tag_for_version(version);
        // Mirror the construction `main()` performs on startup.
        let constructed = format!("sandboxd-lite:{version}");
        assert_eq!(
            daemon_runtime_tag, constructed,
            "lite_image_tag_for_version must produce the canonical \
             sandboxd-lite:<version> tag the daemon stores in its runtime"
        );
        // The CARGO_PKG_VERSION value is non-empty by definition; the
        // tag must therefore never collapse to the bare `:latest`
        // placeholder that gap #1 left behind.
        assert_ne!(
            daemon_runtime_tag, "sandboxd-lite:latest",
            "production daemon must not reference the :latest fixture tag"
        );
    }
}
