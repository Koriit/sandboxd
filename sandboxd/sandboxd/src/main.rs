use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{ConnectInfo, Path, Request, State, connect_info::Connected},
    http::StatusCode,
    middleware::{Next, from_fn},
    response::IntoResponse,
    routing::{delete, get, post},
    serve::IncomingStream,
};
use clap::Parser;
use sandbox_core::backend::{
    BackendKind, CliDockerOps, ContainerRuntime, EnsureImageOutcome, LITE_FIRST_USE_WARNING,
    LimaRuntime, RuntimeHandle, RuntimeStartArgs, SANDBOX_CA_CONTAINER_PATH, SessionRuntime,
    compute_default_resource_limits, ensure_image, home_volume_name, lite_image_tag_for_version,
    map_container_uid_gid, reap_orphans, rebuild_lite_image,
};
use sandbox_core::bridge_conf;
use sandbox_core::events::lifecycle as lifecycle_events;
use sandbox_core::events::session_events_host_dir;
use sandbox_core::gateway::container_name as gateway_container_name;
use sandbox_core::users_conf::validate_users_conf_schema_version;
use sandbox_core::{
    ApiError, AssuranceLevel, BaseImageStatus, CaManager, Cidr4, CoreDnsConfig,
    CreateSessionRequest, DEFAULT_DEADLINE_MS as DNS_GATE_DEFAULT_DEADLINE_MS, Destination,
    DnsCache, DockerExecLdsProbe, DockerHealth, EventBus, EventBusConfig, ExecRequest,
    ExecResponse, GateRequest, GateService, GateServiceOutcome, GateStatus, GatewayHealth,
    GatewayManager, GatewayShutdownReason, GatewayStatus, GuestConnector, GuestResponse,
    HealthComponent, LdsAckOutcome, LdsStatsProbe, LimaManager, LockState, LockToken,
    NetworkHealth, NetworkInfo, NetworkManager, OperatorIdentity, PersistConfig, PersistentSink,
    Policy, PolicyApplyStatus, PolicyCompiler, PolicyDistributor, SandboxError, Session,
    SessionConfig, SessionDto, SessionHealth, SessionId, SessionIngestor, SessionMountInfo,
    SessionNetworkInfo, SessionState, SessionStore, UpdatePolicyRequest, UsersConfig,
    VmIpSessionMap, VmStatus, WorkspaceLockAcquireRequest, WorkspaceLockAcquireResponse,
    WorkspaceLockReleaseRequest, WorkspaceOp, attach_vm_to_bridge, bind_gate_listener,
    detach_vm_from_bridge, generate_ca_inject_script, generate_domain_ip_rules, hash_policy,
    load_users_config, mac_from_session_id, propagate_dns_changes, read_resolved_json,
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
#[command(name = "sandboxd", about = "Sandbox daemon", version)]
struct Args {
    /// Path to the Unix socket to listen on.
    #[arg(long, env = "SANDBOX_SOCKET", default_value_t = default_socket_path())]
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
    /// Default of 14 days matches the event wire format / "Retention"
    /// suggested value and covers roughly two sprint cycles of traffic
    /// for post-incident review. Overridable via
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
    // Returns the XDG/HOME-derived fallback path. SANDBOX_SOCKET is handled
    // by clap's `env = "SANDBOX_SOCKET"` on the `--socket` arg (which is
    // evaluated per-parse and takes precedence over this default). An
    // explicit `--socket` flag takes precedence over the env var.
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

/// State-dir subdirectories whose mode the daemon enforces on every
/// startup. Each is created with mode `0700` if absent; an existing
/// directory with a different mode is corrected in place with a
/// `warn!` line; an existing path that is not a directory is fatal.
///
/// The set is small and stable; carry it as a `&[&str]` so a future
/// caller can introspect or iterate without re-importing the list.
const BASE_DIR_SUBDIRS: &[&str] = &["sessions", "events", "backups"];

/// The numeric mode every per-daemon state-dir subdirectory must
/// carry. `0700` matches the daemon-uid-only access expectation
/// recorded in the daemon-productionization design: the daemon
/// reads and writes its own state; no other uid has any business
/// there.
const BASE_DIR_SUBDIR_MODE: u32 = 0o700;

/// Enforce the base-dir layout invariants on every startup.
///
/// Called once from `main`, immediately after the daemon has ensured
/// the base-dir itself exists and before any code path opens
/// `sessions.db`. The function is synchronous and CPU-cheap (three
/// `stat` calls in the happy path), so it does not need a
/// `spawn_blocking` wrapper.
///
/// Behavior per subdir:
///
/// 1. Missing → create with mode [`BASE_DIR_SUBDIR_MODE`].
/// 2. Present with a different mode → log `warn!`, then chmod in
///    place. Continue startup.
/// 3. Present with the correct mode → no-op.
/// 4. Path exists but is **not** a directory → log `error!` and
///    return `SandboxError::Internal`. The daemon refuses to start
///    so a misconfigured filesystem can't be papered over.
/// 5. Chmod (or create) fails → propagate the `io::Error` through
///    `SandboxError::Io`; the daemon refuses to start.
fn ensure_base_dir_layout(base_dir: &std::path::Path) -> Result<(), SandboxError> {
    use std::os::unix::fs::PermissionsExt;

    for sub in BASE_DIR_SUBDIRS {
        let path = base_dir.join(sub);
        match std::fs::metadata(&path) {
            Ok(md) if md.is_dir() => {
                let mode = md.permissions().mode() & 0o777;
                if mode != BASE_DIR_SUBDIR_MODE {
                    warn!(
                        path = %path.display(),
                        current = format!("{mode:o}"),
                        expected = format!("{BASE_DIR_SUBDIR_MODE:o}"),
                        "subdir mode is not 0700; correcting"
                    );
                    let mut perms = md.permissions();
                    perms.set_mode(BASE_DIR_SUBDIR_MODE);
                    std::fs::set_permissions(&path, perms).map_err(|e| {
                        error!(
                            path = %path.display(),
                            error = %e,
                            "failed to chmod subdir to 0700; refusing to start"
                        );
                        SandboxError::Io(e)
                    })?;
                }
            }
            Ok(_) => {
                error!(
                    path = %path.display(),
                    "expected a directory but found a non-directory; refusing to start"
                );
                return Err(SandboxError::Internal(format!(
                    "{} exists but is not a directory",
                    path.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&path).map_err(|e| {
                    error!(
                        path = %path.display(),
                        error = %e,
                        "failed to create subdir; refusing to start"
                    );
                    SandboxError::Io(e)
                })?;
                std::fs::set_permissions(
                    &path,
                    std::fs::Permissions::from_mode(BASE_DIR_SUBDIR_MODE),
                )
                .map_err(|e| {
                    error!(
                        path = %path.display(),
                        error = %e,
                        "failed to set initial mode on subdir; refusing to start"
                    );
                    SandboxError::Io(e)
                })?;
            }
            Err(e) => {
                error!(
                    path = %path.display(),
                    error = %e,
                    "failed to stat subdir; refusing to start"
                );
                return Err(SandboxError::Io(e));
            }
        }
    }
    Ok(())
}

/// Mode pinned on `sandboxd.sock` immediately after bind. The
/// design documents the socket as
/// `0660 sandbox:sandbox`; doctor check C5 reads `stat(sock).mode &
/// 0o777` against this constant. Forcing the mode explicitly avoids
/// a false-negative on a host running under a `077`-style umask
/// where `bind()` would otherwise land the socket at `0600` (or, on
/// the more common `022` server umask, at `0644` — too permissive
/// for the group-only contract).
const SOCKET_MODE: u32 = 0o660;

/// Bind the unix socket and pin its mode to `0660` before any client
/// can connect.
///
/// `tokio::net::UnixListener::bind` creates the socket inode under the
/// process umask, so the mode of the resulting file is non-deterministic
/// across operator environments. The socket mode contract is `0660`;
/// doctor check C5 reads
/// the on-disk mode to verify it. Calling `set_permissions` immediately
/// after the bind, before the accept loop starts, makes the contract
/// hold regardless of umask and regardless of whether the operator
/// remembered to set `UMask=0117` in the systemd drop-in.
///
/// A failure to chmod the socket is fatal: an unenforceable mode is a
/// silent security regression we will not let through.
fn bind_socket(socket_path: &std::path::Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(SOCKET_MODE)).map_err(
        |e| {
            error!(
                path = %socket_path.display(),
                error = %e,
                mode = format!("{SOCKET_MODE:o}"),
                "failed to pin socket mode; refusing to start"
            );
            e
        },
    )?;
    Ok(listener)
}

// Image-presence probe and the operator-facing missing-image hint
// live in `sandbox-core::gateway` so the integration test suite (which
// imports from sandbox-core, not the daemon binary) can pin the same
// byte sequence the daemon emits.
use sandbox_core::gateway::{gateway_image_present, missing_gateway_image_hint};

// ---------------------------------------------------------------------------
// users.conf startup validation
// ---------------------------------------------------------------------------
//
// The daemon refuses to start unless `/etc/sandboxd/users.conf`
// (or its `SANDBOX_USERS_CONF` test-only override) contains a subnet entry whose
// `allow_users` resolves to the daemon's own uid. The matched subnet's CIDR
// scopes `NetworkManager`'s per-session /28 allocation pool.
//
// See:
//   - lite-mode container backend ("Config file:
//     /etc/sandboxd/users.conf") — the contract this validation enforces.
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

    // Grep-stable phrasing: the install docs reference the "no
    // users.conf subnet matches daemon user" prefix verbatim. Do
    // not re-word without coordinating the docs change.
    Err(SandboxError::InvalidArgument(format!(
        "no users.conf subnet matches daemon user {user_label} \
         in {path}; see install docs at docs/start/installation.md",
        path = users_conf_path().display(),
    )))
}

// ---------------------------------------------------------------------------
// SANDBOX_BASE_VM_NAME validation
// ---------------------------------------------------------------------------
//
// Lima instance names appear as positional arguments in every limactl
// invocation that touches the singleton golden-image VM. An
// attacker-controlled `SANDBOX_BASE_VM_NAME` could otherwise inject
// `--`-prefixed flags into the argv (e.g. `--evil`), so the daemon
// validates the name at startup against the same character class Lima
// itself accepts and rejects malformed values with a clear error before
// it ever shells out.

/// Maximum length of a Lima instance name; matches Lima's own cap.
const BASE_VM_NAME_MAX_LEN: usize = 63;

/// Environment variable that overrides the default base VM name.
const BASE_VM_NAME_ENV: &str = "SANDBOX_BASE_VM_NAME";

/// Validate a Lima instance name destined for `limactl create --name <name>`.
///
/// Accepts the regex `^[A-Za-z0-9][-A-Za-z0-9]*$` with a length cap of
/// [`BASE_VM_NAME_MAX_LEN`]. Rejects:
/// - empty strings
/// - names starting with `-` (would be parsed as a flag by limactl)
/// - names containing characters outside `[A-Za-z0-9-]`
/// - names longer than 63 characters
///
/// Pure function — split out from the startup wiring so unit tests can
/// drive every rejection case without spawning the daemon.
fn validate_base_vm_name(name: &str) -> Result<(), SandboxError> {
    if name.is_empty() {
        return Err(SandboxError::InvalidArgument(format!(
            "{BASE_VM_NAME_ENV} is empty; expected a Lima instance name \
             matching ^[A-Za-z0-9][-A-Za-z0-9]*$"
        )));
    }
    if name.len() > BASE_VM_NAME_MAX_LEN {
        return Err(SandboxError::InvalidArgument(format!(
            "{BASE_VM_NAME_ENV}={name:?} exceeds the {BASE_VM_NAME_MAX_LEN}-character limit"
        )));
    }
    let mut chars = name.chars();
    let first = chars.next().expect("non-empty checked above");
    if !first.is_ascii_alphanumeric() {
        return Err(SandboxError::InvalidArgument(format!(
            "{BASE_VM_NAME_ENV}={name:?} must start with an ASCII alphanumeric \
             character (got {first:?}); names beginning with '-' would be \
             parsed as a flag by limactl"
        )));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '-') {
            return Err(SandboxError::InvalidArgument(format!(
                "{BASE_VM_NAME_ENV}={name:?} contains the disallowed character \
                 {c:?}; only ASCII alphanumerics and '-' are permitted"
            )));
        }
    }
    Ok(())
}

/// Resolve the base VM name from the `SANDBOX_BASE_VM_NAME` env var,
/// falling back to [`DEFAULT_BASE_VM_NAME`].
///
/// Validation happens here so a single early failure stops the daemon
/// before any limactl argv is built. Returns the validated name as an
/// owned `String` ready to hand to [`LimaManager::new`].
fn resolve_base_vm_name() -> Result<String, SandboxError> {
    let raw = std::env::var(BASE_VM_NAME_ENV)
        .unwrap_or_else(|_| sandbox_core::DEFAULT_BASE_VM_NAME.to_string());
    validate_base_vm_name(&raw)?;
    Ok(raw)
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
// Route-helper path resolution
// ---------------------------------------------------------------------------
//
// `sandbox-route-helper` is the privileged setcap binary the daemon
// spawns when a lite session starts (see `ContainerRuntime::start` →
// `invoke_route_helper`). The resolver considers two
// candidate sources; the previous design (sibling-of-daemon +
// canonical install + `$PATH`-walk + cap check) shipped silent fallback
// modes that were either invisible (`$PATH` outside the operator's
// awareness) or mis-targeted (sibling-of-daemon picks an un-cap'd
// `target/debug/` build under 9p / virtio-fs / bind-mount layouts that
// `setcap` cannot annotate).
//
// Lookup order:
//
//   0. `$SANDBOX_ROUTE_HELPER_PATH` — explicit operator override. If
//      set, the resolver uses ONLY this path. Fail-closed: if the path
//      is missing or lacks the cap xattr, the daemon errors out with
//      a message naming the env var. This is for tests and unusual
//      deployments; production operators should not set it.
//   1. `/usr/local/libexec/sandboxd/sandbox-route-helper` — canonical
//      production install path (FHS § 4.7: libexec is for non-user-
//      facing helper executables). Installed by
//      `make install-route-helper-prod-cap`.
//
// Cap-xattr check stays. "Usable" means the file exists AND carries
// the `CAP_SYS_ADMIN` file capability with the effective bit set. A
// missing or un-cap'd binary at the canonical path triggers an error
// pointing at the make target and the install docs.
//
// The function returns a `SandboxError::Internal` rather than a custom
// error type so call sites can propagate it through the existing
// daemon error pipeline. The error message names both candidates (the
// env-var path if it was set, and the canonical install path always),
// the cap requirement, and the `make` target an operator can run to
// fix it.

/// Canonical install path (FHS § 4.7). Used as the only on-disk
/// candidate when `SANDBOX_ROUTE_HELPER_PATH` is not set, and named in
/// the error message in either case.
const ROUTE_HELPER_INSTALL_PATH: &str = "/usr/local/libexec/sandboxd/sandbox-route-helper";

/// Environment variable for explicit operator override of the
/// route-helper path. When set, the resolver uses this path and only
/// this path (fail-closed if missing or un-cap'd). Intended for tests
/// and unusual deployments; production operators should not set it.
const ROUTE_HELPER_PATH_ENV: &str = "SANDBOX_ROUTE_HELPER_PATH";

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
/// if the env-var override is set but its target is missing or
/// un-cap'd, the resolver errors out *without* falling through to the
/// canonical path — explicit operator intent must not be silently
/// overruled. If the env var is unset, the resolver consults the
/// canonical install path and errors out if the file is missing or
/// un-cap'd, naming the make target operators can run to install it.
fn resolve_route_helper_path() -> Result<PathBuf, SandboxError> {
    let env_override = std::env::var_os(ROUTE_HELPER_PATH_ENV).map(PathBuf::from);
    let install_path = PathBuf::from(ROUTE_HELPER_INSTALL_PATH);
    resolve_route_helper_path_from(env_override.as_deref(), &install_path, has_required_caps)
}

/// Pure inner of [`resolve_route_helper_path`].
///
/// Two-step resolver:
///
///   - If `env_override` is `Some(path)`, that is the ONLY candidate.
///     Fail-closed if `is_usable(path)` is false — explicit operator
///     intent is not silently overruled.
///   - Otherwise, the canonical `install_path` is the only candidate.
///     Same `is_usable` requirement; an un-cap'd file at the canonical
///     path is a misconfiguration, not a "fall back to something else"
///     situation.
///
/// Parameterized over `is_usable` so the unit tests can drive the
/// resolver without `setcap`-ing real binaries. Setting file caps
/// requires `CAP_SETFCAP` and is not portable in a unit test
/// environment.
fn resolve_route_helper_path_from<F>(
    env_override: Option<&std::path::Path>,
    install_path: &std::path::Path,
    is_usable: F,
) -> Result<PathBuf, SandboxError>
where
    F: Fn(&std::path::Path) -> bool,
{
    if let Some(env_path) = env_override {
        if is_usable(env_path) {
            return Ok(env_path.to_path_buf());
        }
        return Err(SandboxError::Internal(format!(
            "sandbox-route-helper not usable at {env_path} (set via \
             ${ROUTE_HELPER_PATH_ENV}); the file must exist as a regular \
             file AND carry the CAP_SYS_ADMIN file capability (effective): \
             `sudo setcap cap_sys_admin+ep {env_path}`. To use the canonical \
             install instead, unset {env}; the resolver then looks up \
             {install} (installed by `make install-route-helper-prod-cap`). \
             See docs/start/installation.md § \"sandbox-route-helper\".",
            env_path = env_path.display(),
            env = ROUTE_HELPER_PATH_ENV,
            install = install_path.display(),
        )));
    }
    if is_usable(install_path) {
        return Ok(install_path.to_path_buf());
    }
    Err(SandboxError::Internal(format!(
        "no usable sandbox-route-helper found at the canonical install \
         path {install}. The file must exist as a regular file AND carry the \
         CAP_SYS_ADMIN file capability (effective). Install it with: \
         `make install-route-helper-prod-cap` (production) or set \
         ${ROUTE_HELPER_PATH_ENV} to a custom path. See \
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
/// treat *every* failure mode as "not usable, fail closed": a missing
/// file (ENOENT), a missing or empty `security.capability` xattr
/// (ENODATA), an unreadable file (EACCES), a malformed xattr blob, or
/// anything else, all reduce to `false`. The resolver's error message
/// names whichever path it consulted (env override or canonical) plus
/// the cap requirement and the make target an operator can run, so the
/// negative result is debuggable without a per-candidate reason code.
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
    // Wrapped in `Arc` so the events sub-router (built
    // in [`app`]) can hold its own `Arc<SessionStore>` handle inside an
    // `Arc<events_http::EventsApiState>` without the two routers having
    // to share state via axum's `FromRef`. `SessionStore` is internally
    // `Mutex`-guarded, so the shared handle is safe and adds no
    // synchronization beyond what the store already performs.
    store: Arc<SessionStore>,
    /// Backend dispatch table keyed by [`BackendKind`].
    ///
    /// Handler call sites talking to the *generic* lifecycle
    /// (create / start / stop / delete / status / ip / exec_interactive
    /// / guest_transport) go through the trait, while Lima-specific
    /// orchestration (clone, base image, agent install, list_vms)
    /// continues to call the typed runtime directly via
    /// [`LimaRuntime::manager`]. The same `Arc<LimaRuntime>` is
    /// registered here under [`BackendKind::Lima`] and held by
    /// `lima_runtime` — there is one Lima runtime instance reachable
    /// both ways. The container backend is registered alongside
    /// under [`BackendKind::Container`].
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
    /// Handles for the per-session synchronous DNS-gate listener tasks.
    /// Each handle drives the UDS server bound at
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
    /// unregistered on teardown / deletion.  Ingest tasks
    /// publish into the bus; SSE handlers subscribe.
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
    /// Per-session JSONL ingest tasks.
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
    /// Per-session workspace lock map.
    ///
    /// Serialises the workspace operations defined in
    /// [`sandbox_core::WorkspaceOp`] (initial / pull / push) so that two
    /// callers cannot concurrently mutate the same session's workspace
    /// view. The outer `std::sync::Mutex` guards only mutations of the
    /// map itself (`entry(...).or_insert_with(...)`), so it is held
    /// briefly and never across `.await`. The inner
    /// `tokio::sync::Mutex<LockState>` is the per-session async lock
    /// that handlers hold across the long-running rsync / guest
    /// transitions — that one MUST be a tokio mutex because it crosses
    /// `.await` boundaries.
    ///
    /// Inserted lazily by [`workspace_lock_for_map`] on first reference
    /// for a session; entries are pruned by the session-lifecycle
    /// handlers (remove path) so the map size tracks live sessions.
    workspace_locks: std::sync::Mutex<HashMap<SessionId, Arc<Mutex<sandbox_core::LockState>>>>,
    /// Per-session policy-propagation tracker.
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
    /// Daemon's compile-time uid as observed at startup. Cached so the
    /// `GET /diagnostics` handler can render the load-bearing
    /// `daemon_uid` / `daemon_user` fields without re-querying the
    /// kernel on every probe.
    daemon_uid: u32,
    /// Daemon's resolved username (via `getpwuid_r` at startup).
    /// Empty when resolution fails — the doctor's C1/C2 fail-paths
    /// already surface that, so the diagnostics handler doesn't
    /// double-report.
    daemon_user: String,
    /// The `users.conf` subnet entry the daemon matched at startup —
    /// the CIDR pool the operator authorized for this uid. Surfaced
    /// verbatim through `GET /diagnostics` (C11) so doctor's report
    /// shows the actually-resolved pool rather than expecting the
    /// operator to grep journald.
    users_conf_pool: sandbox_core::users_conf::SubnetEntry,
}

/// Look up the runtime for a given backend kind from the dispatch
/// table.
///
/// Used by handlers that already know the backend kind for the
/// session they are operating on — typically because they read it
/// off the persisted `Session::backend` field. The same call site
/// works for both `BackendKind::Lima` and `BackendKind::Container`
/// rows without any per-handler branching.
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

/// Inner helper: look up (or lazily create) the per-session workspace
/// lock entry in a bare lock map.
///
/// Kept separate from [`workspace_lock_for`] so unit tests can drive
/// the map shape directly without paying the cost of building a full
/// [`AppState`] (which owns a live `SessionStore`, `LimaRuntime`,
/// `ContainerRuntime`, `NetworkManager`, `GatewayManager`, etc.).
///
/// Returns a cloned [`Arc`] so the caller releases the outer
/// `std::sync::Mutex` immediately and then awaits the inner
/// `tokio::sync::Mutex<LockState>` without holding the map lock
/// across `.await`. The `entry(...).or_insert_with(...)` shape
/// guarantees idempotent creation: concurrent first-acquire calls
/// for the same session race for the outer sync mutex, and only the
/// first creates the inner `LockState`; subsequent calls receive
/// the same `Arc`.
///
/// Panics if the outer `std::sync::Mutex` is poisoned. The map is
/// only ever held briefly to swap an `Arc` clone in or out — a
/// poisoned map means a panic already aborted that critical section,
/// and the daemon is in an unrecoverable state. This matches the
/// `expect(...)` convention other short-lived `std::sync::Mutex`
/// locks use in this crate.
fn workspace_lock_for_map(
    map: &std::sync::Mutex<HashMap<SessionId, Arc<Mutex<sandbox_core::LockState>>>>,
    session_id: &SessionId,
) -> Arc<Mutex<sandbox_core::LockState>> {
    let mut guard = map.lock().expect("workspace_locks mutex poisoned");
    guard
        .entry(*session_id)
        .or_insert_with(|| Arc::new(Mutex::new(sandbox_core::LockState::new())))
        .clone()
}

/// Look up (or lazily create) the per-session workspace lock for
/// [`SessionId`].
///
/// Thin wrapper over [`workspace_lock_for_map`] that targets the
/// [`AppState::workspace_locks`] field directly — the shape the
/// workspace acquire/release handlers use.
fn workspace_lock_for(
    state: &AppState,
    session_id: &SessionId,
) -> Arc<Mutex<sandbox_core::LockState>> {
    workspace_lock_for_map(&state.workspace_locks, session_id)
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
/// - `Container` mirrors the lite-mode wire shape from the design —
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
/// [`SessionConfig::cpus_decimal`] when present (the 1-decimal value
/// the operator supplied), falling back to the integer
/// [`SessionConfig::cpus`] otherwise. The Lima variant always
/// projects the integer field — Lima/QEMU pin whole cores.
///
/// `no_cache` is taken from the request rather than the persisted
/// config because it is a per-invocation flag (skip the cached fast
/// path) rather than a session-shape field — `SessionConfig` does not
/// carry it, the daemon consumes it once at create time. Threading
/// it through the projection lets `SessionSpec::validate` reject
/// `--no-cache` on backends whose `per_session_no_cache` capability
/// is `false`.
fn session_spec_from_config(
    config: &SessionConfig,
    kind: BackendKind,
    no_cache: Option<bool>,
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
        no_cache,
    }
}

/// Round a request-supplied `cpus` value to the 1-decimal grid
/// (e.g. `0.81 → 0.8`,
/// `1.55 → 1.5`).
///
/// Mirrors the rounding [`compute_default_resource_limits`] applies to
/// the daemon-side host-80% default so both code paths produce values
/// on the same grid. Without this normalisation step, an operator
/// typing `--cpus 0.81` would reach `format_cpus` as `0.81` and
/// render `--cpus 0.8` (truncating the trailing `1`) rather than
/// the intended round-to-grid behaviour.
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
// Peer-credential acceptor
// ---------------------------------------------------------------------------
//
// Helper-identity-assertion: every connection accepted on the
// daemon's Unix socket is augmented with the operator identity the
// kernel reports via `SO_PEERCRED`. The acceptor reads the credentials
// immediately after `accept(2)`, resolves the uid to a username via
// `getpwuid_r` (`nix::unistd::User::from_uid`), and attaches the
// resulting [`OperatorIdentity`] to every request flowing through the
// connection through axum's `into_make_service_with_connect_info`
// plumbing.
//
// Failure mode: a uid that does not resolve (host `/etc/passwd`
// corruption, race with `userdel`, container-uid-without-passwd) closes
// the stream and `warn!`-logs the unresolved uid. The acceptor continues
// accepting the next connection rather than crashing the server — the
// failure shape is rare and recoverable.
//
// The shape is implemented as a `Listener` impl whose `Addr` is the
// resolved [`OperatorIdentity`]. axum's `Connected<IncomingStream<'_,
// L>>` blanket impl picks up `L::Addr` and inserts it into the request
// extensions. The retry-on-resolution-failure loop lives inside
// `accept()` rather than the `Connected::connect_info` callback because
// the trait's signature is synchronous (`fn connect_info(target) ->
// Self`) and cannot refuse a connection — only the listener's accept
// path can drop a stream and continue.

/// Listener wrapper that reads `SO_PEERCRED` on every accepted
/// connection and yields the resolved [`OperatorIdentity`] as the
/// connection's `Addr`. Connections whose uid does not resolve are
/// closed and logged; the listener continues accepting.
struct PeerCredListener {
    inner: UnixListener,
}

impl PeerCredListener {
    fn new(inner: UnixListener) -> Self {
        Self { inner }
    }
}

/// Per-connection address type emitted by [`PeerCredListener`].
///
/// Local newtype wrapper around the workspace-shared
/// [`OperatorIdentity`]. The wrapper exists for the Rust orphan rule:
/// axum's `Connected` trait and `OperatorIdentity` both live outside
/// this crate, so a direct `impl Connected<…> for OperatorIdentity`
/// would not be permitted. The wrapper crate-locally satisfies the
/// orphan rule, the `Connected::connect_info` impl unwraps it into
/// `OperatorIdentity` for axum to insert as the request extension,
/// and every consumer of the extension (handlers) extracts
/// `Extension<OperatorIdentity>` directly.
#[derive(Debug, Clone)]
struct PeerCredAddr(OperatorIdentity);

impl axum::serve::Listener for PeerCredListener {
    type Io = tokio::net::UnixStream;
    type Addr = PeerCredAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, _peer_addr) = match self.inner.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    // Transient accept(2) error — log and retry. Same
                    // shape axum's built-in `UnixListener::accept` impl
                    // uses (`handle_accept_error`), but inlined here
                    // because the outer accept loop has to also handle
                    // the per-stream peer-cred read.
                    warn!(error = %e, "accept(2) failed; retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };

            let ucred = match stream.peer_cred() {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "peer_cred() failed; closing connection");
                    drop(stream);
                    continue;
                }
            };

            let uid_raw = ucred.uid();
            // `gid()` returns the operator's primary gid as kernel-reported by
            // `SO_PEERCRED`. Captured alongside `uid` so the supervisor-fork
            // pattern can align both halves of the container's
            // `--user <uid>:<gid>` flag (and the Lima cloud-init usermod step)
            // with the operator's on-host identity. Kernel-supplied, cannot be
            // spoofed by the client.
            let gid_raw = ucred.gid();
            match resolve_uid_to_name_with_retry(uid_raw, UID_RESOLVE_ATTEMPTS, UID_RESOLVE_BACKOFF)
                .await
            {
                Some(name) => {
                    return (
                        stream,
                        PeerCredAddr(OperatorIdentity {
                            uid: uid_raw,
                            gid: gid_raw,
                            name,
                        }),
                    );
                }
                None => {
                    warn!(
                        uid = uid_raw,
                        attempts = UID_RESOLVE_ATTEMPTS,
                        "peer uid does not resolve to a username after retries; closing connection"
                    );
                    drop(stream);
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        // `Listener::local_addr` is documented as "the address this
        // listener is bound to" — semantically meaningless for a
        // peer-cred-augmented Unix listener (there is no remote address
        // structurally; every accepted connection has its own
        // `OperatorIdentity`). axum's `serve` does not call `local_addr`
        // on the listener after binding, so this is unreachable in
        // practice; we surface a structured error so a future caller
        // that does invoke it sees a clear "this listener does not
        // expose a single addr" reason rather than a fabricated value.
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "PeerCredListener has no single local addr — every \
             connection has its own per-peer OperatorIdentity",
        ))
    }
}

/// Total attempts (initial + retries) for [`resolve_uid_to_name_with_retry`].
///
/// `getpwuid_r` can return transient `Ok(None)` for a valid uid under
/// host load (concurrent `/etc/passwd` readers/writers, NSS cache
/// eviction, slow NSS modules). Three attempts with a short backoff
/// absorb these transient absences without measurably delaying the
/// happy path or stretching the genuine-deny path.
const UID_RESOLVE_ATTEMPTS: u32 = 3;

/// Backoff between successive `getpwuid_r` attempts.
const UID_RESOLVE_BACKOFF: Duration = Duration::from_millis(50);

/// Resolve a uid to a username via `getpwuid_r`. Returns `None` on any
/// error (lookup failure or no matching record) so callers can collapse
/// "Err" and "Ok(None)" to the same "deny" path.
fn resolve_uid_to_name(uid: u32) -> Option<String> {
    use nix::unistd::{Uid, User};

    match User::from_uid(Uid::from_raw(uid)) {
        Ok(Some(user)) => Some(user.name),
        Ok(None) => None,
        Err(_) => None,
    }
}

/// [`resolve_uid_to_name`] with bounded retry + backoff to absorb
/// transient `getpwuid_r` failures under host load. A persistently
/// missing passwd entry (uid genuinely not in `/etc/passwd` / NSS)
/// still returns `None` after `attempts` tries, so the peer-cred
/// listener's deny path is unchanged for that case — just delayed
/// by ~`(attempts - 1) * backoff` in the worst case.
async fn resolve_uid_to_name_with_retry(
    uid: u32,
    attempts: u32,
    backoff: Duration,
) -> Option<String> {
    retry_lookup(attempts, backoff, || resolve_uid_to_name(uid)).await
}

/// Generic retry-with-backoff wrapper around a synchronous fallible
/// lookup. Extracted from [`resolve_uid_to_name_with_retry`] so the
/// retry/backoff logic itself is unit-testable (the live
/// `getpwuid_r`-backed lookup is exercised by integration tests).
async fn retry_lookup<T, F>(attempts: u32, backoff: Duration, mut lookup: F) -> Option<T>
where
    F: FnMut() -> Option<T>,
{
    for attempt in 0..attempts {
        if let Some(value) = lookup() {
            return Some(value);
        }
        if attempt + 1 < attempts {
            tokio::time::sleep(backoff).await;
        }
    }
    None
}

/// Bridge from axum's `Connected` trait into the request extension
/// map. axum's `IntoMakeServiceWithConnectInfo` invokes
/// `Connected::connect_info` per accepted stream and inserts the result
/// as a `ConnectInfo<PeerCredAddr>` request extension. The
/// [`operator_identity_layer`] middleware then unwraps it into a plain
/// `Extension<OperatorIdentity>` so handlers can pick it up with a
/// single-purpose extractor.
impl Connected<IncomingStream<'_, PeerCredListener>> for PeerCredAddr {
    fn connect_info(stream: IncomingStream<'_, PeerCredListener>) -> Self {
        stream.remote_addr().clone()
    }
}

/// Per-request middleware that unwraps the per-connection
/// `ConnectInfo<PeerCredAddr>` axum installs and inserts a plain
/// `Extension<OperatorIdentity>` into the request's extension map.
///
/// Handlers extract `Extension<OperatorIdentity>` directly; the layer
/// hides the listener's `PeerCredAddr`
/// newtype so handler signatures do not have to reference an
/// implementation detail of the orphan-rule workaround.
async fn operator_identity_layer(mut req: Request, next: Next) -> axum::response::Response {
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<PeerCredAddr>>().cloned() {
        req.extensions_mut().insert(addr.0);
    }
    next.run(req).await
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn app(state: Arc<AppState>) -> Router {
    // Build the events sub-router with its own minimal
    // state (an `Arc` over the same `SessionStore` and the same
    // `EventBus` clone the main state owns).  Merging rather than
    // extending lets the sub-router keep its own typed state without
    // forcing a `FromRef` impl on `AppState`.
    let events_state = Arc::new(sandboxd::events_http::EventsApiState::new(
        Arc::clone(&state.store),
        state.event_bus.clone(),
    ));
    let events_router = sandboxd::events_http::events_router(events_state);

    // Build the policy status sub-router with its own minimal state
    // (shared `SessionStore` + shared `PropagationStates`). Same
    // merging rationale as `events_router` above — the read-only
    // endpoint does not need the full `AppState` surface.
    let policy_state = Arc::new(sandboxd::policy_http::PolicyApiState::new(
        Arc::clone(&state.store),
        Arc::clone(&state.propagation_states),
    ));
    let policy_router = sandboxd::policy_http::policy_router(policy_state);

    // Build the backends-listing sub-router. Holds an `Arc` over the
    // same backend dispatch map the main `AppState` owns; the CLI hits
    // `GET /backends` once per invocation to learn capabilities, so a
    // read-only sub-router keeps the surface narrow and lets
    // `tests/integration_backends_endpoint.rs` drive the route via
    // `oneshot` without booting Lima/gateway/network.
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
        .route(
            "/sessions/{id}/policy",
            post(update_policy).delete(clear_policy),
        )
        .route(
            "/sessions/{id}/workspace-lock",
            post(acquire_workspace_lock).delete(release_workspace_lock),
        )
        .route("/sessions/{id}/health", get(session_health))
        .route("/sessions/{id}/ssh-config", get(get_ssh_config))
        .route("/sessions/{id}/proxy", get(get_proxy))
        .route("/rebuild-image", post(rebuild_image))
        .route("/base-image-status", get(base_image_status))
        .route("/health", get(health_check))
        .route("/version", get(version_handler))
        .route("/diagnostics", get(diagnostics_handler))
        .with_state(state)
        .merge(events_router)
        .merge(policy_router)
        .merge(backends_router)
        // Per-request layer that exposes the per-connection
        // `ConnectInfo<PeerCredAddr>` (set by the
        // `into_make_service_with_connect_info::<PeerCredAddr>()` plumbing)
        // as a plain `Extension<OperatorIdentity>` extension. Handlers
        // that require the operator identity extract it through that
        // extractor; the layer is applied last so it wraps every
        // sub-router merged above.
        .layer(from_fn(operator_identity_layer))
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

/// Daemon-side gate for `CreateSessionRequest.no_gitignore`: only
/// meaningful when the parsed workspace mode is `local:`. Returns
/// `Ok(())` when the combination is valid (no flag, or flag + `local:`)
/// and the operator-facing rejection string otherwise.
///
/// Extracted as a pure function so the gate can be unit-tested without
/// driving the full `create_session` handler (no `AppState`, no HTTP
/// machinery). The wording is:
///
/// > `--no-gitignore is only meaningful for local: workspaces; this session uses <mode>:`
///
/// where `<mode>` is `shared`, `clone`, or the literal `<empty>` when
/// no workspace mode is set. The CLI's
/// `validate_no_gitignore_for_workspace` mirrors this verbatim so a
/// hand-rolled HTTP client (bypassing the CLI gate) surfaces the same
/// diagnostic. Both sides own the literal text rather than a shared
/// constant because `sandbox-core` does not carry a human-readable
/// error catalog today; adding one for a single message would
/// over-index for this scope.
fn validate_no_gitignore_against_workspace(
    no_gitignore: bool,
    workspace_mode: Option<&sandbox_core::WorkspaceMode>,
) -> Result<(), String> {
    if !no_gitignore {
        return Ok(());
    }
    let mode_token = match workspace_mode {
        Some(sandbox_core::WorkspaceMode::Local { .. }) => return Ok(()),
        Some(sandbox_core::WorkspaceMode::Shared { .. }) => "shared",
        Some(sandbox_core::WorkspaceMode::Clone { .. }) => "clone",
        None => "<empty>",
    };
    Err(format!(
        "--no-gitignore is only meaningful for local: workspaces; this session uses {mode_token}:"
    ))
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    Extension(operator): Extension<OperatorIdentity>,
    Json(req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    // Pre-flight: refuse the request when the daemon-version-tagged
    // gateway image is not loaded on the host. Both backends spin up
    // a per-session gateway container; without the image, every
    // downstream path (Lima or container) would fail several hundred
    // lines later inside `GatewayManager::create_gateway` with a
    // less informative `docker run` stderr. The early bail produces
    // the operator-visible hint that points at `sandbox update`. The
    // check is cheap (one `docker image inspect`) and is run per
    // request so a post-startup image load is picked up without
    // bouncing the daemon.
    let gateway_tag =
        sandbox_core::gateway::gateway_image_tag_for_daemon(env!("CARGO_PKG_VERSION"));
    let gateway_tag_for_check = gateway_tag.clone();
    let present_result =
        tokio::task::spawn_blocking(move || gateway_image_present(&gateway_tag_for_check)).await;
    match present_result {
        Ok(Ok(true)) => { /* image present — proceed */ }
        Ok(Ok(false)) => {
            return error_response(SandboxError::Gateway(missing_gateway_image_hint(
                &gateway_tag,
            )))
            .into_response();
        }
        Ok(Err(e)) => {
            return error_response(e).into_response();
        }
        Err(join_err) => {
            return error_response(SandboxError::Internal(format!(
                "gateway image inspect task panicked: {join_err}"
            )))
            .into_response();
        }
    }

    // Determine workspace mode from the request: the `workspace` field
    // takes precedence; fall back to `repo` for backward compatibility.
    let workspace_mode = if let Some(ref ws) = req.workspace {
        match sandbox_core::WorkspaceMode::parse_flag(ws) {
            Ok(mode) => Some(mode),
            Err(e) => {
                return error_response(SandboxError::InvalidArgument(format!(
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

    // `--no-gitignore` is only meaningful for `local:` workspaces. The
    // CLI mirrors this gate client-side for fail-fast operator
    // feedback, but the daemon's check is the authoritative one — a
    // hand-rolled HTTP client that bypasses the CLI surfaces the same
    // diagnostic. Run BEFORE any network / CA / runtime setup so the
    // rejection never burns a session id, network allocation, or
    // gateway container. Plain `error_response(...).into_response()`
    // — no `cleanup_net_ca_and_return!` needed because no state has
    // been allocated yet.
    //
    // Plumbed into a local for the rsync orchestration block, which
    // consumes the bool when it constructs the initial-push argv.
    let no_gitignore_initial_push = req.no_gitignore.unwrap_or(false);
    if let Err(msg) =
        validate_no_gitignore_against_workspace(no_gitignore_initial_push, workspace_mode.as_ref())
    {
        return error_response(SandboxError::InvalidArgument(msg)).into_response();
    }

    // Which backend hosts this session. Default to Lima for back-compat
    // with older CLIs that omit the field. The chosen kind is then
    // validated against the runtime's capability matrix *before* any
    // state is mutated, so a request that asks for `--hardened` on the
    // container backend is rejected with 400 and never spends a session
    // id, network allocation, or CA dir.
    //
    // Resolved up front (before `config` is built) because the
    // resource defaults below are backend-aware.
    let backend_kind = req.backend.unwrap_or(BackendKind::Lima);

    // Resource defaults are backend-aware.
    //
    // - For Lima we keep the historical 2-CPU / 4096-MB defaults that
    //   the original wire shape baked in. These match what
    //   `LimaRuntime::start_vm` consumes and what every long-standing
    //   E2E test expects.
    // - For Container we feed `0` sentinels through, which
    //   `ContainerRuntime::resource_ceilings` interprets as "unset"
    //   and substitutes with the daemon's `compute_default_resource_limits`
    //   host-80% ceilings. Without this
    //   the host-80% path was unreachable through the public CLI
    //   surface (the previous `unwrap_or(2)/(4096)` always fired and
    //   produced Lima-leaning numbers regardless of backend).
    //
    // The `0` sentinel is the lowest-touch shape — it threads through
    // `SessionConfig` (Lima-shaped) into `BackendSpecific::Container`
    // unchanged, and `resource_ceilings` already encoded the
    // "0 means unset" contract. Persisting `0` is safe:
    // `SessionConfig` carries the user-requested ceiling, and a
    // container session that took the host-80% default has `0` in
    // both columns by construction.
    //
    // `req.cpus` is `Option<f32>` so the 1-decimal grammar
    // (`0.8`, `1.5`, …) reaches the
    // runtime without truncation. Lima sessions still see whole-number
    // cores (QEMU's `-smp` grammar pins integers), so we floor any
    // fractional value on the Lima path. The container path normalises
    // to one decimal place via `round_cpus_one_decimal` so `0.81`
    // lands on the grid as `0.8` regardless of whether an operator
    // typo'd extra precision.
    let memory_mb = match backend_kind {
        BackendKind::Lima => req.memory_mb.unwrap_or(4096),
        BackendKind::Container => req.memory_mb.unwrap_or(0),
    };
    let cpus_decimal_request = req.cpus;
    // Reject fractional `--cpus` for Lima sessions at the daemon
    // boundary. QEMU's `-smp` flag (and the Lima YAML it generates)
    // only accepts whole-number cores; an `as u32` truncation would
    // silently downsize a `1.5` request to `1`, which is invisible to
    // non-CLI HTTP clients. The CLI never sends a fractional value on
    // the Lima path (clap parses `--cpus` as `f32` but the resolver
    // enforces integer-shape semantics upstream), so this gate fires
    // only on hand-rolled HTTP clients that bypass the CLI.
    // `SessionDto.warnings` is reserved for post-success operator
    // notices (e.g. lite-image first-use), not for masking malformed
    // sizing requests — so we hard-reject with HTTP 400 to mirror the
    // the documented contract pattern already used by `--hardened`
    // on the container backend.
    if backend_kind == BackendKind::Lima && cpus_decimal_request.is_some_and(|c| c.fract() != 0.0) {
        return error_response(SandboxError::InvalidArgument(
            "Lima sessions require integer --cpus values (QEMU's -smp flag pins whole cores); \
             use the container backend for fractional CPU sizing"
                .into(),
        ))
        .into_response();
    }
    let (cpus_persisted, cpus_decimal) = match backend_kind {
        BackendKind::Lima => {
            // QEMU pins integer cores; the fractional-rejection gate
            // above guarantees the value is integer-shaped here, so
            // the `as u32` cast is precision-preserving.
            let cpus = cpus_decimal_request.map(|c| c as u32).unwrap_or(2);
            (cpus, None)
        }
        BackendKind::Container => match cpus_decimal_request {
            // `Some(0.0)` is semantically identical to `None` — both
            // mean "no caller-specified value, fall back to the
            // host-80% default" (the mapper that consumes
            // `cpus_decimal` substitutes the default whenever the
            // stored f64 is 0.0). Normalise both inputs to `(0, None)`
            // so the persisted state is bit-equal across the two
            // shapes; otherwise an explicit `--cpus 0.0` would
            // round-trip as `cpus_decimal: Some(0.0)` while an
            // omitted flag round-trips as `cpus_decimal: None`,
            // diverging on the wire for no semantic reason.
            None | Some(0.0) => (0, None),
            Some(precise) => {
                let normalised = round_cpus_one_decimal(precise);
                // `cpus` (u32) holds the floored value as a fallback
                // for older daemons rolling back; the precise value
                // lives in `cpus_decimal`.
                (normalised.floor() as u32, Some(normalised))
            }
        },
    };

    // `rootless_docker` is stamped post-probe (after the
    // rootless-Docker gate runs below) so the persisted config
    // carries the probe outcome the same daemon used to make the
    // refuse/accept decision. Initialised to `None` here and patched
    // before the session row is written to the store.
    let mut config = SessionConfig {
        cpus: cpus_persisted,
        memory_mb,
        disk_gb: req.disk_gb.unwrap_or(20),
        workspace_mode,
        hardened: req.hardened.unwrap_or(true),
        // Record the creation inputs so `sandbox inspect`/`describe` can
        // surface them later.  These are persisted in `config_json` and
        // forward-compatible via `#[serde(default)]`; records written by
        // older daemons keep `None` on these three fields.
        repo: req.repo.clone(),
        boot_cmd: req.boot_cmd.clone(),
        template: req.template.clone(),
        cpus_decimal,
        rootless_docker: None,
    };

    // Hardened flag interaction with the container backend:
    // `BackendSpecific::Container` does not carry `hardened`, so the
    // SessionSpec-level `validate()` path silently drops a `true`
    // value. Reject up front when a container request explicitly sets
    // `hardened: true` so the caller gets an operator-facing 400 with
    // the same `UnsupportedFeature::Hardening` message Lima surfaces
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

    // Daemon-side authoritative validation: the documented contract
    // requires the daemon to repeat the capability check the CLI did.
    // The runtime is the single source of truth for its capability
    // matrix. Threading `req.no_cache` through the design projection
    // ensures a non-CLI HTTP client posting
    // `{"backend":"container","no_cache":true}` is refused by
    // `SessionSpec::validate` rather than silently honoured.
    let spec = session_spec_from_config(&config, backend_kind, req.no_cache);
    let runtime_for_validation = runtime_for(&state, backend_kind);
    if let Err(unsupported) = spec.validate(runtime_for_validation.capabilities()) {
        // `UnsupportedFeature: Display` produces the operator-facing
        // sentence (e.g. "hardening flag not supported by container
        // backend"); routing through `InvalidArgument` maps this to
        // an HTTP 400 with the message intact (see `error_response`).
        return error_response(SandboxError::InvalidArgument(unsupported.to_string()))
            .into_response();
    }

    // Rootless-Docker enforcement.
    // Run BEFORE any container artifacts are touched —
    // including the lite-image build below and every subsequent
    // session-create step (CA, network, runtime). On rootless hosts
    // without `--force-rootless-docker` the daemon refuses with
    // `RootlessDockerRefused` (mapped to HTTP 400 by `error_response`)
    // so the call never reaches `docker pull` / `docker create` and
    // no orphan resources get allocated.
    //
    // The probe outcome (detected, forced) is stamped onto `config`
    // below so it persists with the session for `sandbox inspect`
    // visibility (deliverable 3). On probe failure we propagate the
    // error verbatim — a host whose `docker info` doesn't even
    // respond is not in a state to safely create container sessions,
    // and the operator deserves a clear "Docker daemon unreachable"
    // diagnostic over a silent fallback.
    //
    // Lima sessions never call the probe — Docker mode is irrelevant
    // to QEMU/Lima session creation by construction.
    if backend_kind == BackendKind::Container {
        let detected =
            match sandbox_core::backend::container_rootless_probe::is_rootless_docker().await {
                Ok(v) => v,
                Err(e) => return error_response(e).into_response(),
            };
        if detected && !req.force_rootless_docker {
            return error_response(SandboxError::RootlessDockerRefused).into_response();
        }
        config.rootless_docker = Some(sandbox_core::SessionRootlessDocker {
            detected,
            forced: detected && req.force_rootless_docker,
        });
    }

    // Container backend: ensure the lite image exists *before* we
    // burn a session row + network allocation. The first build of a
    // given daemon version surfaces a verbatim warning string back
    // to the caller; steady-
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
    // design note: the session is stamped with the operator's username at
    // creation time so every subsequent per-caller filter in
    // `SessionStore` matches. Guest-version fields are stamped from
    // the daemon's compiled-in constants so the start-time compat
    // predicate (per-caller isolation) immediately accepts
    // freshly-created sessions on the fast path.
    let session = match state.store.create_session_with_backend(
        config.clone(),
        req.name.clone(),
        backend_kind,
        &operator.name,
        sandbox_core::guest::DAEMON_GUEST_PROTO_VERSION,
        sandbox_core::guest::SANDBOX_GUEST_VERSION,
        // Stamp the operator's kernel-supplied `SO_PEERCRED` (uid, gid)
        // onto the new row. The container backend reads these back to
        // build the `--user <uid>:<gid>` argv on `docker create`; the
        // Lima backend reads them back to drive the cloud-init usermod
        // step. Both halves travel together because the
        // supervisor-fork `setresuid`/`setresgid` primitive consumes
        // them as a pair. Pre-V008 rows have `None` for both and
        // continue to route through the legacy spawn-as-daemon path.
        Some(operator.uid),
        Some(operator.gid),
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
                let _ = state
                    .store
                    .update_state(&session_id, &operator.name, SessionState::Error);
                return error_response(e).into_response();
            }
            Err(e) => {
                let _ = state
                    .store
                    .update_state(&session_id, &operator.name, SessionState::Error);
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
                let _ = state
                    .store
                    .update_state(&session_id, &operator.name, SessionState::Error);
                return error_response(e).into_response();
            }
            Err(e) => {
                let _ = state
                    .store
                    .update_state(&session_id, &operator.name, SessionState::Error);
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
    //
    // `local:` mode (`WorkspaceMode::Local`) deliberately does NOT add a
    // 9p mount to the Lima template — the host workspace is mirrored
    // into the guest by a daemon-side rsync after the VM reaches
    // `Running` (see `workspace_rsync::run_initial_push` below). The
    // cached golden image therefore stays valid for `local:` sessions,
    // and the fast-path clone is still eligible. The predicate's name
    // documents that intent: only modes that *require* a per-session
    // template render disqualify the cache hit.
    let workspace_requires_template_render = matches!(
        &config.workspace_mode,
        Some(sandbox_core::WorkspaceMode::Shared { .. })
    );
    let use_cache = !req.no_cache.unwrap_or(false)
        && req.template.is_none()
        && !workspace_requires_template_render;

    // Helper closure: cleanup VM + network + CA on failure, set state to Error.
    // This macro avoids repeating the cleanup pattern in every error branch.
    //
    // VM cleanup goes through the generic trait dispatch
    // (`runtime.delete(&handle).await`); the synchronous network + CA
    // cleanup stays inside a single `spawn_blocking` so we do not pay
    // an extra task spawn per cleanup. The macro is invoked from
    // inside `create_session`'s async body, so the `.await` on
    // `delete` is safe.
    //
    // The request's `backend_kind` is passed in so the cleanup
    // dispatches to the runtime that actually owns the
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
            let _ = $state
                .store
                .update_state(&$session_id, &operator.name, SessionState::Error);
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
            let _ = $state
                .store
                .update_state(&$session_id, &operator.name, SessionState::Error);
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
        // into the lite image). The runtime drives
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
        // `workspace_bind` is populated when the request asked
        // for `--workspace shared:<host>[:<guest>]` — the runtime
        // turns it into a `docker create --mount
        // type=bind,src=<host>,dst=<guest>` flag. For other workspace modes
        // (`Clone`, `Empty`) the field stays `None` and the lite
        // image runs with a read-only rootfs.
        //
        // `route_helper_path = Some(...)` lets the runtime invoke
        // the setcap helper at start time to install the default
        // route via the gateway IP inside the container's netns.
        // [`resolve_route_helper_path`] resolves
        // the absolute path of the helper at the call site via a
        // two-step lookup: (0) the `$SANDBOX_ROUTE_HELPER_PATH` env
        // var (fail-closed if set but missing/un-cap'd), (1) the
        // canonical install path
        // `/usr/local/libexec/sandboxd/sandbox-route-helper` (FHS § 4.7).
        // Each candidate must carry `CAP_SYS_ADMIN+ep`.
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
            // Pull the (host, guest) pair out of the parsed workspace
            // mode (set on `config` above when `req.workspace =
            // Some("shared:<host>[:<guest>][:<model>]")`). Other
            // variants don't bind a host path into the container.
            //
            // `security_model` is meaningless for a Docker bind-mount
            // (it is a 9p concept on the Lima side); the daemon-side
            // mapper rejects any `Some(_)` value here so the runtime
            // stays unaware of the field (container backend has no
            // 9p security-model concept).
            let workspace_bind = match &config.workspace_mode {
                Some(sandbox_core::WorkspaceMode::Shared {
                    host_path,
                    guest_path,
                    security_model,
                }) => {
                    if security_model.is_some() {
                        cleanup_net_ca_and_return!(
                            state,
                            session_id,
                            error_response(sandbox_core::SandboxError::InvalidArgument(
                                "security_model is not supported by the container \
                                 backend (9p-only concept); omit the :<model> token \
                                 from --workspace shared:…"
                                    .to_string(),
                            ))
                            .into_response()
                        );
                    }
                    Some(sandbox_core::backend::WorkspaceBind {
                        host_path: PathBuf::from(host_path),
                        guest_path: PathBuf::from(guest_path),
                    })
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
            // Per-session SSH credential staging.
            //
            // The cross-user CLI access spec puts every CLI operation
            // that reaches *inside* a session through the daemon, with
            // SSH-shaped commands tunnelling through a per-session
            // sshd via `ProxyCommand`. The keypair is generated once
            // here at session-create time and persisted in
            // `sessions.ssh_keypair_json` (V007). The public half is
            // staged to disk under `{base_dir}/sessions/<id>/ssh/`
            // along with synthetic `/etc/passwd` and `/etc/group`
            // overlays, and bind-mounted into the container at
            // `docker create` time.
            //
            // **Why the synthetic /etc/passwd**: when `daemon_uid !=
            // 1000` (the cross-user case the daemon-as-system-user
            // design exists to fix), OpenSSH's `getpwuid(geteuid())`
            // lookup fails inside the container because the in-image
            // `sandbox` user is uid 1000 but the container runs under
            // the daemon's uid. todo #221's decision (b) overlays a
            // single-entry passwd file that maps the runtime uid to
            // the `sandbox` account, reusing the same tmpfs bind-mount
            // surface as the authorized_keys injection. The
            // alternatives — forcing `--user 1000:1000` and
            // re-architecting workspace bind-mount ownership (option
            // a), or rebuilding the lite image per uid (option c) —
            // were rejected for higher blast radius.
            let ssh_host_dir = state
                .base_dir
                .join("sessions")
                .join(session_id.as_str())
                .join("ssh");
            let ssh_keypair_for_staging =
                match sandbox_core::SshKeypair::generate(session_id.as_str()) {
                    Ok(kp) => kp,
                    Err(e) => {
                        cleanup_net_ca_and_return!(
                            state,
                            session_id,
                            error_response(e).into_response()
                        );
                    }
                };
            {
                // Stage the three files (authorized_keys, passwd,
                // group) on a blocking task — `stage_ssh_credentials`
                // performs sync I/O. `daemon_uid`/`daemon_gid` come
                // from the container runtime's configured identity so
                // the synthetic passwd entry matches whatever uid the
                // container will actually run under at
                // `--user <uid>:<gid>` time.
                let ssh_host_dir_owned = ssh_host_dir.clone();
                let kp_owned = ssh_keypair_for_staging.clone();
                let daemon_uid = state.container_runtime.user_uid();
                let daemon_gid = state.container_runtime.user_gid();
                let stage_result = tokio::task::spawn_blocking(move || {
                    sandbox_core::backend::stage_ssh_credentials(
                        &ssh_host_dir_owned,
                        &kp_owned,
                        daemon_uid,
                        daemon_gid,
                    )
                })
                .await;
                match stage_result {
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
                                "spawn_blocking join failed staging ssh credentials: {e}"
                            )))
                            .into_response()
                        );
                    }
                }
            }
            // Persist the keypair onto the session row so the
            // `GET /sessions/{id}/ssh-config` handler can serve it
            // later. Per-caller isolation: `set_ssh_keypair` filters
            // on the owner_username column, same as every other
            // per-session mutation in the store.
            if let Err(e) =
                state
                    .store
                    .set_ssh_keypair(&session_id, &operator.name, &ssh_keypair_for_staging)
            {
                cleanup_net_ca_and_return!(state, session_id, error_response(e).into_response());
            }

            let container_network = sandbox_core::backend::ContainerNetwork {
                docker_network: network_info.docker_network_name.clone(),
                container_ip,
                gateway_ip,
                workspace_bind,
                route_helper_path: Some(route_helper_path),
                // Per-session CA: bind-mounted read-only into the
                // container at /etc/ssl/certs/sandbox-ca.pem and
                // surfaced via CURL_CA_BUNDLE / SSL_CERT_FILE etc. so
                // HTTPS traffic intercepted by Envoy + mitmproxy
                // (L3-HTTP policy levels) verifies cleanly. Mirrors
                // the Lima `inject_ca_into_vm` path; differs in
                // mechanism because the lite container's rootfs is
                // read-only.
                ca_host_path: Some(ca_dir.join("cert.pem")),
                // Per-session SSH staging: the runtime emits three
                // `--mount type=bind,readonly` flags pointing at the
                // three files we just staged above
                // (authorized_keys + synthetic passwd / group).
                ssh_host_dir: Some(ssh_host_dir),
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
            //
            // `for_user` is the operator name resolved from the
            // connecting socket's `SO_PEERCRED` — the container runtime
            // emits it as the helper's `--for-user` argv flag for the
            // pair-membership check.
            let args = RuntimeStartArgs {
                lima_bridge: None,
                lima_mac: None,
                lima_config: None,
                for_user: Some(operator.name.clone()),
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
        if let Err(e) = state
            .store
            .set_network_info(&session_id, &operator.name, &network_info)
        {
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
        if let Err(e) = state
            .store
            .update_state(&session_id, &operator.name, SessionState::Running)
        {
            cleanup_lite_gateway_and_return!(error_response(e).into_response());
        }

        // Guest-readiness gate. Mirrors the Lima branch's
        // `state.guest.ping` at line ~1911: gate every guest-touching
        // dispatch below (apply_policy is gateway-only, but
        // `prewarm_guest_dns`/`state.guest.exec` for `--repo` and
        // `--boot-cmd` all go through the agent's TCP listener at
        // 127.0.0.1:5123). Without this gate, a fast `connect-refused`
        // before the agent has bound its socket would surface as a
        // transport error and route through `fail_explicit_repo_clone` /
        // `fail_explicit_boot_cmd`, marking the session `Error`
        // flakily. The lite image's entrypoint is `sandbox-guest`, so
        // the listener is up shortly after `docker start` returns; the
        // 30s `GUEST_REQUEST_TIMEOUT` inside `ping` covers the boot
        // tail-latency the same way it does for Lima. Failures take
        // the gateway+network teardown path because the gateway has
        // already been brought up above.
        match state.guest.ping(&session_id).await {
            Ok(true) => {
                info!(%session_id, "guest agent responded to ping (lite)");
            }
            Ok(false) => {
                let err = SandboxError::Internal(
                    "guest agent returned unexpected response to ping".into(),
                );
                error!(%session_id, "guest agent ping: unexpected response (lite)");
                cleanup_lite_gateway_and_return!(error_response(err).into_response());
            }
            Err(e) => {
                error!(%session_id, error = %e, "guest agent ping failed (lite)");
                cleanup_lite_gateway_and_return!(error_response(e).into_response());
            }
        }

        // Apply the explicit `--policy <file>` (or `--preset <invocation>`,
        // which the CLI compiles into `req.policy` server-side) now that
        // the session is Running and the gateway is live. Mirrors the
        // Lima branch's apply_policy block at lines ~1651-1679: an
        // explicit policy that fails to compile/distribute is fatal —
        // silently returning a Running session with no policy in place
        // lies to the operator. The implicit "no policy" path never
        // reaches this branch (the CoreDNS fail-closed default was
        // already written by `create_gateway` above via
        // `initial_dns_policy`).
        //
        // `req.policy` is consumed here (moved out of `req`); the
        // `req.repo` clone block immediately below is the backend
        // symmetry for `--repo` (the lite image's entrypoint is the
        // `sandbox-guest` agent, so the `state.guest.exec` dispatch the
        // Lima path uses works unchanged once the agent's TCP listener
        // is up). `--boot-cmd` symmetry follows the same dispatch right
        // after the clone block.
        if let Some(policy) = req.policy {
            let initial_presets = req.source_presets.clone();
            match apply_policy(
                &session_id,
                &operator.name,
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

        // `local:` workspace — host→guest rsync push after policy apply,
        // before repo clone. Mirrors the Lima branch's `local:` block at
        // the bottom of this handler. The container branch uses
        // `cleanup_lite_gateway_and_return!` (not `cleanup_and_return!`)
        // for failure-path teardown — same as the policy-apply and
        // guest-ping rejections sandboxed in this branch.
        if let Some(sandbox_core::WorkspaceMode::Local {
            host_path,
            guest_path,
        }) = &config.workspace_mode
        {
            let session_name = format!("sandbox-{session_id}");
            match sandbox_core::workspace_rsync::run_initial_push(
                backend_kind,
                &session_name,
                host_path,
                guest_path,
                no_gitignore_initial_push,
            )
            .await
            {
                Ok(()) => {
                    info!(%session_id, host_path = %host_path, guest_path = %guest_path,
                        "local-workspace initial push complete (lite)");
                }
                Err(e) => {
                    error!(%session_id, error = %e, "local-workspace rsync failed (lite)");
                    cleanup_lite_gateway_and_return!(error_response(e).into_response());
                }
            }
        }

        // `--repo` symmetry on the container backend.
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
                            &operator.name,
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
                        &operator.name,
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
                        &operator.name,
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
                        &operator.name,
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

        // `--boot-cmd` symmetry on the container backend.
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
                            &operator.name,
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
                        &operator.name,
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
                        &operator.name,
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
                        &operator.name,
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

        let created = match state.store.get_session(&session_id, &operator.name) {
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
        // Surface the rootless-Docker probe outcome on the container
        // create response so operators can confirm whether the daemon
        // detected rootless and whether the `--force-rootless-docker`
        // opt-in was actually applied, without an extra
        // `GET /sessions/{id}` round-trip.
        let rootless_dto = created
            .config
            .rootless_docker
            .as_ref()
            .map(sandbox_core::SessionRootlessDockerDto::from);
        let dto = SessionDto::from(&created)
            .with_warnings(warnings)
            .with_rootless(rootless_dto);
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
            // `for_user` is threaded through on the Lima path for
            // forward-compatibility: Lima does not invoke the route
            // helper today, but populating the field keeps every
            // `runtime.start` call site uniform so a future contributor
            // who adds a third backend or moves the start site across
            // branches does not regress the pair-membership invariant.
            let args = RuntimeStartArgs {
                lima_bridge: Some(network_info.bridge_name.clone()),
                lima_mac: Some(vm_mac.clone()),
                lima_config: Some(config.clone()),
                for_user: Some(operator.name.clone()),
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
        // Dispatch through the trait. The custom-template branch lives
        // inside `LimaRuntime::create` (it inspects
        // `SessionSpec::template`) — handlers no longer pick between
        // `create_vm` and `create_vm_with_custom_template` directly.
        // The wire shape (`CreateSessionRequest.template`) is
        // unchanged; we project the request into a `SessionSpec`
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
            // `for_user` is threaded through on the Lima path for
            // forward-compatibility — see the matching note on the
            // fast-path branch above.
            let args = RuntimeStartArgs {
                lima_bridge: Some(network_info.bridge_name.clone()),
                lima_mac: Some(vm_mac.clone()),
                lima_config: Some(config.clone()),
                for_user: Some(operator.name.clone()),
            };
            match runtime.start(&handle, &args).await {
                Ok(()) => {}
                Err(e) => {
                    cleanup_and_return!(state, session_id, error_response(e).into_response());
                }
            }
        }

        // 2c. Install the guest agent into the VM. Resolve the host-
        // side source via the shared `guest_agent_path` resolver so
        // production installs read from `/usr/local/libexec/sandboxd/`
        // and dev builds fall back to the cargo target — the same
        // contract the container-backend startup-staging path uses.
        let guest_binary_path = match sandbox_core::guest_agent_path() {
            Ok(p) => p,
            Err(e) => {
                cleanup_and_return!(state, session_id, error_response(e).into_response());
            }
        };

        {
            // `install_guest_agent` is Lima-specific (it shells out to
            // `limactl shell` to inject the binary) and stays behind
            // the `LimaRuntime::manager()` escape hatch until the
            // trait surface grows to cover agent bootstrapping in a
            // backend-agnostic way.
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
    if let Err(e) = state
        .store
        .update_state(&session_id, &operator.name, SessionState::Running)
    {
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
        &operator.name,
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
            let _ = state
                .store
                .update_state(&session_id, &operator.name, SessionState::Error);
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
    // failure on an *explicit* policy is fatal for the create call:
    // the alternative is silently returning a Running session with
    // `Policy: none`, which violates the caller's stated intent. The
    // implicit "no policy" default path never reaches this branch at
    // all — for that path we've already written the fail-closed empty
    // CoreDNS config during `setup_session_networking` above and there
    // is nothing to do here.
    if let Some(policy) = req.policy {
        let initial_presets = req.source_presets.clone();
        match apply_policy(
            &session_id,
            &operator.name,
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
                    &operator.name,
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

    // `local:` workspace: mirror the host directory into the guest now
    // that the VM/container is Running and (if requested) the initial
    // policy has been applied. Runs before the repo clone so a session
    // that combines `--workspace local:<host>` with `--repo <url>`
    // first seeds the host snapshot, then layers the repo clone on top
    // (matching the precedence operators expect from the CLI argument
    // order: workspace contents are the substrate, repo is an overlay).
    //
    //
    // `SandboxError::Internal` with rsync's stderr embedded; the
    // `cleanup_and_return!` macro tears the VM/container, network, and
    // CA state down so the session row is removed from the store and
    // the operator does not see a half-seeded `Running` session. The
    // macro is in scope from its definition above (line ~1693).
    if let Some(sandbox_core::WorkspaceMode::Local {
        host_path,
        guest_path,
    }) = &config.workspace_mode
    {
        // Session-name convention: matches `plan_sync_command`'s
        // `sandbox-<id>` form used by `sandbox sync`, so the shell-
        // transport target (`limactl shell sandbox-<id>` /
        // `docker exec sandbox-<id>`) resolves the same way for both
        // create-time push and operator-driven push/pull.
        let session_name = format!("sandbox-{session_id}");
        match sandbox_core::workspace_rsync::run_initial_push(
            backend_kind,
            &session_name,
            host_path,
            guest_path,
            no_gitignore_initial_push,
        )
        .await
        {
            Ok(()) => {
                info!(%session_id, host_path = %host_path, guest_path = %guest_path,
                    "local-workspace initial push complete");
            }
            Err(e) => {
                error!(%session_id, error = %e, "local-workspace rsync failed");
                cleanup_and_return!(state, session_id, error_response(e).into_response());
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
                        &operator.name,
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
                    &operator.name,
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
                    &operator.name,
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
                    &operator.name,
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
    // Any failure here violates the caller's stated intent the same
    // way `--policy` and `--repo` failures would: returning a `Running`
    // session with the boot command's side effects unrealised silently
    // lies to the operator. Mirror the fatal-create pattern: tag the
    // session `Error`, tear down partial gateway/network state, and
    // surface the failure in the HTTP response so the CLI user can
    // see *why* the boot command did not succeed (exit code, stderr
    // snippet, transport error, etc.).
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
                        &operator.name,
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
                    &operator.name,
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
                    &operator.name,
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
                    &operator.name,
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
    let created = match state.store.get_session(&session_id, &operator.name) {
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

    // Rootless-Docker state is container-only; for Lima sessions
    // `created.config.rootless_docker` stays `None` and the wire field
    // is omitted entirely (`skip_serializing_if`). Mirroring the
    // container response for shape symmetry — operators who pipe
    // `POST /sessions` through `jq` see the same key set regardless
    // of which branch served them.
    let rootless_dto = created
        .config
        .rootless_docker
        .as_ref()
        .map(sandbox_core::SessionRootlessDockerDto::from);
    let dto = SessionDto::from(&created)
        .with_status(agent_status, gateway_status)
        .with_policy(policy_opt.as_ref())
        .with_warnings(warnings)
        .with_rootless(rootless_dto);

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

async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Extension(operator): Extension<OperatorIdentity>,
) -> impl IntoResponse {
    let sessions = match state.store.list_sessions(&operator.name) {
        Ok(s) => s,
        Err(e) => return error_response(e).into_response(),
    };

    // Enrich with VM status (best-effort).
    //
    // `list_vms()` is Lima-specific — it returns a `Vec<VmInfo>` shaped
    // by `limactl list --json` and the reconciliation block below
    // matches on `VmStatus`. Multi-backend listing (fan-out across
    // every registered runtime) is a future extension once additional
    // backends ship a comparable inventory surface.
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
                            .update_state_reconcile(&s.id, SessionState::Stopped);
                    }
                    // DB says Stopped but Lima says Running => update to Running
                    (SessionState::Stopped, VmStatus::Running) => {
                        s.state = SessionState::Running;
                        let _ = state
                            .store
                            .update_state_reconcile(&s.id, SessionState::Running);
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
    Extension(operator): Extension<OperatorIdentity>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id, &operator.name) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    // Enrich with VM status (best-effort).
    //
    // Dispatch through the trait. `RuntimeStatus` mirrors `VmStatus`
    // for the Running/Stopped cases the reconciliation cares about;
    // the `Creating`/`Error` variants (set by the container backend)
    // are treated as "no-op" here — the daemon's authoritative state
    // is in the store and we don't overwrite it on a non-matching
    // runtime status.
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
                        .update_state_reconcile(&session.id, SessionState::Stopped);
                }
                (SessionState::Stopped, sandbox_core::backend::RuntimeStatus::Running) => {
                    session.state = SessionState::Running;
                    let _ = state
                        .store
                        .update_state_reconcile(&session.id, SessionState::Running);
                }
                _ => {}
            }
        }
    }

    // Probe guest agent and gateway for running sessions.
    let agent_status = probe_agent_status(&state, &session).await;
    let gateway_status = probe_gateway_status(&state, &session).await;

    // Look up the currently applied policy in the in-memory map. The
    // map is the source of truth at runtime; on-disk persistence
    // (which `SessionStore` handles) is what survives daemon restarts.
    let policy_opt = {
        let policies = state.session_policies.lock().await;
        policies.get(&session.id).cloned()
    };

    // Backend-neutral network/mount surfaces. Both pull from
    // already-canonical sources: `network` from the persisted
    // `NetworkInfo`, `mounts` from the session's own
    // `config.workspace_mode` plus a small per-backend constant set
    // (workspace path, CA bind path, home-volume name). Surfacing
    // them here lets `sandbox inspect` consumers and the e2e suite
    // assert on session-level networking/mount layout without
    // reaching into backend-specific call sites.
    let network = session_network_info_for(&state, &session.id);
    let mounts = Some(session_mount_info_for(&session));

    // Project the persisted rootless-Docker probe outcome onto the
    // wire — `None` for Lima sessions and for older container
    // records that pre-date the probe, `Some({detected, forced})` for
    // any container session whose probe outcome was recorded.
    let rootless_dto = session
        .config
        .rootless_docker
        .as_ref()
        .map(sandbox_core::SessionRootlessDockerDto::from);
    let dto = SessionDto::from(&session)
        .with_status(agent_status, gateway_status)
        .with_policy(policy_opt.as_ref())
        .with_network(network)
        .with_mounts(mounts)
        .with_rootless(rootless_dto);
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
    // Daemon-internal read after handler-side ownership has been
    // verified upstream; the unfiltered helper avoids re-threading the
    // operator name through every inspection-only call site.
    match state.store.get_network_info_unfiltered(session_id) {
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

/// Build a backend-neutral [`SessionMountInfo`] for a session.
///
/// Container sessions populate every field. Lima sessions populate
/// `workspace_path` always, `workspace_host_path` only for
/// `WorkspaceMode::Shared`, and leave `ca_bundle_path` /
/// `home_volume` `None` because Lima's CA injection and home
/// directory are not bind-/volume-backed (the guest agent installs
/// the CA into the system trust store; home is a regular VM
/// directory).
///
/// `workspace_path` is derived from the in-memory `WorkspaceMode`:
///
/// - `Shared` → the operator-resolved `guest_path` (equals
///   `host_path` when no explicit `:<guest>` token was supplied at
///   create time).
/// - `Clone` → the historical `/home/agent/workspace` clone target.
/// - No workspace mode → the historical default for the empty case.
///
/// A trailing `/` is appended so the rendered wire field keeps its
/// historical shape (e.g. `/home/agent/workspace/`); operator scripts
/// that grep on the trailing slash stay byte-compatible.
fn session_mount_info_for(session: &Session) -> SessionMountInfo {
    // Default workspace target retained for the `Clone` and empty
    // cases — `Shared` overrides this with the operator's `guest_path`.
    const CLONE_WORKSPACE_PATH: &str = "/home/agent/workspace";

    let (workspace_path_raw, workspace_host_path) = match &session.config.workspace_mode {
        Some(sandbox_core::WorkspaceMode::Shared {
            host_path,
            guest_path,
            ..
        }) => (guest_path.clone(), Some(host_path.clone())),
        Some(sandbox_core::WorkspaceMode::Clone { .. }) => (CLONE_WORKSPACE_PATH.to_string(), None),
        // `Local` is a host-snapshot rsync: the wire field surfaces the
        // operator's resolved `guest_path` (where the daemon-side rsync
        // landed the snapshot inside the guest). `workspace_host_path`
        // stays `None` — there is no bind-mount, the host path is only
        // a one-shot source.
        Some(sandbox_core::WorkspaceMode::Local { guest_path, .. }) => (guest_path.clone(), None),
        None => (CLONE_WORKSPACE_PATH.to_string(), None),
    };
    // Re-add the trailing `/` that the historical hardcoded constant
    // carried, so the wire form stays byte-identical for scripts
    // (e.g. `workspace_path: "/home/agent/workspace/"`). The parser
    // strips trailing `/` from `guest_path` in normalization, so we
    // reattach exactly one here.
    let workspace_path = if workspace_path_raw.ends_with('/') {
        workspace_path_raw
    } else {
        format!("{workspace_path_raw}/")
    };
    let (ca_bundle_path, home_volume) = match session.backend {
        sandbox_core::backend::BackendKind::Container => (
            Some(SANDBOX_CA_CONTAINER_PATH.to_string()),
            // Container backend names the per-session named volume
            // `sandbox-home-{session_id}` (LM6.4 in spec / orphan
            // reaper's `parse_home_volume_session_id`). The helper
            // is re-exported from the backend module so the inspect
            // surface stays byte-identical to the Docker resource
            // that `docker volume ls` reports.
            Some(home_volume_name(&session.id)),
        ),
        sandbox_core::backend::BackendKind::Lima => (None, None),
    };
    SessionMountInfo {
        workspace_path,
        workspace_host_path,
        ca_bundle_path,
        home_volume,
    }
}

async fn start_session(
    State(state): State<Arc<AppState>>,
    Extension(operator): Extension<OperatorIdentity>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id, &operator.name) {
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

    // Guest-version compat gate (per-caller isolation).
    // The persisted `guest_protocol_version` decides which arm we
    // enter:
    //   - compatible: existing fast path, no refresh.
    //   - refreshable: `runtime.refresh_guest_binary` then the fast
    //     path; on success, atomically stamp the new versions into the
    //     row atomically.
    //   - otherwise: 409 with the structured `GuestProtocolIncompatible`
    //     error.
    let needs_refresh =
        if sandbox_core::guest::is_protocol_compatible(session.guest_protocol_version) {
            false
        } else if sandbox_core::guest::can_refresh_in_place(session.guest_protocol_version) {
            info!(
                session_id = %session.id,
                session_proto = session.guest_protocol_version,
                daemon_proto = sandbox_core::guest::DAEMON_GUEST_PROTO_VERSION,
                "guest protocol mismatch — refreshing guest binary in place before start"
            );
            let runtime = runtime_for(&state, session.backend);
            let handle = RuntimeHandle::from_session_id(&session.id);
            match runtime.refresh_guest_binary(&handle).await {
                Ok(()) => true,
                Err(e) => {
                    error!(
                        session_id = %session.id,
                        error = %e,
                        "guest-refresh failed for session"
                    );
                    return error_response(e).into_response();
                }
            }
        } else {
            return error_response(SandboxError::GuestProtocolIncompatible {
                session_id: session.id.to_string(),
                session_proto: session.guest_protocol_version,
                daemon_proto: sandbox_core::guest::DAEMON_GUEST_PROTO_VERSION,
                reason: format!(
                    "session_proto={} is not refreshable by this daemon",
                    session.guest_protocol_version
                ),
            })
            .into_response();
        };

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
    // Dispatch through the trait. The persisted `SessionConfig` and
    // the per-session bridge / MAC ride down via `RuntimeStartArgs`;
    // the runtime's `start` does its own `spawn_blocking` internally
    // so we just `.await` here. Dispatch is keyed off the persisted
    // `session.backend`, so a container session with `backend =
    // "container"` lands on `ContainerRuntime::start` and Lima
    // sessions land on `LimaRuntime::start` from the same handler.
    {
        let runtime = runtime_for(&state, session.backend);
        let handle = RuntimeHandle::from_session_id(&session.id);
        // `for_user` carries the operator name resolved from
        // `SO_PEERCRED` on the connecting socket. Container backends
        // emit it as the route helper's `--for-user` argv; Lima ignores
        // it but accepts the field for forward-compatibility.
        let args = RuntimeStartArgs {
            lima_bridge: bridge_name.clone(),
            lima_mac: vm_mac.clone(),
            lima_config: Some(session.config.clone()),
            for_user: Some(operator.name.clone()),
        };
        match runtime.start(&handle, &args).await {
            Ok(()) => {}
            Err(e) => {
                let _ = state
                    .store
                    .update_state(&session.id, &operator.name, SessionState::Error);
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
            let _ = state
                .store
                .update_state(&session.id, &operator.name, SessionState::Error);
            return error_response(err).into_response();
        }
        Err(e) => {
            error!(session_id = %session.id, error = %e, "guest agent ping failed after start");
            let _ = state
                .store
                .update_state(&session.id, &operator.name, SessionState::Error);
            return error_response(e).into_response();
        }
    }

    // Update state to Running.
    if let Err(e) = state
        .store
        .update_state(&session.id, &operator.name, SessionState::Running)
    {
        return error_response(e).into_response();
    }

    // Atomic guest-version stamp: only after BOTH refresh and start
    // succeed do we update the persisted version columns.
    // A failure here is logged but does not
    // fail the start — the runtime is genuinely running, and a future
    // start_session will re-run the (idempotent) refresh + retry the
    // update.
    if needs_refresh {
        if let Err(e) = state.store.update_guest_versions(
            &operator.name,
            &session.id,
            sandbox_core::guest::DAEMON_GUEST_PROTO_VERSION,
            sandbox_core::guest::SANDBOX_GUEST_VERSION,
        ) {
            error!(
                session_id = %session.id,
                error = %e,
                "update_guest_versions failed after successful refresh + start; \
                 the next start_session will re-run refresh idempotently"
            );
        }
    }

    // Restore remaining networking: gateway container, plus (Lima-only)
    // guest config + CA injection. The lite path forks at this call —
    // `restore_session_networking_lite` performs the gateway / ingestor /
    // DNS-gate-listener restore but skips `attach_vm_to_bridge` +
    // `inject_ca_into_vm` because they're VM-only steps that try to run
    // `sudo bash -c ...` inside the guest, and the lite image has neither
    // sudo nor those bridge helpers.
    let restore_result = match session.backend {
        BackendKind::Container => {
            restore_session_networking_lite(&session.id, &operator.name, &state).await
        }
        BackendKind::Lima => restore_session_networking(&session.id, &operator.name, &state).await,
    };
    match restore_result {
        Ok(()) => {
            info!(session_id = %session.id, "session networking restored after start");
        }
        Err(e) => {
            error!(session_id = %session.id, error = %e, "networking restore failed after start");
            let _ = state
                .store
                .update_state(&session.id, &operator.name, SessionState::Error);
            // Best-effort teardown of any partial networking state.
            teardown_session_networking(&session.id, &state).await;
            return error_response(e).into_response();
        }
    }

    // Re-fetch the session to get the updated state and timestamp.
    let refreshed = match state.store.get_session(&session.id, &operator.name) {
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
    Extension(operator): Extension<OperatorIdentity>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id, &operator.name) {
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

    // Acquire the per-session workspace-lock mutex and HOLD it across
    // the entire teardown (orchestrator decision Q4). The acquire is
    // cheap on the steady-state Unlocked path; on a contended path a
    // concurrent push/pull is in flight and we must refuse the stop.
    //
    // Atomicity contract:
    // the workspace acquire handler reads the session state INSIDE this
    // same mutex's critical section, so:
    //   * stop-first: stop holds the mutex for the full teardown; a
    //     concurrent acquire waits, then sees state != Running and
    //     returns 400.
    //   * acquire-first: acquire transitions LockState to Locked and
    //     releases the mutex; stop arrives, takes the mutex, observes
    //     `active_op() == Some(_)` here, and returns 409.
    //
    // `lock_state` must live for the rest of the function body — it is
    // a `tokio::sync::Mutex` guard, so holding it across `.await`
    // points is safe (and required, by the atomicity contract above).
    // Renaming to `_lock_state` would suppress clippy's unused-binding
    // lint AT THE COST of dropping the guard immediately; do NOT do
    // that.
    let lock_mutex = workspace_lock_for(&state, &session.id);
    let lock_state = lock_mutex.lock().await;
    let session_name_or_id = session.name.as_deref().unwrap_or(session.id.as_ref());
    if let Err(e) = lifecycle_lock_check(&lock_state, session_name_or_id) {
        return error_response(e).into_response();
    }

    info!(session_id = %session.id, "stopping session");

    // Mark this session as "stopping" so the gateway monitor doesn't restart
    // the gateway container while we are tearing it down.
    state.sessions_stopping.lock().await.insert(session.id);

    // Cancel DNS propagation loop before tearing down networking.
    cancel_dns_propagation_loop(&session.id, &state).await;

    // Cancel the synchronous DNS-gate listener before the container
    // disappears: the UDS file lives inside the events host directory
    // `stop_gateway` is about to remove, and we want the listener task
    // to exit cleanly rather than spin on `accept` against a vanished
    // socket.
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
        // Dispatch through the trait, keyed off the persisted backend.
        let runtime = runtime_for(&state, session.backend);
        let handle = RuntimeHandle::from_session_id(&session.id);
        match runtime.stop(&handle).await {
            Ok(()) => {}
            Err(e) => {
                state.sessions_stopping.lock().await.remove(&session.id);
                let _ = state
                    .store
                    .update_state(&session.id, &operator.name, SessionState::Error);
                return error_response(e).into_response();
            }
        }
    }

    if let Err(e) = state
        .store
        .update_state(&session.id, &operator.name, SessionState::Stopped)
    {
        state.sessions_stopping.lock().await.remove(&session.id);
        return error_response(e).into_response();
    }

    state.sessions_stopping.lock().await.remove(&session.id);

    info!(session_id = %session.id, "session stopped");

    let refreshed = match state.store.get_session(&session.id, &operator.name) {
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
    Extension(operator): Extension<OperatorIdentity>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id, &operator.name) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    // Acquire the per-session workspace-lock mutex and HOLD it across
    // the entire teardown — same contract as `stop_session`. See the
    // detailed comment block there for the atomicity argument; the
    // shape is identical (stop and remove are both "lifecycle exits"
    // for the purposes of the lock-vs-lifecycle interaction).
    //
    // `remove` accepts any session state (a stopped session can be
    // removed without first running stop), so unlike `stop_session`
    // there is no state-precondition early-return above this block —
    // the lock check is the first guard.
    let lock_mutex = workspace_lock_for(&state, &session.id);
    let lock_state = lock_mutex.lock().await;
    let session_name_or_id = session.name.as_deref().unwrap_or(session.id.as_ref());
    if let Err(e) = lifecycle_lock_check(&lock_state, session_name_or_id) {
        return error_response(e).into_response();
    }

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
    // VM cleanup goes through the generic trait dispatch
    // (`runtime.delete(&handle).await`); the rest of the teardown
    // (gateway stop, docker network delete, CA remove, bridge detach)
    // stays inside one shared `spawn_blocking` so we keep a single
    // host-side task for the remaining sync work. Dispatch goes to
    // the runtime that owns this session's resources (Lima for VM
    // rows, Container for docker rows).
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
    match state.store.get_network_info(&session.id, &operator.name) {
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
    // doesn't grow without bound as sessions churn.
    state.propagation_states.remove(&session.id).await;

    // Delete the session from the store.
    if let Err(e) = state.store.delete_session(&session.id, &operator.name) {
        return error_response(e).into_response();
    }

    info!(session_id = %session.id, "session removed");
    StatusCode::NO_CONTENT.into_response()
}

async fn exec_in_session(
    State(state): State<Arc<AppState>>,
    Extension(operator): Extension<OperatorIdentity>,
    Path(id): Path<String>,
    Json(req): Json<ExecRequest>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id, &operator.name) {
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
// Policy handlers
// ---------------------------------------------------------------------------

/// `POST /sessions/{id}/policy` -- update the policy for a running session.
async fn update_policy(
    State(state): State<Arc<AppState>>,
    Extension(operator): Extension<OperatorIdentity>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePolicyRequest>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id, &operator.name) {
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
        &operator.name,
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
    Extension(operator): Extension<OperatorIdentity>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id, &operator.name) {
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

    match clear_session_policy(&session.id, &operator.name, &state).await {
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

// ---------------------------------------------------------------------------
// Workspace-lock handlers
// ---------------------------------------------------------------------------

/// Pure-function body of the workspace-lock acquire handler.
///
/// Lifecycle-gate + state-machine adjudication for the
/// `POST /sessions/{id}/workspace-lock` endpoint, factored out of the
/// async HTTP handler so the contract can be unit-tested without
/// driving the full `AppState`. Atomicity (state-check and lock-take
/// happen inside the same per-session async-mutex critical section)
/// is the caller's responsibility — see [`acquire_workspace_lock`].
///
/// * Returns [`SandboxError::InvalidArgument`] (→ 400) when the
///   session is not in [`SessionState::Running`]. Error message:
///   `session is in state <State>; workspace operations require Running`.
/// * Returns [`SandboxError::Conflict`] (→ 409, via `error_response`)
///   when the lock is already held; the message names the active op
///   (e.g. `session has an active push operation`) so the CLI can
///   surface it verbatim.
/// * On success, returns the freshly-minted [`LockToken`] and the
///   passed-in `lock_state` is now `Locked { op, token }`.
fn acquire_workspace_lock_inner(
    session_state: SessionState,
    lock_state: &mut LockState,
    op: WorkspaceOp,
) -> Result<LockToken, SandboxError> {
    if session_state != SessionState::Running {
        return Err(SandboxError::InvalidArgument(format!(
            "session is in state {session_state}; workspace operations require Running"
        )));
    }
    lock_state.acquire(op)
}

/// Pure-function body of the workspace-lock release handler.
///
/// Delegates straight through to [`LockState::release`] — kept as a
/// thin wrapper so the symmetry with [`acquire_workspace_lock_inner`]
/// is obvious at the call site and so the handler's "inner logic" is
/// uniformly a single function call from outside the mutex critical
/// section.
fn release_workspace_lock_inner(
    lock_state: &mut LockState,
    token: LockToken,
    force: bool,
) -> Result<(), SandboxError> {
    lock_state.release(&token, force)
}

/// Predicate run by `stop_session` / `remove_session` before any
/// teardown work to refuse the lifecycle transition when a workspace
/// op (push/pull) is in flight.
///
/// Returns `Ok(())` on `LockState::Unlocked`. Returns
/// `SandboxError::Conflict` (→ 409 via `error_response`) when the
/// state is `Locked { op, .. }`; the message is:
///
/// ```text
/// session has an active <push|pull> operation; cancel the operation
/// or run 'sandbox workspace unlock <session> --force'
/// ```
///
/// `session_name_or_id` is the operator-facing reference embedded in
/// the recovery hint: prefer the user-given session name; fall back to
/// the session id (orchestrator decision Q7). The caller composes this
/// with `session.name.as_deref().unwrap_or(session.id.as_ref())`.
///
/// Pure-function shape (no async-mutex involvement) so the wording
/// contract can be exercised by unit tests without standing up a
/// runtime; the atomicity invariant — state-read serialised with the
/// acquire/release handlers through the same per-session
/// `tokio::sync::Mutex` — is the caller's responsibility (handled in
/// the `stop_session` / `remove_session` wrappers).
fn lifecycle_lock_check(
    lock_state: &LockState,
    session_name_or_id: &str,
) -> Result<(), SandboxError> {
    if let Some(active_op) = lock_state.active_op() {
        return Err(SandboxError::Conflict(format!(
            "session has an active {active_op} operation; cancel the operation or run 'sandbox workspace unlock {session_name_or_id} --force'"
        )));
    }
    Ok(())
}

/// `POST /sessions/{id}/workspace-lock` — acquire the per-session
/// workspace lock for a `push` or `pull` operation.
///
/// Behaviour:
/// 1. Resolve the session by name or id, scoped to the calling
///    operator. Missing → 404.
/// 2. Fetch the per-session lock-mutex `Arc` and acquire the inner
///    async mutex. The state-read in step 3 happens **after** the
///    mutex acquire so a concurrent `stop`/`remove` cannot transition
///    the session between the state-check and the lock-take.
/// 3. Reject (400) if the session is not `Running`.
/// 4. Try to acquire the lock; on conflict, return 409 via
///    `error_response` with the daemon-rendered message
///    (`session has an active <op> operation`).
/// 5. On success, return 200 with the minted `lock_token`. The async
///    mutex is released on return — the handler does NOT hold it
///    across rsync; the CLI re-acquires nothing during the operation
///    body because the state-machine itself encodes the "held" state.
async fn acquire_workspace_lock(
    State(state): State<Arc<AppState>>,
    Extension(operator): Extension<OperatorIdentity>,
    Path(id): Path<String>,
    Json(req): Json<WorkspaceLockAcquireRequest>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id, &operator.name) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    let lock_mutex = workspace_lock_for(&state, &session.id);
    let mut lock_state = lock_mutex.lock().await;

    match acquire_workspace_lock_inner(session.state, &mut lock_state, req.op.into()) {
        Ok(token) => {
            let body = WorkspaceLockAcquireResponse {
                lock_token: token.to_string(),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => error_response(e).into_response(),
    }
}

/// `DELETE /sessions/{id}/workspace-lock` — release the per-session
/// workspace lock previously taken by [`acquire_workspace_lock`].
///
/// Behaviour:
/// 1. Resolve the session by name or id. Missing → 404.
/// 2. Acquire the per-session async mutex.
/// 3. Parse `req.lock_token`. Per -
///    release token semantics + orchestrator decision Q6, unparseable
///    input is mapped to the all-zeroes [`LockToken::nil`] sentinel
///    so the release adjudication path stays uniform: the state-
///    machine treats it as a wrong-token release unless `force=true`.
/// 4. Delegate to [`LockState::release`]. On conflict (wrong token,
///    `force=false`) → 409 via `error_response`. On success or
///    idempotent already-unlocked → 200 with an empty JSON object,
///    matching the convention used by `update_policy` /
///    `clear_policy` for empty-success bodies.
async fn release_workspace_lock(
    State(state): State<Arc<AppState>>,
    Extension(operator): Extension<OperatorIdentity>,
    Path(id): Path<String>,
    Json(req): Json<WorkspaceLockReleaseRequest>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id, &operator.name) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    let lock_mutex = workspace_lock_for(&state, &session.id);
    let mut lock_state = lock_mutex.lock().await;

    let token = LockToken::from_str(&req.lock_token).unwrap_or_else(|_| LockToken::nil());

    match release_workspace_lock_inner(&mut lock_state, token, req.force) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({}))).into_response(),
        Err(e) => error_response(e).into_response(),
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
    caller_username: &str,
    state: &AppState,
) -> Result<(), SandboxError> {
    let network_info = state
        .store
        .get_network_info(session_id, caller_username)?
        .ok_or_else(|| {
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
    state.store.delete_policy(session_id, caller_username)?;

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
    caller_username: &str,
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

    let result = apply_policy_inner(session_id, caller_username, policy, state).await;

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
    caller_username: &str,
    policy: &Policy,
    state: &AppState,
) -> Result<(), SandboxError> {
    // Look up network info for this session.
    let network_info = state
        .store
        .get_network_info(session_id, caller_username)?
        .ok_or_else(|| {
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

    // Record the applied hash for the propagation tracker.
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
    state
        .store
        .set_policy(session_id, caller_username, policy)?;

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

    // Daemon-internal read: this loop is spawned by callers that have
    // already authorized the session via the per-caller filter
    // (`apply_policy_inner`, `start_session`, `restore_session_networking`).
    let network_info = match state.store.get_network_info_unfiltered(session_id) {
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

    // Daemon-internal read: callers (`apply_policy_inner`, `start_session`,
    // `restore_session_networking_*`) have already authorized the session
    // via the per-caller filter at the handler boundary.
    let network_info = match state.store.get_network_info_unfiltered(session_id) {
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
///    rotation as designed).
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
/// # Propagation tracking
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
        // observed at <250ms in the integration test. Empty
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
    caller_username: &str,
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
    state
        .store
        .set_network_info(session_id, caller_username, network_info)?;

    // Start the synchronous DNS-gate UDS listener.
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
/// Centralises the teardown contract: when `create_session` reaches
/// its `apply_policy` call, the caller has already supplied a
/// non-`None` `req.policy` (either directly via `--policy <file>` or
/// indirectly via `--preset` — both paths populate the wire field at
/// the CLI layer). A failure here means the session would otherwise
/// come up `Running` with `Policy: none`, silently violating the
/// caller's stated intent. The only correct response is to fail the
/// create call and surface the error through the HTTP response.
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
    caller_username: &str,
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
    let _ = store.update_state(session_id, caller_username, SessionState::Error);
    teardown_session_networking_parts(session_id, gateway, network, ingestors).await;
    error_response(e)
}

/// Fail the create call when an explicit `--repo <url>` clone fails
/// in-guest.
///
/// Mirrors the shape of [`fail_explicit_policy_apply`]: when the
/// caller passes `--repo <url>`, the session is supposed to come up
/// with `/home/agent/workspace/` populated. The four failure branches
/// (non-zero exit, `GuestResponse::Error`, unexpected guest response,
/// transport error) must not be `warn!`-swallowed — returning 201
/// CREATED with a `Running` session and an empty workspace would
/// silently violate the caller's stated intent. The only correct
/// response is to fail the create call and surface the failure
/// through the HTTP response so the CLI user can see *why* the clone
/// did not succeed (exit code, stderr snippet, transport error,
/// etc., carried through in the caller-supplied `e`).
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
    caller_username: &str,
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
    let _ = store.update_state(session_id, caller_username, SessionState::Error);
    teardown_session_networking_parts(session_id, gateway, network, ingestors).await;
    error_response(e)
}

/// Fail the create call when an explicit `--boot-cmd <cmd>` returns a
/// non-zero exit code, a guest-agent error, an unexpected guest
/// response, or a transport error.
///
/// Symmetric completion of the fail-explicit triad with
/// [`fail_explicit_policy_apply`] and [`fail_explicit_repo_clone`]:
/// the boot-cmd block must reject `warn!`-and-continue handling for
/// the same reason — when `--boot-cmd` is provided the caller is
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
    caller_username: &str,
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
    let _ = store.update_state(session_id, caller_username, SessionState::Error);
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
/// failure path, the `apply_policy` failure path, and the
/// regular stop path, while letting the unit test drive it without
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
    // Cancel the synchronous DNS-gate listener and
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
async fn reapply_session_policy(session_id: &SessionId, caller_username: &str, state: &AppState) {
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
        None => match state.store.get_policy(session_id, caller_username) {
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
        match apply_policy(
            session_id,
            caller_username,
            &policy,
            state,
            ApplyKind::Restoration,
        )
        .await
        {
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
    caller_username: &str,
    state: &AppState,
) -> Result<(), SandboxError> {
    // Check that network info exists in DB (otherwise there's nothing to restore).
    let network_info = match state.store.get_network_info(session_id, caller_username)? {
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
    } || matches!(
        state.store.get_policy(session_id, caller_username),
        Ok(Some(_))
    );
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
    reapply_session_policy(session_id, caller_username, state).await;

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
/// CA is baked into the image at build time).
///
/// Mirrors `restore_session_networking` steps 1, 2, 2b, plus the ingestor +
/// DNS-gate-listener restoration that the Lima path inherits implicitly from
/// `setup_session_networking`. Steps 3 and 4 (`attach_vm_to_bridge` +
/// `inject_ca_into_vm`) are intentionally absent.
async fn restore_session_networking_lite(
    session_id: &SessionId,
    caller_username: &str,
    state: &AppState,
) -> Result<(), SandboxError> {
    // Network info must be present in the DB (set during create_session
    // step 6); without it there's nothing to rebuild. Mirrors the Lima
    // restore guard at the top of `restore_session_networking`.
    let network_info = match state.store.get_network_info(session_id, caller_username)? {
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
    } || matches!(
        state.store.get_policy(session_id, caller_username),
        Ok(Some(_))
    );
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
    reapply_session_policy(session_id, caller_username, state).await;

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
    Extension(operator): Extension<OperatorIdentity>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id, &operator.name) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    // VM status.
    //
    // Dispatch through the trait. `RuntimeStatus` adds `Creating` and
    // `Error` variants over `VmStatus` for the container backend;
    // both are surfaced as their lower-case names so the existing
    // health-payload consumers (CLI, `tests/e2e`) stay backwards
    // compatible — they already accept arbitrary lower-case status
    // strings.
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
    let network_info = state
        .store
        .get_network_info(&session.id, &operator.name)
        .ok()
        .flatten();
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

/// `GET /sessions/{id}/ssh-config` — serve the per-session SSH client
/// config block plus the private key for the calling operator.
///
/// Implements the cross-user CLI access spec § Daemon API → ssh-config:
///
/// * Container sessions: read the keypair persisted in
///   `sessions.ssh_keypair_json` (V007 migration). Pre-V007 rows
///   surface as `Session.ssh_keypair == None`; we map that to
///   `404 Not Found` with the typed `SSH_NOT_AVAILABLE` error token
///   in the response body. Lazy keypair generation is explicitly
///   out of scope — injecting a new `authorized_keys` into a running
///   container would require sshd hot-reload that the lite image is
///   not designed for.
/// * Lima sessions: Lima manages per-VM SSH credentials on disk under
///   the daemon's `~/.lima/_config/user{,.pub}`. The daemon reads the
///   private half on demand and serves it through the same DTO
///   shape, so the CLI can dispatch backend-agnostically.
///
/// Session ownership is enforced via the existing
/// `get_session_by_name_or_id(&id, &operator.name)` path — a foreign
/// owner's session is invisible (returns the same 404 as a truly
/// non-existent session id, per the per-caller isolation rule).
///
/// **Trust-model note**: the private key bytes are returned in the
/// response body to a peercred-authenticated caller. Per the
/// cross-user CLI access spec security considerations, any member of
/// the `sandbox` OS group is trusted with every session's private
/// key (the trust model the daemon already enforces by virtue of
/// socket-group membership). Tightening this surface (per-session
/// capability tokens, daemon-issued SSH certificates, etc.) was
/// considered and explicitly deferred in the spec's Alternatives
/// section.
async fn get_ssh_config(
    State(state): State<Arc<AppState>>,
    Extension(operator): Extension<OperatorIdentity>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id, &operator.name) {
        Ok(Some(s)) => s,
        Ok(None) => return error_response(SandboxError::SessionNotFound(id)).into_response(),
        Err(e) => return error_response(e).into_response(),
    };

    let private_key = match session.backend {
        BackendKind::Container => match session.ssh_keypair.as_ref() {
            Some(kp) => kp.private.clone(),
            None => {
                // V007 forward-compat: pre-migration container rows
                // carry `ssh_keypair = None`. The typed
                // `SSH_NOT_AVAILABLE` `code` field is the wire signal
                // the CLI matches on to render the operator-actionable
                // "recreate this session" message. The `error` string
                // carries the prefix verbatim for backward
                // compatibility with consumers that predate the
                // `code` field.
                return (
                    StatusCode::NOT_FOUND,
                    Json(sandbox_core::ApiError::with_code(
                        "SSH_NOT_AVAILABLE",
                        "SSH_NOT_AVAILABLE: this session pre-dates the per-session SSH \
                         keypair (V007). Recreate the session to enable cross-user SSH \
                         access: `sandbox rm <id> && sandbox create ...`",
                    )),
                )
                    .into_response();
            }
        },
        BackendKind::Lima => {
            // Lima manages its own SSH credentials under
            // `~/.lima/_config/user` (private) and the matching `.pub`
            // (public). The daemon (running as `sandbox`) reads its
            // own home directory; the CLI never sees the file
            // directly. A `spawn_blocking` is appropriate even for
            // this small read because the handler dispatches off the
            // async runtime.
            let key_result = tokio::task::spawn_blocking(read_lima_user_private_key).await;
            match key_result {
                Ok(Ok(k)) => k,
                Ok(Err(e)) => return error_response(e).into_response(),
                Err(e) => {
                    return error_response(SandboxError::Internal(format!(
                        "spawn_blocking join failed reading Lima user key: {e}"
                    )))
                    .into_response();
                }
            }
        }
    };

    let config = sandbox_core::render_ssh_config_block(session.id.as_str());
    let dto = sandbox_core::SshConfigDto {
        config,
        private_key,
    };
    (StatusCode::OK, Json(dto)).into_response()
}

/// `GET /sessions/{id}/proxy` — WebSocket byte mover into the
/// session's sshd.
///
/// Implements the cross-user CLI access spec § Daemon API → `GET
/// /sessions/{id}/proxy`. The handler:
///
/// 1. Looks up the session under the calling operator (per-caller
///    isolation; a foreign-owner session reads as 404, identical to a
///    truly non-existent id).
/// 2. Performs the HTTP-to-WebSocket upgrade (axum's built-in `ws`
///    feature; binary frames only — SSH does its own multiplexing
///    inside the tunnel, so we deliberately do not adopt the
///    Kubernetes channel-id-prefix framing).
/// 3. Bidirectionally byte-pipes the WebSocket payload with the
///    session's sshd transport per backend (see
///    [`sandboxd::proxy_http`]).
///
/// The long-lived byte pumps in [`sandboxd::proxy_http`] deliberately
/// use `tokio::process::Command` with async pipes rather than the
/// project's standard `std::process::Command` + `spawn_blocking`
/// pattern — see the inline carve-out comment in that module for the
/// rationale. The one-shot `limactl list` probe used for the Lima
/// `sshLocalPort` discovery follows the standard convention.
async fn get_proxy(
    State(state): State<Arc<AppState>>,
    Extension(operator): Extension<OperatorIdentity>,
    Path(id): Path<String>,
    ws: axum::extract::ws::WebSocketUpgrade,
) -> impl IntoResponse {
    let proxy_state = Arc::new(sandboxd::proxy_http::ProxyState {
        store: Arc::clone(&state.store),
        lima: Arc::clone(state.lima_runtime.manager()),
    });
    match sandboxd::proxy_http::handle_proxy(proxy_state, operator.name, id, ws).await {
        Ok(resp) => resp.into_response(),
        Err(e) => e.into_response(),
    }
}

/// Read the daemon's Lima-managed SSH private key from
/// `~/.lima/_config/user`. Returns the file contents verbatim as an
/// OpenSSH-format string.
///
/// The daemon runs as the `sandbox` system user under its
/// systemd-unit launch posture; Lima writes the key under that user's
/// home directory at `~/.lima/_config/user`. The file mode is 0600 (set
/// by Lima at write time) so only the daemon process can read it.
/// This helper is invoked from `get_ssh_config` to serve the private
/// half to the calling operator over the peercred-authenticated socket.
fn read_lima_user_private_key() -> Result<String, SandboxError> {
    // Resolve the daemon's `$HOME` rather than assuming
    // `/home/sandbox`; integration tests run the daemon under their
    // own uid + home, and Lima follows `$HOME` for its config dir.
    let home_dir = std::env::var_os("HOME").ok_or_else(|| {
        SandboxError::Internal(
            "HOME environment variable is not set; cannot locate Lima user key".to_string(),
        )
    })?;
    let path = PathBuf::from(home_dir).join(".lima/_config/user");
    std::fs::read_to_string(&path).map_err(|e| {
        SandboxError::Internal(format!(
            "failed to read Lima user key {}: {e}",
            path.display()
        ))
    })
}

/// JSON body for `POST /rebuild-image`.
///
/// Both fields default so an empty / missing body decodes as the
/// historical behavior (rebuild Lima, no cache-bust flag plumbing).
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
        // Backwards-compat default: an empty body matches the historical
        // handler — Lima, no cache-bust signal.
        Self {
            backend: BackendKind::Lima,
            no_cache: false,
        }
    }
}

/// `POST /rebuild-image` -- rebuild a backend's image.
///
/// JSON body shape:
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
            // `rebuild_base_image` already deletes the golden VM and
            // rebuilds it from scratch — that is the cache-bust. The
            // `no_cache` flag is therefore a no-op on the Lima path;
            // no new flag plumbing is required.
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
            // Per the documented contract: the container rebuild lock
            // is owned inside `rebuild_lite_image` (the same
            // image-namespace lock that `ensure_image` uses), so we
            // deliberately do NOT acquire `state.base_image_lock`
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
    // Base-image status is Lima-specific (the hash-and-age check
    // operates on the golden VM); kept on the typed runtime's escape
    // hatch.
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
/// Returns gateway status per running session. This is a daemon-wide
/// ops probe and is explicitly carved out of per-caller filtering by
/// per-caller isolation — the response covers every
/// running session on the daemon regardless of caller identity.
async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let sessions = match state.store.list_sessions_unfiltered() {
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

/// Version endpoint: `GET /version`
///
/// Returns the daemon's compile-time `CARGO_PKG_VERSION` as a single-
/// field JSON object. The CLI hits this immediately after connecting
/// over the unix socket and refuses to proceed unless its own
/// `CARGO_PKG_VERSION` matches byte-for-byte (the strict-equality
/// rule). The endpoint is unauthenticated and exposes no session or
/// operator data — the socket is already group-restricted at
/// `0660 sandbox:sandbox`, so anyone who can connect is an operator.
async fn version_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
        })),
    )
        .into_response()
}

/// Diagnostics endpoint: `GET /diagnostics`
///
/// Carries two distinct classes of data:
///
/// - **System-level diagnostics** (returned to every connected
///   operator): `daemon_uid`, `daemon_user`, `kvm_readable`,
///   `kvm_writable`, `gateway_image_present`, `lite_image_present`,
///   `gateway_image_probe_failed`, `lite_image_probe_failed`,
///   `gateway_image_probe_error`, `lite_image_probe_error`,
///   `users_conf_pool`. The `*_probe_failed` companions to the
///   image-presence booleans distinguish "docker reports image
///   absent" from "probe could not run" per the documented contract so
///   doctor's C7/C8 can emit the right operator hint.
/// - **Per-operator scoped data** (filtered by `caller_username`
///   from `OperatorIdentity`): `guest_version_drift`,
///   `substrate_orphans`.
///
/// Both classes ship on a single JSON object so the CLI's doctor
/// fetches everything in one request. Operator-scoped fields are
/// filtered through the same `SessionStore::list_sessions(caller)`
/// the per-session endpoints use — an operator cannot infer another
/// operator's session ids from this surface.
///
/// Authentication: yes (per.2). The endpoint extracts
/// `Extension<OperatorIdentity>` from the request; the
/// `unresolvable peer-cred close-on-failure` policy applies as on
/// every other endpoint, so a handler reach implies a resolved
/// operator identity.
async fn diagnostics_handler(
    State(state): State<Arc<AppState>>,
    Extension(operator): Extension<OperatorIdentity>,
) -> impl IntoResponse {
    // System-level: cheap host probes, ~3 file opens. Synchronous,
    // wrapped in `spawn_blocking` so we don't park the runtime on
    // the kvm/image lookups.
    let kvm_readable = tokio::task::spawn_blocking(|| {
        std::fs::OpenOptions::new()
            .read(true)
            .open("/dev/kvm")
            .is_ok()
    })
    .await
    .unwrap_or(false);
    let kvm_writable = tokio::task::spawn_blocking(|| {
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/kvm")
            .is_ok()
    })
    .await
    .unwrap_or(false);

    let gateway_tag =
        sandbox_core::gateway::gateway_image_tag_for_daemon(env!("CARGO_PKG_VERSION"));
    let lite_tag = sandbox_core::lite_image_tag_for_daemon_probe(env!("CARGO_PKG_VERSION"));

    // Probe outcome: the daemon distinguishes three states per
    // the documented contract (probe_failed variant) so doctor's C7/C8 can
    // emit the right operator hint — "image missing" vs "docker
    // daemon unreachable" need different remediations. Returning
    // (present, probe_failed_error) keeps the wire shape
    // backward-compatible: older CLIs still read `gateway_image_present`
    // as `false` on probe failure, while newer CLIs read the
    // `gateway_image_probe_failed` companion field for the rich
    // outcome.
    let gateway_probe = {
        let tag = gateway_tag.clone();
        let join =
            tokio::task::spawn_blocking(move || sandbox_core::gateway::gateway_image_present(&tag))
                .await;
        match join {
            Ok(Ok(true)) => (true, None),
            Ok(Ok(false)) => (false, None),
            Ok(Err(e)) => (false, Some(format!("{e}"))),
            Err(e) => (
                false,
                Some(format!("daemon-side probe task failed to run: {e}")),
            ),
        }
    };
    let lite_probe = {
        let tag = lite_tag.clone();
        let join = tokio::task::spawn_blocking(move || {
            // The shared `image_exists` helper isn't exported the
            // same way the gateway one is; shell out to `docker
            // image inspect` directly so the probe shape matches.
            // Distinguish three cases the way `gateway_image_present`
            // does: exit-0 → present, exit-non-zero with `no such
            // image` / `no such object` stderr → absent, anything
            // else → probe failure (docker daemon unreachable, PATH
            // missing, etc.).
            match std::process::Command::new("docker")
                .args(["image", "inspect", &tag])
                .output()
            {
                Ok(out) if out.status.success() => Ok(true),
                Ok(out) => {
                    let stderr_lower = String::from_utf8_lossy(&out.stderr).to_lowercase();
                    if stderr_lower.contains("no such image")
                        || stderr_lower.contains("no such object")
                    {
                        Ok(false)
                    } else {
                        Err(format!(
                            "docker image inspect {tag} failed unexpectedly: {}",
                            String::from_utf8_lossy(&out.stderr).trim()
                        ))
                    }
                }
                Err(e) => Err(format!("failed to spawn docker image inspect: {e}")),
            }
        })
        .await;
        match join {
            Ok(Ok(true)) => (true, None),
            Ok(Ok(false)) => (false, None),
            Ok(Err(e)) => (false, Some(e)),
            Err(e) => (
                false,
                Some(format!("daemon-side probe task failed to run: {e}")),
            ),
        }
    };

    let gateway_image_present = gateway_probe.0;
    let lite_image_present = lite_probe.0;
    let gateway_image_probe_error = gateway_probe.1;
    let lite_image_probe_error = lite_probe.1;

    let users_conf_pool = serde_json::json!({
        "cidr": format!(
            "{}/{}",
            state.users_conf_pool.cidr.base(),
            state.users_conf_pool.cidr.prefix_len(),
        ),
        "allow_users": state.users_conf_pool.allow_users,
    });

    // Per-operator scoped: enumerate caller's running sessions and
    // expose their persisted guest-protocol stamp. The "live" probe
    // (issuing `GuestRequest::Version` per session) is the doctor's
    // verbose-only C12 — we surface the persisted db_proto/db_binary
    // here so doctor can compute the drift indicator client-side
    // without re-implementing the per-session probe.
    let caller_sessions = state
        .store
        .list_sessions(&operator.name)
        .unwrap_or_default();
    let mut guest_version_drift = Vec::with_capacity(caller_sessions.len());
    let caller_session_ids: std::collections::HashSet<SessionId> =
        caller_sessions.iter().map(|s| s.id).collect();
    for session in &caller_sessions {
        if session.state != SessionState::Running {
            continue;
        }
        guest_version_drift.push(serde_json::json!({
            "session_id": session.id.to_string(),
            "db_proto": session.guest_protocol_version,
            "db_binary_version": session.guest_binary_version,
            // Live probe is out of scope for v1 of the endpoint;
            // doctor's verbose C12 will fan out per-session
            // GuestRequest::Version probes in a future iteration.
            "drift": false,
        }));
    }

    // C13 substrate orphan cross-reference: enumerate substrate
    // resources host-wide, retain only those whose decoded session-id
    // is NOT in the caller's list. An operator only sees resources
    // they cannot account for — they cannot infer another operator's
    // session ids from this surface.
    let lima_runtime_for_blocking = Arc::clone(&state.lima_runtime);
    let caller_session_ids_for_lima = caller_session_ids.clone();
    let lima_orphans: Vec<String> = tokio::task::spawn_blocking(move || {
        lima_runtime_for_blocking
            .manager()
            .list_vms()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|vm| {
                vm.session_id.and_then(|sid| {
                    if caller_session_ids_for_lima.contains(&sid) {
                        None
                    } else {
                        Some(vm.name)
                    }
                })
            })
            .collect()
    })
    .await
    .unwrap_or_default();

    let caller_session_ids_for_docker = caller_session_ids.clone();
    let container_orphans: Vec<String> = tokio::task::spawn_blocking(move || {
        let output = std::process::Command::new("docker")
            .args([
                "ps",
                "-a",
                "--filter",
                "name=sandbox-",
                "--format",
                "{{.Names}}",
            ])
            .output();
        let Ok(output) = output else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|name| {
                // Only count names that decode to a session id —
                // the gateway-container shape (`sandbox-gw-<id>`)
                // and other prefixed names are not orphans of the
                // operator's sessions.
                sandbox_core::backend::orphan_reaper::parse_container_session_id(name).and_then(
                    |sid| {
                        if caller_session_ids_for_docker.contains(&sid) {
                            None
                        } else {
                            Some(name.to_string())
                        }
                    },
                )
            })
            .collect()
    })
    .await
    .unwrap_or_default();

    let session_dirs_root = state.base_dir.join("sessions");
    let caller_session_ids_for_dirs = caller_session_ids;
    let session_dir_orphans: Vec<String> = tokio::task::spawn_blocking(move || {
        let read_dir = match std::fs::read_dir(&session_dirs_root) {
            Ok(rd) => rd,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for entry in read_dir.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if let Ok(sid) = sandbox_core::SessionId::parse(name_str)
                && !caller_session_ids_for_dirs.contains(&sid)
            {
                out.push(name_str.to_string());
            }
        }
        out
    })
    .await
    .unwrap_or_default();

    let body = serde_json::json!({
        "daemon_uid": state.daemon_uid,
        "daemon_user": state.daemon_user,
        "kvm_readable": kvm_readable,
        "kvm_writable": kvm_writable,
        "gateway_image_present": gateway_image_present,
        "lite_image_present": lite_image_present,
        // `*_probe_failed` discriminates "docker reports image
        // absent" (probe ran, result negative) from "docker daemon
        // unreachable / fork failed / unexpected stderr" (probe did
        // not run to a verdict). the documented contract — added so doctor
        // C7/C8 can emit the right operator hint (image-missing →
        // `sandbox update`; probe-failed → restart docker /
        // sandboxd). When the probe succeeded the field is `false`;
        // when it failed the matching `*_probe_error` field carries
        // the operator-facing reason. Old CLIs that only read the
        // bool still get a sane `false`-on-failure value.
        "gateway_image_probe_failed": gateway_image_probe_error.is_some(),
        "gateway_image_probe_error": gateway_image_probe_error,
        "lite_image_probe_failed": lite_image_probe_error.is_some(),
        "lite_image_probe_error": lite_image_probe_error,
        "users_conf_pool": users_conf_pool,
        "guest_version_drift": guest_version_drift,
        "substrate_orphans": {
            "lima_vms": lima_orphans,
            "containers": container_orphans,
            "session_dirs": session_dir_orphans,
        },
    });

    (StatusCode::OK, Json(body)).into_response()
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
/// Takes the wrapping [`LimaRuntime`] rather than the
/// raw [`LimaManager`], reaching for `list_vms()` through
/// [`LimaRuntime::manager`]. The body still pattern-matches on the
/// Lima-native [`VmStatus`] because the reconciliation contract is
/// single-backend; per-backend reconciliation fan-out is a future
/// extension once additional backends ship a comparable inventory
/// surface.
fn reconcile(store: &SessionStore, lima_runtime: &LimaRuntime) {
    // Daemon startup path — runs before any HTTP handler, so per-caller
    // filtering would be meaningless here. Use the unfiltered helper to
    // walk every persisted session.
    let sessions = match store.list_sessions_unfiltered() {
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
        // Skip container-backed sessions. The Lima-VM list does not
        // include them, so the (None, Running) arm below would falsely
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
                let _ = store.update_state_reconcile(&session.id, SessionState::Error);
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
                    let _ = store.update_state_reconcile(&session.id, SessionState::Stopped);
                    fixed_count += 1;
                }
                (SessionState::Stopped, VmStatus::Running) => {
                    info!(
                        session_id = %session.id,
                        "reconciliation: VM running but session says Stopped, updating to Running"
                    );
                    let _ = store.update_state_reconcile(&session.id, SessionState::Running);
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
    // Daemon-internal reconciler — every session row regardless of
    // owner. Per-caller filtering does not apply here.
    let sessions = match state.store.list_sessions_unfiltered() {
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

                        // Daemon-internal reconciler — every session row
                        // regardless of owner. Per-caller filtering does
                        // not apply here.
                        let network_info =
                            match state.store.get_network_info_unfiltered(&session.id) {
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
                                // Daemon-internal reconciler scope — the
                                // session was selected via the unfiltered
                                // listing above, so reuse the row's own
                                // `owner_username` for the per-caller
                                // filter on the policy lookup.
                                reapply_session_policy(&session.id, &session.owner_username, state)
                                    .await;
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
/// bridge IP — its data-path listeners on :10001/:10002 are bound on
/// the bridge IP as well (not 127.0.0.1), because DNAT to loopback
/// would be dropped as a martian destination. The in-container
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

        // Daemon-internal reconciler — every session row regardless of
        // owner. Per-caller filtering does not apply here.
        let sessions = match state.store.list_sessions_unfiltered() {
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

            // Poll per-component health and emit transitions.
            // Only components that *flipped* since
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
            // The contract: "Docker marks the container unhealthy.
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

                    // Daemon-internal reconciler — every session row
                    // regardless of owner. Per-caller filtering does
                    // not apply here.
                    let network_info = match state.store.get_network_info_unfiltered(&session.id) {
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
                            // Daemon-internal reconciler scope — the
                            // session was selected via the unfiltered
                            // listing above, so reuse the row's own
                            // `owner_username` for the per-caller
                            // filter on the policy lookup.
                            reapply_session_policy(&session.id, &session.owner_username, &state)
                                .await;
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

    // Enforce the base-dir subdir layout invariants (mode 0700 on
    // `sessions/`, `events/`, `backups/`) before any code path opens a
    // database, registers a gateway image, or migrates the schema.
    // Running this synchronously is cheap (a handful of stat calls in
    // the happy path) and keeps the operator-visible failure surface
    // tight: if the chmod fails because the operator left a stale
    // root-owned subdir behind, the daemon refuses to start with a
    // clear error before anything downstream is touched.
    {
        let base_dir = base_dir.clone();
        tokio::task::spawn_blocking(move || ensure_base_dir_layout(&base_dir))
            .await
            .map_err(|e| SandboxError::Internal(format!("base-dir layout task panicked: {e}")))??;
    }

    // Gateway-image presence check. The daemon does NOT refuse to
    // start when the image is missing; refusing would block the
    // diagnostic surface (the operator's first instinct on a broken
    // install is to run `sandbox doctor` against the daemon, and we
    // want that to succeed and report the missing image). Instead we
    // log a clear `error!` line here so journald surfaces it
    // immediately, and `create_session` returns
    // `SandboxError::Gateway` with the same hint so the failure
    // surface is consistent.
    let gateway_image_tag =
        sandbox_core::gateway::gateway_image_tag_for_daemon(env!("CARGO_PKG_VERSION"));
    {
        let tag = gateway_image_tag.clone();
        let present = tokio::task::spawn_blocking(move || gateway_image_present(&tag))
            .await
            .map_err(|e| {
                SandboxError::Internal(format!("gateway image inspect task panicked: {e}"))
            })?;
        match present {
            Ok(true) => {
                info!(tag = %gateway_image_tag, "gateway image present");
            }
            Ok(false) => {
                error!(
                    tag = %gateway_image_tag,
                    hint = %missing_gateway_image_hint(&gateway_image_tag),
                    "gateway image missing; daemon continues to start so 'sandbox doctor' can report it, but session-create will be refused"
                );
            }
            Err(e) => {
                // Could not invoke `docker image inspect` at all
                // (docker daemon unreachable, binary missing). Surface
                // the same way as "missing" — refusing to start here
                // would defeat the doctor-first contract above.
                error!(
                    tag = %gateway_image_tag,
                    error = %e,
                    "could not verify gateway image presence; daemon continues to start"
                );
            }
        }
    }

    // Create the socket directory if it doesn't exist.
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Validate `users.conf` before any expensive
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
    // Convergence anchor that forces operators to run
    // `sandbox update` when the on-disk config file drifts behind (or
    // ahead of) the binary's supported schema range. The `users.conf`
    // validator fires immediately after `load_users_config()` succeeds;
    // the bridge.conf validator follows the same shape but reads the
    // first-line `# sandbox-schema-version:` header rather than a JSON
    // field. The daemon refuses to start on either mismatch — systemd's
    // `Restart=on-failure` keeps re-trying until `StartLimitBurst` hits,
    // at which point `journalctl -u sandboxd` shows the operator-facing
    // error.
    if let Err(err) = validate_users_conf_schema_version(&users_config) {
        let sandbox_err: SandboxError = err.into();
        eprintln!("sandboxd: {sandbox_err}");
        return Err(sandbox_err.into());
    }
    if let Err(err) = bridge_conf::validate_schema_version() {
        eprintln!("sandboxd: {err}");
        return Err(SandboxError::InvalidArgument(err.to_string()).into());
    }
    let allocation_pool = match resolve_allocation_pool(daemon_uid, &users_config) {
        Ok(cidr) => cidr,
        Err(err) => {
            eprintln!("sandboxd: {err}");
            return Err(err.into());
        }
    };
    // Snapshot the matched subnet entry for `GET /diagnostics` (C11).
    // `find_subnet_by_uid` would have errored above if no entry
    // matched, so this lookup is infallible — we restate the search
    // to keep the existing `resolve_allocation_pool` signature stable.
    let users_conf_pool_entry = users_config
        .find_subnet_by_uid(daemon_uid)
        .cloned()
        .expect("subnet matched in resolve_allocation_pool must be re-findable");
    let daemon_user_resolved = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(daemon_uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_default();
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
    // Wrap the store in an `Arc` immediately so the events sub-router
    // (built in `app()`) can hold its own handle without an additional
    // `FromRef` binding on `AppState`. All existing `store.*` call
    // sites below keep working unchanged via `Arc`'s
    // `Deref<Target = SessionStore>`.
    let (store, reset_orphans) = SessionStore::new(base_dir.clone())?;
    let store = Arc::new(store);
    let base_vm_name = match resolve_base_vm_name() {
        Ok(name) => name,
        Err(err) => {
            eprintln!("sandboxd: {err}");
            return Err(err.into());
        }
    };
    info!(base_vm_name = %base_vm_name, "base VM name resolved");
    let lima = Arc::new(LimaManager::new(base_dir.clone(), base_vm_name)?);

    // Wrap the existing `LimaManager` in a [`LimaRuntime`] and register
    // it in the backend dispatch table. The same `Arc<LimaRuntime>` is
    // held both as a typed handle (for Lima-only orchestration via
    // `LimaRuntime::manager()`) and inside `runtimes` (for handler-side
    // trait dispatch).
    let lima_runtime = LimaRuntime::new(Arc::clone(&lima));
    let mut runtimes: HashMap<BackendKind, Arc<dyn SessionRuntime>> = HashMap::new();
    runtimes.insert(
        BackendKind::Lima,
        Arc::clone(&lima_runtime) as Arc<dyn SessionRuntime>,
    );

    // Register the lite-mode container runtime in the dispatch table
    // next to Lima. Resource defaults are derived from host capacity
    // (host_ram*0.8, host_cpus*0.8) so the container backend honors
    // the same headroom policy Lima applies. The same
    // `Arc<ContainerRuntime>` is also held as a typed handle on
    // `AppState` so the create-session handler can reach the
    // image-tag/`ensure_image` plumbing without going through the
    // dyn-trait object.
    let (default_memory_mb, default_cpus) = compute_default_resource_limits();
    let daemon_gid = nix::unistd::Gid::current().as_raw();
    // ; non-1000
    // host uids pass through for workspace bind-mount alignment.
    let (container_uid, container_gid) = map_container_uid_gid(daemon_uid, daemon_gid);
    // The runtime's image tag must match the one `ensure_image`
    // actually builds (`sandboxd-lite:<CARGO_PKG_VERSION>`), not a
    // literal `:latest` placeholder. Using a placeholder would break
    // the very first `--lite` create because `docker create` would
    // reference an image tag that no build step ever produced. Pinning
    // it to the same `lite_image_tag_for_version` helper that
    // `ensure_image` and `rebuild_lite_image` use closes the drift at
    // one source.
    // The container backend bind-mounts the installed `sandbox-guest`
    // binary read-only into every session at
    // `/usr/local/bin/sandbox-guest`; refresh becomes `docker
    // restart` against the same already-current source
    // (per-caller isolation). The bind-mount source is
    // resolved via `sandbox_core::guest_agent_path` — production
    // builds find it at the FHS install path
    // (`/usr/local/libexec/sandboxd/sandbox-guest`), dev / test builds
    // fall back to the cargo target directory. `sandbox update`
    // atomically renames the libexec file, so the bind-mount source is
    // always coherent without a daemon-side staging step.
    let guest_bind_source = sandbox_core::guest_agent_path()?;
    let container_runtime = ContainerRuntime::new(
        lite_image_tag_for_version(env!("CARGO_PKG_VERSION")),
        default_memory_mb,
        default_cpus,
        container_uid,
        container_gid,
        guest_bind_source,
    );
    runtimes.insert(
        BackendKind::Container,
        Arc::clone(&container_runtime) as Arc<dyn SessionRuntime>,
    );

    let runtimes = Arc::new(runtimes);

    // `GuestConnector` dispatches per session backend through the
    // runtime registry. It looks up the session's `BackendKind` in
    // the store at request time and asks the matching `SessionRuntime`
    // for a `GuestTransport` — no hard-wired `limactl shell`
    // invocation. Lima sessions still go through
    // `limactl shell ... socat`; container sessions go through
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

    // Lite container backend orphan cleanup.
    // on daemon start" extends the gateway-container reconcile pattern
    // with a Docker-side sweep: any `sandbox-{id}` container,
    // `sandbox-home-{id}` volume, or `sandbox-net-{id}` network whose
    // derived session id is not in `sessions.db` is removed.
    // Best-effort and idempotent — a Docker hiccup logs and continues
    // rather than aborting startup.
    // Daemon-internal orphan reaper — needs every session row regardless
    // of owner. Per-caller filtering does not apply here.
    let live_session_ids: HashSet<SessionId> = match store.list_sessions_unfiltered() {
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
    //
    // The reaper additionally gates `sandbox-net-*` networks against
    // the daemon's allocator pool — only networks whose IPAM-reported
    // IPv4 subnets fall fully inside `allocation_pool` are reaped, and
    // out-of-pool networks' container/volume siblings inherit the same
    // exemption. See the `orphan_reaper.rs` module docs for the
    // dual-anchor model.
    {
        let docker_ops = CliDockerOps;
        let _ = reap_orphans(&docker_ops, &live_session_ids, &allocation_pool).await;
    }

    // Hydrate the in-memory policy map from SQLite **before**
    // `reconcile_networking` runs.  Gateway restoration inside the
    // reconciliation loop calls `reapply_session_policy`, which looks
    // up `state.session_policies`.  Without this hydration step the map
    // is empty on restart and the restored gateway would fall back to
    // the fail-closed empty DNS policy, locking out the session until
    // its stored policy is reapplied — which is less bad than an
    // allow-all fallback but still wrong.
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
        workspace_locks: std::sync::Mutex::new(HashMap::new()),
        propagation_states: Arc::new(PropagationStates::new()),
        daemon_uid,
        daemon_user: daemon_user_resolved,
        users_conf_pool: users_conf_pool_entry,
    });

    // Replay one `policy_reset_on_upgrade` lifecycle event per
    // session whose v1 policy was dropped by migration V004.
    // The store's `SessionStore::new` captured the
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

    let listener = bind_socket(&socket_path)?;

    info!(socket = %socket_path.display(), "sandboxd listening");

    let app = app(Arc::clone(&state));

    // Wrap the listener with the peer-cred acceptor: every
    // accepted connection has `SO_PEERCRED` read, the uid resolved to a
    // username, and the resulting `OperatorIdentity` attached to every
    // request flowing through it via
    // `into_make_service_with_connect_info`.
    let listener = PeerCredListener::new(listener);

    // Graceful shutdown on SIGTERM / SIGINT.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<PeerCredAddr>(),
    )
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
    // workspace_lock_for_map — per-session lock-map fetch helper.
    //
    // Drives the inner free function rather than the `AppState`-typed
    // wrapper so the tests stay independent of the daemon's heavyweight
    // state graph (`SessionStore`, runtimes, network/gateway managers).
    // The wrapper is a one-line delegate so the contract is identical.
    // -----------------------------------------------------------------------

    #[test]
    fn workspace_lock_for_returns_same_arc_for_same_session_id() {
        let map: std::sync::Mutex<HashMap<SessionId, Arc<Mutex<sandbox_core::LockState>>>> =
            std::sync::Mutex::new(HashMap::new());
        let sid = SessionId::generate();

        let a = workspace_lock_for_map(&map, &sid);
        let b = workspace_lock_for_map(&map, &sid);

        // Both calls must yield handles to the SAME inner mutex — Phase
        // 3's acquire/release handlers rely on this to serialise
        // workspace ops for a single session. If `entry(...).or_insert_with`
        // were ever replaced with an unconditional insert, this would
        // catch the regression: two distinct `Arc`s would mean two
        // independent lock states for the same session.
        assert!(
            Arc::ptr_eq(&a, &b),
            "workspace_lock_for_map must return the same Arc for repeat calls with the same session id"
        );
    }

    #[test]
    fn workspace_lock_for_returns_distinct_arc_for_different_session_ids() {
        let map: std::sync::Mutex<HashMap<SessionId, Arc<Mutex<sandbox_core::LockState>>>> =
            std::sync::Mutex::new(HashMap::new());
        let sid1 = SessionId::generate();
        let sid2 = SessionId::generate();
        assert_ne!(sid1, sid2, "generate() must produce distinct ids");

        let a = workspace_lock_for_map(&map, &sid1);
        let b = workspace_lock_for_map(&map, &sid2);

        // Different sessions get independent locks — pinning that an
        // operation on session A cannot block an operation on session B.
        assert!(
            !Arc::ptr_eq(&a, &b),
            "workspace_lock_for_map must return distinct Arcs for distinct session ids"
        );
    }

    /// Workspace locks are per-process state — nothing in the on-disk
    /// session record encodes the lock, so a daemon restart always
    /// reconstructs every entry as `LockState::Unlocked` on first
    /// reference. The contract is documented on
    /// [`sandbox_core::LockState::new`] and load-bearing for orphan-lock
    /// recovery: an operator who restarts the daemon to escape a
    /// wedged-lock situation must observe a clean state, not a
    /// persisted `Locked` row.
    ///
    /// We model "restart" by dropping the map and re-constructing it.
    /// The same `SessionId` then resolves to a fresh `Unlocked` entry.
    /// `tokio::sync::Mutex::blocking_lock()` lets us reach into the
    /// inner mutex from a synchronous test without a runtime.
    #[test]
    fn restart_resets_locks() {
        let sid = SessionId::generate();

        // Pre-restart: acquire the lock so the in-memory map is in a
        // non-trivial `Locked` state. If the lock survived "restart",
        // step 4 below would observe `is_locked() == true`.
        {
            let map: std::sync::Mutex<HashMap<SessionId, Arc<Mutex<sandbox_core::LockState>>>> =
                std::sync::Mutex::new(HashMap::new());
            let lock_arc = workspace_lock_for_map(&map, &sid);
            let mut guard = lock_arc.blocking_lock();
            let _token = guard
                .acquire(WorkspaceOp::Push)
                .expect("acquire on fresh Unlocked must succeed");
            assert!(
                guard.is_locked(),
                "sanity: lock should be Locked after acquire"
            );
            // `map` (and the Arc inside it) goes out of scope at the
            // block end — modelling the daemon's process exit.
        }

        // Post-restart: a new empty map, same `SessionId`. The first
        // `workspace_lock_for_map` lookup must lazily insert a fresh
        // `LockState::new()` — i.e. `Unlocked`.
        let new_map: std::sync::Mutex<HashMap<SessionId, Arc<Mutex<sandbox_core::LockState>>>> =
            std::sync::Mutex::new(HashMap::new());
        let lock_arc = workspace_lock_for_map(&new_map, &sid);
        let guard = lock_arc.blocking_lock();
        assert!(
            !guard.is_locked(),
            "after `restart` (map dropped + reconstructed) the same SessionId \
             must resolve to a fresh Unlocked state — the workspace lock is \
             per-process and never persisted across daemon lifetimes"
        );
        assert_eq!(
            guard.active_op(),
            None,
            "post-restart lock state must have no active workspace op"
        );
    }

    // -----------------------------------------------------------------------
    // acquire_workspace_lock_inner / release_workspace_lock_inner —
    // pure-function bodies of the workspace-lock handlers.
    //
    // The async HTTP handler shells take `State<Arc<AppState>>`, which
    // is awkward to construct in a unit test (it owns live runtimes /
    // store / gateway / network managers). The inner pure functions
    // carry the entire lifecycle-and-state-machine adjudication, so
    // testing them is sufficient for the Phase 3 contract. Wire-level
    // coverage (HTTP-status mapping, JSON shapes) lives in the Phase 7
    // integration tests.
    // -----------------------------------------------------------------------

    #[test]
    fn acquire_returns_token_when_session_running_and_unlocked() {
        // Happy path: a Running session with an Unlocked state-machine
        // entry must mint a token and transition the state to Locked.
        let mut lock = LockState::new();
        let token =
            acquire_workspace_lock_inner(SessionState::Running, &mut lock, WorkspaceOp::Push)
                .expect("acquire on Running + Unlocked must succeed");
        assert!(lock.is_locked());
        assert_eq!(lock.active_op(), Some(WorkspaceOp::Push));
        // The returned token must match the one now held inside the
        // state-machine — the release path is a token-match, so a
        // drifted token here would be undetectable until release time.
        match lock {
            LockState::Locked { token: held, .. } => assert_eq!(held, token),
            other => panic!("expected Locked after acquire, got {other:?}"),
        }
    }

    #[test]
    fn acquire_returns_invalid_argument_when_session_not_running() {
        // Strict Running-only gate (orchestrator Q9): every other
        // SessionState variant must surface InvalidArgument with the
        // spec-pinned wording so the CLI surfaces a uniform diagnostic.
        // SessionState has four variants — Creating, Running, Stopped,
        // Error; this enumerates the three that must reject.
        for state in [
            SessionState::Creating,
            SessionState::Stopped,
            SessionState::Error,
        ] {
            let mut lock = LockState::new();
            let err = acquire_workspace_lock_inner(state, &mut lock, WorkspaceOp::Pull)
                .expect_err("acquire must reject any non-Running session");
            match err {
                SandboxError::InvalidArgument(msg) => {
                    let observed = format!("session is in state {state}");
                    assert!(
                        msg.contains(&observed),
                        "rejection message must include the observed state `{state}`; got: {msg}"
                    );
                    assert!(
                        msg.contains("require Running"),
                        "rejection message must point at the Running requirement; got: {msg}"
                    );
                }
                other => panic!("expected InvalidArgument, got {other:?}"),
            }
            // Critical: a rejected acquire must NOT have mutated the
            // lock state. If the state-check happened *after* the
            // acquire, this would catch it.
            assert!(
                !lock.is_locked(),
                "rejected acquire must leave the lock state Unlocked"
            );
        }
    }

    #[test]
    fn acquire_returns_conflict_when_locked() {
        // Pre-Locked state — the state-machine's existing conflict
        // path must surface as a SandboxError::Conflict (mapped to 409
        // by error_response).
        let mut lock = LockState::new();
        lock.acquire(WorkspaceOp::Push).expect("seed acquire");
        let err = acquire_workspace_lock_inner(SessionState::Running, &mut lock, WorkspaceOp::Pull)
            .expect_err("acquire on Locked must conflict");
        match err {
            SandboxError::Conflict(msg) => {
                assert!(
                    msg.contains("active push operation"),
                    "conflict message must name the held op (push); got: {msg}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn release_succeeds_with_matching_token() {
        let mut lock = LockState::new();
        let token = lock.acquire(WorkspaceOp::Push).expect("seed acquire");
        release_workspace_lock_inner(&mut lock, token, false)
            .expect("release with matching token must succeed");
        assert_eq!(lock, LockState::Unlocked);
    }

    #[test]
    fn release_returns_conflict_with_wrong_token_and_force_false() {
        let mut lock = LockState::new();
        let _held = lock.acquire(WorkspaceOp::Pull).expect("seed acquire");
        let wrong = LockToken::new_v4();
        let err = release_workspace_lock_inner(&mut lock, wrong, false)
            .expect_err("mismatched release without force must conflict");
        match err {
            SandboxError::Conflict(msg) => {
                assert!(
                    msg.contains("lock_token mismatch"),
                    "conflict message must say `lock_token mismatch`; got: {msg}"
                );
                assert!(
                    msg.contains("force=true"),
                    "conflict message must mention the force=true escape hatch; got: {msg}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
        // Failed release must leave the lock held — otherwise a hostile
        // client could probe for tokens by reading post-release state.
        assert!(lock.is_locked());
    }

    #[test]
    fn release_succeeds_with_wrong_token_and_force_true() {
        // Operator escape hatch (orphan-lock recovery). The wrong
        // token plus force=true must release unconditionally — this is
        // the path `sandbox workspace unlock <session> --force` drives.
        let mut lock = LockState::new();
        let _held = lock.acquire(WorkspaceOp::Push).expect("seed acquire");
        let wrong = LockToken::new_v4();
        release_workspace_lock_inner(&mut lock, wrong, true)
            .expect("force-release with wrong token must succeed");
        assert_eq!(lock, LockState::Unlocked);
    }

    #[test]
    fn release_is_idempotent_when_already_unlocked() {
        // Idempotent DELETE: re-issuing release on an already-Unlocked
        // lock must be a no-op success regardless of `force`. Pins the
        //  — "Idempotent on already-unlocked"
        // contract so a retrying CLI doesn't see a spurious 409.
        let mut lock = LockState::new();
        let any = LockToken::new_v4();
        release_workspace_lock_inner(&mut lock, any, false)
            .expect("release on Unlocked must succeed (force=false)");
        assert_eq!(lock, LockState::Unlocked);
        release_workspace_lock_inner(&mut lock, any, true)
            .expect("release on Unlocked must succeed (force=true)");
        assert_eq!(lock, LockState::Unlocked);
    }

    #[test]
    fn release_treats_unparseable_token_as_wrong_when_force_false() {
        // The HTTP handler maps LockToken::from_str failures to
        // LockToken::nil(); the state-machine then adjudicates as
        // wrong-token. Drive that adjudication path through the inner
        // helper so a future refactor that changes the sentinel choice
        // can't silently let unparseable input through. Without
        // `force=true`, the nil sentinel must still produce a 409.
        let mut lock = LockState::new();
        let _held = lock.acquire(WorkspaceOp::Push).expect("seed acquire");
        let sentinel = LockToken::nil();
        let err = release_workspace_lock_inner(&mut lock, sentinel, false)
            .expect_err("nil-sentinel release without force must conflict");
        assert!(matches!(err, SandboxError::Conflict(_)));
        assert!(lock.is_locked(), "failed release must not mutate state");
    }

    #[test]
    fn release_treats_unparseable_token_as_wrong_when_force_true() {
        // Symmetric to the `force=false` test above: the HTTP handler
        // routes any unparseable `lock_token` string to
        // `LockToken::nil()` and forwards `force` verbatim. The
        // contract per orchestrator Q6 is that `force=true` always
        // overrides a wrong-token rejection — including the nil
        // sentinel that an empty or malformed string lands on. This
        // is the operator escape hatch for `sandbox workspace unlock
        // --force` when the original token has been lost.
        let mut lock = LockState::new();
        let _held = lock.acquire(WorkspaceOp::Push).expect("seed acquire");
        assert!(lock.is_locked(), "sanity: seeded lock must be Locked");

        let sentinel = LockToken::nil();
        release_workspace_lock_inner(&mut lock, sentinel, true)
            .expect("nil-sentinel release with force=true must succeed (operator override)");
        assert_eq!(
            lock,
            LockState::Unlocked,
            "force=true release must transition state-machine to Unlocked even \
             when the supplied token is the unparseable-input sentinel"
        );
    }

    // -----------------------------------------------------------------------
    // lifecycle_lock_check — pre-teardown guard run by
    // `stop_session` / `remove_session`.
    //
    // The full lifecycle wrappers carry async-mutex acquisition,
    // session store lookups, and (in stop's case) a Running-state
    // precondition; the wording contract and the Unlocked→Locked
    // discrimination both live in this pure helper. Wire-level
    // coverage (full HTTP-status, the per-session mutex held across
    // a real backend teardown) lives in the Phase 7 integration
    // tests.
    // -----------------------------------------------------------------------

    #[test]
    fn lifecycle_lock_check_passes_when_unlocked() {
        // Steady-state path: the per-session lock has never been
        // acquired (or was already released). Lifecycle handlers
        // proceed with teardown.
        let lock = LockState::new();
        lifecycle_lock_check(&lock, "any-session")
            .expect("Unlocked must allow lifecycle transition");
    }

    #[test]
    fn lifecycle_lock_check_returns_conflict_when_push_active() {
        // A push is in flight — the lifecycle transition must be
        // refused with a 409-mapping error whose message names the
        // active op (push) and includes the session reference verbatim
        // so the CLI can surface it.
        let mut lock = LockState::new();
        lock.acquire(WorkspaceOp::Push).expect("seed acquire");
        let err = lifecycle_lock_check(&lock, "demo-session")
            .expect_err("Locked must refuse lifecycle transition");
        match err {
            SandboxError::Conflict(msg) => {
                assert!(
                    msg.contains("active push operation"),
                    "message must name the active op (push); got: {msg}"
                );
                assert!(
                    msg.contains("demo-session"),
                    "message must include the session reference verbatim so \
                     the operator can copy the recovery command; got: {msg}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn lifecycle_lock_check_returns_conflict_when_pull_active() {
        // Symmetric path for the pull op — pins that the helper
        // delegates the op-name to `WorkspaceOp`'s Display impl rather
        // than hard-coding `push` (which would silently misreport pull
        // contention).
        let mut lock = LockState::new();
        lock.acquire(WorkspaceOp::Pull).expect("seed acquire");
        let err = lifecycle_lock_check(&lock, "demo-session")
            .expect_err("Locked must refuse lifecycle transition");
        match err {
            SandboxError::Conflict(msg) => {
                assert!(
                    msg.contains("active pull operation"),
                    "message must name the active op (pull); got: {msg}"
                );
                assert!(
                    msg.contains("demo-session"),
                    "message must include the session reference; got: {msg}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn lifecycle_lock_check_includes_unlock_force_hint() {
        //
        // recovery hint: the conflict message MUST mention `unlock`
        // and `--force` so the operator (or an LLM agent reading the
        // error) can immediately drive the orphan-lock escape hatch
        // without consulting docs.
        let mut lock = LockState::new();
        lock.acquire(WorkspaceOp::Push).expect("seed acquire");
        let err = lifecycle_lock_check(&lock, "sess-abc")
            .expect_err("Locked must refuse lifecycle transition");
        match err {
            SandboxError::Conflict(msg) => {
                assert!(
                    msg.contains("unlock"),
                    "message must mention `unlock`; got: {msg}"
                );
                assert!(
                    msg.contains("--force"),
                    "message must mention the `--force` flag; got: {msg}"
                );
                assert!(
                    msg.contains("sandbox workspace unlock sess-abc --force"),
                    "message must embed the literal recovery command \
                     interpolated with the session reference; got: {msg}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // round_cpus_one_decimal — boundary normalisation.
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
        // Not required by the contract; the design only mandates the
        // 1-decimal grid. We pin `1.5` and `2.0` (exactly on grid)
        // round to themselves.
        assert_eq!(round_cpus_one_decimal(1.5), 1.5);
        assert_eq!(round_cpus_one_decimal(2.0), 2.0);
        assert_eq!(round_cpus_one_decimal(0.8), 0.8);
    }

    /// Round-trip the 1-decimal grid through the request-parse-time
    /// normalisation
    /// without precision drift. `0.8`, `1.5`, `2.0` survive the
    /// parse → store → serialize round-trip with bit-equality on the
    /// boundary helper.
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
    // validate_no_gitignore_against_workspace — request-shape validation.
    //
    // Pure predicate; we drive every accept/reject branch directly so
    // the rejection-message wording is pinned without driving the full
    // `create_session` handler. The wording mirrors the rejection
    // message for `--no-gitignore` on `sandbox create` and is mirrored on the CLI
    // side (`validate_no_gitignore_for_workspace`) — both sites carry
    // the literal string because there is no shared error catalog in
    // `sandbox-core` today.
    // -----------------------------------------------------------------------

    #[test]
    fn validate_no_gitignore_accepts_flag_with_local_workspace() {
        let mode = sandbox_core::WorkspaceMode::Local {
            host_path: "/tmp/proj".into(),
            guest_path: "/tmp/proj".into(),
        };
        assert_eq!(
            validate_no_gitignore_against_workspace(true, Some(&mode)),
            Ok(())
        );
    }

    #[test]
    fn validate_no_gitignore_accepts_absent_flag_regardless_of_mode() {
        // Flag off → predicate is a no-op for every mode (including
        // None) — pins that the gate never fires unless the operator
        // explicitly passed `--no-gitignore`.
        let shared = sandbox_core::WorkspaceMode::Shared {
            host_path: "/tmp/x".into(),
            guest_path: "/tmp/x".into(),
            security_model: None,
        };
        let clone = sandbox_core::WorkspaceMode::Clone {
            repo_url: "https://example.invalid/repo.git".into(),
        };
        let local = sandbox_core::WorkspaceMode::Local {
            host_path: "/tmp/y".into(),
            guest_path: "/tmp/y".into(),
        };
        assert_eq!(validate_no_gitignore_against_workspace(false, None), Ok(()));
        assert_eq!(
            validate_no_gitignore_against_workspace(false, Some(&shared)),
            Ok(())
        );
        assert_eq!(
            validate_no_gitignore_against_workspace(false, Some(&clone)),
            Ok(())
        );
        assert_eq!(
            validate_no_gitignore_against_workspace(false, Some(&local)),
            Ok(())
        );
    }

    #[test]
    fn validate_no_gitignore_rejects_flag_with_shared_workspace() {
        let mode = sandbox_core::WorkspaceMode::Shared {
            host_path: "/tmp/proj".into(),
            guest_path: "/tmp/proj".into(),
            security_model: None,
        };
        let err = validate_no_gitignore_against_workspace(true, Some(&mode))
            .expect_err("flag + shared: must reject");
        assert_eq!(
            err,
            "--no-gitignore is only meaningful for local: workspaces; this session uses shared:"
        );
    }

    #[test]
    fn validate_no_gitignore_rejects_flag_with_clone_workspace() {
        let mode = sandbox_core::WorkspaceMode::Clone {
            repo_url: "https://example.invalid/repo.git".into(),
        };
        let err = validate_no_gitignore_against_workspace(true, Some(&mode))
            .expect_err("flag + clone: must reject");
        assert_eq!(
            err,
            "--no-gitignore is only meaningful for local: workspaces; this session uses clone:"
        );
    }

    #[test]
    fn validate_no_gitignore_rejects_flag_without_workspace() {
        let err = validate_no_gitignore_against_workspace(true, None)
            .expect_err("flag + absent workspace must reject");
        assert_eq!(
            err,
            "--no-gitignore is only meaningful for local: workspaces; this session uses <empty>:"
        );
    }

    // -----------------------------------------------------------------------
    // resolve_allocation_pool — startup-validation logic.
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
    // are NOT re-tested here — the `users_conf` unit tests cover them.
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
        // The bogus username is the same sentinel that
        // `allows_uid_rejects_bogus_username` uses — a name that
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
    // validate_base_vm_name — startup-validation for SANDBOX_BASE_VM_NAME.
    //
    // Pure function; we drive every accept/reject branch directly so the
    // argv-injection guard is pinned without spinning up the daemon.
    // Validation is a must-have: an attacker-controlled env var could
    // otherwise inject `--`-prefixed flags into `limactl create --name <…>`.
    // -----------------------------------------------------------------------

    #[test]
    fn validate_base_vm_name_accepts_default() {
        validate_base_vm_name(sandbox_core::DEFAULT_BASE_VM_NAME)
            .expect("default base VM name must validate");
    }

    #[test]
    fn validate_base_vm_name_accepts_test_override() {
        validate_base_vm_name("sandbox-test-base").expect("test override must validate");
    }

    #[test]
    fn validate_base_vm_name_accepts_alphanumeric_only() {
        validate_base_vm_name("base42").expect("alphanumeric-only name must validate");
        validate_base_vm_name("A").expect("single-letter name must validate");
        validate_base_vm_name("0").expect("single-digit name must validate");
    }

    #[test]
    fn validate_base_vm_name_accepts_max_length() {
        let name = "a".repeat(BASE_VM_NAME_MAX_LEN);
        validate_base_vm_name(&name).expect("63-character name must validate");
    }

    #[test]
    fn validate_base_vm_name_rejects_empty_string() {
        let err = validate_base_vm_name("").expect_err("empty string must reject");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(
                    msg.contains(BASE_VM_NAME_ENV) && msg.contains("empty"),
                    "message must name the env var and 'empty', got {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn validate_base_vm_name_rejects_leading_hyphen() {
        // The whole point of the check: `--evil` would be parsed as a flag
        // by limactl. Names starting with a single `-` are equally unsafe.
        let err = validate_base_vm_name("--evil").expect_err("leading hyphen must reject");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("--evil") && msg.contains("alphanumeric"),
                    "message must echo the input and explain the rule, got {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }

        validate_base_vm_name("-base").expect_err("single leading hyphen must reject");
    }

    #[test]
    fn validate_base_vm_name_rejects_disallowed_characters() {
        for bad in [
            "foo!bar", "foo bar", "foo/bar", "foo.bar", "foo_bar", "foo:bar",
        ] {
            let err = validate_base_vm_name(bad)
                .unwrap_err_or_panic_with(|| format!("expected reject for {bad:?}"));
            match err {
                SandboxError::InvalidArgument(msg) => {
                    assert!(
                        msg.contains("disallowed") || msg.contains("only ASCII"),
                        "message must explain the rule, got {msg}"
                    );
                }
                other => panic!("expected InvalidArgument for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_base_vm_name_rejects_overly_long_name() {
        let too_long = "a".repeat(BASE_VM_NAME_MAX_LEN + 1);
        let err = validate_base_vm_name(&too_long).expect_err("64+ character name must reject");
        match err {
            SandboxError::InvalidArgument(msg) => {
                assert!(
                    msg.contains("exceeds") && msg.contains(&BASE_VM_NAME_MAX_LEN.to_string()),
                    "message must surface the limit, got {msg}"
                );
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    /// Local helper that mirrors `Result::expect_err` but lets the message
    /// be computed lazily inside a closure; lets the rejection-loop above
    /// stay terse without paying for a `format!` on the happy path.
    trait ResultExt<T, E> {
        fn unwrap_err_or_panic_with<F: FnOnce() -> String>(self, f: F) -> E;
    }

    impl<T: std::fmt::Debug, E> ResultExt<T, E> for Result<T, E> {
        fn unwrap_err_or_panic_with<F: FnOnce() -> String>(self, f: F) -> E {
            match self {
                Ok(value) => panic!("{}: got Ok({value:?})", f()),
                Err(e) => e,
            }
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
        // default_socket_path() returns the XDG/HOME fallback; it no longer
        // reads SANDBOX_SOCKET (that is handled by clap's `env` attribute on
        // the --socket arg). The path must end with `sandboxd.sock`.
        let path = default_socket_path();
        assert!(
            path.ends_with("sandboxd.sock"),
            "expected path to end with sandboxd.sock, got: {path}"
        );
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
    // Route-helper path resolution (two-step resolver).
    //
    // The resolver considers two candidate sources:
    // `$SANDBOX_ROUTE_HELPER_PATH` (env-var override, fail-closed
    // if set but unusable) and the canonical install path
    // `/usr/local/libexec/sandboxd/sandbox-route-helper`. The four
    // permutations the unit tests cover line up with the four corners
    // of (env-var-set | env-var-unset) × (path-usable | path-unusable):
    //
    //   1. env-set, env-path usable → resolver returns env path
    //   2. env-set, env-path unusable → resolver errors, names env var
    //   3. env-unset, canonical usable → resolver returns canonical
    //   4. env-unset, canonical unusable → resolver errors, names make target
    //
    // We deliberately stub `is_usable` rather than `setcap`-ing fixture
    // files because real file capabilities require `CAP_SETFCAP` (so a
    // hermetic unit test cannot apply them) and the cargo workspace
    // commonly lives on filesystems where `setcap` returns "Operation
    // not supported" anyway. The cap-decoder logic is unit-tested
    // separately through `xattr_has_cap_sys_admin_effective`.
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_route_helper_path_from_uses_env_override_when_set_and_usable() {
        let env_path = std::path::PathBuf::from("/tmp/explicit-route-helper");
        let install_path = std::path::Path::new("/usr/local/libexec/sandboxd/sandbox-route-helper");
        let resolved = resolve_route_helper_path_from(
            Some(env_path.as_path()),
            install_path,
            // Predicate: only the env-override path is "usable". The
            // canonical install path is intentionally also marked
            // usable to prove the env override TAKES PRECEDENCE — a
            // resolver that walks the canonical path on env-set would
            // fail this test by returning the canonical path.
            |p| p == env_path.as_path() || p == install_path,
        )
        .expect("env override path is usable; resolver must use it");
        assert_eq!(resolved, env_path);
    }

    #[test]
    fn resolve_route_helper_path_from_errors_when_env_override_set_but_unusable() {
        // env-set, env-path NOT usable, canonical IS usable. The
        // resolver MUST fail closed — explicit operator intent
        // (setting the env var) is not silently overruled by falling
        // through to the canonical path. The error must name the env
        // var so the operator knows what to fix.
        let env_path = std::path::PathBuf::from("/tmp/missing-route-helper");
        let install_path = std::path::Path::new("/usr/local/libexec/sandboxd/sandbox-route-helper");
        let err = resolve_route_helper_path_from(
            Some(env_path.as_path()),
            install_path,
            |p| p == install_path, // only canonical is usable; env-path is not
        )
        .expect_err("env-override unusable; resolver must NOT fall through");
        match err {
            SandboxError::Internal(msg) => {
                assert!(
                    msg.contains("/tmp/missing-route-helper"),
                    "error must name the env-override path that failed, got: {msg}"
                );
                assert!(
                    msg.contains("SANDBOX_ROUTE_HELPER_PATH"),
                    "error must name the env var so operators can unset it, got: {msg}"
                );
                assert!(
                    msg.contains("CAP_SYS_ADMIN"),
                    "error must mention the cap requirement, got: {msg}"
                );
            }
            other => panic!("expected SandboxError::Internal, got {other:?}"),
        }
    }

    #[test]
    fn resolve_route_helper_path_from_uses_canonical_when_env_unset_and_usable() {
        let install_path = std::path::Path::new("/usr/local/libexec/sandboxd/sandbox-route-helper");
        let resolved = resolve_route_helper_path_from(None, install_path, |p| p == install_path)
            .expect("canonical install is usable");
        assert_eq!(resolved, install_path);
    }

    #[test]
    fn resolve_route_helper_path_from_errors_when_env_unset_and_canonical_unusable() {
        let install_path = std::path::Path::new("/usr/local/libexec/sandboxd/sandbox-route-helper");
        let err = resolve_route_helper_path_from(None, install_path, |_| false)
            .expect_err("no usable candidate; resolver must surface error");
        match err {
            SandboxError::Internal(msg) => {
                assert!(
                    msg.contains("sandbox-route-helper"),
                    "error must mention the binary name, got: {msg}"
                );
                assert!(
                    msg.contains(&install_path.display().to_string()),
                    "error must name the canonical install path, got: {msg}"
                );
                assert!(
                    msg.contains("CAP_SYS_ADMIN"),
                    "error must mention the cap requirement, got: {msg}"
                );
                assert!(
                    msg.contains("install-route-helper-prod-cap"),
                    "error must point at the make target operators can run \
                     to fix the install, got: {msg}"
                );
                assert!(
                    msg.contains("SANDBOX_ROUTE_HELPER_PATH"),
                    "expected error to mention env-var alternative, got: {msg}"
                );
            }
            other => panic!("expected SandboxError::Internal, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Outer wrapper: `resolve_route_helper_path()`.
    //
    // The four-corner tests above drive the inner `_from` resolver with
    // a stub predicate; this test pins the outer wrapper that reads
    // `$SANDBOX_ROUTE_HELPER_PATH` and feeds it (along with the real
    // `has_required_caps` predicate) into the inner. We mirror the
    // `unsafe set_var/restore` pattern used by
    // `users_conf_path_honors_env_override` in
    // `sandbox-core/src/users_conf.rs`. Setting/unsetting env vars in
    // Rust 2024 is unsafe due to cross-thread races; we accept the risk
    // in a unit test that does not spawn other env-reading threads.
    //
    // We assert via error-message content because a hermetic unit test
    // cannot `setcap` a fixture file (`CAP_SETFCAP` is unavailable in
    // typical runners and the workspace often lives on a filesystem
    // where `setcap` returns "Operation not supported"). Pointing the
    // env var at a path that definitely does not exist makes
    // `has_required_caps` return false deterministically, so the outer
    // takes the env-set fail-closed branch and surfaces the env-named
    // error — proving the env read happened and that the inner saw the
    // env override.
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_route_helper_path_reads_env_var_when_set() {
        // SAFETY: see the rationale on `users_conf_path_honors_env_override`
        // in `sandbox-core/src/users_conf.rs`.
        let prev = std::env::var(ROUTE_HELPER_PATH_ENV).ok();
        let env_path = "/tmp/sandbox-route-helper-outer-env-read-test-DOES-NOT-EXIST";
        unsafe {
            std::env::set_var(ROUTE_HELPER_PATH_ENV, env_path);
        }

        let result = resolve_route_helper_path();

        // Restore env state before any assertion can panic — otherwise a
        // failing assertion leaks the env mutation into other tests in
        // the same process.
        unsafe {
            match prev {
                Some(v) => std::env::set_var(ROUTE_HELPER_PATH_ENV, v),
                None => std::env::remove_var(ROUTE_HELPER_PATH_ENV),
            }
        }

        match result {
            Err(SandboxError::Internal(msg)) => {
                assert!(
                    msg.contains(env_path),
                    "outer must consult $SANDBOX_ROUTE_HELPER_PATH and surface the \
                     env-set path on fail-closed; got: {msg}"
                );
                assert!(
                    msg.contains(ROUTE_HELPER_PATH_ENV),
                    "outer must name the env var so the operator knows what to fix; got: {msg}"
                );
            }
            Ok(path) => panic!(
                "env-set path is non-existent so the resolver must NOT return Ok; got: {}",
                path.display()
            ),
            Err(other) => panic!("expected SandboxError::Internal, got {other:?}"),
        }
    }

    #[test]
    fn resolve_route_helper_path_falls_back_to_canonical_when_env_unset() {
        // SAFETY: see the rationale on `users_conf_path_honors_env_override`
        // in `sandbox-core/src/users_conf.rs`.
        let prev = std::env::var(ROUTE_HELPER_PATH_ENV).ok();
        let unique_marker = "/tmp/sandbox-route-helper-outer-fallback-test-MARKER-NOT-IN-CANONICAL";
        unsafe {
            std::env::remove_var(ROUTE_HELPER_PATH_ENV);
        }

        let result = resolve_route_helper_path();

        // Restore env state before any assertion can panic.
        unsafe {
            match prev {
                Some(v) => std::env::set_var(ROUTE_HELPER_PATH_ENV, v),
                None => std::env::remove_var(ROUTE_HELPER_PATH_ENV),
            }
        }

        // Two acceptable outcomes depending on host state:
        //   * canonical install present and cap'd → Ok(canonical_path)
        //   * canonical install absent or un-cap'd → Err(message naming canonical)
        // In neither case may the result reference the env-set marker
        // path (we removed the env var, so the env-set branch must not
        // fire). That is the seam under test.
        match result {
            Ok(path) => {
                assert_eq!(
                    path,
                    PathBuf::from(ROUTE_HELPER_INSTALL_PATH),
                    "env unset and canonical usable ⇒ resolver must return the canonical \
                     install path verbatim; got: {}",
                    path.display(),
                );
            }
            Err(SandboxError::Internal(msg)) => {
                assert!(
                    msg.contains(ROUTE_HELPER_INSTALL_PATH),
                    "env-unset error must name the canonical install path; got: {msg}"
                );
                assert!(
                    !msg.contains(unique_marker),
                    "env-unset branch must not surface any env-derived path; got: {msg}"
                );
            }
            Err(other) => panic!("expected SandboxError::Internal, got {other:?}"),
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
        // Regression guard: deny-logger is a first-class monitored
        // subcomponent (it has a real TCP/UDP data path and a /health
        // endpoint), so its liveness MUST participate in
        // `health_degraded` / `health_restored` events.
        assert!(
            MONITORED_COMPONENTS
                .iter()
                .any(|(label, component)| *label == "deny-logger"
                    && *component == HealthComponent::DenyLogger),
            "MONITORED_COMPONENTS must contain (\"deny-logger\", \
             HealthComponent::DenyLogger)"
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
    // fail_explicit_policy_apply regression guard
    //
    // Earlier behaviour: `create_session` `warn!`-swallowed an
    // `apply_policy` error and returned a `Running` session with
    // `Policy: none`, silently violating the caller's `--policy` /
    // `--preset` intent. The helper flips this to a fatal failure:
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
            .create_session(
                SessionConfig::default(),
                Some("policy-fail-test".into()),
                "test-operator",
                0,
                "",
            )
            .expect("create session");
        store
            .update_state(&session.id, "test-operator", SessionState::Running)
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
            "test-operator",
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
            .get_session(&session.id, "test-operator")
            .expect("store readable")
            .expect("session row still present");
        assert_eq!(
            reloaded.state,
            SessionState::Error,
            "session must be marked Error so ps/inspect can surface the failed create"
        );
    }

    // -----------------------------------------------------------------------
    // fail_explicit_repo_clone regression guard
    //
    // Earlier behaviour: the four `git clone` failure branches in
    // `create_session` `warn!`-swallowed the error and returned 201
    // CREATED with a `Running` session and an empty
    // `/home/agent/workspace/`. The CLI user observed success but
    // had no usable repo — silently violating the caller's
    // `--repo <url>` intent. The helper flips this to a fatal failure
    // with the same shape as the policy-apply guard above:
    //   - session state transitions Running → Error
    //   - the HTTP response carries `error_response(e)` with the
    //     diagnostic message (exit code, stderr snippet, transport
    //     error, etc.) the caller built at the failure site
    //   - teardown is issued for any partial networking state
    //
    // The test drives the helper directly (rather than the end-to-end
    // `create_session` handler) because the latter requires Docker +
    // Lima, which are banned from `make test` (see CLAUDE.md
    // "Integration-test convention").
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn fail_explicit_repo_clone_marks_session_error_and_returns_5xx() {
        use std::collections::HashMap;
        use std::net::Ipv4Addr;

        // Fresh store in a tempdir — same hermetic shape as the
        // policy-apply test above.
        let tmp = tempfile::tempdir().expect("tempdir");
        let (store, _orphans) =
            SessionStore::new(tmp.path().to_path_buf()).expect("open session store");
        let store = Arc::new(store);

        // Move the session to `Running` — the only state from which
        // `create_session` reaches the `git clone` block.
        let session = store
            .create_session(
                SessionConfig::default(),
                Some("clone-fail-test".into()),
                "test-operator",
                0,
                "",
            )
            .expect("create session");
        store
            .update_state(&session.id, "test-operator", SessionState::Running)
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
            "test-operator",
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
            .get_session(&session.id, "test-operator")
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
    // fail_explicit_boot_cmd regression guard
    //
    // Earlier behaviour: the four boot-command failure branches in
    // `create_session` (non-zero exit, `GuestResponse::Error`,
    // unexpected guest response, transport error) all
    // `warn!`-swallowed the failure and the handler returned 201
    // CREATED with a `Running` session whose boot command's side
    // effects were unrealised — the same shape that the `--policy`
    // and `--repo` paths had before their fixes. The helper mirrors
    // its two siblings: when the caller supplies `--boot-cmd <cmd>`
    // and the command does not succeed in-guest, the create call
    // must fail.
    //
    // Contracts pinned here mirror the repo-clone test verbatim:
    //   - 5xx response (not a 2xx that hides the failure),
    //   - the diagnostic context built at the failure site
    //     (operation, exit code, stderr snippet) reaches the wire
    //     body verbatim, so the CLI user sees *why* the boot
    //     command did not succeed,
    //   - the session row transitions to `Error`.
    //
    // Like the policy-apply and repo-clone tests, the boot-cmd test
    // drives the helper directly because the end-to-end
    // `create_session` handler requires Docker + Lima, which are
    // banned from `make test` (see CLAUDE.md "Integration-test
    // convention").
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
            .create_session(
                SessionConfig::default(),
                Some("boot-cmd-fail-test".into()),
                "test-operator",
                0,
                "",
            )
            .expect("create session");
        store
            .update_state(&session.id, "test-operator", SessionState::Running)
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
            "test-operator",
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
            .get_session(&session.id, "test-operator")
            .expect("store readable")
            .expect("session row still present");
        assert_eq!(
            reloaded.state,
            SessionState::Error,
            "session must be marked Error so ps/inspect can surface the failed create"
        );
    }

    // -- RebuildImageRequest body deserialization -------------------------

    /// : an empty body must decode as
    /// `{ "backend": "lima", "no_cache": false }` so older CLIs that
    /// POST `/rebuild-image` with no body keep working (backwards-
    /// compat at the wire).
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

    // -----------------------------------------------------------------------
    // ensure_base_dir_layout — startup state-dir mode enforcement.
    //
    // The function is synchronous and operates on `std::fs::*` only;
    // we drive it against a tempdir per test so no two cases share
    // filesystem state. The four cases pin the four behaviors
    // documented in the daemon-productionization.4:
    //   1. missing subdir → created at mode 0700
    //   2. wrong mode → corrected in place
    //   3. correct mode → no-op
    //   4. subdir is a regular file → SandboxError::Internal, refuse start
    // -----------------------------------------------------------------------

    /// All three subdirs (`sessions/`, `events/`, `backups/`) are
    /// created with mode `0700` when the base directory is empty.
    /// Pins the "fresh install" path: the daemon's first start
    /// produces a layout that matches what the doctor's C10 check
    /// expects, with no operator intervention.
    #[test]
    fn ensure_base_dir_layout_creates_missing_subdirs() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        ensure_base_dir_layout(tmp.path()).expect("first-run layout must succeed");

        for sub in BASE_DIR_SUBDIRS {
            let path = tmp.path().join(sub);
            let md = std::fs::metadata(&path)
                .unwrap_or_else(|e| panic!("expected {} to exist: {e}", path.display()));
            assert!(md.is_dir(), "{} must be a directory", path.display());
            let mode = md.permissions().mode() & 0o777;
            assert_eq!(
                mode,
                BASE_DIR_SUBDIR_MODE,
                "{} was created with mode {mode:o}, expected {expected:o}",
                path.display(),
                expected = BASE_DIR_SUBDIR_MODE
            );
        }
    }

    /// A pre-existing subdir with a non-`0700` mode is corrected in
    /// place. The recovery path: an operator who created the dir
    /// manually with `mkdir` (default mode `0755` under umask 022)
    /// shouldn't be forced to chmod every dir by hand on the first
    /// daemon start. The `warn!` line is the operator-visible
    /// signal that the correction happened.
    #[test]
    fn ensure_base_dir_layout_corrects_wrong_mode_with_warn() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let sessions = tmp.path().join("sessions");
        std::fs::create_dir(&sessions).expect("create sessions");
        std::fs::set_permissions(&sessions, std::fs::Permissions::from_mode(0o755))
            .expect("seed mode 0755");

        // Sanity: the precondition is what we expect before the call.
        let pre = std::fs::metadata(&sessions)
            .expect("metadata pre")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            pre, 0o755,
            "test setup must seed sessions/ at 0755; got {pre:o}"
        );

        ensure_base_dir_layout(tmp.path()).expect("correction path must not error");

        let post = std::fs::metadata(&sessions)
            .expect("metadata post")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            post, BASE_DIR_SUBDIR_MODE,
            "sessions/ mode must be corrected to 0700; got {post:o}"
        );

        // The other two subdirs are created fresh in the same call,
        // also at 0700.
        for sub in &["events", "backups"] {
            let path = tmp.path().join(sub);
            let mode = std::fs::metadata(&path)
                .expect("metadata other")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode,
                BASE_DIR_SUBDIR_MODE,
                "{} must be created at 0700; got {mode:o}",
                path.display()
            );
        }
    }

    /// When every subdir already exists at the correct mode the
    /// function is a no-op — no chmod, no recreate, no `warn!`. Pins
    /// the steady-state behavior on subsequent daemon starts.
    #[test]
    fn ensure_base_dir_layout_noop_when_modes_correct() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        for sub in BASE_DIR_SUBDIRS {
            let path = tmp.path().join(sub);
            std::fs::create_dir(&path).unwrap_or_else(|e| panic!("create {sub}: {e}"));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(BASE_DIR_SUBDIR_MODE))
                .unwrap_or_else(|e| panic!("chmod {sub}: {e}"));
        }

        // Snapshot mtimes before the call so we can detect any
        // unintended write-through (chmod or recreate would bump
        // ctime; recreation would also reset mtime).
        let mtimes_before: Vec<_> = BASE_DIR_SUBDIRS
            .iter()
            .map(|sub| {
                std::fs::metadata(tmp.path().join(sub))
                    .expect("metadata pre")
                    .modified()
                    .expect("mtime pre")
            })
            .collect();

        ensure_base_dir_layout(tmp.path()).expect("steady-state path must succeed");

        for (sub, mtime_pre) in BASE_DIR_SUBDIRS.iter().zip(mtimes_before.iter()) {
            let md = std::fs::metadata(tmp.path().join(sub)).expect("metadata post");
            let mode = md.permissions().mode() & 0o777;
            assert_eq!(
                mode, BASE_DIR_SUBDIR_MODE,
                "{sub} mode must remain 0700; got {mode:o}"
            );
            let mtime_post = md.modified().expect("mtime post");
            assert_eq!(
                &mtime_post, mtime_pre,
                "{sub} mtime must not change under the no-op path"
            );
        }
    }

    /// A non-directory at the subdir path is fatal: refuse to start.
    /// The daemon won't silently rename or unlink the offending file;
    /// the operator has to resolve the conflict explicitly.
    #[test]
    fn ensure_base_dir_layout_errors_when_subdir_is_a_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sessions = tmp.path().join("sessions");
        std::fs::write(&sessions, b"not a dir").expect("seed file");

        let err = ensure_base_dir_layout(tmp.path())
            .expect_err("non-directory subdir must produce SandboxError");
        match err {
            SandboxError::Internal(msg) => {
                assert!(
                    msg.contains("sessions") && msg.contains("not a directory"),
                    "error must name the path and the failure reason; got: {msg}"
                );
            }
            other => panic!("expected SandboxError::Internal, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // bind_socket — socket mode pin.
    //
    // The daemon-productionization.1 fixes
    // `/run/sandbox/sandboxd.sock` at mode `0660`, and doctor check C5
    // reads `stat(sock).mode & 0o777` against that constant. The
    // umask of the invoking process is unconstrained (dev shells run
    // at `022`; production systemd units may or may not carry
    // `UMask=0117`), so the daemon has to chmod the inode itself
    // immediately after `bind()` returns. This test pins that
    // behavior independently of the umask the test binary was
    // launched under.
    // -----------------------------------------------------------------------

    /// The socket inode created by `bind_socket` carries mode `0660`
    /// regardless of the test process's umask. Pins the contract that
    /// doctor check C5 reads.
    #[tokio::test]
    async fn socket_bind_sets_mode_0660() {
        use std::os::unix::fs::PermissionsExt;

        // Force a permissive umask in the test process so the
        // assertion catches the case where the daemon would have
        // relied on umask filtering alone. `0o022` is the standard
        // server-default umask; without an explicit chmod the socket
        // would land at `0o755 & !0o022 == 0o755` for a fresh inode,
        // i.e. world-readable — exactly the contract violation this
        // test exists to prevent.
        //
        // SAFETY: `libc::umask` is process-global; tests run in a
        // single shared process under cargo-nextest only when the
        // `test-threads=1` flag is set, but each `#[tokio::test]`
        // gets its own runtime and tempdir, and we never restore the
        // umask — that's fine because every test that creates files
        // through `tempfile` does so under its own private directory
        // path and the umask is irrelevant once the test process
        // exits. A future test that depends on a specific umask
        // should set it itself.
        unsafe {
            libc::umask(0o022);
        }

        let tmp = tempfile::tempdir().expect("tempdir");
        let socket_path = tmp.path().join("sandboxd.sock");

        let _listener = bind_socket(&socket_path).expect("bind_socket must succeed");

        let md = std::fs::metadata(&socket_path)
            .expect("socket inode must exist after a successful bind");
        let mode = md.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o660,
            "socket mode must be pinned to 0660; got {mode:o}"
        );
    }

    // -----------------------------------------------------------------------
    // gateway image tag pinning — pin the symmetry between the
    // gateway and lite image tag helpers, so any future drift of the
    // tag format is caught at compile/test time.
    // -----------------------------------------------------------------------

    /// `gateway_image_tag_for_version` produces
    /// `sandbox-gateway:<version>` for an arbitrary version string —
    /// no leading-colon edge cases, no stray slashes. Mirrors
    /// `daemon_lite_image_tag_matches_ensure_image_for_same_version`
    /// for the gateway image side of the same pinning rule.
    #[test]
    fn gateway_image_tag_for_version_matches_repository_colon_version_shape() {
        let tag = sandbox_core::gateway::gateway_image_tag_for_version("1.2.3");
        assert_eq!(tag, "sandbox-gateway:1.2.3");
    }

    /// Production daemon must never compose the `:latest` reference.
    /// `CARGO_PKG_VERSION` is non-empty by definition (cargo enforces
    /// a semver string in `Cargo.toml`), so the tag always has a
    /// non-trivial right-hand side.
    #[test]
    fn gateway_image_tag_for_daemon_version_is_not_latest() {
        let tag = sandbox_core::gateway::gateway_image_tag_for_version(env!("CARGO_PKG_VERSION"));
        assert_ne!(tag, "sandbox-gateway:latest");
        assert!(
            tag.starts_with("sandbox-gateway:"),
            "tag must use the canonical repository prefix; got: {tag}"
        );
    }

    /// Regression guard: the daemon must construct `ContainerRuntime`
    /// with the *same* image tag that `ensure_image` builds.
    /// Previously `main()` could pass `"sandboxd-lite:latest"` while
    /// `ensure_image` builds `sandboxd-lite:<CARGO_PKG_VERSION>`,
    /// so `docker create` would see an image tag that no build step
    /// ever produced. Routing both through `lite_image_tag_for_version`
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

    // -----------------------------------------------------------------------
    // `/version` endpoint.
    //
    // The handler is parameter-less and returns the daemon's compile-time
    // `CARGO_PKG_VERSION` wrapped in a single-field JSON object. Two pins:
    //   - body matches `{"version": "<env!(CARGO_PKG_VERSION)>"}`
    //   - `200 OK` + `Content-Type: application/json`
    //
    // We exercise the handler directly through its `IntoResponse` surface
    // rather than going through `app(...)`: the route declaration is
    // checked indirectly by the `integration_version_endpoint_real_socket`
    // integration test, which hits the real router over a unix socket.
    // -----------------------------------------------------------------------

    /// Collect an `axum::body::Body` into a `Vec<u8>`. The test uses
    /// `axum::body::to_bytes` with a generous cap (~64 KB) — the version
    /// response is ~30 bytes, so the cap is loose but explicit.
    async fn collect_body_to_vec(body: axum::body::Body) -> Vec<u8> {
        axum::body::to_bytes(body, 64 * 1024)
            .await
            .expect("collect /version body")
            .to_vec()
    }

    #[tokio::test]
    async fn version_endpoint_returns_cargo_pkg_version() {
        let response = version_handler().await.into_response();
        let bytes = collect_body_to_vec(response.into_body()).await;
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("response body must be valid JSON");
        // The body must be a single-field object: `version` is the only
        // key the daemon emits, and the value is the daemon's
        // compile-time `CARGO_PKG_VERSION`. Operators rely on this
        // shape — adding extra fields is a wire-shape break.
        assert_eq!(
            parsed,
            serde_json::json!({ "version": env!("CARGO_PKG_VERSION") }),
            "/version body shape must be exactly \
             `{{\"version\": \"<CARGO_PKG_VERSION>\"}}`"
        );
    }

    #[tokio::test]
    async fn version_endpoint_returns_200_with_application_json() {
        let response = version_handler().await.into_response();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "/version handler returns 200 OK on every invocation; \
             there is no error path"
        );
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("axum `Json` extractor must set Content-Type")
            .to_str()
            .expect("Content-Type is ASCII")
            .to_string();
        assert!(
            content_type.starts_with("application/json"),
            "axum `Json` sets `application/json` (may include `; charset=...`); got {content_type:?}"
        );
    }

    // -----------------------------------------------------------------------
    // `sandboxd --version` output format pin.
    //
    // the documented contract.5's half-installed-state detection parses the output
    // with `awk '{print $2}'`, which depends on the format being exactly
    // two space-separated tokens (`sandboxd <semver>`) followed by a
    // single newline. A regression that adds a trailing token (build
    // SHA, commit hash, ...) would silently break that parse.
    // -----------------------------------------------------------------------

    #[test]
    fn sandboxd_version_flag_produces_pinned_two_token_line() {
        // clap renders `--version` from `#[command(name, version)]`;
        // we drive the same builder here so the test fails the moment
        // a future change drops the `version` attribute or appends an
        // extra token.
        use clap::CommandFactory;
        let rendered = Args::command().render_version();
        assert_eq!(
            rendered,
            format!("sandboxd {}\n", env!("CARGO_PKG_VERSION")),
            "`sandboxd --version` must output exactly \
             `sandboxd <semver>\\n`; any extra token silently breaks \
             the `awk '{{print $2}}'` version-extract pattern"
        );
    }

    // -----------------------------------------------------------------------
    // retry_lookup — bounded retry/backoff wrapper used by
    // `resolve_uid_to_name_with_retry` on the peer-cred accept path.
    //
    // The live `getpwuid_r`-backed lookup is exercised by the
    // integration tests (e.g. `integration_route_helper_uid_without_passwd_*`);
    // here we just pin the retry/backoff scheduling itself so a
    // refactor of the loop body cannot silently drop retries or
    // misorder the early-return.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn retry_lookup_returns_first_success_without_retrying() {
        let mut calls: u32 = 0;
        let result = retry_lookup(3, Duration::from_millis(0), || {
            calls += 1;
            Some("alice")
        })
        .await;
        assert_eq!(result, Some("alice"));
        assert_eq!(
            calls, 1,
            "happy path must not consume backoff or extra attempts"
        );
    }

    #[tokio::test]
    async fn retry_lookup_recovers_on_later_attempt() {
        let mut calls: u32 = 0;
        let result = retry_lookup(3, Duration::from_millis(0), || {
            calls += 1;
            if calls < 3 { None } else { Some("bob") }
        })
        .await;
        assert_eq!(result, Some("bob"));
        assert_eq!(calls, 3, "must keep retrying until success or exhaustion");
    }

    #[tokio::test]
    async fn retry_lookup_exhausts_attempts_and_returns_none() {
        let mut calls: u32 = 0;
        let result: Option<&'static str> = retry_lookup(3, Duration::from_millis(0), || {
            calls += 1;
            None
        })
        .await;
        assert_eq!(result, None);
        assert_eq!(
            calls, 3,
            "persistent absence must still hit the deny path after exactly `attempts` tries"
        );
    }

    #[tokio::test]
    async fn retry_lookup_with_zero_attempts_never_calls_lookup() {
        let mut calls: u32 = 0;
        let result: Option<&'static str> = retry_lookup(0, Duration::from_millis(0), || {
            calls += 1;
            Some("never")
        })
        .await;
        assert_eq!(result, None);
        assert_eq!(calls, 0);
    }
}
