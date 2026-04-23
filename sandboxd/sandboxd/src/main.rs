use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use clap::Parser;
use sandbox_core::events::lifecycle as lifecycle_events;
use sandbox_core::events::session_events_host_dir;
use sandbox_core::gateway::container_name as gateway_container_name;
use sandbox_core::{
    AssuranceLevel, BaseImageStatus, CaManager, CoreDnsConfig, CreateSessionRequest, Destination,
    DnsCache, DockerHealth, EventBus, EventBusConfig, ExecRequest, ExecResponse,
    FileDownloadRequest, FileDownloadResponse, FileUploadRequest, GatewayHealth, GatewayManager,
    GatewayShutdownReason, GatewayStatus, GuestConnector, GuestRequest, GuestResponse,
    HealthComponent, LimaManager, NetworkHealth, NetworkManager, PersistConfig, PersistentSink,
    Policy, PolicyApplyStatus, PolicyCompiler, PolicyDistributor, SandboxError, Session,
    SessionConfig, SessionDto, SessionHealth, SessionId, SessionIngestor, SessionState,
    SessionStore, UpdatePolicyRequest, VmIpSessionMap, VmStatus, attach_vm_to_bridge,
    detach_vm_from_bridge, generate_ca_inject_script, mac_from_session_id, propagate_dns_changes,
    read_resolved_json, write_file_to_container,
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
    /// Default of 14 days matches the M10-S4 Phase 0 Q10 decision;
    /// TODO(M10-S6): replace with measurement-driven tuning.
    #[arg(long, default_value_t = 14)]
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
    lima: Arc<LimaManager>,
    guest: GuestConnector,
    network: Arc<NetworkManager>,
    gateway: Arc<GatewayManager>,
    /// Handles for DNS propagation background tasks, keyed by session ID.
    /// Used to cancel the loop when a session is stopped or deleted.
    dns_loop_handles: Mutex<HashMap<SessionId, tokio::task::JoinHandle<()>>>,
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
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

// The `SandboxError` → HTTP response mapping is shared with the events
// sub-router via `sandboxd::error::error_response` — see that module for
// the full mapping table and logging contract.
use sandboxd::error::error_response;

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

    let config = SessionConfig {
        cpus: req.cpus.unwrap_or(2),
        memory_mb: req.memory_mb.unwrap_or(4096),
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
    };

    // Create session record in store (state = Creating).
    let session = match state.store.create_session(config.clone(), req.name) {
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
    macro_rules! cleanup_and_return {
        ($state:expr, $session_id:expr, $err_resp:expr) => {{
            let lima = $state.lima.clone();
            let network = $state.network.clone();
            let base_dir = $state.base_dir.clone();
            let sid = $session_id;
            let _ = tokio::task::spawn_blocking(move || {
                let _ = lima.delete_vm(&sid);
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

    if use_cache {
        // ---- Fast path: clone from golden base image ----

        // Serialize check + build behind a lock so that concurrent
        // create_session requests don't each see Missing and all
        // independently trigger build_base_image().
        {
            let _base_guard = state.base_image_lock.lock().await;

            let base_status = {
                let lima_check = state.lima.clone();
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
                    let lima_build = state.lima.clone();
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
            let lima_clone = state.lima.clone();
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
            let lima_start = state.lima.clone();
            let sid = session_id;
            let cfg_start = config.clone();
            let bridge = network_info.bridge_name.clone();
            let mac = vm_mac.clone();
            match tokio::task::spawn_blocking(move || {
                lima_start.start_vm(&sid, &cfg_start, Some(&bridge), Some(&mac))
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
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
    } else {
        // ---- Slow path: full create from scratch ----

        // 2a. Create the Lima VM (with optional custom template).
        {
            let lima = state.lima.clone();
            let sid = session_id;
            let cfg = config.clone();
            let template = req.template.clone();
            match tokio::task::spawn_blocking(move || {
                if let Some(template_path) = &template {
                    lima.create_vm_with_custom_template(&sid, template_path.as_ref())
                } else {
                    lima.create_vm(&sid, &cfg)
                }
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

        // 2b. Start the VM with bridge networking env vars.
        {
            let lima = state.lima.clone();
            let sid = session_id;
            let cfg = config.clone();
            let bridge = network_info.bridge_name.clone();
            let mac = vm_mac.clone();
            match tokio::task::spawn_blocking(move || {
                lima.start_vm(&sid, &cfg, Some(&bridge), Some(&mac))
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
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
            let lima = state.lima.clone();
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
    // reload timer fires (~1s).
    let initial_dns_policy_owned: String;
    let initial_dns_policy = if let Some(ref policy) = req.policy {
        // Extract domain names from the policy and format as CoreDNS config.
        let domains: Vec<String> = policy
            .rules
            .iter()
            .filter(|r| r.level != AssuranceLevel::Deny)
            .filter_map(|r| match &r.host {
                Destination::Domain(d) => Some(d.clone()),
                Destination::Cidr(_) => None,
            })
            .collect();
        let config = CoreDnsConfig {
            allowed_domains: domains,
        };
        initial_dns_policy_owned = config.to_file_content();
        Some(initial_dns_policy_owned.as_str())
    } else {
        // Fail-closed: no policy → empty allowed-domains list so CoreDNS
        // returns NXDOMAIN for everything.  The caller can lift this via
        // a later policy update.
        initial_dns_policy_owned = CoreDnsConfig::empty_policy_file_content();
        Some(initial_dns_policy_owned.as_str())
    };
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
                // Policy failure is non-fatal for session creation -- the
                // session is still usable, just without policy enforcement.
                warn!(%session_id, error = %e, "failed to apply initial policy (session created without policy)");
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
                    warn!(
                        %session_id,
                        exit_code,
                        stdout = %stdout.trim(),
                        stderr = %stderr.trim(),
                        "git clone returned non-zero exit code (non-fatal)"
                    );
                } else {
                    info!(
                        %session_id,
                        output = %stdout.trim(),
                        "repository cloned successfully"
                    );
                }
            }
            Ok(GuestResponse::Error { message }) => {
                warn!(
                    %session_id,
                    %message,
                    "guest agent error during git clone (non-fatal)"
                );
            }
            Ok(other) => {
                warn!(
                    %session_id,
                    ?other,
                    "unexpected guest response during git clone (non-fatal)"
                );
            }
            Err(e) => {
                warn!(
                    %session_id,
                    error = %e,
                    "failed to execute git clone in VM (non-fatal)"
                );
            }
        }
    }

    // If a boot command was provided, execute it in the VM.
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
                    warn!(
                        %session_id,
                        exit_code,
                        stdout = %stdout.trim(),
                        stderr = %stderr.trim(),
                        "boot command returned non-zero exit code (non-fatal)"
                    );
                } else {
                    info!(
                        %session_id,
                        output = %stdout.trim(),
                        "boot command completed successfully"
                    );
                }
            }
            Ok(GuestResponse::Error { message }) => {
                warn!(
                    %session_id,
                    %message,
                    "guest agent error during boot command (non-fatal)"
                );
            }
            Ok(other) => {
                warn!(
                    %session_id,
                    ?other,
                    "unexpected guest response during boot command (non-fatal)"
                );
            }
            Err(e) => {
                warn!(
                    %session_id,
                    error = %e,
                    "failed to execute boot command in VM (non-fatal)"
                );
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
        .with_policy(policy_opt.as_ref());

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
    let lima = state.lima.clone();
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
    let mut session = session;
    {
        let lima = state.lima.clone();
        let sid = session.id;
        if let Ok(Ok(vm_status)) = tokio::task::spawn_blocking(move || lima.vm_status(&sid)).await {
            match (&session.state, &vm_status) {
                (SessionState::Running, VmStatus::Stopped) => {
                    session.state = SessionState::Stopped;
                    let _ = state
                        .store
                        .update_state_forced(&session.id, SessionState::Stopped);
                }
                (SessionState::Stopped, VmStatus::Running) => {
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

    let dto = SessionDto::from(&session)
        .with_status(agent_status, gateway_status)
        .with_policy(policy_opt.as_ref());
    (StatusCode::OK, Json(dto)).into_response()
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

    // Start the Lima VM with bridge networking env vars.
    {
        let lima = state.lima.clone();
        let sid = session.id;
        let cfg = session.config.clone();
        let bridge = bridge_name.clone();
        let mac = vm_mac.clone();
        match tokio::task::spawn_blocking(move || {
            lima.start_vm(&sid, &cfg, bridge.as_deref(), mac.as_deref())
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = state.store.update_state(&session.id, SessionState::Error);
                return error_response(e).into_response();
            }
            Err(e) => {
                let _ = state.store.update_state(&session.id, SessionState::Error);
                return error_response(SandboxError::Internal(format!("task join error: {e}")))
                    .into_response();
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

    // Restore remaining networking: gateway container, guest config, CA injection.
    match restore_session_networking(&session.id, &state).await {
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
        let lima = state.lima.clone();
        let sid = session.id;
        match tokio::task::spawn_blocking(move || lima.stop_vm(&sid)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                state.sessions_stopping.lock().await.remove(&session.id);
                let _ = state.store.update_state(&session.id, SessionState::Error);
                return error_response(e).into_response();
            }
            Err(e) => {
                state.sessions_stopping.lock().await.remove(&session.id);
                let _ = state.store.update_state(&session.id, SessionState::Error);
                return error_response(SandboxError::Internal(format!("task join error: {e}")))
                    .into_response();
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

    // Cancel DNS propagation loop before teardown.
    cancel_dns_propagation_loop(&session.id, &state).await;

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
    {
        let lima = state.lima.clone();
        let gateway = state.gateway.clone();
        let network = state.network.clone();
        let base_dir = state.base_dir.clone();
        let sid = session.id;
        let _ = tokio::task::spawn_blocking(move || {
            // Delete the VM from Lima (ignore errors -- it might not exist).
            let _ = lima.delete_vm(&sid);
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
    PolicyDistributor::distribute(session_id, &compiled, &state.gateway)?;

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

/// Compute a stable sha256 hex digest of a [`Policy`] for use as
/// `previous_policy_hash` on `policy_updated` events. Hashes the
/// serde-JSON representation so the digest is deterministic across
/// processes (the in-memory struct layout is not).
fn hash_policy(policy: &Policy) -> Option<String> {
    let bytes = serde_json::to_vec(policy).ok()?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
    let mut s = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    Some(s)
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

    // Distribute to gateway components.
    PolicyDistributor::distribute(session_id, &compiled, &state.gateway)?;

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
        dns_propagation_loop(sid, gateway, network_info, session_policies).await;
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

/// Background DNS propagation loop for a single session.
///
/// Periodically reads resolved.json from the gateway container, updates
/// the DNS cache, and propagates IP changes to nftables.
async fn dns_propagation_loop(
    session_id: SessionId,
    gateway: Arc<GatewayManager>,
    network_info: sandbox_core::NetworkInfo,
    session_policies: Arc<Mutex<HashMap<SessionId, Policy>>>,
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

        if changes.is_empty() && !cache.has_expired_entries() {
            tokio::time::sleep(poll_interval).await;
            continue;
        }

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

        // Propagate the current cache state to nftables.
        let gw = Arc::clone(&gateway);
        let pol = policy.clone();
        let c = cache.clone();
        let ni = network_info.clone();
        let sid = session_id;
        let propagate_result =
            tokio::task::spawn_blocking(move || propagate_dns_changes(&sid, &pol, &c, &gw, &ni))
                .await;
        match propagate_result {
            Ok(Err(e)) => {
                warn!(
                    session_id = %session_id,
                    error = %e,
                    "DNS propagation: failed to update nftables"
                );
            }
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    error = %e,
                    "DNS propagation: spawn_blocking join error updating nftables"
                );
            }
            Ok(Ok(())) => {}
        }

        // Sleep at the end so the first iteration runs immediately after
        // policy application, resolving domain IPs as fast as possible.
        tokio::time::sleep(poll_interval).await;
    }
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

    // 2. Configure the bridge NIC inside the VM (already present from boot).
    if let Err(e) = attach_vm_to_bridge(session_id, network_info, &state.guest).await {
        // Roll back gateway on attach failure. Abort the ingestor first
        // so it releases its inotify watch on the events directory; the
        // container is about to go away and no further events are
        // attributable to this session.
        abort_session_ingestor(session_id, state).await;
        let gw = state.gateway.clone();
        let sid = *session_id;
        let _ = tokio::task::spawn_blocking(move || gw.stop_gateway(&sid)).await;
        return Err(e);
    }

    // 3. Inject CA certificate into VM trust store via guest agent.
    inject_ca_into_vm(&state.guest, session_id, ca_dir).await?;

    // 4. Store network info in DB.
    state.store.set_network_info(session_id, network_info)?;

    Ok(())
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
async fn teardown_session_networking(session_id: &SessionId, state: &AppState) {
    debug!(session_id = %session_id, "tearing down session networking (preserving allocation)");
    // Abort the JSONL ingestor first so its inotify watch and file
    // handles are released before the gateway container disappears.
    // No-op when no ingestor is tracked (e.g., the gateway never
    // finished starting).
    abort_session_ingestor(session_id, state).await;

    // Blocking Docker calls (stop_gateway, remove_docker_network) are
    // wrapped in spawn_blocking to avoid stalling the Tokio runtime.
    let gateway = state.gateway.clone();
    let network = state.network.clone();
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

/// Format a `GatewayStatus` into a human-readable string for the API response.
fn format_gateway_status(gateway: &GatewayManager, session_id: &SessionId) -> String {
    match gateway.gateway_status(session_id) {
        Ok(GatewayStatus::Healthy) => "healthy".to_string(),
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
    let vm_status = {
        let lima = state.lima.clone();
        let sid = session.id;
        tokio::task::spawn_blocking(move || match lima.vm_status(&sid) {
            Ok(VmStatus::Running) => "running".to_string(),
            Ok(VmStatus::Stopped) => "stopped".to_string(),
            Ok(VmStatus::Unknown(s)) => s,
            Err(e) => format!("error: {e}"),
        })
        .await
        .unwrap_or_else(|e| format!("error: task join error: {e}"))
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

/// `POST /rebuild-image` -- rebuild the pre-baked golden base VM image.
async fn rebuild_image(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Hold the base image lock for the entire rebuild so that concurrent
    // create_session requests wait until the rebuild finishes before
    // checking the image status.
    let _base_guard = state.base_image_lock.lock().await;
    let lima = state.lima.clone();
    match tokio::task::spawn_blocking(move || lima.rebuild_base_image()).await {
        Ok(Ok(())) => (StatusCode::OK, "base image rebuilt").into_response(),
        Ok(Err(e)) => error_response(e).into_response(),
        Err(e) => error_response(SandboxError::Internal(format!("task join: {e}"))).into_response(),
    }
}

/// `GET /base-image-status` -- check the status of the golden base image.
async fn base_image_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let lima = state.lima.clone();
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
fn reconcile(store: &SessionStore, lima: &LimaManager) {
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

    let vm_list = match lima.list_vms() {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "reconciliation: failed to list VMs, skipping");
            return;
        }
    };

    let mut ok_count = 0u32;
    let mut fixed_count = 0u32;

    for session in &sessions {
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
                    GatewayStatus::Healthy => {
                        // Gateway is healthy, nothing to do.
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

        // Treat "unknown" (container not running, or the check
        // itself couldn't reach the component) as unhealthy for the
        // purposes of transition detection.  An "unknown" result
        // during steady-state Healthy gateways is already logged
        // above and we want subscribers alerted.
        let is_healthy = health == "healthy";

        let mut states = state.component_health_state.lock().await;
        let session_map = states.entry(*session_id).or_default();
        let previous = session_map.get(component).copied();

        // First observation: seed the map with `true` (healthy)
        // rather than recording and immediately emitting
        // `health_restored`.  We only publish on a real transition.
        match (previous, is_healthy) {
            (None, true) => {
                session_map.insert(*component, true);
            }
            (None, false) => {
                session_map.insert(*component, false);
                drop(states);
                state.event_bus.publish(lifecycle_events::health_degraded(
                    *session_id,
                    *component,
                    format!("component reported {health} on first poll"),
                ));
            }
            (Some(true), false) => {
                session_map.insert(*component, false);
                drop(states);
                state.event_bus.publish(lifecycle_events::health_degraded(
                    *session_id,
                    *component,
                    format!("component reported {health}"),
                ));
            }
            (Some(false), true) => {
                session_map.insert(*component, true);
                drop(states);
                state
                    .event_bus
                    .publish(lifecycle_events::health_restored(*session_id, *component));
            }
            (Some(true), true) | (Some(false), false) => {
                // No transition; leave the map untouched.
            }
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
    let guest = GuestConnector::new(Arc::clone(&lima));

    // Initialize networking managers.
    let network = Arc::new(NetworkManager::with_defaults()?);
    let gateway = Arc::new(GatewayManager::new());

    // Restore network allocator state from existing sessions.
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
    reconcile(&store, &lima);

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

    let state = Arc::new(AppState {
        base_dir,
        store,
        lima,
        guest,
        network,
        gateway,
        dns_loop_handles: Mutex::new(HashMap::new()),
        session_policies: Arc::new(Mutex::new(hydrated_policies)),
        sessions_stopping: Mutex::new(HashSet::new()),
        base_image_lock: Mutex::new(()),
        event_bus,
        vm_ip_map,
        component_health_state: Mutex::new(HashMap::new()),
        ingestors: Mutex::new(HashMap::new()),
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
}
