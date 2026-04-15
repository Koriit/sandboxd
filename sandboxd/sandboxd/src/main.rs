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
use sandbox_core::{
    ApiError, AssuranceLevel, CaManager, CoreDnsConfig, CreateSessionRequest, Destination,
    DnsCache, ExecRequest, ExecResponse, FileDownloadRequest, FileDownloadResponse,
    FileUploadRequest, GatewayHealth, GatewayManager, GatewayStatus, GitRequest, GitResponse,
    GuestConnector, GuestRequest, GuestResponse, LimaManager, NetworkHealth, NetworkManager,
    Policy, PolicyCompiler, PolicyDistributor, SandboxError, Session, SessionConfig, SessionHealth,
    SessionResponse, SessionState, SessionStore, UpdatePolicyRequest, VmStatus,
    attach_vm_to_bridge, detach_vm_from_bridge, generate_ca_inject_script, mac_from_uuid,
    propagate_dns_changes, read_resolved_json, write_file_to_container,
};
use sandbox_core::gateway::container_name as gateway_container_name;
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
}


fn default_socket_path() -> String {
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
// Shared state
// ---------------------------------------------------------------------------

struct AppState {
    base_dir: PathBuf,
    store: SessionStore,
    lima: Arc<LimaManager>,
    guest: GuestConnector,
    network: Arc<NetworkManager>,
    gateway: Arc<GatewayManager>,
    /// Handles for DNS propagation background tasks, keyed by session ID.
    /// Used to cancel the loop when a session is stopped or deleted.
    dns_loop_handles: Mutex<HashMap<uuid::Uuid, tokio::task::JoinHandle<()>>>,
    /// Active policies for sessions, keyed by session ID.
    /// Uses Arc so it can be shared with spawned DNS propagation tasks.
    session_policies: Arc<Mutex<HashMap<uuid::Uuid, Policy>>>,
    /// Sessions currently being stopped.
    ///
    /// Tracks session IDs that are in the middle of the stop sequence
    /// (networking teardown + VM stop).  The gateway monitor and network
    /// reconciliation loops check this set so they don't accidentally
    /// restart a gateway that was intentionally stopped.
    sessions_stopping: Mutex<HashSet<uuid::Uuid>>,
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Convert a `SandboxError` into an HTTP response with appropriate status code.
fn error_response(err: SandboxError) -> (StatusCode, Json<ApiError>) {
    let (status, msg) = match &err {
        SandboxError::SessionNotFound(_) => (StatusCode::NOT_FOUND, err.to_string()),
        SandboxError::InvalidState(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        SandboxError::Network(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        SandboxError::Ca(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        SandboxError::Gateway(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        SandboxError::Lima(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        SandboxError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        SandboxError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        SandboxError::Http(_) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        SandboxError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        SandboxError::Timeout { .. } => (StatusCode::GATEWAY_TIMEOUT, err.to_string()),
    };
    error!(%status, error = %msg, "handler error");
    (status, Json(ApiError::new(msg)))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn app(state: Arc<AppState>) -> Router {
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
        .route("/sessions/{id}/git", post(git_in_session))
        .route("/sessions/{id}/policy", post(update_policy))
        .route("/sessions/{id}/health", get(session_health))
        .route("/health", get(health_check))
        .with_state(state)
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
        req.repo.as_ref().map(|repo_url| sandbox_core::WorkspaceMode::Clone {
            repo_url: repo_url.clone(),
        })
    };

    let config = SessionConfig {
        cpus: req.cpus.unwrap_or(2),
        memory_mb: req.memory_mb.unwrap_or(4096),
        disk_gb: req.disk_gb.unwrap_or(20),
        workspace_mode,
        hardened: req.hardened.unwrap_or(true),
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
                return error_response(SandboxError::Internal(format!(
                    "task join error: {e}"
                )))
                .into_response();
            }
        }
    };

    let network_info = {
        let network = state.network.clone();
        let sid = session_id;
        match tokio::task::spawn_blocking(move || network.create_network(&sid))
            .await
        {
            Ok(Ok(info)) => info,
            Ok(Err(e)) => {
                let base_dir = state.base_dir.clone();
                let sid = session_id;
                let _ = tokio::task::spawn_blocking(move || {
                    CaManager::remove_session_ca(&base_dir, &sid)
                }).await;
                let _ = state.store.update_state(&session_id, SessionState::Error);
                return error_response(e).into_response();
            }
            Err(e) => {
                let _ = state.store.update_state(&session_id, SessionState::Error);
                return error_response(SandboxError::Internal(format!(
                    "task join error: {e}"
                )))
                .into_response();
            }
        }
    };

    // Generate MAC address for the VM's bridge NIC.
    let vm_mac = mac_from_uuid(&session_id);

    info!(%session_id, bridge = %network_info.bridge_name, mac = %vm_mac, "creating VM");

    // 2. Create the Lima VM (with optional custom template).
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
                let network = state.network.clone();
                let base_dir = state.base_dir.clone();
                let sid = session_id;
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = network.delete_network(&sid);
                    let _ = CaManager::remove_session_ca(&base_dir, &sid);
                }).await;
                let _ = state.store.update_state(&session_id, SessionState::Error);
                return error_response(e).into_response();
            }
            Err(e) => {
                let network = state.network.clone();
                let base_dir = state.base_dir.clone();
                let sid = session_id;
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = network.delete_network(&sid);
                    let _ = CaManager::remove_session_ca(&base_dir, &sid);
                }).await;
                let _ = state.store.update_state(&session_id, SessionState::Error);
                return error_response(SandboxError::Internal(format!(
                    "task join error: {e}"
                )))
                .into_response();
            }
        }
    }

    // 3. Start the VM with bridge networking env vars so QEMU attaches to
    //    the Docker bridge via qemu-bridge-helper at boot.
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
                let network = state.network.clone();
                let base_dir = state.base_dir.clone();
                let sid = session_id;
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = network.delete_network(&sid);
                    let _ = CaManager::remove_session_ca(&base_dir, &sid);
                }).await;
                let _ = state.store.update_state(&session_id, SessionState::Error);
                return error_response(e).into_response();
            }
            Err(e) => {
                let network = state.network.clone();
                let base_dir = state.base_dir.clone();
                let sid = session_id;
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = network.delete_network(&sid);
                    let _ = CaManager::remove_session_ca(&base_dir, &sid);
                }).await;
                let _ = state.store.update_state(&session_id, SessionState::Error);
                return error_response(SandboxError::Internal(format!(
                    "task join error: {e}"
                )))
                .into_response();
            }
        }
    }

    // 4. Install the guest agent into the VM.
    let guest_binary_path = match std::env::current_exe() {
        Ok(exe) => match exe.parent() {
            Some(dir) => dir.join("sandbox-guest"),
            None => {
                let lima = state.lima.clone();
                let network = state.network.clone();
                let base_dir = state.base_dir.clone();
                let sid = session_id;
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = lima.delete_vm(&sid);
                    let _ = network.delete_network(&sid);
                    let _ = CaManager::remove_session_ca(&base_dir, &sid);
                }).await;
                let _ = state.store.update_state(&session_id, SessionState::Error);
                return error_response(SandboxError::Internal(
                    "executable path has no parent directory".to_string(),
                ))
                .into_response();
            }
        },
        Err(e) => {
            let lima = state.lima.clone();
            let network = state.network.clone();
            let base_dir = state.base_dir.clone();
            let sid = session_id;
            let _ = tokio::task::spawn_blocking(move || {
                let _ = lima.delete_vm(&sid);
                let _ = network.delete_network(&sid);
                let _ = CaManager::remove_session_ca(&base_dir, &sid);
            }).await;
            let _ = state.store.update_state(&session_id, SessionState::Error);
            return error_response(SandboxError::Internal(format!(
                "failed to determine daemon executable path: {e}"
            )))
            .into_response();
        }
    };

    {
        let lima = state.lima.clone();
        let sid = session_id;
        let guest_bin = guest_binary_path.clone();
        match tokio::task::spawn_blocking(move || {
            lima.install_guest_agent(&sid, &guest_bin)
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                error!(%session_id, error = %e, "failed to install guest agent");
                let lima = state.lima.clone();
                let network = state.network.clone();
                let base_dir = state.base_dir.clone();
                let sid = session_id;
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = lima.delete_vm(&sid);
                    let _ = network.delete_network(&sid);
                    let _ = CaManager::remove_session_ca(&base_dir, &sid);
                }).await;
                let _ = state.store.update_state(&session_id, SessionState::Error);
                return error_response(e).into_response();
            }
            Err(e) => {
                let lima = state.lima.clone();
                let network = state.network.clone();
                let base_dir = state.base_dir.clone();
                let sid = session_id;
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = lima.delete_vm(&sid);
                    let _ = network.delete_network(&sid);
                    let _ = CaManager::remove_session_ca(&base_dir, &sid);
                }).await;
                let _ = state.store.update_state(&session_id, SessionState::Error);
                return error_response(SandboxError::Internal(format!(
                    "task join error: {e}"
                )))
                .into_response();
            }
        }
    }

    // 5. Verify the guest agent is responsive.
    match state.guest.ping(&session_id).await {
        Ok(true) => {
            info!(%session_id, "guest agent responded to ping");
        }
        Ok(false) => {
            let err = SandboxError::Internal(
                "guest agent returned unexpected response to ping".into(),
            );
            error!(%session_id, "guest agent ping: unexpected response");
            let lima = state.lima.clone();
            let network = state.network.clone();
            let base_dir = state.base_dir.clone();
            let sid = session_id;
            let _ = tokio::task::spawn_blocking(move || {
                let _ = lima.delete_vm(&sid);
                let _ = network.delete_network(&sid);
                let _ = CaManager::remove_session_ca(&base_dir, &sid);
            }).await;
            let _ = state.store.update_state(&session_id, SessionState::Error);
            return error_response(err).into_response();
        }
        Err(e) => {
            error!(%session_id, error = %e, "guest agent ping failed");
            let lima = state.lima.clone();
            let network = state.network.clone();
            let base_dir = state.base_dir.clone();
            let sid = session_id;
            let _ = tokio::task::spawn_blocking(move || {
                let _ = lima.delete_vm(&sid);
                let _ = network.delete_network(&sid);
                let _ = CaManager::remove_session_ca(&base_dir, &sid);
            }).await;
            let _ = state.store.update_state(&session_id, SessionState::Error);
            return error_response(e).into_response();
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
            .filter_map(|r| match &r.destination {
                Destination::Domain(d) => Some(d.clone()),
                Destination::Cidr(_) => None,
            })
            .collect();
        let config = CoreDnsConfig { allowed_domains: domains };
        initial_dns_policy_owned = config.to_file_content();
        Some(initial_dns_policy_owned.as_str())
    } else {
        Some("# Default allow-all policy (no policy specified)\n*\n")
    };
    match setup_session_networking(
        &session_id, &network_info, &ca_dir, &state, initial_dns_policy,
    ).await {
        Ok(()) => {
            info!(%session_id, "session networking configured");
        }
        Err(e) => {
            error!(%session_id, error = %e, "networking setup failed");
            let _ = state.store.update_state(&session_id, SessionState::Error);
            // Best-effort teardown of any partial networking state.
            teardown_session_networking(&session_id, &state);
            return error_response(e).into_response();
        }
    }

    // If a policy was provided, compile and distribute it now that the
    // gateway is running.  The DNS policy for the no-policy case was already
    // written during gateway creation above.
    if let Some(policy) = req.policy {
        match apply_policy(&session_id, &policy, &state).await {
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
    match state.store.get_session(&session_id) {
        Ok(Some(s)) => (StatusCode::CREATED, Json(s)).into_response(),
        Ok(None) => error_response(SandboxError::SessionNotFound(session_id.to_string()))
            .into_response(),
        Err(e) => error_response(e).into_response(),
    }
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
                        let _ = state.store.update_state(&s.id, SessionState::Stopped);
                    }
                    // DB says Stopped but Lima says Running => update to Running
                    (SessionState::Stopped, VmStatus::Running) => {
                        s.state = SessionState::Running;
                        let _ = state.store.update_state(&s.id, SessionState::Running);
                    }
                    _ => {}
                }
            }
            s
        })
        .collect();

    // Probe guest agent and gateway for running sessions (with a short timeout).
    let mut enriched: Vec<SessionResponse> = Vec::with_capacity(reconciled.len());
    for session in reconciled {
        let agent_status = if session.state == SessionState::Running {
            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                state.guest.ping(&session.id),
            )
            .await
            {
                Ok(Ok(true)) => Some("connected".to_string()),
                _ => Some("unreachable".to_string()),
            }
        } else {
            None
        };
        let gateway_status = if session.state == SessionState::Running {
            let gateway = state.gateway.clone();
            let sid = session.id;
            Some(
                tokio::task::spawn_blocking(move || format_gateway_status(&gateway, &sid))
                    .await
                    .unwrap_or_else(|_| "error: task join failed".to_string()),
            )
        } else {
            None
        };
        enriched.push(SessionResponse::from_session_with_status(
            session,
            agent_status,
            gateway_status,
        ));
    }

    (StatusCode::OK, Json(enriched)).into_response()
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return error_response(SandboxError::SessionNotFound(id)).into_response()
        }
        Err(e) => return error_response(e).into_response(),
    };

    // Enrich with VM status (best-effort).
    let mut session = session;
    {
        let lima = state.lima.clone();
        let sid = session.id;
        if let Ok(Ok(vm_status)) =
            tokio::task::spawn_blocking(move || lima.vm_status(&sid)).await
        {
            match (&session.state, &vm_status) {
                (SessionState::Running, VmStatus::Stopped) => {
                    session.state = SessionState::Stopped;
                    let _ = state.store.update_state(&session.id, SessionState::Stopped);
                }
                (SessionState::Stopped, VmStatus::Running) => {
                    session.state = SessionState::Running;
                    let _ = state.store.update_state(&session.id, SessionState::Running);
                }
                _ => {}
            }
        }
    }

    // Probe guest agent and gateway for running sessions.
    let agent_status = if session.state == SessionState::Running {
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            state.guest.ping(&session.id),
        )
        .await
        {
            Ok(Ok(true)) => Some("connected".to_string()),
            _ => Some("unreachable".to_string()),
        }
    } else {
        None
    };

    let gateway_status = if session.state == SessionState::Running {
        let gateway = state.gateway.clone();
        let sid = session.id;
        Some(
            tokio::task::spawn_blocking(move || format_gateway_status(&gateway, &sid))
                .await
                .unwrap_or_else(|_| "error: task join failed".to_string()),
        )
    } else {
        None
    };

    let response =
        SessionResponse::from_session_with_status(session, agent_status, gateway_status);
    (StatusCode::OK, Json(response)).into_response()
}

async fn start_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return error_response(SandboxError::SessionNotFound(id)).into_response()
        }
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
        match tokio::task::spawn_blocking(move || network.ensure_network(&sid))
            .await
        {
            Ok(Ok(info)) => {
                let mac = mac_from_uuid(&session.id);
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
                return error_response(SandboxError::Internal(format!(
                    "task join error: {e}"
                )))
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
            teardown_session_networking(&session.id, &state);
            return error_response(e).into_response();
        }
    }

    // Re-fetch the session to get the updated state and timestamp.
    match state.store.get_session(&session.id) {
        Ok(Some(s)) => (StatusCode::OK, Json(s)).into_response(),
        Ok(None) => error_response(SandboxError::SessionNotFound(session.id.to_string()))
            .into_response(),
        Err(e) => error_response(e).into_response(),
    }
}

async fn stop_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return error_response(SandboxError::SessionNotFound(id)).into_response()
        }
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
        }).await;
    }

    {
        let lima = state.lima.clone();
        let sid = session.id;
        match tokio::task::spawn_blocking(move || lima.stop_vm(&sid))
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                state.sessions_stopping.lock().await.remove(&session.id);
                let _ = state.store.update_state(&session.id, SessionState::Error);
                return error_response(e).into_response();
            }
            Err(e) => {
                state.sessions_stopping.lock().await.remove(&session.id);
                let _ = state.store.update_state(&session.id, SessionState::Error);
                return error_response(SandboxError::Internal(format!(
                    "task join error: {e}"
                )))
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

    match state.store.get_session(&session.id) {
        Ok(Some(s)) => (StatusCode::OK, Json(s)).into_response(),
        Ok(None) => error_response(SandboxError::SessionNotFound(session.id.to_string()))
            .into_response(),
        Err(e) => error_response(e).into_response(),
    }
}

async fn remove_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return error_response(SandboxError::SessionNotFound(id)).into_response()
        }
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

    // Stop VM if running, then delete from Lima, then full network teardown.
    // All of these are best-effort blocking calls.
    {
        let lima = state.lima.clone();
        let gateway = state.gateway.clone();
        let network = state.network.clone();
        let base_dir = state.base_dir.clone();
        let sid = session.id;
        let is_running = session.state == SessionState::Running;
        let _ = tokio::task::spawn_blocking(move || {
            // Stop VM if running (ignore errors -- it might already be stopped).
            if is_running {
                let _ = lima.stop_vm(&sid);
            }
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
        }).await;
    }

    // Remove from the stopping set now that teardown is complete.
    state.sessions_stopping.lock().await.remove(&session.id);

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
        Ok(None) => {
            return error_response(SandboxError::SessionNotFound(id)).into_response()
        }
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
        Ok(None) => {
            return error_response(SandboxError::SessionNotFound(id)).into_response()
        }
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
                error_response(SandboxError::Internal(format!(
                    "file upload failed: {msg}"
                )))
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
        Ok(None) => {
            return error_response(SandboxError::SessionNotFound(id)).into_response()
        }
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
// Git transport handler
// ---------------------------------------------------------------------------

/// `POST /sessions/{id}/git` -- relay a git protocol operation to the VM.
async fn git_in_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<GitRequest>,
) -> impl IntoResponse {
    let session = match state.store.get_session_by_name_or_id(&id) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return error_response(SandboxError::SessionNotFound(id)).into_response()
        }
        Err(e) => return error_response(e).into_response(),
    };

    if session.state != SessionState::Running {
        return error_response(SandboxError::InvalidState(format!(
            "cannot run git operation in session with state {} (must be running)",
            session.state
        )))
        .into_response();
    }

    let guest_request = match req.operation.as_str() {
        "upload-pack" => GuestRequest::GitUploadPack {
            repo_path: req.repo_path,
            data: req.data,
        },
        "receive-pack" => GuestRequest::GitReceivePack {
            repo_path: req.repo_path,
            data: req.data,
        },
        other => {
            return error_response(SandboxError::InvalidState(format!(
                "unsupported git operation: {other} (must be 'upload-pack' or 'receive-pack')"
            )))
            .into_response();
        }
    };

    match state.guest.send_request(&session.id, guest_request).await {
        Ok(GuestResponse::GitResult {
            data,
            exit_code,
            stderr,
        }) => {
            let response = GitResponse {
                data,
                exit_code,
                stderr,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Ok(GuestResponse::Error { message }) => {
            error!(session_id = %session.id, %message, "guest agent git error");
            error_response(SandboxError::Internal(format!(
                "guest agent error: {message}"
            )))
            .into_response()
        }
        Ok(other) => {
            error!(session_id = %session.id, ?other, "unexpected guest response to git");
            error_response(SandboxError::Internal(
                "unexpected response from guest agent".into(),
            ))
            .into_response()
        }
        Err(e) => {
            error!(session_id = %session.id, error = %e, "guest agent git failed");
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
        Ok(None) => {
            return error_response(SandboxError::SessionNotFound(id)).into_response()
        }
        Err(e) => return error_response(e).into_response(),
    };

    if session.state != SessionState::Running {
        return error_response(SandboxError::InvalidState(format!(
            "cannot update policy for session in {} state (must be running)",
            session.state
        )))
        .into_response();
    }

    match apply_policy(&session.id, &req.policy, &state).await {
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

/// Apply a policy to a running session: compile, distribute, and start DNS loop.
async fn apply_policy(
    session_id: &uuid::Uuid,
    policy: &Policy,
    state: &AppState,
) -> Result<(), SandboxError> {
    // Look up network info for this session.
    let network_info = state
        .store
        .get_network_info(session_id)?
        .ok_or_else(|| {
            SandboxError::Internal(format!(
                "no network info for session {session_id} (networking not configured)"
            ))
        })?;

    // Compile the policy.
    let compiled = PolicyCompiler::compile(policy, &network_info)?;

    // Distribute to gateway components.
    PolicyDistributor::distribute(session_id, &compiled, &state.gateway)?;

    // Store the policy for the DNS propagation loop.
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
async fn start_dns_propagation_loop(session_id: &uuid::Uuid, state: &AppState) {
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
async fn cancel_dns_propagation_loop(session_id: &uuid::Uuid, state: &AppState) {
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
    session_id: uuid::Uuid,
    gateway: Arc<GatewayManager>,
    network_info: sandbox_core::NetworkInfo,
    session_policies: Arc<Mutex<HashMap<uuid::Uuid, Policy>>>,
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
        let report = match tokio::task::spawn_blocking(move || {
            read_resolved_json(&sid)
        }).await {
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
        let propagate_result = tokio::task::spawn_blocking(move || {
            propagate_dns_changes(&sid, &pol, &c, &gw, &ni)
        }).await;
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
    session_id: &uuid::Uuid,
    ca_dir: &std::path::Path,
) -> Result<(), SandboxError> {
    let cert_pem = std::fs::read_to_string(ca_dir.join("cert.pem")).map_err(|e| {
        SandboxError::Ca(format!("failed to read CA cert for injection: {e}"))
    })?;
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
    session_id: &uuid::Uuid,
    network_info: &sandbox_core::NetworkInfo,
    ca_dir: &std::path::Path,
    state: &AppState,
    initial_dns_policy: Option<&str>,
) -> Result<(), SandboxError> {
    // 1. Create gateway container with nftables, mounting the CA.
    //    Pass the initial DNS policy so it is written to the container
    //    before CoreDNS starts, avoiding a reload-timer race.
    state
        .gateway
        .create_gateway(session_id, network_info, Some(ca_dir), initial_dns_policy)?;

    // 2. Configure the bridge NIC inside the VM (already present from boot).
    if let Err(e) =
        attach_vm_to_bridge(session_id, network_info, &state.guest).await
    {
        // Roll back gateway on attach failure.
        let _ = state.gateway.stop_gateway(session_id);
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
fn teardown_session_networking(session_id: &uuid::Uuid, state: &AppState) {
    debug!(session_id = %session_id, "tearing down session networking (preserving allocation)");
    // detach_vm_from_bridge is a no-op (TAP owned by QEMU), but call it
    // for completeness / future-proofing.
    if let Err(e) = detach_vm_from_bridge(session_id) {
        warn!(%session_id, error = %e, "failed to detach VM from bridge (best-effort)");
    }
    if let Err(e) = state.gateway.stop_gateway(session_id) {
        warn!(%session_id, error = %e, "failed to stop gateway (best-effort)");
    }
    if let Err(e) = state.network.remove_docker_network(session_id) {
        warn!(%session_id, error = %e, "failed to remove Docker network (best-effort)");
    }
}

/// Re-apply the session's policy to a freshly created gateway container.
///
/// When a gateway is recreated (restart, crash recovery, reconciliation),
/// its tmpfs is wiped. This helper restores the policy that was active
/// before the gateway went away. If no policy is stored (session created
/// without one), it writes the allow-all wildcard so CoreDNS permits all
/// DNS queries.
///
/// Policy re-application is best-effort: failures are logged but do not
/// propagate, matching the non-fatal semantics of initial policy setup.
async fn reapply_session_policy(session_id: &uuid::Uuid, state: &AppState) {
    let container = gateway_container_name(session_id);

    // Check the in-memory policy store.
    let policy = {
        let policies = state.session_policies.lock().await;
        policies.get(session_id).cloned()
    };

    if let Some(policy) = policy {
        match apply_policy(session_id, &policy, state).await {
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
        // No policy stored — write allow-all wildcard so CoreDNS permits
        // all DNS resolution (same as the else branch in create_session).
        let allow_all = "# Default allow-all policy (no policy specified)\n*\n";
        match write_file_to_container(&container, "/etc/coredns/policy.conf", allow_all) {
            Ok(()) => {
                debug!(
                    session_id = %session_id,
                    "wrote default allow-all DNS policy to restored gateway"
                );
            }
            Err(e) => {
                warn!(
                    session_id = %session_id,
                    error = %e,
                    "failed to write default DNS policy to restored gateway"
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
    session_id: &uuid::Uuid,
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
    //    When no explicit policy is stored for this session, pass an
    //    allow-all DNS policy so CoreDNS loads it at startup (same race
    //    fix as in create_session).
    let has_stored_policy = {
        let policies = state.session_policies.lock().await;
        policies.contains_key(session_id)
    };
    let initial_dns_policy = if !has_stored_policy {
        Some("# Default allow-all policy (no policy specified)\n*\n")
    } else {
        None
    };
    if let Err(e) =
        state
            .gateway
            .create_gateway(session_id, &network_info, Some(&ca_dir), initial_dns_policy)
    {
        // Roll back the Docker network on gateway failure.
        let _ = state.network.remove_docker_network(session_id);
        return Err(e);
    }

    // 2b. Re-apply the session's policy to the fresh gateway container.
    // If a policy is stored, compile and distribute it to the running
    // gateway.  If no policy is stored, the allow-all was already written
    // during gateway creation above, so reapply only writes if needed.
    reapply_session_policy(session_id, state).await;

    // 3. Configure the bridge NIC inside the VM (already present from boot).
    if let Err(e) =
        attach_vm_to_bridge(session_id, &network_info, &state.guest).await
    {
        // Roll back gateway and Docker network on attach failure.
        let _ = state.gateway.stop_gateway(session_id);
        let _ = state.network.remove_docker_network(session_id);
        return Err(e);
    }

    // 4. Inject CA certificate into VM trust store.
    inject_ca_into_vm(&state.guest, session_id, &ca_dir).await
}

/// Format a `GatewayStatus` into a human-readable string for the API response.
fn format_gateway_status(gateway: &GatewayManager, session_id: &uuid::Uuid) -> String {
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
        Ok(None) => {
            return error_response(SandboxError::SessionNotFound(id)).into_response()
        }
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
    let (container_status, envoy, mitmproxy, coredns) =
        if session.state == SessionState::Running {
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
                let _ = store.update_state(&session.id, SessionState::Error);
                fixed_count += 1;
            }
            // VM missing, session already stopped or errored -> OK
            (None, SessionState::Stopped | SessionState::Error) => {
                ok_count += 1;
            }
            // VM exists
            (Some(vm_info), _) => {
                match (&session.state, &vm_info.status) {
                    (SessionState::Running, VmStatus::Running) => ok_count += 1,
                    (SessionState::Stopped, VmStatus::Stopped) => ok_count += 1,
                    (SessionState::Running, VmStatus::Stopped) => {
                        info!(
                            session_id = %session.id,
                            "reconciliation: VM stopped but session says Running, updating to Stopped"
                        );
                        let _ = store.update_state(&session.id, SessionState::Stopped);
                        fixed_count += 1;
                    }
                    (SessionState::Stopped, VmStatus::Running) => {
                        info!(
                            session_id = %session.id,
                            "reconciliation: VM running but session says Stopped, updating to Running"
                        );
                        let _ = store.update_state(&session.id, SessionState::Running);
                        fixed_count += 1;
                    }
                    _ => {
                        ok_count += 1;
                    }
                }
            }
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
                let status_result = tokio::task::spawn_blocking(move || {
                    gw.gateway_status(&sid)
                }).await;
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

                        let network_info =
                            match state.store.get_network_info(&session.id) {
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
                        let ensure_result = tokio::task::spawn_blocking(move || {
                            net.ensure_network(&sid)
                        }).await;
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
                        let has_policy = {
                            let policies = state.session_policies.lock().await;
                            policies.contains_key(&session.id)
                        };
                        let init_dns_str = "# Default allow-all policy (no policy specified)\n*\n";
                        let init_dns = if !has_policy {
                            Some(init_dns_str)
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
                        }).await;
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
                let status_result = tokio::task::spawn_blocking(move || {
                    gw.gateway_status(&sid)
                }).await;
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
                        let _ = tokio::task::spawn_blocking(move || {
                            gw.stop_gateway(&sid)
                        }).await;
                        cleaned += 1;
                    }
                    Ok(Err(_)) | Err(_) => {
                        // Container doesn't exist or join error, that's fine.
                    }
                }

                // Best-effort TAP cleanup (no-op: TAP is owned by QEMU).
                let sid = session.id;
                let _ = tokio::task::spawn_blocking(move || {
                    detach_vm_from_bridge(&sid)
                }).await;
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

            let gw = Arc::clone(&state.gateway);
            let sid = session.id;
            let status_result = tokio::task::spawn_blocking(move || {
                gw.gateway_status(&sid)
            }).await;
            let status = match status_result {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    warn!(
                        session_id = %session.id,
                        error = %e,
                        "gateway monitor: failed to check gateway status"
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
            };

            match status {
                GatewayStatus::Healthy => {
                    // All good, nothing to do.
                }
                GatewayStatus::NotRunning | GatewayStatus::Unhealthy(_) => {
                    warn!(
                        session_id = %session.id,
                        gateway_status = ?status,
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
                    let ensure_result = tokio::task::spawn_blocking(move || {
                        net.ensure_network(&sid)
                    }).await;
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
                    let has_policy = {
                        let policies = state.session_policies.lock().await;
                        policies.contains_key(&session.id)
                    };
                    let init_dns_str = "# Default allow-all policy (no policy specified)\n*\n";
                    let init_dns = if !has_policy {
                        Some(init_dns_str)
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
                    }).await;
                    match restart_result {
                        Ok(Ok(())) => {
                            info!(
                                session_id = %session.id,
                                "gateway monitor: gateway recovered successfully"
                            );
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

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
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
    let store = SessionStore::new(base_dir.clone())?;
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

    // Run startup reconciliation (VM state).
    reconcile(&store, &lima);

    let state = Arc::new(AppState {
        base_dir,
        store,
        lima,
        guest,
        network,
        gateway,
        dns_loop_handles: Mutex::new(HashMap::new()),
        session_policies: Arc::new(Mutex::new(HashMap::new())),
        sessions_stopping: Mutex::new(HashSet::new()),
    });

    // Run networking reconciliation: restart crashed gateways, clean up
    // lingering resources for stopped sessions.
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

    // Clean up the socket file on exit.
    let _ = tokio::fs::remove_file(&socket_path).await;
    info!("sandboxd shut down");

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm =
        signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint =
        signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

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
    fn error_response_http_returns_500() {
        let (status, body) = error_body(SandboxError::Http("connection refused".into()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            body.error.contains("connection refused"),
            "expected body to contain http error message, got: {}",
            body.error
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
        let (_, Json(body)) =
            error_response(SandboxError::Network("test message".into()));
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
        assert_eq!(body.error, "oops", "Network body should be the raw inner message");

        let (_, body) = error_body(SandboxError::Ca("oops".into()));
        assert_eq!(body.error, "oops", "Ca body should be the raw inner message");

        let (_, body) = error_body(SandboxError::Gateway("oops".into()));
        assert_eq!(body.error, "oops", "Gateway body should be the raw inner message");

        let (_, body) = error_body(SandboxError::Lima("oops".into()));
        assert_eq!(body.error, "oops", "Lima body should be the raw inner message");
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

        let (_, body) = error_body(SandboxError::Http("timeout".into()));
        assert_eq!(body.error, "HTTP error: timeout");
    }

    // -----------------------------------------------------------------------
    // default_socket_path / default_base_dir
    // -----------------------------------------------------------------------

    #[test]
    fn default_socket_path_ends_with_sock() {
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
}
