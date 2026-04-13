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
    ApiError, CaManager, CreateSessionRequest, ExecRequest, ExecResponse, GatewayHealth,
    GatewayManager, GatewayStatus, GuestConnector, GuestResponse, LimaManager, NetworkHealth,
    NetworkManager, SandboxError, Session, SessionConfig, SessionHealth, SessionResponse,
    SessionState, SessionStore, VmStatus, attach_vm_to_bridge, detach_vm_from_bridge,
    generate_ca_inject_script,
};
use tokio::net::UnixListener;
use tracing::{error, info, warn};

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
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    format!("{home}/.sandboxd/sandboxd.sock")
}

fn default_base_dir() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    format!("{home}/.sandboxd")
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
        .route("/sessions/{id}/health", get(session_health))
        .route("/health", get(health_check))
        .with_state(state)
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    let config = SessionConfig {
        cpus: req.cpus.unwrap_or(2),
        memory_mb: req.memory_mb.unwrap_or(4096),
        disk_gb: req.disk_gb.unwrap_or(20),
    };

    // Create session record in store (state = Creating).
    let session = match state.store.create_session(config.clone(), req.name) {
        Ok(s) => s,
        Err(e) => return error_response(e).into_response(),
    };

    let session_id = session.id;
    info!(%session_id, "creating VM");

    // Create the Lima VM (with optional custom template).
    let create_result = if let Some(template_path) = &req.template {
        state
            .lima
            .create_vm_with_custom_template(&session_id, template_path.as_ref())
    } else {
        state.lima.create_vm(&session_id, &config)
    };

    if let Err(e) = create_result {
        let _ = state.store.update_state(&session_id, SessionState::Error);
        return error_response(e).into_response();
    }

    // Start the VM.
    if let Err(e) = state.lima.start_vm(&session_id) {
        let _ = state.store.update_state(&session_id, SessionState::Error);
        return error_response(e).into_response();
    }

    // Install the guest agent into the VM.
    let guest_binary_path = match std::env::current_exe() {
        Ok(exe) => exe
            .parent()
            .expect("executable must have a parent directory")
            .join("sandbox-guest"),
        Err(e) => {
            let _ = state.store.update_state(&session_id, SessionState::Error);
            return error_response(SandboxError::Internal(format!(
                "failed to determine daemon executable path: {e}"
            )))
            .into_response();
        }
    };

    if let Err(e) = state.lima.install_guest_agent(&session_id, &guest_binary_path) {
        error!(%session_id, error = %e, "failed to install guest agent");
        let _ = state.store.update_state(&session_id, SessionState::Error);
        return error_response(e).into_response();
    }

    // Verify the guest agent is responsive.
    match state.guest.ping(&session_id).await {
        Ok(true) => {
            info!(%session_id, "guest agent responded to ping");
        }
        Ok(false) => {
            let err = SandboxError::Internal(
                "guest agent returned unexpected response to ping".into(),
            );
            error!(%session_id, "guest agent ping: unexpected response");
            let _ = state.store.update_state(&session_id, SessionState::Error);
            return error_response(err).into_response();
        }
        Err(e) => {
            error!(%session_id, error = %e, "guest agent ping failed");
            let _ = state.store.update_state(&session_id, SessionState::Error);
            return error_response(e).into_response();
        }
    }

    // Update state to Running.
    if let Err(e) = state.store.update_state(&session_id, SessionState::Running) {
        return error_response(e).into_response();
    }

    // Set up networking: Docker bridge, gateway container, VM NIC attachment.
    match setup_session_networking(&session_id, &state).await {
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
    let vm_list = state.lima.list_vms().unwrap_or_default();

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
            Some(format_gateway_status(&state.gateway, &session.id))
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
    if let Ok(vm_status) = state.lima.vm_status(&session.id) {
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
        Some(format_gateway_status(&state.gateway, &session.id))
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

    // Start the Lima VM.
    if let Err(e) = state.lima.start_vm(&session.id) {
        let _ = state.store.update_state(&session.id, SessionState::Error);
        return error_response(e).into_response();
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

    // Recreate networking from existing network info (if available).
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

    // Tear down networking resources (TAP, gateway, Docker network) before
    // stopping the VM. The network_info is kept in the DB so `start` can
    // recreate everything. The subnet remains allocated in the
    // NetworkManager so it is not reused by another session.
    teardown_session_networking(&session.id, &state);

    if let Err(e) = state.lima.stop_vm(&session.id) {
        let _ = state.store.update_state(&session.id, SessionState::Error);
        return error_response(e).into_response();
    }

    if let Err(e) = state.store.update_state(&session.id, SessionState::Stopped) {
        return error_response(e).into_response();
    }

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

    // Stop VM if running (ignore errors -- it might already be stopped).
    if session.state == SessionState::Running {
        let _ = state.lima.stop_vm(&session.id);
    }

    // Delete the VM from Lima (ignore errors -- it might not exist).
    let _ = state.lima.delete_vm(&session.id);

    // Full teardown: networking + CA + release subnet allocation.
    teardown_session_networking_full(&session.id, &state);

    // Delete the session from the store.
    if let Err(e) = state.store.delete_session(&session.id) {
        return error_response(e).into_response();
    }

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
// Networking helpers
// ---------------------------------------------------------------------------

/// Set up full networking for a new session.
///
/// 1. Generate per-session CA certificate
/// 2. Create Docker bridge network
/// 3. Create gateway container with nftables (mounting the CA)
/// 4. Attach VM to bridge (TAP + QMP hot-add + guest config)
/// 5. Inject CA certificate into VM trust store
/// 6. Store network info in DB
async fn setup_session_networking(
    session_id: &uuid::Uuid,
    state: &AppState,
) -> Result<(), SandboxError> {
    // 1. Generate per-session CA certificate.
    let ca_dir = CaManager::generate_session_ca(&state.base_dir, session_id)?;

    // 2. Create Docker bridge network.
    let network_info = match state.network.create_network(session_id) {
        Ok(info) => info,
        Err(e) => {
            let _ = CaManager::remove_session_ca(&state.base_dir, session_id);
            return Err(e);
        }
    };

    // 3. Create gateway container with nftables, mounting the CA.
    if let Err(e) =
        state
            .gateway
            .create_gateway(session_id, &network_info, Some(&ca_dir))
    {
        // Roll back the Docker network and CA on gateway failure.
        let _ = state.network.delete_network(session_id);
        let _ = CaManager::remove_session_ca(&state.base_dir, session_id);
        return Err(e);
    }

    // 4. Attach VM to bridge (TAP + QMP hot-add + guest config).
    if let Err(e) =
        attach_vm_to_bridge(session_id, &network_info, &state.network, &state.guest).await
    {
        // Roll back gateway, Docker network, and CA on attach failure.
        let _ = state.gateway.stop_gateway(session_id);
        let _ = state.network.delete_network(session_id);
        let _ = CaManager::remove_session_ca(&state.base_dir, session_id);
        return Err(e);
    }

    // 5. Inject CA certificate into VM trust store via guest agent.
    let cert_pem = std::fs::read_to_string(ca_dir.join("cert.pem")).map_err(|e| {
        SandboxError::Ca(format!("failed to read CA cert for injection: {e}"))
    })?;
    let inject_script = generate_ca_inject_script(&cert_pem);

    info!(session_id = %session_id, "injecting CA certificate into VM");

    match state
        .guest
        .exec(session_id, "bash", &["-c", &inject_script])
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
        }
        Ok(GuestResponse::Error { message }) => {
            return Err(SandboxError::Ca(format!(
                "guest agent error during CA injection: {message}"
            )));
        }
        Ok(other) => {
            return Err(SandboxError::Ca(format!(
                "unexpected guest response during CA injection: {other:?}"
            )));
        }
        Err(e) => {
            return Err(SandboxError::Ca(format!(
                "failed to inject CA certificate into VM: {e}"
            )));
        }
    }

    // 6. Store network info in DB.
    state.store.set_network_info(session_id, &network_info)?;

    Ok(())
}

/// Tear down session networking infrastructure (best-effort, ignores errors).
///
/// Removes the TAP device, stops the gateway container, and removes the
/// Docker bridge network. The subnet allocation and network_info in the DB
/// are preserved so `start` can recreate everything.
///
/// The CA certificate files on disk are NOT removed — they are reused on
/// start.
fn teardown_session_networking(session_id: &uuid::Uuid, state: &AppState) {
    if let Err(e) = detach_vm_from_bridge(session_id, &state.network) {
        warn!(%session_id, error = %e, "failed to detach VM from bridge (best-effort)");
    }
    if let Err(e) = state.gateway.stop_gateway(session_id) {
        warn!(%session_id, error = %e, "failed to stop gateway (best-effort)");
    }
    if let Err(e) = state.network.remove_docker_network(session_id) {
        warn!(%session_id, error = %e, "failed to remove Docker network (best-effort)");
    }
}

/// Full teardown: remove all networking resources AND release the subnet
/// allocation. Used when deleting a session permanently.
fn teardown_session_networking_full(session_id: &uuid::Uuid, state: &AppState) {
    if let Err(e) = detach_vm_from_bridge(session_id, &state.network) {
        warn!(%session_id, error = %e, "failed to detach VM from bridge (best-effort)");
    }
    if let Err(e) = state.gateway.stop_gateway(session_id) {
        warn!(%session_id, error = %e, "failed to stop gateway (best-effort)");
    }
    if let Err(e) = state.network.delete_network(session_id) {
        warn!(%session_id, error = %e, "failed to delete network (best-effort)");
    }
    if let Err(e) = CaManager::remove_session_ca(&state.base_dir, session_id) {
        warn!(%session_id, error = %e, "failed to remove session CA (best-effort)");
    }
}

/// Restore session networking from existing network info in the DB.
///
/// This is called by the `start` handler and by startup reconciliation.
/// It recreates the Docker bridge, gateway container, TAP attachment, and
/// CA injection using the same IPs that were originally allocated.
async fn restore_session_networking(
    session_id: &uuid::Uuid,
    state: &AppState,
) -> Result<(), SandboxError> {
    // Check that network info exists in DB (otherwise there's nothing to restore).
    if state.store.get_network_info(session_id)?.is_none() {
        info!(
            session_id = %session_id,
            "no network info in DB, skipping networking restore"
        );
        return Ok(());
    }

    // 1. Ensure the Docker bridge network exists (recreate if needed).
    //    This uses the NetworkManager's in-memory map (restored from DB at startup).
    let network_info = state.network.ensure_network(session_id)?;

    // 2. Get or regenerate the CA certificate.
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

    // 3. Create gateway container with nftables, mounting the CA.
    if let Err(e) =
        state
            .gateway
            .create_gateway(session_id, &network_info, Some(&ca_dir))
    {
        // Roll back the Docker network on gateway failure.
        let _ = state.network.remove_docker_network(session_id);
        return Err(e);
    }

    // 4. Attach VM to bridge (TAP + QMP hot-add + guest config).
    if let Err(e) =
        attach_vm_to_bridge(session_id, &network_info, &state.network, &state.guest).await
    {
        // Roll back gateway and Docker network on attach failure.
        let _ = state.gateway.stop_gateway(session_id);
        let _ = state.network.remove_docker_network(session_id);
        return Err(e);
    }

    // 5. Inject CA certificate into VM trust store.
    let cert_pem = std::fs::read_to_string(ca_dir.join("cert.pem")).map_err(|e| {
        SandboxError::Ca(format!("failed to read CA cert for injection: {e}"))
    })?;
    let inject_script = generate_ca_inject_script(&cert_pem);

    info!(session_id = %session_id, "injecting CA certificate into VM");

    match state
        .guest
        .exec(session_id, "bash", &["-c", &inject_script])
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
        }
        Ok(GuestResponse::Error { message }) => {
            return Err(SandboxError::Ca(format!(
                "guest agent error during CA injection: {message}"
            )));
        }
        Ok(other) => {
            return Err(SandboxError::Ca(format!(
                "unexpected guest response during CA injection: {other:?}"
            )));
        }
        Err(e) => {
            return Err(SandboxError::Ca(format!(
                "failed to inject CA certificate into VM: {e}"
            )));
        }
    }

    Ok(())
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
    let vm_status = match state.lima.vm_status(&session.id) {
        Ok(VmStatus::Running) => "running".to_string(),
        Ok(VmStatus::Stopped) => "stopped".to_string(),
        Ok(VmStatus::Unknown(s)) => s,
        Err(e) => format!("error: {e}"),
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
            match state.gateway.gateway_status(&session.id) {
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

    // Network health: check if bridge and TAP exist.
    let network_info = state.store.get_network_info(&session.id).ok().flatten();
    let bridge_exists = network_info
        .as_ref()
        .map(|info| {
            std::process::Command::new("docker")
                .args(["network", "inspect", &info.docker_network_name])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let tap_exists = {
        let tap_name = sandbox_core::tap_name_for_session(&session.id);
        std::process::Command::new("ip")
            .args(["link", "show", &tap_name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };

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
        let gw_status = format_gateway_status(&state.gateway, &session.id);
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
fn reconcile_networking(state: &AppState) {
    let sessions = match state.store.list_sessions() {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "network reconciliation: failed to list sessions");
            return;
        }
    };

    let mut restored = 0u32;
    let mut cleaned = 0u32;

    for session in &sessions {
        match session.state {
            SessionState::Running => {
                // Check if gateway is running.
                match state.gateway.gateway_status(&session.id) {
                    Ok(GatewayStatus::Healthy) => {
                        // Gateway is healthy, nothing to do.
                    }
                    Ok(status) => {
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
                        if let Err(e) = state.network.ensure_network(&session.id) {
                            warn!(
                                session_id = %session.id,
                                error = %e,
                                "network reconciliation: failed to ensure Docker network"
                            );
                            continue;
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

                        // Restart the gateway.
                        if let Err(e) = state
                            .gateway
                            .restart_gateway(&session.id, &network_info, ca_ref)
                        {
                            warn!(
                                session_id = %session.id,
                                error = %e,
                                "network reconciliation: failed to restart gateway"
                            );
                        } else {
                            info!(
                                session_id = %session.id,
                                "network reconciliation: gateway restarted"
                            );
                            restored += 1;
                        }
                    }
                    Err(e) => {
                        warn!(
                            session_id = %session.id,
                            error = %e,
                            "network reconciliation: failed to check gateway status"
                        );
                    }
                }
            }
            SessionState::Stopped => {
                // Ensure lingering gateway and TAP are cleaned up.
                match state.gateway.gateway_status(&session.id) {
                    Ok(GatewayStatus::NotRunning) => {
                        // Already clean.
                    }
                    Ok(_) => {
                        info!(
                            session_id = %session.id,
                            "network reconciliation: cleaning up lingering gateway for stopped session"
                        );
                        let _ = state.gateway.stop_gateway(&session.id);
                        cleaned += 1;
                    }
                    Err(_) => {
                        // Container doesn't exist, that's fine.
                    }
                }

                // Best-effort TAP cleanup.
                let _ = detach_vm_from_bridge(&session.id, &state.network);
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

        for session in &sessions {
            if session.state != SessionState::Running {
                continue;
            }

            let status = match state.gateway.gateway_status(&session.id) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        session_id = %session.id,
                        error = %e,
                        "gateway monitor: failed to check gateway status"
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
                    if let Err(e) = state.network.ensure_network(&session.id) {
                        warn!(
                            session_id = %session.id,
                            error = %e,
                            "gateway monitor: failed to ensure Docker network"
                        );
                        continue;
                    }

                    // Get CA directory.
                    let ca_dir = CaManager::ca_dir(&state.base_dir, &session.id);
                    let ca_ref = if ca_dir.join("cert.pem").exists() {
                        Some(ca_dir.as_path())
                    } else {
                        None
                    };

                    // Restart the gateway.
                    match state
                        .gateway
                        .restart_gateway(&session.id, &network_info, ca_ref)
                    {
                        Ok(()) => {
                            info!(
                                session_id = %session.id,
                                "gateway monitor: gateway recovered successfully"
                            );
                        }
                        Err(e) => {
                            error!(
                                session_id = %session.id,
                                error = %e,
                                "gateway monitor: failed to recover gateway"
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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let base_dir = PathBuf::from(&args.base_dir);
    let socket_path = PathBuf::from(&args.socket);

    // Create the base directory if it doesn't exist.
    tokio::fs::create_dir_all(&base_dir).await?;

    // Create the socket directory if it doesn't exist.
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Initialize store and Lima manager.
    let store = SessionStore::new(base_dir.clone())?;
    let lima = Arc::new(LimaManager::new(base_dir.clone()));
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
    });

    // Run networking reconciliation: restart crashed gateways, clean up
    // lingering resources for stopped sessions.
    reconcile_networking(&state);

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
