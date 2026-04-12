use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use clap::Parser;
use sandbox_core::{
    ApiError, CreateSessionRequest, ExecRequest, ExecResponse, GuestConnector, GuestResponse,
    LimaManager, SandboxError, Session, SessionConfig, SessionResponse, SessionState,
    SessionStore, VmStatus,
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
    store: SessionStore,
    lima: Arc<LimaManager>,
    guest: GuestConnector,
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Convert a `SandboxError` into an HTTP response with appropriate status code.
fn error_response(err: SandboxError) -> (StatusCode, Json<ApiError>) {
    let (status, msg) = match &err {
        SandboxError::SessionNotFound(_) => (StatusCode::NOT_FOUND, err.to_string()),
        SandboxError::InvalidState(_) => (StatusCode::BAD_REQUEST, err.to_string()),
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

    // Probe guest agent for running sessions (with a short timeout).
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
        enriched.push(SessionResponse::from_session_with_status(session, agent_status));
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

    // Probe guest agent for running sessions.
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

    let response = SessionResponse::from_session_with_status(session, agent_status);
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

    if let Err(e) = state.lima.start_vm(&session.id) {
        let _ = state.store.update_state(&session.id, SessionState::Error);
        return error_response(e).into_response();
    }

    if let Err(e) = state.store.update_state(&session.id, SessionState::Running) {
        return error_response(e).into_response();
    }

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
    let lima = Arc::new(LimaManager::new(base_dir));
    let guest = GuestConnector::new(Arc::clone(&lima));

    // Run startup reconciliation.
    reconcile(&store, &lima);

    let state = Arc::new(AppState { store, lima, guest });

    // Remove stale socket file if it exists.
    if socket_path.exists() {
        info!(?socket_path, "removing stale socket file");
        tokio::fs::remove_file(&socket_path).await?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    info!(socket = %socket_path.display(), "sandboxd listening");

    let app = app(state);

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
