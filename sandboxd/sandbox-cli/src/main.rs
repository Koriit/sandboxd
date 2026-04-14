use std::path::Path;
use std::process;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use sandbox_core::{ApiError, ExecResponse, Policy, Session, SessionHealth, SessionResponse};
use tokio::net::UnixStream;

/// CLI client for managing sandbox sessions.
#[derive(Parser, Debug)]
#[command(name = "sandbox", about = "Manage sandbox sessions")]
struct Cli {
    /// Path to the sandboxd Unix socket.
    #[arg(long, global = true, default_value_t = default_socket_path())]
    socket: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Create a new sandbox session.
    Create {
        /// Optional name for the session.
        #[arg(long)]
        name: Option<String>,
        /// Number of CPU cores (default: 2).
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        /// Memory in megabytes (default: 4096).
        #[arg(long, default_value_t = 4096)]
        memory: u32,
        /// Disk size in gigabytes (default: 20).
        #[arg(long, default_value_t = 20)]
        disk: u32,
        /// Path to a custom Lima template.
        #[arg(long)]
        template: Option<String>,
        /// Path to a policy JSON file to apply after creation.
        #[arg(long)]
        policy: Option<String>,
        /// Git repository URL to clone into /root/workspace/ after session setup.
        ///
        /// Mutually exclusive with --workspace.
        #[arg(long, conflicts_with = "workspace")]
        repo: Option<String>,
        /// Command to execute after clone (or after setup if no repo).
        #[arg(long)]
        boot_cmd: Option<String>,
        /// Workspace mode: `shared:<host-path>` mounts a host directory into
        /// the VM at /home/agent/workspace via 9p.
        ///
        /// Mutually exclusive with --repo.
        #[arg(long, conflicts_with = "repo")]
        workspace: Option<String>,
        /// Disable QEMU hardening (device lockdown, seccomp).
        ///
        /// By default, hardening is enabled. Use this flag for debugging
        /// or when the hardened configuration causes compatibility issues.
        #[arg(long)]
        no_hardening: bool,
    },
    /// Start a sandbox session.
    Start {
        /// Session name or ID.
        session: String,
    },
    /// Stop a sandbox session.
    Stop {
        /// Session name or ID.
        session: String,
    },
    /// Remove a sandbox session.
    Rm {
        /// Session name or ID.
        session: String,
    },
    /// List sandbox sessions.
    Ps,
    /// List sandbox sessions (alias for ps).
    Ls,
    /// Copy files between host and sandbox VM.
    ///
    /// Use session:path syntax to specify the remote side:
    ///   sandbox cp local/file session:remote/path   (upload)
    ///   sandbox cp session:remote/path local/file    (download)
    Cp {
        /// Source path (prefix with session: for VM paths).
        src: String,
        /// Destination path (prefix with session: for VM paths).
        dst: String,
    },
    /// Open an interactive SSH session (or run a command) in a sandbox.
    Ssh {
        /// Session name or ID.
        session: String,
        /// Optional command to run (non-interactive). Use after --.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Execute a command inside a sandbox via the guest agent.
    Exec {
        /// Session name or ID.
        session: String,
        /// Command and arguments to run. Use after --.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Stream gateway container logs.
    Logs {
        /// Session name or ID.
        session: String,
        /// Component to filter: envoy, mitmproxy, coredns, or all.
        #[arg(long, default_value = "all")]
        component: LogComponent,
        /// Stream logs continuously (like docker logs -f).
        #[arg(long, short)]
        follow: bool,
        /// Show last N lines (default: 100).
        #[arg(long, default_value_t = 100)]
        tail: u32,
    },
    /// Update the network policy for a running sandbox session.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Show detailed health status of a sandbox session.
    Health {
        /// Session name or ID.
        session: String,
    },
    /// Act as a git remote helper for the ext:: transport.
    ///
    /// This command is designed to be invoked by git's ext:: remote transport.
    /// It relays the git protocol stream between the local git client and a
    /// repository inside a sandbox VM.
    ///
    /// Example:
    ///   git remote add sandbox "ext::sandbox --socket /tmp/s.sock git-remote %S my-session"
    #[command(name = "git-remote")]
    GitRemote {
        /// Git service name (e.g., git-upload-pack or git-receive-pack),
        /// passed by git as %S.
        service: String,
        /// Session name or ID.
        session: String,
        /// Path to the git repository inside the VM (default: /root/workspace).
        #[arg(long, default_value = "/root/workspace")]
        repo_path: String,
    },
}

/// Policy subcommands.
#[derive(Subcommand, Debug, Clone)]
enum PolicyAction {
    /// Apply a policy from a JSON file to a session.
    Update {
        /// Session name or ID.
        session: String,
        /// Path to the policy JSON file.
        policy_path: String,
    },
}

/// Log component filter for the `logs` subcommand.
#[derive(Debug, Clone, ValueEnum)]
enum LogComponent {
    All,
    Envoy,
    Mitmproxy,
    Coredns,
}

fn default_socket_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    format!("{home}/.sandboxd/sandboxd.sock")
}

/// Build the HTTP request for the given CLI command.
///
/// Returns `None` for commands that are handled specially (e.g. `ssh`).
fn build_request(command: &Command) -> Option<Request<String>> {
    let req = match command {
        Command::Create {
            name,
            cpus,
            memory,
            disk,
            template,
            policy,
            repo,
            boot_cmd,
            workspace,
            no_hardening,
        } => {
            let mut body = serde_json::Map::new();
            if let Some(n) = name {
                body.insert("name".into(), serde_json::Value::String(n.clone()));
            }
            body.insert("cpus".into(), serde_json::json!(*cpus));
            body.insert("memory_mb".into(), serde_json::json!(*memory));
            body.insert("disk_gb".into(), serde_json::json!(*disk));
            if let Some(t) = template {
                body.insert("template".into(), serde_json::Value::String(t.clone()));
            }
            if let Some(policy_path) = policy {
                let policy_json = match std::fs::read_to_string(policy_path) {
                    Ok(content) => content,
                    Err(e) => {
                        eprintln!("Error: cannot read policy file '{policy_path}': {e}");
                        process::exit(1);
                    }
                };
                let policy_value: serde_json::Value = match serde_json::from_str(&policy_json) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Error: invalid policy JSON in '{policy_path}': {e}");
                        process::exit(1);
                    }
                };
                body.insert("policy".into(), policy_value);
            }
            if let Some(r) = repo {
                body.insert("repo".into(), serde_json::Value::String(r.clone()));
            }
            if let Some(cmd) = boot_cmd {
                body.insert("boot_cmd".into(), serde_json::Value::String(cmd.clone()));
            }
            if let Some(ws) = workspace {
                // Validate the workspace value client-side before sending.
                let path_part = ws.strip_prefix("shared:").unwrap_or("");
                if !ws.starts_with("shared:") {
                    eprintln!("Error: --workspace must start with 'shared:', got: {ws}");
                    process::exit(1);
                }
                if path_part.is_empty() {
                    eprintln!("Error: --workspace shared: path must not be empty");
                    process::exit(1);
                }
                let p = Path::new(path_part);
                if !p.is_absolute() {
                    eprintln!("Error: --workspace path must be absolute, got: {path_part}");
                    process::exit(1);
                }
                if !p.exists() {
                    eprintln!("Error: --workspace path does not exist: {path_part}");
                    process::exit(1);
                }
                body.insert("workspace".into(), serde_json::Value::String(ws.clone()));
            }
            if *no_hardening {
                body.insert("hardened".into(), serde_json::json!(false));
            }
            let body_str = serde_json::Value::Object(body).to_string();
            Request::builder()
                .method("POST")
                .uri("/sessions")
                .header("content-type", "application/json")
                .body(body_str)
                .expect("failed to build request")
        }
        Command::Start { session } => Request::builder()
            .method("POST")
            .uri(format!("/sessions/{session}/start"))
            .body(String::new())
            .expect("failed to build request"),
        Command::Stop { session } => Request::builder()
            .method("POST")
            .uri(format!("/sessions/{session}/stop"))
            .body(String::new())
            .expect("failed to build request"),
        Command::Rm { session } => Request::builder()
            .method("DELETE")
            .uri(format!("/sessions/{session}"))
            .body(String::new())
            .expect("failed to build request"),
        Command::Ps | Command::Ls => Request::builder()
            .method("GET")
            .uri("/sessions")
            .body(String::new())
            .expect("failed to build request"),
        Command::Exec { session, command } => {
            if command.is_empty() {
                eprintln!("Error: exec requires a command. Usage: sandbox exec <session> -- <command> [args...]");
                process::exit(1);
            }
            let cmd = &command[0];
            let args: Vec<String> = command[1..].to_vec();
            let body = serde_json::json!({
                "command": cmd,
                "args": args,
            });
            Request::builder()
                .method("POST")
                .uri(format!("/sessions/{session}/exec"))
                .header("content-type", "application/json")
                .body(body.to_string())
                .expect("failed to build request")
        }
        Command::Policy { action } => match action {
            PolicyAction::Update {
                session,
                policy_path,
            } => {
                let policy_json = match std::fs::read_to_string(policy_path) {
                    Ok(content) => content,
                    Err(e) => {
                        eprintln!("Error: cannot read policy file '{policy_path}': {e}");
                        process::exit(1);
                    }
                };
                // Validate that it parses as a Policy before sending.
                if let Err(e) = serde_json::from_str::<Policy>(&policy_json) {
                    eprintln!("Error: invalid policy JSON in '{policy_path}': {e}");
                    process::exit(1);
                }
                Request::builder()
                    .method("POST")
                    .uri(format!("/sessions/{session}/policy"))
                    .header("content-type", "application/json")
                    .body(policy_json)
                    .expect("failed to build request")
            }
        },
        Command::Health { session } => Request::builder()
            .method("GET")
            .uri(format!("/sessions/{session}/health"))
            .body(String::new())
            .expect("failed to build request"),
        // Ssh, Logs, Cp, and GitRemote are handled specially -- not via a single HTTP request.
        Command::Ssh { .. } | Command::Logs { .. } | Command::Cp { .. } | Command::GitRemote { .. } => return None,
    };
    Some(req)
}

/// Format a timestamp as a relative time string (e.g., "2m ago", "3h ago").
fn format_relative_time(dt: &DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(dt);

    let seconds = duration.num_seconds();
    if seconds < 0 {
        return "just now".to_string();
    }

    if seconds < 60 {
        return format!("{seconds}s ago");
    }

    let minutes = duration.num_minutes();
    if minutes < 60 {
        return format!("{minutes}m ago");
    }

    let hours = duration.num_hours();
    if hours < 24 {
        return format!("{hours}h ago");
    }

    let days = duration.num_days();
    if days < 30 {
        return format!("{days}d ago");
    }

    // Fall back to date.
    dt.format("%Y-%m-%d").to_string()
}

/// Display a list of sessions as a formatted table.
fn display_sessions_table(sessions: &[SessionResponse]) {
    if sessions.is_empty() {
        println!("No sessions found.");
        return;
    }

    // Header.
    println!(
        "{:<36}  {:<16}  {:<10}  {:<11}  {:<11}  CREATED",
        "ID", "NAME", "STATE", "AGENT", "GATEWAY"
    );

    for session in sessions {
        let name = session.name.as_deref().unwrap_or("-");
        let state = session.state.to_string();
        let agent = session
            .guest_agent_status
            .as_deref()
            .unwrap_or("-");
        let gateway = session
            .gateway_status
            .as_deref()
            .unwrap_or("-");
        let created = format_relative_time(&session.created_at);

        println!(
            "{:<36}  {:<16}  {:<10}  {:<11}  {:<11}  {created}",
            session.id, name, state, agent, gateway
        );
    }
}

/// Display a single session in detail.
fn display_session(session: &Session) {
    let name = session.name.as_deref().unwrap_or("-");
    println!("ID:       {}", session.id);
    println!("Name:     {name}");
    println!("State:    {}", session.state);
    println!("CPUs:     {}", session.config.cpus);
    println!("Memory:   {} MB", session.config.memory_mb);
    println!("Disk:     {} GB", session.config.disk_gb);
    println!("Created:  {} ({})", session.created_at.format("%Y-%m-%d %H:%M:%S UTC"), format_relative_time(&session.created_at));
    println!("Updated:  {} ({})", session.updated_at.format("%Y-%m-%d %H:%M:%S UTC"), format_relative_time(&session.updated_at));
}

async fn send_request(
    socket_path: &str,
    req: Request<String>,
) -> Result<(hyper::StatusCode, String), String> {
    let stream = UnixStream::connect(socket_path).await.map_err(|e| {
        format!(
            "Cannot connect to sandboxd at {socket_path} \u{2014} is the daemon running? ({e})"
        )
    })?;

    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("HTTP handshake failed: {e}"))?;

    // Spawn the connection driver.
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("connection error: {e}");
        }
    });

    let response = sender
        .send_request(req)
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = response.status();
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("failed to read response body: {e}"))?
        .to_bytes();

    let body = String::from_utf8_lossy(&body_bytes).to_string();

    Ok((status, body))
}

/// Handle the response based on the command and status code.
fn handle_response(command: &Command, status: hyper::StatusCode, body: &str) -> Result<(), String> {
    if !status.is_success() {
        // Try to parse as ApiError for a clean message.
        if let Ok(api_err) = serde_json::from_str::<ApiError>(body) {
            eprintln!("Error: {}", api_err.error);
        } else {
            eprintln!("Error ({status}): {body}");
        }
        return Err(format!("server returned {status}"));
    }

    match command {
        Command::Ps | Command::Ls => {
            let sessions: Vec<SessionResponse> = serde_json::from_str(body)
                .map_err(|e| format!("failed to parse response: {e}"))?;
            display_sessions_table(&sessions);
        }
        Command::Rm { .. } => {
            // 204 No Content -- nothing to print.
            println!("Session removed.");
        }
        Command::Create { .. } => {
            let session: Session = serde_json::from_str(body)
                .map_err(|e| format!("failed to parse response: {e}"))?;
            println!("Session created:");
            display_session(&session);
        }
        Command::Start { .. } => {
            let session: Session = serde_json::from_str(body)
                .map_err(|e| format!("failed to parse response: {e}"))?;
            println!("Session started:");
            display_session(&session);
        }
        Command::Stop { .. } => {
            let session: Session = serde_json::from_str(body)
                .map_err(|e| format!("failed to parse response: {e}"))?;
            println!("Session stopped:");
            display_session(&session);
        }
        Command::Exec { .. } => {
            let result: ExecResponse = serde_json::from_str(body)
                .map_err(|e| format!("failed to parse exec response: {e}"))?;
            if !result.stdout.is_empty() {
                print!("{}", result.stdout);
            }
            if !result.stderr.is_empty() {
                eprint!("{}", result.stderr);
            }
            if result.exit_code != 0 {
                process::exit(result.exit_code);
            }
        }
        Command::Policy { .. } => {
            let result: serde_json::Value = serde_json::from_str(body)
                .map_err(|e| format!("failed to parse policy response: {e}"))?;
            if let Some(message) = result.get("message").and_then(|m| m.as_str()) {
                println!("{message}");
            } else {
                println!("Policy updated.");
            }
        }
        Command::Health { .. } => {
            let health: SessionHealth = serde_json::from_str(body)
                .map_err(|e| format!("failed to parse health response: {e}"))?;
            println!("Session:   {}", health.session_id);
            println!("VM:        {}", health.vm_status);
            println!("Agent:     {}", health.guest_agent);
            println!("Gateway:");
            println!("  Container: {}", health.gateway.container_status);
            println!("  Envoy:     {}", health.gateway.envoy);
            println!("  mitmproxy: {}", health.gateway.mitmproxy);
            println!("  CoreDNS:   {}", health.gateway.coredns);
            println!("Network:");
            println!("  Bridge:  {}", if health.network.bridge_exists { "exists" } else { "missing" });
            println!("  TAP:     {}", if health.network.tap_exists { "exists" } else { "missing" });
        }
        Command::Ssh { .. } | Command::Logs { .. } | Command::Cp { .. } | Command::GitRemote { .. } => {
            // Ssh, Logs, Cp, and GitRemote are handled separately, should not reach here.
            unreachable!("ssh/logs/cp/git-remote commands should be handled before send_request");
        }
    }

    Ok(())
}

/// Handle the `ssh` subcommand: resolve session via daemon API, then exec
/// `limactl shell`.
async fn handle_ssh(socket_path: &str, session: &str, command: &[String]) {
    // Resolve the session name/id to a Session via the daemon API.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/sessions/{session}"))
        .body(String::new())
        .expect("failed to build request");

    let (status, body) = match send_request(socket_path, req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    if !status.is_success() {
        if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
            eprintln!("Error: {}", api_err.error);
        } else {
            eprintln!("Error ({status}): {body}");
        }
        process::exit(1);
    }

    let session_resp: SessionResponse = match serde_json::from_str(&body) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to parse session response: {e}");
            process::exit(1);
        }
    };

    let vm_name = format!("sandbox-{}", session_resp.id);

    // Build the limactl shell command.
    let mut cmd = std::process::Command::new("limactl");
    cmd.arg("shell").arg(&vm_name);

    if !command.is_empty() {
        cmd.arg("--");
        for arg in command {
            cmd.arg(arg);
        }
    }

    // Use .status() to inherit stdin/stdout/stderr for interactive use.
    match cmd.status() {
        Ok(exit_status) => {
            process::exit(exit_status.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("Failed to execute limactl shell: {e}");
            process::exit(1);
        }
    }
}

/// Handle the `logs` subcommand: resolve session via daemon API, then exec
/// `docker logs` for the gateway container.
async fn handle_logs(
    socket_path: &str,
    session: &str,
    component: &LogComponent,
    follow: bool,
    tail: u32,
) {
    // Resolve the session name/id to a Session via the daemon API.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/sessions/{session}"))
        .body(String::new())
        .expect("failed to build request");

    let (status, body) = match send_request(socket_path, req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    if !status.is_success() {
        if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
            eprintln!("Error: {}", api_err.error);
        } else {
            eprintln!("Error ({status}): {body}");
        }
        process::exit(1);
    }

    let session_resp: SessionResponse = match serde_json::from_str(&body) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to parse session response: {e}");
            process::exit(1);
        }
    };

    let container_name = format!("sandbox-gw-{}", session_resp.id);

    let mut cmd = std::process::Command::new("docker");

    match component {
        LogComponent::All => {
            // Use docker logs for the entrypoint's stdout/stderr output.
            cmd.arg("logs");
            cmd.arg("--tail").arg(tail.to_string());
            if follow {
                cmd.arg("-f");
            }
            cmd.arg(&container_name);
        }
        _ => {
            // Components log to individual files inside the container.
            let log_file = match component {
                LogComponent::Envoy => "/var/log/gateway/envoy.log",
                LogComponent::Mitmproxy => "/var/log/gateway/mitmproxy.log",
                LogComponent::Coredns => "/var/log/gateway/coredns.log",
                LogComponent::All => unreachable!(),
            };
            cmd.arg("exec").arg(&container_name);
            cmd.arg("tail");
            cmd.arg("-n").arg(tail.to_string());
            if follow {
                cmd.arg("-f");
            }
            cmd.arg(log_file);
        }
    }

    // Inherit stdin/stdout/stderr so output streams to the terminal.
    match cmd.status() {
        Ok(exit_status) => {
            process::exit(exit_status.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("Failed to execute docker: {e}");
            process::exit(1);
        }
    }
}

/// Maximum raw file size for a single-chunk transfer.
///
/// Base64 expands data by ~33%, so 700 KB raw stays well within the 1 MB
/// framed message limit after encoding + JSON overhead.
const CP_CHUNK_SIZE: usize = 700 * 1024;

/// Parse a `session:path` spec, returning `(session, path)` if the spec
/// contains a colon, or `None` if it's a local path.
fn parse_remote_spec(spec: &str) -> Option<(&str, &str)> {
    // Split on the first colon only.
    spec.split_once(':')
}

/// Handle the `cp` subcommand: copy files between host and sandbox VM.
async fn handle_cp(socket_path: &str, src: &str, dst: &str) {
    // Determine transfer direction.
    let src_remote = parse_remote_spec(src);
    let dst_remote = parse_remote_spec(dst);

    match (src_remote, dst_remote) {
        (None, Some((session, remote_path))) => {
            // Upload: local -> VM
            handle_cp_upload(socket_path, src, session, remote_path).await;
        }
        (Some((session, remote_path)), None) => {
            // Download: VM -> local
            handle_cp_download(socket_path, session, remote_path, dst).await;
        }
        (Some(_), Some(_)) => {
            eprintln!("Error: both source and destination cannot be remote");
            process::exit(1);
        }
        (None, None) => {
            eprintln!(
                "Error: one of source or destination must be a remote path (session:path)\n\
                 Usage:\n  \
                 sandbox cp local/file session:remote/path   (upload)\n  \
                 sandbox cp session:remote/path local/file   (download)"
            );
            process::exit(1);
        }
    }
}

/// Upload a local file to a sandbox VM.
async fn handle_cp_upload(
    socket_path: &str,
    local_path: &str,
    session: &str,
    remote_path: &str,
) {
    // Read the local file.
    let data = match std::fs::read(local_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: cannot read local file '{local_path}': {e}");
            process::exit(1);
        }
    };

    if data.len() <= CP_CHUNK_SIZE {
        // Single-chunk upload.
        let encoded = BASE64.encode(&data);
        let body = serde_json::json!({
            "path": remote_path,
            "data": encoded,
        });
        let req = Request::builder()
            .method("POST")
            .uri(format!("/sessions/{session}/upload"))
            .header("content-type", "application/json")
            .body(body.to_string())
            .expect("failed to build request");

        let (status, resp_body) = match send_request(socket_path, req).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e}");
                process::exit(1);
            }
        };

        if !status.is_success() {
            if let Ok(api_err) = serde_json::from_str::<ApiError>(&resp_body) {
                eprintln!("Error: {}", api_err.error);
            } else {
                eprintln!("Error ({status}): {resp_body}");
            }
            process::exit(1);
        }
    } else {
        // Chunked upload: split into chunks, upload each to a temp file,
        // then concatenate on the VM side.
        let chunk_count = data.len().div_ceil(CP_CHUNK_SIZE);
        let mut chunk_paths: Vec<String> = Vec::with_capacity(chunk_count);

        for (i, chunk) in data.chunks(CP_CHUNK_SIZE).enumerate() {
            let chunk_remote = format!("{remote_path}.chunk.{i}");
            let encoded = BASE64.encode(chunk);
            let body = serde_json::json!({
                "path": chunk_remote,
                "data": encoded,
            });
            let req = Request::builder()
                .method("POST")
                .uri(format!("/sessions/{session}/upload"))
                .header("content-type", "application/json")
                .body(body.to_string())
                .expect("failed to build request");

            let (status, resp_body) = match send_request(socket_path, req).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{e}");
                    process::exit(1);
                }
            };

            if !status.is_success() {
                if let Ok(api_err) = serde_json::from_str::<ApiError>(&resp_body) {
                    eprintln!("Error uploading chunk {i}: {}", api_err.error);
                } else {
                    eprintln!("Error uploading chunk {i} ({status}): {resp_body}");
                }
                process::exit(1);
            }

            chunk_paths.push(chunk_remote);
        }

        // Concatenate chunks on the VM side via exec.
        let cat_args: Vec<String> = chunk_paths.iter().map(|p| p.to_string()).collect();
        let cat_cmd = format!(
            "cat {} > {} && rm -f {}",
            cat_args.join(" "),
            remote_path,
            cat_args.join(" "),
        );
        let exec_body = serde_json::json!({
            "command": "bash",
            "args": ["-c", cat_cmd],
        });
        let req = Request::builder()
            .method("POST")
            .uri(format!("/sessions/{session}/exec"))
            .header("content-type", "application/json")
            .body(exec_body.to_string())
            .expect("failed to build request");

        let (status, resp_body) = match send_request(socket_path, req).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e}");
                process::exit(1);
            }
        };

        if !status.is_success() {
            if let Ok(api_err) = serde_json::from_str::<ApiError>(&resp_body) {
                eprintln!("Error concatenating chunks: {}", api_err.error);
            } else {
                eprintln!("Error concatenating chunks ({status}): {resp_body}");
            }
            process::exit(1);
        }

        // Check the exec result.
        if let Ok(exec_resp) = serde_json::from_str::<ExecResponse>(&resp_body) {
            if exec_resp.exit_code != 0 {
                eprintln!(
                    "Error: chunk concatenation failed (exit {}): {}",
                    exec_resp.exit_code, exec_resp.stderr
                );
                process::exit(1);
            }
        }
    }
}

/// Download a file from a sandbox VM to the local filesystem.
async fn handle_cp_download(
    socket_path: &str,
    session: &str,
    remote_path: &str,
    local_path: &str,
) {
    let body = serde_json::json!({
        "path": remote_path,
    });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/sessions/{session}/download"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .expect("failed to build request");

    let (status, resp_body) = match send_request(socket_path, req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    if !status.is_success() {
        if let Ok(api_err) = serde_json::from_str::<ApiError>(&resp_body) {
            eprintln!("Error: {}", api_err.error);
        } else {
            eprintln!("Error ({status}): {resp_body}");
        }
        process::exit(1);
    }

    // Parse the response.
    let download_resp: serde_json::Value = match serde_json::from_str(&resp_body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: failed to parse download response: {e}");
            process::exit(1);
        }
    };

    let data_b64 = match download_resp.get("data").and_then(|d| d.as_str()) {
        Some(d) => d,
        None => {
            // Check if there's an error field.
            if let Some(err) = download_resp.get("error").and_then(|e| e.as_str()) {
                eprintln!("Error: {err}");
            } else {
                eprintln!("Error: no data in download response");
            }
            process::exit(1);
        }
    };

    let decoded = match BASE64.decode(data_b64) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: failed to decode base64 data: {e}");
            process::exit(1);
        }
    };

    if let Err(e) = std::fs::write(local_path, &decoded) {
        eprintln!("Error: failed to write local file '{local_path}': {e}");
        process::exit(1);
    }
}

/// Handle the `git-remote` subcommand: relay git protocol between stdin/stdout
/// and the sandbox VM via the daemon's git endpoint.
///
/// This function is designed to be called by git's `ext::` remote transport.
/// Git invokes it as a subprocess, sends git protocol data on stdin, and
/// expects git protocol response data on stdout.
async fn handle_git_remote(
    socket_path: &str,
    service: &str,
    session: &str,
    repo_path: &str,
) {
    use std::io::Read;

    // Map the git service name to our operation.
    let operation = match service {
        "git-upload-pack" => "upload-pack",
        "git-receive-pack" => "receive-pack",
        other => {
            eprintln!("Error: unsupported git service: {other}");
            eprintln!("Supported: git-upload-pack, git-receive-pack");
            process::exit(1);
        }
    };

    // Read all of stdin (the git protocol data from the local git client).
    let mut stdin_data = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut stdin_data) {
        eprintln!("Error: failed to read git data from stdin: {e}");
        process::exit(1);
    }

    // Base64-encode the input data.
    let encoded_input = BASE64.encode(&stdin_data);

    // Build and send the request to the daemon.
    let body = serde_json::json!({
        "operation": operation,
        "repo_path": repo_path,
        "data": encoded_input,
    });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/sessions/{session}/git"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .expect("failed to build request");

    let (status, resp_body) = match send_request(socket_path, req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            process::exit(128);
        }
    };

    if !status.is_success() {
        if let Ok(api_err) = serde_json::from_str::<ApiError>(&resp_body) {
            eprintln!("Error: {}", api_err.error);
        } else {
            eprintln!("Error ({status}): {resp_body}");
        }
        process::exit(128);
    }

    // Parse the response.
    let git_resp: serde_json::Value = match serde_json::from_str(&resp_body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: failed to parse git response: {e}");
            process::exit(128);
        }
    };

    // Decode the base64 output data and write to stdout.
    if let Some(data_b64) = git_resp.get("data").and_then(|d| d.as_str()) {
        let decoded = match BASE64.decode(data_b64) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: failed to decode git response data: {e}");
                process::exit(128);
            }
        };

        use std::io::Write;
        if let Err(e) = std::io::stdout().write_all(&decoded) {
            eprintln!("Error: failed to write git data to stdout: {e}");
            process::exit(128);
        }
        if let Err(e) = std::io::stdout().flush() {
            eprintln!("Error: failed to flush stdout: {e}");
            process::exit(128);
        }
    }

    // Print stderr from the git subprocess (if any) to our stderr.
    if let Some(stderr) = git_resp.get("stderr").and_then(|s| s.as_str()) {
        if !stderr.is_empty() {
            eprint!("{stderr}");
        }
    }

    // Exit with the git subprocess exit code.
    let exit_code = git_resp
        .get("exit_code")
        .and_then(|c| c.as_i64())
        .unwrap_or(0) as i32;

    if exit_code != 0 {
        process::exit(exit_code);
    }
}

/// Check whether this binary was invoked as `git-remote-sandbox` (i.e. as a
/// git remote helper).  Returns `true` if argv[0] ends with
/// `git-remote-sandbox`, in which case the caller should enter remote-helper
/// mode instead of normal CLI parsing.
fn invoked_as_remote_helper() -> bool {
    std::env::args_os()
        .next()
        .map(|arg0| {
            let p = Path::new(&arg0);
            p.file_name()
                .map(|name| name == "git-remote-sandbox")
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Parse a `sandbox::` URL into (session, repo_path).
///
/// URL format: `sandbox::<session>/<repo-path>`
/// The part after `sandbox::` is passed as the second argument to the
/// remote helper. It has the form `<session>/<repo-path>` where repo-path
/// can contain slashes.
///
/// Returns `(session, repo_path)`.
fn parse_remote_helper_url(url: &str) -> Result<(String, String), String> {
    // The URL git passes to us is the part after "sandbox::" — but git may
    // also pass the full URL including the scheme prefix in some cases.
    let payload = url.strip_prefix("sandbox::").unwrap_or(url);

    // Split on the first slash to get session and repo-path.
    if let Some(idx) = payload.find('/') {
        let session = &payload[..idx];
        let repo_path = &payload[idx..]; // keeps the leading slash
        if session.is_empty() {
            return Err(format!("empty session name in URL: {url}"));
        }
        if repo_path.is_empty() || repo_path == "/" {
            return Err(format!("empty repo path in URL: {url}"));
        }
        Ok((session.to_string(), repo_path.to_string()))
    } else {
        // No slash — treat the whole thing as session, use default repo path.
        if payload.is_empty() {
            return Err(format!("empty URL: {url}"));
        }
        Ok((payload.to_string(), "/root/workspace".to_string()))
    }
}

/// Run as a git remote helper.
///
/// Git invokes: `git-remote-sandbox <remote-name> <url>`
///
/// Protocol (on stdin/stdout):
/// - Git sends `capabilities\n` → we respond `connect\n\n`
/// - Git sends `connect <service>\n` → we respond `\n` then proxy
///   stdin/stdout to the daemon's git endpoint for that service.
fn run_remote_helper() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: git-remote-sandbox <remote-name> <url>");
        eprintln!("This is a git remote helper, invoked by git automatically.");
        process::exit(1);
    }

    let url = &args[2];

    let (session, repo_path) = match parse_remote_helper_url(url) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    // Determine socket path: SANDBOX_SOCKET env var, or default.
    let socket_path = std::env::var("SANDBOX_SOCKET").unwrap_or_else(|_| default_socket_path());

    // Read commands from stdin line by line.
    // We track a pending `connect` service so we can break out of the loop
    // (dropping the StdinLock) before spawning the SSH subprocess.
    use std::io::{BufRead, Write};
    let mut connect_service: Option<String> = None;

    {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();

        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Error reading from stdin: {e}");
                    process::exit(1);
                }
            };

            let line = line.trim().to_string();

            if line.is_empty() {
                // Blank line — ignore (protocol allows trailing blank lines).
                continue;
            }

            if line == "capabilities" {
                // Respond with our capabilities: we support the `connect` protocol.
                if let Err(e) = writeln!(stdout, "connect") {
                    eprintln!("Error writing capabilities: {e}");
                    process::exit(1);
                }
                // Blank line terminates the capability listing.
                if let Err(e) = writeln!(stdout) {
                    eprintln!("Error writing capabilities terminator: {e}");
                    process::exit(1);
                }
                if let Err(e) = stdout.flush() {
                    eprintln!("Error flushing stdout: {e}");
                    process::exit(1);
                }
            } else if let Some(service) = line.strip_prefix("connect ") {
                // Respond with a blank line to indicate we're ready.
                if let Err(e) = writeln!(stdout) {
                    eprintln!("Error writing connect ack: {e}");
                    process::exit(1);
                }
                if let Err(e) = stdout.flush() {
                    eprintln!("Error flushing stdout: {e}");
                    process::exit(1);
                }

                // Record the service and break out of the loop so the StdinLock
                // is dropped before we spawn the child process.
                connect_service = Some(service.to_string());
                break;
            } else {
                eprintln!("Error: unsupported remote helper command: {line}");
                process::exit(1);
            }
        }
    } // StdinLock is dropped here.

    if let Some(service) = connect_service {
        // Spawn `sandbox ssh <session> -- <service> <repo_path>` with inherited
        // stdin/stdout/stderr so git gets a true bidirectional pipe to the
        // remote git process inside the VM via SSH.
        let sandbox_bin = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error: failed to determine sandbox binary path: {e}");
                process::exit(1);
            }
        };

        // Use sudo because the guest agent (which creates repos) runs as root,
        // but limactl shell connects as the default (non-root) Lima user.
        let status = std::process::Command::new(&sandbox_bin)
            .args([
                "--socket",
                &socket_path,
                "ssh",
                &session,
                "--",
                "sudo",
                &service,
                &repo_path,
            ])
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status();

        match status {
            Ok(exit_status) => {
                process::exit(exit_status.code().unwrap_or(1));
            }
            Err(e) => {
                eprintln!("Error: failed to execute sandbox ssh: {e}");
                process::exit(128);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    // Check if we were invoked as git-remote-sandbox (git remote helper mode).
    if invoked_as_remote_helper() {
        run_remote_helper();
        return;
    }

    let cli = Cli::parse();

    // Handle ssh specially — it doesn't follow the normal request/response flow.
    if let Command::Ssh { session, command } = &cli.command {
        handle_ssh(&cli.socket, session, command).await;
        return;
    }

    // Handle cp specially — it uses upload/download endpoints.
    if let Command::Cp { src, dst } = &cli.command {
        handle_cp(&cli.socket, src, dst).await;
        return;
    }

    // Handle logs specially — it streams output and doesn't use the normal
    // request/response flow.
    if let Command::Logs {
        session,
        component,
        follow,
        tail,
    } = &cli.command
    {
        handle_logs(&cli.socket, session, component, *follow, *tail).await;
        return;
    }

    // Handle git-remote specially — it relays git protocol via stdin/stdout.
    if let Command::GitRemote {
        service,
        session,
        repo_path,
    } = &cli.command
    {
        handle_git_remote(&cli.socket, service, session, repo_path).await;
        return;
    }

    let req = match build_request(&cli.command) {
        Some(r) => r,
        None => {
            // Should not happen — ssh and logs are handled above.
            eprintln!("Internal error: unhandled command");
            process::exit(1);
        }
    };

    match send_request(&cli.socket, req).await {
        Ok((status, body)) => {
            if let Err(e) = handle_response(&cli.command, status, &body) {
                eprintln!("{e}");
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_create_no_name() {
        let cli = Cli::parse_from(["sandbox", "create"]);
        assert!(matches!(
            cli.command,
            Command::Create {
                name: None,
                cpus: 2,
                memory: 4096,
                disk: 20,
                template: None,
                policy: None,
                repo: None,
                boot_cmd: None,
                workspace: None,
                no_hardening: false,
            }
        ));
    }

    #[test]
    fn parse_create_with_name() {
        let cli = Cli::parse_from(["sandbox", "create", "--name", "mybox"]);
        match &cli.command {
            Command::Create { name, .. } => assert_eq!(name.as_deref(), Some("mybox")),
            _ => panic!("expected Create command"),
        }
    }

    #[test]
    fn parse_create_with_all_options() {
        let cli = Cli::parse_from([
            "sandbox", "create", "--name", "full", "--cpus", "4", "--memory", "8192", "--disk",
            "50", "--template", "/tmp/custom.yaml",
        ]);
        match &cli.command {
            Command::Create {
                name,
                cpus,
                memory,
                disk,
                template,
                ..
            } => {
                assert_eq!(name.as_deref(), Some("full"));
                assert_eq!(*cpus, 4);
                assert_eq!(*memory, 8192);
                assert_eq!(*disk, 50);
                assert_eq!(template.as_deref(), Some("/tmp/custom.yaml"));
            }
            _ => panic!("expected Create command"),
        }
    }

    #[test]
    fn parse_start() {
        let cli = Cli::parse_from(["sandbox", "start", "my-session"]);
        match &cli.command {
            Command::Start { session } => assert_eq!(session, "my-session"),
            _ => panic!("expected Start command"),
        }
    }

    #[test]
    fn parse_stop() {
        let cli = Cli::parse_from(["sandbox", "stop", "my-session"]);
        match &cli.command {
            Command::Stop { session } => assert_eq!(session, "my-session"),
            _ => panic!("expected Stop command"),
        }
    }

    #[test]
    fn parse_rm() {
        let cli = Cli::parse_from(["sandbox", "rm", "my-session"]);
        match &cli.command {
            Command::Rm { session } => assert_eq!(session, "my-session"),
            _ => panic!("expected Rm command"),
        }
    }

    #[test]
    fn parse_ps() {
        let cli = Cli::parse_from(["sandbox", "ps"]);
        assert!(matches!(cli.command, Command::Ps));
    }

    #[test]
    fn parse_ls() {
        let cli = Cli::parse_from(["sandbox", "ls"]);
        assert!(matches!(cli.command, Command::Ls));
    }

    #[test]
    fn parse_ssh_interactive() {
        let cli = Cli::parse_from(["sandbox", "ssh", "my-session"]);
        match &cli.command {
            Command::Ssh { session, command } => {
                assert_eq!(session, "my-session");
                assert!(command.is_empty());
            }
            _ => panic!("expected Ssh command"),
        }
    }

    #[test]
    fn parse_ssh_with_command() {
        let cli = Cli::parse_from(["sandbox", "ssh", "my-session", "--", "uname", "-a"]);
        match &cli.command {
            Command::Ssh { session, command } => {
                assert_eq!(session, "my-session");
                assert_eq!(command, &["uname", "-a"]);
            }
            _ => panic!("expected Ssh command"),
        }
    }

    #[test]
    fn parse_exec() {
        let cli = Cli::parse_from(["sandbox", "exec", "my-session", "--", "ls", "-la"]);
        match &cli.command {
            Command::Exec { session, command } => {
                assert_eq!(session, "my-session");
                assert_eq!(command, &["ls", "-la"]);
            }
            _ => panic!("expected Exec command"),
        }
    }

    #[test]
    fn default_socket_path_set() {
        let cli = Cli::parse_from(["sandbox", "ps"]);
        assert!(cli.socket.ends_with("sandboxd.sock"));
    }

    #[test]
    fn custom_socket_path() {
        let cli = Cli::parse_from(["sandbox", "--socket", "/tmp/custom.sock", "ps"]);
        assert_eq!(cli.socket, "/tmp/custom.sock");
    }

    #[test]
    fn build_create_request_with_name() {
        let cmd = Command::Create {
            name: Some("test".into()),
            cpus: 2,
            memory: 4096,
            disk: 20,
            template: None,
            policy: None,
            repo: None,
            boot_cmd: None,
            workspace: None,
            no_hardening: false,
        };
        let req = build_request(&cmd).expect("should produce request");
        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri(), "/sessions");
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert_eq!(body["name"], "test");
        assert_eq!(body["cpus"], 2);
        assert_eq!(body["memory_mb"], 4096);
        assert_eq!(body["disk_gb"], 20);
    }

    #[test]
    fn build_create_request_no_name() {
        let cmd = Command::Create {
            name: None,
            cpus: 4,
            memory: 8192,
            disk: 50,
            template: None,
            policy: None,
            repo: None,
            boot_cmd: None,
            workspace: None,
            no_hardening: false,
        };
        let req = build_request(&cmd).expect("should produce request");
        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri(), "/sessions");
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert!(body.get("name").is_none());
        assert_eq!(body["cpus"], 4);
        assert_eq!(body["memory_mb"], 8192);
        assert_eq!(body["disk_gb"], 50);
    }

    #[test]
    fn build_create_request_with_template() {
        let cmd = Command::Create {
            name: Some("custom".into()),
            cpus: 2,
            memory: 4096,
            disk: 20,
            template: Some("/tmp/my-template.yaml".into()),
            policy: None,
            repo: None,
            boot_cmd: None,
            workspace: None,
            no_hardening: false,
        };
        let req = build_request(&cmd).expect("should produce request");
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert_eq!(body["template"], "/tmp/my-template.yaml");
    }

    #[test]
    fn build_start_request() {
        let cmd = Command::Start {
            session: "abc".into(),
        };
        let req = build_request(&cmd).expect("should produce request");
        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri(), "/sessions/abc/start");
    }

    #[test]
    fn build_stop_request() {
        let cmd = Command::Stop {
            session: "abc".into(),
        };
        let req = build_request(&cmd).expect("should produce request");
        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri(), "/sessions/abc/stop");
    }

    #[test]
    fn build_rm_request() {
        let cmd = Command::Rm {
            session: "abc".into(),
        };
        let req = build_request(&cmd).expect("should produce request");
        assert_eq!(req.method(), "DELETE");
        assert_eq!(req.uri(), "/sessions/abc");
    }

    #[test]
    fn build_ps_request() {
        let cmd = Command::Ps;
        let req = build_request(&cmd).expect("should produce request");
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), "/sessions");
    }

    #[test]
    fn build_ls_request() {
        let cmd = Command::Ls;
        let req = build_request(&cmd).expect("should produce request");
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), "/sessions");
    }

    #[test]
    fn build_exec_request() {
        let cmd = Command::Exec {
            session: "my-box".into(),
            command: vec!["uname".into(), "-a".into()],
        };
        let req = build_request(&cmd).expect("should produce request");
        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri(), "/sessions/my-box/exec");
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert_eq!(body["command"], "uname");
        assert_eq!(body["args"], serde_json::json!(["-a"]));
    }

    #[test]
    fn build_ssh_returns_none() {
        let cmd = Command::Ssh {
            session: "abc".into(),
            command: vec![],
        };
        assert!(build_request(&cmd).is_none());
    }

    #[test]
    fn test_format_relative_time_seconds() {
        let now = Utc::now();
        let dt = now - chrono::Duration::seconds(30);
        let result = format_relative_time(&dt);
        assert!(result.contains("s ago"), "expected seconds ago, got: {result}");
    }

    #[test]
    fn test_format_relative_time_minutes() {
        let now = Utc::now();
        let dt = now - chrono::Duration::minutes(5);
        let result = format_relative_time(&dt);
        assert_eq!(result, "5m ago");
    }

    #[test]
    fn test_format_relative_time_hours() {
        let now = Utc::now();
        let dt = now - chrono::Duration::hours(3);
        let result = format_relative_time(&dt);
        assert_eq!(result, "3h ago");
    }

    #[test]
    fn test_format_relative_time_days() {
        let now = Utc::now();
        let dt = now - chrono::Duration::days(7);
        let result = format_relative_time(&dt);
        assert_eq!(result, "7d ago");
    }

    #[test]
    fn parse_logs_defaults() {
        let cli = Cli::parse_from(["sandbox", "logs", "my-session"]);
        match &cli.command {
            Command::Logs {
                session,
                component,
                follow,
                tail,
            } => {
                assert_eq!(session, "my-session");
                assert!(matches!(component, LogComponent::All));
                assert!(!follow);
                assert_eq!(*tail, 100);
            }
            _ => panic!("expected Logs command"),
        }
    }

    #[test]
    fn parse_logs_with_component() {
        let cli = Cli::parse_from([
            "sandbox",
            "logs",
            "my-session",
            "--component",
            "envoy",
        ]);
        match &cli.command {
            Command::Logs {
                session, component, ..
            } => {
                assert_eq!(session, "my-session");
                assert!(matches!(component, LogComponent::Envoy));
            }
            _ => panic!("expected Logs command"),
        }
    }

    #[test]
    fn parse_logs_with_follow_and_tail() {
        let cli = Cli::parse_from([
            "sandbox",
            "logs",
            "my-session",
            "--follow",
            "--tail",
            "50",
        ]);
        match &cli.command {
            Command::Logs {
                follow, tail, ..
            } => {
                assert!(*follow);
                assert_eq!(*tail, 50);
            }
            _ => panic!("expected Logs command"),
        }
    }

    #[test]
    fn parse_logs_component_mitmproxy() {
        let cli = Cli::parse_from([
            "sandbox",
            "logs",
            "my-session",
            "--component",
            "mitmproxy",
        ]);
        match &cli.command {
            Command::Logs { component, .. } => {
                assert!(matches!(component, LogComponent::Mitmproxy));
            }
            _ => panic!("expected Logs command"),
        }
    }

    #[test]
    fn parse_logs_component_coredns() {
        let cli = Cli::parse_from([
            "sandbox",
            "logs",
            "my-session",
            "--component",
            "coredns",
        ]);
        match &cli.command {
            Command::Logs { component, .. } => {
                assert!(matches!(component, LogComponent::Coredns));
            }
            _ => panic!("expected Logs command"),
        }
    }

    #[test]
    fn parse_health() {
        let cli = Cli::parse_from(["sandbox", "health", "my-session"]);
        match &cli.command {
            Command::Health { session } => {
                assert_eq!(session, "my-session");
            }
            _ => panic!("expected Health command"),
        }
    }

    #[test]
    fn build_health_request() {
        let cmd = Command::Health {
            session: "abc".into(),
        };
        let req = build_request(&cmd).expect("should produce request");
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), "/sessions/abc/health");
    }

    #[test]
    fn build_logs_returns_none() {
        let cmd = Command::Logs {
            session: "abc".into(),
            component: LogComponent::All,
            follow: false,
            tail: 100,
        };
        assert!(build_request(&cmd).is_none());
    }

    #[test]
    fn parse_policy_update() {
        let cli = Cli::parse_from([
            "sandbox",
            "policy",
            "update",
            "my-session",
            "/tmp/policy.json",
        ]);
        match &cli.command {
            Command::Policy {
                action: PolicyAction::Update {
                    session,
                    policy_path,
                },
            } => {
                assert_eq!(session, "my-session");
                assert_eq!(policy_path, "/tmp/policy.json");
            }
            _ => panic!("expected Policy Update command"),
        }
    }

    #[test]
    fn parse_create_with_policy_flag() {
        let cli = Cli::parse_from([
            "sandbox",
            "create",
            "--name",
            "test",
            "--policy",
            "/tmp/policy.json",
        ]);
        match &cli.command {
            Command::Create { name, policy, .. } => {
                assert_eq!(name.as_deref(), Some("test"));
                assert_eq!(policy.as_deref(), Some("/tmp/policy.json"));
            }
            _ => panic!("expected Create command"),
        }
    }

    #[test]
    fn parse_create_without_policy_flag() {
        let cli = Cli::parse_from(["sandbox", "create"]);
        match &cli.command {
            Command::Create { policy, .. } => {
                assert!(policy.is_none());
            }
            _ => panic!("expected Create command"),
        }
    }

    #[test]
    fn parse_create_with_repo() {
        let cli = Cli::parse_from([
            "sandbox",
            "create",
            "--repo",
            "https://github.com/octocat/Hello-World.git",
        ]);
        match &cli.command {
            Command::Create { repo, boot_cmd, .. } => {
                assert_eq!(
                    repo.as_deref(),
                    Some("https://github.com/octocat/Hello-World.git")
                );
                assert!(boot_cmd.is_none());
            }
            _ => panic!("expected Create command"),
        }
    }

    #[test]
    fn parse_create_with_boot_cmd() {
        let cli = Cli::parse_from([
            "sandbox",
            "create",
            "--boot-cmd",
            "npm install",
        ]);
        match &cli.command {
            Command::Create { repo, boot_cmd, .. } => {
                assert!(repo.is_none());
                assert_eq!(boot_cmd.as_deref(), Some("npm install"));
            }
            _ => panic!("expected Create command"),
        }
    }

    #[test]
    fn parse_create_with_repo_and_boot_cmd() {
        let cli = Cli::parse_from([
            "sandbox",
            "create",
            "--repo",
            "https://github.com/example/repo.git",
            "--boot-cmd",
            "make build",
        ]);
        match &cli.command {
            Command::Create { repo, boot_cmd, .. } => {
                assert_eq!(
                    repo.as_deref(),
                    Some("https://github.com/example/repo.git")
                );
                assert_eq!(boot_cmd.as_deref(), Some("make build"));
            }
            _ => panic!("expected Create command"),
        }
    }

    #[test]
    fn build_create_request_with_repo() {
        let cmd = Command::Create {
            name: Some("with-repo".into()),
            cpus: 2,
            memory: 4096,
            disk: 20,
            template: None,
            policy: None,
            repo: Some("https://github.com/octocat/Hello-World.git".into()),
            boot_cmd: None,
            workspace: None,
            no_hardening: false,
        };
        let req = build_request(&cmd).expect("should produce request");
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert_eq!(body["repo"], "https://github.com/octocat/Hello-World.git");
        assert!(body.get("boot_cmd").is_none());
    }

    #[test]
    fn build_create_request_with_boot_cmd() {
        let cmd = Command::Create {
            name: Some("with-boot".into()),
            cpus: 2,
            memory: 4096,
            disk: 20,
            template: None,
            policy: None,
            repo: None,
            boot_cmd: Some("npm install".into()),
            workspace: None,
            no_hardening: false,
        };
        let req = build_request(&cmd).expect("should produce request");
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert!(body.get("repo").is_none());
        assert_eq!(body["boot_cmd"], "npm install");
    }

    #[test]
    fn parse_create_with_no_hardening_flag() {
        let cli = Cli::parse_from(["sandbox", "create", "--no-hardening"]);
        match &cli.command {
            Command::Create { no_hardening, .. } => {
                assert!(
                    *no_hardening,
                    "--no-hardening flag should set no_hardening to true"
                );
            }
            _ => panic!("expected Create command"),
        }
    }

    #[test]
    fn parse_create_default_hardening_on() {
        let cli = Cli::parse_from(["sandbox", "create"]);
        match &cli.command {
            Command::Create { no_hardening, .. } => {
                assert!(
                    !*no_hardening,
                    "hardening should be on by default (no_hardening = false)"
                );
            }
            _ => panic!("expected Create command"),
        }
    }

    #[test]
    fn build_create_request_with_no_hardening() {
        let cmd = Command::Create {
            name: Some("debug".into()),
            cpus: 2,
            memory: 4096,
            disk: 20,
            template: None,
            policy: None,
            repo: None,
            boot_cmd: None,
            workspace: None,
            no_hardening: true,
        };
        let req = build_request(&cmd).expect("should produce request");
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert_eq!(
            body["hardened"], false,
            "--no-hardening should set hardened=false in request body"
        );
    }

    #[test]
    fn build_create_request_default_omits_hardened() {
        let cmd = Command::Create {
            name: Some("normal".into()),
            cpus: 2,
            memory: 4096,
            disk: 20,
            template: None,
            policy: None,
            repo: None,
            boot_cmd: None,
            workspace: None,
            no_hardening: false,
        };
        let req = build_request(&cmd).expect("should produce request");
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert!(
            body.get("hardened").is_none(),
            "default (hardened=true) should omit the field from request body"
        );
    }

    #[test]
    fn parse_cp_upload() {
        let cli = Cli::parse_from([
            "sandbox",
            "cp",
            "local/file.txt",
            "my-session:/root/file.txt",
        ]);
        match &cli.command {
            Command::Cp { src, dst } => {
                assert_eq!(src, "local/file.txt");
                assert_eq!(dst, "my-session:/root/file.txt");
            }
            _ => panic!("expected Cp command"),
        }
    }

    #[test]
    fn parse_cp_download() {
        let cli = Cli::parse_from([
            "sandbox",
            "cp",
            "my-session:/root/file.txt",
            "local/file.txt",
        ]);
        match &cli.command {
            Command::Cp { src, dst } => {
                assert_eq!(src, "my-session:/root/file.txt");
                assert_eq!(dst, "local/file.txt");
            }
            _ => panic!("expected Cp command"),
        }
    }

    #[test]
    fn build_cp_returns_none() {
        let cmd = Command::Cp {
            src: "local.txt".into(),
            dst: "session:/remote.txt".into(),
        };
        assert!(build_request(&cmd).is_none());
    }

    #[test]
    fn parse_remote_spec_with_colon() {
        let result = parse_remote_spec("my-session:/root/file.txt");
        assert_eq!(result, Some(("my-session", "/root/file.txt")));
    }

    #[test]
    fn parse_remote_spec_no_colon() {
        let result = parse_remote_spec("local/file.txt");
        assert_eq!(result, None);
    }

    #[test]
    fn parse_remote_spec_multiple_colons() {
        // Only splits on first colon.
        let result = parse_remote_spec("session:/path/with:colon");
        assert_eq!(result, Some(("session", "/path/with:colon")));
    }

    #[test]
    fn parse_git_remote() {
        let cli = Cli::parse_from([
            "sandbox",
            "git-remote",
            "git-upload-pack",
            "my-session",
        ]);
        match &cli.command {
            Command::GitRemote {
                service,
                session,
                repo_path,
            } => {
                assert_eq!(service, "git-upload-pack");
                assert_eq!(session, "my-session");
                assert_eq!(repo_path, "/root/workspace");
            }
            _ => panic!("expected GitRemote command"),
        }
    }

    #[test]
    fn parse_git_remote_with_repo_path() {
        let cli = Cli::parse_from([
            "sandbox",
            "git-remote",
            "git-receive-pack",
            "my-session",
            "--repo-path",
            "/root/myrepo",
        ]);
        match &cli.command {
            Command::GitRemote {
                service,
                session,
                repo_path,
            } => {
                assert_eq!(service, "git-receive-pack");
                assert_eq!(session, "my-session");
                assert_eq!(repo_path, "/root/myrepo");
            }
            _ => panic!("expected GitRemote command"),
        }
    }

    #[test]
    fn build_git_remote_returns_none() {
        let cmd = Command::GitRemote {
            service: "git-upload-pack".into(),
            session: "abc".into(),
            repo_path: "/root/workspace".into(),
        };
        assert!(build_request(&cmd).is_none());
    }

    // -- Remote helper URL parsing tests ------------------------------------

    #[test]
    fn parse_remote_helper_url_session_and_path() {
        let (session, repo_path) =
            parse_remote_helper_url("my-session/root/workspace/repo.git").unwrap();
        assert_eq!(session, "my-session");
        assert_eq!(repo_path, "/root/workspace/repo.git");
    }

    #[test]
    fn parse_remote_helper_url_with_scheme_prefix() {
        // git may pass the full URL including the sandbox:: prefix.
        let (session, repo_path) =
            parse_remote_helper_url("sandbox::my-session/root/workspace/repo").unwrap();
        assert_eq!(session, "my-session");
        assert_eq!(repo_path, "/root/workspace/repo");
    }

    #[test]
    fn parse_remote_helper_url_session_only() {
        // No slash — defaults to /root/workspace.
        let (session, repo_path) = parse_remote_helper_url("my-session").unwrap();
        assert_eq!(session, "my-session");
        assert_eq!(repo_path, "/root/workspace");
    }

    #[test]
    fn parse_remote_helper_url_empty() {
        assert!(parse_remote_helper_url("").is_err());
    }

    #[test]
    fn parse_remote_helper_url_empty_session() {
        // Starts with slash — empty session name.
        assert!(parse_remote_helper_url("/root/workspace").is_err());
    }
}
