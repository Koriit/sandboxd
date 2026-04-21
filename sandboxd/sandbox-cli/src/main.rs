use std::path::Path;
use std::process;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use sandbox_core::{
    ApiError, ExecResponse, Policy, PolicyDto, PolicyLevelDto, PolicyRuleDto, SessionDto,
    SessionHealth,
};
use tokio::net::UnixStream;

/// CLI client for managing sandbox sessions.
#[derive(Parser, Debug)]
#[command(name = "sandbox", about = "Manage sandbox sessions")]
struct Cli {
    /// Path to the sandboxd Unix socket.
    #[arg(long, global = true, default_value_t = default_socket_path())]
    socket: String,

    /// Assume yes to interactive prompts (use defaults without prompting).
    #[arg(long, short = 'y', global = true)]
    yes: bool,

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
        /// Git repository URL to clone into /home/agent/workspace/ after session setup.
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
        /// Disable QEMU hardening (device lockdown, cgroup limits).
        ///
        /// By default, hardening is enabled. Use this flag for debugging
        /// or when the hardened configuration causes compatibility issues.
        #[arg(long)]
        no_hardening: bool,
        /// Skip pre-baked image, use full create path.
        #[arg(long)]
        no_cache: bool,
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
    /// Dump one or more sessions as pretty-printed JSON.
    ///
    /// Emits a JSON array of `SessionDto` objects (one per argument) in
    /// input order. Intended for scripts and `jq` consumers. If any named
    /// session is missing, the CLI writes an error to stderr naming the
    /// first missing id, exits non-zero, and produces no stdout.
    Inspect {
        /// One or more session names or IDs to inspect.
        #[arg(required = true)]
        sessions: Vec<String>,
    },
    /// Render a human-readable description of one or more sessions.
    ///
    /// Prints session header, config, runtime, and policy sections per
    /// argument. Blocks are separated by a single blank line. If any
    /// named session is missing, the CLI writes an error to stderr naming
    /// the first missing id, exits non-zero, and produces no stdout.
    Describe {
        /// One or more session names or IDs to describe.
        #[arg(required = true)]
        sessions: Vec<String>,
    },
    /// Rebuild the pre-baked base VM image.
    RebuildImage,
}

/// Policy subcommands.
#[derive(Subcommand, Debug, Clone)]
enum PolicyAction {
    /// Update the policy for a session.
    ///
    /// Exactly one of `--policy` or `--clear` must be supplied.  `--clear` is
    /// idempotent (safe to call on a session that already has no policy).
    Update {
        /// Session name or ID.
        session: String,
        /// Path to the policy JSON file to apply.
        #[arg(long, conflicts_with = "clear")]
        policy: Option<String>,
        /// Remove any policy from the session and revert to the fail-closed
        /// default (empty CoreDNS allow-list, deny-all mitmproxy/Envoy).
        /// Idempotent.  Mutually exclusive with `--policy`.
        #[arg(long, conflicts_with = "policy")]
        clear: bool,
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
    // Honor SANDBOX_SOCKET as an override (symmetric with the daemon). The
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
            no_cache,
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
            if *no_cache {
                body.insert("no_cache".into(), serde_json::json!(true));
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
                eprintln!(
                    "Error: exec requires a command. Usage: sandbox exec <session> -- <command> [args...]"
                );
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
                policy,
                clear,
            } => {
                // Exactly one of the two must be present.  clap's
                // `conflicts_with` catches the "both" case, but "none" has to
                // be validated here.
                let selected = [policy.is_some(), *clear].iter().filter(|x| **x).count();
                if selected != 1 {
                    eprintln!(
                        "Error: `sandbox policy update` requires exactly one of \
                         `--policy <path>` or `--clear`."
                    );
                    process::exit(1);
                }

                if *clear {
                    // Revert to fail-closed.  No request body — the daemon
                    // handler reads the session id from the URL.
                    Request::builder()
                        .method("DELETE")
                        .uri(format!("/sessions/{session}/policy"))
                        .body(String::new())
                        .expect("failed to build request")
                } else {
                    // POST a policy document.  `UpdatePolicyRequest` is
                    // `#[serde(flatten)]` over the inner `Policy`, so the
                    // wire body is the raw policy JSON at the top level.
                    let path = policy
                        .as_ref()
                        .expect("selected == 1 and !*clear implies policy.is_some()");
                    let body = match std::fs::read_to_string(path) {
                        Ok(content) => content,
                        Err(e) => {
                            eprintln!("Error: cannot read policy file '{path}': {e}");
                            process::exit(1);
                        }
                    };
                    if let Err(e) = serde_json::from_str::<Policy>(&body) {
                        eprintln!("Error: invalid policy JSON in '{path}': {e}");
                        process::exit(1);
                    }
                    Request::builder()
                        .method("POST")
                        .uri(format!("/sessions/{session}/policy"))
                        .header("content-type", "application/json")
                        .body(body)
                        .expect("failed to build request")
                }
            }
        },
        Command::Health { session } => Request::builder()
            .method("GET")
            .uri(format!("/sessions/{session}/health"))
            .body(String::new())
            .expect("failed to build request"),
        Command::RebuildImage => Request::builder()
            .method("POST")
            .uri("/rebuild-image")
            .body(String::new())
            .expect("failed to build request"),
        // Ssh, Logs, Cp, Inspect, and Describe are handled specially --
        // not via a single HTTP request. Inspect and Describe issue one
        // GET /sessions/{id} per argument and render client-side.
        Command::Ssh { .. }
        | Command::Logs { .. }
        | Command::Cp { .. }
        | Command::Inspect { .. }
        | Command::Describe { .. } => return None,
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
fn display_sessions_table(sessions: &[SessionDto]) {
    if sessions.is_empty() {
        println!("No sessions found.");
        return;
    }

    // Header.
    println!(
        "{:<12}  {:<16}  {:<10}  {:<11}  {:<11}  CREATED",
        "ID", "NAME", "STATE", "AGENT", "GATEWAY"
    );

    for session in sessions {
        let name = session.name.as_deref().unwrap_or("-");
        let state = session.state.to_string();
        let agent = session.guest_agent_status.as_deref().unwrap_or("-");
        let gateway = session.gateway_status.as_deref().unwrap_or("-");
        let created = format_relative_time(&session.created_at);

        println!(
            "{:<12}  {:<16}  {:<10}  {:<11}  {:<11}  {created}",
            session.id, name, state, agent, gateway
        );
    }
}

/// Display a single session in detail.
fn display_session(session: &SessionDto) {
    let name = session.name.as_deref().unwrap_or("-");
    println!("ID:       {}", session.id);
    println!("Name:     {name}");
    println!("State:    {}", session.state);
    println!("CPUs:     {}", session.config.cpus);
    println!("Memory:   {} MB", session.config.memory_mb);
    println!("Disk:     {} GB", session.config.disk_gb);
    println!(
        "Created:  {} ({})",
        session.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        format_relative_time(&session.created_at)
    );
    println!(
        "Updated:  {} ({})",
        session.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        format_relative_time(&session.updated_at)
    );
}

/// Maximum time to wait for the daemon to respond to an HTTP request.
///
/// Session creation involves VM boot, guest agent install, and networking
/// setup, so this must be generous.
const CLI_HTTP_TIMEOUT: Duration = Duration::from_secs(600);

async fn send_request(
    socket_path: &str,
    req: Request<String>,
) -> Result<(hyper::StatusCode, String), String> {
    send_request_with_timeout(socket_path, req, CLI_HTTP_TIMEOUT).await
}

async fn send_request_with_timeout(
    socket_path: &str,
    req: Request<String>,
    timeout: Duration,
) -> Result<(hyper::StatusCode, String), String> {
    let uri = req.uri().to_string();

    tokio::time::timeout(timeout, async {
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
    })
    .await
    .unwrap_or_else(|_| {
        Err(format!(
            "request to {uri} timed out after {}s",
            timeout.as_secs()
        ))
    })
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
            let sessions: Vec<SessionDto> =
                serde_json::from_str(body).map_err(|e| format!("failed to parse response: {e}"))?;
            display_sessions_table(&sessions);
        }
        Command::Rm { .. } => {
            // 204 No Content -- nothing to print.
            println!("Session removed.");
        }
        Command::Create { .. } => {
            let session: SessionDto =
                serde_json::from_str(body).map_err(|e| format!("failed to parse response: {e}"))?;
            println!("Session created:");
            display_session(&session);
        }
        Command::Start { .. } => {
            let session: SessionDto =
                serde_json::from_str(body).map_err(|e| format!("failed to parse response: {e}"))?;
            println!("Session started:");
            display_session(&session);
        }
        Command::Stop { .. } => {
            let session: SessionDto =
                serde_json::from_str(body).map_err(|e| format!("failed to parse response: {e}"))?;
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
        Command::Policy { action } => {
            let result: serde_json::Value = serde_json::from_str(body)
                .map_err(|e| format!("failed to parse policy response: {e}"))?;
            if let Some(message) = result.get("message").and_then(|m| m.as_str()) {
                println!("{message}");
            } else {
                // Fallback when the daemon response lacks a message field.
                // Choose the verb by subcommand to keep output truthful.
                match action {
                    PolicyAction::Update { clear: true, .. } => println!("Policy cleared."),
                    _ => println!("Policy updated."),
                }
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
            println!(
                "  Bridge:  {}",
                if health.network.bridge_exists {
                    "exists"
                } else {
                    "missing"
                }
            );
            println!(
                "  TAP:     {}",
                if health.network.tap_exists {
                    "exists"
                } else {
                    "missing"
                }
            );
        }
        Command::RebuildImage => {
            eprintln!("Done.");
        }
        Command::Ssh { .. }
        | Command::Logs { .. }
        | Command::Cp { .. }
        | Command::Inspect { .. }
        | Command::Describe { .. } => {
            // These commands are handled separately and never call
            // handle_response. Reaching here indicates a dispatch bug.
            unreachable!(
                "ssh/logs/cp/inspect/describe commands should be handled before send_request"
            );
        }
    }

    Ok(())
}

/// Fetch each session by name or ID via `GET /sessions/{id}` in parallel,
/// returning the DTOs in the same order as the input.
///
/// Used by `inspect` and `describe` to implement strict atomic error
/// behaviour: if **any** lookup fails, the caller writes an error to
/// stderr naming the **first** missing id (in input order), exits
/// non-zero, and emits **no** stdout.
///
/// No batch endpoint is introduced on the daemon — this is purely
/// client-side fan-out.  The cost of one GET per session is negligible
/// against the UX of a single atomic call from the user's point of view.
async fn fetch_sessions_parallel(
    socket_path: &str,
    sessions: &[String],
) -> Result<Vec<SessionDto>, String> {
    let mut handles: Vec<tokio::task::JoinHandle<Result<SessionDto, String>>> =
        Vec::with_capacity(sessions.len());

    for session in sessions {
        let socket = socket_path.to_string();
        let id = session.clone();
        handles.push(tokio::spawn(async move {
            let req = Request::builder()
                .method("GET")
                .uri(format!("/sessions/{id}"))
                .body(String::new())
                .expect("failed to build request");

            let (status, body) = send_request(&socket, req).await?;

            if status == hyper::StatusCode::NOT_FOUND {
                return Err(format!("session not found: {id}"));
            }

            if !status.is_success() {
                if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
                    return Err(format!("failed to look up session {id}: {}", api_err.error));
                }
                return Err(format!("failed to look up session {id} ({status}): {body}"));
            }

            serde_json::from_str::<SessionDto>(&body)
                .map_err(|e| format!("failed to parse session {id}: {e}"))
        }));
    }

    // Await every task. Collect results preserving input order; surface
    // the FIRST error in input order, mirroring the spec's "names the
    // first missing id" requirement.
    let mut results: Vec<Result<SessionDto, String>> = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.await {
            Ok(r) => results.push(r),
            Err(join_err) => results.push(Err(format!("task join error: {join_err}"))),
        }
    }

    // Find first error in input order.
    if let Some(err) = results.iter().find_map(|r| r.as_ref().err().cloned()) {
        return Err(err);
    }

    Ok(results
        .into_iter()
        .map(|r| r.expect("checked above"))
        .collect())
}

/// Render a slice of `SessionDto` as the human-readable `sandbox describe`
/// output. Separator between sessions is a single blank line.
///
/// Layout follows the spec §2:
/// - header block (Session, Name, State, Created, Updated)
/// - `Config:` block
/// - `Runtime:` block
/// - `Policy:` block — either `Policy: none` or a version/count header
///   followed by one indented rule entry per rule.
///
/// Timestamps are rendered as absolute UTC plus the existing relative
/// age suffix (e.g. `5m ago`), matching the sample in the spec.
fn render_describe(sessions: &[SessionDto]) -> String {
    let mut out = String::new();
    for (idx, session) in sessions.iter().enumerate() {
        if idx > 0 {
            // Single blank line between session blocks.
            out.push('\n');
        }
        render_describe_one(session, &mut out);
    }
    out
}

fn render_describe_one(session: &SessionDto, out: &mut String) {
    use std::fmt::Write as _;

    let name = session.name.as_deref().unwrap_or("-");
    let _ = writeln!(out, "Session:      {}", session.id);
    let _ = writeln!(out, "Name:         {name}");
    // Render state in lowercase to match spec §2 (and the wire/JSON
    // snake_case serde representation), not the capitalized `Display`
    // impl used by `ps` table headers.
    let _ = writeln!(
        out,
        "State:        {}",
        session.state.to_string().to_lowercase()
    );
    let _ = writeln!(
        out,
        "Created:      {} ({})",
        session.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        format_relative_time(&session.created_at)
    );
    let _ = writeln!(
        out,
        "Updated:      {} ({})",
        session.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        format_relative_time(&session.updated_at)
    );
    out.push('\n');

    let _ = writeln!(out, "Config:");
    let _ = writeln!(out, "  CPUs:        {}", session.config.cpus);
    let _ = writeln!(out, "  Memory:      {} MB", session.config.memory_mb);
    let _ = writeln!(out, "  Disk:        {} GB", session.config.disk_gb);
    let _ = writeln!(
        out,
        "  Workspace:   {}",
        session.config.workspace_mode.as_deref().unwrap_or("-")
    );
    let _ = writeln!(out, "  Hardened:    {}", session.config.hardened);
    let _ = writeln!(
        out,
        "  Repo:        {}",
        session.config.repo.as_deref().unwrap_or("-")
    );
    let _ = writeln!(
        out,
        "  Boot cmd:    {}",
        session.config.boot_cmd.as_deref().unwrap_or("-")
    );
    let _ = writeln!(
        out,
        "  Template:    {}",
        session.config.template.as_deref().unwrap_or("-")
    );
    out.push('\n');

    let _ = writeln!(out, "Runtime:");
    let _ = writeln!(
        out,
        "  Guest agent: {}",
        session.guest_agent_status.as_deref().unwrap_or("-")
    );
    let _ = writeln!(
        out,
        "  Gateway:     {}",
        session.gateway_status.as_deref().unwrap_or("-")
    );
    out.push('\n');

    render_policy_block(session.policy.as_ref(), out);
}

fn render_policy_block(policy: Option<&PolicyDto>, out: &mut String) {
    use std::fmt::Write as _;
    let policy = match policy {
        None => {
            let _ = writeln!(out, "Policy: none");
            return;
        }
        Some(p) => p,
    };

    let _ = writeln!(
        out,
        "Policy (v{}, {} rules):",
        policy.version,
        policy.rules.len()
    );
    for (i, rule) in policy.rules.iter().enumerate() {
        render_policy_rule(i, rule, out);
    }
}

fn render_policy_rule(idx: usize, rule: &PolicyRuleDto, out: &mut String) {
    use std::fmt::Write as _;

    // Top line: `  [i] <action> <protocol>  <destination>`.
    //
    // "action" is the level variant name (`allow` for any non-deny level
    // keeps faith with the sample in the spec, which uses `allow http`,
    // `allow tls`, etc.; `deny` is left as-is).  We map each level to a
    // (action, level_word) pair so the top line stays compact and the
    // sub-lines carry the detail.
    let (action, level_word) = match &rule.level {
        PolicyLevelDto::Deny => ("deny", ""),
        PolicyLevelDto::Transport => ("allow", "transport"),
        PolicyLevelDto::Tls => ("allow", "tls"),
        PolicyLevelDto::Http { .. } => ("allow", "http"),
    };

    let protocol_str = protocol_to_str(&rule.protocol);
    let host_str: String = rule.host.clone().into();
    let port = rule.port;

    // Layout: `  [i] <action> <level><pad><host>:<port>`. The combined
    // `<action> <level>` segment is padded to a fixed width (16) so the
    // host column lines up across rules regardless of level.  For
    // `deny` (no level word) we emit the action alone and rely on the
    // same padding to align the column.
    let target = format!("{host_str}:{port}");
    let header = if level_word.is_empty() {
        format!("  [{idx}] {:<16}{target}", action)
    } else {
        format!("  [{idx}] {:<16}{target}", format!("{action} {level_word}"))
    };
    let _ = writeln!(out, "{header}");

    let _ = writeln!(out, "        protocol:    {protocol_str}");

    if let PolicyLevelDto::Http { http_filters } = &rule.level {
        for filter in http_filters {
            let _ = writeln!(
                out,
                "        http_filters: {} {}",
                filter.method, filter.path
            );
        }
    }

    if let Some(reason) = &rule.reason {
        let _ = writeln!(out, "        reason:      {reason}");
    }
}

fn protocol_to_str(protocol: &sandbox_core::Protocol) -> &'static str {
    use sandbox_core::Protocol;
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

/// Handle `sandbox inspect <session>...`: emit a pretty-printed JSON array
/// of `SessionDto`, one element per argument, in input order. Any missing
/// session causes a non-zero exit with an error on stderr and no stdout.
async fn handle_inspect(socket_path: &str, sessions: &[String]) {
    let dtos = match fetch_sessions_parallel(socket_path, sessions).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    match serde_json::to_string_pretty(&dtos) {
        Ok(s) => {
            println!("{s}");
        }
        Err(e) => {
            eprintln!("Error: failed to serialize sessions: {e}");
            process::exit(1);
        }
    }
}

/// Handle `sandbox describe <session>...`: render human-readable sections
/// for each session per the spec §2 layout. Any missing session causes a
/// non-zero exit with an error on stderr and no stdout.
async fn handle_describe(socket_path: &str, sessions: &[String]) {
    let dtos = match fetch_sessions_parallel(socket_path, sessions).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    let rendered = render_describe(&dtos);
    // `print!` so we do not add a trailing blank line beyond what the
    // renderer already emitted (the last block ends with `\n` after the
    // last `writeln!` line).
    print!("{rendered}");
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

    let session_resp: SessionDto = match serde_json::from_str(&body) {
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

    let session_resp: SessionDto = match serde_json::from_str(&body) {
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
async fn handle_cp_upload(socket_path: &str, local_path: &str, session: &str, remote_path: &str) {
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
async fn handle_cp_download(socket_path: &str, session: &str, remote_path: &str, local_path: &str) {
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
        Ok((payload.to_string(), "/home/agent/workspace".to_string()))
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

    // Determine socket path via the shared helper, which honors SANDBOX_SOCKET
    // and falls back to the XDG/HOME default. The `--socket` global flag is
    // not available in remote-helper mode (git controls argv), so the env var
    // is the only override path here.
    let socket_path = default_socket_path();

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

        // The guest agent runs as the `agent` user (same as limactl shell),
        // so no privilege escalation is needed for workspace operations.
        let status = std::process::Command::new(&sandbox_bin)
            .args([
                "--socket",
                &socket_path,
                "ssh",
                &session,
                "--",
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

/// Pre-flight check for base image staleness before creating a session.
///
/// Queries the daemon's `GET /base-image-status` endpoint. If the image is
/// stale, prompts the user on stderr and optionally rebuilds before proceeding.
async fn check_base_image_staleness(socket_path: &str) {
    let req = match Request::builder()
        .method("GET")
        .uri("/base-image-status")
        .body(String::new())
    {
        Ok(r) => r,
        Err(_) => return, // Best-effort; don't block create on pre-flight failure.
    };

    let (status, body) = match send_request(socket_path, req).await {
        Ok(r) => r,
        Err(_) => return, // Daemon might not support the endpoint yet.
    };

    if !status.is_success() {
        return; // Best-effort.
    }

    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return,
    };

    let status_str = json.get("status").and_then(|s| s.as_str()).unwrap_or("");
    if status_str != "stale" {
        return;
    }

    let age_days = json.get("age_days").and_then(|v| v.as_u64()).unwrap_or(0);
    eprintln!("Warning: base image is {} days old.", age_days);
    eprint!("Rebuild before creating session? [y/N] ");

    // Read user response from stdin.
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return;
    }
    let answer = input.trim().to_lowercase();
    if answer == "y" || answer == "yes" {
        eprintln!("Rebuilding base image...");
        let rebuild_req = Request::builder()
            .method("POST")
            .uri("/rebuild-image")
            .body(String::new())
            .expect("failed to build rebuild request");

        match send_request_with_timeout(socket_path, rebuild_req, CLI_HTTP_TIMEOUT).await {
            Ok((s, _)) if s.is_success() => {
                eprintln!("Done.");
            }
            Ok((s, resp_body)) => {
                eprintln!("Warning: rebuild failed ({s}): {resp_body}");
            }
            Err(e) => {
                eprintln!("Warning: rebuild failed: {e}");
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

    // Handle inspect/describe specially — they fan out N parallel HTTP
    // requests and render client-side.
    if let Command::Inspect { sessions } = &cli.command {
        handle_inspect(&cli.socket, sessions).await;
        return;
    }
    if let Command::Describe { sessions } = &cli.command {
        handle_describe(&cli.socket, sessions).await;
        return;
    }

    // Pre-flight base image staleness check for create commands.
    if let Command::Create { no_cache, .. } = &cli.command {
        if !cli.yes && !*no_cache {
            check_base_image_staleness(&cli.socket).await;
        }
    }

    // Print progress message for rebuild-image before sending the request.
    if matches!(&cli.command, Command::RebuildImage) {
        eprintln!("Rebuilding base image...");
    }

    let req = match build_request(&cli.command) {
        Some(r) => r,
        None => {
            // Should not happen — ssh and logs are handled above.
            eprintln!("Internal error: unhandled command");
            process::exit(1);
        }
    };

    match send_request_with_timeout(&cli.socket, req, CLI_HTTP_TIMEOUT).await {
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
                no_cache: false,
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
            "sandbox",
            "create",
            "--name",
            "full",
            "--cpus",
            "4",
            "--memory",
            "8192",
            "--disk",
            "50",
            "--template",
            "/tmp/custom.yaml",
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
        // Ensure the test is not perturbed by an inherited SANDBOX_SOCKET
        // from the surrounding shell -- the default value should end with
        // `sandboxd.sock` regardless of outside state.
        let prior = std::env::var("SANDBOX_SOCKET").ok();
        // SAFETY: Tests in this module that touch SANDBOX_SOCKET mutate and
        // restore it in a single test body to avoid cross-test races under
        // `cargo test` (nextest already provides per-test process isolation).
        unsafe { std::env::remove_var("SANDBOX_SOCKET") };
        let cli = Cli::parse_from(["sandbox", "ps"]);
        assert!(cli.socket.ends_with("sandboxd.sock"));
        // Restore prior state.
        if let Some(v) = prior {
            unsafe { std::env::set_var("SANDBOX_SOCKET", v) };
        }
    }

    #[test]
    fn custom_socket_path() {
        let cli = Cli::parse_from(["sandbox", "--socket", "/tmp/custom.sock", "ps"]);
        assert_eq!(cli.socket, "/tmp/custom.sock");
    }

    #[test]
    fn default_socket_path_honors_sandbox_socket_env() {
        // Save and restore the env var to keep the test hermetic. Both
        // assertions live in one test so that parallel threads under
        // `cargo test` cannot race on the same var (nextest runs each test
        // in its own process, so this is belt-and-suspenders there).
        let prior = std::env::var("SANDBOX_SOCKET").ok();

        // SANDBOX_SOCKET is honored when no --socket flag is given. This
        // matches the daemon's precedence: `--socket` > env > XDG/HOME.
        // SAFETY: see note on the restore block; the test body is the only
        // window in which the variable is mutated.
        unsafe { std::env::set_var("SANDBOX_SOCKET", "/tmp/from-env.sock") };
        assert_eq!(default_socket_path(), "/tmp/from-env.sock");
        let cli = Cli::parse_from(["sandbox", "ps"]);
        assert_eq!(cli.socket, "/tmp/from-env.sock");

        // An explicit --socket still wins over the env var.
        let cli = Cli::parse_from(["sandbox", "--socket", "/tmp/explicit.sock", "ps"]);
        assert_eq!(cli.socket, "/tmp/explicit.sock");

        // When SANDBOX_SOCKET is unset the XDG/HOME default applies.
        unsafe { std::env::remove_var("SANDBOX_SOCKET") };
        assert!(default_socket_path().ends_with("sandboxd.sock"));

        // Restore prior state so other tests that happen to share the
        // process (under `cargo test`) are unaffected.
        match prior {
            Some(v) => unsafe { std::env::set_var("SANDBOX_SOCKET", v) },
            None => unsafe { std::env::remove_var("SANDBOX_SOCKET") },
        }
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
            no_cache: false,
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
            no_cache: false,
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
            no_cache: false,
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
        assert!(
            result.contains("s ago"),
            "expected seconds ago, got: {result}"
        );
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
        let cli = Cli::parse_from(["sandbox", "logs", "my-session", "--component", "envoy"]);
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
        let cli = Cli::parse_from(["sandbox", "logs", "my-session", "--follow", "--tail", "50"]);
        match &cli.command {
            Command::Logs { follow, tail, .. } => {
                assert!(*follow);
                assert_eq!(*tail, 50);
            }
            _ => panic!("expected Logs command"),
        }
    }

    #[test]
    fn parse_logs_component_mitmproxy() {
        let cli = Cli::parse_from(["sandbox", "logs", "my-session", "--component", "mitmproxy"]);
        match &cli.command {
            Command::Logs { component, .. } => {
                assert!(matches!(component, LogComponent::Mitmproxy));
            }
            _ => panic!("expected Logs command"),
        }
    }

    #[test]
    fn parse_logs_component_coredns() {
        let cli = Cli::parse_from(["sandbox", "logs", "my-session", "--component", "coredns"]);
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
    fn parse_policy_update_with_file() {
        let cli = Cli::parse_from([
            "sandbox",
            "policy",
            "update",
            "my-session",
            "--policy",
            "/tmp/policy.json",
        ]);
        match &cli.command {
            Command::Policy {
                action:
                    PolicyAction::Update {
                        session,
                        policy,
                        clear,
                    },
            } => {
                assert_eq!(session, "my-session");
                assert_eq!(policy.as_deref(), Some("/tmp/policy.json"));
                assert!(!clear);
            }
            _ => panic!("expected Policy Update command"),
        }
    }

    #[test]
    fn parse_policy_update_with_clear() {
        let cli = Cli::parse_from(["sandbox", "policy", "update", "my-session", "--clear"]);
        match &cli.command {
            Command::Policy {
                action:
                    PolicyAction::Update {
                        session,
                        policy,
                        clear,
                    },
            } => {
                assert_eq!(session, "my-session");
                assert!(policy.is_none());
                assert!(*clear);
            }
            _ => panic!("expected Policy Update command"),
        }
    }

    #[test]
    fn parse_policy_update_conflicts_policy_and_clear() {
        let result = Cli::try_parse_from([
            "sandbox",
            "policy",
            "update",
            "my-session",
            "--policy",
            "/tmp/p.json",
            "--clear",
        ]);
        assert!(
            result.is_err(),
            "expected clap error for conflicting --policy + --clear"
        );
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
        let cli = Cli::parse_from(["sandbox", "create", "--boot-cmd", "npm install"]);
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
                assert_eq!(repo.as_deref(), Some("https://github.com/example/repo.git"));
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
            no_cache: false,
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
            no_cache: false,
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
            no_cache: false,
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
            no_cache: false,
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

    // -- Remote helper URL parsing tests ------------------------------------

    #[test]
    fn parse_remote_helper_url_session_and_path() {
        let (session, repo_path) =
            parse_remote_helper_url("my-session/home/agent/workspace/repo.git").unwrap();
        assert_eq!(session, "my-session");
        assert_eq!(repo_path, "/home/agent/workspace/repo.git");
    }

    #[test]
    fn parse_remote_helper_url_with_scheme_prefix() {
        // git may pass the full URL including the sandbox:: prefix.
        let (session, repo_path) =
            parse_remote_helper_url("sandbox::my-session/home/agent/workspace/repo").unwrap();
        assert_eq!(session, "my-session");
        assert_eq!(repo_path, "/home/agent/workspace/repo");
    }

    #[test]
    fn parse_remote_helper_url_session_only() {
        // No slash — defaults to /home/agent/workspace.
        let (session, repo_path) = parse_remote_helper_url("my-session").unwrap();
        assert_eq!(session, "my-session");
        assert_eq!(repo_path, "/home/agent/workspace");
    }

    #[test]
    fn parse_remote_helper_url_empty() {
        assert!(parse_remote_helper_url("").is_err());
    }

    #[test]
    fn parse_remote_helper_url_empty_session() {
        // Starts with slash — empty session name.
        assert!(parse_remote_helper_url("/home/agent/workspace").is_err());
    }

    // -- No-cache and yes flag tests ------------------------------------------

    #[test]
    fn parse_create_with_no_cache() {
        let cli = Cli::parse_from(["sandbox", "create", "--no-cache"]);
        match &cli.command {
            Command::Create { no_cache, .. } => {
                assert!(*no_cache, "--no-cache flag should set no_cache to true");
            }
            _ => panic!("expected Create command"),
        }
    }

    #[test]
    fn parse_create_default_no_cache_off() {
        let cli = Cli::parse_from(["sandbox", "create"]);
        match &cli.command {
            Command::Create { no_cache, .. } => {
                assert!(!*no_cache, "no_cache should be false by default");
            }
            _ => panic!("expected Create command"),
        }
    }

    #[test]
    fn build_create_request_with_no_cache() {
        let cmd = Command::Create {
            name: Some("cached".into()),
            cpus: 2,
            memory: 4096,
            disk: 20,
            template: None,
            policy: None,
            repo: None,
            boot_cmd: None,
            workspace: None,
            no_hardening: false,
            no_cache: true,
        };
        let req = build_request(&cmd).expect("should produce request");
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert_eq!(
            body["no_cache"], true,
            "--no-cache should set no_cache=true in request body"
        );
    }

    #[test]
    fn build_create_request_default_omits_no_cache() {
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
            no_cache: false,
        };
        let req = build_request(&cmd).expect("should produce request");
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert!(
            body.get("no_cache").is_none(),
            "default (no_cache=false) should omit the field from request body"
        );
    }

    #[test]
    fn parse_yes_flag_global() {
        let cli = Cli::parse_from(["sandbox", "-y", "create"]);
        assert!(cli.yes, "-y should set yes to true");
    }

    #[test]
    fn parse_yes_flag_long() {
        let cli = Cli::parse_from(["sandbox", "--yes", "ps"]);
        assert!(cli.yes, "--yes should set yes to true");
    }

    #[test]
    fn parse_yes_default_off() {
        let cli = Cli::parse_from(["sandbox", "ps"]);
        assert!(!cli.yes, "yes should be false by default");
    }

    // -- Rebuild-image tests --------------------------------------------------

    #[test]
    fn parse_rebuild_image() {
        let cli = Cli::parse_from(["sandbox", "rebuild-image"]);
        assert!(matches!(cli.command, Command::RebuildImage));
    }

    #[test]
    fn build_rebuild_image_request() {
        let cmd = Command::RebuildImage;
        let req = build_request(&cmd).expect("should produce request");
        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri(), "/rebuild-image");
        assert!(req.body().is_empty());
    }

    // -- Inspect / describe tests --------------------------------------------

    use sandbox_core::{
        Destination, HttpFilter, HttpMethod, Protocol, SessionConfigDto, SessionId, SessionState,
    };

    fn make_session_dto(
        id: &str,
        name: Option<&str>,
        policy: Option<PolicyDto>,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> SessionDto {
        SessionDto {
            id: SessionId::parse(id).expect("valid session id"),
            name: name.map(|s| s.to_string()),
            state: SessionState::Running,
            created_at,
            updated_at: created_at,
            config: SessionConfigDto {
                cpus: 2,
                memory_mb: 4096,
                disk_gb: 20,
                workspace_mode: Some("shared:/home/olek/project".into()),
                hardened: true,
                repo: Some("https://github.com/example/app.git".into()),
                boot_cmd: Some("make setup".into()),
                template: None,
            },
            guest_agent_status: Some("connected".into()),
            gateway_status: Some("running".into()),
            policy,
        }
    }

    #[test]
    fn parse_inspect_two_sessions() {
        let cli = Cli::parse_from(["sandbox", "inspect", "alpha", "beta"]);
        match &cli.command {
            Command::Inspect { sessions } => {
                assert_eq!(sessions, &vec!["alpha".to_string(), "beta".to_string()]);
            }
            _ => panic!("expected Inspect command"),
        }
    }

    #[test]
    fn parse_describe_one_session() {
        let cli = Cli::parse_from(["sandbox", "describe", "alpha"]);
        match &cli.command {
            Command::Describe { sessions } => {
                assert_eq!(sessions, &vec!["alpha".to_string()]);
            }
            _ => panic!("expected Describe command"),
        }
    }

    #[test]
    fn inspect_build_request_returns_none() {
        // Inspect is handled outside the single-request pipeline.
        let cmd = Command::Inspect {
            sessions: vec!["alpha".into()],
        };
        assert!(build_request(&cmd).is_none());
    }

    #[test]
    fn describe_build_request_returns_none() {
        let cmd = Command::Describe {
            sessions: vec!["alpha".into()],
        };
        assert!(build_request(&cmd).is_none());
    }

    #[test]
    fn describe_renders_policy_none_when_dto_omits_policy() {
        let dto = make_session_dto(
            "0123456789ab",
            Some("no-policy"),
            None,
            chrono::Utc::now() - chrono::Duration::minutes(5),
        );
        let rendered = render_describe(std::slice::from_ref(&dto));
        assert!(
            rendered.contains("Policy: none"),
            "expected 'Policy: none' line, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("Policy ("),
            "must not emit versioned header when policy is absent, got:\n{rendered}"
        );
    }

    #[test]
    fn describe_renders_full_rule_block_with_filters_and_reason() {
        let policy = PolicyDto {
            version: "2.0".into(),
            rules: vec![
                PolicyRuleDto {
                    host: Destination::Domain("github.com".into()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    level: PolicyLevelDto::Http {
                        http_filters: vec![HttpFilter {
                            method: HttpMethod::Get,
                            path: "/repos/*".into(),
                        }],
                    },
                    reason: Some("fetch repo metadata".into()),
                },
                PolicyRuleDto {
                    host: Destination::Domain("registry.npmjs.org".into()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    level: PolicyLevelDto::Tls,
                    reason: None,
                },
                PolicyRuleDto {
                    host: Destination::Cidr("0.0.0.0/0".into()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    level: PolicyLevelDto::Deny,
                    reason: Some("default deny".into()),
                },
            ],
        };

        let dto = make_session_dto(
            "abcdef012345",
            Some("policy-box"),
            Some(policy),
            chrono::Utc::now() - chrono::Duration::minutes(5),
        );
        let rendered = render_describe(std::slice::from_ref(&dto));

        // Header.
        assert!(
            rendered.contains("Policy (v2.0, 3 rules):"),
            "policy header missing, got:\n{rendered}"
        );

        // Per-rule top lines and sub-fields.
        assert!(
            rendered.contains("[0] allow http"),
            "expected rule 0 action/level, got:\n{rendered}"
        );
        assert!(
            rendered.contains("github.com:443"),
            "expected rule 0 host:port, got:\n{rendered}"
        );
        assert!(
            rendered.contains("http_filters: GET /repos/*"),
            "expected http_filters line, got:\n{rendered}"
        );
        assert!(
            rendered.contains("reason:      fetch repo metadata"),
            "expected reason line for rule 0, got:\n{rendered}"
        );

        assert!(
            rendered.contains("[1] allow tls"),
            "expected rule 1 action/level, got:\n{rendered}"
        );
        // Rule 1 has no reason → no reason line for that block.  We check
        // presence of the host and protocol to make sure rule 1 was
        // rendered at all.
        assert!(
            rendered.contains("registry.npmjs.org:443"),
            "expected rule 1 host:port, got:\n{rendered}"
        );

        assert!(
            rendered.contains("[2] deny"),
            "expected rule 2 action, got:\n{rendered}"
        );
        assert!(
            rendered.contains("reason:      default deny"),
            "expected reason line for rule 2, got:\n{rendered}"
        );
    }

    // Visual regression harness: render a realistic multi-rule example and
    // eprint it (invisible under normal test runs, visible under
    // `--no-capture`). Keeps the spec sample near the implementation.
    #[test]
    fn describe_visual_preview() {
        let policy = PolicyDto {
            version: "2.0".into(),
            rules: vec![
                PolicyRuleDto {
                    host: Destination::Domain("github.com".into()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    level: PolicyLevelDto::Http {
                        http_filters: vec![HttpFilter {
                            method: HttpMethod::Get,
                            path: "/repos/*".into(),
                        }],
                    },
                    reason: Some("fetch repo metadata".into()),
                },
                PolicyRuleDto {
                    host: Destination::Domain("registry.npmjs.org".into()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    level: PolicyLevelDto::Tls,
                    reason: None,
                },
                PolicyRuleDto {
                    host: Destination::Cidr("0.0.0.0/0".into()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    level: PolicyLevelDto::Deny,
                    reason: Some("default deny".into()),
                },
            ],
        };
        let dto = make_session_dto(
            "abcdef012345",
            Some("preview"),
            Some(policy),
            chrono::Utc::now() - chrono::Duration::minutes(5),
        );
        let rendered = render_describe(std::slice::from_ref(&dto));
        eprintln!("--- describe preview ---\n{rendered}--- end preview ---");
    }

    #[test]
    fn describe_renders_multiple_http_filters_one_per_line() {
        let policy = PolicyDto {
            version: "2.0".into(),
            rules: vec![PolicyRuleDto {
                host: Destination::Domain("api.example.com".into()),
                port: 443,
                protocol: Protocol::Tcp,
                level: PolicyLevelDto::Http {
                    http_filters: vec![
                        HttpFilter {
                            method: HttpMethod::Get,
                            path: "/v1/*".into(),
                        },
                        HttpFilter {
                            method: HttpMethod::Post,
                            path: "/v1/upload".into(),
                        },
                    ],
                },
                reason: None,
            }],
        };
        let dto = make_session_dto(
            "aaaabbbbcccc",
            Some("multi-filter"),
            Some(policy),
            chrono::Utc::now(),
        );
        let rendered = render_describe(std::slice::from_ref(&dto));
        let filter_lines: Vec<&str> = rendered
            .lines()
            .filter(|line| line.contains("http_filters:"))
            .collect();
        assert_eq!(
            filter_lines.len(),
            2,
            "expected one http_filters line per filter, got:\n{rendered}"
        );
        assert!(filter_lines[0].contains("GET /v1/*"));
        assert!(filter_lines[1].contains("POST /v1/upload"));
    }

    #[test]
    fn describe_separates_sessions_by_exactly_one_blank_line() {
        let now = chrono::Utc::now();
        let a = make_session_dto("111111111111", Some("a"), None, now);
        let b = make_session_dto("222222222222", Some("b"), None, now);
        let c = make_session_dto("333333333333", Some("c"), None, now);
        let rendered = render_describe(&[a, b, c]);

        // Find each "Session:      " line and ensure exactly one blank
        // line precedes each subsequent session block.
        let lines: Vec<&str> = rendered.lines().collect();
        let session_line_indices: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter_map(|(i, line)| {
                if line.starts_with("Session:") {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(session_line_indices.len(), 3);

        for &idx in session_line_indices.iter().skip(1) {
            assert!(
                idx >= 2,
                "session block must be preceded by content + blank line"
            );
            let blank = lines[idx - 1];
            let prev = lines[idx - 2];
            assert!(
                blank.is_empty(),
                "expected blank line before Session header at line {idx}, got: {blank:?}"
            );
            assert!(
                !prev.is_empty(),
                "expected non-blank content two lines before Session header at line {idx}, got: {prev:?}"
            );
        }

        // Sanity: no run of more than one consecutive blank line within
        // the whole render.
        let mut prev_blank = false;
        for line in &lines {
            let blank = line.is_empty();
            if blank && prev_blank {
                panic!("found two consecutive blank lines in render:\n{rendered}");
            }
            prev_blank = blank;
        }
    }

    // -- Inspect / describe end-to-end over a local Unix socket ----------------

    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixListener;
    use std::thread;

    /// Spawn a tiny blocking HTTP server on a Unix socket that serves
    /// canned responses. `route` maps a request path (e.g.
    /// `/sessions/alpha`) to an `(HTTP status line, body)` pair.
    ///
    /// Runs in a background thread, accepting connections in a loop and
    /// handling each request sequentially (each connection serves one
    /// request). Returns the socket path to pass to the CLI.
    fn spawn_fake_daemon(
        routes: std::collections::HashMap<String, (u16, String)>,
    ) -> (tempfile::TempDir, String) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sock_path = tmp.path().join("sandboxd.sock");
        let sock_str = sock_path.to_string_lossy().to_string();

        let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
        // The listener is moved into the server thread; the TempDir stays
        // in the caller so the socket file lives for the duration of the
        // test.
        thread::spawn(move || {
            for conn in listener.incoming() {
                let mut stream = match conn {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = [0u8; 4096];
                let n = match stream.read(&mut buf) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                // Parse the request line (first line).
                let request_line = req.lines().next().unwrap_or("");
                // Format: "GET /path HTTP/1.1"
                let path = request_line.split_whitespace().nth(1).unwrap_or("");

                let (status, body) = routes
                    .get(path)
                    .cloned()
                    .unwrap_or_else(|| (500, "{\"error\":\"unhandled path\"}".into()));

                let status_text = match status {
                    200 => "OK",
                    404 => "Not Found",
                    _ => "Internal Server Error",
                };
                let response = format!(
                    "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.shutdown(std::net::Shutdown::Write);
            }
        });

        (tmp, sock_str)
    }

    fn session_dto_json(id: &str, name: &str) -> String {
        // Build a minimal SessionDto JSON response that the CLI can
        // deserialize. Keep the shape in sync with `SessionDto`.
        let dto = make_session_dto(id, Some(name), None, chrono::Utc::now());
        serde_json::to_string(&dto).expect("serialize session dto")
    }

    #[tokio::test]
    async fn inspect_two_sessions_emits_json_array_in_input_order() {
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "/sessions/aaaaaaaaaaaa".to_string(),
            (200, session_dto_json("aaaaaaaaaaaa", "alpha")),
        );
        routes.insert(
            "/sessions/bbbbbbbbbbbb".to_string(),
            (200, session_dto_json("bbbbbbbbbbbb", "beta")),
        );
        let (_tmp, sock) = spawn_fake_daemon(routes);

        let dtos = fetch_sessions_parallel(
            &sock,
            &["aaaaaaaaaaaa".to_string(), "bbbbbbbbbbbb".to_string()],
        )
        .await
        .expect("both sessions should resolve");

        assert_eq!(dtos.len(), 2);
        assert_eq!(dtos[0].id.as_str(), "aaaaaaaaaaaa");
        assert_eq!(dtos[0].name.as_deref(), Some("alpha"));
        assert_eq!(dtos[1].id.as_str(), "bbbbbbbbbbbb");
        assert_eq!(dtos[1].name.as_deref(), Some("beta"));

        // And the pretty-printed JSON array is valid JSON of length 2.
        let pretty = serde_json::to_string_pretty(&dtos).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&pretty).expect("valid json");
        let arr = parsed.as_array().expect("top-level array");
        assert_eq!(arr.len(), 2);
    }

    #[tokio::test]
    async fn inspect_with_one_missing_session_returns_error_naming_first_missing() {
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "/sessions/aaaaaaaaaaaa".to_string(),
            (200, session_dto_json("aaaaaaaaaaaa", "alpha")),
        );
        routes.insert(
            "/sessions/missing-one".to_string(),
            (404, "{\"error\":\"session not found\"}".into()),
        );
        routes.insert(
            "/sessions/cccccccccccc".to_string(),
            (200, session_dto_json("cccccccccccc", "gamma")),
        );
        let (_tmp, sock) = spawn_fake_daemon(routes);

        let result = fetch_sessions_parallel(
            &sock,
            &[
                "aaaaaaaaaaaa".to_string(),
                "missing-one".to_string(),
                "cccccccccccc".to_string(),
            ],
        )
        .await;

        let err = result.expect_err("expected a missing-session error");
        // Spec: "names the first missing id". Here "missing-one" is the
        // only missing one; the error string must contain its id.
        assert!(
            err.contains("missing-one"),
            "error must name the missing id, got: {err}"
        );
        assert!(
            !err.contains("aaaaaaaaaaaa") || err.contains("missing-one"),
            "must focus on the missing id: {err}"
        );
    }

    #[tokio::test]
    async fn inspect_first_missing_id_is_named_when_multiple_missing() {
        // When multiple sessions are missing, the error must identify the
        // first missing id in argument order — not whichever happens to
        // complete first across the parallel fan-out.
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "/sessions/first-miss".to_string(),
            (404, "{\"error\":\"not found\"}".into()),
        );
        routes.insert(
            "/sessions/second-miss".to_string(),
            (404, "{\"error\":\"not found\"}".into()),
        );
        let (_tmp, sock) = spawn_fake_daemon(routes);

        let err = fetch_sessions_parallel(
            &sock,
            &["first-miss".to_string(), "second-miss".to_string()],
        )
        .await
        .expect_err("both missing");

        assert!(
            err.contains("first-miss"),
            "first missing id must win, got: {err}"
        );
    }
}
