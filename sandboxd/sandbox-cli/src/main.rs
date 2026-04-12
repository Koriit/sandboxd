use std::process;

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use sandbox_core::{ApiError, Session};
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
}

fn default_socket_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    format!("{home}/.sandboxd/sandboxd.sock")
}

/// Build the HTTP request for the given CLI command.
fn build_request(command: &Command) -> Request<String> {
    match command {
        Command::Create {
            name,
            cpus,
            memory,
            disk,
            template,
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
    }
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
fn display_sessions_table(sessions: &[Session]) {
    if sessions.is_empty() {
        println!("No sessions found.");
        return;
    }

    // Header — use a pre-formatted constant to avoid clippy::print_literal.
    const HEADER: &str = "ID                                    NAME              STATE       CREATED";
    println!("{HEADER}");

    for session in sessions {
        let name = session
            .name
            .as_deref()
            .unwrap_or("-");
        let state = session.state.to_string();
        let created = format_relative_time(&session.created_at);

        println!(
            "{:<36}  {:<16}  {:<10}  {created}",
            session.id, name, state
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
            let sessions: Vec<Session> = serde_json::from_str(body)
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
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let req = build_request(&cli.command);

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
        };
        let req = build_request(&cmd);
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
        };
        let req = build_request(&cmd);
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
        };
        let req = build_request(&cmd);
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert_eq!(body["template"], "/tmp/my-template.yaml");
    }

    #[test]
    fn build_start_request() {
        let cmd = Command::Start {
            session: "abc".into(),
        };
        let req = build_request(&cmd);
        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri(), "/sessions/abc/start");
    }

    #[test]
    fn build_stop_request() {
        let cmd = Command::Stop {
            session: "abc".into(),
        };
        let req = build_request(&cmd);
        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri(), "/sessions/abc/stop");
    }

    #[test]
    fn build_rm_request() {
        let cmd = Command::Rm {
            session: "abc".into(),
        };
        let req = build_request(&cmd);
        assert_eq!(req.method(), "DELETE");
        assert_eq!(req.uri(), "/sessions/abc");
    }

    #[test]
    fn build_ps_request() {
        let cmd = Command::Ps;
        let req = build_request(&cmd);
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), "/sessions");
    }

    #[test]
    fn build_ls_request() {
        let cmd = Command::Ls;
        let req = build_request(&cmd);
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), "/sessions");
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
}
