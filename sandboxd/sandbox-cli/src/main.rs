use std::path::Path;
use std::process;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, SecondsFormat, Utc};
use clap::{ArgAction, ArgGroup, Parser, Subcommand, ValueEnum};
use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use sandbox_core::{
    ApiError, EventDto, ExecResponse, Policy, PolicyDto, PolicyLevelDto, PolicyRule, PolicyRuleDto,
    SessionDto, SessionHealth, UpdatePolicyRequest,
};
use tokio::net::UnixStream;

mod presets;

use presets::{Catalog, ParsedInvocation, Preset, PresetSource};

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
        /// Preset invocation(s) to apply on top of the optional
        /// `--policy` file. Repeatable. Each invocation has the form
        /// `'<name>[:key=value[,key=value,...]]'` (e.g. `npm:`,
        /// `github-repo:repo=foo/bar`). Presets expand client-side
        /// into rules that merge with the policy file; the composed
        /// effective policy is sent to the daemon, along with the
        /// original invocation strings as `source_presets` for audit.
        ///
        /// Run `sandbox policy preset list` to see the built-in
        /// catalog.
        #[arg(long, action = ArgAction::Append, num_args = 1)]
        preset: Vec<String>,
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
    /// Stream or replay events from a sandbox session.
    ///
    /// By default emits a bounded replay of the session's event ring as
    /// JSONL (one JSON object per line). Use `--follow` to keep the
    /// connection open and stream live events. `--table` swaps the
    /// default JSONL renderer for a human-readable fixed-column table.
    ///
    /// Multiple `--layer` / `--event` values narrow the filter by OR
    /// within an axis; axes combine with AND. `--decision` is
    /// single-valued (the server accepts a repeatable query parameter
    /// but specifying both values is equivalent to omitting the filter
    /// entirely).
    #[command(group = ArgGroup::new("events_output").args(["json", "table"]))]
    Events {
        /// Session name or ID.
        session: String,
        /// Stream live events as they arrive (chunked JSONL).  Without
        /// this flag the CLI prints the current ring-buffer contents
        /// and exits.
        #[arg(long, short = 'f')]
        follow: bool,
        /// Filter by layer name (`dns`, `envoy`, `mitmproxy`,
        /// `deny-logger`, `lifecycle`).  Repeat to include multiple
        /// layers.
        #[arg(long, action = ArgAction::Append, num_args = 1)]
        layer: Vec<String>,
        /// Filter by event name (e.g. `query_denied`,
        /// `connection_allowed`, `deny`). Repeat to include multiple
        /// event names.
        #[arg(long, action = ArgAction::Append, num_args = 1)]
        event: Vec<String>,
        /// Filter by decision: `allow` or `deny`.
        #[arg(long)]
        decision: Option<String>,
        /// Lower-bound cutoff for event timestamps. Accepts either an
        /// RFC 3339 timestamp (e.g. `2026-04-22T12:00:00Z`) or a
        /// shorthand duration (`5s`, `2m`, `3h`, `7d`) which is
        /// resolved against the current wall clock on the CLI side.
        #[arg(long)]
        since: Option<String>,
        /// Emit raw JSONL (the default).  Preserves round-trip fidelity
        /// for shell-redirect persistence
        /// (`sandbox events <id> --follow > file.jsonl`).
        #[arg(long)]
        json: bool,
        /// Render a human-readable fixed-column table instead of JSONL.
        /// Deny rows are colored red when stdout is a TTY.
        #[arg(long)]
        table: bool,
    },
    /// Rebuild the pre-baked base VM image.
    RebuildImage,
}

/// Policy subcommands.
#[derive(Subcommand, Debug, Clone)]
enum PolicyAction {
    /// Update the policy for a session.
    ///
    /// At least one of `--policy`, `--preset`, or `--clear` must be
    /// supplied. `--clear` is idempotent (safe to call on a session
    /// that already has no policy) and is mutually exclusive with
    /// both `--policy` and `--preset`. `--policy` and `--preset`
    /// compose: presets expand into rules that merge with the policy
    /// file's rules (see `sandbox policy preset`).
    Update {
        /// Session name or ID.
        session: String,
        /// Path to the policy JSON file to apply.
        #[arg(long, conflicts_with = "clear")]
        policy: Option<String>,
        /// Preset invocation(s) to apply on top of the optional
        /// `--policy` file. See `sandbox create --preset` for the
        /// invocation syntax and `sandbox policy preset list` for
        /// the built-in catalog. Repeatable. Mutually exclusive
        /// with `--clear`.
        #[arg(long, action = ArgAction::Append, num_args = 1, conflicts_with = "clear")]
        preset: Vec<String>,
        /// Remove any policy from the session and revert to the fail-closed
        /// default (empty CoreDNS allow-list, deny-all mitmproxy/Envoy).
        /// Idempotent. Mutually exclusive with `--policy` and `--preset`.
        #[arg(long, conflicts_with = "policy", conflicts_with = "preset")]
        clear: bool,
    },
    /// Inspect the built-in and user-configured preset catalog (client-local).
    ///
    /// All three subcommands run entirely inside the CLI — they do
    /// not contact the sandbox daemon. User presets are loaded from
    /// `$XDG_CONFIG_HOME/sandboxd/presets/*.json` (falling back to
    /// `$HOME/.config/sandboxd/presets/`).
    Preset {
        #[command(subcommand)]
        action: PresetAction,
    },
}

/// `sandbox policy preset` subcommands.
#[derive(Subcommand, Debug, Clone)]
enum PresetAction {
    /// List every preset available to the CLI, alphabetically.
    ///
    /// The output is a two-column table of `NAME | SOURCE` where
    /// SOURCE is `built-in` or `user: /abs/path`.
    List,
    /// Show a preset's description and parameter schema.
    Show {
        /// Preset name (e.g. `npm`, `github-repo`).
        name: String,
    },
    /// Expand a preset invocation into a v2 policy document and
    /// print it as JSON.
    ///
    /// Output shape: `{"version":"2.0.0","rules":[...]}` — a copy-
    /// pasteable policy document that the daemon will accept via
    /// `--policy`. Errors in the invocation (unknown preset, missing
    /// required param, forbidden character in a value, ...) exit
    /// non-zero with the error text on stderr.
    Expand {
        /// Raw invocation string, e.g. `github-repo:repo=foo/bar`.
        raw: String,
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

/// Expand `--preset` invocations into a merged effective `Policy`.
///
/// Shared between `Command::Create` and `PolicyAction::Update`. Both
/// call sites must produce the same `(effective_policy, source_presets)`
/// tuple from the same `(file, file_path, raw_invocations)` inputs,
/// so the helper centralizes the four-step pipeline:
///
/// 1. Load the preset [`Catalog`] (built-ins + XDG user presets).
/// 2. Parse each raw `--preset` string into a [`ParsedInvocation`].
/// 3. Call `presets::expand` per invocation to produce rule lists.
/// 4. Call `presets::merge_effective` to combine the policy file + all
///    expansions into a single validated [`Policy`].
///
/// Any [`PresetError`] along the way prints its `Display` impl to
/// stderr and calls `process::exit(1)` **before** returning. The
/// error wording is spec-mandated (Part 1 lines 140-150, Part 2
/// "Error shapes"), so we defer to `PresetError`'s `Display` impl
/// verbatim — callers must not reformat or add a prefix.
///
/// Returning `(Policy, Vec<String>)` keeps the call sites simple:
/// `Vec<String>` is the list of `.raw` invocations for the
/// `source_presets` wire field, in user-provided order.
fn expand_and_merge_presets(
    file_policy: Option<&Policy>,
    file_path: Option<&Path>,
    raw_invocations: &[String],
) -> (Policy, Vec<String>) {
    // Load built-ins + XDG user presets. In production `cli_xdg_override`
    // is always `None`; the test hook lives in the `presets` module.
    let catalog = match Catalog::load(None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    // Parse every `--preset` value into `(ParsedInvocation, rules)`.
    // Parse errors fire one-at-a-time so the operator sees the exact
    // bad invocation; we surface the first one and exit.
    let mut expansions: Vec<(ParsedInvocation, Vec<PolicyRule>)> =
        Vec::with_capacity(raw_invocations.len());
    for raw in raw_invocations {
        let inv = match ParsedInvocation::parse(raw) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        };
        let rules = match presets::expand(&catalog, &inv) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        };
        expansions.push((inv, rules));
    }

    // Merge policy file + expansions into one validated Policy.
    let effective = match presets::merge_effective(file_policy, file_path, &catalog, &expansions) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    let source_presets = expansions.into_iter().map(|(inv, _)| inv.raw).collect();
    (effective, source_presets)
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
            preset,
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
            // Compose `--policy` (optional file) with any `--preset`
            // invocations (repeatable) into a single effective policy.
            //
            // - If neither is present, omit `policy` from the body
            //   (legacy "no policy" shape — server defaults to
            //   fail-closed).
            // - If only `--policy` is present, parse it and pass it
            //   through (matches the pre-M10-S5 wire shape).
            // - If `--preset` is present (with or without `--policy`),
            //   expand presets client-side, merge them with the file,
            //   and send the effective `Policy` JSON plus
            //   `source_presets` as a sibling field for audit.
            //
            // Preset errors short-circuit to stderr + exit(1) BEFORE
            // any Unix-socket work — this matches the spec invariant
            // "the daemon never sees a malformed preset invocation".
            let (file_policy, file_path): (Option<Policy>, Option<std::path::PathBuf>) =
                if let Some(policy_path) = policy {
                    let policy_json = match std::fs::read_to_string(policy_path) {
                        Ok(content) => content,
                        Err(e) => {
                            eprintln!("Error: cannot read policy file '{policy_path}': {e}");
                            process::exit(1);
                        }
                    };
                    let parsed: Policy = match serde_json::from_str(&policy_json) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("Error: invalid policy JSON in '{policy_path}': {e}");
                            process::exit(1);
                        }
                    };
                    (Some(parsed), Some(std::path::PathBuf::from(policy_path)))
                } else {
                    (None, None)
                };

            if !preset.is_empty() {
                let (effective, source_presets) =
                    expand_and_merge_presets(file_policy.as_ref(), file_path.as_deref(), preset);
                let policy_value =
                    serde_json::to_value(&effective).expect("Policy always serializes to JSON");
                body.insert("policy".into(), policy_value);
                body.insert(
                    "source_presets".into(),
                    serde_json::Value::Array(
                        source_presets
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            } else if let Some(effective) = file_policy {
                let policy_value =
                    serde_json::to_value(&effective).expect("Policy always serializes to JSON");
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
                preset,
                clear,
            } => {
                // At least one of `--policy`, `--preset`, or `--clear`
                // must be supplied. clap's `conflicts_with` already
                // catches the "clear + policy" and "clear + preset"
                // cases; "none of the three" has to be validated here.
                // `--policy` and `--preset` compose: presets merge on
                // top of the optional file.
                let any_provided = policy.is_some() || !preset.is_empty() || *clear;
                if !any_provided {
                    eprintln!(
                        "Error: `sandbox policy update` requires at least one of \
                         `--policy <path>`, `--preset '<invocation>'`, or `--clear`."
                    );
                    process::exit(1);
                }

                if *clear {
                    // Revert to fail-closed. No request body — the
                    // daemon handler reads the session id from the URL.
                    Request::builder()
                        .method("DELETE")
                        .uri(format!("/sessions/{session}/policy"))
                        .body(String::new())
                        .expect("failed to build request")
                } else {
                    // POST an `UpdatePolicyRequest`. The DTO is
                    // `#[serde(flatten)]` over the inner `Policy` with
                    // `source_presets` as a sibling, so the wire shape
                    // is `{"version":"2.0.0","rules":[...],"source_presets":[...]}`
                    // when presets are present and bitwise-identical to
                    // the pre-M10-S5 shape when they are not (thanks to
                    // `skip_serializing_if = "Vec::is_empty"` on the DTO).
                    let (file_policy, file_path): (Option<Policy>, Option<std::path::PathBuf>) =
                        if let Some(path) = policy {
                            let raw = match std::fs::read_to_string(path) {
                                Ok(content) => content,
                                Err(e) => {
                                    eprintln!("Error: cannot read policy file '{path}': {e}");
                                    process::exit(1);
                                }
                            };
                            let parsed: Policy = match serde_json::from_str(&raw) {
                                Ok(v) => v,
                                Err(e) => {
                                    eprintln!("Error: invalid policy JSON in '{path}': {e}");
                                    process::exit(1);
                                }
                            };
                            (Some(parsed), Some(std::path::PathBuf::from(path)))
                        } else {
                            (None, None)
                        };

                    let (effective, source_presets) = if !preset.is_empty() {
                        expand_and_merge_presets(file_policy.as_ref(), file_path.as_deref(), preset)
                    } else {
                        // No presets — just use the file (guaranteed
                        // present by the `any_provided` check above when
                        // `clear` is false).
                        let effective = file_policy.expect(
                            "!clear && preset.is_empty() implies policy.is_some() per any_provided check",
                        );
                        (effective, Vec::new())
                    };

                    let request_dto = UpdatePolicyRequest {
                        policy: effective,
                        source_presets,
                    };
                    let body = serde_json::to_string(&request_dto)
                        .expect("UpdatePolicyRequest always serializes to JSON");
                    Request::builder()
                        .method("POST")
                        .uri(format!("/sessions/{session}/policy"))
                        .header("content-type", "application/json")
                        .body(body)
                        .expect("failed to build request")
                }
            }
            PolicyAction::Preset { .. } => {
                // Handled entirely client-side before `build_request` is
                // ever called — see the dispatch in `main()`. Returning
                // `None` here would drop the request, so we panic
                // defensively: reaching this branch indicates a dispatch
                // bug where the preset subcommand was routed through the
                // normal request pipeline.
                unreachable!(
                    "`sandbox policy preset ...` is handled client-side \
                     in main() before build_request"
                );
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
        // Ssh, Logs, Cp, Inspect, Describe, and Events are handled
        // specially -- not via a single buffered request/response pair.
        // Inspect and Describe issue one GET /sessions/{id} per argument
        // and render client-side. Events streams chunked JSONL and
        // cannot go through `send_request` (which buffers the body).
        Command::Ssh { .. }
        | Command::Logs { .. }
        | Command::Cp { .. }
        | Command::Inspect { .. }
        | Command::Describe { .. }
        | Command::Events { .. } => return None,
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
        | Command::Describe { .. }
        | Command::Events { .. } => {
            // These commands are handled separately and never call
            // handle_response. Reaching here indicates a dispatch bug.
            unreachable!(
                "ssh/logs/cp/inspect/describe/events commands should be handled before send_request"
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

/// Handle `sandbox policy preset {list,show,expand}` entirely
/// client-local.
///
/// None of the three subcommands contact the daemon — they inspect
/// the CLI's built-in catalog plus the user's XDG preset directory.
/// Errors exit non-zero with the spec-mandated `PresetError` wording
/// on stderr so operators can paste-and-compare against the spec.
///
/// Output contracts (enforced by unit tests in `tests/preset_cli.rs`):
/// - `list`: one line per preset, `NAME<TAB>SOURCE`. SOURCE is
///   `built-in` or `user: <abs-path>`. Alphabetical by name.
/// - `show`: a multi-line block with the preset name on the first
///   line, the description on the second, and a `Params:` section
///   listing every declared parameter (built-in or user-configured).
/// - `expand`: a single JSON document on stdout matching
///   `{"version":"2.0.0","rules":[...]}` (D-10).
fn handle_policy_preset(action: &PresetAction) {
    let catalog = match Catalog::load(None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    match action {
        PresetAction::List => {
            // Print one row per preset, alphabetical by name. Tab
            // separator keeps the output column-friendly without
            // pulling in a TUI dep; `column -t -s $'\t'` gives
            // operators a pretty table if they want one.
            for summary in catalog.list() {
                let source_str = match &summary.source {
                    PresetSource::Builtin => "built-in".to_string(),
                    PresetSource::User { path } => format!("user: {}", path.display()),
                };
                println!("{}\t{}", summary.name, source_str);
            }
        }
        PresetAction::Show { name } => {
            let preset = match catalog.find(name) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            };
            print_preset_details(&preset);
        }
        PresetAction::Expand { raw } => {
            let inv = match ParsedInvocation::parse(raw) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            };
            let rules = match presets::expand(&catalog, &inv) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: {e}");
                    process::exit(1);
                }
            };
            // D-10: `expand` outputs `{"version":"2.0.0","rules":[...]}`
            // — the same shape the daemon accepts via `--policy`.
            // Build it through `Policy` so the `version` field is
            // sourced from the same constant the daemon uses.
            let doc = Policy {
                version: sandbox_core::policy::SCHEMA_VERSION.to_string(),
                rules,
            };
            let rendered =
                serde_json::to_string_pretty(&doc).expect("Policy always serializes to JSON");
            println!("{rendered}");
        }
    }
}

/// Render the full body of `sandbox policy preset show <name>`.
///
/// Kept separate from [`handle_policy_preset`] because the `Show`
/// branch is the most complex of the three and because unit tests in
/// `tests/preset_cli.rs` exercise the rendering path directly by
/// constructing a `Preset` and comparing the captured stdout.
fn print_preset_details(preset: &Preset) {
    println!("Preset: {}", preset.name());
    if let Some(desc) = preset.description() {
        println!("Description: {desc}");
    }
    match preset {
        Preset::Builtin(b) => {
            println!("Source: built-in");
            // Built-in param schemas are hard-coded per the spec.
            // Keep this table in lock-step with the expander bodies
            // in `presets::builtin` — the unit test
            // `show_github_repo_documents_repo_param` guards against
            // drift.
            let schema = builtin_param_schema(b.name);
            if schema.is_empty() {
                println!("Params: (none)");
            } else {
                println!("Params:");
                for row in schema {
                    println!("  - {row}");
                }
            }
        }
        Preset::User(u) => {
            println!("Source: user: {}", u.source_path.display());
            if u.params.is_empty() {
                println!("Params: (none)");
            } else {
                println!("Params:");
                for p in &u.params {
                    let mut flags: Vec<&'static str> = Vec::new();
                    if p.required {
                        flags.push("required");
                    }
                    if p.repeatable {
                        flags.push("repeatable");
                    }
                    let flags_str = if flags.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", flags.join(", "))
                    };
                    println!("  - {}: string{}", p.name, flags_str);
                }
            }
        }
    }
}

/// Parameter-schema rows shown by `sandbox policy preset show <name>`
/// for built-in presets.
///
/// Returned as a `Vec<&'static str>` rather than a typed struct
/// because the output is display-only; the one test that inspects
/// the `github-repo` row (`show_github_repo_documents_repo_param`)
/// asserts against substrings. Keep the wording in sync with the
/// expander bodies in `presets::builtin`.
fn builtin_param_schema(name: &str) -> Vec<&'static str> {
    match name {
        "github-repo" => vec!["repo=owner/name (required, repeatable)"],
        "github-pr" => vec![
            "repo=owner/name (required, repeatable, paired with pr=)",
            "pr=<positive-integer> (required, repeatable, paired with repo=)",
        ],
        // Unparameterized built-ins — every other entry in BUILTINS.
        _ => Vec::new(),
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

// ---------------------------------------------------------------------------
// `sandbox events` — M10-S4 Phase 4
// ---------------------------------------------------------------------------
//
// `Command::Events` cannot reuse `send_request`: that helper buffers the
// full response body, which is fine for policy/session JSON but wrong for
// a chunked JSONL stream that may never end. The events path therefore
// opens its own `hyper::client::conn::http1::handshake`, iterates the
// body frames via `Body::frame`, and forwards complete `\n`-delimited
// lines to a pluggable output sink (raw JSONL or the hand-rolled
// `--table` formatter).
//
// Module-local helpers covered by unit tests at the bottom of this file:
//
// - `parse_since_rfc3339` / `parse_since_duration` / `resolve_since`
//   — normalize the `--since` CLI input (RFC 3339 literal *or* GNU-style
//   shorthand duration) into the single RFC 3339 UTC string the daemon
//   expects on the wire.
// - `build_events_query_string` — deterministic query-string assembly
//   from the parsed `Command::Events` variant. Hand-rolled percent
//   encoding keeps `sandbox-cli` dep-free.
// - `split_jsonl_lines` — the cross-chunk line splitter.
// - `format_table_header` / `format_table_row` — the `--table` renderer.

/// Parse a `--since` value that is expected to be a bare RFC 3339
/// timestamp (e.g. `2026-04-22T12:00:00Z`). Used both as a standalone
/// helper and as the RFC-3339 branch of [`resolve_since`].
fn parse_since_rfc3339(raw: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| format!("invalid --since RFC 3339 timestamp `{raw}`: {e}"))
}

/// Parse a `--since` value as a GNU-coreutils-style shorthand duration.
///
/// Accepts `Ns`, `Nm`, `Nh`, `Nd` where `N` is an unsigned integer.
/// Returns the `DateTime<Utc>` computed as `now - duration`. `0s` is
/// valid (returns `now`). Anything else — including a leading `-`, a
/// trailing unit we don't support (`5x`), a bare integer (`5`), or an
/// empty string — yields `Err`.
fn parse_since_duration(raw: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    if raw.is_empty() {
        return Err("--since value is empty".into());
    }
    // Split off the trailing unit character. ASCII-only so indexing the
    // penultimate byte is safe; a leading minus sign is rejected
    // implicitly by `u64::from_str` below.
    let (num_part, unit) = match raw.as_bytes().last() {
        Some(&b) if b.is_ascii_alphabetic() => (&raw[..raw.len() - 1], b as char),
        _ => {
            return Err(format!(
                "invalid --since duration `{raw}`: missing unit suffix"
            ));
        }
    };
    let magnitude: u64 = num_part.parse().map_err(|_| {
        format!(
            "invalid --since duration `{raw}`: \
             numeric prefix must be an unsigned integer"
        )
    })?;
    let secs: u64 = match unit {
        's' => magnitude,
        'm' => magnitude.saturating_mul(60),
        'h' => magnitude.saturating_mul(60 * 60),
        'd' => magnitude.saturating_mul(60 * 60 * 24),
        other => {
            return Err(format!(
                "invalid --since duration `{raw}`: unit `{other}` not one of s/m/h/d"
            ));
        }
    };
    let delta = chrono::Duration::seconds(secs as i64);
    now.checked_sub_signed(delta)
        .ok_or_else(|| format!("--since duration `{raw}` overflowed the CLI clock"))
}

/// Resolve a `--since` input — either an RFC 3339 timestamp or a
/// shorthand duration — into a UTC timestamp, then format it as RFC 3339
/// with millisecond precision and the `Z` suffix (the shape the daemon's
/// `EventsQueryDto::parse_since` expects on the wire).
///
/// Called by [`build_events_query_string`]; split out so tests can
/// exercise each branch separately without reconstructing a full
/// `Command::Events` value.
fn resolve_since(raw: &str, now: DateTime<Utc>) -> Result<String, String> {
    // Duration shorthand is a tight regex: digits followed by exactly one
    // of `s`/`m`/`h`/`d`. Anything else (including RFC 3339 strings,
    // which start with a digit but contain `-` and `:`) falls through to
    // the RFC 3339 parser.
    let looks_like_duration = !raw.is_empty()
        && raw
            .as_bytes()
            .iter()
            .take(raw.len() - 1)
            .all(|b| b.is_ascii_digit())
        && matches!(raw.as_bytes().last(), Some(b's' | b'm' | b'h' | b'd'));

    let resolved = if looks_like_duration {
        parse_since_duration(raw, now)?
    } else {
        parse_since_rfc3339(raw)?
    };
    Ok(resolved.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// Parsed-and-resolved arguments for the `sandbox events` subcommand.
///
/// Distinct from the raw `Command::Events` variant so query-string
/// assembly can be unit-tested without threading clap-constructed
/// `Command` values through the tests.
#[derive(Debug, Clone)]
struct EventsArgs {
    session: String,
    follow: bool,
    layers: Vec<String>,
    events: Vec<String>,
    decision: Option<String>,
    /// `since` is pre-resolved to RFC 3339 on the wire (whether the user
    /// typed a timestamp or a shorthand duration).
    since: Option<String>,
    mode: EventsOutputMode,
}

/// Output renderer selection for the `sandbox events` subcommand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventsOutputMode {
    /// Emit each JSONL line verbatim (default).
    Json,
    /// Parse lines as `EventDto` and render a fixed-column table.
    Table,
}

/// Percent-encode a value for a URL query-string component.
///
/// Hand-rolled to avoid pulling `url`/`form_urlencoded` as a direct
/// dependency: the three characters that matter for our inputs are
/// `&`, `=`, and `+`, plus anything non-ASCII. We follow the
/// application/x-www-form-urlencoded encoding (spaces → `+`, other
/// reserved chars → `%XX`). Inputs in practice are filter names
/// (`dns`, `deny-logger`, `query_denied`) and RFC 3339 timestamps that
/// only need the colons escaped — but the full encoder keeps the CLI
/// robust against future, more exotic values.
fn percent_encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

/// Assemble the query string for `GET /sessions/{id}/events`.
///
/// `follow=true` is emitted only when `args.follow` is set (axum's
/// `EventsQueryDto` uses `#[serde(default)]` for the bool, so omitting
/// the key is equivalent to `follow=false`).
///
/// Repeatable keys emit `&layer=a&layer=b` in input order.  Deterministic
/// ordering is an explicit property: the encoded URL is the same for
/// the same inputs, which keeps the CLI test vector stable.
///
/// Returns a non-empty string on non-empty args; the empty string
/// otherwise. The caller assembles the final URI as
/// `/sessions/{id}/events[?<qs>]`.
fn build_events_query_string(args: &EventsArgs) -> String {
    let mut parts: Vec<String> = Vec::new();
    if args.follow {
        parts.push("follow=true".to_string());
    }
    for layer in &args.layers {
        parts.push(format!("layer={}", percent_encode_query_value(layer)));
    }
    for event in &args.events {
        parts.push(format!("event={}", percent_encode_query_value(event)));
    }
    if let Some(decision) = &args.decision {
        parts.push(format!("decision={}", percent_encode_query_value(decision)));
    }
    if let Some(since) = &args.since {
        parts.push(format!("since={}", percent_encode_query_value(since)));
    }
    parts.join("&")
}

/// Split a growing byte buffer at every `\n` and return the set of
/// complete lines (without trailing `\n`).  The buffer is updated in
/// place: any trailing partial line (after the last `\n`) stays behind
/// for the next chunk.
///
/// Callers drive this per body frame; the function has no knowledge of
/// HTTP framing or chunked transfer — just line framing.
///
/// # Invariant
///
/// After every call, the buffer never contains an already-consumed
/// `\n`: each iteration drains bytes through the newline inclusively
/// via `split_off(pos + 1)`, so the residue is strictly the bytes that
/// come after the last `\n` seen so far.
fn split_jsonl_lines(buffer: &mut Vec<u8>) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
        // Drain the first `pos` bytes *plus* the newline from the head
        // of the buffer in a single move.
        let rest = buffer.split_off(pos + 1);
        // `buffer` now holds the line + `\n`; drop the `\n` and decode
        // as UTF-8 lossily — a malformed byte is rare (should never
        // happen on a well-behaved server) but we keep the stream
        // alive rather than panic.
        let mut line = std::mem::replace(buffer, rest);
        line.pop(); // drop the `\n`
        let s = String::from_utf8_lossy(&line).into_owned();
        out.push(s);
    }
    out
}

// --- Table renderer ---------------------------------------------------------
//
// Hand-rolled so `sandbox-cli` does not take on a new crate dep for one
// command. Columns:
//
//     TIME                      SESSION    LAYER         EVENT                    HOST:PORT              DETAIL
//     2026-04-22T23:12:34.567Z  <short>    deny-logger   deny                     203.0.113.1:80         reason=policy_mismatch decision=deny
//
// * TIME is already RFC 3339 with millis + `Z` on the wire, so no
//   reformatting is needed beyond slicing to 23 chars.
// * SESSION is truncated to the first 8 chars of the session_id
//   envelope field. Full UUIDs are too wide for the row.
// * LAYER and EVENT are left-padded to fixed widths — `deny-logger` is
//   the widest layer name the spec uses today; `policy_reset_on_upgrade`
//   is the widest event name.
// * HOST:PORT is reconstructed from whichever of `host:port` or
//   `orig_dst_ip:orig_dst_port` the event carries; `-` when neither.
// * DETAIL is a compact, hand-chosen subset of remaining fields
//   (`reason`, `decision`, `method`, `path`, ...).  Truncated at 60
//   columns with `…`.
//
// Rows with `decision == "deny"` are wrapped in ANSI red when stdout is
// a TTY.

const TABLE_TIME_WIDTH: usize = 24;
const TABLE_SESSION_WIDTH: usize = 8;
const TABLE_LAYER_WIDTH: usize = 13;
const TABLE_EVENT_WIDTH: usize = 24;
const TABLE_HOSTPORT_WIDTH: usize = 22;
const TABLE_DETAIL_MAX: usize = 60;

/// Emit the table header row.  Called once per invocation (for both
/// follow and non-follow), before the stream loop.
fn format_table_header() -> String {
    format!(
        "{:<tw$}  {:<sw$}  {:<lw$}  {:<ew$}  {:<hw$}  {}",
        "TIME",
        "SESSION",
        "LAYER",
        "EVENT",
        "HOST:PORT",
        "DETAIL",
        tw = TABLE_TIME_WIDTH,
        sw = TABLE_SESSION_WIDTH,
        lw = TABLE_LAYER_WIDTH,
        ew = TABLE_EVENT_WIDTH,
        hw = TABLE_HOSTPORT_WIDTH,
    )
}

/// Format one JSONL line as a table row.
///
/// - If `line` parses as [`EventDto`], extract the envelope + body
///   fields and render a fixed-column row. Deny rows are wrapped in
///   ANSI red when `colorize` is true.
/// - Otherwise (e.g. the streaming `lifecycle.ring_buffer_lag`
///   synthetic, whose shape does not match `EventDto`), fall through
///   to a raw-line print prefixed with `!` so the user can see the
///   line rather than having it silently dropped.
fn format_table_row(line: &str, colorize: bool) -> String {
    let dto = match serde_json::from_str::<EventDto>(line) {
        Ok(d) => d,
        Err(_) => return format!("! {line}"),
    };

    let (timestamp, session, layer, event, host_port, detail, is_deny) = extract_table_fields(&dto);

    let time_col = format_time_column(&timestamp);
    let session_col = format_session_column(&session);
    let layer_col = format!("{layer:<lw$}", lw = TABLE_LAYER_WIDTH);
    let event_col = format!("{event:<ew$}", ew = TABLE_EVENT_WIDTH);
    let host_col = format!("{host_port:<hw$}", hw = TABLE_HOSTPORT_WIDTH);
    let detail_col = truncate_detail(&detail);

    let row =
        format!("{time_col}  {session_col}  {layer_col}  {event_col}  {host_col}  {detail_col}");

    if colorize && is_deny {
        format!("\x1b[31m{row}\x1b[0m")
    } else {
        row
    }
}

/// Truncate TIME to the fixed column width.  The wire format is
/// `YYYY-MM-DDTHH:MM:SS.mmmZ` (24 chars including the trailing `Z`)
/// but we defensively pad or truncate to match.
fn format_time_column(ts: &str) -> String {
    if ts.len() >= TABLE_TIME_WIDTH {
        ts.chars().take(TABLE_TIME_WIDTH).collect()
    } else {
        format!("{ts:<w$}", w = TABLE_TIME_WIDTH)
    }
}

/// Truncate session_id to an 8-char short ID for the SESSION column.
fn format_session_column(session: &str) -> String {
    if session.is_empty() {
        return format!("{:<w$}", "-", w = TABLE_SESSION_WIDTH);
    }
    let short: String = session.chars().take(TABLE_SESSION_WIDTH).collect();
    format!("{short:<w$}", w = TABLE_SESSION_WIDTH)
}

/// Truncate DETAIL to `TABLE_DETAIL_MAX` columns, adding `…` as a
/// suffix when the field was cut short.  Uses `chars().take` rather
/// than byte-slicing so multi-byte characters are not split mid-codepoint.
fn truncate_detail(detail: &str) -> String {
    let char_count = detail.chars().count();
    if char_count <= TABLE_DETAIL_MAX {
        return detail.to_string();
    }
    let kept: String = detail.chars().take(TABLE_DETAIL_MAX - 1).collect();
    format!("{kept}\u{2026}")
}

/// Extract (timestamp, session, layer, event, host:port, detail, is_deny)
/// from an `EventDto` for the `--table` renderer.
///
/// `layer` is the spec's kebab-case layer name; `event` is the body's
/// snake_case event-name discriminator; `host:port` is pulled from
/// whichever shape the body exposes (HTTP-style `host:port`, Envoy
/// `dst_ip:dst_port`, deny-logger `orig_dst_ip:orig_dst_port`) or `-`
/// when absent; `detail` is a compact `key=value`-joined summary of
/// the body-specific fields worth showing.
fn extract_table_fields(
    dto: &EventDto,
) -> (
    String,
    String,
    &'static str,
    &'static str,
    String,
    String,
    bool,
) {
    use sandbox_core::{
        DenyLoggerEventBodyDto, DenyProtocolDto, DnsEventBodyDto, EnvoyConnectionDto,
        EnvoyEventBodyDto, LifecycleEventBodyDto, MitmproxyEventBodyDto,
    };

    match dto {
        EventDto::Dns(d) => {
            let (event_name, host_port, detail, is_deny) = match &d.body {
                DnsEventBodyDto::QueryAllowed {
                    query,
                    qtype,
                    resolved_ips,
                } => (
                    "query_allowed",
                    query.clone(),
                    format!("qtype={qtype} ips={}", resolved_ips.join(",")),
                    false,
                ),
                DnsEventBodyDto::QueryDenied {
                    query,
                    qtype,
                    reason,
                } => (
                    "query_denied",
                    query.clone(),
                    format!("qtype={qtype} reason={reason} decision=deny"),
                    true,
                ),
            };
            (
                d.timestamp.clone(),
                d.session.clone(),
                "dns",
                event_name,
                host_port,
                detail,
                is_deny,
            )
        }
        EventDto::Envoy(e) => {
            let (event_name, conn, is_deny): (_, &EnvoyConnectionDto, _) = match &e.body {
                EnvoyEventBodyDto::ConnectionAllowed(c) => ("connection_allowed", c, false),
                EnvoyEventBodyDto::ConnectionDenied(c) => ("connection_denied", c, true),
            };
            let host_port = format!("{}:{}", conn.dst_ip, conn.dst_port);
            let mut detail = format!(
                "cluster={} chain={} flags={} bytes_in={} bytes_out={} duration_ms={}",
                conn.cluster,
                conn.matched_chain,
                conn.response_flags,
                conn.bytes_received,
                conn.bytes_sent,
                conn.duration_ms,
            );
            if let Some(auth) = &conn.connect_authority {
                detail.push_str(&format!(" connect_authority={auth}"));
            }
            if is_deny {
                detail.push_str(" decision=deny");
            }
            (
                e.timestamp.clone(),
                e.session.clone(),
                "envoy",
                event_name,
                host_port,
                detail,
                is_deny,
            )
        }
        EventDto::Mitmproxy(m) => {
            let (event_name, host, port, method, path, reason, is_deny) = match &m.body {
                MitmproxyEventBodyDto::RequestAllowed {
                    host,
                    port,
                    method,
                    path,
                } => ("request_allowed", host, port, method, path, None, false),
                MitmproxyEventBodyDto::RequestDenied {
                    host,
                    port,
                    method,
                    path,
                    reason,
                } => (
                    "request_denied",
                    host,
                    port,
                    method,
                    path,
                    Some(reason.clone()),
                    true,
                ),
            };
            let host_port = format!("{host}:{port}");
            let mut detail = format!("method={method} path={path}");
            if let Some(r) = reason {
                detail.push_str(&format!(" reason={r}"));
            }
            if is_deny {
                detail.push_str(" decision=deny");
            }
            (
                m.timestamp.clone(),
                m.session.clone(),
                "mitmproxy",
                event_name,
                host_port,
                detail,
                is_deny,
            )
        }
        EventDto::DenyLogger(dl) => match &dl.body {
            DenyLoggerEventBodyDto::Deny {
                orig_dst_ip,
                orig_dst_port,
                protocol,
                src_ip,
                src_port,
            } => {
                let host_port = format!("{orig_dst_ip}:{orig_dst_port}");
                let proto = match protocol {
                    DenyProtocolDto::Tcp => "tcp",
                    DenyProtocolDto::Udp => "udp",
                };
                let detail = format!("proto={proto} src={src_ip}:{src_port} decision=deny");
                (
                    dl.timestamp.clone(),
                    dl.session.clone(),
                    "deny-logger",
                    "deny",
                    host_port,
                    detail,
                    true,
                )
            }
            DenyLoggerEventBodyDto::RateLimited {
                rate_limited_count,
                since_ts,
            } => (
                dl.timestamp.clone(),
                dl.session.clone(),
                "deny-logger",
                "rate_limited",
                "-".to_string(),
                format!("count={rate_limited_count} since={since_ts}"),
                false,
            ),
        },
        EventDto::Lifecycle(l) => {
            let (event_name, detail) = match &l.body {
                LifecycleEventBodyDto::GatewayBooting => ("gateway_booting", String::new()),
                LifecycleEventBodyDto::GatewayReady => ("gateway_ready", String::new()),
                LifecycleEventBodyDto::PolicyApplied {
                    policy,
                    source_presets,
                    status,
                    error,
                } => {
                    let mut d = format!(
                        "status={:?} rules={} presets={}",
                        status,
                        policy.rules.len(),
                        source_presets.join(",")
                    );
                    if let Some(e) = error {
                        d.push_str(&format!(" error={e}"));
                    }
                    ("policy_applied", d)
                }
                LifecycleEventBodyDto::PolicyUpdated {
                    policy,
                    source_presets,
                    status,
                    error,
                    previous_policy_hash,
                } => {
                    let mut d = format!(
                        "status={:?} rules={} presets={}",
                        status,
                        policy.rules.len(),
                        source_presets.join(",")
                    );
                    if let Some(e) = error {
                        d.push_str(&format!(" error={e}"));
                    }
                    if let Some(h) = previous_policy_hash {
                        d.push_str(&format!(" prev_hash={h}"));
                    }
                    ("policy_updated", d)
                }
                LifecycleEventBodyDto::PolicyResetOnUpgrade {
                    previous_rule_count,
                } => (
                    "policy_reset_on_upgrade",
                    format!("previous_rule_count={previous_rule_count}"),
                ),
                LifecycleEventBodyDto::PolicyPropagated { policy_hash } => {
                    // Truncate to the first 12 hex chars so the detail
                    // column stays a reasonable width on typical
                    // terminals. The full hash is still available via
                    // the JSON renderer (`--json`), which serializes
                    // `policy_hash` verbatim.
                    let short = policy_hash.get(..12).unwrap_or(policy_hash.as_str());
                    ("policy_propagated", format!("hash={short}"))
                }
                LifecycleEventBodyDto::HealthDegraded { component, reason } => (
                    "health_degraded",
                    format!("component={component:?} reason={reason}"),
                ),
                LifecycleEventBodyDto::HealthRestored { component } => {
                    ("health_restored", format!("component={component:?}"))
                }
                LifecycleEventBodyDto::GatewayShutdown { reason, error } => {
                    let mut d = format!("reason={reason:?}");
                    if let Some(e) = error {
                        d.push_str(&format!(" error={e}"));
                    }
                    ("gateway_shutdown", d)
                }
            };
            (
                l.timestamp.clone(),
                l.session.clone(),
                "lifecycle",
                event_name,
                "-".to_string(),
                detail,
                false,
            )
        }
    }
}

// --- Streaming HTTP client --------------------------------------------------

/// Exit code used when the `sandbox events` stream is interrupted by
/// SIGINT (Ctrl+C). The shell convention for SIGINT is 128 + 2 = 130.
const EVENTS_SIGINT_EXIT_CODE: i32 = 130;

/// Open a streaming HTTP/1.1 connection to the daemon and iterate body
/// frames, forwarding complete `\n`-delimited lines to the selected
/// output sink until either (a) the response body ends, or (b) SIGINT
/// is received.
///
/// This helper intentionally does **not** share code with `send_request`:
/// that helper buffers the full response body via `BodyExt::collect`,
/// which is correct for JSON endpoints but wrong for chunked JSONL.
/// Here we call `response.body_mut().frame().await` in a loop so each
/// chunk is processed as it arrives.
async fn stream_events_to_stdout(socket_path: &str, args: &EventsArgs) -> Result<(), String> {
    use tokio::io::{AsyncWriteExt, BufWriter};

    let qs = build_events_query_string(args);
    let uri = if qs.is_empty() {
        format!("/sessions/{}/events", args.session)
    } else {
        format!("/sessions/{}/events?{}", args.session, qs)
    };
    // `connection: close` asks the server to close the TCP/Unix socket
    // after the response body ends. Combined with dropping the request
    // machinery before awaiting the hyper conn driver (see the end of
    // this function), it guarantees that non-follow `sandbox events`
    // exits promptly once the daemon finishes streaming. Without it,
    // the default HTTP/1.1 keep-alive leaves the driver idling for a
    // next request that never arrives. See the Phase 6b fix for M10-S4.
    let req = Request::builder()
        .method("GET")
        .uri(&uri)
        .header("accept", "application/jsonl")
        .header("connection", "close")
        .body(String::new())
        .expect("failed to build events request");

    // Dial the daemon over the Unix socket. Mirrors `send_request` but
    // keeps the sender/connection around across frame reads.
    let stream = UnixStream::connect(socket_path).await.map_err(|e| {
        format!("Cannot connect to sandboxd at {socket_path} \u{2014} is the daemon running? ({e})")
    })?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("HTTP handshake failed: {e}"))?;

    // Connection driver: runs concurrently with frame reads until the
    // body completes or is dropped (Ctrl+C path).
    let conn_task = tokio::spawn(async move {
        if let Err(e) = conn.await {
            // Suppress "connection closed" noise on normal teardown;
            // only surface unexpected errors.
            let msg = e.to_string();
            if !msg.contains("IncompleteMessage") && !msg.contains("closed") {
                eprintln!("connection error: {e}");
            }
        }
    });

    let mut response = sender
        .send_request(req)
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = response.status();
    if !status.is_success() {
        // Non-success: read the (bounded) error body and report.
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("failed to read error body: {e}"))?
            .to_bytes();
        let body = String::from_utf8_lossy(&body_bytes).to_string();
        if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
            return Err(format!("Error: {}", api_err.error));
        }
        return Err(format!("Error ({status}): {body}"));
    }

    // Table mode prints the header once before the first row.
    let mut stdout = BufWriter::new(tokio::io::stdout());
    let colorize = args.mode == EventsOutputMode::Table
        && std::io::IsTerminal::is_terminal(&std::io::stdout());
    if args.mode == EventsOutputMode::Table {
        let header = format_table_header();
        stdout
            .write_all(header.as_bytes())
            .await
            .map_err(|e| format!("stdout write failed: {e}"))?;
        stdout
            .write_all(b"\n")
            .await
            .map_err(|e| format!("stdout write failed: {e}"))?;
    }

    let mut buffer: Vec<u8> = Vec::new();

    // Race the body read against SIGINT. On Ctrl+C we flush stdout,
    // drop the response (which closes the connection), and exit 130.
    let ctrlc = tokio::signal::ctrl_c();
    tokio::pin!(ctrlc);

    loop {
        tokio::select! {
            biased;
            _ = &mut ctrlc => {
                // Flush buffered stdout and exit cleanly. Dropping
                // `response` and `sender` via scope exit closes the
                // socket; the daemon's streaming task observes
                // RecvError::Closed and shuts down its subscription.
                let _ = stdout.flush().await;
                drop(response);
                // Don't wait on the connection driver — Ctrl+C is fast-exit.
                conn_task.abort();
                process::exit(EVENTS_SIGINT_EXIT_CODE);
            }
            frame = response.body_mut().frame() => {
                match frame {
                    None => break,
                    Some(Err(e)) => {
                        return Err(format!("stream read failed: {e}"));
                    }
                    Some(Ok(frame)) => {
                        if let Some(data) = frame.data_ref() {
                            buffer.extend_from_slice(data);
                            for line in split_jsonl_lines(&mut buffer) {
                                let rendered = match args.mode {
                                    EventsOutputMode::Json => line,
                                    EventsOutputMode::Table => {
                                        format_table_row(&line, colorize)
                                    }
                                };
                                stdout
                                    .write_all(rendered.as_bytes())
                                    .await
                                    .map_err(|e| format!("stdout write failed: {e}"))?;
                                stdout
                                    .write_all(b"\n")
                                    .await
                                    .map_err(|e| format!("stdout write failed: {e}"))?;
                            }
                            // Flush per chunk so `tail -f`-style
                            // downstream consumers see each line
                            // promptly.  JSONL-to-file users pay a
                            // negligible cost here; interactive users
                            // get sub-second latency instead of
                            // blocking until the buffer fills.
                            stdout.flush().await.ok();
                        }
                    }
                }
            }
        }
    }

    // If the stream ended without a trailing `\n`, warn and drop the
    // partial tail — the daemon's contract is to always emit complete
    // JSONL lines.
    if !buffer.is_empty() {
        tracing::warn!(
            dropped_bytes = buffer.len(),
            "stream ended mid-line, dropping partial tail"
        );
    }

    stdout
        .flush()
        .await
        .map_err(|e| format!("stdout flush failed: {e}"))?;
    // Drop the response body and the request sender *before* awaiting
    // the hyper connection driver. Hyper's HTTP/1.1 driver only
    // returns once both ends of the conversation signal they are done
    // — on the client side, that means the sender is dropped and no
    // response body is still borrowed. If we await the driver while
    // `sender`/`response` are still alive, keep-alive semantics leave
    // the driver idling for a next request that never arrives and the
    // await never returns. Paired with `connection: close` on the
    // outgoing request (see request builder above) this makes the
    // shutdown robust across hyper minor versions.
    drop(response);
    drop(sender);
    let _ = conn_task.await;
    Ok(())
}

/// Handle `sandbox events <session> [flags]`.
///
/// Thin wrapper that resolves `--since` (if any) from the user-facing
/// input (RFC 3339 or shorthand duration) to the wire-format RFC 3339
/// string, then hands off to [`stream_events_to_stdout`].
#[allow(clippy::too_many_arguments)]
async fn handle_events(
    socket_path: &str,
    session: &str,
    follow: bool,
    layer: Vec<String>,
    event: Vec<String>,
    decision: Option<String>,
    since: Option<String>,
    json_flag: bool,
    table_flag: bool,
) {
    // Three-way precedence for the output mode (matches
    // `docs/reference/cli.md` documentation for `--json` / `--table`):
    //
    // 1. `--table` wins — explicit request for the human-friendly view.
    // 2. `--json` wins — explicit request for machine-readable JSONL.
    // 3. No flag set: auto-detect based on stdout — JSONL when piped
    //    (scripts) and table when connected to a terminal (interactive).
    //
    // clap's ArgGroup guarantees at most one of `--json` / `--table` is
    // set, so the two explicit branches are mutually exclusive.
    let stdout_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let mode = if table_flag {
        EventsOutputMode::Table
    } else if json_flag || !stdout_is_tty {
        EventsOutputMode::Json
    } else {
        EventsOutputMode::Table
    };

    let resolved_since = match since {
        None => None,
        Some(raw) => match resolve_since(&raw, Utc::now()) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        },
    };

    let args = EventsArgs {
        session: session.to_string(),
        follow,
        layers: layer,
        events: event,
        decision,
        since: resolved_since,
        mode,
    };

    if let Err(e) = stream_events_to_stdout(socket_path, &args).await {
        eprintln!("{e}");
        process::exit(1);
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

    // Handle events specially — it streams JSONL over chunked HTTP and
    // needs client-side SIGINT handling, so it cannot reuse the normal
    // request/response flow.
    if let Command::Events {
        session,
        follow,
        layer,
        event,
        decision,
        since,
        json,
        table,
    } = &cli.command
    {
        handle_events(
            &cli.socket,
            session,
            *follow,
            layer.clone(),
            event.clone(),
            decision.clone(),
            since.clone(),
            *json,
            *table,
        )
        .await;
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

    // `sandbox policy preset ...` is entirely client-local — it never
    // contacts the daemon. Route it before any socket work so we don't
    // spuriously fail when the daemon is down and the user only wants
    // to inspect the preset catalog.
    if let Command::Policy {
        action: PolicyAction::Preset { action },
    } = &cli.command
    {
        handle_policy_preset(action);
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
        // Exhaustive match guarantees every field has its documented
        // default. `preset` was added in M10-S5 Phase 5a; an empty
        // vec is the "no presets requested" shape the `--preset`
        // flag would populate.
        match &cli.command {
            Command::Create {
                name: None,
                cpus: 2,
                memory: 4096,
                disk: 20,
                template: None,
                policy: None,
                preset,
                repo: None,
                boot_cmd: None,
                workspace: None,
                no_hardening: false,
                no_cache: false,
            } => assert!(preset.is_empty(), "default preset list should be empty"),
            _ => panic!("expected Create command with default fields"),
        }
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
            preset: vec![],
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
            preset: vec![],
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
            preset: vec![],
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
                        preset,
                        clear,
                    },
            } => {
                assert_eq!(session, "my-session");
                assert_eq!(policy.as_deref(), Some("/tmp/policy.json"));
                assert!(preset.is_empty());
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
                        preset,
                        clear,
                    },
            } => {
                assert_eq!(session, "my-session");
                assert!(policy.is_none());
                assert!(preset.is_empty());
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
            preset: vec![],
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
            preset: vec![],
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
            preset: vec![],
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
            preset: vec![],
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
            preset: vec![],
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
            preset: vec![],
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

    // -----------------------------------------------------------------
    // `sandbox events` subcommand — Phase 4 of M10-S4.
    //
    // Coverage matrix (aligned with the implementation plan):
    //
    //   * `parse_since_rfc3339`   — accepts / rejects RFC 3339 input
    //   * `parse_since_duration`  — accepts `Ns`/`Nm`/`Nh`/`Nd`, rejects
    //                               garbage, rejects leading `-`
    //   * `resolve_since`         — dispatches both branches, formats
    //                               the result with millis + `Z`
    //   * clap parsing            — repeatable flags, mutually
    //                               exclusive `--json` / `--table`, and
    //                               the missing-positional error
    //   * `build_events_query_string` — deterministic ordering,
    //                               percent-encoding, empty case
    //   * `split_jsonl_lines`     — cross-chunk partial-tail buffering
    //   * `format_table_row`      — happy path + `!`-prefix fallback
    //                               for the `ring_buffer_lag` synthetic
    // -----------------------------------------------------------------

    #[test]
    fn events_parse_since_rfc3339_accepts_z_suffix() {
        let ts = parse_since_rfc3339("2026-04-22T12:00:00Z").expect("z-form rfc3339");
        assert_eq!(
            ts.to_rfc3339_opts(SecondsFormat::Secs, true),
            "2026-04-22T12:00:00Z"
        );
    }

    #[test]
    fn events_parse_since_rfc3339_rejects_garbage() {
        let err = parse_since_rfc3339("garbage").expect_err("non-rfc3339 must fail");
        assert!(err.contains("garbage"), "error must cite input: {err}");
    }

    #[test]
    fn events_parse_since_duration_accepts_all_units() {
        let now: DateTime<Utc> = "2026-04-22T12:00:00Z".parse().unwrap();
        let cases = [
            ("5s", 5_i64),
            ("2m", 2 * 60),
            ("3h", 3 * 60 * 60),
            ("7d", 7 * 24 * 60 * 60),
        ];
        for (raw, secs) in cases {
            let got = parse_since_duration(raw, now)
                .unwrap_or_else(|e| panic!("duration `{raw}` must parse: {e}"));
            let expected = now - chrono::Duration::seconds(secs);
            assert_eq!(
                got, expected,
                "duration `{raw}`: want {expected}, got {got}"
            );
        }
    }

    #[test]
    fn events_parse_since_duration_accepts_zero() {
        let now: DateTime<Utc> = "2026-04-22T12:00:00Z".parse().unwrap();
        assert_eq!(parse_since_duration("0s", now).unwrap(), now);
    }

    #[test]
    fn events_parse_since_duration_rejects_bad_inputs() {
        let now: DateTime<Utc> = "2026-04-22T12:00:00Z".parse().unwrap();
        // Leading `-` (negative number) — u64 parse rejects it.
        assert!(
            parse_since_duration("-5s", now).is_err(),
            "negative prefix must not parse"
        );
        // Unknown unit.
        assert!(
            parse_since_duration("5x", now).is_err(),
            "unknown unit `x` must not parse"
        );
        // Bare integer (no unit).
        assert!(
            parse_since_duration("5", now).is_err(),
            "missing unit must not parse"
        );
        // Non-integer prefix.
        assert!(
            parse_since_duration("foo", now).is_err(),
            "letters must not parse"
        );
        // Empty string.
        assert!(
            parse_since_duration("", now).is_err(),
            "empty must not parse"
        );
    }

    #[test]
    fn events_resolve_since_rfc3339_branch_normalises_to_millis_z() {
        let now: DateTime<Utc> = "2026-04-22T12:00:00Z".parse().unwrap();
        // Even though the input is second-precision, the output must
        // carry `.000` millis + `Z`.
        let out = resolve_since("2026-04-22T08:30:00Z", now).unwrap();
        assert_eq!(out, "2026-04-22T08:30:00.000Z");
    }

    #[test]
    fn events_resolve_since_duration_branch_formats_as_rfc3339_millis_z() {
        let now: DateTime<Utc> = "2026-04-22T12:00:00Z".parse().unwrap();
        let out = resolve_since("5m", now).unwrap();
        // 5 minutes earlier than `now`, rendered with `.000` millis + `Z`.
        assert_eq!(out, "2026-04-22T11:55:00.000Z");
    }

    #[test]
    fn events_resolve_since_errors_surface_to_caller() {
        let now: DateTime<Utc> = "2026-04-22T12:00:00Z".parse().unwrap();
        assert!(resolve_since("nonsense", now).is_err());
        assert!(resolve_since("5x", now).is_err());
    }

    #[test]
    fn events_parse_repeatable_layer_and_event() {
        let cli = Cli::parse_from([
            "sandbox",
            "events",
            "abc123",
            "--layer",
            "dns",
            "--layer",
            "envoy",
            "--event",
            "query_denied",
        ]);
        match cli.command {
            Command::Events {
                session,
                layer,
                event,
                follow,
                decision,
                since,
                json,
                table,
            } => {
                assert_eq!(session, "abc123");
                assert_eq!(layer, vec!["dns".to_string(), "envoy".to_string()]);
                assert_eq!(event, vec!["query_denied".to_string()]);
                assert!(!follow);
                assert!(decision.is_none());
                assert!(since.is_none());
                assert!(!json);
                assert!(!table);
            }
            other => panic!("expected Events, got {other:?}"),
        }
    }

    #[test]
    fn events_parse_follow_and_single_decision() {
        let cli = Cli::parse_from(["sandbox", "events", "abc123", "--follow", "--decision=deny"]);
        match cli.command {
            Command::Events {
                follow, decision, ..
            } => {
                assert!(follow);
                assert_eq!(decision.as_deref(), Some("deny"));
            }
            other => panic!("expected Events, got {other:?}"),
        }
    }

    #[test]
    fn events_parse_since_shorthand() {
        let cli = Cli::parse_from(["sandbox", "events", "abc123", "--since=5m"]);
        match cli.command {
            Command::Events { since, .. } => {
                assert_eq!(since.as_deref(), Some("5m"));
            }
            other => panic!("expected Events, got {other:?}"),
        }
    }

    #[test]
    fn events_parse_json_and_table_are_mutually_exclusive() {
        let err = Cli::try_parse_from(["sandbox", "events", "abc123", "--json", "--table"])
            .expect_err("--json and --table must conflict");
        // clap surfaces ArgGroup violations via `ErrorKind::ArgumentConflict`.
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn events_parse_missing_session_is_an_error() {
        let err =
            Cli::try_parse_from(["sandbox", "events"]).expect_err("missing positional must fail");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn events_build_query_string_empty_when_no_flags() {
        let args = EventsArgs {
            session: "abc".into(),
            follow: false,
            layers: vec![],
            events: vec![],
            decision: None,
            since: None,
            mode: EventsOutputMode::Json,
        };
        assert_eq!(build_events_query_string(&args), "");
    }

    #[test]
    fn events_build_query_string_only_emits_follow_when_set() {
        let args = EventsArgs {
            session: "abc".into(),
            follow: false,
            layers: vec!["dns".into()],
            events: vec![],
            decision: None,
            since: None,
            mode: EventsOutputMode::Json,
        };
        // follow=false must NOT appear on the wire (server default).
        assert_eq!(build_events_query_string(&args), "layer=dns");
    }

    #[test]
    fn events_build_query_string_full_combo_is_deterministic() {
        let args = EventsArgs {
            session: "abc".into(),
            follow: true,
            layers: vec!["dns".into(), "deny-logger".into()],
            events: vec!["query_denied".into(), "deny".into()],
            decision: Some("deny".into()),
            since: Some("2026-04-22T12:00:00.000Z".into()),
            mode: EventsOutputMode::Table,
        };
        let qs = build_events_query_string(&args);
        // Input order is preserved per-axis; axes interleave in
        // follow/layer/event/decision/since order.
        assert_eq!(
            qs,
            concat!(
                "follow=true",
                "&layer=dns",
                "&layer=deny-logger",
                "&event=query_denied",
                "&event=deny",
                "&decision=deny",
                "&since=2026-04-22T12%3A00%3A00.000Z",
            )
        );
    }

    #[test]
    fn events_percent_encode_covers_reserved_chars() {
        // `:` must be `%3A` (rfc3339 timestamps) — the critical case.
        assert_eq!(percent_encode_query_value("a:b"), "a%3Ab");
        // `&` and `=` must be escaped too.
        assert_eq!(percent_encode_query_value("a&b=c"), "a%26b%3Dc");
        // Unreserved characters pass through.
        assert_eq!(percent_encode_query_value("deny-logger"), "deny-logger");
        assert_eq!(percent_encode_query_value("query_denied"), "query_denied");
    }

    #[test]
    fn events_split_jsonl_lines_handles_cross_chunk_split() {
        // Simulate the body arriving as two frames. The server sends
        // one-line-per-frame in the happy path, but chunked transfer
        // may slice any line at any byte boundary.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"{\"a\":1}\n{\"b\":");
        let lines = split_jsonl_lines(&mut buf);
        assert_eq!(lines, vec!["{\"a\":1}".to_string()]);
        // The partial `{"b":` must stay in the buffer for the next chunk.
        assert_eq!(buf.as_slice(), b"{\"b\":");

        // Second chunk completes the second line and adds a third.
        buf.extend_from_slice(b"2}\n{\"c\":3}");
        let lines = split_jsonl_lines(&mut buf);
        assert_eq!(lines, vec!["{\"b\":2}".to_string()]);
        // No trailing newline — `{"c":3}` stays buffered.
        assert_eq!(buf.as_slice(), b"{\"c\":3}");
    }

    #[test]
    fn events_split_jsonl_lines_returns_empty_on_no_newline() {
        let mut buf: Vec<u8> = b"partial".to_vec();
        let lines = split_jsonl_lines(&mut buf);
        assert!(lines.is_empty());
        assert_eq!(buf.as_slice(), b"partial");
    }

    #[test]
    fn events_split_jsonl_lines_handles_multiple_lines_in_one_chunk() {
        let mut buf: Vec<u8> = b"{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n".to_vec();
        let lines = split_jsonl_lines(&mut buf);
        assert_eq!(
            lines,
            vec![
                "{\"a\":1}".to_string(),
                "{\"b\":2}".to_string(),
                "{\"c\":3}".to_string(),
            ]
        );
        assert!(
            buf.is_empty(),
            "buffer must be drained when input ends in `\\n`"
        );
    }

    #[test]
    fn events_format_table_header_has_all_columns() {
        let h = format_table_header();
        for col in ["TIME", "SESSION", "LAYER", "EVENT", "HOST:PORT", "DETAIL"] {
            assert!(h.contains(col), "header missing `{col}`: {h}");
        }
    }

    #[test]
    fn events_format_table_row_for_dns_query_denied() {
        // Build a DNS deny event via the canonical wire shape.
        let line = serde_json::json!({
            "layer": "dns",
            "timestamp": "2026-04-22T12:00:00.500Z",
            "session": "abc12345-feed-dead-beef-cafebabe0000",
            "event": "query_denied",
            "query": "example.com",
            "qtype": "A",
            "reason": "no_matching_rule",
        })
        .to_string();

        let row = format_table_row(&line, false);
        assert!(row.contains("2026-04-22T12:00:00.500Z"), "time col: {row}");
        assert!(
            row.contains("abc12345"),
            "session col truncated to 8: {row}"
        );
        assert!(row.contains("dns"), "layer col: {row}");
        assert!(row.contains("query_denied"), "event col: {row}");
        assert!(row.contains("example.com"), "host col uses query: {row}");
        assert!(
            row.contains("reason=no_matching_rule"),
            "detail includes reason: {row}"
        );
        assert!(
            row.contains("decision=deny"),
            "detail tags the decision: {row}"
        );
        // No ANSI when colorize=false even for deny rows.
        assert!(
            !row.contains("\x1b["),
            "non-tty path must not inject ANSI escapes: {row}"
        );
    }

    #[test]
    fn events_format_table_row_colorises_deny_rows_when_tty() {
        let line = serde_json::json!({
            "layer": "dns",
            "timestamp": "2026-04-22T12:00:00.500Z",
            "session": "abc12345-feed-dead-beef-cafebabe0000",
            "event": "query_denied",
            "query": "example.com",
            "qtype": "A",
            "reason": "no_matching_rule",
        })
        .to_string();

        let row = format_table_row(&line, true);
        assert!(
            row.starts_with("\x1b[31m"),
            "deny row must start with red ANSI: {row:?}"
        );
        assert!(
            row.ends_with("\x1b[0m"),
            "deny row must end with reset ANSI: {row:?}"
        );
    }

    #[test]
    fn events_format_table_row_does_not_colorise_allow_rows() {
        let line = serde_json::json!({
            "layer": "dns",
            "timestamp": "2026-04-22T12:00:00.500Z",
            "session": "abc12345",
            "event": "query_allowed",
            "query": "example.com",
            "qtype": "A",
            "resolved_ips": ["203.0.113.1"],
        })
        .to_string();

        let row = format_table_row(&line, true);
        // Allow rows must not wrap in ANSI regardless of colorize flag.
        assert!(
            !row.contains("\x1b["),
            "allow row must not carry ANSI even with colorize=true: {row:?}"
        );
    }

    #[test]
    fn events_format_table_row_falls_back_to_bang_prefix_for_unparseable() {
        // `lifecycle.ring_buffer_lag` is a streaming-only synthetic whose
        // shape does not match `EventDto` (no `body` tagged-union wire
        // form). The CLI must print the raw line prefixed with `!` rather
        // than dropping it.
        let raw = r#"{"layer":"lifecycle","event":"ring_buffer_lag","skipped":3,"timestamp":"2026-04-22T12:00:00.500Z"}"#;
        let row = format_table_row(raw, false);
        assert!(
            row.starts_with("! "),
            "unparseable fallback must start with `! `: {row}"
        );
        assert!(
            row.contains(raw),
            "fallback carries the raw line verbatim: {row}"
        );
    }

    #[test]
    fn events_format_table_row_bang_prefix_for_empty_or_garbage() {
        assert_eq!(format_table_row("", false), "! ");
        let garbage = "not json at all";
        assert_eq!(format_table_row(garbage, false), format!("! {garbage}"));
    }
}
