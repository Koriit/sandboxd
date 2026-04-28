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
    PropagationStatusResponse, SessionDto, SessionHealth, SessionMountInfo, SessionNetworkInfo,
    UpdatePolicyRequest,
};
use tokio::net::UnixStream;

use sandbox_cli::backend::{
    BackendKindArg, BackendResolutionInputs, FeatureMismatchContext, RebuildImageBackend,
    load_cli_config, render_feature_mismatch, render_isolation_warning,
    render_no_cache_rejection_for_container, resolve_backend,
};
use sandbox_cli::backends_cache::BackendsCache;
use sandbox_cli::presets::{self, Catalog, ParsedInvocation, Preset, PresetSource};

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
        /// Number of CPU cores. Defaults are backend-specific:
        /// `lima` falls back to 2 cores; `container` falls back to
        /// the daemon's host-80% ceiling (spec § "Resource defaults").
        /// Omit to take the backend default; pass an explicit value
        /// to override.
        #[arg(long)]
        cpus: Option<u32>,
        /// Memory in megabytes. Defaults are backend-specific:
        /// `lima` falls back to 4096 MB; `container` falls back to
        /// the daemon's host-80% ceiling (spec § "Resource defaults").
        /// Omit to take the backend default; pass an explicit value
        /// to override.
        #[arg(long)]
        memory: Option<u32>,
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
        /// Backend that should host the session (`lima` or `container`).
        ///
        /// Mutually exclusive with `--lite`. When neither is set, the
        /// backend is resolved from `SANDBOX_DEFAULT_BACKEND`, the
        /// per-user config (`~/.config/sandboxd/config.json` →
        /// `default_backend`), and finally the hardcoded default
        /// `lima`. See spec § "CLI & UX → Invocation".
        #[arg(long, value_enum)]
        backend: Option<BackendKindArg>,
        /// Sugar for `--backend container` — the container ("lite")
        /// backend.
        ///
        /// Mutually exclusive with `--backend`.
        #[arg(long, conflicts_with = "backend")]
        lite: bool,
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
    ///
    /// With `-v`/`--verbose`, appends a `Capabilities` block per session
    /// showing the daemon-advertised capability matrix for that
    /// session's backend (fetched once per invocation via
    /// `GET /backends`). Failure to fetch the matrix degrades gracefully
    /// — the rest of the describe output is unaffected.
    Describe {
        /// One or more session names or IDs to describe.
        #[arg(required = true)]
        sessions: Vec<String>,
        /// Append the daemon-advertised capability matrix for each
        /// session's backend. Spec § "sandbox inspect" → `-v` view.
        #[arg(short, long)]
        verbose: bool,
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
    /// Rebuild the pre-baked backend image(s).
    ///
    /// Spec § "`rebuild-image`: extend the existing flat command":
    /// `--backend` selects which backend's image to rebuild
    /// (`lima`, `container`, or `all`; default `all`); `--no-cache`
    /// passes through to `docker build --no-cache` for the container
    /// path and to the equivalent cache-bust mechanism for Lima's
    /// golden image rebuild.
    RebuildImage {
        /// Which backend's image to rebuild.
        ///
        /// `all` (the default) rebuilds every installed backend's
        /// image. For Lima, "rebuild" means cache-bust the golden VM
        /// image; for container, it means rebuild the lite image.
        #[arg(long, value_enum, default_value_t = RebuildImageBackend::All)]
        backend: RebuildImageBackend,
        /// Cache-bust the rebuild.
        ///
        /// Container: passes `--no-cache` to `docker build`. Lima:
        /// already cache-busts on every rebuild (delete-then-build
        /// the golden VM), so this flag is a no-op for Lima but kept
        /// for symmetry with the container path.
        #[arg(long)]
        no_cache: bool,
    },
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
    /// Report policy-propagation status for a session.
    ///
    /// Queries `GET /sessions/{id}/policy/propagation-status` and
    /// prints the result. Use `--wait` to poll until the latest
    /// policy-apply has reached steady state across all three
    /// enforcement layers (nftables, Envoy, mitmproxy/CoreDNS).
    ///
    /// Exits 0 when the latest policy-apply has propagated, or when
    /// no policy has ever been applied (nothing to wait for). Exits
    /// non-zero on daemon errors. With `--wait`, exits non-zero if the
    /// deadline passes before the policy propagates; the E2E suite and
    /// scripts use this to fail fast instead of time.sleep()-ing.
    Status {
        /// Session name or ID.
        session: String,
        /// Poll until the latest apply has propagated or the timeout
        /// elapses. Without this flag the command reads the status
        /// once and exits.
        #[arg(long)]
        wait: bool,
        /// Deadline for `--wait`. Accepts a human-readable duration:
        /// plain seconds (`60`), seconds with `s` (`60s`), minutes
        /// (`2m`), hours (`1h`), or milliseconds (`500ms`). Ignored
        /// unless `--wait` is set.
        #[arg(long, default_value = "60s")]
        timeout: String,
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

/// Build the `POST /sessions` request from a `Command::Create` and the
/// backend the preflight chose.
///
/// Pulled out of [`build_request`] because the resolved backend is the
/// product of an async preflight (`/backends` fetch + `SessionSpec`
/// validation) that cannot run inside `build_request`'s sync interface.
/// The dispatch in `main` calls [`dispatch_create_preflight`] first
/// and then this function with the result, threading the validated
/// backend choice into the wire body.
///
/// Panics (via `unreachable!`) if `command` is not `Command::Create` —
/// callers must only invoke this for the Create variant.
fn build_create_request_body(
    command: &Command,
    resolved_backend: sandbox_core::BackendKind,
) -> Request<String> {
    let Command::Create {
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
        backend: _backend,
        lite: _lite,
    } = command
    else {
        unreachable!("build_create_request_body called with non-Create command");
    };

    let mut body = serde_json::Map::new();
    if let Some(n) = name {
        body.insert("name".into(), serde_json::Value::String(n.clone()));
    }
    // M11-S4 Phase 4D-pre gap #4: only stamp `cpus`/`memory_mb` on the
    // wire when the operator passed an explicit value. Older daemons
    // that ignore the absence treat it as "Lima-leaning 2/4096"; newer
    // daemons fold absence into the container backend's host-80%
    // default. Always sending a concrete number (the pre-fix
    // `default_value_t` shape) made the host-80% ceiling unreachable
    // through the public CLI. Forward-compatible with old daemons via
    // their existing `unwrap_or` Lima fallback path.
    if let Some(v) = cpus {
        body.insert("cpus".into(), serde_json::json!(*v));
    }
    if let Some(v) = memory {
        body.insert("memory_mb".into(), serde_json::json!(*v));
    }
    body.insert("disk_gb".into(), serde_json::json!(*disk));
    if let Some(t) = template {
        body.insert("template".into(), serde_json::Value::String(t.clone()));
    }
    // Compose `--policy` (optional file) with any `--preset`
    // invocations (repeatable) into a single effective policy.
    //
    // - If neither is present, omit `policy` from the body
    //   (legacy "no policy" shape — server defaults to fail-closed).
    // - If only `--policy` is present, parse it and pass it through
    //   (matches the pre-M10-S5 wire shape).
    // - If `--preset` is present (with or without `--policy`),
    //   expand presets client-side, merge them with the file, and
    //   send the effective `Policy` JSON plus `source_presets` as a
    //   sibling field for audit.
    //
    // Preset errors short-circuit to stderr + exit(1) BEFORE any
    // Unix-socket work — this matches the spec invariant "the daemon
    // never sees a malformed preset invocation".
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
    // M11-S4 Phase 4A: stamp the resolved backend onto the request
    // body. The daemon's `CreateSessionRequest` carries this as
    // `Option<BackendKind>` (added in M11-S3 Phase 3D); older daemons
    // that ignore the field default to Lima, which is consistent with
    // the resolver's tier-5 fallback. Always send the field (even for
    // Lima) so the daemon-side audit / persistence sees an explicit
    // choice rather than relying on the default.
    body.insert(
        "backend".into(),
        serde_json::json!(resolved_backend.as_str()),
    );
    let body_str = serde_json::Value::Object(body).to_string();
    Request::builder()
        .method("POST")
        .uri("/sessions")
        .header("content-type", "application/json")
        .body(body_str)
        .expect("failed to build request")
}

/// Build the HTTP request for the given CLI command.
///
/// Returns `None` for commands that are handled specially (e.g. `ssh`).
fn build_request(command: &Command) -> Option<Request<String>> {
    let req = match command {
        Command::Create { .. } => {
            // M11-S4 Phase 4A: the `Create` branch is owned by
            // [`build_create_request_body`] because the resolved
            // backend (computed in the async preflight that runs
            // before this function) must be threaded into the
            // request body. `build_request`'s sync interface cannot
            // host that fetch, so `main` short-circuits Create
            // before this match is reached. Returning `None` here is
            // defensive: a future caller that forgets the bypass
            // hits the same "unhandled command" path `ssh` / `cp` /
            // `logs` use, instead of silently sending an unvalidated
            // request.
            return None;
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
            PolicyAction::Status { .. } => {
                // Handled by `handle_policy_status` in `main()` before
                // `build_request` is reached. The status command owns
                // its own polling loop and exit-code mapping, which the
                // generic request/response pipeline cannot express.
                unreachable!(
                    "`sandbox policy status ...` is handled client-side \
                     in main() before build_request"
                );
            }
        },
        Command::Health { session } => Request::builder()
            .method("GET")
            .uri(format!("/sessions/{session}/health"))
            .body(String::new())
            .expect("failed to build request"),
        Command::RebuildImage { .. } => {
            // M11-S4 Phase 4C: rebuild-image fans out one HTTP call per
            // selected backend (spec § "rebuild-image"). The single-
            // request shape `build_request` returns cannot express that;
            // `main` short-circuits this command into
            // [`dispatch_rebuild_image`] before reaching this match,
            // mirroring how `Create` is hosted by
            // [`build_create_request_body`]. Returning `None` here is
            // defensive: a future caller that forgets the bypass hits
            // the same "unhandled command" path `ssh` / `cp` / `logs`
            // use, instead of silently sending the wrong request shape.
            return None;
        }
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
///
/// Writes to stdout via the `Write` interface so unit tests can capture
/// the rendered output into a buffer without wrestling stdout. The
/// production caller passes a locked `std::io::stdout()` handle.
fn display_sessions_table(sessions: &[SessionDto]) {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    write_sessions_table(&mut handle, sessions);
}

/// Render the `sandbox list` (a.k.a. `ps` / `ls`) table to an arbitrary
/// writer. Pulled out of [`display_sessions_table`] so unit tests can
/// capture the output into a buffer; production wraps `stdout`.
///
/// Column ordering: `ID NAME STATE BACKEND AGENT GATEWAY CREATED`. The
/// `BACKEND` column lands between `STATE` and `AGENT` so the operator's
/// eye scans backend-affinity adjacent to the lifecycle state — both
/// answer the same kind of question ("what *is* this session?"). 9
/// chars is enough to print `container` without truncation.
fn write_sessions_table(out: &mut dyn std::io::Write, sessions: &[SessionDto]) {
    if sessions.is_empty() {
        let _ = writeln!(out, "No sessions found.");
        return;
    }

    let _ = writeln!(
        out,
        "{:<12}  {:<16}  {:<10}  {:<9}  {:<11}  {:<11}  CREATED",
        "ID", "NAME", "STATE", "BACKEND", "AGENT", "GATEWAY"
    );

    for session in sessions {
        let name = session.name.as_deref().unwrap_or("-");
        let state = session.state.to_string();
        let backend = session.backend.as_str();
        let agent = session.guest_agent_status.as_deref().unwrap_or("-");
        let gateway = session.gateway_status.as_deref().unwrap_or("-");
        let created = format_relative_time(&session.created_at);

        let _ = writeln!(
            out,
            "{:<12}  {:<16}  {:<10}  {:<9}  {:<11}  {:<11}  {created}",
            session.id, name, state, backend, agent, gateway
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
        Command::RebuildImage { .. } => {
            // Phase 4C: per-backend dispatch owns its own success /
            // error reporting in `dispatch_rebuild_image`; reaching
            // `handle_response` for a rebuild-image command means the
            // dispatch bypass at the top of `main` was skipped. Treat
            // this the same as the `ssh` / `cp` family (also dispatch-
            // bypass commands).
            unreachable!("rebuild-image is handled by dispatch_rebuild_image before send_request");
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

/// Resolution of a `Capabilities` lookup for a single session's backend.
///
/// Carries either the daemon-advertised capability matrix or the error
/// that prevented the lookup. The describe renderer surfaces the error
/// inline ("<capability matrix unavailable: ...>") rather than failing
/// — describe's primary contract is showing session data, capability
/// info is an enhancement (handoff Task 2 plumbing-note).
#[derive(Debug, Clone)]
enum CapabilitiesLookup {
    Available(sandbox_core::Capabilities),
    Unavailable(String),
}

/// Render a slice of `SessionDto` as the human-readable `sandbox describe`
/// output. Separator between sessions is a single blank line.
///
/// Layout follows the spec §2 plus M11-S4 Phase 4B additions:
/// - header block (Session, Name, State, **Backend**, Created, Updated)
/// - `Config:` block
/// - `Runtime:` block
/// - `Network:` block — backend-neutral gateway IP, session IP, and
///   per-session /28 CIDR (M11-S7 Bundle Y / todo #72).
/// - `Mounts:` block — backend-neutral workspace path, host bind
///   source, CA bundle path, and home volume (M11-S7 Bundle Y).
/// - `Policy:` block — either `Policy: none` or a version/count header
///   followed by one indented rule entry per rule.
/// - `Capabilities:` block (only when `verbose_caps` is `Some`) showing
///   the daemon-advertised capability matrix for that session's backend.
///
/// `verbose_caps` is `None` for the default view and `Some(map)` under
/// `-v`. The map keys by backend kind so a multi-session render shows
/// the right matrix per session even when both backends appear in the
/// arg list.
///
/// Timestamps are rendered as absolute UTC plus the existing relative
/// age suffix (e.g. `5m ago`), matching the sample in the spec.
fn render_describe(
    sessions: &[SessionDto],
    verbose_caps: Option<
        &std::collections::HashMap<sandbox_core::backend::BackendKind, CapabilitiesLookup>,
    >,
) -> String {
    let mut out = String::new();
    for (idx, session) in sessions.iter().enumerate() {
        if idx > 0 {
            // Single blank line between session blocks.
            out.push('\n');
        }
        let caps = verbose_caps.and_then(|map| map.get(&session.backend));
        render_describe_one(session, caps, &mut out);
    }
    out
}

fn render_describe_one(
    session: &SessionDto,
    verbose_caps: Option<&CapabilitiesLookup>,
    out: &mut String,
) {
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
    // Spec § "sandbox inspect" — backend prominently alongside session
    // id, state, and IP. `as_str()` matches the wire/persisted spelling
    // (`lima` / `container`).
    let _ = writeln!(out, "Backend:      {}", session.backend.as_str());
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

    render_network_block(session.network.as_ref(), out);
    render_mounts_block(session.mounts.as_ref(), out);

    render_policy_block(session.policy.as_ref(), out);

    if let Some(caps) = verbose_caps {
        // Single blank line between Policy and Capabilities so the
        // block separator pattern matches the rest of the layout.
        out.push('\n');
        render_capabilities_block(caps, out);
    }
}

/// Render the daemon-advertised capability matrix as a key/value block.
///
/// Spec § "sandbox inspect → -v view" — capability matrix is the
/// `Capabilities` struct rendered as a key/value table. The keys are
/// the struct field identifiers (so they match `serde_json` keys an
/// operator may have already seen via `inspect`); values use each
/// nested type's serialize form for stability.
///
/// Only operator-meaningful fields render — `kind` is omitted because
/// the parent block already shows `Backend:` adjacent to `State:`, and
/// duplicating it here would muddy the output.
fn render_capabilities_block(lookup: &CapabilitiesLookup, out: &mut String) {
    use std::fmt::Write as _;
    let _ = writeln!(out, "Capabilities:");
    match lookup {
        CapabilitiesLookup::Unavailable(err) => {
            // The describe command's primary contract is showing
            // session data; cap-matrix failures degrade gracefully so
            // the rest of the output still reaches the operator.
            let _ = writeln!(out, "  <capability matrix unavailable: {err}>");
        }
        CapabilitiesLookup::Available(caps) => {
            let isolation = match caps.isolation {
                sandbox_core::backend::IsolationLevel::Vm => "vm",
                sandbox_core::backend::IsolationLevel::Container => "container",
            };
            let _ = writeln!(out, "  isolation:            {isolation}");
            let _ = writeln!(out, "  nested_virt:          {}", caps.nested_virt);
            let _ = writeln!(out, "  privileged_ops:       {}", caps.privileged_ops);
            let _ = writeln!(out, "  raw_network:          {}", caps.raw_network);
            let _ = writeln!(out, "  hardening_flag:       {}", caps.hardening_flag);
            let _ = writeln!(out, "  per_session_no_cache: {}", caps.per_session_no_cache);
            let _ = writeln!(
                out,
                "  workspace_modes:      {}",
                render_workspace_modes(caps)
            );
        }
    }
}

/// Render a `Capabilities`'s `workspace_modes` set as a stable comma-
/// separated list using each kind's `snake_case` serde form. Empty
/// sets render as `-` so the column is never blank.
///
/// Takes the full `Capabilities` (rather than the `EnumSet` directly)
/// so this module need not depend on `enumset` — `sandbox-cli` does not
/// pull the crate in, and re-exporting the type from `sandbox-core`
/// would expand the public surface unnecessarily.
fn render_workspace_modes(caps: &sandbox_core::Capabilities) -> String {
    use sandbox_core::session::WorkspaceModeKind;
    let modes = &caps.workspace_modes;
    if modes.is_empty() {
        return "-".to_string();
    }
    let mut parts: Vec<&'static str> = Vec::new();
    // List explicitly in declaration order so the rendered string is
    // stable across runs — keeps the byte-equality test contract simple.
    if modes.contains(WorkspaceModeKind::Shared) {
        parts.push("shared");
    }
    if modes.contains(WorkspaceModeKind::Clone) {
        parts.push("clone");
    }
    parts.join(", ")
}

/// Render the backend-neutral session networking block (M11-S7
/// Bundle Y / todo #72). Always emitted so operators see a stable
/// `Network:` heading per session block; missing data renders as
/// `none` (matching the `Policy: none` shape) rather than absent.
///
/// Field labels mirror the spec's "operator-readable" naming so a
/// human reader and the e2e suite parse the same surface — the e2e
/// suite uses the JSON output of `sandbox inspect`, so the field
/// *contents* (IPs / CIDR strings) are what matters for tests; the
/// label format here is purely for `sandbox describe`.
fn render_network_block(network: Option<&SessionNetworkInfo>, out: &mut String) {
    use std::fmt::Write as _;
    match network {
        None => {
            let _ = writeln!(out, "Network: none");
        }
        Some(n) => {
            let _ = writeln!(out, "Network:");
            let _ = writeln!(out, "  Gateway IP:  {}", n.gateway_ip);
            let _ = writeln!(out, "  Session IP:  {}", n.session_ip);
            let _ = writeln!(out, "  Subnet:      {}", n.session_subnet_cidr);
        }
    }
    out.push('\n');
}

/// Render the backend-neutral session mount-surface block (M11-S7
/// Bundle Y). Same emission contract as [`render_network_block`]:
/// always emitted, with `none` fallback when the daemon has no
/// mount info to surface.
///
/// `workspace_host_path`, `ca_bundle_path`, and `home_volume` are
/// `Option<String>` on the wire and render as `-` when absent so
/// each row stays present (operators never have to wonder if a row
/// is missing because of a bug).
fn render_mounts_block(mounts: Option<&SessionMountInfo>, out: &mut String) {
    use std::fmt::Write as _;
    match mounts {
        None => {
            let _ = writeln!(out, "Mounts: none");
        }
        Some(m) => {
            let _ = writeln!(out, "Mounts:");
            let _ = writeln!(out, "  Workspace:        {}", m.workspace_path);
            let _ = writeln!(
                out,
                "  Workspace host:   {}",
                m.workspace_host_path.as_deref().unwrap_or("-")
            );
            let _ = writeln!(
                out,
                "  CA bundle:        {}",
                m.ca_bundle_path.as_deref().unwrap_or("-")
            );
            let _ = writeln!(
                out,
                "  Home volume:      {}",
                m.home_volume.as_deref().unwrap_or("-")
            );
        }
    }
    out.push('\n');
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
        format!("  [{idx}] {action:<16}{target}")
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

/// Parse a human-readable duration into [`Duration`].
///
/// Accepted forms:
/// - plain number: interpreted as seconds (`60` → 60s)
/// - suffixed: `500ms`, `30s`, `2m`, `1h`
///
/// Returns `Err(String)` with a user-facing message on any parse
/// failure — the CLI surfaces this directly on stderr.
///
/// Centralised here rather than pulled in as a dep because this is the
/// only duration parse site in the CLI today, and the grammar is
/// small enough that a handwritten parser is cheaper than a crate.
fn parse_duration_arg(s: &str) -> Result<Duration, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("empty duration".to_string());
    }
    // Longest-suffix-first so `ms` wins over `s`.
    let (num_str, multiplier_ms): (&str, u64) = if let Some(rest) = trimmed.strip_suffix("ms") {
        (rest, 1)
    } else if let Some(rest) = trimmed.strip_suffix('s') {
        (rest, 1_000)
    } else if let Some(rest) = trimmed.strip_suffix('m') {
        (rest, 60 * 1_000)
    } else if let Some(rest) = trimmed.strip_suffix('h') {
        (rest, 60 * 60 * 1_000)
    } else {
        // No suffix — treat as seconds to match common CLI ergonomics
        // (`--timeout 60` and `--timeout 60s` behave identically).
        (trimmed, 1_000)
    };
    let n: u64 = num_str
        .trim()
        .parse()
        .map_err(|e| format!("invalid duration '{s}': {e}"))?;
    Ok(Duration::from_millis(n.saturating_mul(multiplier_ms)))
}

/// Handle the `sandbox policy status [--wait] [--timeout ...]`
/// subcommand.
///
/// Client-side polling loop that queries
/// `GET /sessions/{session}/policy/propagation-status` until either:
/// - the response reports `propagated=true` (exit 0)
/// - `--wait` is unset (always exit after one query)
/// - the deadline passes (`--wait` + `--timeout` elapsed, exit 1)
/// - the daemon returns a non-2xx error (exit 1)
///
/// Polling cadence is fixed at 200ms to keep the round-trip latency
/// negligible vs. the actual DNS propagation loop (which cycles on
/// the order of seconds). The loop streams a short human-readable
/// status line on every poll so scripts and operators can see
/// progress without running the full suite.
async fn handle_policy_status(socket_path: &str, session: &str, wait: bool, timeout_str: &str) {
    let timeout = if wait {
        match parse_duration_arg(timeout_str) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        }
    } else {
        Duration::from_secs(0)
    };

    // Fixed poll cadence; empirically short enough that the CLI never
    // shows a user-visible gap between the DNS loop completing and the
    // next poll observing `propagated=true`.
    const POLL_INTERVAL: Duration = Duration::from_millis(200);

    let start = std::time::Instant::now();
    loop {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/sessions/{session}/policy/propagation-status"))
            .body(String::new())
            .expect("failed to build request");

        match send_request(socket_path, req).await {
            Ok((status, body)) => {
                if !status.is_success() {
                    if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
                        eprintln!("Error: {}", api_err.error);
                    } else {
                        eprintln!("Error ({status}): {body}");
                    }
                    process::exit(1);
                }
                let resp: PropagationStatusResponse = match serde_json::from_str(&body) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Error: failed to parse propagation-status response: {e}");
                        process::exit(1);
                    }
                };
                print_propagation_status(&resp);
                if resp.propagated {
                    return;
                }
                // No apply has ever happened — there is nothing to
                // propagate, so treat it as success to keep scripts
                // idempotent. A `--wait` that expected a propagation
                // should provide a session that has had a policy
                // applied.
                if resp.expected_hash.is_none() {
                    return;
                }
                if !wait {
                    // One-shot read: exit non-zero to signal
                    // "polled once, not yet propagated" so callers
                    // can chain `|| sleep && retry`.
                    process::exit(2);
                }
                if start.elapsed() >= timeout {
                    eprintln!(
                        "Error: policy did not propagate within {}",
                        humanize_duration(timeout)
                    );
                    process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("{e}");
                process::exit(1);
            }
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Render a one-line human-readable status suitable for stdout.
///
/// Intentionally terse so `--wait` loops can print every poll without
/// scrolling operator terminals off the screen.
fn print_propagation_status(resp: &PropagationStatusResponse) {
    let expected = resp.expected_hash.as_deref().map(short_hash).unwrap_or("-");
    let propagated = resp
        .propagated_hash
        .as_deref()
        .map(short_hash)
        .unwrap_or("-");
    println!(
        "propagated={} expected={expected} actual={propagated} age={}s",
        resp.propagated, resp.seconds_since_apply
    );
}

/// Truncate a hex hash to 12 chars for user-facing output. Hashes are
/// hex-encoded SHA-256 (64 chars); the first 12 is unambiguous for
/// any real working set and fits on an 80-column terminal.
fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

/// Render a [`Duration`] back into its shortest human-readable form.
/// Used only for the "did not propagate within ..." error line.
fn humanize_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms.is_multiple_of(1000) {
        let secs = ms / 1000;
        if secs.is_multiple_of(3600) {
            format!("{}h", secs / 3600)
        } else if secs.is_multiple_of(60) {
            format!("{}m", secs / 60)
        } else {
            format!("{secs}s")
        }
    } else {
        format!("{ms}ms")
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
///
/// When `verbose` is set, additionally fetches the daemon's capability
/// matrix once via `BackendsCache` and appends a `Capabilities:` block
/// per session keyed off `SessionDto.backend`. Cache failures degrade
/// gracefully — describe's primary contract is showing session data.
async fn handle_describe(socket_path: &str, sessions: &[String], verbose: bool) {
    let dtos = match fetch_sessions_parallel(socket_path, sessions).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    let caps_map = if verbose {
        Some(fetch_capabilities_for(&dtos, socket_path).await)
    } else {
        None
    };

    let rendered = render_describe(&dtos, caps_map.as_ref());
    // `print!` so we do not add a trailing blank line beyond what the
    // renderer already emitted (the last block ends with `\n` after the
    // last `writeln!` line).
    print!("{rendered}");
}

/// Fetch the capability matrix for every backend referenced by the
/// supplied DTOs. The cache is constructed per-invocation per spec
/// "exactly one /backends fetch per CLI invocation" — a single
/// [`BackendsCache`] services every session in the slice.
///
/// Cache or per-backend failures surface as
/// [`CapabilitiesLookup::Unavailable`] entries so the renderer can
/// inline the error rather than aborting the entire describe.
async fn fetch_capabilities_for(
    dtos: &[SessionDto],
    socket_path: &str,
) -> std::collections::HashMap<sandbox_core::backend::BackendKind, CapabilitiesLookup> {
    let mut map: std::collections::HashMap<sandbox_core::backend::BackendKind, CapabilitiesLookup> =
        std::collections::HashMap::new();
    let mut cache = BackendsCache::new(socket_path);
    let mut seen: Vec<sandbox_core::backend::BackendKind> = Vec::new();
    for dto in dtos {
        if seen.contains(&dto.backend) {
            continue;
        }
        seen.push(dto.backend);
        let lookup = match cache.get(dto.backend).await {
            Ok(Some(c)) => CapabilitiesLookup::Available(c.clone()),
            Ok(None) => CapabilitiesLookup::Unavailable(format!(
                "daemon did not advertise the {} backend on /backends",
                dto.backend
            )),
            Err(e) => CapabilitiesLookup::Unavailable(e.to_string()),
        };
        map.insert(dto.backend, lookup);
    }
    map
}

/// Plan the program + argv `sandbox ssh` shells out to for a given
/// session backend.
///
/// Pulled out of [`handle_ssh`] as a pure function so unit tests can
/// drive the dispatch without spawning a subprocess. The shape is
/// `(program, args)` where `args` already includes the session-name
/// arg and any user-supplied trailing command — i.e. the caller can
/// pass the values straight to [`std::process::Command`].
///
/// Backend-specific shapes (spec § "Lifecycle"):
///
/// - **Lima** — `limactl shell sandbox-<id> [-- <cmd>...]`. The
///   pre-existing path; the `--` separator is omitted when the user
///   did not pass a trailing command so an interactive shell starts.
/// - **Container** — `docker exec -i [-t] sandbox-<id> [<cmd>...]`.
///   Mirrors `ContainerRuntime::exec_interactive` (`docker exec -i …`).
///   The `-t` (allocate TTY) flag is added only when the parent
///   process's stdin is itself a terminal — `docker exec -t` fails
///   fast with "cannot attach stdin to a TTY-enabled container
///   because stdin is not a terminal" when the caller is e.g. a
///   pytest subprocess or any other pipe-fed parent. No `--user`:
///   the container is created with `--user uid:gid` already, and
///   `docker exec` inherits that identity by default.
fn plan_ssh_command(
    backend: sandbox_core::backend::BackendKind,
    session_id: &sandbox_core::SessionId,
    command: &[String],
    stdin_is_tty: bool,
) -> (&'static str, Vec<String>) {
    let target_name = format!("sandbox-{session_id}");
    match backend {
        sandbox_core::backend::BackendKind::Lima => {
            let mut args = vec!["shell".to_string(), target_name];
            if !command.is_empty() {
                args.push("--".to_string());
                args.extend(command.iter().cloned());
            }
            ("limactl", args)
        }
        sandbox_core::backend::BackendKind::Container => {
            // Always pass `-i` so stdin is forwarded to the in-container
            // process. Only add `-t` when the caller's stdin is a real
            // TTY: `docker exec -t` aborts at startup if stdin isn't a
            // terminal (e.g. pytest's PIPE stdin), so passing it
            // unconditionally would break every non-interactive caller.
            let flags = if stdin_is_tty { "-it" } else { "-i" };
            let mut args = vec!["exec".to_string(), flags.to_string(), target_name];
            if !command.is_empty() {
                args.extend(command.iter().cloned());
            }
            ("docker", args)
        }
    }
}

/// Handle the `ssh` subcommand: resolve session via daemon API, then
/// exec the backend-appropriate shell helper (`limactl shell` for Lima,
/// `docker exec -it` for Container).
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

    // M11-S4 Phase 4D-pre gap #2: dispatch on the persisted backend so
    // container sessions reach `docker exec` instead of failing with
    // `limactl shell sandbox-<id>: no such instance`.
    //
    // `stdin_is_tty` controls whether `docker exec` gets `-t`: passing
    // `-t` when our own stdin is not a terminal (e.g. piped from a
    // test harness) causes docker to abort with "cannot attach stdin
    // to a TTY-enabled container because stdin is not a terminal".
    let stdin_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let (program, args) = plan_ssh_command(
        session_resp.backend,
        &session_resp.id,
        command,
        stdin_is_tty,
    );

    let mut cmd = std::process::Command::new(program);
    cmd.args(&args);

    // Use .status() to inherit stdin/stdout/stderr for interactive use.
    match cmd.status() {
        Ok(exit_status) => {
            process::exit(exit_status.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("Failed to execute {program}: {e}");
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
    let layer_col = format!("{layer:<TABLE_LAYER_WIDTH$}");
    let event_col = format!("{event:<TABLE_EVENT_WIDTH$}");
    let host_col = format!("{host_port:<TABLE_HOSTPORT_WIDTH$}");
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
        format!("{ts:<TABLE_TIME_WIDTH$}")
    }
}

/// Truncate session_id to an 8-char short ID for the SESSION column.
fn format_session_column(session: &str) -> String {
    if session.is_empty() {
        return format!("{:<w$}", "-", w = TABLE_SESSION_WIDTH);
    }
    let short: String = session.chars().take(TABLE_SESSION_WIDTH).collect();
    format!("{short:<TABLE_SESSION_WIDTH$}")
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
    eprintln!("Warning: base image is {age_days} days old.");
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

/// M11-S4 Phase 4C: per-backend dispatcher for `sandbox rebuild-image`.
///
/// Spec § "`rebuild-image`: extend the existing flat command" requires
/// fanning out one HTTP call per selected backend, prefixing per-
/// backend errors with `rebuild-image[<kind>]:`, and exiting non-zero
/// if any selected backend fails. The fan-out is best-effort —
/// remaining backends still run after one fails, so the operator sees
/// every error in a single invocation rather than chasing them one
/// rebuild at a time.
///
/// Process exit semantics:
/// - All selected backends succeed → exit 0.
/// - At least one backend fails → exit 1 (after attempting every
///   selected backend).
async fn dispatch_rebuild_image(socket_path: &str, backend: RebuildImageBackend, no_cache: bool) {
    // Drive the dispatcher through the production HTTP layer; the
    // unit tests below substitute a fake closure to drive the loop
    // without a real Unix socket.
    let result = run_rebuild_image_dispatch(backend, no_cache, |kind, body| {
        let socket = socket_path.to_string();
        Box::pin(async move { send_rebuild_image_request(&socket, kind, body).await })
    })
    .await;
    if !result.all_ok {
        process::exit(1);
    }
}

/// Outcome of [`run_rebuild_image_dispatch`]. Two return signals: the
/// per-backend stderr lines (already formatted with the spec's
/// `rebuild-image[<kind>]:` prefix) and a final all-or-some flag that
/// drives the exit code.
#[derive(Debug, Default, PartialEq, Eq)]
struct RebuildDispatchOutcome {
    /// `true` iff every selected backend's HTTP call succeeded.
    all_ok: bool,
    /// One stderr line per backend, in dispatch order. Pre-formatted
    /// per spec ("rebuild-image[<kind>]: ..." for failures, plain
    /// status for successes).
    lines: Vec<String>,
}

/// Inner dispatch loop, pulled out of [`dispatch_rebuild_image`] so
/// the unit tests can substitute the HTTP call.
///
/// `send` is the per-backend transport: it receives the
/// [`BackendKind`] and the JSON body string the daemon expects,
/// returns either the daemon's success body (which is currently a
/// short status string) or an error message ready to splice into the
/// `rebuild-image[<kind>]:` prefix.
async fn run_rebuild_image_dispatch<F>(
    backend: RebuildImageBackend,
    no_cache: bool,
    mut send: F,
) -> RebuildDispatchOutcome
where
    F: FnMut(
        sandbox_core::backend::BackendKind,
        String,
    )
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send>>,
{
    let kinds = backend.into_kinds();
    let mut all_ok = true;
    let mut lines: Vec<String> = Vec::with_capacity(kinds.len());

    for kind in kinds {
        // The wire body is `{"backend": "<kind>", "no_cache": <bool>}`
        // per Phase 4C — JSON-only config / wire (CLAUDE.md). The
        // daemon defaults an empty body to lima/no_cache=false for
        // backwards compat with older CLIs; explicit-body callers
        // (this CLI from Phase 4C onwards) always send the full
        // shape so the daemon side never has to guess.
        let body = serde_json::json!({
            "backend": kind.as_str(),
            "no_cache": no_cache,
        })
        .to_string();
        eprintln!("rebuild-image[{kind}]: rebuilding...");
        match send(kind, body).await {
            Ok(_) => {
                lines.push(format!("rebuild-image[{kind}]: done"));
                eprintln!("rebuild-image[{kind}]: done");
            }
            Err(msg) => {
                all_ok = false;
                let line = format!("rebuild-image[{kind}]: {msg}");
                lines.push(line.clone());
                eprintln!("{line}");
            }
        }
    }

    RebuildDispatchOutcome { all_ok, lines }
}

/// Issue a single per-backend `POST /rebuild-image` with the JSON
/// `body` and reduce the daemon response to either `Ok(body)` (any
/// 2xx) or `Err(msg)` carrying a human-readable failure string.
///
/// On a non-2xx response the daemon ships an `ApiError` JSON with an
/// `error` field; if the parse fails (older daemon, unexpected
/// shape), fall through to a generic `<status>: <body>` rendering so
/// the operator never sees an empty error.
async fn send_rebuild_image_request(
    socket_path: &str,
    _kind: sandbox_core::backend::BackendKind,
    body: String,
) -> Result<String, String> {
    let req = Request::builder()
        .method("POST")
        .uri("/rebuild-image")
        .header("content-type", "application/json")
        .body(body)
        .map_err(|e| format!("failed to build request: {e}"))?;
    let (status, body) = send_request_with_timeout(socket_path, req, CLI_HTTP_TIMEOUT).await?;
    if status.is_success() {
        return Ok(body);
    }
    if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
        return Err(api_err.error);
    }
    Err(format!("{status}: {body}"))
}

/// M11-S4 Phase 4A: pre-flight gate for `sandbox create`.
///
/// Runs the work that must happen before the daemon is contacted, in
/// the order the spec mandates:
///
/// 1. Resolve the backend across the five-tier precedence chain
///    (`--lite`, `--backend`, env, config, hardcoded Lima).
/// 2. If the resolved backend is `Container` and `--no-cache` is set,
///    render the spec's three-line error and exit 2 — this never
///    reaches the daemon.
/// 3. Lazily fetch `/backends` once via [`BackendsCache`] and project
///    the operator's flags into a [`sandbox_core::SessionSpec`].
/// 4. Run [`SessionSpec::validate`] against the cached capabilities;
///    on `Err`, render the spec's `error:`+`help:` shape and exit 2.
///
/// Returns `Ok(())` when every gate passes; the caller proceeds to
/// build the request body and send it. Errors short-circuit by calling
/// `process::exit(2)` directly so the dispatch flow stays linear.
///
/// `cli_yes` mirrors `Cli::yes` — currently unused by the preflight
/// itself but threaded through for symmetry with future "skip
/// confirmation" knobs (the staleness check above already consumes
/// it).
async fn dispatch_create_preflight(
    socket_path: &str,
    backend_arg: Option<BackendKindArg>,
    lite_flag: bool,
    no_hardening: bool,
    no_cache: bool,
    workspace: Option<&str>,
    cli_config_xdg_override: Option<&Path>,
) -> sandbox_core::BackendKind {
    // Tier 4 of the precedence chain — load the per-user CLI config.
    // Spec § "CLI & UX → Config file" treats a missing file as not-an-
    // error and a malformed file as a hard error with a path pointer.
    let cli_config = match load_cli_config(cli_config_xdg_override) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(2);
        }
    };

    // Run the spec's five-tier resolver against the actual env + the
    // loaded config.
    let inputs = BackendResolutionInputs {
        lite_flag,
        backend_flag: backend_arg.map(BackendKindArg::into_kind),
        env_default_backend: std::env::var("SANDBOX_DEFAULT_BACKEND").ok(),
        config_default_backend: cli_config.default_backend,
    };
    let resolved_backend = match resolve_backend(&inputs) {
        Ok(kind) => kind,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(2);
        }
    };

    // Spec § "Isolation warning" (lines 751-762): every container-
    // backed create prints a per-invocation warning to stderr **before**
    // the daemon round-trip. Lima creates emit nothing — the helper
    // returns an empty string in that case, so the unconditional
    // `eprint!` is a no-op for Lima. Emitting here (after the resolver,
    // before any further validation or daemon contact) means the
    // operator sees the warning even if the daemon is slow or
    // unreachable.
    eprint!("{}", render_isolation_warning(resolved_backend));

    // Spec § "CLI & UX → `sandbox create --no-cache` is forbidden on
    // container": the rejection runs *before* the daemon is
    // contacted. Mirrors the daemon-side gate (which lives in
    // `SessionSpec::validate` once SessionSpec carries no_cache) but
    // executes earlier so the operator never burns a round-trip.
    if no_cache && resolved_backend == sandbox_core::BackendKind::Container {
        eprint!("{}", render_no_cache_rejection_for_container(lite_flag));
        process::exit(2);
    }

    // Capability-driven validation: fetch `/backends` once and run
    // `SessionSpec::validate` against the matrix the daemon
    // advertised for the chosen backend. The cache is dropped at the
    // end of this function — Phase 4A only needs one validation call
    // per invocation; later phases that surface capability matrices
    // (inspect -v) will thread the cache through the rest of the
    // dispatch.
    let mut cache = BackendsCache::new(socket_path);
    let caps = match cache.get(resolved_backend).await {
        Ok(Some(c)) => c.clone(),
        Ok(None) => {
            eprintln!(
                "error: daemon did not advertise the {resolved_backend} backend on /backends"
            );
            eprintln!(
                "   help: check that the daemon was built with the {resolved_backend} backend enabled"
            );
            process::exit(2);
        }
        Err(e) => {
            eprintln!("error: failed to load backend capabilities: {e}");
            process::exit(2);
        }
    };

    // Project the args into a SessionSpec for validation.
    let workspace_mode = workspace.and_then(|raw| {
        // The full validation of `--workspace` (path exists, is
        // absolute, etc.) lives later in `build_request` to preserve
        // the existing error wording. Here we only need a kind-bearing
        // value so the capability validator can route to the right
        // `WorkspaceModeKind` arm; an empty payload is fine because
        // `validate` only inspects `kind()`.
        sandbox_core::WorkspaceMode::parse_flag(raw).ok()
    });

    let backend_specific = match resolved_backend {
        sandbox_core::BackendKind::Lima => sandbox_core::BackendSpecific::Lima {
            // The daemon-side `hardened` field defaults to true; the
            // CLI inverts `--no-hardening` to that boolean. Mirror
            // the same logic so the CLI-side validate sees the same
            // effective spec the daemon will.
            hardened: !no_hardening,
            memory_mb: 0,
            cpus: 0,
        },
        sandbox_core::BackendKind::Container => sandbox_core::BackendSpecific::Container {
            memory_mb: 0,
            cpus: 0,
        },
    };
    let spec = sandbox_core::SessionSpec {
        backend_specific,
        workspace_mode,
        repo: None,
        boot_cmd: None,
        template: None,
        disk_gb: None,
    };

    if let Err(unsupported) = spec.validate(&caps) {
        eprint!(
            "{}",
            render_feature_mismatch(
                &unsupported,
                &FeatureMismatchContext {
                    lite_flag_used: lite_flag,
                    no_hardening_flag_used: no_hardening,
                },
            )
        );
        process::exit(2);
    }

    resolved_backend
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
    if let Command::Describe { sessions, verbose } = &cli.command {
        handle_describe(&cli.socket, sessions, *verbose).await;
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

    // `sandbox policy status ...` owns its own polling loop and
    // non-standard exit codes (0 = propagated / never-applied,
    // 1 = daemon error or --wait timeout, 2 = one-shot polled-once
    // not-yet-propagated). Route it before the generic request/
    // response pipeline, which cannot express either the loop or
    // the exit-code mapping.
    if let Command::Policy {
        action:
            PolicyAction::Status {
                session,
                wait,
                timeout,
            },
    } = &cli.command
    {
        handle_policy_status(&cli.socket, session, *wait, timeout).await;
        return;
    }

    // Pre-flight base image staleness check for create commands.
    if let Command::Create { no_cache, .. } = &cli.command {
        if !cli.yes && !*no_cache {
            check_base_image_staleness(&cli.socket).await;
        }
    }

    // M11-S4 Phase 4C: rebuild-image fans out one HTTP call per
    // selected backend (spec § "rebuild-image"). The single-call
    // build_request / send_request flow does not fit a multi-call
    // command, so the dispatcher owns the full request loop, error
    // formatting (`rebuild-image[<kind>]: <msg>` per spec), and
    // exit-code mapping ("non-zero exit if any selected backend
    // fails").
    if let Command::RebuildImage { backend, no_cache } = &cli.command {
        dispatch_rebuild_image(&cli.socket, *backend, *no_cache).await;
        return;
    }

    // M11-S4 Phase 4A: Create has a dedicated dispatch path because
    // the request body depends on a backend choice that is the output
    // of an async preflight (config load → resolver → /backends fetch
    // → SessionSpec validation). Running it here keeps `build_request`
    // sync for every other command and confines the new logic to one
    // explicit branch.
    let req = if let Command::Create {
        backend,
        lite,
        no_hardening,
        no_cache,
        workspace,
        ..
    } = &cli.command
    {
        let resolved = dispatch_create_preflight(
            &cli.socket,
            *backend,
            *lite,
            *no_hardening,
            *no_cache,
            workspace.as_deref(),
            None,
        )
        .await;
        build_create_request_body(&cli.command, resolved)
    } else {
        match build_request(&cli.command) {
            Some(r) => r,
            None => {
                // Should not happen — ssh and logs are handled above.
                eprintln!("Internal error: unhandled command");
                process::exit(1);
            }
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
                cpus: None,
                memory: None,
                disk: 20,
                template: None,
                policy: None,
                preset,
                repo: None,
                boot_cmd: None,
                workspace: None,
                no_hardening: false,
                no_cache: false,
                backend: None,
                lite: false,
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
                assert_eq!(*cpus, Some(4));
                assert_eq!(*memory, Some(8192));
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
            cpus: Some(2),
            memory: Some(4096),
            disk: 20,
            template: None,
            policy: None,
            preset: vec![],
            repo: None,
            boot_cmd: None,
            workspace: None,
            no_hardening: false,
            no_cache: false,
            backend: None,
            lite: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
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
            cpus: Some(4),
            memory: Some(8192),
            disk: 50,
            template: None,
            policy: None,
            preset: vec![],
            repo: None,
            boot_cmd: None,
            workspace: None,
            no_hardening: false,
            no_cache: false,
            backend: None,
            lite: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
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
            cpus: Some(2),
            memory: Some(4096),
            disk: 20,
            template: Some("/tmp/my-template.yaml".into()),
            policy: None,
            preset: vec![],
            repo: None,
            boot_cmd: None,
            workspace: None,
            no_hardening: false,
            no_cache: false,
            backend: None,
            lite: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
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
            cpus: Some(2),
            memory: Some(4096),
            disk: 20,
            template: None,
            policy: None,
            preset: vec![],
            repo: Some("https://github.com/octocat/Hello-World.git".into()),
            boot_cmd: None,
            workspace: None,
            no_hardening: false,
            no_cache: false,
            backend: None,
            lite: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert_eq!(body["repo"], "https://github.com/octocat/Hello-World.git");
        assert!(body.get("boot_cmd").is_none());
    }

    #[test]
    fn build_create_request_with_boot_cmd() {
        let cmd = Command::Create {
            name: Some("with-boot".into()),
            cpus: Some(2),
            memory: Some(4096),
            disk: 20,
            template: None,
            policy: None,
            preset: vec![],
            repo: None,
            boot_cmd: Some("npm install".into()),
            workspace: None,
            no_hardening: false,
            no_cache: false,
            backend: None,
            lite: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
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
            cpus: Some(2),
            memory: Some(4096),
            disk: 20,
            template: None,
            policy: None,
            preset: vec![],
            repo: None,
            boot_cmd: None,
            workspace: None,
            no_hardening: true,
            no_cache: false,
            backend: None,
            lite: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
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
            cpus: Some(2),
            memory: Some(4096),
            disk: 20,
            template: None,
            policy: None,
            preset: vec![],
            repo: None,
            boot_cmd: None,
            workspace: None,
            no_hardening: false,
            no_cache: false,
            backend: None,
            lite: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
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
            cpus: Some(2),
            memory: Some(4096),
            disk: 20,
            template: None,
            policy: None,
            preset: vec![],
            repo: None,
            boot_cmd: None,
            workspace: None,
            no_hardening: false,
            no_cache: true,
            backend: None,
            lite: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
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
            cpus: Some(2),
            memory: Some(4096),
            disk: 20,
            template: None,
            policy: None,
            preset: vec![],
            repo: None,
            boot_cmd: None,
            workspace: None,
            no_hardening: false,
            no_cache: false,
            backend: None,
            lite: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
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

    /// Default invocation: `--backend` defaults to `all`, `--no-cache`
    /// defaults to `false` (spec § "rebuild-image": defaults).
    #[test]
    fn parse_rebuild_image_defaults_to_all_no_cache_false() {
        let cli = Cli::parse_from(["sandbox", "rebuild-image"]);
        match cli.command {
            Command::RebuildImage { backend, no_cache } => {
                assert_eq!(backend, RebuildImageBackend::All);
                assert!(!no_cache);
            }
            other => panic!("expected RebuildImage, got: {other:?}"),
        }
    }

    /// `--backend container --no-cache` is the spec's example shape;
    /// pin both fields make it through the parser.
    #[test]
    fn parse_rebuild_image_backend_container_no_cache() {
        let cli = Cli::parse_from([
            "sandbox",
            "rebuild-image",
            "--backend",
            "container",
            "--no-cache",
        ]);
        match cli.command {
            Command::RebuildImage { backend, no_cache } => {
                assert_eq!(backend, RebuildImageBackend::Container);
                assert!(no_cache);
            }
            other => panic!("expected RebuildImage, got: {other:?}"),
        }
    }

    #[test]
    fn parse_rebuild_image_backend_lima() {
        let cli = Cli::parse_from(["sandbox", "rebuild-image", "--backend", "lima"]);
        match cli.command {
            Command::RebuildImage { backend, no_cache } => {
                assert_eq!(backend, RebuildImageBackend::Lima);
                assert!(!no_cache);
            }
            other => panic!("expected RebuildImage, got: {other:?}"),
        }
    }

    /// `build_request` must short-circuit `RebuildImage` (its multi-call
    /// shape cannot fit the single-request flow); the dispatch happens
    /// in `dispatch_rebuild_image` instead.
    #[test]
    fn build_request_rebuild_image_returns_none() {
        let cmd = Command::RebuildImage {
            backend: RebuildImageBackend::All,
            no_cache: false,
        };
        assert!(
            build_request(&cmd).is_none(),
            "rebuild-image is dispatched separately"
        );
    }

    // -- Rebuild-image dispatch tests ----------------------------------------

    /// Helper that builds a fake `send` closure recording every (kind,
    /// body) pair it sees, returning success or a per-backend error
    /// string. The closure intentionally returns owned `String`s so it
    /// can be passed by `FnMut` into [`run_rebuild_image_dispatch`].
    fn make_recording_sender(
        responses: std::collections::HashMap<
            sandbox_core::backend::BackendKind,
            Result<String, String>,
        >,
        recorder: std::sync::Arc<
            std::sync::Mutex<Vec<(sandbox_core::backend::BackendKind, String)>>,
        >,
    ) -> impl FnMut(
        sandbox_core::backend::BackendKind,
        String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<String, String>> + Send>,
    > {
        move |kind, body| {
            recorder.lock().unwrap().push((kind, body.clone()));
            let outcome = responses
                .get(&kind)
                .cloned()
                .unwrap_or_else(|| Ok("ok".into()));
            Box::pin(async move { outcome })
        }
    }

    /// Spec § "rebuild-image": `--backend all` issues two HTTP
    /// requests in Lima-then-Container order, each with the per-
    /// backend JSON body.
    #[tokio::test]
    async fn dispatch_rebuild_image_all_fans_out_lima_then_container() {
        let recorder = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let send = make_recording_sender(std::collections::HashMap::new(), recorder.clone());
        let outcome = run_rebuild_image_dispatch(RebuildImageBackend::All, false, send).await;
        assert!(outcome.all_ok, "every fake response was Ok");
        let calls = recorder.lock().unwrap().clone();
        assert_eq!(calls.len(), 2, "all → two HTTP calls");
        assert_eq!(calls[0].0, sandbox_core::backend::BackendKind::Lima);
        assert_eq!(calls[1].0, sandbox_core::backend::BackendKind::Container);
        // Spec § "rebuild-image": JSON wire body carries the resolved
        // backend kind plus no_cache.
        let lima_body: serde_json::Value = serde_json::from_str(&calls[0].1).unwrap();
        assert_eq!(lima_body["backend"], serde_json::json!("lima"));
        assert_eq!(lima_body["no_cache"], serde_json::json!(false));
        let container_body: serde_json::Value = serde_json::from_str(&calls[1].1).unwrap();
        assert_eq!(container_body["backend"], serde_json::json!("container"));
        assert_eq!(container_body["no_cache"], serde_json::json!(false));
    }

    /// Per-backend errors must be prefixed with `rebuild-image[<kind>]:`
    /// (spec § "rebuild-image"); a single failing backend forces
    /// `all_ok = false`, but remaining backends still run (best-effort
    /// dispatch — operator sees every error in one invocation).
    #[tokio::test]
    async fn dispatch_rebuild_image_prefixes_per_backend_errors() {
        let recorder = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut responses = std::collections::HashMap::new();
        responses.insert(
            sandbox_core::backend::BackendKind::Lima,
            Err("limactl gone fishing".to_string()),
        );
        // Container left unset → defaults to Ok.
        let send = make_recording_sender(responses, recorder.clone());
        let outcome = run_rebuild_image_dispatch(RebuildImageBackend::All, true, send).await;
        assert!(!outcome.all_ok, "any failure flips all_ok to false");
        // Both backends were still attempted (best-effort dispatch).
        assert_eq!(recorder.lock().unwrap().len(), 2);
        // Lima line carries the spec's prefix shape and the daemon's
        // raw error message.
        assert!(
            outcome
                .lines
                .iter()
                .any(|l| l == "rebuild-image[lima]: limactl gone fishing"),
            "expected lima failure line; got: {:?}",
            outcome.lines
        );
        // Container line is the success shape ("done") because the
        // fake responder returned Ok for it.
        assert!(
            outcome
                .lines
                .iter()
                .any(|l| l == "rebuild-image[container]: done"),
            "expected container success line; got: {:?}",
            outcome.lines
        );
    }

    /// `--no-cache` flag flows into the JSON body verbatim; pinned so a
    /// future refactor of the body shape cannot silently drop the field.
    #[tokio::test]
    async fn dispatch_rebuild_image_threads_no_cache_into_body() {
        let recorder = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let send = make_recording_sender(std::collections::HashMap::new(), recorder.clone());
        let outcome = run_rebuild_image_dispatch(RebuildImageBackend::Container, true, send).await;
        assert!(outcome.all_ok);
        let calls = recorder.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        let body: serde_json::Value = serde_json::from_str(&calls[0].1).unwrap();
        assert_eq!(body["backend"], serde_json::json!("container"));
        assert_eq!(body["no_cache"], serde_json::json!(true));
    }

    /// All-success path leaves `all_ok = true` and emits per-backend
    /// "done" lines — pinned so a future refactor that swallows the
    /// success line stays visible.
    #[tokio::test]
    async fn dispatch_rebuild_image_all_success_yields_done_lines() {
        let recorder = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let send = make_recording_sender(std::collections::HashMap::new(), recorder.clone());
        let outcome = run_rebuild_image_dispatch(RebuildImageBackend::All, false, send).await;
        assert!(outcome.all_ok);
        assert_eq!(
            outcome.lines,
            vec![
                "rebuild-image[lima]: done".to_string(),
                "rebuild-image[container]: done".to_string(),
            ]
        );
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
                resolved_cpus: 2.0,
                resolved_memory_mb: 4096,
                workspace_mode: Some("shared:/home/olek/project".into()),
                hardened: true,
                repo: Some("https://github.com/example/app.git".into()),
                boot_cmd: Some("make setup".into()),
                template: None,
            },
            guest_agent_status: Some("connected".into()),
            gateway_status: Some("running".into()),
            policy,
            warnings: Vec::new(),
            backend: sandbox_core::backend::BackendKind::Lima,
            network: None,
            mounts: None,
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
            Command::Describe { sessions, verbose } => {
                assert_eq!(sessions, &vec!["alpha".to_string()]);
                assert!(!verbose, "default describe is non-verbose");
            }
            _ => panic!("expected Describe command"),
        }
    }

    #[test]
    fn parse_describe_verbose_short_flag() {
        let cli = Cli::parse_from(["sandbox", "describe", "-v", "alpha"]);
        match &cli.command {
            Command::Describe { sessions, verbose } => {
                assert_eq!(sessions, &vec!["alpha".to_string()]);
                assert!(*verbose, "-v should set verbose=true");
            }
            _ => panic!("expected Describe command"),
        }
    }

    #[test]
    fn parse_describe_verbose_long_flag() {
        let cli = Cli::parse_from(["sandbox", "describe", "--verbose", "alpha"]);
        match &cli.command {
            Command::Describe { sessions, verbose } => {
                assert_eq!(sessions, &vec!["alpha".to_string()]);
                assert!(*verbose, "--verbose should set verbose=true");
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
            verbose: false,
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
        let rendered = render_describe(std::slice::from_ref(&dto), None);
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
        let rendered = render_describe(std::slice::from_ref(&dto), None);

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
        let rendered = render_describe(std::slice::from_ref(&dto), None);
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
        let rendered = render_describe(std::slice::from_ref(&dto), None);
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
        let rendered = render_describe(&[a, b, c], None);

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

    // -- BACKEND column / describe backend prominence / capabilities ---------

    /// `display_sessions_table` rendered into a buffer must include the
    /// `BACKEND` column header between `STATE` and `AGENT`. M11-S4
    /// Phase 4B contract pin.
    #[test]
    fn write_sessions_table_header_includes_backend_between_state_and_agent() {
        let dto = make_session_dto("0123456789ab", Some("alpha"), None, chrono::Utc::now());
        let mut buf = Vec::new();
        write_sessions_table(&mut buf, std::slice::from_ref(&dto));
        let rendered = String::from_utf8(buf).expect("table is UTF-8");
        let header = rendered.lines().next().expect("header line");
        let state_idx = header.find("STATE").expect("STATE in header");
        let backend_idx = header.find("BACKEND").expect("BACKEND in header");
        let agent_idx = header.find("AGENT").expect("AGENT in header");
        assert!(
            state_idx < backend_idx && backend_idx < agent_idx,
            "expected STATE < BACKEND < AGENT in header, got: {header:?}"
        );
    }

    /// Each row of the rendered table must show the lowercase backend
    /// identifier (`lima` / `container`) for the corresponding session.
    #[test]
    fn write_sessions_table_rows_show_backend_per_session() {
        let mut lima = make_session_dto("0123456789ab", Some("lima-box"), None, chrono::Utc::now());
        lima.backend = sandbox_core::backend::BackendKind::Lima;
        let mut container =
            make_session_dto("ba9876543210", Some("ctr-box"), None, chrono::Utc::now());
        container.backend = sandbox_core::backend::BackendKind::Container;

        let mut buf = Vec::new();
        write_sessions_table(&mut buf, &[lima, container]);
        let rendered = String::from_utf8(buf).expect("table is UTF-8");
        let lines: Vec<&str> = rendered.lines().collect();
        // [0] = header, [1] = lima row, [2] = container row.
        assert!(
            lines[1].contains("lima"),
            "lima row must include the `lima` backend tag, got:\n{}",
            lines[1]
        );
        assert!(
            lines[2].contains("container"),
            "container row must include the `container` backend tag, got:\n{}",
            lines[2]
        );
        // Defence against accidental confusion between the two rows.
        assert!(
            !lines[1].contains("container"),
            "lima row must not show `container`, got:\n{}",
            lines[1]
        );
    }

    /// Empty session list still emits a friendly placeholder via the
    /// writer interface.
    #[test]
    fn write_sessions_table_empty_emits_placeholder() {
        let mut buf = Vec::new();
        write_sessions_table(&mut buf, &[]);
        let rendered = String::from_utf8(buf).expect("UTF-8");
        assert_eq!(rendered, "No sessions found.\n");
    }

    /// Default-view `describe` (no `-v`) must show `Backend:` adjacent
    /// to `State:` per spec § "sandbox inspect → Default view".
    #[test]
    fn describe_default_view_shows_backend_in_session_block() {
        let mut dto = make_session_dto("abcdef012345", Some("lite-box"), None, chrono::Utc::now());
        dto.backend = sandbox_core::backend::BackendKind::Container;
        let rendered = render_describe(std::slice::from_ref(&dto), None);
        assert!(
            rendered.contains("Backend:      container"),
            "expected `Backend:` line with container tag, got:\n{rendered}"
        );
        // Backend must precede Created in the header block.
        let backend_pos = rendered.find("Backend:").expect("Backend line present");
        let created_pos = rendered.find("Created:").expect("Created line present");
        assert!(
            backend_pos < created_pos,
            "Backend must appear before Created in the header block, got:\n{rendered}"
        );
    }

    /// Without `-v`, no `Capabilities` block is rendered — the matrix
    /// is opt-in.
    #[test]
    fn describe_default_view_omits_capabilities_block() {
        let dto = make_session_dto("abcdef012345", Some("plain"), None, chrono::Utc::now());
        let rendered = render_describe(std::slice::from_ref(&dto), None);
        assert!(
            !rendered.contains("Capabilities:"),
            "default view must not render a Capabilities block, got:\n{rendered}"
        );
    }

    /// Verbose render with a Lima cap matrix pins the most distinctive
    /// fields (isolation, hardening_flag, workspace_modes) so a future
    /// re-shape of `Capabilities` surfaces here.
    #[test]
    fn describe_verbose_renders_lima_capabilities_block() {
        let mut dto = make_session_dto("aaaabbbbcccc", Some("lima"), None, chrono::Utc::now());
        dto.backend = sandbox_core::backend::BackendKind::Lima;
        let mut caps = std::collections::HashMap::new();
        caps.insert(
            sandbox_core::backend::BackendKind::Lima,
            CapabilitiesLookup::Available(sandbox_core::Capabilities::for_lima()),
        );
        let rendered = render_describe(std::slice::from_ref(&dto), Some(&caps));
        assert!(
            rendered.contains("Capabilities:"),
            "expected Capabilities block, got:\n{rendered}"
        );
        assert!(
            rendered.contains("isolation:            vm"),
            "Lima isolation should serialize to `vm`, got:\n{rendered}"
        );
        assert!(
            rendered.contains("hardening_flag:       true"),
            "Lima honours hardening, got:\n{rendered}"
        );
        assert!(
            rendered.contains("workspace_modes:      shared, clone"),
            "Lima advertises both workspace modes, got:\n{rendered}"
        );
    }

    /// Verbose render with a Container cap matrix — distinct field
    /// values from Lima (no hardening, empty workspace modes).
    #[test]
    fn describe_verbose_renders_container_capabilities_block() {
        let mut dto = make_session_dto("ddddeeeeffff", Some("ctr"), None, chrono::Utc::now());
        dto.backend = sandbox_core::backend::BackendKind::Container;
        // Build a Container capabilities value via JSON round-trip
        // because `Capabilities` is `#[non_exhaustive]` and external
        // callers cannot brace-construct it. The wire shape mirrors
        // `capabilities_for_container` in sandbox-core.
        let caps_value: sandbox_core::Capabilities = serde_json::from_str(
            r#"{
                "kind": "container",
                "isolation": "container",
                "nested_virt": false,
                "privileged_ops": false,
                "raw_network": false,
                "hardening_flag": false,
                "per_session_no_cache": false,
                "workspace_modes": []
            }"#,
        )
        .expect("decode container caps");
        let mut caps = std::collections::HashMap::new();
        caps.insert(
            sandbox_core::backend::BackendKind::Container,
            CapabilitiesLookup::Available(caps_value),
        );
        let rendered = render_describe(std::slice::from_ref(&dto), Some(&caps));
        assert!(
            rendered.contains("isolation:            container"),
            "Container isolation should serialize to `container`, got:\n{rendered}"
        );
        assert!(
            rendered.contains("hardening_flag:       false"),
            "Container does not honour hardening, got:\n{rendered}"
        );
        assert!(
            rendered.contains("workspace_modes:      -"),
            "empty workspace_modes set should render as `-`, got:\n{rendered}"
        );
    }

    /// A cache failure surfaces as `<capability matrix unavailable: ...>`
    /// — describe still completes, the rest of the output is intact.
    #[test]
    fn describe_verbose_unavailable_caps_renders_inline_marker() {
        let dto = make_session_dto("eeee11112222", Some("oops"), None, chrono::Utc::now());
        let mut caps = std::collections::HashMap::new();
        caps.insert(
            sandbox_core::backend::BackendKind::Lima,
            CapabilitiesLookup::Unavailable("connect refused".into()),
        );
        let rendered = render_describe(std::slice::from_ref(&dto), Some(&caps));
        assert!(
            rendered.contains("Capabilities:"),
            "block header still rendered, got:\n{rendered}"
        );
        assert!(
            rendered.contains("<capability matrix unavailable: connect refused>"),
            "inline error marker missing, got:\n{rendered}"
        );
        // The session's own data must still be rendered above the
        // failed-caps marker — describe degrades gracefully.
        assert!(
            rendered.contains("Session:      eeee11112222"),
            "session data must still render despite caps failure, got:\n{rendered}"
        );
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
        // M11-S4 Phase 4B: the JSON `inspect` automation contract picks
        // up `backend` "for free" via SessionDto's additive field. Pin
        // the wire key here so an accidental rename or removal in
        // `SessionDto` lights up the inspect contract test, not just
        // the deeper serde unit tests.
        assert_eq!(
            arr[0]
                .get("backend")
                .and_then(|v| v.as_str())
                .expect("backend field present on inspect JSON"),
            "lima",
            "default backend in test fixture is Lima; JSON must reflect it"
        );
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

    // ---------------------------------------------------------------
    // `policy status` subcommand (M10-S6 todo #37)
    // ---------------------------------------------------------------

    #[test]
    fn parse_duration_plain_number_is_seconds() {
        assert_eq!(parse_duration_arg("60").unwrap(), Duration::from_secs(60));
    }

    #[test]
    fn parse_duration_with_s_suffix() {
        assert_eq!(parse_duration_arg("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn parse_duration_with_ms_suffix() {
        assert_eq!(
            parse_duration_arg("500ms").unwrap(),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn parse_duration_with_m_suffix() {
        assert_eq!(parse_duration_arg("2m").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn parse_duration_with_h_suffix() {
        assert_eq!(parse_duration_arg("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn parse_duration_rejects_empty() {
        assert!(parse_duration_arg("").is_err());
    }

    #[test]
    fn parse_duration_rejects_non_numeric() {
        assert!(parse_duration_arg("abc").is_err());
        assert!(parse_duration_arg("5 minutes").is_err());
    }

    #[test]
    fn humanize_duration_round_trips_common_values() {
        assert_eq!(humanize_duration(Duration::from_secs(60)), "1m");
        assert_eq!(humanize_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(humanize_duration(Duration::from_secs(45)), "45s");
        assert_eq!(humanize_duration(Duration::from_millis(250)), "250ms");
    }

    #[test]
    fn parse_policy_status_defaults() {
        let cli = Cli::parse_from(["sandbox", "policy", "status", "my-session"]);
        match &cli.command {
            Command::Policy {
                action:
                    PolicyAction::Status {
                        session,
                        wait,
                        timeout,
                    },
            } => {
                assert_eq!(session, "my-session");
                assert!(!wait);
                // Default pinned in the derive attribute so operators can
                // rely on it in scripts.
                assert_eq!(timeout, "60s");
            }
            _ => panic!("expected Policy Status command"),
        }
    }

    #[test]
    fn parse_policy_status_with_wait_and_timeout() {
        let cli = Cli::parse_from([
            "sandbox",
            "policy",
            "status",
            "my-session",
            "--wait",
            "--timeout",
            "5m",
        ]);
        match &cli.command {
            Command::Policy {
                action:
                    PolicyAction::Status {
                        session,
                        wait,
                        timeout,
                    },
            } => {
                assert_eq!(session, "my-session");
                assert!(*wait);
                assert_eq!(timeout, "5m");
            }
            _ => panic!("expected Policy Status command"),
        }
    }

    #[test]
    fn short_hash_truncates_to_12_chars() {
        let full = "deadbeef1234567890abcdef";
        assert_eq!(short_hash(full), "deadbeef1234");
    }

    #[test]
    fn short_hash_passes_through_short_input() {
        assert_eq!(short_hash("abc"), "abc");
    }

    // -----------------------------------------------------------------------
    // plan_ssh_command — M11-S4 Phase 4D-pre gap #2 dispatch logic.
    //
    // Pure helper: returns `(program, args)` based on the session's
    // backend kind. The handler then forwards them to
    // `std::process::Command`, but the dispatch shape itself is what
    // these tests pin so a future refactor cannot regress the
    // Lima-only behaviour or wire the wrong `docker exec` flags.
    // -----------------------------------------------------------------------

    fn ssh_session_id() -> sandbox_core::SessionId {
        sandbox_core::SessionId::parse("0123456789ab").expect("test fixture session id must parse")
    }

    #[test]
    fn plan_ssh_lima_no_command_starts_interactive_shell() {
        let sid = ssh_session_id();
        let (program, args) =
            plan_ssh_command(sandbox_core::backend::BackendKind::Lima, &sid, &[], true);
        assert_eq!(program, "limactl");
        assert_eq!(
            args,
            vec!["shell".to_string(), "sandbox-0123456789ab".to_string()]
        );
    }

    #[test]
    fn plan_ssh_lima_with_command_uses_double_dash_separator() {
        let sid = ssh_session_id();
        let cmd = vec!["echo".to_string(), "hello".to_string()];
        let (program, args) =
            plan_ssh_command(sandbox_core::backend::BackendKind::Lima, &sid, &cmd, true);
        assert_eq!(program, "limactl");
        assert_eq!(
            args,
            vec![
                "shell".to_string(),
                "sandbox-0123456789ab".to_string(),
                "--".to_string(),
                "echo".to_string(),
                "hello".to_string(),
            ]
        );
    }

    #[test]
    fn plan_ssh_container_no_command_with_tty_uses_docker_exec_it() {
        let sid = ssh_session_id();
        let (program, args) = plan_ssh_command(
            sandbox_core::backend::BackendKind::Container,
            &sid,
            &[],
            true,
        );
        assert_eq!(program, "docker");
        assert_eq!(
            args,
            vec![
                "exec".to_string(),
                "-it".to_string(),
                "sandbox-0123456789ab".to_string(),
            ]
        );
    }

    #[test]
    fn plan_ssh_container_with_command_and_tty_appends_command_after_target() {
        let sid = ssh_session_id();
        let cmd = vec!["echo".to_string(), "hello".to_string()];
        let (program, args) = plan_ssh_command(
            sandbox_core::backend::BackendKind::Container,
            &sid,
            &cmd,
            true,
        );
        assert_eq!(program, "docker");
        // Spec § "Lifecycle" — `docker exec -it <ctr> <cmd>...`. No
        // `--` separator: docker exec parses positional args after the
        // container name as the command.
        assert_eq!(
            args,
            vec![
                "exec".to_string(),
                "-it".to_string(),
                "sandbox-0123456789ab".to_string(),
                "echo".to_string(),
                "hello".to_string(),
            ]
        );
    }

    #[test]
    fn plan_ssh_container_no_command_without_tty_drops_t_flag() {
        // When the caller's stdin is not a TTY (pytest, CI, any
        // pipe-fed parent), `docker exec -t` aborts at startup with
        // "cannot attach stdin to a TTY-enabled container because
        // stdin is not a terminal". Pin that we drop `-t` and keep
        // `-i` so stdin is still forwarded.
        let sid = ssh_session_id();
        let (program, args) = plan_ssh_command(
            sandbox_core::backend::BackendKind::Container,
            &sid,
            &[],
            false,
        );
        assert_eq!(program, "docker");
        assert_eq!(
            args,
            vec![
                "exec".to_string(),
                "-i".to_string(),
                "sandbox-0123456789ab".to_string(),
            ]
        );
    }

    #[test]
    fn plan_ssh_container_with_command_without_tty_drops_t_flag() {
        let sid = ssh_session_id();
        let cmd = vec!["echo".to_string(), "hello".to_string()];
        let (program, args) = plan_ssh_command(
            sandbox_core::backend::BackendKind::Container,
            &sid,
            &cmd,
            false,
        );
        assert_eq!(program, "docker");
        assert_eq!(
            args,
            vec![
                "exec".to_string(),
                "-i".to_string(),
                "sandbox-0123456789ab".to_string(),
                "echo".to_string(),
                "hello".to_string(),
            ]
        );
    }
}
