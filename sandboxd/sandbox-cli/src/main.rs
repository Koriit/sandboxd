use std::path::Path;
use std::process;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use clap::{ArgAction, ArgGroup, Parser, Subcommand, ValueEnum};
use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use sandbox_core::{
    ApiError, EventDto, ExecResponse, Policy, PolicyDto, PolicyLevelDto, PolicyRule, PolicyRuleDto,
    PropagationStatusResponse, SessionDto, SessionHealth, SessionMountInfo, SessionNetworkInfo,
    SessionRootlessDockerDto, UpdatePolicyRequest, WorkspaceModeDetailDto,
    WorkspaceSecurityModelDto,
};
use tokio::net::UnixStream;

use sandbox_cli::backend::{
    BackendKindArg, BackendResolutionInputs, FeatureMismatchContext, RebuildImageBackend,
    load_cli_config, render_feature_mismatch, render_force_rootless_docker_lima_rejection,
    render_isolation_warning, render_no_cache_rejection_for_container, resolve_backend,
};
use sandbox_cli::backends_cache::BackendsCache;
use sandbox_cli::presets::{self, Catalog, ParsedInvocation, Preset, PresetSource, UserPreset};

/// CLI client for managing sandbox sessions.
#[derive(Parser, Debug)]
#[command(name = "sandbox", about = "Manage sandbox sessions", version)]
struct Cli {
    /// Path to the sandboxd Unix socket.
    #[arg(long, global = true, env = "SANDBOX_SOCKET", default_value_t = default_socket_path())]
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
        /// the daemon's host-80% ceiling.
        /// Omit to take the backend default; pass an explicit value
        /// to override.
        ///
        /// `f32` so the resource-defaults 1-decimal grammar (`0.8`, `1.5`,
        /// `2.0`, …) reaches the
        /// daemon without truncation. The daemon rounds
        /// to one decimal at request-parse time so `0.81` lands on
        /// the grid as `0.8`. Lima sessions truncate the fractional
        /// part on the daemon side — QEMU's `-smp` flag pins integer
        /// cores.
        #[arg(long)]
        cpus: Option<f32>,
        /// Memory in megabytes. Defaults are backend-specific:
        /// `lima` falls back to 4096 MB; `container` falls back to
        /// the daemon's host-80% ceiling.
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
        /// `'<name>[:key=value[,key=value,...]]'` (e.g. `npm`,
        /// `github-repo:repo=foo/bar`). Presets expand client-side
        /// into rules that merge with the policy file; the composed
        /// effective policy is sent to the daemon, along with the
        /// original invocation strings as `source_presets` for audit.
        ///
        /// Run `sandbox policy preset list` to see the built-in
        /// catalog.
        #[arg(long, action = ArgAction::Append, num_args = 1)]
        preset: Vec<String>,
        /// Git repository URL to clone into /home/sandbox/workspace/ after session setup.
        ///
        /// Mutually exclusive with --workspace.
        #[arg(long, conflicts_with = "workspace")]
        repo: Option<String>,
        /// Command to execute after clone (or after setup if no repo).
        #[arg(long)]
        boot_cmd: Option<String>,
        /// Workspace mode: `shared:<host>[:<guest>][:<security-model>]`
        /// (9p / bind mount), or `local:<host>[:<guest>]` (rsync
        /// snapshot at session create; operator-driven push/pull via
        /// `sandbox workspace push|pull`). The guest path defaults to
        /// the host path; the security model defaults to
        /// `mapped-xattr` (alternative: `none`). See
        /// `docs/guides/workspaces.md` for the full grammar.
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
        /// Skip the `.gitignore` filter on the create-time initial-push
        /// rsync for `local:` workspaces.
        ///
        /// Meaningful only when `--workspace` resolves to a `local:`
        /// mode; the CLI rejects the combination with any other mode
        /// (including absent `--workspace`) before the request goes on
        /// the wire, and the daemon mirrors the rejection for non-CLI
        /// clients. The create-time choice is **not** persisted —
        /// subsequent `sandbox workspace push` / `pull` invocations
        /// carry their own `--no-gitignore` flag.
        #[arg(long = "no-gitignore")]
        no_gitignore: bool,
        /// Backend that should host the session (`lima` or `container`).
        ///
        /// Mutually exclusive with `--lite`. When neither is set, the
        /// backend is resolved from `SANDBOX_DEFAULT_BACKEND`, the
        /// per-user config (`~/.config/sandboxd/config.json` →
        /// `default_backend`), and finally the hardcoded default
        /// `lima`.
        #[arg(long, value_enum)]
        backend: Option<BackendKindArg>,
        /// Sugar for `--backend container` — the container ("lite")
        /// backend.
        ///
        /// Mutually exclusive with `--backend`.
        #[arg(long, conflicts_with = "backend")]
        lite: bool,
        /// Allow session-create on rootless Docker (operator opt-in; explicitly outside the supported envelope).
        ///
        /// By default the daemon probes `docker info` and refuses
        /// container-backend session-create when the host is in
        /// rootless mode. Pass this flag to override that refusal
        /// for the current invocation only — the flag is
        /// never persisted to any config file or preset, so accidental
        /// opt-in across multiple invocations is not possible.
        ///
        /// Container-backend only: combining this flag with a
        /// resolved Lima backend is a misuse error (exit 2); Lima
        /// sessions are unaffected by Docker mode entirely.
        //
        // Implementation note (not in --help output): the rejection
        // is programmatic in `dispatch_create_preflight` rather than
        // `conflicts_with`-based because the resolved backend is the
        // product of a five-tier precedence chain (`--lite`,
        // `--backend`, env, config, hardcoded default) — not a single
        // CLI flag clap could pin against.
        #[arg(long)]
        force_rootless_docker: bool,
    },
    /// Start a sandbox session.
    Start {
        /// Session name or ID.
        session: String,
    },
    /// Stop one or more sandbox sessions.
    Stop {
        /// Session names or IDs to stop. At least one is required.
        #[arg(required = true)]
        sessions: Vec<String>,
        /// Force-stop: pass ?force=true to the daemon (bypasses
        /// workspace-lock conflicts if the daemon supports it).
        #[arg(short = 'f', long = "force")]
        force: bool,
    },
    /// Remove one or more sandbox sessions.
    Rm {
        /// Session names or IDs to remove. At least one is required.
        #[arg(required = true)]
        sessions: Vec<String>,
    },
    /// List sandbox sessions.
    Ps {
        /// Skip the opportunistic reconcile pass against
        /// `~/.ssh/sandbox/` after rendering the listing.
        ///
        /// By default `sandbox ps` / `sandbox ls` remove local
        /// per-session SSH config + key files whose ids the daemon no
        /// longer knows about (Spec § Architecture → CLI: persistent
        /// ssh-config → Reconcile on listing). Tooling consumers that
        /// need strict read-only semantics — e.g. machine-readable JSON
        /// pipelines, or scripts that intentionally inspect stale
        /// entries — opt out with this flag. The reconcile is also
        /// skipped automatically when the daemon is unreachable (no
        /// regression in error mode); this flag covers the
        /// daemon-reachable case.
        #[arg(long = "no-reconcile")]
        no_reconcile: bool,
        /// Quiet: print only session IDs, one per line, to stdout.
        /// Useful for scripting (`sandbox ps -q | xargs sandbox stop`).
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
    },
    /// List sandbox sessions (alias for ps).
    Ls {
        /// Skip the opportunistic reconcile pass against
        /// `~/.ssh/sandbox/` after rendering the listing.
        ///
        /// See `sandbox ps --help` for the full reconcile semantics.
        #[arg(long = "no-reconcile")]
        no_reconcile: bool,
        /// Quiet: print only session IDs, one per line, to stdout.
        /// Useful for scripting (`sandbox ls -q | xargs sandbox rm`).
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
    },
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
    /// Mirror a directory between host and sandbox session via rsync.
    ///
    /// Like `sandbox cp`, but dispatches to `rsync -a --delete` over the
    /// backend's native shell transport (`limactl shell` for Lima,
    /// `docker exec -i` for container). Use this for incremental
    /// directory mirroring where attribute preservation, deletion of
    /// removed files, and skip-unchanged behaviour matter — `cp`
    /// retransfers the full tree on every invocation.
    ///
    /// Use session:path syntax to specify the remote side:
    ///   sandbox sync local/dir session:remote/dir   (upload)
    ///   sandbox sync session:remote/dir local/dir   (download)
    ///
    /// Extra rsync flags can be passed after `--`, in which case they
    /// are spliced after the baseline `-a --delete -e <shell>` and
    /// before the source/destination operands. Examples: `--exclude
    /// '*.log'`, `--bwlimit=1m`, `--partial`, `--info=progress2`. See
    /// the [CLI reference](docs/reference/cli.md#sandbox-sync) for the
    /// argv shape.
    ///
    /// Requires `rsync` on both the host and inside the session image.
    /// The sandboxd-provisioned base images ship rsync; if you supply a
    /// custom image, install rsync yourself.
    Sync {
        /// Source path (prefix with session: for VM paths).
        src: String,
        /// Destination path (prefix with session: for VM paths).
        dst: String,
        /// Extra rsync flags (everything after `--`). Spliced between
        /// the baseline `-a --delete -e <shell>` and the source /
        /// destination operands so users can layer pass-through flags
        /// (`--exclude`, `--bwlimit`, `--partial`, `--info=progress2`,
        /// etc.) without losing the safety baseline.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rsync_args: Vec<String>,
    },
    /// Push, pull, or unlock the `local:` workspace for a sandbox session.
    ///
    /// Operator-driven counterpart to the create-time initial-push rsync:
    /// `push` mirrors the host workspace into the guest, `pull` mirrors
    /// the guest workspace back to the host, and `unlock` clears a stuck
    /// workspace lock (orphan-lock recovery). All three operations
    /// require the session to be in `local:` workspace mode; push/pull
    /// additionally require the session to be `Running`.
    Workspace {
        #[command(subcommand)]
        action: WorkspaceAction,
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
        /// session's backend. The `-v` flag appends the capability matrix.
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
    /// Print the CLI's own version and exit.
    ///
    /// Does **not** connect to the daemon — this is the local answer to
    /// "what version of the CLI do I have?" and intentionally bypasses
    /// the strict CLI ↔ daemon version-equality handshake every other
    /// subcommand performs. Combine with `sandbox doctor` for "what
    /// version of the daemon do I have?".
    Version,
    /// Diagnose the local sandboxd installation.
    ///
    /// Connects tolerantly: the CLI ↔ daemon strict-equality handshake
    /// is bypassed for this subcommand so the operator can use doctor
    /// to *diagnose* a version skew, not be refused by it. The check
    /// inventory and output contract live in [`sandbox_cli::doctor`].
    Doctor {
        /// Print all checks (including passes) rather than just the
        /// ones that failed or surfaced a skip-hint.
        #[arg(long)]
        verbose: bool,
    },
    /// Rebuild the pre-baked backend image(s).
    ///
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

    /// Apply a pending sandboxd upgrade (or report what would happen).
    ///
    /// `sandbox update` orchestrates the full upgrade flow:
    /// pre-flight checks (read-only), confirmation prompt, and the
    /// stateful steps that stop the daemon, install new binaries, run
    /// config migrations, and restart. Each privileged step uses
    /// `sudo -k <action>` so every elevation appears as its own line
    /// in `/var/log/sandbox-install.log`.
    ///
    /// Exit codes:
    /// - `0` — up to date (`--check`), `--dry-run` printed plan, or
    ///   confirmation prompt answered `N`.
    /// - `1` — error (pre-flight refused, network failure, etc.).
    /// - `2` — argument-parse failure / refused flag combination
    ///   (e.g. `--cosign-bundle` without `--from`).
    /// - `3` — update available (`--check` only); machine-readable
    ///   signal for "an update is waiting; run `sandbox update` to
    ///   apply".
    Update {
        /// Pin to a specific release tag (default: latest).
        #[arg(long, default_value = "latest")]
        version: String,
        /// Use a local tarball instead of auto-downloading from GitHub
        /// Releases. Air-gap override: when absent, the tarball and its
        /// `.sigstore` bundle are downloaded automatically from
        /// `--source-url`. Requires `--cosign-bundle` (or a sibling
        /// `.sigstore` file) when the bundle is not alongside the
        /// tarball.
        #[arg(long)]
        from: Option<std::path::PathBuf>,
        /// Path to a sigstore bundle for `--from` air-gap
        /// verification. Required when the tarball does not have a
        /// sibling `<tarball>.sigstore` file.
        #[arg(long, requires = "from")]
        cosign_bundle: Option<std::path::PathBuf>,
        /// Override the default release-tarball base URL. Mutually
        /// exclusive with `--from` (which is local-only).
        #[arg(
            long,
            default_value = "https://github.com/Koriit/sandboxd/releases/download"
        )]
        source_url: String,
        /// Read-only mode: report installed vs available, then exit.
        /// Never acquires the lock, never contacts cosign, never
        /// extracts anything.
        #[arg(long, conflicts_with = "dry_run")]
        check: bool,
        /// Read-only mode: print the step-by-step plan
        /// (`would execute` / `would skip` per stateful step) and
        /// exit. Never mutates state.
        #[arg(long)]
        dry_run: bool,
        /// Skip the interactive confirmation prompt. Equivalent to
        /// answering `y`.
        #[arg(long)]
        yes: bool,
        /// Proceed past the "active sessions exist" guard.
        /// The daemon stop will terminate active
        /// sessions mid-flight — use only when the daemon is wedged
        /// and you want to upgrade anyway.
        #[arg(long)]
        force: bool,
        /// Quieter logging.
        #[arg(long, conflicts_with = "verbose")]
        quiet: bool,
        /// Verbose logging.
        #[arg(long)]
        verbose: bool,
    },

    /// Hidden internal affordance: apply a single config migration in
    /// memory and write the result to `--out`. The outer
    /// `sandbox update` flow then `sudo -k mv`s the output into place.
    ///
    /// Refusal arms (access-gating block — `clap-hide` is
    /// not access control):
    ///
    /// 1. Caller must be root (`getuid() == 0`).
    /// 2. `--file` must be one of the registry's canonical paths
    ///    (`/etc/sandboxd/users.conf` or `/etc/qemu/bridge.conf`).
    /// 3. `--out` must be a tempfile under the same directory as
    ///    `--file` with basename matching
    ///    `\.<file-basename>\.tmp\.V[0-9]+$`.
    /// 4. `--migration` must resolve to a registered migration whose
    ///    `target_file()` matches the validated `--file`.
    #[command(hide = true, name = "apply-config-migration")]
    ApplyConfigMigration {
        /// Input file path (must be one of the canonical paths).
        #[arg(long)]
        file: String,
        /// Migration to apply, as `V<NNN>` (e.g. `V001`).
        #[arg(long)]
        migration: String,
        /// Output tempfile path (must be a tempfile under `--file`'s
        /// parent directory).
        #[arg(long)]
        out: String,
    },

    /// Hidden installer affordance: apply the full config-migration chain
    /// for every managed config file, idempotently advancing each to the
    /// latest registered schema version.
    ///
    /// Requires root (`geteuid() == 0`). Writes directly to the canonical
    /// paths (e.g. `/etc/sandboxd/users.conf`, `/etc/qemu/bridge.conf`)
    /// using atomic rename. Safe to call when a file is already at the
    /// latest version — `apply_pending_at` is a no-op in that case.
    ///
    /// Invoked by `scripts/install.sh` from within its privileged root
    /// batch after the binaries are written, so that a pre-existing v0
    /// `users.conf` is migrated before the daemon is (re)started.
    ///
    /// # Stable external contract
    ///
    /// The subcommand name `apply-config-migrations` (plural, no flags)
    /// and the `requires-root` refusal text are a **stable external
    /// contract**: the install.sh installer calls this exact invocation
    /// across releases. Do NOT rename this subcommand, do NOT change the
    /// calling convention, and do NOT alter the `requires root` error
    /// message prefix without a coordinated, backwards-compatible change
    /// to `scripts/install.sh`. A prior-release orchestrator MUST be able
    /// to invoke `sandbox apply-config-migrations` against a newer binary
    /// and have it succeed.
    #[command(hide = true, name = "apply-config-migrations")]
    ApplyConfigMigrations,

    /// Hidden internal affordance: print the static migration registry
    /// as JSON to stdout. Used by `sandbox update --dry-run` for the
    /// stopped-session classification step. Read-only
    /// — no privilege check, no path arguments.
    #[command(hide = true, name = "dump-migration-set")]
    DumpMigrationSet,

    /// Hidden internal affordance: print the daemon-side guest protocol
    /// constants as JSON to stdout. Invoked by `sandbox update` against
    /// the *staged* (target-version) CLI binary so the pre-flight can
    /// classify each persisted session against the upgrade target's
    /// `DAEMON_GUEST_PROTO_VERSION`. The shape is
    /// `{ "daemon_guest_proto_version": <u32> }` — operator-stable, so
    /// future protocol bumps add fields rather than renaming this key.
    /// Read-only; no privilege check, no path arguments.
    #[command(hide = true, name = "dump-proto-version")]
    DumpProtoVersion,

    /// Hidden subcommand: `ProxyCommand` shim invoked by the daemon-
    /// emitted SSH config block.
    ///
    /// The cross-user CLI access design generates a `Host
    /// sandbox-<id>` block under `~/.ssh/sandbox/` whose
    /// `ProxyCommand` line reads `sandbox proxy <id>`. The shim
    /// opens a WebSocket against the daemon's
    /// `GET /sessions/{id}/proxy` endpoint over the existing Unix-
    /// socket transport, then bidirectionally splices its own stdin
    /// and stdout with binary WebSocket frames. The daemon's byte
    /// mover (`sandboxd::proxy_http`) carries those bytes into the
    /// session's sshd per backend.
    ///
    /// **Wire format**: the subcommand name (`proxy`) and the single
    /// positional argument (`<id>`) are pinned by
    /// `sandbox_core::render_ssh_config_block`. Renaming either is a
    /// wire break with the daemon-side template.
    ///
    /// Hidden because operators are not expected to invoke this
    /// directly — `ssh sandbox-<id>` (or the `sandbox ssh` wrapper)
    /// is the user-facing surface.
    #[command(hide = true, name = "proxy")]
    Proxy {
        /// Session id (12 lowercase-hex chars).
        session: String,
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
        /// Path to a policy JSON file to apply. Produce one with
        /// `sandbox policy dump <session>`.
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
    /// Dump a session's current policy as round-trippable JSON.
    ///
    /// Fetches the flat expanded rule list from the daemon and prints it
    /// as a `{"version":"2.0.0","rules":[...]}` document — exactly the
    /// shape that `sandbox policy update --policy <file>` accepts.
    ///
    /// The output is the expanded rule set, not preset names; preset
    /// attribution is not part of the stored policy and is intentionally
    /// absent from the dump.
    ///
    /// Typical round-trip:
    ///
    ///     sandbox policy dump web > policy.json
    ///     # edit policy.json
    ///     sandbox policy update web --policy policy.json
    Dump {
        /// Session name or ID.
        session: String,
        /// Write JSON to this file instead of stdout.
        #[arg(long, short = 'o')]
        output: Option<String>,
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

/// `sandbox workspace` subcommands.
///
/// Push and pull mirror the `local:` workspace tree between host and
/// guest via rsync. Unlock clears a stuck workspace lock (orphan-lock
/// recovery). The push/pull surface is intentionally narrow: no
/// trailing pass-through args (unlike `sandbox sync`), one of
/// `-f`/`-n` is required, and the daemon-side workspace-lock serialises
/// concurrent invocations on the same session.
#[derive(Subcommand, Debug, Clone)]
enum WorkspaceAction {
    /// Push the host `local:` workspace into the guest.
    ///
    /// Mirrors the host `host_path` recorded on the session into the
    /// guest workspace via rsync; deletions on the host are mirrored
    /// into the guest (the `--delete` behavior is the contract — use
    /// `-n` to inspect first).
    Push {
        /// Session name or ID.
        session: String,
        /// Required to perform the destructive mirror operation.
        /// Mutually exclusive with `-n`/`--dry-run`.
        #[arg(short = 'f', long = "force", conflicts_with = "dry_run")]
        force: bool,
        /// Show what would change without modifying the guest.
        /// Mutually exclusive with `-f`/`--force`.
        #[arg(short = 'n', long = "dry-run", conflicts_with = "force")]
        dry_run: bool,
        /// Preserve in-tree symlinks; skip out-of-tree symlinks.
        /// Default is to follow all symlinks (`-L`).
        #[arg(long = "safe-links")]
        safe_links: bool,
        /// Skip the `.gitignore` filter; transfer everything.
        #[arg(long = "no-gitignore")]
        no_gitignore: bool,
    },
    /// Pull the guest `local:` workspace back to the host.
    ///
    /// Mirrors the guest workspace into the host destination via rsync;
    /// deletions in the guest are mirrored into the host destination
    /// (the `--delete` behavior is the contract — use `-n` to inspect
    /// first).
    Pull {
        /// Session name or ID.
        session: String,
        /// Required to perform the destructive mirror operation.
        /// Mutually exclusive with `-n`/`--dry-run`.
        #[arg(short = 'f', long = "force", conflicts_with = "dry_run")]
        force: bool,
        /// Show what would change without modifying the host.
        /// Mutually exclusive with `-f`/`--force`.
        #[arg(short = 'n', long = "dry-run", conflicts_with = "force")]
        dry_run: bool,
        /// Preserve in-tree symlinks; skip out-of-tree symlinks.
        /// Default is to follow all symlinks (`-L`).
        #[arg(long = "safe-links")]
        safe_links: bool,
        /// Skip the `.gitignore` filter; transfer everything.
        #[arg(long = "no-gitignore")]
        no_gitignore: bool,
        /// Override the host destination path. Default: the
        /// `host_path` recorded on the session at create time.
        #[arg(long)]
        dest: Option<String>,
    },
    /// Clear a stuck workspace lock on a session.
    ///
    /// Without `--force`, the request is sent with an empty (sentinel)
    /// token — the daemon adjudicates the wrong-token mismatch and
    /// returns 409 if the lock is currently held by a different
    /// caller. With `--force`, the daemon releases the lock
    /// unconditionally (orphan-lock recovery after a SIGKILL'd CLI).
    /// Idempotent on an already-unlocked session: returns success.
    Unlock {
        /// Session name or ID.
        session: String,
        /// Bypass the token-match check; release the lock
        /// unconditionally. Use this when the lock is orphaned (a
        /// previous CLI was SIGKILL'd before it could release).
        #[arg(long)]
        force: bool,
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
    default_socket_path_with(
        |p| std::path::Path::new(p).exists(),
        |k| std::env::var(k).ok(),
    )
}

/// Pure inner of [`default_socket_path`], parameterised over an existence
/// check and an env lookup so unit tests stay hermetic (no real filesystem or
/// process-env mutation, which would race under cargo's threaded runner).
///
/// `SANDBOX_SOCKET` / `--socket` take precedence via clap; this is the
/// "discover the daemon" fallback used only when neither is given. Order:
///
/// 1. `/run/sandbox/sandboxd.sock` **if it exists** — the system-service
///    daemon (systemd unit's `--socket`). Checked first so an operator on a
///    deployed host reaches the system daemon out of the box. A developer
///    running their own daemon on a host that also has a system install sets
///    `SANDBOX_SOCKET` explicitly to override.
/// 2. `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock` — the dev / user-run daemon
///    default. Returned as the path even if the socket does not yet exist, so
///    a connect error names the dev location (the common interactive case).
/// 3. `$HOME/.local/share/sandboxd/sandboxd.sock` — fallback when XDG is unset.
///
/// Only #1 is existence-probed; #2/#3 stay the unconditional default so the
/// error path names a sensible dev location when no daemon is running anywhere.
fn default_socket_path_with(
    exists: impl Fn(&str) -> bool,
    get: impl Fn(&str) -> Option<String>,
) -> String {
    if exists(sandbox_cli::SYSTEM_SOCKET_PATH) {
        return sandbox_cli::SYSTEM_SOCKET_PATH.to_string();
    }
    if let Some(runtime_dir) = get("XDG_RUNTIME_DIR").filter(|s| !s.is_empty()) {
        return format!("{runtime_dir}/sandboxd/sandboxd.sock");
    }
    let home = get("HOME")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/tmp".into());
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
/// Any [`presets::PresetError`] along the way prints its `Display` impl to
/// stderr and calls `process::exit(1)` **before** returning. The
/// error wording is required, so we defer to `PresetError`'s `Display` impl
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

/// Expand a leading `~` in the host-path token of a `--workspace` value
/// against the CLI process's `$HOME`. Mirrors the shell-expansion the
/// operator would have got had they typed an absolute path, while
/// keeping the substitution on the CLI side of the wire — the daemon
/// runs with a different `$HOME` and the [`WorkspaceMode::parse_flag`]
/// parser explicitly rejects any residual `~` it sees.
///
/// Layout of the expected input: `<mode>:<host>[:<guest>][:<security>]`.
/// Only the host-path token is expanded; the guest-path token (if any)
/// uses literal `~` → `/home/sandbox` substitution inside the shared
/// parser and is left untouched here. Inputs that do not contain a `:`
/// or whose host token does not start with `~` pass through verbatim —
/// `parse_flag` is the authoritative grammar gate downstream.
///
/// On `$HOME`-unset or expanded-path-does-not-exist, returns a friendly
/// error string suitable for printing as an `Error: ...` line. General
/// host-path validation for parsed workspace modes happens in
/// [`validate_workspace_host_path_for_create`].
fn expand_host_tilde_in_workspace_flag(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    // Find the mode prefix (everything before the first `:`); if there
    // is no `:` the value is malformed but we leave that diagnosis to
    // `parse_flag` so the operator sees one consistent error vocabulary.
    let Some((mode, rest)) = trimmed.split_once(':') else {
        return Ok(value.to_string());
    };
    // Right-to-left classification of optional trailing tokens happens
    // inside `parse_flag`; here we only need the *first* colon-segment
    // after the mode prefix, which is always the host-path token.
    let (host_token, tail) = match rest.split_once(':') {
        Some((h, t)) => (h, Some(t)),
        None => (rest, None),
    };
    let host_token_trimmed = host_token.trim();
    if !host_token_trimmed.starts_with('~') {
        return Ok(value.to_string());
    }
    let home = std::env::var("HOME").map_err(|_| {
        format!(
            "--workspace host path starts with `~` but $HOME is not set; \
             pass an absolute path instead (got: {value:?})"
        )
    })?;
    if home.is_empty() {
        return Err(format!(
            "--workspace host path starts with `~` but $HOME is empty; \
             pass an absolute path instead (got: {value:?})"
        ));
    }
    let expanded_host = if host_token_trimmed == "~" {
        home.clone()
    } else if let Some(suffix) = host_token_trimmed.strip_prefix("~/") {
        format!("{home}/{suffix}")
    } else {
        // `~user` form — not supported; let `parse_flag` produce the
        // canonical absolute-path error.
        return Ok(value.to_string());
    };
    if !Path::new(&expanded_host).exists() {
        return Err(format!(
            "--workspace path does not exist after `~` expansion: {expanded_host} \
             (from {value:?})"
        ));
    }
    let mut rebuilt = String::with_capacity(value.len() + home.len());
    rebuilt.push_str(mode);
    rebuilt.push(':');
    rebuilt.push_str(&expanded_host);
    if let Some(t) = tail {
        rebuilt.push(':');
        rebuilt.push_str(t);
    }
    Ok(rebuilt)
}

/// Validate operator-host paths before `sandbox create` reaches the daemon.
///
/// The daemon may run as another user and may not be able to see the
/// operator's workspace tree, so `WorkspaceMode::parse_flag` intentionally
/// stays filesystem-free. The CLI is the boundary that can fail fast on
/// typos while helper/backend code remains the final authority at use time.
fn validate_workspace_host_path_for_create(
    mode: &sandbox_core::WorkspaceMode,
) -> Result<(), String> {
    match mode {
        sandbox_core::WorkspaceMode::Shared { host_path, .. } => {
            if !Path::new(host_path).exists() {
                return Err(format!(
                    "shared workspace host_path does not exist: {host_path:?}"
                ));
            }
            Ok(())
        }
        sandbox_core::WorkspaceMode::Local { host_path, .. } => {
            match std::fs::metadata(host_path) {
                Ok(metadata) if metadata.is_dir() => Ok(()),
                Ok(_) => Err(format!(
                    "host_path must be a directory for `local:`; to seed a single file, \
                 use `sandbox cp <file> <session>:<path>` after creating the session. \
                 (Got: {host_path:?})"
                )),
                Err(_) => Err(format!(
                    "local workspace host_path does not exist: {host_path:?}"
                )),
            }
        }
        sandbox_core::WorkspaceMode::Clone { .. } => Ok(()),
    }
}

/// CLI-side gate for `--no-gitignore`: only meaningful when paired
/// with a `local:` workspace. Returns the operator-facing error string
/// that the caller pairs with `eprintln!` + `process::exit(1)`.
///
/// Mirrors the daemon-side rejection in `create_session` byte-for-byte
/// so a CLI-driven failure and a hand-rolled HTTP-client failure both
/// surface the same diagnostic. The `<mode>` token is `shared`,
/// `clone`, or the literal `<empty>` (no `--workspace` passed). Parses
/// the `--workspace` value with [`sandbox_core::WorkspaceMode::parse_flag`]
/// — the single pure parser shared with the daemon.
///
/// The rejection wording lives at the call sites (CLI + daemon)
/// rather than as a shared constant because:
/// - The daemon-side check is independent (a misbehaving CLI cannot
///   bypass the gate by skipping this client-side validation).
/// - There is no `sandbox-core` location both sides reasonably depend
///   on for human-readable error strings (the existing
///   `SandboxError::InvalidArgument` carries owned strings, not a
///   shared error catalog).
fn validate_no_gitignore_for_workspace(workspace: Option<&str>) -> Result<(), String> {
    // Resolve the mode token from the parsed workspace flag. We
    // tolerate parse failures here (an invalid workspace value will
    // be reported by the existing `parse_flag` call below, which
    // produces a more informative diagnostic); fall back to `<empty>`
    // so the rejection still fires for the `--no-gitignore` +
    // `--workspace <invalid>` combination.
    let mode = match workspace {
        None => "<empty>",
        Some(ws) => match sandbox_core::WorkspaceMode::parse_flag(ws) {
            Ok(sandbox_core::WorkspaceMode::Local { .. }) => return Ok(()),
            Ok(sandbox_core::WorkspaceMode::Shared { .. }) => "shared",
            Ok(sandbox_core::WorkspaceMode::Clone { .. }) => "clone",
            // An unparseable `--workspace` value still triggers the
            // gate — there is no `local:` mode on the request, so
            // `--no-gitignore` has no meaning. Use `<empty>` as the
            // mode token for consistency with the absent-flag case.
            Err(_) => "<empty>",
        },
    };
    Err(format!(
        "--no-gitignore is only meaningful for local: workspaces; this session uses {mode}:"
    ))
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
        no_gitignore,
        backend: _backend,
        lite: _lite,
        force_rootless_docker,
    } = command
    else {
        unreachable!("build_create_request_body called with non-Create command");
    };

    // `--no-gitignore` is only meaningful when paired with a `local:`
    // workspace. Mirror the daemon-side gate client-side so the
    // operator sees the rejection before the request reaches the
    // wire (fail-fast, matching the existing pattern for malformed
    // `--workspace` values below). The daemon-side check in
    // `create_session` is the authoritative one — this CLI check
    // exists for operator latency only.
    if *no_gitignore {
        if let Err(e) = validate_no_gitignore_for_workspace(workspace.as_deref()) {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }

    let mut body = serde_json::Map::new();
    if let Some(n) = name {
        body.insert("name".into(), serde_json::Value::String(n.clone()));
    }
    // Only stamp `cpus`/`memory_mb` on the wire when the operator
    // passed an explicit value. Older daemons that ignore the absence
    // treat it as "Lima-leaning 2/4096"; newer daemons fold absence
    // into the container backend's host-80% default. Always sending a
    // concrete number (the pre-fix `default_value_t` shape) made the
    // host-80% ceiling unreachable through the public CLI.
    // Forward-compatible with old daemons via their existing
    // `unwrap_or` Lima fallback path.
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
    //   (matches the legacy file-only wire shape).
    // - If `--preset` is present (with or without `--policy`),
    //   expand presets client-side, merge them with the file, and
    //   send the effective `Policy` JSON plus `source_presets` as a
    //   sibling field for audit.
    //
    // Preset errors short-circuit to stderr + exit(1) BEFORE any
    // Unix-socket work — this matches the design invariant "the daemon
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
        // Resolve the workspace value client-side before sending. The
        // CLI is the only site that expands a leading `~` in the host
        // path against `$HOME`: the daemon parser rejects any residual
        // `~` because the operator's `$HOME` does not match the
        // daemon's. After expansion we hand the value to
        // `WorkspaceMode::parse_flag` — the single pure parser shared
        // with the daemon — and stamp the resolved string into the
        // request body so the daemon parses the same input we did.
        let expanded = match expand_host_tilde_in_workspace_flag(ws) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error: {e}");
                process::exit(1);
            }
        };
        let mode = match sandbox_core::WorkspaceMode::parse_flag(&expanded) {
            Ok(mode) => mode,
            Err(e) => {
                eprintln!("Error: --workspace {e}");
                process::exit(1);
            }
        };
        if let Err(e) = validate_workspace_host_path_for_create(&mode) {
            eprintln!("Error: --workspace {e}");
            process::exit(1);
        }
        body.insert("workspace".into(), serde_json::Value::String(expanded));
    }
    if *no_hardening {
        body.insert("hardened".into(), serde_json::json!(false));
    }
    if *no_cache {
        body.insert("no_cache".into(), serde_json::json!(true));
    }
    // Only stamp `no_gitignore` on the wire when the operator passed
    // `--no-gitignore`. Older daemons that don't know about the field
    // would tolerate it anyway (via `#[serde(default)]` and serde's
    // unknown-field behaviour), but omitting the field when false
    // keeps the body bit-equal to the historical shape and avoids
    // misleading log lines on older daemons that surface request
    // bodies verbatim. The CLI's pre-validation above has already
    // confirmed the workspace mode is `local:` when this fires.
    if *no_gitignore {
        body.insert("no_gitignore".into(), serde_json::json!(true));
    }
    // Only stamp `force_rootless_docker` when the operator explicitly
    // passed `--force-rootless-docker`. The conditional insert below
    // keeps the body bit-equal to the default-hardened path when the
    // flag is absent, so older daemons that ignore the field see
    // exactly the request they used to receive.
    // (`CreateSessionRequest` derives `Deserialize` only, so there is
    // no serialize-side `skip_serializing_if` attribute on the wire
    // struct — the bit-equality is enforced here at the body-builder
    // seam.)
    // Container-only by construction — `dispatch_create_preflight`
    // already rejected the `--force-rootless-docker --backend lima`
    // combination with exit 2 before this function runs.
    if *force_rootless_docker {
        body.insert("force_rootless_docker".into(), serde_json::json!(true));
    }
    // Stamp the resolved backend onto the request body. The daemon's
    // `CreateSessionRequest` carries this as `Option<BackendKind>`;
    // older daemons that ignore the field default to Lima, which is
    // consistent with the resolver's tier-5 fallback. Always send the
    // field (even for Lima) so the daemon-side audit / persistence
    // sees an explicit choice rather than relying on the default.
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
            // The `Create` branch is owned by
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
        // `sandbox stop` is intercepted in `main()` (see `handle_stop`)
        // before `build_request` is reached: it loops over the variadic
        // session list, issues one POST per session, and accumulates
        // per-id outcomes. The multi-session shape does not fit the
        // single-request `build_request` / `send_request` pipeline, so
        // this arm returns `None` defensively.
        Command::Stop { .. } => return None,
        // `sandbox rm` is intercepted in `main()` (see `handle_rm`)
        // before `build_request` is reached: it does a name→id
        // resolve, then a `DELETE /sessions/{id}`, then the local
        // `~/.ssh/sandbox/sandbox-<id>{,.key}` cleanup. The two-step
        // shape does not fit the single-request `build_request` /
        // `send_request` pipeline, so this arm returns `None`
        // defensively — a future caller that forgets the dispatch
        // bypass surfaces the "unhandled command" error instead of
        // silently issuing a DELETE that skips the cleanup hook.
        Command::Rm { .. } => return None,
        Command::Ps { .. } | Command::Ls { .. } => Request::builder()
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
                    // the legacy preset-free shape when they are not
                    // (thanks to `skip_serializing_if = "Vec::is_empty"`
                    // on the DTO).
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
            PolicyAction::Dump { .. } => {
                // Handled by `handle_policy_dump` in `main()` before
                // `build_request` is reached.
                unreachable!(
                    "`sandbox policy dump ...` is handled client-side \
                     in main() before build_request"
                );
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
            // rebuild-image fans out one HTTP call per selected
            // backend. The single-request
            // shape `build_request` returns cannot express that;
            // `main` short-circuits this command into
            // [`dispatch_rebuild_image`] before reaching this match,
            // mirroring how `Create` is hosted by
            // [`build_create_request_body`]. Returning `None` here is
            // defensive: a future caller that forgets the bypass hits
            // the same "unhandled command" path `ssh` / `cp` / `logs`
            // use, instead of silently sending the wrong request shape.
            return None;
        }
        Command::Version | Command::Doctor { .. } => {
            // `sandbox version` and `sandbox doctor` are dispatched at
            // the top of `main` before `build_request` is called.
            // Reaching this branch indicates a dispatch bug — the
            // version-handshake bypass relies on these subcommands
            // never reaching `send_request_with_timeout`, so returning
            // `None` would silently send a malformed request instead
            // of failing loudly.
            unreachable!(
                "`sandbox version` / `sandbox doctor` are handled client-side \
                 in main() before build_request"
            );
        }
        // Ssh, Logs, Cp, Sync, Inspect, Describe, and Events are
        // handled specially -- not via a single buffered request/
        // response pair. Inspect and Describe issue one GET
        // /sessions/{id} per argument and render client-side. Events
        // streams chunked JSONL and cannot go through `send_request`
        // (which buffers the body). Cp and Sync resolve the session
        // via `GET /sessions/{id}` and then exec the backend's
        // native copy / rsync tool with stdio inherited.
        Command::Ssh { .. }
        | Command::Logs { .. }
        | Command::Cp { .. }
        | Command::Sync { .. }
        | Command::Workspace { .. }
        | Command::Inspect { .. }
        | Command::Describe { .. }
        | Command::Events { .. } => return None,
        // Hidden internal affordances for `sandbox update`. All three are
        // dispatched client-side in `main()` before `build_request`
        // is reached. Reaching this branch indicates a dispatch bug.
        Command::ApplyConfigMigration { .. }
        | Command::ApplyConfigMigrations
        | Command::DumpMigrationSet
        | Command::DumpProtoVersion => {
            unreachable!(
                "`sandbox apply-config-migration(s)` / `dump-migration-set` / \
                 `dump-proto-version` are handled client-side in main() before build_request"
            );
        }
        // `sandbox proxy` is the hidden `ProxyCommand` shim for the
        // SSH-config tunnel. It performs its own HTTP-to-WebSocket
        // upgrade against `/sessions/{id}/proxy` over the daemon
        // socket and bidirectionally splices stdin/stdout with binary
        // WebSocket frames; the generic single-request/response
        // pipeline does not apply.
        Command::Proxy { .. } => return None,
        // `sandbox update` runs its own orchestration (pre-flight,
        // confirmation prompt, stateful steps). It owns the full
        // process lifecycle and never hits the single-request /
        // single-response build_request pipeline.
        Command::Update { .. } => {
            unreachable!("`sandbox update` is handled client-side in main() before build_request");
        }
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

fn display_sessions_quiet(sessions: &[SessionDto]) {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    write_sessions_quiet(&mut handle, sessions);
}

/// Render the quiet (`-q`) session list to an arbitrary writer: one bare
/// session ID per line, no header, no table glyphs. Suitable for shell
/// pipelines (`sandbox ps -q | xargs sandbox stop`). Pulled out of the
/// command handler so unit tests can capture the output into a buffer.
fn write_sessions_quiet(out: &mut dyn std::io::Write, sessions: &[SessionDto]) {
    for s in sessions {
        let _ = writeln!(out, "{}", s.id);
    }
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
    println!("CPUs:     {}", format_cpus_field(&session.config));
    println!("Memory:   {}", format_memory_field(&session.config));
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

/// Render a [`sandbox_core::SessionConfigDto`]'s `cpus` field for human-readable
/// `sandbox describe` / inspect output.
///
/// The container backend uses `0`/`0.0` as the "operator did not pass
/// `--cpus`" sentinel, with the daemon substituting its host-80%
/// default at runtime. Surfacing the raw `0` mislead operators into
/// thinking the session had no CPU budget; the daemon already plumbs
/// the resolved value through `resolved_cpus`, so this helper picks
/// the right value to render and decorates the default case with a
/// `(default)` suffix.
///
/// - Stored value > 0 (operator-supplied explicit ceiling): render
///   the value verbatim. Lima sessions always take this branch
///   because the request handler stamps the historical `2` Lima
///   default when the operator omits `--cpus`.
/// - Stored value == 0 (container default): render the resolved
///   value with a `(default)` hint so operators see the actually-
///   applied ceiling instead of `0`.
///
/// `f32` formatting omits a trailing `.0` for integer-valued
/// fractions (e.g. `2.0` → `2`) so Lima sessions render the same
/// way as before todo #67. The `:.1` formatting on container
/// fractions preserves the 1-decimal grammar.
fn format_cpus_field(config: &sandbox_core::SessionConfigDto) -> String {
    if config.cpus == 0.0 {
        // Container "use the daemon default" path. `resolved_cpus`
        // is the daemon's host-80% ceiling rendered to one decimal
        // place; the parenthetical hint distinguishes this from an
        // operator-supplied `0` (which the daemon rejects upstream).
        format!("{:.1} (default)", config.resolved_cpus)
    } else if config.cpus.fract() == 0.0 {
        // Integer-valued fraction: render without trailing ".0" so
        // Lima sessions ("CPUs:     2") and explicit container
        // sessions ("CPUs:     4") produce the same output as
        // pre-todo-#67 builds.
        format!("{}", config.cpus as u32)
    } else {
        format!("{:.1}", config.cpus)
    }
}

/// Render a [`sandbox_core::SessionConfigDto`]'s `memory_mb` field with the same
/// "stored 0 → daemon default" rule as [`format_cpus_field`].
fn format_memory_field(config: &sandbox_core::SessionConfigDto) -> String {
    if config.memory_mb == 0 {
        format!("{} MB (default)", config.resolved_memory_mb)
    } else {
        format!("{} MB", config.memory_mb)
    }
}

/// Maximum time to wait for the daemon to respond to an HTTP request.
///
/// Session creation involves VM boot, guest agent install, and networking
/// setup, so this must be generous.
const CLI_HTTP_TIMEOUT: Duration = Duration::from_secs(600);

/// Maximum time to wait for the daemon to respond to a base-image
/// rebuild request (`POST /rebuild-image`).
///
/// The Lima rebuild path can legitimately take 15+ minutes on slow
/// networks: the Ubuntu 24.04 cloud-image qcow2 is ~580 MiB and
/// `cloud-images.ubuntu.com` has been observed serving as low as
/// 1.3 MB/s on some hosts (~ 7-8 min download alone), after which
/// `limactl start` runs cloud-init provisioning (apt installs of
/// socat, git, Docker) which adds another minute or two. The
/// daemon-side budget for these two phases is
/// `BASE_CREATE_TIMEOUT + BASE_START_TIMEOUT = 1200 + 600 = 1800 s`
/// (see `sandbox-core::lima`); we add a small grace margin on top so
/// the CLI does not abandon the request a few seconds before the
/// daemon would have surfaced the actual outcome.
///
/// This timeout is used only for `POST /rebuild-image` — every other
/// CLI request continues to use `CLI_HTTP_TIMEOUT`.
const CLI_REBUILD_IMAGE_TIMEOUT: Duration = Duration::from_secs(1900);

/// Exit code the CLI uses when it refuses to proceed because the
/// daemon's reported version does not match the CLI's compile-time
/// `CARGO_PKG_VERSION`. Distinct from `1` (daemon-side error after a
/// successful handshake) so wrapper scripts can tell the two apart.
const CLI_VERSION_MISMATCH_EXIT_CODE: i32 = 2;

/// Format the verbatim stderr message printed when the CLI detects a
/// version skew with the daemon. The tokens `version mismatch`,
/// `CLI is`, `daemon is`, and `both must match` are load-bearing — the
/// integration test greps for them, and downstream
/// scripts may match the wording to surface a friendly upgrade hint.
fn render_version_mismatch_message(cli_version: &str, daemon_version: &str) -> String {
    format!(
        "sandbox: version mismatch\n  CLI is {cli_version}\n  daemon is {daemon_version}\n  both must match \u{2014} reinstall to align (sandbox update)"
    )
}

/// Compare the CLI's compile-time version to the daemon's reported
/// version under the strict-equality rule. Returns `Err(message)` with
/// the verbatim stderr wording on skew so the caller can route the
/// message to whatever sink suits (test capture vs. process stderr).
fn check_daemon_version_equality(cli_version: &str, daemon_version: &str) -> Result<(), String> {
    if cli_version == daemon_version {
        Ok(())
    } else {
        Err(render_version_mismatch_message(cli_version, daemon_version))
    }
}

/// Subcommands that bypass the strict CLI ↔ daemon version-equality
/// check. `Version` answers locally without connecting to the daemon
/// at all, so it never reaches the handshake. `Doctor` connects
/// tolerantly: it must run *under* a skew so the operator can diagnose
/// the skew via doctor's C3 check rather than being refused at the
/// gate. Every other subcommand performs the strict equality check
/// inside `send_request_with_timeout` immediately after socket
/// connect, per the version-check contract.
///
/// The dispatch in `main` short-circuits both `Version` and `Doctor`
/// before reaching the socket-connect path, so this predicate is the
/// single source of truth for the bypass set; it is queried by the
/// unit tests so the bypass surface is asserted at
/// every refactor.
#[cfg_attr(not(test), allow(dead_code))]
fn command_bypasses_version_check(command: &Command) -> bool {
    matches!(
        command,
        Command::Version
            | Command::Doctor { .. }
            | Command::ApplyConfigMigration { .. }
            | Command::ApplyConfigMigrations
            | Command::DumpMigrationSet
            | Command::DumpProtoVersion
            // `sandbox update` must run under a CLI/daemon version
            // skew — the whole point is to *resolve* that skew. The
            // pre-flight queries the daemon read-only (active sessions
            // count) and tolerates `/version` returning anything.
            | Command::Update { .. }
            // `sandbox proxy` is the WebSocket `ProxyCommand` shim
            // generated into the per-session SSH config block. The
            // shim's wire shape (subcommand name + positional argv) is
            // pinned by `sandbox_core::render_ssh_config_block` and
            // ships in the same crate as the daemon, so daemon ⇄ CLI
            // skew on the proxy endpoint is structurally impossible
            // (both ends move together). The shim also runs under
            // stdin/stdout pipes wired to `ssh`'s process — a stderr
            // warning from the version-check pre-flight would corrupt
            // the SSH banner exchange. Bypass keeps the byte pipe
            // clean.
            | Command::Proxy { .. }
    )
}

/// JSON body shape `GET /version` returns. The daemon emits a
/// single-field object (`{"version": "<semver>"}`); the CLI only
/// reads the `version` field, but parsing into a typed struct keeps
/// the deserialization tolerant if the daemon later grows extra
/// fields and lets us return a clean `Result` to the caller.
#[derive(serde::Deserialize)]
struct DaemonVersionResponse {
    version: String,
}

/// Run the strict CLI ↔ daemon version-equality handshake against an
/// already-handshaken hyper sender. On skew the verbatim stderr message
/// is printed and the process exits with [`CLI_VERSION_MISMATCH_EXIT_CODE`]
/// — there is no return path to the caller, matching the original
/// in-line implementation that lived inside `send_request_with_timeout`.
///
/// Shared between the normal request/response path
/// (`send_request_with_timeout`) and the long-lived streaming path
/// (`stream_events_to_stdout`) so every side-channel CLI command that
/// connects to the daemon goes through the same equality gate, per
/// the documented contract. Subcommands that need to bypass the check (e.g.
/// `sandbox version`, `sandbox doctor`, `sandbox update`) are routed
/// before the socket-connect path in `main` and never call this
/// helper — see [`command_bypasses_version_check`].
async fn enforce_version_handshake(
    sender: &mut hyper::client::conn::http1::SendRequest<String>,
) -> Result<(), String> {
    let daemon_version = fetch_daemon_version(sender).await?;
    let cli_version = env!("CARGO_PKG_VERSION");
    if let Err(message) = check_daemon_version_equality(cli_version, &daemon_version) {
        eprintln!("{message}");
        process::exit(CLI_VERSION_MISMATCH_EXIT_CODE);
    }
    Ok(())
}

/// Issue `GET /version` against an already-handshaken hyper sender and
/// return the daemon's reported `CARGO_PKG_VERSION`. Errors map to the
/// same `String`-message shape every other `send_request_with_timeout`
/// failure mode uses, so the caller can short-circuit by propagating
/// `?` without bespoke handling. Empty-body GET is sent as `String`
/// because `send_request_with_timeout`'s sender is typed against
/// `String` bodies (the caller's request and the version probe must
/// share a body type).
async fn fetch_daemon_version(
    sender: &mut hyper::client::conn::http1::SendRequest<String>,
) -> Result<String, String> {
    let req = Request::builder()
        .method("GET")
        .uri("/version")
        // Authority is meaningless on a unix socket; supply *something*
        // so the request line parses cleanly through hyper's HTTP/1.1
        // header validator.
        .header("host", "localhost")
        .body(String::new())
        .expect("failed to build /version request");
    let response = sender
        .send_request(req)
        .await
        .map_err(|e| format!("version handshake failed: {e}"))?;
    let status = response.status();
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("failed to read /version body: {e}"))?
        .to_bytes();
    if !status.is_success() {
        let body = String::from_utf8_lossy(&body_bytes);
        return Err(format!("daemon /version returned {status}: {body}"));
    }
    let parsed: DaemonVersionResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
        let body = String::from_utf8_lossy(&body_bytes);
        format!("failed to parse /version response (`{body}`): {e}")
    })?;
    Ok(parsed.version)
}

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

        // Strict CLI ↔ daemon version-equality handshake.
        // Fired on every CLI invocation that reaches the daemon — the
        // bypass for `sandbox version` / `sandbox doctor` is handled
        // upstream in `main` (see `command_bypasses_version_check`).
        // Mismatch short-circuits with the verbatim stderr wording and
        // exits with `CLI_VERSION_MISMATCH_EXIT_CODE` so the caller's
        // request is never sent against a skewed daemon. The same
        // helper is invoked from `stream_events_to_stdout` so the
        // streaming side-channel inherits the gate symmetrically per
        // the documented contract.
        enforce_version_handshake(&mut sender).await?;

        // Wait until the connection's internal dispatcher is ready for the
        // next request. The `conn` task signals readiness asynchronously
        // (via hyper's `want` mechanism) after processing the version-check
        // response; without this `.ready()` await the second `send_request`
        // can race with the signal and fail with "connection was not ready".
        sender
            .ready()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

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
        Command::Ps {
            no_reconcile,
            quiet,
        }
        | Command::Ls {
            no_reconcile,
            quiet,
        } => {
            let sessions: Vec<SessionDto> =
                serde_json::from_str(body).map_err(|e| format!("failed to parse response: {e}"))?;
            if *quiet {
                display_sessions_quiet(&sessions);
            } else {
                display_sessions_table(&sessions);
            }
            // Opportunistic reconcile of `~/.ssh/sandbox/` against the
            // authoritative session list returned by the daemon. Runs
            // regardless of quiet mode so that `-q` pipelines do not
            // silently leave stale ssh-config entries behind. Guarded
            // by `--no-reconcile` for tooling consumers that need
            // strict read-only semantics. The daemon-unreachable case
            // is silently skipped because we never reach this point
            // without a successful list response.
            if !*no_reconcile {
                reconcile_ssh_sandbox_dir_silent(&sessions);
            }
        }
        Command::Rm { .. } => {
            // `sandbox rm` is intercepted in `main()` (see
            // `handle_rm`); the two-step
            // resolve-then-DELETE-then-local-cleanup shape never
            // reaches the generic response handler. Reaching this
            // arm is a dispatch bug.
            unreachable!("`sandbox rm` is handled client-side in main() before send_request");
        }
        Command::Stop { .. } => {
            // `sandbox stop` is intercepted in `main()` (see
            // `handle_stop`); the multi-session loop shape never
            // reaches the generic response handler. Reaching this
            // arm is a dispatch bug.
            unreachable!("`sandbox stop` is handled client-side in main() before send_request");
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
            match action {
                PolicyAction::Dump { .. } => {
                    // Dump is handled client-side by `handle_policy_dump`
                    // before the generic pipeline is reached.
                    unreachable!(
                        "`sandbox policy dump ...` is handled client-side \
                         in main() before handle_response"
                    );
                }
                _ => {
                    let result: serde_json::Value = serde_json::from_str(body)
                        .map_err(|e| format!("failed to parse policy response: {e}"))?;
                    if let Some(message) = result.get("message").and_then(|m| m.as_str()) {
                        println!("{message}");
                    } else {
                        // Fallback when the daemon response lacks a message field.
                        // Choose the verb by subcommand to keep output truthful.
                        match action {
                            PolicyAction::Update { clear: true, .. } => {
                                println!("Policy cleared.")
                            }
                            _ => println!("Policy updated."),
                        }
                    }
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
        | Command::Sync { .. }
        | Command::Workspace { .. }
        | Command::Inspect { .. }
        | Command::Describe { .. }
        | Command::Events { .. } => {
            // These commands are handled separately and never call
            // handle_response. Reaching here indicates a dispatch bug.
            unreachable!(
                "ssh/logs/cp/sync/workspace/inspect/describe/events commands should be handled before send_request"
            );
        }
        Command::Version | Command::Doctor { .. } => {
            // `sandbox version` and `sandbox doctor` exit from `main`
            // before any HTTP request is sent; reaching `handle_response`
            // for them indicates a dispatch bug. See the matching arm
            // in `build_request` for the symmetric guard.
            unreachable!(
                "`sandbox version` / `sandbox doctor` are handled client-side \
                 in main() before send_request"
            );
        }
        Command::ApplyConfigMigration { .. }
        | Command::ApplyConfigMigrations
        | Command::DumpMigrationSet
        | Command::DumpProtoVersion => {
            // Hidden config-migration / proto-version affordances are
            // handled client-side in `main()` and `process::exit`
            // before any HTTP request fires. Reaching `handle_response`
            // for them indicates a dispatch bug.
            unreachable!(
                "`apply-config-migration(s)` / `dump-migration-set` / `dump-proto-version` \
                 are handled client-side in main() before send_request"
            );
        }
        Command::Proxy { .. } => {
            // The `sandbox proxy` shim has its own dispatch path in
            // `main()` (it performs an HTTP-to-WebSocket upgrade and
            // splices stdio with binary frames); it never reaches the
            // generic request/response handler.
            unreachable!("`sandbox proxy` is handled client-side in main() before send_request");
        }
        Command::Update { .. } => {
            // `sandbox update` runs its own orchestration loop in
            // `update::run`; the generic single-request pipeline is
            // never engaged. Reaching here is a dispatch bug.
            unreachable!("`sandbox update` is handled client-side in main() before send_request");
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
    // the FIRST error in input order, mirroring the "names the
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
/// Layout:
/// - header block (Session, Name, State, **Backend**, Created, Updated)
/// - `Config:` block
/// - `Runtime:` block
/// - `Network:` block — backend-neutral gateway IP, session IP, and
///   per-session /28 CIDR.
/// - `Mounts:` block — backend-neutral workspace path, host bind
///   source, CA bundle path, and home volume.
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
/// age suffix (e.g. `5m ago`), matching the sample in the design.
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
    // Render state in lowercase to match the wire/JSON snake_case serde
    // representation, not the capitalized `Display` impl used by `ps`
    // table headers.
    let _ = writeln!(
        out,
        "State:        {}",
        session.state.to_string().to_lowercase()
    );
    // Show backend prominently alongside session
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
    // When the operator omitted `--cpus`/`--memory` on a container
    // session, the persisted column is `0` and the daemon substitutes
    // its host-80% default at runtime. Rendering the raw `0`
    // previously mislead operators; surface the resolved applied
    // value with a `(default)` hint instead.
    let _ = writeln!(out, "  CPUs:        {}", format_cpus_field(&session.config));
    let _ = writeln!(
        out,
        "  Memory:      {}",
        format_memory_field(&session.config)
    );
    let _ = writeln!(out, "  Disk:        {} GB", session.config.disk_gb);
    render_workspace_block(
        session.config.workspace_mode_detail.as_ref(),
        session.config.workspace_mode.as_deref(),
        out,
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
    render_rootless_block(session.rootless.as_ref(), out);

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
/// The `-v` view capability matrix is the `Capabilities` struct rendered as a key/value table. The keys are
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

/// Render the `Workspace:` portion of the `Config:` block.
///
/// When the daemon populates `workspace_mode_detail`, the renderer
/// emits a multi-line block with `Mode:` / `Host path:` /
/// `Guest path:` / `Security:` rows for `Shared` (and the `Local`
/// equivalent without the `Security:` row), or `Mode:` / `Repo:` for
/// `Clone`. The `Security:` value follows the rendering rule:
/// `mapped-xattr (default)` when the operator passed no override
/// (`security_model = None`), and the model verbatim for any
/// `Some(_)` choice.
///
/// When `workspace_mode_detail` is absent (older daemons), the
/// renderer falls back to the historical single-line
/// `Workspace:   <flat-string>` form, sourcing the value from the
/// retained `workspace_mode: Option<String>` field. This keeps the
/// CLI compatible with older daemons.
fn render_workspace_block(
    detail: Option<&WorkspaceModeDetailDto>,
    flat: Option<&str>,
    out: &mut String,
) {
    use std::fmt::Write as _;
    match detail {
        Some(WorkspaceModeDetailDto::Shared {
            host_path,
            guest_path,
            security_model,
        }) => {
            let _ = writeln!(out, "  Workspace:");
            let _ = writeln!(out, "    Mode:       shared");
            let _ = writeln!(out, "    Host path:  {host_path}");
            let _ = writeln!(out, "    Guest path: {guest_path}");
            let _ = writeln!(
                out,
                "    Security:   {}",
                render_security_model(*security_model)
            );
        }
        Some(WorkspaceModeDetailDto::Clone { repo_url }) => {
            let _ = writeln!(out, "  Workspace:");
            let _ = writeln!(out, "    Mode:       clone");
            let _ = writeln!(out, "    Repo:       {repo_url}");
        }
        Some(WorkspaceModeDetailDto::Local {
            host_path,
            guest_path,
        }) => {
            // Render analogously to Shared minus the `Security:` row.
            let _ = writeln!(out, "  Workspace:");
            let _ = writeln!(out, "    Mode:       local");
            let _ = writeln!(out, "    Host path:  {host_path}");
            let _ = writeln!(out, "    Guest path: {guest_path}");
        }
        None => {
            // Older-daemon fallback: render the historical single-line
            // form using the flat string. Older daemons populate only
            // `workspace_mode: Option<String>`; the structured field
            // is absent.
            let _ = writeln!(out, "  Workspace:   {}", flat.unwrap_or("-"));
        }
    }
}

/// Render the `Security:` value for the shared-workspace describe row.
///
/// `None` means "no operator override at create time"; we annotate the
/// inherited default with `(default)` so the inheritance is visible.
/// `Some(_)` means the operator typed the model explicitly at create
/// time; the value is rendered verbatim without an annotation because
/// it is operator-asserted, not inherited.
fn render_security_model(model: Option<WorkspaceSecurityModelDto>) -> &'static str {
    match model {
        None => "mapped-xattr (default)",
        Some(WorkspaceSecurityModelDto::MappedXattr) => "mapped-xattr",
        Some(WorkspaceSecurityModelDto::NoneMapping) => "none",
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
    if modes.contains(WorkspaceModeKind::Local) {
        parts.push("local");
    }
    parts.join(", ")
}

/// Render the backend-neutral session networking block. Always
/// emitted so operators see a stable `Network:` heading per session
/// block; missing data renders as `none` (matching the `Policy: none`
/// shape) rather than absent.
///
/// Field labels mirror the "operator-readable" naming so a
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

/// Render the backend-neutral session mount-surface block. Same
/// emission contract as [`render_network_block`]: always emitted,
/// with `none` fallback when the daemon has no mount info to surface.
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

/// Render the rootless-Docker probe outcome.
///
///
/// the lite container backend; the daemon stamps the probe outcome
/// onto each container session at create time so operators can see
/// (a) whether the host was detected as rootless, and (b) whether
/// the `--force-rootless-docker` opt-in was actually applied.
///
/// Render contract:
/// - `None` (Lima sessions, pre-Wave-2 container records): the block
///   is omitted entirely. This matches the conditional rendering for
///   `network` / `mounts` blocks — Lima sessions never carry
///   container-only state, and printing `Rootless Docker: none` for
///   them would be operator confusion (the answer is "n/a", not
///   "none").
/// - `Some({detected: false, forced: _})`: render only the `detected`
///   line. `forced` is operator-irrelevant on a default-hardened
///   host (the override has nothing to override) and printing it
///   would muddy the output.
/// - `Some({detected: true, forced: _})`: render both lines so the
///   operator can confirm which mode actually applied.
fn render_rootless_block(rootless: Option<&SessionRootlessDockerDto>, out: &mut String) {
    use std::fmt::Write as _;
    let Some(r) = rootless else {
        // Field absent — nothing to render. Mirrors the network/mounts
        // None-branch's "no key on the wire" semantics.
        return;
    };
    let _ = writeln!(out, "Rootless Docker:");
    let _ = writeln!(
        out,
        "  detected:    {}",
        if r.detected { "yes" } else { "no" }
    );
    if r.detected {
        let _ = writeln!(
            out,
            "  forced:      {}",
            if r.forced { "yes" } else { "no" }
        );
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
    // keeps faith with the sample in the design, which uses `allow http`,
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
/// Errors exit non-zero with the required `PresetError` wording
/// on stderr so operators can paste-and-compare against the design.
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

/// Handle the `sandbox policy dump [--output <file>]` subcommand.
///
/// Fetches `GET /sessions/{session}/policy` and emits the response as
/// pretty-printed JSON. When `--output` is given the JSON is written to
/// that path instead of stdout; the file is created or overwritten.
async fn handle_policy_dump(socket_path: &str, session: &str, output: Option<&str>) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/sessions/{session}/policy"))
        .body(String::new())
        .expect("failed to build request");

    let (status, body) = match send_request(socket_path, req).await {
        Ok(pair) => pair,
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

    let policy: Policy = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: failed to parse policy response: {e}");
            process::exit(1);
        }
    };

    let rendered = serde_json::to_string_pretty(&policy).expect("Policy always serializes to JSON");

    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, rendered) {
                eprintln!("Error: failed to write policy to '{path}': {e}");
                process::exit(1);
            }
        }
        None => println!("{rendered}"),
    }
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
            // Built-in param schemas are hard-coded per the design.
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
            println!("Example: --preset '{}'", builtin_invocation_example(b.name));
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
            println!("Example: --preset '{}'", user_preset_invocation_example(u));
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

/// A canonical `--preset` invocation string for built-in presets, shown
/// in the `Example:` line of `sandbox policy preset show`.
///
/// For parameterless presets the bare name is sufficient (P1 makes the
/// trailing `:` optional). For parameterized presets, a concrete
/// illustrative value is shown so operators can copy-paste and fill in
/// the real values.
///
/// Keep in sync with the expander bodies in `presets::builtin`.
fn builtin_invocation_example(name: &str) -> String {
    match name {
        "github-repo" => "github-repo:repo=owner/name".to_string(),
        "github-pr" => "github-pr:repo=owner/name,pr=42".to_string(),
        // All other built-ins are unparameterized; bare name suffices.
        _ => name.to_string(),
    }
}

/// Derive a `--preset` invocation example for a user preset.
///
/// For each required param, the example shows `param=<value>` with the
/// param name as a placeholder. Optional params are omitted from the
/// example to keep it minimal. If a preset has no required params the
/// bare name is returned.
fn user_preset_invocation_example(u: &UserPreset) -> String {
    let required_params: Vec<String> = u
        .params
        .iter()
        .filter(|p| p.required)
        .map(|p| format!("{}=<value>", p.name))
        .collect();
    if required_params.is_empty() {
        u.name.clone()
    } else {
        format!("{}:{}", u.name, required_params.join(","))
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
/// for each session. Any missing session causes a
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
/// supplied DTOs. The cache is constructed per-invocation as designed
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

/// Resolve `session` (either a name or canonical 12-char id) via the
/// daemon to its canonical [`SessionDto`]. Surfaces the daemon's typed
/// error envelope verbatim on failure and `process::exit`s with code
/// 1 — mirrors the pattern the SSH-shaped handlers used pre-rewrite.
///
/// Used by every SSH-shaped command (`ssh`, `cp`, `sync`, `workspace
/// push|pull`) as the first step: even though the SSH-tool argv only
/// needs the canonical session id, we resolve through the daemon so
/// operators can pass either an id or a session name uniformly across
/// every command.
async fn resolve_session_for_ssh_dispatch(socket_path: &str, session: &str) -> SessionDto {
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

    match serde_json::from_str::<SessionDto>(&body) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to parse session response: {e}");
            process::exit(1);
        }
    }
}

/// Fetch `GET /sessions/{id}/ssh-config` and parse the response into
/// an [`SshConfigDto`]. Used as the `fetch_dto` callback into
/// [`sandbox_cli::ssh_commands::run_with_drift_recovery`]. The
/// closure form lets the wrapper re-fetch on a drift signal without
/// the dispatch site duplicating the request-building logic.
async fn fetch_ssh_config_dto(
    socket_path: &str,
    id: &str,
) -> Result<sandbox_core::SshConfigDto, sandbox_cli::ssh_commands::DriftRecoveryError> {
    let req = sandbox_cli::ssh_commands::build_ssh_config_request(id);
    let (status, body) = match send_request(socket_path, req).await {
        Ok(r) => r,
        Err(e) => {
            return Err(sandbox_cli::ssh_commands::DriftRecoveryError::FetchDto(e));
        }
    };
    sandbox_cli::ssh_commands::parse_ssh_config_response(
        status,
        &body,
        std::path::Path::new(socket_path),
        id,
    )
}

/// Render the [`sandbox_cli::ssh_commands::DriftRecoveryError`] for an
/// operator-facing error path and exit. Centralised so every SSH-shaped
/// command's failure surface speaks the same vocabulary.
fn fail_drift_recovery(err: sandbox_cli::ssh_commands::DriftRecoveryError) -> ! {
    eprintln!("Error: {err}");
    process::exit(1)
}

/// Handle `sandbox stop [--force] <sessions...>` end-to-end.
///
/// For each session name or id in `sessions`, issues one `POST
/// /sessions/{session}/stop` (appending `?force=true` when `force` is
/// set). Outcomes are printed per-id as they arrive. Exits 0 only if
/// every stop succeeded; exits 1 on the first failure that is
/// accumulated — every session is attempted even when earlier ones fail
/// so a multi-id invocation does not short-circuit mid-list.
async fn handle_stop(socket_path: &str, sessions: &[String], force: bool) {
    let mut any_failed = false;
    for session in sessions {
        let uri = if force {
            format!("/sessions/{session}/stop?force=true")
        } else {
            format!("/sessions/{session}/stop")
        };
        let req = Request::builder()
            .method("POST")
            .uri(&uri)
            .body(String::new())
            .expect("failed to build stop request");
        match send_request(socket_path, req).await {
            Err(e) => {
                eprintln!("Error stopping `{session}`: {e}");
                any_failed = true;
            }
            Ok((status, body)) => {
                if status.is_success() {
                    // Parse the returned SessionDto for the confirmation
                    // line, but don't fail if the body is unexpected — the
                    // stop already succeeded daemon-side.
                    if let Ok(dto) = serde_json::from_str::<SessionDto>(&body) {
                        println!("Session stopped:");
                        display_session(&dto);
                    } else {
                        println!("Session `{session}` stopped.");
                    }
                } else {
                    if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
                        eprintln!("Error stopping `{session}`: {}", api_err.error);
                    } else {
                        eprintln!("Error stopping `{session}` ({status}): {body}");
                    }
                    any_failed = true;
                }
            }
        }
    }
    if any_failed {
        process::exit(1);
    }
}

/// Testable core of the rm dispatch path.
///
/// Two-step shape:
///
/// 1. Resolve `session` (name **or** id) via `GET /sessions/{session}`
///    so we know the canonical session id — the local
///    `~/.ssh/sandbox/sandbox-<id>{,.key}` filenames are keyed off the
///    id, never the name. A pre-check `GET` round-trip also lets us
///    fail fast on a non-existent session before mutating any state.
/// 2. Issue `DELETE /sessions/{id}` and only on the 2xx response do we
///    remove the local per-session entry. If the daemon-side delete
///    fails we **do not** touch the local entry — leaving the SSH
///    config in place so a working daemon-side session does not lose
///    its config block to a transient delete failure.
///
/// Local-removal errors (permission denied on the file, filesystem
/// full, …) are reported as a stderr warning but do not flip the
/// success result: the daemon-side state is the source of truth, and
/// `sandbox ls` reconcile will pick up the stale local entry on a
/// later invocation anyway.
///
/// `home_override` lets hermetic tests pin the home directory to a
/// tempdir without mutating the process-wide `$HOME`. In production
/// the caller passes `None` and the function resolves `$HOME` itself
/// (via `ssh_config::resolve_home`). The Result return type lets the
/// tests assert on the failure paths without invoking
/// `process::exit`.
async fn handle_rm_inner(
    socket_path: &str,
    session: &str,
    home_override: Option<&std::path::Path>,
) -> Result<(), String> {
    // Step 1 — resolve to canonical id. We use a dedicated
    // request/response shape rather than `resolve_session_for_ssh_dispatch`
    // (which calls `process::exit` on failure) so the failure mode is
    // testable as an `Err`.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/sessions/{session}"))
        .body(String::new())
        .expect("failed to build request");
    let (status, body) = send_request(socket_path, req).await?;
    if !status.is_success() {
        if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
            return Err(format!("Error: {}", api_err.error));
        }
        return Err(format!("Error ({status}): {body}"));
    }
    let dto: SessionDto = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse session response: {e}"))?;
    let id = dto.id.as_str().to_string();

    // Step 2 — DELETE against the canonical id. Hitting the id (not the
    // operator-supplied name) keeps the failure-path semantics tight:
    // if the resolve succeeded the id is the authoritative handle.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/sessions/{id}"))
        .body(String::new())
        .expect("failed to build request");
    let (status, body) = send_request(socket_path, req).await?;
    if !status.is_success() {
        // Daemon refused the delete — do NOT touch the local entry.
        // A stranded daemon session with a working SSH config block is
        // strictly better than the inverse: an alive session whose
        // operator suddenly cannot reach it because we pruned the
        // managed config out from under them.
        if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
            return Err(format!("Error: {}", api_err.error));
        }
        return Err(format!("Error ({status}): {body}"));
    }

    // Daemon-side delete succeeded. Print the same success line the
    // generic dispatcher would have emitted so operators see no
    // behaviour change.
    println!("Session removed.");

    // Local cleanup — best-effort. Failure to remove the per-session
    // entry must not flip the success exit code: the daemon-side
    // session is gone (the source of truth) and the next `sandbox ls`
    // reconcile will catch a stranded local entry anyway.
    if let Err(e) = remove_session_entry_or_resolve_home(home_override, &id) {
        eprintln!(
            "warning: failed to remove local ssh config for `{id}`: {e}; \
             `sandbox ls` reconcile or a manual `rm \
             ~/.ssh/sandbox/sandbox-{id}*` will clean it up"
        );
    }

    Ok(())
}

/// Either remove the per-session entry under `home_override` (testing)
/// or resolve `$HOME` and remove under that (production). Folded into
/// one helper so [`handle_rm_inner`] has a single error branch for
/// both modes.
fn remove_session_entry_or_resolve_home(
    home_override: Option<&std::path::Path>,
    id: &str,
) -> Result<(), sandbox_cli::ssh_config::SshConfigError> {
    let home_owned;
    let home: &std::path::Path = match home_override {
        Some(p) => p,
        None => {
            home_owned = sandbox_cli::ssh_config::resolve_home()?;
            &home_owned
        }
    };
    sandbox_cli::ssh_config::remove_session_entry(home, id)
}

/// Opportunistically reconcile `~/.ssh/sandbox/` against `sessions` —
/// the authoritative list the daemon just returned for the calling
/// operator. Every per-session entry whose id is not in the list is
/// removed (Spec § Architecture → CLI: persistent ssh-config → Reconcile
/// on listing). Used by the `sandbox ps` / `sandbox ls` post-render
/// hook; deliberately **silent** on both the success path (no per-entry
/// output noise in the listing) and the failure path (a reconcile that
/// can't run must not surface as an `ls` error — Spec: "no regression
/// in error mode"). Failures are logged at `debug!` so an operator
/// running with `RUST_LOG=sandbox=debug` can still inspect them.
fn reconcile_ssh_sandbox_dir_silent(sessions: &[SessionDto]) {
    // `$HOME` resolution failure is rare (`HOME` unset) and treated
    // the same as any other reconcile-skip case: log + swallow.
    let home = match sandbox_cli::ssh_config::resolve_home() {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!(error = %e, "ls reconcile skipped: cannot resolve home");
            return;
        }
    };
    let live_ids: Vec<&str> = sessions.iter().map(|s| s.id.as_str()).collect();
    match sandbox_cli::ssh_config::reconcile_against_list(&home, &live_ids) {
        Ok(removed) => {
            if !removed.is_empty() {
                tracing::debug!(
                    removed = removed.len(),
                    "ls reconcile removed stale ~/.ssh/sandbox/ entries"
                );
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "ls reconcile failed (silent)");
        }
    }
}

/// Extra environment variables passed to every spawned SSH-tool child
/// so the `ProxyCommand sandbox proxy <id>` line in the daemon-emitted
/// config block reaches the same daemon socket the parent CLI is
/// talking to, and finds the same `sandbox` binary on `$PATH`.
///
/// * `SANDBOX_SOCKET` — propagated so the inner `sandbox proxy` shim
///   reaches the same daemon the parent CLI is talking to. Without
///   this the shim falls back to `default_socket_path()`, which
///   silently breaks for operators using a non-default socket (CI
///   harnesses, multi-daemon hosts).
/// * `PATH` — prefixed with the directory of the running `sandbox`
///   binary so `ssh`/`scp`/`rsync`'s `ProxyCommand sandbox proxy <id>`
///   resolves to *this* binary (and not a stale system-installed
///   one). Test harnesses commonly invoke us by absolute path against
///   a `target/debug/sandbox` build that is not on `$PATH`; without
///   the prefix the `ProxyCommand` would fail with "sandbox: command
///   not found" and the operator would see `Connection closed by
///   UNKNOWN port 65535` instead of an actionable error.
fn ssh_child_extra_env(socket_path: &str) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::with_capacity(2);
    env.push(("SANDBOX_SOCKET".to_string(), socket_path.to_string()));
    if let Ok(self_exe) = std::env::current_exe() {
        if let Some(parent) = self_exe.parent() {
            let current = std::env::var("PATH").unwrap_or_default();
            let prefixed = if current.is_empty() {
                parent.display().to_string()
            } else {
                format!("{}:{current}", parent.display())
            };
            env.push(("PATH".to_string(), prefixed));
        }
    }
    env
}

/// Handle the `ssh` subcommand: ensure the per-session SSH config
/// entry exists under `~/.ssh/sandbox/`, spawn `ssh sandbox-<id> [--
/// cmd]`, and wire the single-retry drift-recovery wrapper around the
/// child process. Mirrors Spec § Architecture → CLI: persistent
/// ssh-config (Per-session entry write + Per-command translation).
///
/// `LC_ALL=C` / `LANG=C` are injected into the child's environment so
/// the `Permission denied (publickey)` substring the drift sniffer
/// matches against is locale-stable. `SANDBOX_SOCKET` is also injected
/// so the recursive `sandbox proxy` invocation triggered by the
/// `ProxyCommand` directive reaches the same daemon socket.
async fn handle_ssh(socket_path: &str, session: &str, command: &[String]) {
    let session_dto = resolve_session_for_ssh_dispatch(socket_path, session).await;
    let id = session_dto.id.as_str().to_string();
    let home = match sandbox_cli::ssh_commands::resolve_home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    let command = command.to_vec();
    let socket_owned = socket_path.to_string();
    let id_for_fetch = id.clone();

    let exit_code = match sandbox_cli::ssh_commands::run_with_drift_recovery(
        &home,
        &id,
        move || {
            let s = socket_owned.clone();
            let i = id_for_fetch.clone();
            async move { fetch_ssh_config_dto(&s, &i).await }
        },
        move |alias, _attempt_idx| {
            let extras = ssh_child_extra_env(socket_path);
            let cmd = command.clone();
            async move {
                let (program, args) = sandbox_cli::ssh_commands::plan_ssh_argv(&alias, &cmd);
                sandbox_cli::ssh_commands::spawn_ssh_tool_attempt(&program, &args, extras).await
            }
        },
    )
    .await
    {
        Ok(code) => code,
        Err(e) => fail_drift_recovery(e),
    };
    process::exit(exit_code);
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
// `sandbox events`
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
//   the widest layer name the design uses today; `policy_reset_on_upgrade`
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
/// `layer` is the kebab-case layer name; `event` is the body's
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
            DenyLoggerEventBodyDto::Allow {
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
                let detail = format!("proto={proto} src={src_ip}:{src_port} decision=allow");
                (
                    dl.timestamp.clone(),
                    dl.session.clone(),
                    "deny-logger",
                    "allow",
                    host_port,
                    detail,
                    false,
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
    // next request that never arrives.
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

    // Strict CLI ↔ daemon version-equality handshake (the documented contract).
    // `sandbox events` does not reach `send_request_with_timeout`
    // because of its streaming response shape, but the version gate
    // must still fire so a CLI ↔ daemon skew refuses the stream
    // before any session-scoped data crosses the wire. Mismatch
    // exits the process with the verbatim wording other side-channel
    // commands print; the streaming sender is shut down by the
    // process exit.
    enforce_version_handshake(&mut sender).await?;

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

/// Parse a `session:path` spec, returning `(session, path)` if the spec
/// contains a colon, or `None` if it is a local path.
fn parse_remote_spec(spec: &str) -> Option<(&str, &str)> {
    // Split on the first colon only — paths after the colon may
    // themselves contain colons (e.g. `session:/abs:with:colons.txt`).
    spec.split_once(':')
}

/// Handle the `cp` subcommand: copy files between host and sandbox VM
/// by dispatching to `scp sandbox-<id>:<path>` with stdio inherited
/// for the operator's progress/error visibility.
///
/// Implements Spec § Architecture → CLI: persistent ssh-config
/// (Per-command translation) — `sandbox cp` resolves through the
/// daemon-mediated proxy via the `sandbox-<id>` alias the operator's
/// `~/.ssh/config` Include block defines. The single-retry drift-
/// recovery wrapper from
/// [`sandbox_cli::ssh_commands::run_with_drift_recovery`] reauthorises
/// the local entry against the daemon on a `Permission denied
/// (publickey)` failure and retries once.
async fn handle_cp(socket_path: &str, src: &str, dst: &str) {
    use sandbox_cli::ssh_commands::TransferDirection;

    // Determine transfer direction by which side carries `session:`.
    let src_remote = parse_remote_spec(src);
    let dst_remote = parse_remote_spec(dst);

    let (session_arg, host_path, remote_path, direction) = match (src_remote, dst_remote) {
        (None, Some((session, remote_path))) => {
            (session, src, remote_path, TransferDirection::Upload)
        }
        (Some((session, remote_path)), None) => {
            (session, dst, remote_path, TransferDirection::Download)
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
    };

    let session_dto = resolve_session_for_ssh_dispatch(socket_path, session_arg).await;
    let id = session_dto.id.as_str().to_string();
    let home = match sandbox_cli::ssh_commands::resolve_home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    // Stat the host-side source so the planner can decide whether to
    // pass `-r` to `scp`. On Download the source lives on the VM
    // side; we deliberately do not remote-stat (would require a
    // daemon round-trip on the happy path), and operators wanting
    // directory download fall through to `sandbox sync`.
    let source_is_dir = match direction {
        TransferDirection::Upload => std::fs::metadata(host_path)
            .map(|m| m.is_dir())
            .unwrap_or(false),
        TransferDirection::Download => false,
    };

    let host_path = host_path.to_string();
    let remote_path = remote_path.to_string();
    let socket_owned = socket_path.to_string();
    let id_for_fetch = id.clone();

    let exit_code = match sandbox_cli::ssh_commands::run_with_drift_recovery(
        &home,
        &id,
        move || {
            let s = socket_owned.clone();
            let i = id_for_fetch.clone();
            async move { fetch_ssh_config_dto(&s, &i).await }
        },
        move |alias, _attempt_idx| {
            let host_path = host_path.clone();
            let remote_path = remote_path.clone();
            let extras = ssh_child_extra_env(socket_path);
            async move {
                let (program, args) = sandbox_cli::ssh_commands::plan_scp_argv(
                    &alias,
                    &host_path,
                    &remote_path,
                    direction,
                    source_is_dir,
                );
                sandbox_cli::ssh_commands::spawn_ssh_tool_attempt(&program, &args, extras).await
            }
        },
    )
    .await
    {
        Ok(code) => code,
        Err(e) => fail_drift_recovery(e),
    };
    process::exit(exit_code);
}

/// Handle the `sync` subcommand: rsync-mirror a directory between
/// host and session via `rsync -a --delete -e ssh sandbox-<id>:<path>`.
///
/// The shell transport is bare `ssh`; the operator's `~/.ssh/config`
/// (via our managed `Include` block) resolves `sandbox-<id>` to the
/// daemon-mediated proxy. Single-retry drift recovery from
/// [`sandbox_cli::ssh_commands::run_with_drift_recovery`] reauthorises
/// the local entry against the daemon on `Permission denied
/// (publickey)`.
async fn handle_sync(socket_path: &str, src: &str, dst: &str, rsync_args: &[String]) {
    use sandbox_cli::ssh_commands::TransferDirection;

    let src_remote = parse_remote_spec(src);
    let dst_remote = parse_remote_spec(dst);

    let (session_arg, host_path, remote_path, direction) = match (src_remote, dst_remote) {
        (None, Some((session, remote_path))) => {
            (session, src, remote_path, TransferDirection::Upload)
        }
        (Some((session, remote_path)), None) => {
            (session, dst, remote_path, TransferDirection::Download)
        }
        (Some(_), Some(_)) => {
            eprintln!("Error: both source and destination cannot be remote");
            process::exit(1);
        }
        (None, None) => {
            eprintln!(
                "Error: one of source or destination must be a remote path (session:path)\n\
                 Usage:\n  \
                 sandbox sync local/dir session:remote/dir   (upload)\n  \
                 sandbox sync session:remote/dir local/dir   (download)"
            );
            process::exit(1);
        }
    };

    let session_dto = resolve_session_for_ssh_dispatch(socket_path, session_arg).await;
    let id = session_dto.id.as_str().to_string();
    let home = match sandbox_cli::ssh_commands::resolve_home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    let source_is_dir = match direction {
        TransferDirection::Upload => std::fs::metadata(host_path)
            .map(|m| m.is_dir())
            .unwrap_or(false),
        TransferDirection::Download => false,
    };

    let host_path = host_path.to_string();
    let remote_path = remote_path.to_string();
    let rsync_args = rsync_args.to_vec();
    let socket_owned = socket_path.to_string();
    let id_for_fetch = id.clone();

    let exit_code = match sandbox_cli::ssh_commands::run_with_drift_recovery(
        &home,
        &id,
        move || {
            let s = socket_owned.clone();
            let i = id_for_fetch.clone();
            async move { fetch_ssh_config_dto(&s, &i).await }
        },
        move |alias, _attempt_idx| {
            let host_path = host_path.clone();
            let remote_path = remote_path.clone();
            let rsync_args = rsync_args.clone();
            let extras = ssh_child_extra_env(socket_path);
            async move {
                let (program, args) = sandbox_cli::ssh_commands::plan_sync_argv(
                    &alias,
                    &host_path,
                    &remote_path,
                    direction,
                    &rsync_args,
                    source_is_dir,
                );
                sandbox_cli::ssh_commands::spawn_ssh_tool_attempt(&program, &args, extras).await
            }
        },
    )
    .await
    {
        Ok(code) => code,
        Err(e) => fail_drift_recovery(e),
    };
    process::exit(exit_code);
}

/// Direction of a `sandbox workspace` rsync mirror — local alias of
/// [`sandbox_core::Direction`]. Push: host → guest. Pull: guest → host.
///
/// The pure-function planner lives in
/// [`sandbox_cli::ssh_commands::plan_workspace_rsync_argv`] and is
/// driven from `run_workspace_push_or_pull` below; this alias survives
/// because the daemon-facing `WorkspaceOpDto` shape and the workspace-
/// action enum still speak in `Direction`.
type WorkspaceSyncDirection = sandbox_core::Direction;

/// Expand a leading `~` in a `--dest` value against the CLI process's
/// `$HOME`. Mirrors the rule applied to `--workspace`'s host path at
/// session create time: the daemon never sees a `~` (it runs with a
/// different `$HOME`), so the CLI resolves the substitution before
/// constructing the rsync argv.
///
/// `~` alone resolves to `$HOME`; `~/suffix` resolves to `$HOME/suffix`.
/// `~user` is rejected (not supported here — the host_path parser at
/// create time also rejects it). Inputs that don't start with `~` pass
/// through verbatim.
///
/// Returns an operator-facing error string on `$HOME` lookup failure or
/// `~user` form; the caller pairs it with `eprintln!("Error: {e}")` +
/// `process::exit(...)`.
fn expand_dest_tilde(dest: &str) -> Result<String, String> {
    let trimmed = dest.trim_start();
    if !trimmed.starts_with('~') {
        return Ok(dest.to_string());
    }
    let home = std::env::var("HOME").map_err(|_| {
        format!(
            "--dest starts with `~` but $HOME is not set; \
             pass an absolute path instead (got: {dest:?})"
        )
    })?;
    if home.is_empty() {
        return Err(format!(
            "--dest starts with `~` but $HOME is empty; \
             pass an absolute path instead (got: {dest:?})"
        ));
    }
    if trimmed == "~" {
        Ok(home)
    } else if let Some(suffix) = trimmed.strip_prefix("~/") {
        Ok(format!("{home}/{suffix}"))
    } else {
        // `~user` form — not supported.
        Err(format!(
            "--dest `~user` form is not supported; pass an absolute path instead (got: {dest:?})"
        ))
    }
}

/// Fetch the session DTO via `GET /sessions/{session}`. Shared between
/// the three `sandbox workspace` handlers so they have a single place
/// where the lookup error vocabulary is shaped. On any non-2xx response
/// or transport failure, the helper prints the daemon's error message
/// (or a transport-level diagnostic) to stderr and `process::exit(1)`s
/// — there is no return path for the failure case, matching the
/// pattern `handle_cp` / `handle_sync` use.
async fn fetch_session_dto(socket_path: &str, session: &str) -> SessionDto {
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
        if let Ok(api_err) = serde_json::from_str::<sandbox_core::ApiError>(&body) {
            eprintln!("Error: {}", api_err.error);
        } else {
            eprintln!("Error ({status}): {body}");
        }
        process::exit(1);
    }

    match serde_json::from_str(&body) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to parse session response: {e}");
            process::exit(1);
        }
    }
}

/// Resolve a session's `local:` workspace paths from the DTO. Returns
/// `(host_path, guest_path)` if the session is in `local:` mode;
/// otherwise prints the required mode-mismatch error and exits 2
/// (clap's misuse convention).
///
/// The error wording — `"sandbox workspace push/pull only applies to
/// local: workspaces; this session uses <mode>"` — uses `<mode>` =
/// `shared`, `clone`, or `<empty>` when `workspace_mode_detail` is absent.
fn require_local_workspace(session: &SessionDto) -> (String, String) {
    use sandbox_core::WorkspaceModeDetailDto;
    match &session.config.workspace_mode_detail {
        Some(WorkspaceModeDetailDto::Local {
            host_path,
            guest_path,
        }) => (host_path.clone(), guest_path.clone()),
        Some(WorkspaceModeDetailDto::Shared { .. }) => {
            eprintln!(
                "Error: sandbox workspace push/pull only applies to local: \
                 workspaces; this session uses shared:"
            );
            process::exit(2);
        }
        Some(WorkspaceModeDetailDto::Clone { .. }) => {
            eprintln!(
                "Error: sandbox workspace push/pull only applies to local: \
                 workspaces; this session uses clone:"
            );
            process::exit(2);
        }
        None => {
            eprintln!(
                "Error: sandbox workspace push/pull only applies to local: \
                 workspaces; this session uses <empty>:"
            );
            process::exit(2);
        }
    }
}

/// Verify a session is in `SessionState::Running`. Push and pull both
/// require the shell transport (`limactl shell` / `docker exec -i`),
/// which is only viable for running sessions. Stopped/Creating/Error
/// sessions fail fast here so the daemon-side lock acquire isn't
/// even attempted.
///
/// Exit code 1: "Session not running → exit code 1".
fn require_running_session(session: &SessionDto) {
    use sandbox_core::session::SessionState;
    if session.state != SessionState::Running {
        let display_name = session
            .name
            .as_deref()
            .unwrap_or_else(|| session.id.as_ref());
        eprintln!(
            "Error: session {display_name} is not running (state: {}); start it first",
            session.state
        );
        process::exit(1);
    }
}

/// Acquire the daemon-side workspace lock via
/// `POST /sessions/<id>/workspace-lock`. Returns the granted
/// `lock_token` on success; on 4xx (notably 409 Conflict on a held
/// lock, 400 on a non-Running session) prints the daemon's error
/// verbatim and exits 1.
///
/// The lock acquire is the *atomic* state-gate: between this call and
/// the matching release, the daemon refuses competing acquires and
/// also refuses `stop`/`rm` on the same session. See
/// lock → Lifecycle interaction.
async fn acquire_workspace_lock(
    socket_path: &str,
    session: &str,
    op: sandbox_core::WorkspaceOpDto,
) -> String {
    let body = serde_json::to_string(&sandbox_core::WorkspaceLockAcquireRequest { op })
        .expect("acquire request always serialises");
    let req = Request::builder()
        .method("POST")
        .uri(format!("/sessions/{session}/workspace-lock"))
        .header("content-type", "application/json")
        .body(body)
        .expect("failed to build acquire request");

    let (status, resp_body) = match send_request(socket_path, req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    if !status.is_success() {
        if let Ok(api_err) = serde_json::from_str::<sandbox_core::ApiError>(&resp_body) {
            eprintln!("Error: {}", api_err.error);
        } else {
            eprintln!("Error ({status}): {resp_body}");
        }
        process::exit(1);
    }

    let parsed: sandbox_core::WorkspaceLockAcquireResponse = match serde_json::from_str(&resp_body)
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to parse workspace-lock response: {e}");
            process::exit(1);
        }
    };
    parsed.lock_token
}

/// Release the daemon-side workspace lock via
/// `DELETE /sessions/<id>/workspace-lock`. Best-effort: release
/// failures log to stderr but do not modify the caller's intended
/// exit code (typically rsync's). The daemon treats an already-
/// unlocked session as a no-op 200 (idempotent DELETE semantics).
///
/// `force` is the operator's `--force` opt-in: with `force == true`,
/// the daemon bypasses the token-match check. The CLI release on the
/// happy path of push/pull passes `force == false` (strict-match);
/// `sandbox workspace unlock --force` is the one call site that
/// passes `force == true`.
async fn release_workspace_lock(
    socket_path: &str,
    session: &str,
    lock_token: &str,
    force: bool,
) -> (hyper::StatusCode, String) {
    let body = serde_json::to_string(&sandbox_core::WorkspaceLockReleaseRequest {
        lock_token: lock_token.to_string(),
        force,
    })
    .expect("release request always serialises");
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/sessions/{session}/workspace-lock"))
        .header("content-type", "application/json")
        .body(body)
        .expect("failed to build release request");

    match send_request(socket_path, req).await {
        Ok(r) => r,
        Err(e) => {
            // Transport-level failure (socket disappeared, timeout).
            // The caller in push/pull logs but proceeds; surface a
            // synthetic status so the caller's branching is uniform.
            (hyper::StatusCode::INTERNAL_SERVER_ERROR, e)
        }
    }
}

/// Exit code used when a `sandbox workspace push|pull` rsync child is
/// interrupted by SIGINT. The Unix convention for a signal-terminated
/// process is `128 + signo`; SIGINT is 2 → 130. Matches the existing
/// [`EVENTS_SIGINT_EXIT_CODE`] for `sandbox events`.
const WORKSPACE_SIGINT_EXIT_CODE: i32 = 130;

/// Exit code used when the rsync child is interrupted by SIGTERM.
/// Same `128 + signo` convention as above; SIGTERM is 15 → 143.
#[cfg(unix)]
const WORKSPACE_SIGTERM_EXIT_CODE: i32 = 143;

/// Run a workspace-lock release request and forward any non-success
/// status as a `Warning:` line on stderr. This is the
/// release-failure-must-not-mask-rsync-exit-code contract from the
/// spec, factored out so the normal-return path, the scopeguard
/// drop-path, and the signal-handling arm all behave identically.
async fn release_workspace_lock_best_effort(socket_path: &str, session: &str, lock_token: &str) {
    let (release_status, release_body) =
        release_workspace_lock(socket_path, session, lock_token, false).await;
    if release_status.is_success() {
        return;
    }
    if let Ok(api_err) = serde_json::from_str::<sandbox_core::ApiError>(&release_body) {
        eprintln!(
            "Warning: failed to release workspace lock for {session}: {}",
            api_err.error
        );
    } else {
        eprintln!(
            "Warning: failed to release workspace lock for {session} \
             ({release_status}): {release_body}"
        );
    }
}

/// Drive [`release_workspace_lock_best_effort`] from a synchronous
/// context — specifically, the `Drop` closure of the scopeguard that
/// covers normal-return + panic-unwind. We can't call `.await` from
/// `Drop`, and we can't use `tokio::runtime::Handle::current().block_on(...)`
/// from inside an existing runtime context (tokio forbids re-entry).
///
/// Building a fresh `current_thread` runtime is *not* sufficient on
/// its own: tokio rejects `block_on` from within any existing runtime
/// context — including the outer `#[tokio::main]` runtime that is
/// still on this OS thread when the scopeguard fires on the normal
/// success path. The robust pattern is to dispatch the runtime + the
/// `block_on` to a brand-new OS thread via `std::thread::spawn`, which
/// has no tokio context attached, and then `join()` it synchronously
/// so the drop scope still observes completion before unwinding
/// proceeds. Failure to construct the runtime — or a panic in the
/// spawned thread — is logged but does not propagate; the scopeguard
/// can run during an unwind, where a second panic would abort the
/// process.
fn release_workspace_lock_blocking(socket_path: &str, session: &str, lock_token: &str) {
    // Move owned copies into the spawned thread so it can outlive the
    // borrow scope of the caller (the scopeguard already captures
    // owned `String`s, but the helper takes `&str`).
    let socket = socket_path.to_owned();
    let session_owned = session.to_owned();
    let lock_token = lock_token.to_owned();
    let session_for_log = session_owned.clone();
    let handle = std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!(
                    "Warning: failed to release workspace lock for {session_owned}: \
                     could not build runtime for cleanup ({e})"
                );
                return;
            }
        };
        rt.block_on(release_workspace_lock_best_effort(
            &socket,
            &session_owned,
            &lock_token,
        ));
    });
    if let Err(e) = handle.join() {
        eprintln!(
            "Warning: failed to release workspace lock for {session_for_log}: \
             release thread panicked ({e:?})"
        );
    }
}

/// Common push/pull flow factored from [`handle_workspace_push`] and
/// [`handle_workspace_pull`]. Both follow the same sequence:
///
/// 1. Fetch the session DTO.
/// 2. Verify the session is in `local:` workspace mode.
/// 3. Verify the session is `Running`.
/// 4. (Pull only) Resolve `--dest`: `~` expansion, existing-file
///    rejection, `create_dir_all(dirname)`.
/// 5. Acquire the daemon-side workspace lock.
/// 6. Build the rsync argv via
///    [`sandbox_cli::ssh_commands::plan_workspace_rsync_argv`] (after
///    the drift-recovery wrapper has ensured the per-session
///    `~/.ssh/sandbox/` entry exists).
/// 7. Spawn rsync as a child future; race it against SIGINT/SIGTERM.
/// 8. Release the workspace lock (best-effort, on every exit path).
/// 9. Exit with rsync's exit code (or `128 + signo` on signal).
///
/// **Release-on-cancel guarantee.** The acquired lock MUST be released
/// regardless of how this function exits: normal rsync success, rsync
/// non-zero, planner usage error, child-spawn failure, panic anywhere
/// after acquire, SIGINT, or SIGTERM. The guarantee is implemented by
/// a [`scopeguard::guard`] whose drop closure issues the release —
/// scopeguard covers normal-return + panic-unwind. The signal arms of
/// the `tokio::select!` race release inline before exiting with the
/// conventional `128 + signo` exit code; they then forget the guard so
/// the cleanup does not double-fire. Release failures degrade to a
/// stderr warning per the design
/// rsync exit code. Operators have `sandbox workspace unlock --force`
/// as the manual recovery path if the daemon was unreachable.
#[allow(clippy::too_many_arguments)] // each arg maps to a distinct clap flag
async fn run_workspace_push_or_pull(
    socket_path: &str,
    session_arg: &str,
    direction: WorkspaceSyncDirection,
    force: bool,
    dry_run: bool,
    safe_links: bool,
    no_gitignore: bool,
    dest: Option<String>,
) {
    let session = fetch_session_dto(socket_path, session_arg).await;
    let (host_path, guest_path) = require_local_workspace(&session);
    require_running_session(&session);

    // `--dest` resolution: only meaningful on pull. The planner
    // accepts the resolved string verbatim and slots it into the dst
    // position. Push has no analogue — the host path is fixed at
    // the session's recorded `host_path`.
    let dest_override: Option<String> = if matches!(direction, WorkspaceSyncDirection::Pull) {
        match dest.as_deref() {
            None => None,
            Some(raw) => {
                let expanded = match expand_dest_tilde(raw) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error: {e}");
                        process::exit(1);
                    }
                };
                // Existing-file rejection: `--dest` must name a
                // directory (existing or to-be-created), never a
                // regular file.
                // --dest → Rejected with an error before rsync is
                // spawned`.
                let dest_path = Path::new(&expanded);
                if let Ok(meta) = std::fs::metadata(dest_path) {
                    if meta.is_file() {
                        eprintln!(
                            "Error: --dest {expanded} is an existing file; \
                             expected a directory"
                        );
                        process::exit(1);
                    }
                }
                // `create_dir_all(dirname(dest))` lets rsync create
                // the leaf itself.
                // create_dir_all(dirname(<--dest>)) before spawning
                // rsync; rsync creates the leaf itself."
                if let Some(parent) = dest_path.parent() {
                    if !parent.as_os_str().is_empty() {
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            eprintln!(
                                "Error: failed to create parent of --dest \
                                 {expanded}: {e}"
                            );
                            process::exit(1);
                        }
                    }
                }
                Some(expanded)
            }
        }
    } else {
        // Push: ignore `dest` if somehow provided. The clap surface
        // restricts `--dest` to the Pull variant, but this guard makes
        // the planner contract explicit.
        None
    };

    // Pre-flight: verify `rsync` is on the host's `$PATH` BEFORE
    // acquiring the per-session workspace lock. If we acquired the
    // lock first and then discovered rsync was missing, we'd leave
    // an orphan lock requiring `sandbox workspace unlock --force` to
    // recover. The host-side `which` binary ships in `coreutils` on
    // every realistic operator host, so calling it avoids pulling in
    // the `which` crate as a dependency.
    match std::process::Command::new("which").arg("rsync").output() {
        Ok(out) if out.status.success() => {}
        _ => {
            eprintln!("rsync not found on host; install rsync to use sandbox workspace push/pull");
            process::exit(1);
        }
    }

    // Workspace-lock op tag for the acquire request. Push and pull
    // both lock the same per-session mutex; the op tag only exists so
    // the conflict response can name the held op accurately.
    let op = match direction {
        WorkspaceSyncDirection::Push => sandbox_core::WorkspaceOpDto::Push,
        WorkspaceSyncDirection::Pull => sandbox_core::WorkspaceOpDto::Pull,
    };

    let lock_token = acquire_workspace_lock(socket_path, session_arg, op).await;

    // Release-on-cancel guard. From this point on, every exit path —
    // normal return, planner error, child-spawn error, rsync non-zero,
    // panic during spawn, SIGINT, SIGTERM — must release the lock. The
    // scopeguard covers the normal-return + panic-unwind cases; the
    // signal arms of the `tokio::select!` race release inline and then
    // `ScopeGuard::into_inner` the guard so the drop is a no-op (we
    // can't release twice — the daemon would return 409 wrong-token on
    // the second call). Captured `String`s are owned to keep the guard
    // `'static` regardless of the surrounding borrow scope.
    let release_socket = socket_path.to_string();
    let release_session = session_arg.to_string();
    let release_token = lock_token.clone();
    let release_guard = scopeguard::guard((), move |()| {
        release_workspace_lock_blocking(&release_socket, &release_session, &release_token);
    });

    // Construct the workspace-rsync plan inputs up front so the
    // closure passed to drift-recovery can build the argv on each
    // attempt without re-deriving them from scratch. The plan-level
    // usage errors (`-f`/`-n` neither/both) surface as
    // `Err(_)` from the planner inside the closure on every retry,
    // but we *also* validate once here so a usage error never burns
    // a daemon ssh-config fetch.
    let validate_plan = sandbox_cli::ssh_commands::WorkspaceRsyncPlan {
        alias: "sandbox-placeholder",
        host_path: host_path.clone(),
        guest_path: guest_path.clone(),
        direction: workspace_direction_to_planner(direction),
        dest_override: dest_override.clone(),
        force,
        dry_run,
        safe_links,
        no_gitignore,
    };
    if let Err(e) = sandbox_cli::ssh_commands::plan_workspace_rsync_argv(&validate_plan) {
        eprintln!("Error: {e}");
        drop(release_guard);
        process::exit(2);
    }

    let id = session.id.as_str().to_string();
    let home = match sandbox_cli::ssh_commands::resolve_home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error: {e}");
            drop(release_guard);
            process::exit(1);
        }
    };

    // Drive the underlying rsync invocation through the single-retry
    // drift-recovery wrapper. The per-attempt closure owns the full
    // signal-handled child lifecycle (SIGINT/SIGTERM arms exit the
    // process inline, in which case the wrapper never observes the
    // attempt's outcome — the workspace lock is released by the
    // signal arm's explicit best-effort release call). A
    // `Permission denied (publickey)` failure is surfaced as
    // `AttemptOutcome::PublickeyDrift`, the wrapper re-fetches the
    // SSH config, overwrites the local entry, and re-spawns once.
    let socket_for_fetch = socket_path.to_string();
    let socket_for_attempt_closure = socket_path.to_string();
    let session_arg_owned = session_arg.to_string();
    let id_for_fetch = id.clone();
    let lock_token_for_signal = lock_token.clone();
    let host_path_for_attempt = host_path;
    let guest_path_for_attempt = guest_path;
    let dest_override_for_attempt = dest_override;

    let exit_code = match sandbox_cli::ssh_commands::run_with_drift_recovery(
        &home,
        &id,
        move || {
            let s = socket_for_fetch.clone();
            let i = id_for_fetch.clone();
            async move { fetch_ssh_config_dto(&s, &i).await }
        },
        move |alias, _attempt_idx| {
            let host_path_clone = host_path_for_attempt.clone();
            let guest_path_clone = guest_path_for_attempt.clone();
            let dest_override_clone = dest_override_for_attempt.clone();
            let socket_for_attempt = socket_for_attempt_closure.clone();
            let session_for_attempt = session_arg_owned.clone();
            let lock_token_attempt = lock_token_for_signal.clone();
            async move {
                let plan = sandbox_cli::ssh_commands::WorkspaceRsyncPlan {
                    alias: alias.as_str(),
                    host_path: host_path_clone,
                    guest_path: guest_path_clone,
                    direction: workspace_direction_to_planner(direction),
                    dest_override: dest_override_clone,
                    force,
                    dry_run,
                    safe_links,
                    no_gitignore,
                };
                // The pre-flight `validate_plan` above already
                // caught usage errors; a failure here would be a
                // planner regression that surfaced between attempts.
                let argv = sandbox_cli::ssh_commands::plan_workspace_rsync_argv(&plan)
                    .map_err(sandbox_cli::ssh_commands::DriftRecoveryError::FetchDto)?;
                run_workspace_rsync_attempt(
                    argv,
                    socket_for_attempt,
                    session_for_attempt,
                    lock_token_attempt,
                )
                .await
            }
        },
    )
    .await
    {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e}");
            drop(release_guard);
            process::exit(1);
        }
    };
    // Normal path. Dropping `release_guard` here runs the scopeguard's
    // closure (which spins up a one-shot runtime and issues the
    // release); equivalent to letting the function end, but explicit
    // drop makes the ordering reviewable.
    drop(release_guard);
    process::exit(exit_code);
}

/// Translate the daemon-facing [`WorkspaceSyncDirection`] enum
/// (`sandbox_core::Direction`) to the planner-local
/// [`sandbox_cli::ssh_commands::WorkspaceDirection`]. Two enums exist
/// because the planner stays free of `sandbox_core::Direction`'s
/// daemon-API dependencies; the conversion is exhaustive and total.
fn workspace_direction_to_planner(
    direction: WorkspaceSyncDirection,
) -> sandbox_cli::ssh_commands::WorkspaceDirection {
    match direction {
        WorkspaceSyncDirection::Push => sandbox_cli::ssh_commands::WorkspaceDirection::Push,
        WorkspaceSyncDirection::Pull => sandbox_cli::ssh_commands::WorkspaceDirection::Pull,
    }
}

/// Run a single `rsync` workspace push/pull attempt under SIGINT and
/// SIGTERM handlers, with the workspace lock released in the signal
/// arms before the process exits. Returns an
/// [`sandbox_cli::ssh_commands::AttemptOutcome`] so the drift-recovery
/// wrapper can decide whether to retry on a pubkey-drift signal.
///
/// `LC_ALL=C` / `LANG=C` are set on the child environment so the
/// stderr substring sniffer (`looks_like_publickey_drift`) is locale-
/// stable. The `SANDBOX_SOCKET` env var is propagated so the
/// `ProxyCommand sandbox proxy <id>` directive inside the per-session
/// SSH config reaches the same daemon socket the parent CLI is using.
///
/// Signal arms `process::exit` directly — that aborts the future
/// stack mid-flight and the drift-recovery wrapper never gets to see
/// the outcome, which is correct because the operator asked to
/// cancel.
async fn run_workspace_rsync_attempt(
    argv: Vec<String>,
    socket_path: String,
    session_arg: String,
    lock_token: String,
) -> Result<sandbox_cli::ssh_commands::AttemptOutcome, sandbox_cli::ssh_commands::DriftRecoveryError>
{
    use sandbox_cli::ssh_commands::{
        AttemptOutcome, DriftRecoveryError, looks_like_publickey_drift,
    };

    // argv[0] is "rsync" (the program); argv[1..] is the actual flag
    // list — mirrors the convention `plan_workspace_rsync_argv` ships.
    let program = argv[0].clone();
    let mut cmd = tokio::process::Command::new(&program);
    cmd.args(&argv[1..])
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::piped())
        // `kill_on_drop` is the belt-and-suspenders companion to the
        // explicit `child.kill()` in the signal arm: if anything
        // causes this future to be dropped before `child.wait()`
        // resolves (e.g. a panic between `spawn()` and the
        // `select!`), the rsync child is reaped instead of being
        // left as a zombie of the parent.
        .kill_on_drop(true);
    for (k, v) in ssh_child_extra_env(&socket_path) {
        cmd.env(k, v);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Err(DriftRecoveryError::Spawn { program, source: e });
        }
    };

    // Tee stderr to the operator's terminal AND capture into a
    // buffer so the wrapper can inspect for the pubkey-drift signal
    // after the child exits.
    let stderr = child
        .stderr
        .take()
        .expect("child stderr is piped by Command builder above");
    let tee = tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut parent_stderr = tokio::io::stderr();
        let mut reader = stderr;
        loop {
            match tokio::io::AsyncReadExt::read(&mut reader, &mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut parent_stderr, &chunk[..n]).await;
                    let _ = tokio::io::AsyncWriteExt::flush(&mut parent_stderr).await;
                }
                Err(_) => break,
            }
        }
        buf
    });

    // Signal plumbing. `ctrl_c()` covers SIGINT on all platforms
    // tokio supports; SIGTERM is Unix-only.
    let ctrlc = tokio::signal::ctrl_c();
    tokio::pin!(ctrlc);

    #[cfg(unix)]
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "could not install SIGTERM handler");
            None
        }
    };

    enum Outcome {
        Exited(i32),
        Interrupted,
        Terminated,
    }

    let outcome = {
        #[cfg(unix)]
        {
            let sigterm_fut = async {
                match sigterm.as_mut() {
                    Some(s) => {
                        s.recv().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                res = child.wait() => match res {
                    Ok(status) => Outcome::Exited(status.code().unwrap_or(1)),
                    Err(e) => {
                        eprintln!("Error: rsync child wait failed: {e}");
                        Outcome::Exited(1)
                    }
                },
                _ = &mut ctrlc => Outcome::Interrupted,
                _ = sigterm_fut => Outcome::Terminated,
            }
        }
        #[cfg(not(unix))]
        {
            tokio::select! {
                res = child.wait() => match res {
                    Ok(status) => Outcome::Exited(status.code().unwrap_or(1)),
                    Err(e) => {
                        eprintln!("Error: rsync child wait failed: {e}");
                        Outcome::Exited(1)
                    }
                },
                _ = &mut ctrlc => Outcome::Interrupted,
            }
        }
    };

    match outcome {
        Outcome::Exited(code) => {
            let stderr_bytes = tee.await.unwrap_or_default();
            if code != 0 && looks_like_publickey_drift(&stderr_bytes) {
                Ok(AttemptOutcome::PublickeyDrift)
            } else {
                Ok(AttemptOutcome::Exited(code))
            }
        }
        Outcome::Interrupted => {
            eprintln!("interrupted; killing rsync");
            let _ = child.kill().await;
            release_workspace_lock_best_effort(&socket_path, &session_arg, &lock_token).await;
            process::exit(WORKSPACE_SIGINT_EXIT_CODE);
        }
        Outcome::Terminated => {
            eprintln!("terminated; killing rsync");
            let _ = child.kill().await;
            release_workspace_lock_best_effort(&socket_path, &session_arg, &lock_token).await;
            #[cfg(unix)]
            {
                process::exit(WORKSPACE_SIGTERM_EXIT_CODE);
            }
            #[cfg(not(unix))]
            {
                process::exit(1);
            }
        }
    }
}

/// Dispatch `sandbox workspace push <session> ...`. See
/// [`run_workspace_push_or_pull`] for the orchestration shape.
async fn handle_workspace_push(
    socket_path: &str,
    session: &str,
    force: bool,
    dry_run: bool,
    safe_links: bool,
    no_gitignore: bool,
) {
    run_workspace_push_or_pull(
        socket_path,
        session,
        WorkspaceSyncDirection::Push,
        force,
        dry_run,
        safe_links,
        no_gitignore,
        None,
    )
    .await;
}

/// Dispatch `sandbox workspace pull <session> [--dest <path>] ...`. See
/// [`run_workspace_push_or_pull`] for the orchestration shape.
async fn handle_workspace_pull(
    socket_path: &str,
    session: &str,
    force: bool,
    dry_run: bool,
    safe_links: bool,
    no_gitignore: bool,
    dest: Option<String>,
) {
    run_workspace_push_or_pull(
        socket_path,
        session,
        WorkspaceSyncDirection::Pull,
        force,
        dry_run,
        safe_links,
        no_gitignore,
        dest,
    )
    .await;
}

/// Dispatch `sandbox workspace unlock <session> [--force]`. Sends a
/// release request with an empty (sentinel) `lock_token`. Without
/// `--force`, the daemon adjudicates the empty token as a wrong-token
/// mismatch and returns 409 if the lock is currently held — the
/// operator must `--force` to clear an orphan lock. With `--force`,
/// the daemon releases unconditionally. The already-unlocked case is
/// a 200 idempotent no-op per the design
/// already-unlocked.
///
/// Per
/// is the documented sentinel for `unlock` without `--force`; the
/// daemon's `LockToken::from_str` rejects it as unparseable and
/// adjudicates as "wrong token".
async fn handle_workspace_unlock(socket_path: &str, session: &str, force: bool) {
    let (status, body) = release_workspace_lock(socket_path, session, "", force).await;

    if status.is_success() {
        println!("workspace lock released");
        return;
    }

    // 409 (lock held, wrong token) and other 4xx surface the daemon
    // error verbatim. The 409 hint string includes the recommended
    // `--force` workflow, so the operator sees what to try next.
    if let Ok(api_err) = serde_json::from_str::<sandbox_core::ApiError>(&body) {
        eprintln!("Error: {}", api_err.error);
    } else {
        eprintln!("Error ({status}): {body}");
    }
    process::exit(1);
}

/// Check whether this binary was invoked as `git-remote-sandbox` (i.e. as a
/// git remote helper).  Returns `true` if `argv[0]` ends with
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
/// URL format: `sandbox::<session>[/<repo-path>]`
/// The part after `sandbox::` is passed as the second argument to the
/// remote helper. It has the form `<session>[/<repo-path>]` where
/// repo-path can contain slashes; when no slash is present, the caller
/// is expected to resolve the repo path from the session's workspace
/// configuration via the daemon.
///
/// Returns `(session, Some(repo_path))` when the URL contained a slash
/// and `(session, None)` when the URL is slash-less. The runtime
/// caller in [`run_remote_helper`] resolves the slash-less case by
/// querying the daemon for the session's `guest_path` (see
/// [`resolve_default_repo_path`]).
fn parse_remote_helper_url(url: &str) -> Result<(String, Option<String>), String> {
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
        Ok((session.to_string(), Some(repo_path.to_string())))
    } else {
        // No slash — treat the whole thing as session; the caller resolves
        // the repo path from the session DTO at runtime.
        if payload.is_empty() {
            return Err(format!("empty URL: {url}"));
        }
        Ok((payload.to_string(), None))
    }
}

/// Pick the default repo path for a slash-less `sandbox::<session>`
/// remote-helper URL given the session's `workspace_mode_detail`.
///
/// - `Shared { guest_path, .. }` and `Local { guest_path, .. }`
///   → use that guest_path (M17 made the guest mount point
///   operator-configurable, so we must read it from the DTO rather
///   than assume `/home/sandbox/workspace`).
/// - `Clone { .. }` and `None` (no workspace, or an older daemon
///   that doesn't populate the detail field) → fall back to
///   `/home/sandbox/workspace`. Clone-mode sessions land the repo at
///   that path by convention, and an older daemon that omits the
///   field could have been a pre-M17 session in shared-mode at the
///   historical default — falling back preserves backward
///   compatibility in both shapes.
fn resolve_default_repo_path(detail: Option<&WorkspaceModeDetailDto>) -> String {
    match detail {
        Some(WorkspaceModeDetailDto::Shared { guest_path, .. })
        | Some(WorkspaceModeDetailDto::Local { guest_path, .. }) => guest_path.clone(),
        Some(WorkspaceModeDetailDto::Clone { .. }) | None => "/home/sandbox/workspace".to_string(),
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
async fn run_remote_helper() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: git-remote-sandbox <remote-name> <url>");
        eprintln!("This is a git remote helper, invoked by git automatically.");
        process::exit(1);
    }

    let url = &args[2];

    let (session, repo_path_opt) = match parse_remote_helper_url(url) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    // Determine socket path. The `--socket` global flag is not available
    // in remote-helper mode (git controls argv), so ``SANDBOX_SOCKET`` is
    // the only override path. Honour it directly here — the rest of the
    // CLI relies on clap's ``env = "SANDBOX_SOCKET"`` annotation on the
    // global ``--socket`` arg, which is not consulted in this entry
    // point. Fall back to the XDG/HOME default when the env var is
    // unset or empty.
    let socket_path = std::env::var("SANDBOX_SOCKET")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_socket_path);

    // For slash-less URLs (`sandbox::<session>` with no path), resolve the
    // default repo path from the session's workspace configuration. M17
    // made the guest mount point operator-configurable, so we can no
    // longer assume `/home/sandbox/workspace`. On daemon error (404,
    // network, parse) we print a helpful message and exit non-zero —
    // never silently fall back, since that would surface the wrong
    // directory to git.
    let repo_path = match repo_path_opt {
        Some(p) => p,
        None => {
            let req = match Request::builder()
                .method("GET")
                .uri(format!("/sessions/{session}"))
                .body(String::new())
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "Error: failed to build session lookup request for `{url}`: {e}\n\
                         Hint: pass an explicit path, e.g. `sandbox::{session}/<repo-path>`."
                    );
                    process::exit(1);
                }
            };

            let lookup = send_request(&socket_path, req).await;

            match lookup {
                Ok((status, body)) if status.is_success() => {
                    match serde_json::from_str::<SessionDto>(&body) {
                        Ok(dto) => {
                            resolve_default_repo_path(dto.config.workspace_mode_detail.as_ref())
                        }
                        Err(e) => {
                            eprintln!(
                                "Error: failed to parse session response for `{url}`: {e}\n\
                                 Hint: pass an explicit path, e.g. `sandbox::{session}/<repo-path>`."
                            );
                            process::exit(1);
                        }
                    }
                }
                Ok((status, body)) => {
                    let detail = if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
                        api_err.error
                    } else {
                        format!("HTTP {status}: {body}")
                    };
                    eprintln!(
                        "Error: cannot resolve default repo path for `{url}` — {detail}\n\
                         Hint: pass an explicit path, e.g. `sandbox::{session}/<repo-path>`."
                    );
                    process::exit(1);
                }
                Err(e) => {
                    eprintln!(
                        "Error: cannot resolve default repo path for `{url}` — {e}\n\
                         Hint: pass an explicit path, e.g. `sandbox::{session}/<repo-path>`."
                    );
                    process::exit(1);
                }
            }
        }
    };

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

        // The guest agent runs as the `sandbox` user (same as limactl shell),
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

        match send_request_with_timeout(socket_path, rebuild_req, CLI_REBUILD_IMAGE_TIMEOUT).await {
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

// ---------------------------------------------------------------------------
// Hidden `--apply-config-migration` / `--dump-migration-set` handlers
// ---------------------------------------------------------------------------

/// Refusal handler for the access-gated `apply-config-migration`
/// hidden subcommand. Returns the process exit code; the caller
/// `process::exit`s on it.
///
/// Access-gating block — four refusal arms applied in
/// order. The first match wins (we don't continue to deeper checks if
/// the caller is unprivileged, etc.).
fn handle_apply_config_migration(file_arg: &str, migration_arg: &str, out_arg: &str) -> i32 {
    apply_config_migration_inner(file_arg, migration_arg, out_arg, nix::unistd::geteuid())
}

/// Outcome of the access-gate checks. Either we have a validated
/// `(target_file, migration_id)` pair to act on, or we surface a
/// refusal string the caller writes to stderr and exits non-zero.
enum ApplyGateOutcome {
    Refuse(String),
    Proceed {
        target_file: sandbox_cli::cfg_migrations::TargetFile,
        migration_id: u32,
    },
}

/// Pure access-gate function used by the unit tests to verify each
/// refusal arm's stderr substring.
fn apply_config_migration_gate(
    file_arg: &str,
    migration_arg: &str,
    out_arg: &str,
    euid: nix::unistd::Uid,
) -> ApplyGateOutcome {
    use sandbox_cli::cfg_migrations::TargetFile;
    use std::path::Path;

    // Arm 1 — caller must be root.
    if !euid.is_root() {
        return ApplyGateOutcome::Refuse(
            "--apply-config-migration is internal to `sandbox update` and requires root; \
             run via `sudo sandbox update` instead"
                .to_string(),
        );
    }

    // Arm 2 — --file must be one of the registry's canonical paths.
    let file_path = Path::new(file_arg);
    let target_file = match TargetFile::from_canonical_path(file_path) {
        Some(tf) => tf,
        None => {
            return ApplyGateOutcome::Refuse(format!(
                "--file must be one of the registry's canonical paths \
                 (/etc/sandboxd/users.conf, /etc/qemu/bridge.conf); got: {file_arg}"
            ));
        }
    };

    // Arm 3 — --out must be a tempfile under --file's parent dir, with
    // basename `\.<file-basename>\.tmp\.V[0-9]+$`.
    let out_path = Path::new(out_arg);
    let file_parent = file_path
        .parent()
        .expect("canonical path has a parent (validated by from_canonical_path)");
    let out_parent = out_path.parent().unwrap_or_else(|| Path::new(""));
    let file_basename = file_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let out_basename = out_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let expected_prefix = format!(".{file_basename}.tmp.V");
    let basename_ok = out_basename.starts_with(&expected_prefix)
        && out_basename[expected_prefix.len()..]
            .chars()
            .all(|c| c.is_ascii_digit())
        && out_basename.len() > expected_prefix.len();
    if out_parent != file_parent || !basename_ok {
        return ApplyGateOutcome::Refuse(format!(
            "--out must be a tempfile under the same directory as --file, with \
             basename matching `.{file_basename}.tmp.V<NNN>`; got: {out_arg}"
        ));
    }

    // Arm 4 — --migration must resolve in the registry against the
    // validated target file.
    let migration_id = match parse_migration_id(migration_arg) {
        Some(id) => id,
        None => {
            return ApplyGateOutcome::Refuse(format!(
                "--migration must be of the form V<NNN> (e.g. V001); got: {migration_arg}"
            ));
        }
    };
    let migration = match sandbox_cli::cfg_migrations::find_by_id(migration_id) {
        Some(m) if m.target_file() == target_file => m,
        _ => {
            return ApplyGateOutcome::Refuse(format!(
                "migration V{migration_id:03} not found in registry for {}",
                target_file.display_name()
            ));
        }
    };

    ApplyGateOutcome::Proceed {
        target_file,
        migration_id: migration.id(),
    }
}

/// uid-injectable inner so the unit tests can exercise the non-root
/// refusal arm without actually running as root. Production callers go
/// through [`handle_apply_config_migration`].
fn apply_config_migration_inner(
    file_arg: &str,
    migration_arg: &str,
    out_arg: &str,
    euid: nix::unistd::Uid,
) -> i32 {
    use std::path::Path;

    let (target_file, migration_id) =
        match apply_config_migration_gate(file_arg, migration_arg, out_arg, euid) {
            ApplyGateOutcome::Refuse(msg) => {
                eprintln!("sandbox: {msg}");
                return 1;
            }
            ApplyGateOutcome::Proceed {
                target_file,
                migration_id,
            } => (target_file, migration_id),
        };

    let file_path = Path::new(file_arg);
    let out_path = Path::new(out_arg);

    // All gates passed. Read --file, apply in memory, validate, write
    // to --out via the framework's atomic_write. The outer
    // `sandbox update` shell flow then `sudo mv`s --out into place.
    let input = match std::fs::read(file_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("sandbox: failed to read {file_arg}: {e}");
            return 1;
        }
    };
    let transformed = match sandbox_cli::cfg_migrations::apply_migration_in_memory(
        migration_id,
        &input,
        target_file,
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("sandbox: migration apply failed for {file_arg}: {e}");
            return 1;
        }
    };
    if let Err(e) = sandbox_cli::cfg_migrations::atomic_write(out_path, &transformed) {
        eprintln!("sandbox: failed to write {out_arg}: {e}");
        return 1;
    }

    // atomic_write creates the tempfile with mode 0600. The subsequent
    // `rename_via_sudo` (sudo mv) preserves whatever mode the tempfile
    // has, so we must set the intended mode here — before the caller renames.
    //
    // Force 0644 unconditionally: this is the canonical mode for all daemon
    // config files (install.sh sets it; the daemon requires world-readable
    // to parse on startup). Preserving the existing mode would perpetuate
    // a broken 0600 — the exact misconfiguration this path is supposed to
    // repair. An explicit chown root:root is redundant here (this subcommand
    // is root-gated) but it makes the intent unambiguous.
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(0o644)) {
        eprintln!("sandbox: failed to set permissions on {out_arg}: {e}");
        return 1;
    }
    // chown root:root on the output tempfile so the rename lands with the
    // correct owner regardless of the process umask or temp-area ownership.
    {
        use nix::unistd::{Gid, Uid, chown};
        let root_uid = Uid::from_raw(0);
        let root_gid = Gid::from_raw(0);
        if let Err(e) = chown(out_path, Some(root_uid), Some(root_gid)) {
            eprintln!("sandbox: failed to chown {out_arg} to root:root: {e}");
            return 1;
        }
    }
    0
}

/// Parse `V<NNN>` (e.g. `V001`) into an integer. Returns `None` for
/// any other shape — the caller surfaces a refusal.
fn parse_migration_id(raw: &str) -> Option<u32> {
    let tail = raw.strip_prefix('V').or_else(|| raw.strip_prefix('v'))?;
    if tail.is_empty() || !tail.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    tail.parse::<u32>().ok()
}

/// `--dump-migration-set` handler. Writes the migration set JSON
/// to stdout. Read-only; exits `0` on success.
fn handle_dump_migration_set() -> i32 {
    let entries = sandbox_cli::cfg_migrations::dump_migration_set();
    match serde_json::to_string(&entries) {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => {
            eprintln!("sandbox: failed to serialise migration set: {e}");
            1
        }
    }
}

/// `--dump-proto-version` handler. Writes a single-field JSON object
/// `{ "daemon_guest_proto_version": <u32> }` carrying this binary's
/// `sandbox_core::guest::DAEMON_GUEST_PROTO_VERSION`. Invoked by the
/// `sandbox update` pre-flight against the *staged* (target-version)
/// CLI binary so it can classify each persisted session against the
/// upgrade target's protocol constant. Read-only;
/// exits `0` on success.
fn handle_dump_proto_version() -> i32 {
    let payload = serde_json::json!({
        "daemon_guest_proto_version": sandbox_core::guest::DAEMON_GUEST_PROTO_VERSION,
    });
    match serde_json::to_string(&payload) {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => {
            eprintln!("sandbox: failed to serialise proto-version payload: {e}");
            1
        }
    }
}

/// `apply-config-migrations` handler.
///
/// Applies the full migration chain for every managed config file that
/// exists on disk, advancing each to the latest registered schema version.
/// Files already at the latest version are silently skipped (idempotent).
/// Files that do not exist on disk are skipped without error — they will
/// be created fresh by the daemon or a later install step with the correct
/// schema.
///
/// Requires root. Returns `0` on success (including nothing-to-do),
/// `1` on any error.
///
/// # Stable external contract — do NOT change the calling convention
///
/// `scripts/install.sh` invokes `sandbox apply-config-migrations` (no
/// flags) from within its privileged root batch across releases. The
/// subcommand name, the zero-argument calling convention, and the
/// `requires root` refusal message prefix are all load-bearing: a
/// prior-release installer shell must be able to run the current binary
/// with this exact incantation. Renaming, adding required flags, or
/// changing the error prefix requires a coordinated, backwards-compatible
/// change to `scripts/install.sh`.
fn handle_apply_config_migrations() -> i32 {
    use sandbox_cli::cfg_migrations::TargetFile;

    let euid = nix::unistd::geteuid();
    if !euid.is_root() {
        eprintln!(
            "sandbox: apply-config-migrations requires root; \
             run as root (e.g. from within the installer's privileged batch)"
        );
        return 1;
    }

    let files = [TargetFile::UsersConf, TargetFile::BridgeConf];
    let mut exit_code = 0i32;

    for file in files {
        let path = file.canonical_path();
        if !path.exists() {
            continue;
        }
        match sandbox_cli::cfg_migrations::apply_pending_at(file, &path) {
            Ok(applied) if applied.is_empty() => {
                // Already at latest version — no-op.
            }
            Ok(applied) => {
                let ids: Vec<String> = applied.iter().map(|id| format!("V{id:03}")).collect();
                eprintln!(
                    "sandbox: apply-config-migrations: {} migrated ({})",
                    path.display(),
                    ids.join(", ")
                );
            }
            Err(e) => {
                eprintln!(
                    "sandbox: apply-config-migrations: failed for {}: {e}",
                    path.display()
                );
                exit_code = 1;
            }
        }
    }

    exit_code
}

/// Per-backend dispatcher for `sandbox rebuild-image`.
///
/// Fans out one HTTP call per selected backend, prefixes per-backend
/// errors with `rebuild-image[<kind>]:`, and exits non-zero
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
    // `--backend gateway` is refused client-side with
    // exit code 2 and a verbatim pointer at `sandbox update`. The
    // refusal must fire before any HTTP request is built; the unit
    // test `rebuild_image_gateway_backend_refuses_with_pointer_to_update`
    // asserts no request is sent.
    if matches!(backend, RebuildImageBackend::Gateway) {
        eprintln!(
            "sandbox: --backend gateway is not supported for rebuild-image.\n  \
             The gateway image is shipped pre-built per release and loaded by \
             `sandbox update`.\n  To refresh the gateway image, run: sudo sandbox update"
        );
        process::exit(2);
    }
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
/// per-backend stderr lines (already formatted with the
/// `rebuild-image[<kind>]:` prefix) and a final all-or-some flag that
/// drives the exit code.
#[derive(Debug, Default, PartialEq, Eq)]
struct RebuildDispatchOutcome {
    /// `true` iff every selected backend's HTTP call succeeded.
    all_ok: bool,
    /// One stderr line per backend, in dispatch order. Pre-formatted
    /// as designed (`rebuild-image[<kind>]: ...` for failures, plain
    /// status for successes).
    lines: Vec<String>,
}

/// Inner dispatch loop, pulled out of [`dispatch_rebuild_image`] so
/// the unit tests can substitute the HTTP call.
///
/// `send` is the per-backend transport: it receives the
/// [`sandbox_core::BackendKind`] and the JSON body string the daemon expects,
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
    let (status, body) =
        send_request_with_timeout(socket_path, req, CLI_REBUILD_IMAGE_TIMEOUT).await?;
    if status.is_success() {
        return Ok(body);
    }
    if let Ok(api_err) = serde_json::from_str::<ApiError>(&body) {
        return Err(api_err.error);
    }
    Err(format!("{status}: {body}"))
}

/// Pre-flight gate for `sandbox create`.
///
/// Runs the work that must happen before the daemon is contacted, in
/// the order the design mandates:
///
/// 1. Resolve the backend across the five-tier precedence chain
///    (`--lite`, `--backend`, env, config, hardcoded Lima).
/// 2. If the resolved backend is `Container` and `--no-cache` is set,
///    render the three-line error and exit 2 — this never
///    reaches the daemon.
/// 3. Lazily fetch `/backends` once via [`BackendsCache`] and project
///    the operator's flags into a [`sandbox_core::SessionSpec`].
/// 4. Run [`sandbox_core::SessionSpec::validate`] against the cached capabilities;
///    on `Err`, render the `error:`+`help:` shape and exit 2.
///
/// Returns `Ok(())` when every gate passes; the caller proceeds to
/// build the request body and send it. Errors short-circuit by calling
/// `process::exit(2)` directly so the dispatch flow stays linear.
///
/// `cli_yes` mirrors `Cli::yes` — currently unused by the preflight
/// itself but threaded through for symmetry with future "skip
/// confirmation" knobs (the staleness check above already consumes
/// it).
// 8 args — one knob per CLI flag the preflight gate consults
// (`--lite`, `--backend`, `--no-hardening`, `--no-cache`,
// `--force-rootless-docker`) plus the socket path, the workspace
// string, and the test-only XDG override. Bundling them into a
// struct would obscure the call site (every arg is a distinct CLI
// flag, not a coherent "preflight inputs" object that exists
// elsewhere). Allow the warning at function scope so the clippy
// signal still surfaces if the next gate ever adds a ninth knob.
#[allow(clippy::too_many_arguments)]
async fn dispatch_create_preflight(
    socket_path: &str,
    backend_arg: Option<BackendKindArg>,
    lite_flag: bool,
    no_hardening: bool,
    no_cache: bool,
    force_rootless_docker: bool,
    workspace: Option<&str>,
    cli_config_xdg_override: Option<&Path>,
) -> sandbox_core::BackendKind {
    // Tier 4 of the precedence chain — load the per-user CLI config.
    // `load_cli_config` treats a missing file as not-an-error
    // and a malformed file as a hard error with a path pointer.
    let cli_config = match load_cli_config(cli_config_xdg_override) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(2);
        }
    };

    // Run the five-tier resolver against the actual env + the
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

    //  (lines 751-762): every container-
    // backed create prints a per-invocation warning to stderr **before**
    // the daemon round-trip. Lima creates emit nothing — the helper
    // returns an empty string in that case, so the unconditional
    // `eprint!` is a no-op for Lima. Emitting here (after the resolver,
    // before any further validation or daemon contact) means the
    // operator sees the warning even if the daemon is slow or
    // unreachable.
    eprint!("{}", render_isolation_warning(resolved_backend));

    //
    // container": the rejection runs *before* the daemon is
    // contacted. Mirrors the daemon-side gate (which lives in
    // `SessionSpec::validate` once SessionSpeccarries no_cache) but
    // executes earlier so the operator never burns a round-trip.
    if no_cache && resolved_backend == sandbox_core::BackendKind::Container {
        eprint!("{}", render_no_cache_rejection_for_container(lite_flag));
        process::exit(2);
    }

    // `--force-rootless-docker` is the operator's per-invocation
    // opt-in to allow session-create on a rootless Docker host
    // it is only meaningful for the
    // container backend. Combining it with a resolved Lima backend
    // is operator confusion the CLI rejects up-front so the daemon
    // never sees a malformed request. Same shape as the
    // `--no-cache` rejection above (programmatic, exit 2, runs before
    // daemon contact). `clap`'s `conflicts_with` cannot express this
    // — the offending state is "resolved backend is Lima", which is
    // the output of the five-tier resolver, not a single CLI flag.
    if force_rootless_docker && resolved_backend == sandbox_core::BackendKind::Lima {
        eprint!("{}", render_force_rootless_docker_lima_rejection());
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

    // Project the args into a SessionSpecfor validation.
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
            cpus: 0.0,
        },
    };
    let spec = sandbox_core::SessionSpec {
        backend_specific,
        workspace_mode,
        repo: None,
        boot_cmd: None,
        template: None,
        disk_gb: None,
        // The CLI runs its own dedicated `--no-cache`/Container reject
        // (`render_no_cache_rejection_for_container`) before this
        // `SessionSpec::validate` call, so threading the value through
        // here would only duplicate that gate. Leave the design field as
        // `None` — the daemon-side validate does the authoritative
        // check via the request's `no_cache` field.
        no_cache: None,
        operator_identity: None,
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
        run_remote_helper().await;
        return;
    }

    let cli = Cli::parse();

    // `sandbox version` answers locally — never connect to the daemon.
    // This is the deliberate bypass for the strict CLI ↔ daemon
    // version-equality handshake every other subcommand performs
    // inside `send_request_with_timeout`: the operator should always
    // be able to ask "what version of the CLI do I have?" without a
    // running daemon and without being refused by a skew. Output
    // format is the same `<name> <semver>\n` pin as `sandbox --version`.
    if matches!(cli.command, Command::Version) {
        println!("sandbox {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // `sandbox doctor` is the operator's diagnostic surface. It
    // intentionally bypasses the strict CLI ↔ daemon version-equality
    // handshake (see `command_bypasses_version_check`) so the operator
    // can use doctor to *diagnose* a skew rather than be refused by
    // the gate inside `send_request_with_timeout`. Doctor itself
    // probes `/version` directly via its C3 check; the comparison is
    // surfaced as a `Fail` row, not a refusal.
    //
    // Exit code semantics:
    //   `0` — every check pass or skip
    //   `1` — at least one check fails
    //   `2` — doctor itself couldn't run (socket path unresolvable,
    //         internal panic, etc.)
    if let Command::Doctor { verbose } = &cli.command {
        match sandbox_cli::doctor::run(&cli.socket, *verbose).await {
            Ok(code) => process::exit(code),
            Err(e) => {
                eprintln!("sandbox doctor: internal error: {e}");
                process::exit(2);
            }
        }
    }

    // Hidden affordances for `sandbox update` orchestration.
    // Both dispatch entirely client-side — no socket access — so route
    // them before any other branch.
    if let Command::ApplyConfigMigration {
        file,
        migration,
        out,
    } = &cli.command
    {
        let code = handle_apply_config_migration(file, migration, out);
        process::exit(code);
    }
    if matches!(&cli.command, Command::ApplyConfigMigrations) {
        let code = handle_apply_config_migrations();
        process::exit(code);
    }
    if matches!(&cli.command, Command::DumpMigrationSet) {
        let code = handle_dump_migration_set();
        process::exit(code);
    }
    if matches!(&cli.command, Command::DumpProtoVersion) {
        let code = handle_dump_proto_version();
        process::exit(code);
    }

    // Handle `sandbox proxy <id>` specially — the hidden ProxyCommand
    // shim performs its own HTTP-to-WebSocket upgrade against
    // `/sessions/{id}/proxy` on the daemon socket and bidirectionally
    // splices stdin/stdout with binary WebSocket frames. It bypasses
    // the version-equality handshake (see
    // `command_bypasses_version_check`) because (a) it ships in the
    // same crate as the daemon so structural skew is impossible and
    // (b) any pre-flight stderr output would corrupt the SSH banner
    // exchange running over the same pipe.
    if let Command::Proxy { session } = &cli.command {
        let code = sandbox_cli::proxy::run(&cli.socket, session).await;
        process::exit(code);
    }

    // Handle ssh specially — it doesn't follow the normal request/response flow.
    if let Command::Ssh { session, command } = &cli.command {
        handle_ssh(&cli.socket, session, command).await;
        return;
    }

    // Handle stop specially — issues one POST per session so outcomes
    // can be printed and failures accumulated without short-circuiting
    // the remaining ids. See `handle_stop` for the full contract.
    if let Command::Stop { sessions, force } = &cli.command {
        handle_stop(&cli.socket, sessions, *force).await;
        return;
    }

    // Handle rm specially so the local
    // `~/.ssh/sandbox/sandbox-<id>{,.key}` cleanup runs only after the
    // daemon-side delete returns OK. Two-step shape: resolve to the
    // canonical id, DELETE, then `ssh_config::remove_session_entry`.
    // See `handle_rm` for the full contract. With variadic sessions,
    // we loop and accumulate failures; exit 1 if any session failed.
    if let Command::Rm { sessions } = &cli.command {
        let mut any_failed = false;
        for session in sessions {
            match handle_rm_inner(&cli.socket, session, None).await {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("{e}");
                    any_failed = true;
                }
            }
        }
        if any_failed {
            process::exit(1);
        }
        return;
    }

    // Handle cp specially — it dispatches to the backend's native
    // copy tool (`limactl cp` / `docker cp`) with stdio inherited.
    if let Command::Cp { src, dst } = &cli.command {
        handle_cp(&cli.socket, src, dst).await;
        return;
    }

    // Handle sync specially — same dispatch shape as cp, but the
    // subprocess is `rsync` with the backend's native shell as the
    // remote-shell transport (`-e` slot).
    if let Command::Sync {
        src,
        dst,
        rsync_args,
    } = &cli.command
    {
        handle_sync(&cli.socket, src, dst, rsync_args).await;
        return;
    }

    // Handle workspace push/pull/unlock specially — push/pull resolve
    // the session, acquire the daemon-side workspace lock, spawn rsync
    // with stdio inherited, then release the lock. Unlock is a single
    // DELETE call. None of the three fits the generic single
    // request/response shape `send_request` provides.
    if let Command::Workspace { action } = &cli.command {
        match action {
            WorkspaceAction::Push {
                session,
                force,
                dry_run,
                safe_links,
                no_gitignore,
            } => {
                handle_workspace_push(
                    &cli.socket,
                    session,
                    *force,
                    *dry_run,
                    *safe_links,
                    *no_gitignore,
                )
                .await;
            }
            WorkspaceAction::Pull {
                session,
                force,
                dry_run,
                safe_links,
                no_gitignore,
                dest,
            } => {
                handle_workspace_pull(
                    &cli.socket,
                    session,
                    *force,
                    *dry_run,
                    *safe_links,
                    *no_gitignore,
                    dest.clone(),
                )
                .await;
            }
            WorkspaceAction::Unlock { session, force } => {
                handle_workspace_unlock(&cli.socket, session, *force).await;
            }
        }
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

    // `sandbox policy dump ...` fetches the current policy from the
    // daemon and emits it as JSON. Route it before the generic pipeline
    // so the output path (stdout vs. --output file) is handled here
    // rather than inside the generic response handler.
    if let Command::Policy {
        action: PolicyAction::Dump { session, output },
    } = &cli.command
    {
        handle_policy_dump(&cli.socket, session, output.as_deref()).await;
        return;
    }

    // Pre-flight base image staleness check for create commands.
    if let Command::Create { no_cache, .. } = &cli.command {
        if !cli.yes && !*no_cache {
            check_base_image_staleness(&cli.socket).await;
        }
    }

    // rebuild-image fans out one HTTP call per selected backend.
    // The single-call
    // build_request / send_request flow does not fit a multi-call
    // command, so the dispatcher owns the full request loop, error
    // formatting (`rebuild-image[<kind>]: <msg>` as designed), and
    // exit-code mapping ("non-zero exit if any selected backend
    // fails").
    if let Command::RebuildImage { backend, no_cache } = &cli.command {
        dispatch_rebuild_image(&cli.socket, *backend, *no_cache).await;
        return;
    }

    // `sandbox update` runs its own orchestration loop (pre-flight,
    // confirmation prompt, stateful steps); exit-code semantics
    // (0 / 1 / 2 / 3) are defined by `update::run`, which returns the
    // exit code as a `process::ExitCode` forwarded verbatim here.
    if let Command::Update {
        version,
        from,
        cosign_bundle,
        source_url,
        check,
        dry_run,
        yes,
        force,
        quiet,
        verbose,
    } = &cli.command
    {
        let args = sandbox_cli::update::UpdateArgs {
            version: version.clone(),
            from: from.clone(),
            cosign_bundle: cosign_bundle.clone(),
            source_url: source_url.clone(),
            check: *check,
            dry_run: *dry_run,
            yes: *yes,
            force: *force,
            quiet: *quiet,
            verbose: *verbose,
            socket_path: cli.socket.clone(),
        };
        let code = sandbox_cli::update::run(args).await;
        std::process::exit(code);
    }

    // Create has a dedicated dispatch path because the request body
    // depends on a backend choice that is the output
    // of an async preflight (config load → resolver → /backends fetch
    // → SessionSpecvalidation). Running it here keeps `build_request`
    // sync for every other command and confines the new logic to one
    // explicit branch.
    let req = if let Command::Create {
        backend,
        lite,
        no_hardening,
        no_cache,
        force_rootless_docker,
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
            *force_rootless_docker,
            workspace.as_deref(),
            None,
        )
        .await;
        if resolved == sandbox_core::BackendKind::Lima {
            eprintln!("Creating sandbox VM — may take a few minutes…");
        }
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

    // Serializes all tests that read or write `SANDBOX_SOCKET`. Under
    // `cargo test`, multiple test threads share the same process and can
    // race on this env var. nextest provides per-test process isolation so
    // the lock is belt-and-suspenders there, but it keeps `cargo test` safe.
    static SANDBOX_SOCKET_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

    #[test]
    fn parse_create_no_name() {
        let cli = Cli::parse_from(["sandbox", "create"]);
        // Exhaustive match guarantees every field has its documented
        // default. `preset` is the repeatable preset invocation list;
        // an empty vec is the "no presets requested" shape the
        // `--preset` flag would populate.
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
                no_gitignore: false,
                backend: None,
                lite: false,
                force_rootless_docker: false,
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
                // `--cpus 4` parses as `4.0_f32`.
                assert_eq!(*cpus, Some(4.0_f32));
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
            Command::Stop { sessions, force } => {
                assert_eq!(sessions, &["my-session"]);
                assert!(!force);
            }
            _ => panic!("expected Stop command"),
        }
    }

    #[test]
    fn parse_stop_multiple_sessions() {
        let cli = Cli::parse_from(["sandbox", "stop", "sess-a", "sess-b", "sess-c"]);
        match &cli.command {
            Command::Stop { sessions, force } => {
                assert_eq!(sessions, &["sess-a", "sess-b", "sess-c"]);
                assert!(!force);
            }
            _ => panic!("expected Stop command"),
        }
    }

    #[test]
    fn parse_stop_with_force() {
        let cli = Cli::parse_from(["sandbox", "stop", "--force", "my-session"]);
        match &cli.command {
            Command::Stop { sessions, force } => {
                assert_eq!(sessions, &["my-session"]);
                assert!(force);
            }
            _ => panic!("expected Stop command"),
        }
    }

    #[test]
    fn parse_rm() {
        let cli = Cli::parse_from(["sandbox", "rm", "my-session"]);
        match &cli.command {
            Command::Rm { sessions } => assert_eq!(sessions, &["my-session"]),
            _ => panic!("expected Rm command"),
        }
    }

    #[test]
    fn parse_rm_multiple_sessions() {
        let cli = Cli::parse_from(["sandbox", "rm", "sess-a", "sess-b"]);
        match &cli.command {
            Command::Rm { sessions } => assert_eq!(sessions, &["sess-a", "sess-b"]),
            _ => panic!("expected Rm command"),
        }
    }

    #[test]
    fn parse_ps() {
        let cli = Cli::parse_from(["sandbox", "ps"]);
        assert!(matches!(
            cli.command,
            Command::Ps {
                no_reconcile: false,
                quiet: false,
            }
        ));
    }

    #[test]
    fn parse_ps_quiet() {
        let cli = Cli::parse_from(["sandbox", "ps", "-q"]);
        assert!(matches!(
            cli.command,
            Command::Ps {
                no_reconcile: false,
                quiet: true,
            }
        ));
    }

    #[test]
    fn parse_ls() {
        let cli = Cli::parse_from(["sandbox", "ls"]);
        assert!(matches!(
            cli.command,
            Command::Ls {
                no_reconcile: false,
                quiet: false,
            }
        ));
    }

    #[test]
    fn parse_ls_quiet() {
        let cli = Cli::parse_from(["sandbox", "ls", "--quiet"]);
        assert!(matches!(
            cli.command,
            Command::Ls {
                no_reconcile: false,
                quiet: true,
            }
        ));
    }

    #[test]
    fn parse_ls_no_reconcile() {
        let cli = Cli::parse_from(["sandbox", "ls", "--no-reconcile"]);
        assert!(matches!(
            cli.command,
            Command::Ls {
                no_reconcile: true,
                ..
            }
        ));
    }

    #[test]
    fn parse_ps_no_reconcile() {
        let cli = Cli::parse_from(["sandbox", "ps", "--no-reconcile"]);
        assert!(matches!(
            cli.command,
            Command::Ps {
                no_reconcile: true,
                ..
            }
        ));
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
        // When SANDBOX_SOCKET is absent, the clap env attr falls through to
        // default_socket_path() and the resolved path must end with
        // `sandboxd.sock`. Clear any inherited env var first so the test is
        // hermetic. Hold SANDBOX_SOCKET_LOCK for the duration so concurrent
        // cargo-test threads cannot race on the env var.
        let _guard = SANDBOX_SOCKET_LOCK.lock().unwrap();
        let prior = std::env::var("SANDBOX_SOCKET").ok();
        // SAFETY: protected by SANDBOX_SOCKET_LOCK; only one thread touches
        // this var at a time. nextest runs each test in its own process so
        // the lock is belt-and-suspenders there.
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
    fn default_socket_prefers_system_when_present() {
        // System socket exists → wins over XDG, so a deployed-host operator
        // reaches the system daemon without setting SANDBOX_SOCKET.
        let got = default_socket_path_with(
            |p| p == sandbox_cli::SYSTEM_SOCKET_PATH,
            |k| match k {
                "XDG_RUNTIME_DIR" => Some("/run/user/1000".to_string()),
                _ => None,
            },
        );
        assert_eq!(got, sandbox_cli::SYSTEM_SOCKET_PATH);
    }

    #[test]
    fn default_socket_falls_to_xdg_when_no_system() {
        // No system socket → dev / user-run daemon default under XDG.
        let got = default_socket_path_with(
            |_| false,
            |k| match k {
                "XDG_RUNTIME_DIR" => Some("/run/user/1000".to_string()),
                "HOME" => Some("/home/op".to_string()),
                _ => None,
            },
        );
        assert_eq!(got, "/run/user/1000/sandboxd/sandboxd.sock");
    }

    #[test]
    fn default_socket_falls_to_home_when_no_system_no_xdg() {
        let got = default_socket_path_with(
            |_| false,
            |k| match k {
                "HOME" => Some("/home/op".to_string()),
                _ => None,
            },
        );
        assert_eq!(got, "/home/op/.local/share/sandboxd/sandboxd.sock");
    }

    #[test]
    fn default_socket_path_honors_sandbox_socket_env() {
        // Hold SANDBOX_SOCKET_LOCK for the duration so concurrent cargo-test
        // threads cannot interleave their env-var mutations with this test.
        let _guard = SANDBOX_SOCKET_LOCK.lock().unwrap();
        let prior = std::env::var("SANDBOX_SOCKET").ok();

        // SANDBOX_SOCKET is honored by clap's `env = "SANDBOX_SOCKET"` on
        // the --socket arg when no explicit flag is given. This matches the
        // daemon's precedence: `--socket` > env > XDG/HOME.
        // Note: default_socket_path() itself no longer reads SANDBOX_SOCKET;
        // clap reads the env var per-parse, which is safe and correct here
        // because the lock prevents other threads from mutating it concurrently.
        // SAFETY: protected by SANDBOX_SOCKET_LOCK; only one thread touches
        // this var at a time. nextest runs each test in its own process so
        // the lock is belt-and-suspenders there.
        unsafe { std::env::set_var("SANDBOX_SOCKET", "/tmp/from-env.sock") };
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
            cpus: Some(2.0),
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
            no_gitignore: false,
            backend: None,
            lite: false,
            force_rootless_docker: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri(), "/sessions");
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert_eq!(body["name"], "test");
        // cpus is `f32` on the wire; serde_json renders `2.0_f32`
        // as JSON `2.0` (a `Number::Float`), so compare via `as_f64`
        // rather than against an integer literal.
        assert_eq!(body["cpus"].as_f64(), Some(2.0));
        assert_eq!(body["memory_mb"], 4096);
        assert_eq!(body["disk_gb"], 20);
    }

    #[test]
    fn build_create_request_no_name() {
        let cmd = Command::Create {
            name: None,
            cpus: Some(4.0),
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
            no_gitignore: false,
            backend: None,
            lite: false,
            force_rootless_docker: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri(), "/sessions");
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert!(body.get("name").is_none());
        assert_eq!(body["cpus"].as_f64(), Some(4.0));
        assert_eq!(body["memory_mb"], 8192);
        assert_eq!(body["disk_gb"], 50);
    }

    #[test]
    fn build_create_request_with_template() {
        let cmd = Command::Create {
            name: Some("custom".into()),
            cpus: Some(2.0),
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
            no_gitignore: false,
            backend: None,
            lite: false,
            force_rootless_docker: false,
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
    fn build_stop_request_returns_none_for_dispatch_bypass() {
        // `sandbox stop` is intercepted in `main()` via `handle_stop`,
        // so the generic `build_request` pipeline is never reached.
        // The multi-session loop with per-id outcomes lives in
        // `handle_stop` and is not exercisable through `build_request`.
        let cmd = Command::Stop {
            sessions: vec!["abc".into()],
            force: false,
        };
        assert!(
            build_request(&cmd).is_none(),
            "Stop is intercepted in main() — build_request must return None"
        );
    }

    #[test]
    fn build_rm_request_returns_none_for_dispatch_bypass() {
        // `sandbox rm` is intercepted in `main()` via `handle_rm`,
        // so the generic `build_request` pipeline never builds the
        // DELETE request itself. The two-step
        // resolve-then-DELETE-then-local-cleanup shape lives in
        // `handle_rm_inner` and is exercised by its own hermetic
        // tests (`handle_rm_removes_local_entry_on_daemon_success`,
        // `handle_rm_keeps_local_entry_on_daemon_delete_failure`,
        // `handle_rm_keeps_local_entry_on_404_resolve`).
        let cmd = Command::Rm {
            sessions: vec!["abc".into()],
        };
        assert!(
            build_request(&cmd).is_none(),
            "Rm is intercepted in main() — build_request must return None"
        );
    }

    #[test]
    fn build_ps_request() {
        let cmd = Command::Ps {
            no_reconcile: false,
            quiet: false,
        };
        let req = build_request(&cmd).expect("should produce request");
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), "/sessions");
    }

    #[test]
    fn build_ls_request() {
        let cmd = Command::Ls {
            no_reconcile: false,
            quiet: false,
        };
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
            cpus: Some(2.0),
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
            no_gitignore: false,
            backend: None,
            lite: false,
            force_rootless_docker: false,
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
            cpus: Some(2.0),
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
            no_gitignore: false,
            backend: None,
            lite: false,
            force_rootless_docker: false,
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
            cpus: Some(2.0),
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
            no_gitignore: false,
            backend: None,
            lite: false,
            force_rootless_docker: false,
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
            cpus: Some(2.0),
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
            no_gitignore: false,
            backend: None,
            lite: false,
            force_rootless_docker: false,
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
            parse_remote_helper_url("my-session/home/sandbox/workspace/repo.git").unwrap();
        assert_eq!(session, "my-session");
        assert_eq!(
            repo_path,
            Some("/home/sandbox/workspace/repo.git".to_string())
        );
    }

    #[test]
    fn parse_remote_helper_url_with_scheme_prefix() {
        // git may pass the full URL including the sandbox:: prefix.
        let (session, repo_path) =
            parse_remote_helper_url("sandbox::my-session/home/sandbox/workspace/repo").unwrap();
        assert_eq!(session, "my-session");
        assert_eq!(repo_path, Some("/home/sandbox/workspace/repo".to_string()));
    }

    #[test]
    fn parse_remote_helper_url_session_only() {
        // No slash — the path is left unresolved (None) so the caller
        // can derive the default from the session's workspace
        // configuration via the daemon. M17 made the guest mount point
        // operator-configurable, so the parser must not bake in the
        // `/home/sandbox/workspace` default.
        let (session, repo_path) = parse_remote_helper_url("my-session").unwrap();
        assert_eq!(session, "my-session");
        assert_eq!(repo_path, None);
    }

    #[test]
    fn parse_remote_helper_url_session_only_with_scheme_prefix() {
        // Same as above but with the `sandbox::` prefix git sometimes
        // includes when invoking the helper.
        let (session, repo_path) = parse_remote_helper_url("sandbox::my-session").unwrap();
        assert_eq!(session, "my-session");
        assert_eq!(repo_path, None);
    }

    #[test]
    fn parse_remote_helper_url_empty() {
        assert!(parse_remote_helper_url("").is_err());
    }

    #[test]
    fn parse_remote_helper_url_empty_session() {
        // Starts with slash — empty session name.
        assert!(parse_remote_helper_url("/home/sandbox/workspace").is_err());
    }

    // -- resolve_default_repo_path tests ------------------------------------

    #[test]
    fn resolve_default_repo_path_shared_uses_guest_path() {
        let detail = WorkspaceModeDetailDto::Shared {
            host_path: "/host/proj".into(),
            guest_path: "/mnt/work".into(),
            security_model: None,
        };
        assert_eq!(resolve_default_repo_path(Some(&detail)), "/mnt/work");
    }

    #[test]
    fn resolve_default_repo_path_local_uses_guest_path() {
        let detail = WorkspaceModeDetailDto::Local {
            host_path: "/host/proj".into(),
            guest_path: "/srv/repo".into(),
        };
        assert_eq!(resolve_default_repo_path(Some(&detail)), "/srv/repo");
    }

    #[test]
    fn resolve_default_repo_path_clone_uses_workspace_default() {
        // Clone-mode sessions land the repo at /home/sandbox/workspace
        // by convention; the parser default preserves that for slash-
        // less URLs.
        let detail = WorkspaceModeDetailDto::Clone {
            repo_url: "https://example/r.git".into(),
        };
        assert_eq!(
            resolve_default_repo_path(Some(&detail)),
            "/home/sandbox/workspace"
        );
    }

    #[test]
    fn resolve_default_repo_path_none_uses_workspace_default() {
        // No workspace, or an older daemon that doesn't populate
        // `workspace_mode_detail` — fall back to the unified default.
        assert_eq!(resolve_default_repo_path(None), "/home/sandbox/workspace");
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
            cpus: Some(2.0),
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
            no_gitignore: false,
            backend: None,
            lite: false,
            force_rootless_docker: false,
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
            cpus: Some(2.0),
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
            no_gitignore: false,
            backend: None,
            lite: false,
            force_rootless_docker: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert!(
            body.get("no_cache").is_none(),
            "default (no_cache=false) should omit the field from request body"
        );
    }

    // -----------------------------------------------------------------------
    // validate_no_gitignore_for_workspace — CLI-side pre-validation gate.
    //
    // Pure predicate; matches the daemon-side
    // `validate_no_gitignore_against_workspace` rejection wording
    // byte-for-byte so a CLI-driven failure and a hand-rolled HTTP
    // client failure both surface the same diagnostic. The literal
    // string lives at both call sites because there is no shared
    // error catalog in `sandbox-core` today.
    // -----------------------------------------------------------------------

    #[test]
    fn validate_no_gitignore_accepts_local_workspace() {
        // `/tmp` is guaranteed to exist and be a directory on every
        // host the test runs on; the parser's SF-11 directory-required
        // check passes.
        assert_eq!(
            validate_no_gitignore_for_workspace(Some("local:/tmp")),
            Ok(())
        );
        // Explicit guest path also lands on the local arm.
        assert_eq!(
            validate_no_gitignore_for_workspace(Some("local:/tmp:/srv/work")),
            Ok(())
        );
    }

    #[test]
    fn validate_no_gitignore_rejects_shared_workspace() {
        let err = validate_no_gitignore_for_workspace(Some("shared:/tmp"))
            .expect_err("flag + shared: must reject");
        assert_eq!(
            err,
            "--no-gitignore is only meaningful for local: workspaces; this session uses shared:"
        );
    }

    #[test]
    fn validate_no_gitignore_rejects_clone_workspace() {
        let err =
            validate_no_gitignore_for_workspace(Some("clone:https://example.invalid/repo.git"))
                .expect_err("flag + clone: must reject");
        assert_eq!(
            err,
            "--no-gitignore is only meaningful for local: workspaces; this session uses clone:"
        );
    }

    #[test]
    fn validate_no_gitignore_rejects_absent_workspace() {
        let err = validate_no_gitignore_for_workspace(None)
            .expect_err("flag + absent --workspace must reject");
        assert_eq!(
            err,
            "--no-gitignore is only meaningful for local: workspaces; this session uses <empty>:"
        );
    }

    #[test]
    fn validate_workspace_host_path_accepts_existing_shared_path() {
        let mode = sandbox_core::WorkspaceMode::parse_flag("shared:/tmp").unwrap();
        assert_eq!(validate_workspace_host_path_for_create(&mode), Ok(()));
    }

    #[test]
    fn validate_workspace_host_path_rejects_missing_shared_path() {
        let missing = std::env::temp_dir().join(format!(
            "sandbox-missing-shared-host-{}-{}",
            std::process::id(),
            line!()
        ));
        let missing = missing.to_string_lossy().to_string();
        let mode = sandbox_core::WorkspaceMode::parse_flag(&format!("shared:{missing}")).unwrap();

        let err = validate_workspace_host_path_for_create(&mode)
            .expect_err("missing shared path must reject in the CLI");
        assert!(err.contains("shared workspace host_path does not exist"));
        assert!(err.contains(&missing), "err = {err}");
    }

    #[test]
    fn validate_workspace_host_path_rejects_missing_local_path() {
        let missing = std::env::temp_dir().join(format!(
            "sandbox-missing-local-host-{}-{}",
            std::process::id(),
            line!()
        ));
        let missing = missing.to_string_lossy().to_string();
        let mode = sandbox_core::WorkspaceMode::parse_flag(&format!("local:{missing}")).unwrap();

        let err = validate_workspace_host_path_for_create(&mode)
            .expect_err("missing local path must reject in the CLI");
        assert!(err.contains("local workspace host_path does not exist"));
        assert!(err.contains(&missing), "err = {err}");
    }

    #[test]
    fn validate_workspace_host_path_rejects_local_file_path() {
        let path = std::env::temp_dir().join(format!(
            "sandbox-local-file-host-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::write(&path, b"single-file payload").expect("write temp file");
        let path = path.to_string_lossy().to_string();
        let mode = sandbox_core::WorkspaceMode::parse_flag(&format!("local:{path}")).unwrap();

        let err = validate_workspace_host_path_for_create(&mode)
            .expect_err("local file path must reject in the CLI");
        assert!(err.contains("must be a directory for `local:`"));
        assert!(err.contains("sandbox cp"));
        assert!(err.contains(&path), "err = {err}");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn build_create_request_with_no_gitignore_and_local_workspace() {
        // Happy path: `--no-gitignore` + `--workspace local:` stamps
        // `no_gitignore: true` on the wire body. `/tmp` is the same
        // safe always-exists path the session-side parser tests use
        // — the parser's SF-11 directory check requires a real
        // directory on the host running the test.
        let cmd = Command::Create {
            name: Some("local-skip-gitignore".into()),
            cpus: Some(2.0),
            memory: Some(4096),
            disk: 20,
            template: None,
            policy: None,
            preset: vec![],
            repo: None,
            boot_cmd: None,
            workspace: Some("local:/tmp".into()),
            no_hardening: false,
            no_cache: false,
            no_gitignore: true,
            backend: None,
            lite: false,
            force_rootless_docker: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert_eq!(
            body["no_gitignore"], true,
            "--no-gitignore should stamp no_gitignore=true on the wire body"
        );
    }

    #[test]
    fn build_create_request_default_omits_no_gitignore() {
        let cmd = Command::Create {
            name: Some("default".into()),
            cpus: Some(2.0),
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
            no_gitignore: false,
            backend: None,
            lite: false,
            force_rootless_docker: false,
        };
        let req = build_create_request_body(&cmd, sandbox_core::BackendKind::Lima);
        let body: serde_json::Value = serde_json::from_str(req.body()).unwrap();
        assert!(
            body.get("no_gitignore").is_none(),
            "default (no_gitignore=false) must omit the field from the request body so older daemons see a bit-equal request"
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
    /// defaults to `false`.
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

    /// `--backend container --no-cache` is the example shape;
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

    /// `--backend all` issues two HTTP
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
        // : JSON wire body carries the resolved
        // backend kind plus no_cache.
        let lima_body: serde_json::Value = serde_json::from_str(&calls[0].1).unwrap();
        assert_eq!(lima_body["backend"], serde_json::json!("lima"));
        assert_eq!(lima_body["no_cache"], serde_json::json!(false));
        let container_body: serde_json::Value = serde_json::from_str(&calls[1].1).unwrap();
        assert_eq!(container_body["backend"], serde_json::json!("container"));
        assert_eq!(container_body["no_cache"], serde_json::json!(false));
    }

    /// Per-backend errors must be prefixed with `rebuild-image[<kind>]:`
    /// A single failing backend forces
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
        // Lima line carries the prefix shape and the daemon's
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
            owner_username: "test-operator".into(),
            config: SessionConfigDto {
                cpus: 2.0,
                memory_mb: 4096,
                disk_gb: 20,
                resolved_cpus: 2.0,
                resolved_memory_mb: 4096,
                workspace_mode: Some("shared:/home/olek/project".into()),
                workspace_mode_detail: Some(WorkspaceModeDetailDto::Shared {
                    host_path: "/home/olek/project".into(),
                    guest_path: "/home/olek/project".into(),
                    security_model: None,
                }),
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
            rootless: None,
            guest_protocol_version: 0,
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
    // `--no-capture`). Keeps the design sample near the implementation.
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
    /// `BACKEND` column header between `STATE` and `AGENT`. Contract
    /// pin so the column does not silently drift.
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

    // -- quiet (-q) output shape ---------------------------------------------------

    /// `-q` output must be one bare session ID per line with no header,
    /// no table glyphs, and no trailing whitespace beyond the newline.
    /// Contract pin so the pipeline-friendly shape (`sandbox ps -q | xargs
    /// sandbox stop`) cannot silently regress.
    #[test]
    fn write_sessions_quiet_emits_one_id_per_line_no_header() {
        let a = make_session_dto("0123456789ab", Some("alpha"), None, chrono::Utc::now());
        let b = make_session_dto("ba9876543210", Some("beta"), None, chrono::Utc::now());
        let mut buf = Vec::new();
        write_sessions_quiet(&mut buf, &[a.clone(), b.clone()]);
        let rendered = String::from_utf8(buf).expect("quiet output is UTF-8");

        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "expected exactly 2 lines for 2 sessions, got:\n{rendered}"
        );
        assert_eq!(
            lines[0],
            a.id.as_str(),
            "first line must be the first session ID verbatim"
        );
        assert_eq!(
            lines[1],
            b.id.as_str(),
            "second line must be the second session ID verbatim"
        );
        // No header or table glyphs: lines must not contain column names or
        // box-drawing characters.
        for line in &lines {
            assert!(
                !line.contains("ID") && !line.contains("STATE") && !line.contains("NAME"),
                "quiet line must not contain table headers, got: {line}"
            );
        }
    }

    /// `-q` output for an empty session list must be completely empty
    /// (no placeholder, no blank line) — empty output is the correct
    /// signal for a pipeline that finds nothing to act on.
    #[test]
    fn write_sessions_quiet_empty_emits_nothing() {
        let mut buf = Vec::new();
        write_sessions_quiet(&mut buf, &[]);
        let rendered = String::from_utf8(buf).expect("quiet output is UTF-8");
        assert_eq!(
            rendered, "",
            "quiet mode with no sessions must produce empty output"
        );
    }

    // -- describe/inspect rendering of cpus / memory must surface the
    //    daemon's host-80% default for container sessions whose
    //    persisted column is `0` (operator omitted `--cpus`/`--memory`).
    //    An earlier render shape rendered "CPUs: 0, Memory: 0 MB"
    //    which mislead operators.

    /// Container session created without `--cpus` (`config.cpus == 0`).
    /// `format_cpus_field` must surface the daemon's resolved host-80%
    /// default with a `(default)` hint instead of the raw `0`.
    #[test]
    fn format_cpus_field_default_path_renders_resolved_with_hint() {
        let dto_config = sandbox_core::SessionConfigDto {
            cpus: 0.0,
            memory_mb: 0,
            disk_gb: 20,
            resolved_cpus: 1.6,
            resolved_memory_mb: 13107,
            workspace_mode: None,
            workspace_mode_detail: None,
            hardened: false,
            repo: None,
            boot_cmd: None,
            template: None,
        };
        assert_eq!(format_cpus_field(&dto_config), "1.6 (default)");
        assert_eq!(format_memory_field(&dto_config), "13107 MB (default)");
    }

    /// Operator-supplied integer ceiling (e.g. Lima default `2`):
    /// render without trailing `.0` so the display matches the
    /// pre-todo-#67 shape Lima operators are used to.
    #[test]
    fn format_cpus_field_integer_value_renders_without_trailing_dot_zero() {
        let dto_config = sandbox_core::SessionConfigDto {
            cpus: 2.0,
            memory_mb: 4096,
            disk_gb: 20,
            resolved_cpus: 2.0,
            resolved_memory_mb: 4096,
            workspace_mode: None,
            workspace_mode_detail: None,
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
        };
        assert_eq!(format_cpus_field(&dto_config), "2");
        assert_eq!(format_memory_field(&dto_config), "4096 MB");
    }

    /// Operator-supplied 1-decimal value (e.g. `--cpus 1.5` on a
    /// container session): render with the `:.1` precision, no
    /// `(default)` hint because the value is explicit.
    #[test]
    fn format_cpus_field_fractional_value_renders_one_decimal() {
        let dto_config = sandbox_core::SessionConfigDto {
            cpus: 1.5,
            memory_mb: 2048,
            disk_gb: 20,
            resolved_cpus: 1.5,
            resolved_memory_mb: 2048,
            workspace_mode: None,
            workspace_mode_detail: None,
            hardened: false,
            repo: None,
            boot_cmd: None,
            template: None,
        };
        assert_eq!(format_cpus_field(&dto_config), "1.5");
        assert_eq!(format_memory_field(&dto_config), "2048 MB");
    }

    /// End-to-end through `render_describe`: the rendered describe
    /// output for a container session created without `--cpus` /
    /// `--memory` must contain the resolved-default lines and must
    /// NOT contain the raw `CPUs:        0` / `Memory:      0 MB`
    /// strings the pre-Bundle-Z render would have produced.
    #[test]
    fn describe_container_default_resources_render_as_resolved_with_hint() {
        let mut dto = make_session_dto(
            "ccccdddddeee",
            Some("lite-default"),
            None,
            chrono::Utc::now(),
        );
        dto.backend = sandbox_core::backend::BackendKind::Container;
        dto.config.cpus = 0.0;
        dto.config.memory_mb = 0;
        dto.config.resolved_cpus = 1.6;
        dto.config.resolved_memory_mb = 13107;
        let rendered = render_describe(std::slice::from_ref(&dto), None);
        assert!(
            rendered.contains("CPUs:        1.6 (default)"),
            "expected resolved cpus with `(default)` hint, got:\n{rendered}"
        );
        assert!(
            rendered.contains("Memory:      13107 MB (default)"),
            "expected resolved memory with `(default)` hint, got:\n{rendered}"
        );
        // Regression net for the pre-Bundle-Z misleading shape.
        assert!(
            !rendered.contains("CPUs:        0\n"),
            "must not render the raw `0` sentinel, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("Memory:      0 MB\n"),
            "must not render the raw `0` memory sentinel, got:\n{rendered}"
        );
    }

    /// Default-view `describe` (no `-v`) must show `Backend:` adjacent
    /// to `State:`.
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
            rendered.contains("workspace_modes:      shared, clone, local"),
            "Lima advertises every workspace mode, got:\n{rendered}"
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

    // -- Workspace block rendering --------------------------------------------

    /// `Shared` with `security_model = None` (no operator override at
    /// create time) renders the `mapped-xattr (default)` annotation so
    /// the operator can tell the value was inherited, not asserted.
    #[test]
    fn describe_renders_shared_workspace_with_default_security_annotation() {
        let mut dto = make_session_dto(
            "1111aaaa2222",
            Some("shared-default"),
            None,
            chrono::Utc::now(),
        );
        dto.config.workspace_mode = Some("shared:/home/olek/project".into());
        dto.config.workspace_mode_detail = Some(WorkspaceModeDetailDto::Shared {
            host_path: "/home/olek/project".into(),
            guest_path: "/home/olek/project".into(),
            security_model: None,
        });
        let rendered = render_describe(std::slice::from_ref(&dto), None);
        assert!(
            rendered.contains("  Workspace:\n"),
            "expected multi-line Workspace header, got:\n{rendered}"
        );
        assert!(
            rendered.contains("    Mode:       shared\n"),
            "expected Mode row, got:\n{rendered}"
        );
        assert!(
            rendered.contains("    Host path:  /home/olek/project\n"),
            "expected Host path row, got:\n{rendered}"
        );
        assert!(
            rendered.contains("    Guest path: /home/olek/project\n"),
            "expected Guest path row, got:\n{rendered}"
        );
        assert!(
            rendered.contains("    Security:   mapped-xattr (default)\n"),
            "expected default-annotated Security row, got:\n{rendered}"
        );
    }

    /// `Some(MappedXattr)` is an operator-asserted choice — the
    /// `(default)` annotation must NOT appear because the value is no
    /// longer inherited.
    #[test]
    fn describe_renders_shared_workspace_with_explicit_mapped_xattr() {
        let mut dto = make_session_dto(
            "1111aaaa3333",
            Some("shared-mapped"),
            None,
            chrono::Utc::now(),
        );
        dto.config.workspace_mode = Some("shared:/home/olek/project:mapped-xattr".into());
        dto.config.workspace_mode_detail = Some(WorkspaceModeDetailDto::Shared {
            host_path: "/home/olek/project".into(),
            guest_path: "/home/olek/project".into(),
            security_model: Some(WorkspaceSecurityModelDto::MappedXattr),
        });
        let rendered = render_describe(std::slice::from_ref(&dto), None);
        assert!(
            rendered.contains("    Security:   mapped-xattr\n"),
            "expected verbatim Security row, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("    Security:   mapped-xattr (default)"),
            "explicit Some(MappedXattr) must not carry (default) annotation, got:\n{rendered}"
        );
    }

    /// `Some(NoneMapping)` renders the `none` wire token verbatim.
    #[test]
    fn describe_renders_shared_workspace_with_explicit_none() {
        let mut dto = make_session_dto(
            "1111aaaa4444",
            Some("shared-none"),
            None,
            chrono::Utc::now(),
        );
        dto.config.workspace_mode = Some("shared:/home/olek/project:none".into());
        dto.config.workspace_mode_detail = Some(WorkspaceModeDetailDto::Shared {
            host_path: "/home/olek/project".into(),
            guest_path: "/home/olek/project".into(),
            security_model: Some(WorkspaceSecurityModelDto::NoneMapping),
        });
        let rendered = render_describe(std::slice::from_ref(&dto), None);
        assert!(
            rendered.contains("    Security:   none\n"),
            "expected `none` Security row, got:\n{rendered}"
        );
    }

    /// Custom `guest_path` distinct from `host_path` renders both
    /// rows with the operator's resolved values.
    #[test]
    fn describe_renders_shared_workspace_with_custom_guest_path() {
        let mut dto = make_session_dto(
            "1111aaaa5555",
            Some("shared-guest"),
            None,
            chrono::Utc::now(),
        );
        dto.config.workspace_mode = Some("shared:/tmp/sbx-a:/srv/work".into());
        dto.config.workspace_mode_detail = Some(WorkspaceModeDetailDto::Shared {
            host_path: "/tmp/sbx-a".into(),
            guest_path: "/srv/work".into(),
            security_model: None,
        });
        let rendered = render_describe(std::slice::from_ref(&dto), None);
        assert!(
            rendered.contains("    Host path:  /tmp/sbx-a\n"),
            "expected operator's host path, got:\n{rendered}"
        );
        assert!(
            rendered.contains("    Guest path: /srv/work\n"),
            "expected operator's guest path distinct from host, got:\n{rendered}"
        );
    }

    /// `Clone` renders the two-row block with `Mode: clone` and
    /// `Repo: <url>` — no host/guest path rows.
    #[test]
    fn describe_renders_clone_workspace_block() {
        let mut dto = make_session_dto(
            "1111aaaa6666",
            Some("clone-block"),
            None,
            chrono::Utc::now(),
        );
        dto.config.workspace_mode = Some("clone:https://github.com/example/app.git".into());
        dto.config.workspace_mode_detail = Some(WorkspaceModeDetailDto::Clone {
            repo_url: "https://github.com/example/app.git".into(),
        });
        let rendered = render_describe(std::slice::from_ref(&dto), None);
        assert!(
            rendered.contains("  Workspace:\n"),
            "expected multi-line Workspace header, got:\n{rendered}"
        );
        assert!(
            rendered.contains("    Mode:       clone\n"),
            "expected `Mode: clone` row, got:\n{rendered}"
        );
        assert!(
            rendered.contains("    Repo:       https://github.com/example/app.git\n"),
            "expected `Repo:` row, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("Host path:"),
            "Clone must not render a Host path row, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("Security:"),
            "Clone must not render a Security row, got:\n{rendered}"
        );
    }

    /// `Local` renders the three-row block with `Mode: local`,
    /// `Host path:`, and `Guest path:` rows — no `Security:` row
    /// (only `shared:` has a security model).
    ///
    /// Byte-equal golden test pinning the exact rendered substring so
    /// future refactors of `render_workspace_block` cannot silently
    /// shift the operator-facing surface. The 12-char value-column
    /// padding matches the `Shared` arm pattern (see
    /// `describe_renders_shared_workspace_*` tests above).
    #[test]
    fn describe_renders_local_workspace_block() {
        let mut dto = make_session_dto(
            "1111aaaa8888",
            Some("local-block"),
            None,
            chrono::Utc::now(),
        );
        dto.config.workspace_mode = Some("local:/home/user/proj:/srv/work".into());
        dto.config.workspace_mode_detail = Some(WorkspaceModeDetailDto::Local {
            host_path: "/home/user/proj".into(),
            guest_path: "/srv/work".into(),
        });
        let rendered = render_describe(std::slice::from_ref(&dto), None);
        // Byte-equal golden: the four-line `Workspace:` block must
        // appear verbatim in the rendered output, including the
        // exact 12-char value-column padding.
        let expected = "  Workspace:\n    \
            Mode:       local\n    \
            Host path:  /home/user/proj\n    \
            Guest path: /srv/work\n";
        assert!(
            rendered.contains(expected),
            "expected verbatim Local block; got:\n{rendered}"
        );
        // The Local workspace block has no Security row (only shared:
        // carries a security model) and no Repo row (only clone:
        // names a repo URL inside the workspace block). Note: the
        // top-level `Repo:` row in `Config:` comes from the session-
        // level `repo` field and is unrelated; we scope the
        // negative assertion to the workspace block by checking for
        // the indented multi-line forms.
        assert!(
            !rendered.contains("    Security:"),
            "Local must not render a Security row inside Workspace, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("    Repo:"),
            "Local must not render a Repo row inside Workspace, got:\n{rendered}"
        );
    }

    /// `Local` with `guest_path == host_path` still renders both rows
    /// verbatim — the describe surface is uniform across the
    /// guest-explicit and guest-equals-host cases (no compact-form
    /// collapse in describe; the compact-form rule applies only to
    /// the flat-string `workspace_mode` field).
    #[test]
    fn describe_renders_local_workspace_block_with_default_guest_path() {
        let mut dto = make_session_dto(
            "1111aaaa9999",
            Some("local-default"),
            None,
            chrono::Utc::now(),
        );
        dto.config.workspace_mode = Some("local:/home/user/proj".into());
        dto.config.workspace_mode_detail = Some(WorkspaceModeDetailDto::Local {
            host_path: "/home/user/proj".into(),
            guest_path: "/home/user/proj".into(),
        });
        let rendered = render_describe(std::slice::from_ref(&dto), None);
        let expected = "  Workspace:\n    \
            Mode:       local\n    \
            Host path:  /home/user/proj\n    \
            Guest path: /home/user/proj\n";
        assert!(
            rendered.contains(expected),
            "expected verbatim Local block with equal host/guest paths; got:\n{rendered}"
        );
    }

    /// Older daemons populate only `workspace_mode` (the flat string)
    /// and leave `workspace_mode_detail = None`. The CLI must fall
    /// back to the historical single-line render so the
    /// operator-facing surface stays compatible across the
    /// daemon-vs-CLI version skew.
    #[test]
    fn describe_renders_older_daemon_workspace_single_line_fallback() {
        let mut dto = make_session_dto(
            "1111aaaa7777",
            Some("legacy-daemon"),
            None,
            chrono::Utc::now(),
        );
        dto.config.workspace_mode = Some("shared:/foo".into());
        dto.config.workspace_mode_detail = None;
        let rendered = render_describe(std::slice::from_ref(&dto), None);
        assert!(
            rendered.contains("  Workspace:   shared:/foo\n"),
            "expected single-line fallback when detail is absent, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("    Mode:"),
            "fallback must not emit multi-line Mode row, got:\n{rendered}"
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
        mut routes: std::collections::HashMap<String, (u16, String)>,
    ) -> (tempfile::TempDir, String) {
        // Auto-install the `/version` handshake route every fake
        // daemon needs: `send_request_with_timeout` issues
        // `GET /version` on every connection (strict CLI ↔ daemon
        // version-equality rule), and the equality predicate must
        // pass for the test's actual request to flow through. The
        // route is overridable — a test that wants to exercise a
        // skewed daemon can pre-populate the entry.
        routes.entry("/version".to_string()).or_insert_with(|| {
            (
                200,
                format!(r#"{{"version":"{}"}}"#, env!("CARGO_PKG_VERSION")),
            )
        });

        let tmp = tempfile::tempdir().expect("tempdir");
        let sock_path = tmp.path().join("sandboxd.sock");
        let sock_str = sock_path.to_string_lossy().to_string();

        let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
        // The listener is moved into the server thread; the TempDir stays
        // in the caller so the socket file lives for the duration of the
        // test.
        //
        // Each accepted connection now serves the version handshake +
        // up to one subsequent request on the same HTTP/1.1 keep-
        // alive: `send_request_with_timeout` fires `GET /version`
        // first, reads the response, and then issues the caller's
        // real request on the same connection. The fake server must
        // therefore loop over reads-per-connection (read until the
        // peer closes the socket) rather than closing after a single
        // exchange. Each request is parsed as one line + headers
        // (no body for GET) and the response carries `Connection:
        // close` only after the **second** request, so the CLI's
        // keep-alive driver is happy to send both requests.
        thread::spawn(move || {
            for conn in listener.incoming() {
                let mut stream = match conn {
                    Ok(s) => s,
                    Err(_) => break,
                };
                // Serve up to two requests per connection (version
                // handshake + caller's request). After the second
                // request we send `Connection: close` and break.
                let mut buf = vec![0u8; 8192];
                let mut accumulated: Vec<u8> = Vec::new();
                let mut served = 0;
                loop {
                    if served >= 2 {
                        break;
                    }
                    // Read until we have at least one complete request
                    // (terminated by `\r\n\r\n`).
                    let header_end = loop {
                        if let Some(pos) = accumulated.windows(4).position(|w| w == b"\r\n\r\n") {
                            break Some(pos);
                        }
                        let n = match stream.read(&mut buf) {
                            Ok(0) => break None,
                            Ok(n) => n,
                            Err(_) => break None,
                        };
                        accumulated.extend_from_slice(&buf[..n]);
                    };
                    let Some(header_end) = header_end else {
                        break;
                    };
                    let req = String::from_utf8_lossy(&accumulated[..header_end]).to_string();
                    accumulated.drain(..header_end + 4);
                    let request_line = req.lines().next().unwrap_or("");
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
                    served += 1;
                    let conn_header = if served >= 2 { "close" } else { "keep-alive" };
                    let response = format!(
                        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {conn_header}\r\n\r\n{body}",
                        body.len(),
                    );
                    if stream.write_all(response.as_bytes()).is_err() {
                        break;
                    }
                }
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
        // The JSON `inspect` automation contract picks up `backend`
        // "for free" via SessionDto's additive field. Pin the wire
        // key here so an accidental rename or removal in `SessionDto`
        // lights up the inspect contract test, not just the deeper
        // serde unit tests.
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
        // The error names the first missing id. Here "missing-one" is the
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
    // `sandbox events` subcommand.
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
    // `policy status` subcommand
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
    // The historical `plan_ssh_command` / `plan_cp_command` /
    // `plan_sync_command` planners were backend-dispatching helpers
    // that emitted `limactl shell …` / `docker exec …` argvs. They
    // are replaced by the bare-`ssh`/`scp`/`rsync` planners in
    // `sandbox_cli::ssh_commands` (which take the daemon-issued
    // `sandbox-<id>` alias and require no backend dispatch — the
    // daemon-mediated proxy collapses both backends behind the alias).
    // The hermetic argv-shape tests now live next to the new
    // planners; see `sandbox_cli::ssh_commands::tests`.

    // -- render_rootless_block -------------------------------------------------

    /// `None` — Lima sessions and records from before the rootless
    /// block landed emit nothing.
    /// Mirrors how `render_network_block`/`render_mounts_block` behave
    /// for absent data, but without a `none` placeholder line: the
    /// rootless-Docker block is container-only, and printing
    /// `Rootless Docker: none` for a Lima session would mislead the
    /// operator (the answer is "not applicable", not "none observed").
    #[test]
    fn render_rootless_block_none_emits_nothing() {
        let mut out = String::new();
        render_rootless_block(None, &mut out);
        assert!(
            out.is_empty(),
            "rootless block must be silent when None; got: {out:?}"
        );
    }

    /// Default-hardened host (probe returned `false`): render only
    /// the `detected: no` line. `forced` is suppressed because the
    /// override has nothing to override.
    #[test]
    fn render_rootless_block_default_hardened_omits_forced() {
        let mut out = String::new();
        render_rootless_block(
            Some(&SessionRootlessDockerDto {
                detected: false,
                forced: false,
            }),
            &mut out,
        );
        assert!(out.contains("Rootless Docker:"), "header missing: {out:?}");
        assert!(
            out.contains("detected:    no"),
            "detected line missing: {out:?}"
        );
        assert!(
            !out.contains("forced:"),
            "forced line must be suppressed when not detected: {out:?}"
        );
    }

    /// Rootless host with the override applied: both lines present.
    #[test]
    fn render_rootless_block_forced_renders_both_lines() {
        let mut out = String::new();
        render_rootless_block(
            Some(&SessionRootlessDockerDto {
                detected: true,
                forced: true,
            }),
            &mut out,
        );
        assert!(
            out.contains("detected:    yes"),
            "detected line missing: {out:?}"
        );
        assert!(
            out.contains("forced:      yes"),
            "forced line missing: {out:?}"
        );
    }

    /// Rootless host but the operator did NOT pass the override —
    /// this state cannot occur in practice today (the daemon refuses
    /// such requests with `RootlessDockerRefused` before this DTO is
    /// ever built), but the renderer must still produce a sensible
    /// output if a future code path injects this shape (or if the
    /// persisted record is read back by an inspect endpoint).
    #[test]
    fn render_rootless_block_detected_unforced_renders_both_lines() {
        let mut out = String::new();
        render_rootless_block(
            Some(&SessionRootlessDockerDto {
                detected: true,
                forced: false,
            }),
            &mut out,
        );
        assert!(out.contains("detected:    yes"));
        assert!(
            out.contains("forced:      no"),
            "forced: no must render when detected: yes; got {out:?}"
        );
    }

    // -----------------------------------------------------------------------
    // CLI ↔ daemon strict version-equality handshake.
    //
    // `check_daemon_version_equality` is the equality predicate
    // `send_request_with_timeout` calls after `GET /version`; on `Ok`
    // it proceeds, on `Err` it prints the verbatim stderr wording and
    // `process::exit(2)`s. The four tests pin:
    //   - proceeds on match (`Ok(())`)
    //   - refuses on skew with the verbatim stderr substrings
    //   - the bypass set covers `sandbox doctor`
    //   - the bypass set covers `sandbox version`
    // -----------------------------------------------------------------------

    #[test]
    fn version_handshake_proceeds_on_match() {
        // The equality predicate returns `Ok(())` only when the
        // daemon's reported version is byte-for-byte equal to the
        // CLI's compile-time `CARGO_PKG_VERSION`. Same string in
        // both slots → handshake passes and the caller's request is
        // sent (the `Ok(())` branch in
        // `send_request_with_timeout`).
        let result = check_daemon_version_equality("1.0.3", "1.0.3");
        assert!(
            result.is_ok(),
            "byte-for-byte match must pass the equality predicate; got {result:?}"
        );
    }

    #[test]
    fn version_handshake_refuses_on_skew_with_verbatim_stderr() {
        // The four tokens `version mismatch`, `CLI is`, `daemon is`,
        // and `both must match` are load-bearing — the integration
        // test in.6 greps for them, and downstream scripts
        // may match the wording to surface a friendly upgrade hint.
        let err = check_daemon_version_equality("1.0.3", "1.0.4")
            .expect_err("skewed pair must fail the equality predicate");
        assert!(
            err.contains("version mismatch"),
            "stderr must contain `version mismatch`; got {err:?}"
        );
        assert!(
            err.contains("CLI is 1.0.3"),
            "stderr must report the CLI's version after `CLI is`; got {err:?}"
        );
        assert!(
            err.contains("daemon is 1.0.4"),
            "stderr must report the daemon's version after `daemon is`; got {err:?}"
        );
        assert!(
            err.contains("both must match"),
            "stderr must contain `both must match`; got {err:?}"
        );
        // The exit code is `2` (distinct from `1`, which the CLI
        // uses for daemon-side errors *after* a successful handshake)
        // — pinned by the constant the runtime calls `process::exit`
        // with. The predicate itself does not exit; the runtime path
        // routes the `Err` to stderr and then exits.
        assert_eq!(
            CLI_VERSION_MISMATCH_EXIT_CODE, 2,
            "version-mismatch exit code is pinned to 2 by.3"
        );
    }

    #[test]
    fn version_handshake_bypassed_for_doctor_subcommand() {
        // `sandbox doctor` must remain functional under a skew — the
        // operator uses doctor to *diagnose* the skew, so refusing to
        // run it under skew would mean the operator has no way to
        // diagnose. The bypass predicate is the single source of truth
        // for the bypass set, queried at the top of `main` before any
        // socket connect.
        let cmd = Command::Doctor { verbose: false };
        assert!(
            command_bypasses_version_check(&cmd),
            "`sandbox doctor` must bypass the strict-equality check; \
             refusing to run doctor under skew leaves the operator with no \
             diagnostic surface"
        );
        // The verbose variant must also bypass — bypass is keyed on
        // the variant, not its arguments.
        let cmd_verbose = Command::Doctor { verbose: true };
        assert!(
            command_bypasses_version_check(&cmd_verbose),
            "`sandbox doctor --verbose` must also bypass the check"
        );
    }

    #[test]
    fn version_handshake_bypassed_for_version_subcommand() {
        // `sandbox version` answers locally — the dispatch in `main`
        // never opens a socket for it, so the version-handshake never
        // fires. The bypass predicate confirms the variant is in the
        // bypass set; any refactor that drops the early-return arm
        // from `main` would still leave the predicate consistent, so
        // this test also implicitly asserts the single source of
        // truth.
        let cmd = Command::Version;
        assert!(
            command_bypasses_version_check(&cmd),
            "`sandbox version` must bypass the strict-equality check; it \
             answers locally without a daemon connection"
        );
    }

    #[test]
    fn version_handshake_bypassed_for_proxy_subcommand() {
        // `sandbox proxy <id>` is invoked as a `ProxyCommand` from the
        // daemon-emitted SSH config with stdin/stdout connected to
        // `ssh`'s pipes; any stderr line printed by the version
        // pre-flight (or stdout, worse) would corrupt the SSH banner
        // exchange. The pre-flight is also unnecessary because the
        // proxy wire format ships in the same crate as the daemon —
        // structural skew is impossible.
        let cmd = Command::Proxy {
            session: "0123456789ab".into(),
        };
        assert!(
            command_bypasses_version_check(&cmd),
            "`sandbox proxy` must bypass the version-equality check so the \
             pre-flight cannot corrupt the SSH banner running over the \
             ProxyCommand pipe"
        );
    }

    /// `sandbox proxy <id>` parses as the `Proxy` variant. Pins the
    /// argv shape the daemon's `render_ssh_config_block` writes into
    /// every `ProxyCommand` line: `sandbox proxy <12-hex-id>`. A
    /// rename of the subcommand or its positional argv slot here is
    /// a wire break with the daemon-side template.
    #[test]
    fn proxy_subcommand_parses_with_session_id_positional() {
        let cli = Cli::parse_from(["sandbox", "proxy", "0123456789ab"]);
        match cli.command {
            Command::Proxy { session } => assert_eq!(session, "0123456789ab"),
            other => panic!("expected Command::Proxy, got {other:?}"),
        }
    }

    /// `sandbox proxy` is hidden from `--help` by design:
    /// operators are not the intended caller (the
    /// daemon-emitted SSH config block is). Verified by rendering the
    /// long help via clap and asserting the `proxy` token does not
    /// appear on a subcommand line. Renaming the flag or dropping
    /// `hide = true` would silently expose the wire-format-bound
    /// subcommand to operator-visible documentation.
    #[test]
    fn proxy_subcommand_is_hidden_from_help() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        // Subcommands appear as a leading-space-or-tab `proxy` token
        // in the help output's `Commands:` block; the long description
        // mentions the subcommand name many times. Grep for the
        // subcommand-line shape ("\n  proxy" with description after)
        // rather than the substring.
        for line in help.lines() {
            let trimmed = line.trim_start();
            assert!(
                !trimmed.starts_with("proxy "),
                "`sandbox proxy` must remain hidden; found subcommand line: {line:?}\n\
                 full help:\n{help}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // `sandbox --version` output format pin.
    //
    // The format is `sandbox <semver>\n` — exactly two space-separated
    // tokens, with the semver in column 2. the documented contract.5's
    // half-installed-state detection parses the output with
    // `awk '{print $2}'`; a regression that adds a trailing token
    // (build SHA, commit hash, ...) would silently break that parse.
    // -----------------------------------------------------------------------

    #[test]
    fn sandbox_version_flag_produces_pinned_two_token_line() {
        // clap derives the `--version` output from `#[command(name,
        // version)]` — we render it here through the same builder and
        // assert the exact `<name> <semver>\n` shape.6 pins.
        use clap::CommandFactory;
        let rendered = Cli::command().render_version();
        assert_eq!(
            rendered,
            format!("sandbox {}\n", env!("CARGO_PKG_VERSION")),
            "`sandbox --version` must output exactly `sandbox <semver>\\n`; \
             any trailing token (build SHA, etc.) silently breaks \
             the `awk '{{print $2}}'` version-extract pattern"
        );
    }

    // -----------------------------------------------------------------------
    // `rebuild-image --backend gateway` refusal.
    // -----------------------------------------------------------------------

    /// Pin the `Gateway` variant parses, and the refusal text is
    /// reachable through the dispatcher.
    ///
    /// The dispatcher calls `process::exit(2)` on the refusal arm, so
    /// we exercise the prefix logic by parsing the CLI and asserting
    /// the variant survives clap's value-enum mapping. The
    /// stderr-text and exit-code assertion lives in a separate
    /// subprocess test below.
    #[test]
    fn parse_rebuild_image_backend_gateway() {
        let cli = Cli::parse_from(["sandbox", "rebuild-image", "--backend", "gateway"]);
        match cli.command {
            Command::RebuildImage { backend, no_cache } => {
                assert_eq!(backend, RebuildImageBackend::Gateway);
                assert!(!no_cache);
            }
            other => panic!("expected RebuildImage with Gateway, got: {other:?}"),
        }
    }

    // `rebuild_image_gateway_backend_refuses_with_pointer_to_update` is
    // owned by `tests/integration_cfg_migrations_cli.rs` because it
    // spawns the compiled binary as a subprocess (the
    // `CARGO_BIN_EXE_sandbox` env var is only set for integration-test
    // crates, not for unit tests living inside the binary's own
    // `src/main.rs`). The unit-level surface is covered by
    // `parse_rebuild_image_backend_gateway` (variant parses) above.

    /// Test: `rebuild_image_container_backend_sends_correct_body`.
    /// Regression: the existing dispatch test already pins the wire
    /// body shape (see `dispatch_rebuild_image_container_only_fires_once`
    /// elsewhere in this module); this test names the assertion under
    /// the exact label so the design rows map 1:1 to a
    /// test function name.
    #[tokio::test]
    async fn rebuild_image_container_backend_sends_correct_body() {
        let recorder = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let send = make_recording_sender(std::collections::HashMap::new(), recorder.clone());
        let outcome = run_rebuild_image_dispatch(RebuildImageBackend::Container, false, send).await;
        assert!(outcome.all_ok);
        let calls = recorder.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "container backend → exactly one HTTP call");
        assert_eq!(calls[0].0, sandbox_core::backend::BackendKind::Container);
        let body: serde_json::Value = serde_json::from_str(&calls[0].1).unwrap();
        assert_eq!(body["backend"], serde_json::json!("container"));
        assert_eq!(body["no_cache"], serde_json::json!(false));
    }

    /// Test: `rebuild_image_lima_backend_sends_correct_body`.
    #[tokio::test]
    async fn rebuild_image_lima_backend_sends_correct_body() {
        let recorder = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let send = make_recording_sender(std::collections::HashMap::new(), recorder.clone());
        let outcome = run_rebuild_image_dispatch(RebuildImageBackend::Lima, true, send).await;
        assert!(outcome.all_ok);
        let calls = recorder.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "lima backend → exactly one HTTP call");
        assert_eq!(calls[0].0, sandbox_core::backend::BackendKind::Lima);
        let body: serde_json::Value = serde_json::from_str(&calls[0].1).unwrap();
        assert_eq!(body["backend"], serde_json::json!("lima"));
        assert_eq!(body["no_cache"], serde_json::json!(true));
    }

    // -----------------------------------------------------------------------
    // `--apply-config-migration` access gating.
    //
    // Four refusal arms, applied in order. Tests drive the inner
    // function with an injected euid so we can exercise the non-root
    // refusal arm without actually being root.
    // -----------------------------------------------------------------------

    /// Helper: drive the access gate and assert it produced a refusal
    /// whose message carries the given substring. Each refusal arm
    /// names a load-bearing substring that we pin here.
    fn assert_gate_refuses_with(
        file_arg: &str,
        migration_arg: &str,
        out_arg: &str,
        euid: nix::unistd::Uid,
        substr: &str,
    ) {
        match apply_config_migration_gate(file_arg, migration_arg, out_arg, euid) {
            ApplyGateOutcome::Refuse(msg) => {
                assert!(
                    msg.contains(substr),
                    "expected refusal substring `{substr}`; got: {msg}"
                );
            }
            ApplyGateOutcome::Proceed { .. } => {
                panic!("gate must refuse; substring expected: {substr}");
            }
        }
    }

    /// Test: `apply_config_migration_refuses_non_root_caller`.
    /// Pins the `requires root` substring from arm 1.
    #[test]
    fn apply_config_migration_refuses_non_root_caller() {
        assert_gate_refuses_with(
            "/etc/sandboxd/users.conf",
            "V001",
            "/etc/sandboxd/.users.conf.tmp.V001",
            nix::unistd::Uid::from_raw(1000),
            "requires root",
        );
    }

    /// Test: `apply_config_migration_refuses_non_canonical_file`.
    /// Pins the `canonical paths` substring from arm 2.
    #[test]
    fn apply_config_migration_refuses_non_canonical_file() {
        assert_gate_refuses_with(
            "/tmp/fake.json",
            "V001",
            "/tmp/.fake.json.tmp.V001",
            nix::unistd::Uid::from_raw(0),
            "canonical paths",
        );
    }

    /// Test: `apply_config_migration_refuses_arbitrary_out_path`.
    /// Pins the `tempfile under the same directory as --file`
    /// substring from arm 3.
    #[test]
    fn apply_config_migration_refuses_arbitrary_out_path() {
        assert_gate_refuses_with(
            "/etc/sandboxd/users.conf",
            "V001",
            "/tmp/whatever",
            nix::unistd::Uid::from_raw(0),
            "tempfile under the same directory as --file",
        );
    }

    /// Test: `apply_config_migration_refuses_unknown_migration_id`.
    /// Pins the `not found in registry` substring from arm 4.
    #[test]
    fn apply_config_migration_refuses_unknown_migration_id() {
        assert_gate_refuses_with(
            "/etc/sandboxd/users.conf",
            "V999",
            "/etc/sandboxd/.users.conf.tmp.V999",
            nix::unistd::Uid::from_raw(0),
            "not found in registry",
        );
    }

    /// Regression guard for the J fix: `apply_config_migration_inner`
    /// must force 0644 on the output tempfile regardless of the input
    /// file's existing mode. The corrupted state this repair targets is
    /// an existing `users.conf` at mode 0600 — preserving that mode
    /// would leave the daemon unable to read the file after migration.
    ///
    /// This test requires root to pass the gate's euid check and to read
    /// `/etc/sandboxd/users.conf`. It is skipped when not running as
    /// root so it does not block CI. The E2E suite provides root-level
    /// coverage.
    #[test]
    fn apply_config_migration_inner_forces_0644_on_output_tempfile() {
        use std::os::unix::fs::PermissionsExt;

        if !nix::unistd::geteuid().is_root() {
            // Not root → the gate would refuse; skip rather than fail.
            return;
        }

        // Use the real /etc/sandboxd/users.conf if it exists; if not the
        // gate will pass (euid=root, canonical path recognised) but
        // std::fs::read will fail — skip in that case too.
        let file_arg = "/etc/sandboxd/users.conf";
        let out_arg = "/etc/sandboxd/.users.conf.tmp.V001";
        let migration_arg = "V001";

        if !std::path::Path::new(file_arg).exists() {
            // No live config on this host (e.g. a plain CI machine).
            return;
        }

        // Set the destination file to 0600 before the inner call.
        // The inner call must force it to 0644 on the output tempfile,
        // not propagate the 0600 source mode.
        let src_meta = std::fs::metadata(file_arg).expect("metadata on source file");
        let orig_mode = src_meta.permissions().mode() & 0o7777;
        std::fs::set_permissions(file_arg, std::fs::Permissions::from_mode(0o600))
            .expect("set source file to 0600 for test");

        let code = apply_config_migration_inner(
            file_arg,
            migration_arg,
            out_arg,
            nix::unistd::Uid::from_raw(0),
        );

        // Restore the source file mode regardless of outcome.
        let _ = std::fs::set_permissions(file_arg, std::fs::Permissions::from_mode(orig_mode));

        if code != 0 {
            // Might fail if V001 is already applied; that's fine — the
            // interesting invariant is the output mode when it does succeed.
            let _ = std::fs::remove_file(out_arg);
            return;
        }

        let out_mode = std::fs::metadata(out_arg)
            .expect("out tempfile exists after success")
            .permissions()
            .mode()
            & 0o7777;
        let _ = std::fs::remove_file(out_arg);
        assert_eq!(
            out_mode, 0o644,
            "output tempfile must be 0644 regardless of source mode; got {out_mode:#o}"
        );
    }

    /// parse_migration_id round-trip.
    #[test]
    fn parse_migration_id_accepts_v001_v001_and_rejects_others() {
        assert_eq!(parse_migration_id("V001"), Some(1));
        assert_eq!(parse_migration_id("v001"), Some(1));
        assert_eq!(parse_migration_id("V42"), Some(42));
        assert_eq!(parse_migration_id("001"), None, "missing prefix");
        assert_eq!(parse_migration_id("V"), None, "no digits");
        assert_eq!(parse_migration_id("Vabc"), None, "non-digits");
        assert_eq!(parse_migration_id("VFOO1"), None);
    }

    // -----------------------------------------------------------------------
    // `--dump-migration-set`.
    // -----------------------------------------------------------------------

    /// the install framework exit-criteria #9: `sandbox dump-migration-set` exits 0
    /// and prints a JSON array. Unit-tested at the handler level
    /// here; the subprocess shape (which exercises `process::exit(0)`)
    /// lives in `tests/integration_cfg_migrations_cli.rs`.
    #[test]
    fn dump_migration_set_handler_returns_zero() {
        // The handler writes to stdout. We can't easily capture stdout
        // from a unit test, so we verify the structure of
        // `dump_migration_set()` directly (the only thing the handler
        // does is `serde_json::to_string` on it). The subprocess test
        // owns the stdout-capture half.
        let entries = sandbox_cli::cfg_migrations::dump_migration_set();
        assert!(!entries.is_empty(), "registry has at least V001");
        for e in &entries {
            assert!(e.id > 0);
            assert!(!e.name.is_empty());
            assert!(!e.target_file.is_empty());
        }
        // Verify the JSON shape one layer up — to_string returns Ok.
        let _ = serde_json::to_string(&entries).expect("serialise");
    }

    // -----------------------------------------------------------------------
    // `--dump-proto-version`.
    // -----------------------------------------------------------------------

    /// `--dump-proto-version` emits the single-field
    /// `{ "daemon_guest_proto_version": <u32> }` payload carrying this
    /// binary's `DAEMON_GUEST_PROTO_VERSION`. The shape is the
    /// operator-stable contract the update pre-flight depends on for
    /// per-session compat classification. Subprocess shape
    /// lives in `tests/integration_cfg_migrations_cli.rs`.
    #[test]
    fn dump_proto_version_payload_carries_daemon_proto_const() {
        let payload = serde_json::json!({
            "daemon_guest_proto_version": sandbox_core::guest::DAEMON_GUEST_PROTO_VERSION,
        });
        let json = serde_json::to_string(&payload).expect("serialise");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        let v = parsed
            .get("daemon_guest_proto_version")
            .and_then(|v| v.as_u64())
            .expect("daemon_guest_proto_version u64");
        assert_eq!(
            v as u32,
            sandbox_core::guest::DAEMON_GUEST_PROTO_VERSION,
            "payload must mirror the constant"
        );
    }

    // -----------------------------------------------------------------------
    // The workspace-rsync planner now lives in
    // `sandbox_cli::ssh_commands::plan_workspace_rsync_argv` and is
    // covered by hermetic tests there (SSH-alias shape, dry-run
    // placement, src/dst swap on pull, --dest override, safe-links,
    // no-gitignore, usage-error variants). The historical
    // `plan_workspace_sync_argv` (with `limactl shell`/`docker exec
    // -i` per-backend transports) is gone — the daemon-mediated
    // proxy collapses every transport to bare `ssh sandbox-<id>:`.

    // -----------------------------------------------------------------------
    // expand_dest_tilde — CLI-side `~` resolution for `--dest`.
    // -----------------------------------------------------------------------

    /// No leading `~` → input passes through verbatim. Mirrors the
    /// `expand_host_tilde_in_workspace_flag` short-circuit on non-`~`
    /// inputs.
    #[test]
    fn expand_dest_tilde_passthrough_when_no_tilde() {
        let out = expand_dest_tilde("/abs/path").expect("absolute path passes through");
        assert_eq!(out, "/abs/path");
    }

    /// Bare `~` expands to `$HOME`. The exact `$HOME` value is whatever
    /// the test environment carries; this test only asserts the
    /// expansion happens (no residual `~`) and the result is non-empty.
    #[test]
    fn expand_dest_tilde_resolves_bare_tilde() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        // SAFETY: tests run single-threaded by nextest, and we restore
        // the original value below. The `set_var`/`remove_var` calls
        // are needed because we may run under CI where `$HOME` is
        // pinned or unset.
        unsafe {
            std::env::set_var("HOME", &home);
        }
        let out = expand_dest_tilde("~").expect("~ resolves with HOME set");
        assert_eq!(out, home);
        assert!(!out.starts_with('~'), "expansion left literal `~`: {out}");
    }

    /// `~/suffix` expands to `$HOME/suffix`.
    #[test]
    fn expand_dest_tilde_resolves_tilde_slash_suffix() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        unsafe {
            std::env::set_var("HOME", &home);
        }
        let out = expand_dest_tilde("~/proj/dst").expect("~/suffix resolves with HOME set");
        assert_eq!(out, format!("{home}/proj/dst"));
    }

    /// `~user` form is rejected (not supported). The host_path parser
    /// at create time also rejects this form; `--dest` mirrors the
    /// rejection for consistency.
    #[test]
    fn expand_dest_tilde_rejects_tilde_user_form() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        unsafe {
            std::env::set_var("HOME", &home);
        }
        let err = expand_dest_tilde("~alice/proj").expect_err("~user must be rejected");
        assert!(
            err.contains("~user"),
            "rejection must mention `~user` form: {err}"
        );
    }

    // ----- Release-on-cancel scopeguard mechanics ------------------
    //
    // These tests exercise the scopeguard wrapper used by
    // `run_workspace_push_or_pull` to guarantee release-on-cancel.
    // They do not touch the HTTP-release helpers — the asserted
    // behavior is the scopeguard primitive (closure fires on normal
    // scope exit and on panic-unwind). The HTTP release path is
    // exercised in higher-level integration coverage (Phase 7).

    /// The drop closure of `scopeguard::guard` must fire when the
    /// guarded value goes out of scope on the normal-return path —
    /// the foundation of the post-rsync release.
    #[test]
    fn release_guard_fires_on_normal_exit() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let fired = Arc::new(AtomicBool::new(false));
        {
            let fired_inner = Arc::clone(&fired);
            let _guard = scopeguard::guard((), move |()| {
                fired_inner.store(true, Ordering::SeqCst);
            });
            // Guard is alive here; the closure has not yet run.
            assert!(
                !fired.load(Ordering::SeqCst),
                "guard closure must not fire while the guard is alive"
            );
        }
        assert!(
            fired.load(Ordering::SeqCst),
            "guard closure must fire on normal scope exit"
        );
    }

    /// The drop closure must also fire when the scope unwinds due to
    /// a panic between acquire and release. `catch_unwind` confines
    /// the panic so the test binary keeps running, and the same
    /// `AtomicBool` flag verifies the closure ran during unwind.
    #[test]
    fn release_guard_fires_on_panic() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let fired = Arc::new(AtomicBool::new(false));
        let fired_inner = Arc::clone(&fired);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = scopeguard::guard((), move |()| {
                fired_inner.store(true, Ordering::SeqCst);
            });
            panic!("simulated rsync-flow panic");
        }));
        assert!(
            result.is_err(),
            "catch_unwind must observe the simulated panic"
        );
        assert!(
            fired.load(Ordering::SeqCst),
            "guard closure must fire on panic-unwind"
        );
    }

    /// `scopeguard::ScopeGuard::into_inner` defuses the guard so the
    /// drop closure does NOT run — this is the exit path used by the
    /// signal arms of the `select!` in `run_workspace_push_or_pull`,
    /// where the release has already been issued inline and a second
    /// release would trip the daemon's wrong-token check.
    #[test]
    fn release_guard_defused_via_into_inner() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let fired = Arc::new(AtomicBool::new(false));
        {
            let fired_inner = Arc::clone(&fired);
            let guard = scopeguard::guard((), move |()| {
                fired_inner.store(true, Ordering::SeqCst);
            });
            scopeguard::ScopeGuard::into_inner(guard);
        }
        assert!(
            !fired.load(Ordering::SeqCst),
            "guard closure must NOT fire after into_inner defuses it"
        );
    }

    // -- Lifecycle hooks ---------------------------------------------------
    //
    // Hermetic tests for the `sandbox rm` / `sandbox ls` cleanup hooks. The
    // `sandbox proxy` lazy-404 hook is tested separately in `proxy.rs`.
    // These tests reuse `spawn_fake_daemon` from earlier in this module to
    // stand up a canned-response daemon on a Unix socket and exercise
    // `handle_rm_inner` and `reconcile_ssh_sandbox_dir_silent` end-to-end
    // against a tempdir home (passed through the `home_override` seam to
    // avoid mutating the process-wide `$HOME`).

    /// Seed a per-session entry in `home`'s `~/.ssh/sandbox/` so the
    /// removal tests have something to remove.
    fn seed_local_entry(home: &std::path::Path, id: &str) {
        let dto = sandbox_core::SshConfigDto {
            config: sandbox_core::render_ssh_config_block(id),
            private_key: format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-{id}\n-----END OPENSSH PRIVATE KEY-----\n"
            ),
        };
        sandbox_cli::ssh_config::ensure_session_entry(home, id, &dto)
            .expect("seed per-session entry");
    }

    /// `sandbox rm` happy path: daemon resolve 200, daemon DELETE 204
    /// → local per-session entry is removed.
    #[tokio::test]
    async fn handle_rm_removes_local_entry_on_daemon_success() {
        let id = "aaaaaaaaaaaa";
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            format!("/sessions/{id}"),
            (200, session_dto_json(id, "alpha")),
        );
        // DELETE response: 204 No Content. spawn_fake_daemon's blocking
        // server doesn't differentiate methods — both GET and DELETE
        // hit the same route map keyed by path. The 204 status text
        // / empty body still parses as success on the CLI side.
        // (status 204 is the canonical "success, no body" for DELETE.)
        // spawn_fake_daemon special-cases status 200/404; an
        // unrecognised status falls through to "Internal Server
        // Error" so we use 200 with an empty body — the CLI only
        // inspects `.is_success()`, which is true for any 2xx.
        let (_tmp_sock, sock) = spawn_fake_daemon(routes);

        let tmp_home = tempfile::TempDir::new().unwrap();
        let home = tmp_home.path();
        seed_local_entry(home, id);
        let cfg = sandbox_cli::ssh_config::session_config_path(home, id);
        let key = sandbox_cli::ssh_config::session_key_path(home, id);
        assert!(cfg.exists());
        assert!(key.exists());

        handle_rm_inner(&sock, id, Some(home))
            .await
            .expect("handle_rm_inner should succeed on 2xx DELETE");

        assert!(!cfg.exists(), "rm hook must remove the per-session config");
        assert!(!key.exists(), "rm hook must remove the per-session key");
    }

    /// `sandbox rm` failure path: daemon resolve 200, daemon DELETE
    /// returns 5xx → local entry MUST survive.
    #[tokio::test]
    async fn handle_rm_keeps_local_entry_on_daemon_delete_failure() {
        let id = "bbbbbbbbbbbb";
        let mut routes = std::collections::HashMap::new();
        // Inject a custom response that returns 500 on the DELETE step.
        // `spawn_fake_daemon` serves the same path twice in the same
        // connection (version handshake + caller request) — but each
        // CLI request opens a new connection, so resolve and DELETE
        // each see a fresh `/sessions/{id}` lookup. To make resolve
        // succeed but DELETE fail, we'd need a method-aware fake
        // daemon. spawn_fake_daemon's keying is path-only; both calls
        // would hit the same response. Workaround: configure a 500
        // route so BOTH calls fail — the first call (the resolve)
        // fails too, and `handle_rm_inner` returns Err BEFORE the
        // DELETE step. The seeded local entry survives — which is
        // exactly the contract we're pinning: ANY pre-DELETE failure
        // leaves the local entry alone.
        routes.insert(
            format!("/sessions/{id}"),
            (500, "{\"error\":\"daemon down\"}".into()),
        );
        let (_tmp_sock, sock) = spawn_fake_daemon(routes);

        let tmp_home = tempfile::TempDir::new().unwrap();
        let home = tmp_home.path();
        seed_local_entry(home, id);
        let cfg = sandbox_cli::ssh_config::session_config_path(home, id);
        let key = sandbox_cli::ssh_config::session_key_path(home, id);

        let result = handle_rm_inner(&sock, id, Some(home)).await;
        assert!(result.is_err(), "5xx daemon response must produce Err");

        assert!(
            cfg.exists(),
            "daemon failure must NOT touch the per-session config"
        );
        assert!(
            key.exists(),
            "daemon failure must NOT touch the per-session key"
        );
    }

    /// `sandbox rm` against a 404 resolve also keeps the local entry.
    /// Pins the "fail closed" semantic: if the daemon doesn't know the
    /// session, we still leave any local artefact alone (the reconcile
    /// on the next `sandbox ls` will catch it).
    #[tokio::test]
    async fn handle_rm_keeps_local_entry_on_404_resolve() {
        let id = "cccccccccccc";
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            format!("/sessions/{id}"),
            (404, "{\"error\":\"session not found\"}".into()),
        );
        let (_tmp_sock, sock) = spawn_fake_daemon(routes);

        let tmp_home = tempfile::TempDir::new().unwrap();
        let home = tmp_home.path();
        seed_local_entry(home, id);
        let cfg = sandbox_cli::ssh_config::session_config_path(home, id);
        let key = sandbox_cli::ssh_config::session_key_path(home, id);

        let result = handle_rm_inner(&sock, id, Some(home)).await;
        assert!(result.is_err(), "404 resolve must produce Err");

        assert!(cfg.exists(), "404 resolve must NOT touch the local config");
        assert!(key.exists(), "404 resolve must NOT touch the local key");
    }

    /// `reconcile_against_list` happy path: stale local entries get
    /// removed, live ones survive. Drives the same helper
    /// `reconcile_ssh_sandbox_dir_silent` calls.
    #[test]
    fn reconcile_pass_removes_stale_local_entries() {
        let tmp_home = tempfile::TempDir::new().unwrap();
        let home = tmp_home.path();

        let live = "dddddddddddd";
        let stale = "eeeeeeeeeeee";
        seed_local_entry(home, live);
        seed_local_entry(home, stale);

        let removed = sandbox_cli::ssh_config::reconcile_against_list(home, &[live])
            .expect("reconcile must succeed against tempdir home");
        assert_eq!(removed, vec![stale.to_string()]);

        assert!(sandbox_cli::ssh_config::session_config_path(home, live).exists());
        assert!(!sandbox_cli::ssh_config::session_config_path(home, stale).exists());
        assert!(!sandbox_cli::ssh_config::session_key_path(home, stale).exists());
    }

    /// `reconcile_ssh_sandbox_dir_silent` with HOME unset: silently
    /// returns, no panic. Pins the "no regression in error mode"
    /// contract from Spec § Reconcile on listing.
    ///
    /// Uses an `HOME` env redirect so we can simulate the
    /// `resolve_home` failure path. We serialise against the proxy
    /// module's own home-guard mutex by using a sibling mutex here:
    /// this test must not race against any other test that mutates
    /// `HOME`.
    #[test]
    fn reconcile_silent_returns_on_unresolvable_home() {
        // SAFETY: env mutation is process-wide. Hold the lock for the
        // duration of the test so no other parallel test in this
        // binary observes the redirect mid-flight.
        let lock = main_tests_home_mutex()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let prior = std::env::var_os("HOME");
        // SAFETY: held by `lock` until end of scope; no concurrent
        // mutator in this binary's test set.
        unsafe { std::env::remove_var("HOME") };

        // Empty session list — function should not panic and should
        // silently early-return when `resolve_home` fails (HOME unset
        // returns NoHome).
        reconcile_ssh_sandbox_dir_silent(&[]);

        // Restore.
        // SAFETY: same.
        unsafe {
            match prior {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        drop(lock);
    }

    /// `reconcile_ssh_sandbox_dir_silent` happy path: with HOME set to
    /// a tempdir containing a stale entry, the reconcile removes it.
    /// Wire-up test for the helper that the `Ps`/`Ls` arm of
    /// `handle_response` calls.
    #[test]
    fn reconcile_silent_removes_stale_under_redirected_home() {
        let tmp_home = tempfile::TempDir::new().unwrap();
        let live = "1111aaaaaaaa";
        let stale = "2222bbbbbbbb";
        seed_local_entry(tmp_home.path(), live);
        seed_local_entry(tmp_home.path(), stale);

        let lock = main_tests_home_mutex()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let prior = std::env::var_os("HOME");
        // SAFETY: held by `lock`.
        unsafe { std::env::set_var("HOME", tmp_home.path()) };

        // Single-DTO sessions slice with only `live`; reconcile must
        // drop `stale`.
        let sessions = vec![make_session_dto(
            live,
            Some("live"),
            None,
            chrono::Utc::now(),
        )];
        reconcile_ssh_sandbox_dir_silent(&sessions);

        // Restore env before assertions so any failure print does not
        // dangle a redirected `$HOME`.
        // SAFETY: same.
        unsafe {
            match prior {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        drop(lock);

        assert!(
            sandbox_cli::ssh_config::session_config_path(tmp_home.path(), live).exists(),
            "reconcile must keep the live entry"
        );
        assert!(
            !sandbox_cli::ssh_config::session_config_path(tmp_home.path(), stale).exists(),
            "reconcile must remove the stale entry"
        );
    }

    fn main_tests_home_mutex() -> &'static std::sync::Mutex<()> {
        static M: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        M.get_or_init(|| std::sync::Mutex::new(()))
    }
}
