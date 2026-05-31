//! SSH-shaped command machinery for `sandbox ssh`, `sandbox cp`,
//! `sandbox sync`, and `sandbox workspace push|pull`.
//!
//! This module owns:
//!
//! 1. **Pure argv planners** ([`plan_ssh_argv`], [`plan_scp_argv`],
//!    [`plan_sync_argv`], [`plan_workspace_rsync_argv`]) — given the
//!    daemon-issued `sandbox-<id>` alias plus the operator's source/
//!    destination paths, return the `(program, args)` tuple to spawn.
//!    They are pure functions: no I/O, no environment access, no
//!    spawning. Every command translates "operator-facing CLI flags"
//!    into "argv for `ssh`/`scp`/`rsync` against `sandbox-<id>`" through
//!    one of these.
//!
//! 2. **The single-retry drift-recovery wrapper**
//!    ([`run_with_drift_recovery`]) — implements Spec §
//!    Architecture → CLI: persistent ssh-config → Key drift recovery:
//!    on a child SSH-tool process exiting non-zero with `Permission
//!    denied (publickey)` in its stderr, re-fetch the SSH config from
//!    the daemon, overwrite the per-session entry, and re-spawn the
//!    underlying tool **once**. A second failure propagates the error
//!    so the wrapper never loops.
//!
//!    The wrapper is matched **only at the outermost CLI dispatch**
//!    (`sandbox ssh`/`cp`/`sync`/`workspace`). It is **never** invoked
//!    from `sandbox proxy` — that subcommand is the `ProxyCommand` shim
//!    invoked recursively from `~/.ssh/config`, and wrapping it would
//!    stack retries (each outer command would already retry, plus the
//!    inner proxy too) per Spec § Key drift recovery: "never inside
//!    `sandbox proxy`, so nested invocations from `git-remote-sandbox`
//!    cannot stack retries".
//!
//! 3. **The locale-pinned stderr substring sniffer**
//!    ([`looks_like_publickey_drift`]) — the substring `Permission
//!    denied (publickey)` is matched against the spawned tool's
//!    stderr. `LC_ALL=C` + `LANG=C` are injected into the child env so
//!    the substring is stable across operator locales.

use std::ffi::OsStr;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use sandbox_core::backend::BackendKind;
use sandbox_core::{
    Direction as CoreDirection, SSH_TRANSPORT_TOKEN, SshConfigDto, WorkspaceRsyncOptions,
    build_workspace_rsync_argv,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::ssh_config;

// ---------------------------------------------------------------------------
// Direction of a remote ↔ local transfer
// ---------------------------------------------------------------------------

/// Which side of an `scp`/`rsync` operation is the remote endpoint.
/// Mirrors the existing `TransferDirection` enum used by the
/// pre-rewrite `handle_cp` / `handle_sync` — kept module-local so the
/// rewrite is hermetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    /// Local source → remote destination.
    Upload,
    /// Remote source → local destination.
    Download,
}

// ---------------------------------------------------------------------------
// Pure argv planners
// ---------------------------------------------------------------------------

/// Plan `ssh sandbox-<id> [-- cmd …]`.
///
/// The argv begins with the alias (which the operator's `~/.ssh/config`
/// — via our managed `Include` block — resolves to the full per-session
/// `Host sandbox-<id>` stanza including `ProxyCommand sandbox proxy
/// <id>` and the `IdentityFile` line we rewrote). When `command` is
/// non-empty the CLI inserts a literal `--` separator so the trailing
/// tokens are unambiguously the remote command (preserves operator
/// flags like `-l`/`-v` that would otherwise be interpreted by `ssh`).
///
/// No backend dispatch: the daemon-mediated proxy hides the backend
/// distinction from the SSH client.
pub fn plan_ssh_argv(alias: &str, command: &[String]) -> (String, Vec<String>) {
    let mut args: Vec<String> = Vec::with_capacity(2 + command.len());
    args.push(alias.to_string());
    if !command.is_empty() {
        args.push("--".to_string());
        args.extend(command.iter().cloned());
    }
    ("ssh".to_string(), args)
}

/// Plan `scp [-r] <src> <dst>` against the `sandbox-<id>` alias.
///
/// `source_is_dir` controls whether `-r` is appended. The caller stats
/// the local source on Upload; on Download we conservatively assume
/// `false` (a remote-stat round-trip would slow the happy path; the
/// operator wanting directory download falls through to `sandbox
/// sync` per the existing CLI guidance).
pub fn plan_scp_argv(
    alias: &str,
    host_path: &str,
    remote_path: &str,
    direction: TransferDirection,
    source_is_dir: bool,
) -> (String, Vec<String>) {
    let remote_arg = format!("{alias}:{remote_path}");
    let (src_arg, dst_arg) = match direction {
        TransferDirection::Upload => (host_path.to_string(), remote_arg),
        TransferDirection::Download => (remote_arg, host_path.to_string()),
    };
    let mut args: Vec<String> = Vec::with_capacity(3);
    if source_is_dir {
        // `scp -r` recurses into directories. Required for directory
        // uploads; harmless on Download (we always pass `false`
        // there).
        args.push("-r".to_string());
    }
    args.push(src_arg);
    args.push(dst_arg);
    ("scp".to_string(), args)
}

/// Plan `rsync -a --delete -e ssh [extras…] <src> <dst>` for `sandbox
/// sync`.
///
/// `extra_args` is spliced between the baseline (`-a --delete -e ssh`)
/// and the source/destination operands so operator-supplied flags
/// (`--exclude`, `--bwlimit`, `--info=progress2`, etc.) land in a
/// position rsync accepts. The shell transport is bare `ssh` — the
/// operator's `ssh` client picks up the per-session config block via
/// our managed `Include`.
///
/// Trailing-slash auto-append: on Upload, when `source_is_dir` and the
/// host path does not already end with `/`, append one so rsync
/// mirrors *contents* rather than nesting the directory itself. Pull
/// path is unchanged — the host has no way to remote-stat without an
/// extra round-trip; operators wanting contents-mirroring on pull
/// supply the trailing slash explicitly in the remote path.
pub fn plan_sync_argv(
    alias: &str,
    host_path: &str,
    remote_path: &str,
    direction: TransferDirection,
    extra_args: &[String],
    source_is_dir: bool,
) -> (String, Vec<String>) {
    let host_arg = if matches!(direction, TransferDirection::Upload)
        && source_is_dir
        && !host_path.ends_with('/')
    {
        format!("{host_path}/")
    } else {
        host_path.to_string()
    };
    let remote_arg = format!("{alias}:{remote_path}");
    let (src_arg, dst_arg) = match direction {
        TransferDirection::Upload => (host_arg, remote_arg),
        TransferDirection::Download => (remote_arg, host_arg),
    };
    let mut args: Vec<String> = vec![
        "-a".to_string(),
        "--delete".to_string(),
        "-e".to_string(),
        "ssh".to_string(),
    ];
    args.extend(extra_args.iter().cloned());
    args.push(src_arg);
    args.push(dst_arg);
    ("rsync".to_string(), args)
}

/// Operator-supplied inputs for the workspace push/pull planner. The
/// fields mirror the pre-rewrite `WorkspaceSyncPlan` but drop the
/// `backend` field (no backend dispatch on the SSH-alias path) and
/// take the alias explicitly instead.
#[derive(Debug, Clone)]
pub struct WorkspaceRsyncPlan<'a> {
    pub alias: &'a str,
    pub host_path: String,
    pub guest_path: String,
    pub direction: WorkspaceDirection,
    pub dest_override: Option<String>,
    pub force: bool,
    pub dry_run: bool,
    pub safe_links: bool,
    pub no_gitignore: bool,
}

/// Push vs pull for `sandbox workspace`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceDirection {
    Push,
    Pull,
}

/// Plan `rsync -aL --delete --filter=:- .gitignore -e ssh [--dry-run]
/// <src> <dst>` for `sandbox workspace push|pull`.
///
/// Output shape:
///
/// ```text
/// rsync [-aL | -a --safe-links] --delete [--filter=:- .gitignore]
///   -e ssh [--dry-run] <src> <dst>
/// ```
///
/// `<src>`/`<dst>` always carry a trailing `/`. Push: host → guest.
/// Pull: guest → host (with `dest_override` swapping in for the host
/// path when supplied).
///
/// Returns argv with `"rsync"` as `argv[0]` so the call site can pass
/// `argv[1..]` to `Command::args`. Argv construction is delegated to
/// [`sandbox_core::build_workspace_rsync_argv`] with
/// `custom_transport = Some("ssh")` (the SSH-alias path); this
/// function owns the CLI-specific gates (`force`/`dry_run` mutex,
/// `dest_override` resolution) that sit above the pure argv builder.
pub fn plan_workspace_rsync_argv(plan: &WorkspaceRsyncPlan) -> Result<Vec<String>, String> {
    // Exactly one of `force` / `dry_run` must be set. Clap's
    // `conflicts_with` already catches both-set; the neither-set case
    // falls through to here.
    match (plan.force, plan.dry_run) {
        (false, false) => {
            return Err("one of `-f`/`--force` or `-n`/`--dry-run` is required".to_string());
        }
        (true, true) => {
            return Err("`-f`/`--force` and `-n`/`--dry-run` are mutually exclusive".to_string());
        }
        _ => {}
    }

    // `dest_override` is a CLI-level concept: on a Pull, the operator
    // can redirect the host destination to a different path.  Resolve
    // it here before handing off to the core builder.
    let host_path = match (plan.direction, plan.dest_override.as_deref()) {
        (WorkspaceDirection::Pull, Some(dest)) => dest.to_string(),
        _ => plan.host_path.clone(),
    };

    let core_direction = match plan.direction {
        WorkspaceDirection::Push => CoreDirection::Push,
        WorkspaceDirection::Pull => CoreDirection::Pull,
    };

    // The CLI uses the SSH-alias transport (`-e ssh`); `custom_transport`
    // overrides the backend-derived default in the core builder.
    // `BackendKind` does not affect the argv when `custom_transport` is
    // set, so `Lima` is used as a harmless placeholder.
    let core_opts = WorkspaceRsyncOptions {
        backend: BackendKind::Lima,
        custom_transport: Some(SSH_TRANSPORT_TOKEN.to_string()),
        session_name: plan.alias.to_string(),
        host_path,
        guest_path: plan.guest_path.clone(),
        direction: core_direction,
        no_gitignore: plan.no_gitignore,
        dry_run: plan.dry_run,
        safe_links: plan.safe_links,
        // Operator-driven push/pull does not use `--mkpath`; the
        // destination already exists (the session is running).
        mkpath: false,
    };

    // The core builder returns argv WITHOUT the leading `"rsync"` program
    // name.  Prepend it here to match the historical convention this
    // function established (call sites pass `argv[1..]` to
    // `Command::args`, keeping `argv[0]` as the program name for
    // diagnostic output).
    let mut argv = vec!["rsync".to_string()];
    argv.extend(build_workspace_rsync_argv(&core_opts));
    Ok(argv)
}

// ---------------------------------------------------------------------------
// Stderr sniffer
// ---------------------------------------------------------------------------

/// Stable substring that OpenSSH (and `scp`/`rsync -e ssh`) emit on a
/// public-key authentication failure under `LC_ALL=C`/`LANG=C`. The
/// exact spelling is pinned by openssh-portable's `sshconnect2.c`.
const PUBKEY_DRIFT_SUBSTR: &[u8] = b"Permission denied (publickey)";

/// Return `true` when `stderr` contains the locale-pinned "Permission
/// denied (publickey)" substring — the signal Spec § Key drift
/// recovery matches on to decide whether the local SSH config is
/// stale relative to the daemon's session-side key.
///
/// We match raw bytes (not UTF-8) because `ssh`'s stderr is binary-
/// noise tolerant; substring search in `&[u8]` is allocation-free.
pub fn looks_like_publickey_drift(stderr: &[u8]) -> bool {
    stderr_contains(stderr, PUBKEY_DRIFT_SUBSTR)
}

/// Subslice search over `&[u8]`. The needle is short (~30 bytes) and
/// the haystack is bounded by how much stderr the spawned tool emits
/// before exit, so a naive `windows` scan is fine.
fn stderr_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Drift-recovery wrapper
// ---------------------------------------------------------------------------

/// Failure surfaced by [`run_with_drift_recovery`]. Distinct from a
/// non-zero exit of the spawned tool (which is propagated as
/// `Ok(exit_code)`): this is for setup-time errors before/between
/// spawns.
#[derive(Debug, thiserror::Error)]
pub enum DriftRecoveryError {
    /// The daemon returned an error from `GET /sessions/{id}/ssh-config`.
    /// The message is rendered for the operator already (includes the
    /// HTTP status and the body if the daemon emitted one).
    #[error("{0}")]
    FetchDto(String),
    /// Writing the per-session entry under `~/.ssh/sandbox/` failed.
    #[error("ssh-config setup: {0}")]
    EntrySetup(#[from] ssh_config::SshConfigError),
    /// Spawning the underlying SSH-tool process failed (binary not on
    /// `$PATH`, etc.).
    #[error("failed to execute {program}: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
}

/// Outcome of a single child-process attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// Tool exited with a status code (zero or non-zero).
    Exited(i32),
    /// Tool exited non-zero with a stderr matching
    /// `Permission denied (publickey)` — caller may retry.
    PublickeyDrift,
}

/// Drive the outermost CLI dispatch under the single-retry drift-
/// recovery contract. Generic over the DTO-fetch callback and the
/// spawn-and-wait callback so the loop is hermetically testable
/// without a real daemon or `ssh` process.
///
/// **Invocation order:**
///
/// 1. Call `fetch_dto()` to obtain the per-session SSH config and key.
/// 2. Call `ssh_config::ensure_session_entry(home, id, &dto)` to write
///    the entry under `~/.ssh/sandbox/`.
/// 3. Call `run_attempt(alias, attempt_idx)` to spawn the underlying
///    SSH-tool process, tee its stderr to the parent's stderr, and
///    return [`AttemptOutcome`].
/// 4. If the outcome is `Exited(_)`: propagate the exit code. If it is
///    `PublickeyDrift` and `attempt_idx == 0`: loop to step (1). On
///    `attempt_idx == 1`: propagate the exit code anyway — the spec
///    pins a single retry.
///
/// The wrapper enforces the single-retry budget at this level — the
/// caller must NOT itself retry on `Ok(non-zero)`. Calling sites are
/// `handle_ssh`, `handle_cp`, `handle_sync`,
/// `run_workspace_push_or_pull`; the proxy shim
/// (`sandbox_cli::proxy::run`) is deliberately **not** wrapped.
pub async fn run_with_drift_recovery<F, Fut, G, GFut>(
    home: &Path,
    id: &str,
    mut fetch_dto: F,
    mut run_attempt: G,
) -> Result<i32, DriftRecoveryError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<SshConfigDto, DriftRecoveryError>>,
    G: FnMut(String, usize) -> GFut,
    GFut: Future<Output = Result<AttemptOutcome, DriftRecoveryError>>,
{
    // Spec § Architecture → CLI: persistent ssh-config → Key drift
    // recovery: "Single retry only — a second failure propagates the
    // error to the operator so we never loop."
    const MAX_ATTEMPTS: usize = 2;

    for attempt_idx in 0..MAX_ATTEMPTS {
        let dto = fetch_dto().await?;
        let alias = ssh_config::ensure_session_entry(home, id, &dto)?;

        match run_attempt(alias, attempt_idx).await? {
            AttemptOutcome::Exited(code) => return Ok(code),
            AttemptOutcome::PublickeyDrift => {
                if attempt_idx + 1 == MAX_ATTEMPTS {
                    // Spec: "a second failure propagates the error to
                    // the operator so we never loop". The pubkey-drift
                    // signal on the final attempt has already been
                    // teed to the operator's stderr by the spawn-and-
                    // wait callback; we just propagate the standard
                    // SSH-style exit code (255 — the standard SSH/scp
                    // "fatal error" code).
                    return Ok(ssh_failure_exit_code());
                }
                // Continue to the next iteration: re-fetch and re-spawn.
            }
        }
    }
    // Unreachable: the loop body always returns or continues, and the
    // final continue is intercepted by the `attempt_idx + 1 ==
    // MAX_ATTEMPTS` branch above. Keep the explicit fall-through for
    // clippy / future-proofing.
    Ok(ssh_failure_exit_code())
}

/// Conventional SSH/scp "fatal error" exit code (`255`). Used when
/// we exhaust the single retry budget without a successful spawn-and-
/// wait — keeps the operator's experience aligned with what `ssh`
/// would have emitted on its own.
pub fn ssh_failure_exit_code() -> i32 {
    255
}

// ---------------------------------------------------------------------------
// Spawn helper — used by every outermost CLI dispatch
// ---------------------------------------------------------------------------

/// Spawn `program` with `args`, inherit the parent's stdin and
/// stdout, pipe stderr (so the wrapper can sniff for `Permission
/// denied (publickey)`), and inject `LC_ALL=C` + `LANG=C` into the
/// child environment so the stderr substring match is locale-stable.
///
/// While the child runs, stderr bytes are forwarded to the parent's
/// stderr (tee'd) so the operator sees them live, while also being
/// accumulated into an in-memory buffer the wrapper inspects after
/// child exit. On exit:
///
/// * code 0 / any non-zero without the pubkey-drift substring →
///   [`AttemptOutcome::Exited(code)`].
/// * non-zero with the substring →
///   [`AttemptOutcome::PublickeyDrift`].
///
/// `extra_env` lets the caller append further environment variables
/// (e.g. `SANDBOX_SOCKET` so the `sandbox proxy` shim invoked via
/// `ProxyCommand` reaches the same daemon socket the parent CLI is
/// talking to). Each entry is `(name, value)`.
pub async fn spawn_ssh_tool_attempt<I, K, V>(
    program: &str,
    args: &[String],
    extra_env: I,
) -> Result<AttemptOutcome, DriftRecoveryError>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        // Belt-and-suspenders: kill the child if the future is
        // dropped before `wait()` resolves (panic, surrounding
        // `tokio::select!` cancellation, etc.).
        .kill_on_drop(true);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().map_err(|e| DriftRecoveryError::Spawn {
        program: program.to_string(),
        source: e,
    })?;

    // Pipe-tee stderr: forward bytes to the parent's stderr in real
    // time AND accumulate into an in-memory buffer so the wrapper can
    // inspect the bytes for the pubkey-drift signal after child exit.
    let stderr = child
        .stderr
        .take()
        .expect("child stderr is piped by Command builder above");
    let tee_handle = tokio::spawn(tee_stderr(stderr));

    let status = child.wait().await.map_err(|e| DriftRecoveryError::Spawn {
        program: program.to_string(),
        source: e,
    })?;

    // Await the tee task so we own the captured bytes before deciding
    // on the outcome. If the tee task itself panicked we treat the
    // attempt as a generic non-zero exit (we already inherited
    // stderr into the parent, so the operator saw the error message
    // anyway).
    let stderr_bytes: Vec<u8> = tee_handle.await.unwrap_or_default();

    let code = status.code().unwrap_or_else(ssh_failure_exit_code);
    if code != 0 && looks_like_publickey_drift(&stderr_bytes) {
        Ok(AttemptOutcome::PublickeyDrift)
    } else {
        Ok(AttemptOutcome::Exited(code))
    }
}

/// Tee task body: read stderr line-by-line from the child, write
/// every chunk to the parent's stderr, and accumulate a copy of the
/// bytes for post-exit inspection. Returns the accumulated bytes.
async fn tee_stderr<R: tokio::io::AsyncRead + Unpin>(mut reader: R) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                // Best-effort tee: writing to parent stderr can only
                // fail if the parent's stderr is itself closed
                // (rare), in which case we still want to keep
                // accumulating so the wrapper can still detect the
                // drift signal. Use a fresh handle each iteration so
                // we do not hold the global stderr lock across awaits.
                let mut parent_stderr = tokio::io::stderr();
                let _ = parent_stderr.write_all(&chunk[..n]).await;
                let _ = parent_stderr.flush().await;
            }
            Err(_) => break,
        }
    }
    buf
}

// ---------------------------------------------------------------------------
// DTO fetch helper — small wrapper around `GET /sessions/{id}/ssh-config`
// ---------------------------------------------------------------------------

/// Fetch a fresh [`SshConfigDto`] for `id` from the daemon at
/// `socket_path`. Used by every dispatch site as the `fetch_dto`
/// callback into [`run_with_drift_recovery`].
///
/// The implementation lives in `main.rs` because the HTTP client
/// (`send_request`) does too; this is a typed pointer wrapping that
/// call site. Kept here so the wrapper signature reads close to
/// where the planners are defined.
pub fn build_ssh_config_request(id: &str) -> hyper::Request<String> {
    hyper::Request::builder()
        .method("GET")
        .uri(format!("/sessions/{id}/ssh-config"))
        .body(String::new())
        .expect("static request build cannot fail")
}

/// Translate an HTTP response from `GET /sessions/{id}/ssh-config`
/// into either a parsed DTO or an operator-facing error message.
/// Pure helper so the dispatch sites stay terse.
///
/// On a 404 with a typed `code: "SSH_NOT_AVAILABLE"` field, the
/// daemon is signalling a pre-V007 container session — the CLI
/// surfaces the operator-actionable "recreate the session"
/// remediation. We match on the typed `code` field rather than the
/// `error` string so a daemon-side rewording of the message text
/// does not silently break the boundary.
pub fn parse_ssh_config_response(
    status: hyper::StatusCode,
    body: &str,
    socket_path: &Path,
    id: &str,
) -> Result<SshConfigDto, DriftRecoveryError> {
    if status.is_success() {
        return serde_json::from_str(body)
            .map_err(|e| DriftRecoveryError::FetchDto(format!("parse ssh-config response: {e}")));
    }
    let api_err = serde_json::from_str::<sandbox_core::ApiError>(body).ok();
    let typed_code = api_err.as_ref().and_then(|e| e.code.as_deref());
    let detail = api_err
        .as_ref()
        .map(|e| e.error.clone())
        .unwrap_or_else(|| format!("HTTP {status}: {body}"));
    if status == hyper::StatusCode::NOT_FOUND && typed_code == Some("SSH_NOT_AVAILABLE") {
        return Err(DriftRecoveryError::FetchDto(format!(
            "GET /sessions/{id}/ssh-config (via {socket}): session pre-dates the \
             per-session SSH keypair; recreate the session to enable cross-user SSH \
             access (`sandbox rm {id} && sandbox create ...`). Daemon detail: {detail}",
            socket = socket_path.display(),
        )));
    }
    Err(DriftRecoveryError::FetchDto(format!(
        "GET /sessions/{id}/ssh-config (via {socket}) failed: {detail}",
        socket = socket_path.display(),
    )))
}

/// Resolve `$HOME` for the dispatch sites. Wraps
/// `ssh_config::resolve_home` so callers see a single namespace for
/// the SSH-command machinery.
pub fn resolve_home() -> Result<PathBuf, ssh_config::SshConfigError> {
    ssh_config::resolve_home()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn alias() -> String {
        ssh_config::ssh_alias_for("0123456789ab")
    }

    // -----------------------------------------------------------------------
    // plan_ssh_argv
    // -----------------------------------------------------------------------

    #[test]
    fn ssh_argv_interactive_emits_just_alias() {
        let (program, args) = plan_ssh_argv(&alias(), &[]);
        assert_eq!(program, "ssh");
        assert_eq!(args, vec!["sandbox-0123456789ab".to_string()]);
    }

    #[test]
    fn ssh_argv_with_command_uses_double_dash_separator() {
        let cmd = vec!["uname".to_string(), "-a".to_string()];
        let (program, args) = plan_ssh_argv(&alias(), &cmd);
        assert_eq!(program, "ssh");
        assert_eq!(
            args,
            vec![
                "sandbox-0123456789ab".to_string(),
                "--".to_string(),
                "uname".to_string(),
                "-a".to_string(),
            ]
        );
    }

    #[test]
    fn ssh_argv_does_not_carry_backend_specific_tokens() {
        // The whole point of the rewrite is that there is no
        // `limactl`/`docker exec` dispatch any more — the operator's
        // SSH client reaches a single daemon-mediated endpoint via
        // the `Host sandbox-<id>` config block. Pin that the
        // *program* is `ssh` and the *first positional argument* is
        // the alias — a refactor that inserted a backend-specific
        // wrapper (e.g. `limactl shell` between the program and the
        // alias) would shift the positional, failing this assertion
        // shape without false positives on operator-supplied
        // arguments that happen to contain substrings like `exec`.
        let (program, args) = plan_ssh_argv(&alias(), &[]);
        assert_eq!(program, "ssh", "SSH planner must shell out to bare `ssh`");
        assert_eq!(
            args.first().map(String::as_str),
            Some(alias().as_str()),
            "first positional argument must be the alias; got: {args:?}",
        );
        // The whole-list "no backend-specific tokens" check stays —
        // it catches a regression that pre-pended `--remote-shell`
        // or similar — but is now scoped to argv slots before the
        // `--` separator (where the operator's user-supplied
        // command begins).
        let pre_separator: Vec<&String> = args.iter().take_while(|a| a.as_str() != "--").collect();
        for arg in pre_separator {
            assert!(
                !arg.contains("limactl"),
                "no limactl token in pre-separator argv: {args:?}",
            );
            assert!(
                !arg.contains("docker"),
                "no docker token in pre-separator argv: {args:?}",
            );
        }
    }

    // -----------------------------------------------------------------------
    // plan_scp_argv
    // -----------------------------------------------------------------------

    #[test]
    fn scp_argv_upload_file_no_recurse() {
        let (program, args) = plan_scp_argv(
            &alias(),
            "/local/file",
            "/remote/path",
            TransferDirection::Upload,
            false,
        );
        assert_eq!(program, "scp");
        assert_eq!(
            args,
            vec![
                "/local/file".to_string(),
                "sandbox-0123456789ab:/remote/path".to_string(),
            ]
        );
    }

    #[test]
    fn scp_argv_upload_directory_uses_dash_r() {
        let (program, args) = plan_scp_argv(
            &alias(),
            "/local/dir",
            "/remote/path",
            TransferDirection::Upload,
            true,
        );
        assert_eq!(program, "scp");
        assert_eq!(
            args,
            vec![
                "-r".to_string(),
                "/local/dir".to_string(),
                "sandbox-0123456789ab:/remote/path".to_string(),
            ]
        );
    }

    #[test]
    fn scp_argv_download_swaps_src_and_dst() {
        let (program, args) = plan_scp_argv(
            &alias(),
            "/local/file",
            "/remote/path",
            TransferDirection::Download,
            false,
        );
        assert_eq!(program, "scp");
        assert_eq!(
            args,
            vec![
                "sandbox-0123456789ab:/remote/path".to_string(),
                "/local/file".to_string(),
            ]
        );
    }

    // -----------------------------------------------------------------------
    // plan_sync_argv
    // -----------------------------------------------------------------------

    #[test]
    fn sync_argv_upload_directory_appends_trailing_slash() {
        let (program, args) = plan_sync_argv(
            &alias(),
            "/local/dir",
            "/remote/dir",
            TransferDirection::Upload,
            &[],
            true,
        );
        assert_eq!(program, "rsync");
        assert_eq!(
            args,
            vec![
                "-a".to_string(),
                "--delete".to_string(),
                "-e".to_string(),
                "ssh".to_string(),
                "/local/dir/".to_string(),
                "sandbox-0123456789ab:/remote/dir".to_string(),
            ]
        );
    }

    #[test]
    fn sync_argv_upload_file_does_not_add_slash() {
        let (_program, args) = plan_sync_argv(
            &alias(),
            "/local/file",
            "/remote/file",
            TransferDirection::Upload,
            &[],
            false,
        );
        // No trailing slash on a file source.
        assert_eq!(
            args.last().map(String::as_str),
            Some("sandbox-0123456789ab:/remote/file")
        );
        assert!(args.iter().any(|a| a == "/local/file"));
    }

    #[test]
    fn sync_argv_download_does_not_modify_remote_path() {
        let (_program, args) = plan_sync_argv(
            &alias(),
            "/local/dir",
            "/remote/dir",
            TransferDirection::Download,
            &[],
            false,
        );
        // dst is `/local/dir` (no slash auto-appended on Download),
        // src is the remote spec.
        assert_eq!(args.last().map(String::as_str), Some("/local/dir"));
        assert_eq!(
            args.iter().rev().nth(1).map(String::as_str),
            Some("sandbox-0123456789ab:/remote/dir")
        );
    }

    #[test]
    fn sync_argv_splices_extra_args_between_baseline_and_operands() {
        let extras = vec![
            "--exclude".to_string(),
            "*.log".to_string(),
            "--bwlimit=1m".to_string(),
        ];
        let (_program, args) = plan_sync_argv(
            &alias(),
            "/src",
            "/dst",
            TransferDirection::Upload,
            &extras,
            false,
        );
        // Baseline followed by extras followed by operands.
        let baseline_end = args
            .iter()
            .position(|a| a == "ssh")
            .expect("baseline `-e ssh` must appear");
        let exclude_idx = args
            .iter()
            .position(|a| a == "--exclude")
            .expect("extras must appear");
        let src_idx = args.len() - 2;
        assert!(baseline_end < exclude_idx);
        assert!(exclude_idx < src_idx);
    }

    #[test]
    fn sync_argv_uses_bare_ssh_transport_not_limactl_or_docker() {
        let (_program, args) = plan_sync_argv(
            &alias(),
            "/src",
            "/dst",
            TransferDirection::Upload,
            &[],
            false,
        );
        // `-e ssh` (not `limactl shell` / `docker exec -i`).
        let e_idx = args.iter().position(|a| a == "-e").expect("-e present");
        assert_eq!(args.get(e_idx + 1).map(String::as_str), Some("ssh"));
    }

    // -----------------------------------------------------------------------
    // plan_workspace_rsync_argv
    // -----------------------------------------------------------------------

    fn workspace_plan_baseline(
        direction: WorkspaceDirection,
        force: bool,
        dry_run: bool,
    ) -> WorkspaceRsyncPlan<'static> {
        WorkspaceRsyncPlan {
            alias: "sandbox-abcdef012345",
            host_path: "/host/path".to_string(),
            guest_path: "/guest/path".to_string(),
            direction,
            dest_override: None,
            force,
            dry_run,
            safe_links: false,
            no_gitignore: false,
        }
    }

    #[test]
    fn workspace_argv_push_force_baseline() {
        let plan = workspace_plan_baseline(WorkspaceDirection::Push, true, false);
        let argv = plan_workspace_rsync_argv(&plan).expect("must plan");
        assert_eq!(
            argv,
            vec![
                "rsync".to_string(),
                "-aL".to_string(),
                "--delete".to_string(),
                "--filter=:- .gitignore".to_string(),
                "-e".to_string(),
                "ssh".to_string(),
                "/host/path/".to_string(),
                "sandbox-abcdef012345:/guest/path/".to_string(),
            ]
        );
    }

    #[test]
    fn workspace_argv_dry_run_appends_dry_run_flag_before_operands() {
        let plan = workspace_plan_baseline(WorkspaceDirection::Push, false, true);
        let argv = plan_workspace_rsync_argv(&plan).expect("must plan");
        // `--dry-run` sits between `-e ssh` and `<src>`.
        let dry_idx = argv
            .iter()
            .position(|a| a == "--dry-run")
            .expect("--dry-run present");
        let src_idx = argv.len() - 2;
        assert!(dry_idx < src_idx);
    }

    #[test]
    fn workspace_argv_pull_swaps_src_and_dst() {
        let plan = workspace_plan_baseline(WorkspaceDirection::Pull, true, false);
        let argv = plan_workspace_rsync_argv(&plan).expect("must plan");
        // src is `sandbox-…:<guest>/`, dst is `<host>/`.
        assert_eq!(
            argv.iter().rev().nth(1).map(String::as_str),
            Some("sandbox-abcdef012345:/guest/path/")
        );
        assert_eq!(argv.last().map(String::as_str), Some("/host/path/"));
    }

    #[test]
    fn workspace_argv_pull_dest_override_replaces_host() {
        let mut plan = workspace_plan_baseline(WorkspaceDirection::Pull, true, false);
        plan.dest_override = Some("/custom/destination".to_string());
        let argv = plan_workspace_rsync_argv(&plan).expect("must plan");
        // dst is the override (with appended trailing slash); src is
        // the guest path.
        assert_eq!(
            argv.last().map(String::as_str),
            Some("/custom/destination/")
        );
    }

    #[test]
    fn workspace_argv_safe_links_splits_a_and_drops_l() {
        let mut plan = workspace_plan_baseline(WorkspaceDirection::Push, true, false);
        plan.safe_links = true;
        let argv = plan_workspace_rsync_argv(&plan).expect("must plan");
        assert!(!argv.iter().any(|a| a == "-aL"));
        assert_eq!(argv.get(1).map(String::as_str), Some("-a"));
        assert_eq!(argv.get(2).map(String::as_str), Some("--safe-links"));
    }

    #[test]
    fn workspace_argv_no_gitignore_drops_filter() {
        let mut plan = workspace_plan_baseline(WorkspaceDirection::Push, true, false);
        plan.no_gitignore = true;
        let argv = plan_workspace_rsync_argv(&plan).expect("must plan");
        assert!(argv.iter().all(|a| !a.starts_with("--filter")));
    }

    #[test]
    fn workspace_argv_neither_force_nor_dry_run_is_a_usage_error() {
        let plan = workspace_plan_baseline(WorkspaceDirection::Push, false, false);
        let err = plan_workspace_rsync_argv(&plan).expect_err("must reject neither-set");
        assert!(err.contains("required"));
    }

    #[test]
    fn workspace_argv_both_force_and_dry_run_is_a_usage_error() {
        let plan = workspace_plan_baseline(WorkspaceDirection::Push, true, true);
        let err = plan_workspace_rsync_argv(&plan).expect_err("must reject both-set");
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn workspace_argv_uses_bare_ssh_transport() {
        let plan = workspace_plan_baseline(WorkspaceDirection::Push, true, false);
        let argv = plan_workspace_rsync_argv(&plan).expect("must plan");
        let e_idx = argv.iter().position(|a| a == "-e").expect("-e present");
        assert_eq!(argv.get(e_idx + 1).map(String::as_str), Some("ssh"));
    }

    // -----------------------------------------------------------------------
    // looks_like_publickey_drift
    // -----------------------------------------------------------------------

    #[test]
    fn drift_sniffer_matches_canonical_substring() {
        let stderr = b"some preamble\n@@ \nuser@host: Permission denied (publickey).\nmore noise\n";
        assert!(looks_like_publickey_drift(stderr));
    }

    #[test]
    fn drift_sniffer_rejects_other_failures() {
        // Connection refused / host unreachable / remote command
        // non-zero exit must NOT be treated as drift.
        assert!(!looks_like_publickey_drift(
            b"ssh: connect to host 127.0.0.1 port 22: Connection refused\n"
        ));
        assert!(!looks_like_publickey_drift(
            b"Host key verification failed.\n"
        ));
        assert!(!looks_like_publickey_drift(b"command not found\n"));
    }

    #[test]
    fn drift_sniffer_handles_empty_stderr() {
        assert!(!looks_like_publickey_drift(b""));
    }

    // -----------------------------------------------------------------------
    // run_with_drift_recovery — state machine
    // -----------------------------------------------------------------------

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    fn dto_for(id: &str) -> SshConfigDto {
        SshConfigDto {
            config: sandbox_core::render_ssh_config_block(id),
            private_key: format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-{id}\n-----END OPENSSH PRIVATE KEY-----\n"
            ),
        }
    }

    #[tokio::test]
    async fn drift_recovery_zero_exit_first_attempt_does_not_retry() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";

        let fetch_calls = Arc::new(AtomicUsize::new(0));
        let attempt_calls = Arc::new(AtomicUsize::new(0));

        let fetch_calls_ = Arc::clone(&fetch_calls);
        let attempt_calls_ = Arc::clone(&attempt_calls);

        let exit = run_with_drift_recovery(
            home,
            id,
            move || {
                let fc = Arc::clone(&fetch_calls_);
                async move {
                    fc.fetch_add(1, Ordering::SeqCst);
                    Ok(dto_for(id))
                }
            },
            move |_alias, _attempt_idx| {
                let ac = Arc::clone(&attempt_calls_);
                async move {
                    ac.fetch_add(1, Ordering::SeqCst);
                    Ok(AttemptOutcome::Exited(0))
                }
            },
        )
        .await
        .expect("must succeed");

        assert_eq!(exit, 0);
        assert_eq!(fetch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(attempt_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn drift_recovery_nonzero_exit_without_pubkey_signal_does_not_retry() {
        // A `connection refused` or `remote command exited 42` must
        // propagate unchanged — drift recovery is matched ONLY on the
        // pubkey-drift signal. Spec § Key drift recovery: "Other SSH
        // failures … are passed through unchanged."
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";
        let attempt_calls = Arc::new(AtomicUsize::new(0));
        let attempt_calls_ = Arc::clone(&attempt_calls);

        let exit = run_with_drift_recovery(
            home,
            id,
            || async { Ok(dto_for(id)) },
            move |_alias, _attempt_idx| {
                let ac = Arc::clone(&attempt_calls_);
                async move {
                    ac.fetch_add(1, Ordering::SeqCst);
                    Ok(AttemptOutcome::Exited(42))
                }
            },
        )
        .await
        .expect("must succeed");

        assert_eq!(exit, 42);
        assert_eq!(attempt_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn drift_recovery_pubkey_signal_triggers_single_retry() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";
        let fetch_calls = Arc::new(AtomicUsize::new(0));
        let attempt_calls = Arc::new(AtomicUsize::new(0));

        let fc = Arc::clone(&fetch_calls);
        let ac = Arc::clone(&attempt_calls);

        let exit = run_with_drift_recovery(
            home,
            id,
            move || {
                let fc = Arc::clone(&fc);
                async move {
                    fc.fetch_add(1, Ordering::SeqCst);
                    Ok(dto_for(id))
                }
            },
            move |_alias, attempt_idx| {
                let ac = Arc::clone(&ac);
                async move {
                    ac.fetch_add(1, Ordering::SeqCst);
                    if attempt_idx == 0 {
                        Ok(AttemptOutcome::PublickeyDrift)
                    } else {
                        Ok(AttemptOutcome::Exited(0))
                    }
                }
            },
        )
        .await
        .expect("must succeed");

        assert_eq!(exit, 0);
        assert_eq!(
            fetch_calls.load(Ordering::SeqCst),
            2,
            "must re-fetch ssh-config on drift before second attempt"
        );
        assert_eq!(
            attempt_calls.load(Ordering::SeqCst),
            2,
            "must run the underlying tool exactly twice — single retry budget"
        );
    }

    #[tokio::test]
    async fn drift_recovery_second_pubkey_failure_propagates_without_third_attempt() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";
        let attempt_calls = Arc::new(AtomicUsize::new(0));
        let ac = Arc::clone(&attempt_calls);

        let exit = run_with_drift_recovery(
            home,
            id,
            || async { Ok(dto_for(id)) },
            move |_alias, _attempt_idx| {
                let ac = Arc::clone(&ac);
                async move {
                    ac.fetch_add(1, Ordering::SeqCst);
                    Ok(AttemptOutcome::PublickeyDrift)
                }
            },
        )
        .await
        .expect("must succeed (the inner failure is bubbled as an exit code)");

        // SSH "fatal error" exit code (255) — spec § Key drift
        // recovery pins single-retry, so the second pubkey failure
        // propagates to the operator without a third attempt.
        assert_eq!(exit, ssh_failure_exit_code());
        assert_eq!(
            attempt_calls.load(Ordering::SeqCst),
            2,
            "must NOT exceed the single-retry budget"
        );
    }

    #[tokio::test]
    async fn drift_recovery_writes_session_entry_on_each_attempt() {
        // Both attempts must call `ensure_session_entry`, which writes
        // the per-session key/config files under `~/.ssh/sandbox/`.
        // After a successful retry the entry is on disk and resolvable
        // by `ssh sandbox-<id>` — that is the post-condition the spec
        // promises operators.
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";

        run_with_drift_recovery(
            home,
            id,
            || async { Ok(dto_for(id)) },
            |_alias, attempt_idx| async move {
                if attempt_idx == 0 {
                    Ok(AttemptOutcome::PublickeyDrift)
                } else {
                    Ok(AttemptOutcome::Exited(0))
                }
            },
        )
        .await
        .expect("must succeed");

        // Verify the per-session entry exists.
        let cfg = ssh_config::session_config_path(home, id);
        let key = ssh_config::session_key_path(home, id);
        assert!(cfg.exists(), "per-session config must be on disk");
        assert!(key.exists(), "per-session key must be on disk");
        // And the global Include block exists in `~/.ssh/config`.
        let global = std::fs::read_to_string(ssh_config::ssh_config_path(home))
            .expect("~/.ssh/config must exist");
        assert!(global.contains(ssh_config::INCLUDE_LINE));
    }

    #[tokio::test]
    async fn drift_recovery_does_not_fire_for_setup_errors() {
        // If the fetch callback fails (e.g. daemon socket
        // unreachable), the wrapper surfaces the error to the caller
        // without retrying — there is no point re-fetching when the
        // first fetch failed for a transport reason.
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";
        let attempt_calls = Arc::new(AtomicUsize::new(0));
        let ac = Arc::clone(&attempt_calls);

        let err = run_with_drift_recovery(
            home,
            id,
            || async { Err(DriftRecoveryError::FetchDto("simulated".into())) },
            move |_alias, _attempt_idx| {
                let ac = Arc::clone(&ac);
                async move {
                    ac.fetch_add(1, Ordering::SeqCst);
                    Ok(AttemptOutcome::Exited(0))
                }
            },
        )
        .await
        .expect_err("must surface setup error");

        assert!(matches!(err, DriftRecoveryError::FetchDto(_)));
        assert_eq!(attempt_calls.load(Ordering::SeqCst), 0);
    }

    // -----------------------------------------------------------------------
    // parse_ssh_config_response — wire-shape boundary
    // -----------------------------------------------------------------------

    /// On a 404 carrying the typed `code: SSH_NOT_AVAILABLE`, the
    /// CLI must render the operator-actionable "recreate the
    /// session" remediation. We match on the typed `code` field
    /// rather than substring-sniffing the `error` text so a
    /// daemon-side rewording cannot silently break the boundary.
    #[test]
    fn parse_ssh_config_response_404_with_typed_code_surfaces_recreate_remediation() {
        let body = r#"{"error":"SSH_NOT_AVAILABLE: detail unused by the match","code":"SSH_NOT_AVAILABLE"}"#;
        let id = "0123456789ab";
        let err = parse_ssh_config_response(
            hyper::StatusCode::NOT_FOUND,
            body,
            std::path::Path::new("/run/sandboxd.sock"),
            id,
        )
        .expect_err("404 with SSH_NOT_AVAILABLE must surface as DriftRecoveryError::FetchDto");
        let msg = match err {
            DriftRecoveryError::FetchDto(m) => m,
            other => panic!("unexpected error variant: {other:?}"),
        };
        assert!(
            msg.contains("recreate the session"),
            "operator-actionable remediation must appear in the rendered error; got: {msg}",
        );
        assert!(
            msg.contains(id),
            "rendered error must include the session id so the operator can act; got: {msg}",
        );
    }

    /// On a 404 *without* the typed code, the CLI falls back to the
    /// generic "GET /sessions/{id}/ssh-config failed" message. Pins
    /// the boundary so a daemon that emits a 404 for some unrelated
    /// reason (e.g. foreign-owner) is not mis-rendered as the
    /// SSH_NOT_AVAILABLE remediation.
    #[test]
    fn parse_ssh_config_response_404_without_typed_code_falls_through_to_generic() {
        let body = r#"{"error":"session not found: deadbeefcafe"}"#;
        let id = "deadbeefcafe";
        let err = parse_ssh_config_response(
            hyper::StatusCode::NOT_FOUND,
            body,
            std::path::Path::new("/run/sandboxd.sock"),
            id,
        )
        .expect_err("404 must surface as DriftRecoveryError::FetchDto");
        let msg = match err {
            DriftRecoveryError::FetchDto(m) => m,
            other => panic!("unexpected error variant: {other:?}"),
        };
        assert!(
            !msg.contains("recreate the session"),
            "untyped 404 must NOT trigger the SSH_NOT_AVAILABLE branch; got: {msg}",
        );
        assert!(
            msg.contains("session not found"),
            "fallback path must preserve the daemon's error text; got: {msg}",
        );
    }

    /// 5xx errors fall through to the generic message regardless of
    /// the `code` field — the typed-code branch is 404-specific.
    #[test]
    fn parse_ssh_config_response_5xx_falls_through_to_generic() {
        let body = r#"{"error":"db lost"}"#;
        let err = parse_ssh_config_response(
            hyper::StatusCode::INTERNAL_SERVER_ERROR,
            body,
            std::path::Path::new("/run/sandboxd.sock"),
            "0123456789ab",
        )
        .expect_err("5xx must surface as DriftRecoveryError::FetchDto");
        let msg = match err {
            DriftRecoveryError::FetchDto(m) => m,
            other => panic!("unexpected error variant: {other:?}"),
        };
        assert!(msg.contains("db lost"));
        assert!(!msg.contains("recreate"));
    }

    // -----------------------------------------------------------------------
    // run_with_drift_recovery — retry-path end-to-end coverage
    //
    // The state-machine tests above cover call-count invariants; the
    // tests below drive the full operator-visible retry path:
    //
    // * a pre-existing **stale** entry on disk (simulating a prior
    //   daemon-side rotation the local CLI missed) is overwritten by
    //   the post-drift refresh — the on-disk bytes after a successful
    //   retry match the *new* DTO, not the stale one;
    // * a non-drift exit (e.g. `command not found` → 127) propagates
    //   without re-fetching or rewriting the entry — the wrapper is
    //   matched only on the locale-pinned pubkey-drift substring;
    // * the architectural invariant that `sandbox proxy` is excluded
    //   from drift recovery is asserted as a static source-level
    //   property (no `run_with_drift_recovery` call site in
    //   `proxy.rs`), so a future refactor that accidentally wires the
    //   wrapper into the ProxyCommand shim breaks this test.
    // -----------------------------------------------------------------------

    /// Build a DTO whose config + key carry a tag that distinguishes
    /// it from any other DTO produced in the same test. Used to prove
    /// the post-drift refresh actually overwrites a pre-staged stale
    /// entry rather than leaving the old bytes in place.
    fn tagged_dto(id: &str, tag: &str) -> SshConfigDto {
        // Embed the tag in a benign comment line inside the rendered
        // config block. The daemon-emitted block carries an
        // `IdentityFile <PLACEHOLDER>` line that `ensure_session_entry`
        // rewrites; the rest of the block round-trips verbatim, so a
        // `# tag=…` comment is a stable marker the test can grep for
        // on disk.
        let base = sandbox_core::render_ssh_config_block(id);
        let tagged_config = format!("# tag={tag}\n{base}");
        SshConfigDto {
            config: tagged_config,
            private_key: format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n\
                 fake-{id}-{tag}\n\
                 -----END OPENSSH PRIVATE KEY-----\n"
            ),
        }
    }

    /// Drift-recovery's headline operator-visible promise: a **stale
    /// local entry** under `~/.ssh/sandbox/` is silently refreshed
    /// when the daemon's current keypair has rotated past it.
    ///
    /// Setup: pre-stage a per-session entry built from a "stale" DTO,
    /// proving the wrapper inherits an existing on-disk state rather
    /// than starting from an empty `HOME`. Run the wrapper with a
    /// fetch callback that returns a **fresh** DTO (tag mismatch on
    /// every field that gets written to disk) and an attempt closure
    /// that fails the first call with `PublickeyDrift` and succeeds
    /// the second. After the wrapper returns:
    ///
    /// * the post-drift refresh ran (fetch_dto called twice — once
    ///   per attempt iteration);
    /// * the attempt closure ran exactly twice (single-retry budget);
    /// * the on-disk per-session config + key bytes now match the
    ///   **fresh** DTO, not the stale one — i.e. the retry actually
    ///   re-wrote the entry between attempts.
    #[tokio::test]
    async fn drift_recovery_overwrites_stale_local_entry_on_refresh() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";

        // Pre-stage a stale entry under `~/.ssh/sandbox/`. After this
        // call the per-session config + key are present with the
        // `stale-` tag baked into both.
        let stale_dto = tagged_dto(id, "stale-pre-rotation");
        ssh_config::ensure_session_entry(home, id, &stale_dto).expect("pre-stage the stale entry");

        // Sanity: the stale tag must actually be on disk before the
        // wrapper runs — otherwise the post-condition below is vacuous.
        let cfg_path = ssh_config::session_config_path(home, id);
        let key_path = ssh_config::session_key_path(home, id);
        let pre_cfg = std::fs::read_to_string(&cfg_path).unwrap();
        let pre_key = std::fs::read_to_string(&key_path).unwrap();
        assert!(
            pre_cfg.contains("# tag=stale-pre-rotation"),
            "pre-staged config must carry the stale tag; got: {pre_cfg}",
        );
        assert!(
            pre_key.contains("fake-0123456789ab-stale-pre-rotation"),
            "pre-staged key must carry the stale tag; got: {pre_key}",
        );

        // The wrapper's fetch callback returns the **fresh** DTO every
        // time — modelling a daemon whose current keypair has already
        // rotated past whatever the local entry carried. The attempt
        // closure fails the first call with `PublickeyDrift` (the
        // signal that drives the refresh) and succeeds the second.
        let fetch_calls = Arc::new(AtomicUsize::new(0));
        let attempt_calls = Arc::new(AtomicUsize::new(0));
        let fc = Arc::clone(&fetch_calls);
        let ac = Arc::clone(&attempt_calls);

        let exit = run_with_drift_recovery(
            home,
            id,
            move || {
                let fc = Arc::clone(&fc);
                async move {
                    fc.fetch_add(1, Ordering::SeqCst);
                    Ok(tagged_dto(id, "fresh-post-rotation"))
                }
            },
            move |_alias, attempt_idx| {
                let ac = Arc::clone(&ac);
                async move {
                    ac.fetch_add(1, Ordering::SeqCst);
                    if attempt_idx == 0 {
                        Ok(AttemptOutcome::PublickeyDrift)
                    } else {
                        Ok(AttemptOutcome::Exited(0))
                    }
                }
            },
        )
        .await
        .expect("must succeed after the single retry");

        assert_eq!(exit, 0);
        assert_eq!(
            fetch_calls.load(Ordering::SeqCst),
            2,
            "must re-fetch ssh-config between the two attempts",
        );
        assert_eq!(
            attempt_calls.load(Ordering::SeqCst),
            2,
            "must run the underlying tool exactly twice — single retry budget",
        );

        // The headline post-condition: the stale entry was overwritten
        // with the fresh DTO. Both files must now carry the `fresh-`
        // tag, and neither must carry the `stale-` tag.
        let post_cfg = std::fs::read_to_string(&cfg_path).unwrap();
        let post_key = std::fs::read_to_string(&key_path).unwrap();
        assert!(
            post_cfg.contains("# tag=fresh-post-rotation"),
            "post-refresh config must carry the fresh tag; got: {post_cfg}",
        );
        assert!(
            !post_cfg.contains("stale-pre-rotation"),
            "post-refresh config must NOT carry the stale tag; got: {post_cfg}",
        );
        assert!(
            post_key.contains("fake-0123456789ab-fresh-post-rotation"),
            "post-refresh key must carry the fresh tag; got: {post_key}",
        );
        assert!(
            !post_key.contains("stale-pre-rotation"),
            "post-refresh key must NOT carry the stale tag; got: {post_key}",
        );
    }

    /// Counterpart to the stale-overwrite test above: a **non-drift
    /// exit** must propagate unchanged without re-fetching the DTO or
    /// re-writing the local entry. The locale-pinned substring is the
    /// only signal that triggers a retry; anything else
    /// (`command not found` → 127, remote-side user error, etc.)
    /// passes through.
    ///
    /// Pre-stage a known entry, run the wrapper with an attempt that
    /// returns `Exited(127)` on the first call. After return:
    ///
    /// * the wrapper exited with the same 127 code;
    /// * fetch_dto was called exactly **once** (the initial fetch —
    ///   no post-drift refresh because there was no drift);
    /// * the attempt closure ran exactly **once**;
    /// * the on-disk entry is byte-identical to what was pre-staged
    ///   (the wrapper's first-iteration write is allowed to be a
    ///   no-op rewrite of the same content — what matters is the
    ///   wrapper did NOT rewrite it with refreshed DTO content
    ///   between attempts because there were no second attempts).
    #[tokio::test]
    async fn drift_recovery_does_not_retry_on_non_drift_exit() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path();
        let id = "0123456789ab";

        let dto = tagged_dto(id, "only-dto");
        // Pre-stage the entry so the post-condition below can grep
        // for the tag — this also models the realistic case where a
        // prior successful invocation already populated the entry.
        ssh_config::ensure_session_entry(home, id, &dto).expect("pre-stage");

        let fetch_calls = Arc::new(AtomicUsize::new(0));
        let attempt_calls = Arc::new(AtomicUsize::new(0));
        let fc = Arc::clone(&fetch_calls);
        let ac = Arc::clone(&attempt_calls);

        // 127 is the POSIX shell convention for "command not found";
        // the wrapper must propagate it unchanged. A non-zero exit
        // that is *not* `PublickeyDrift` is the only thing we are
        // asserting on here — the specific code is incidental.
        let exit = run_with_drift_recovery(
            home,
            id,
            move || {
                let fc = Arc::clone(&fc);
                async move {
                    fc.fetch_add(1, Ordering::SeqCst);
                    Ok(tagged_dto(id, "only-dto"))
                }
            },
            move |_alias, _attempt_idx| {
                let ac = Arc::clone(&ac);
                async move {
                    ac.fetch_add(1, Ordering::SeqCst);
                    Ok(AttemptOutcome::Exited(127))
                }
            },
        )
        .await
        .expect("must succeed (the non-zero exit is bubbled as Ok(code))");

        assert_eq!(exit, 127, "non-drift exit code must propagate verbatim");
        assert_eq!(
            fetch_calls.load(Ordering::SeqCst),
            1,
            "non-drift exit must NOT trigger a second fetch",
        );
        assert_eq!(
            attempt_calls.load(Ordering::SeqCst),
            1,
            "non-drift exit must NOT trigger a second attempt",
        );

        // The on-disk entry must still carry the original tag — no
        // refresh happened because no drift signal fired.
        let cfg_path = ssh_config::session_config_path(home, id);
        let key_path = ssh_config::session_key_path(home, id);
        let post_cfg = std::fs::read_to_string(&cfg_path).unwrap();
        let post_key = std::fs::read_to_string(&key_path).unwrap();
        assert!(post_cfg.contains("# tag=only-dto"));
        assert!(post_key.contains("fake-0123456789ab-only-dto"));
    }

    /// Architectural invariant: the `sandbox proxy` subcommand is
    /// excluded from drift recovery. Spec § Key drift recovery:
    /// "never inside `sandbox proxy`, so nested invocations from
    /// `git-remote-sandbox` cannot stack retries."
    ///
    /// We cannot drive the proxy through `run_with_drift_recovery` in
    /// a hermetic test (proxy needs a real WebSocket-capable daemon
    /// socket, which would push this test into the integration tier).
    /// Instead, assert the invariant statically: scan the `proxy.rs`
    /// source and verify it contains no call site for the wrapper.
    /// A future refactor that accidentally wires drift recovery into
    /// the ProxyCommand shim (e.g. by importing `run_with_drift_recovery`
    /// into the proxy run-loop) trips this test, surfacing the
    /// regression at unit-test time rather than at e2e time where
    /// nested `git-remote-sandbox` retries would stack.
    #[test]
    fn drift_recovery_is_not_invoked_from_proxy_shim() {
        // Include the proxy.rs source verbatim at compile time. The
        // path is relative to this file (`ssh_commands.rs`); both live
        // in `sandbox-cli/src/`.
        const PROXY_SOURCE: &str = include_str!("proxy.rs");

        // The exact function name is the wire-level invariant. A
        // hypothetical rename would force this needle to change too,
        // and the test breakage at that point would be the cue to
        // re-evaluate the architectural invariant — by design.
        const FORBIDDEN_NEEDLE: &str = "run_with_drift_recovery";

        // Strip comment lines so a benign doc-comment reference to the
        // wrapper (which proxy.rs has — explaining *why* drift recovery
        // is excluded) does not trip the static assertion. Only
        // executable code matters for the invariant; references in
        // `//`-prefixed comments are explanatory and stay legal.
        let executable: String = PROXY_SOURCE
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            !executable.contains(FORBIDDEN_NEEDLE),
            "proxy.rs must NOT invoke `{FORBIDDEN_NEEDLE}` — drift recovery is \
             deliberately excluded from the `sandbox proxy` shim so nested \
             `git-remote-sandbox` invocations cannot stack retries. If you \
             intentionally wired the wrapper into the proxy run-loop, also \
             revisit this invariant in the spec.",
        );
    }
}
