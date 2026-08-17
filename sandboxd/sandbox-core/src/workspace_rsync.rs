//! Daemon-side `rsync` orchestration for `local:` workspace mode.
//!
//! Exports [`run_initial_push_via_helper`], the async function that
//! `sandboxd::create_session` invokes after the VM/container reaches
//! `Running` to mirror the host workspace into the guest via
//! `sandbox-lima-helper run-rsync` (which pivots to the operator uid
//! before exec'ing `rsync`, so it can read operator-owned host
//! workspace directories). The module is deliberately small and free of
//! `sandboxd`-internal types so the same primitives can later back
//! operator-driven `sandbox workspace push/pull` from a CLI-side
//! planner.
//!
//! ## Argv shape
//!
//! ```text
//! rsync -aL --delete --filter=':- .gitignore' \
//!   -e <shell-transport> --mkpath \
//!   <host>/ sandbox-<id>:<guest>/
//! ```
//!
//! where `<shell-transport>` is `limactl shell` (Lima) or
//! `docker exec -i` (container). The `--filter=':- .gitignore'` flag is
//! dropped when `no_gitignore == true`. Both `<host>` and `<guest>` carry
//! a trailing `/` so rsync mirrors directory contents rather than the
//! directory entry itself. `--mkpath` (rsync ≥ 3.2.3) delegates
//! parent-directory creation to rsync; the base + lite images ship
//! rsync 3.2.7+ via cloud-init.
//!
//! ## Cancellation
//!
//! The spawned `rsync` child is tagged `kill_on_drop(true)`. When the
//! HTTP request future is dropped (operator Ctrl+C, daemon SIGTERM
//! during graceful shutdown, CLI HTTP timeout), `tokio::process::Child`
//! sends `SIGKILL` to the rsync process after a cancellation timeout.
//!
//! ## Error mapping
//!
//! Non-zero rsync exits collapse to
//! `SandboxError::Internal(format!("local-workspace rsync failed (exit
//! {code}): {stderr}"))`. All non-zero exits are fatal (codes 23
//! "partial transfer" and 24 "vanished source" are not special-cased —
//! the uniform "all-non-zero-fatal" rule keeps the contract simple). The
//! captured stderr is decoded lossy (UTF-8 with U+FFFD replacement chars)
//! so binary noise never panics the error path.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::info;

use crate::backend::BackendKind;
use sandbox_docker_argv::container::ContainerCommand;

use crate::docker::{DockerOp, DockerRoute};
use crate::error::SandboxError;
use crate::lima::{LimaExecutor, LimaOp};

/// Caller-side rsync `-e` transport token for Lima sessions.
/// Passed to rsync as the remote-shell argument; rsync (running as the
/// operator uid on the CLI side) exec's `limactl shell <vm> <cmd>`.
/// The daemon never spawns this command directly — this is a string
/// token in an argv array built for rsync, not a daemon `Command::new`.
const LIMACTL_SHELL_TOKEN: &str = "limactl shell";

/// Rsync `-e` transport token for the SSH-alias path used by the CLI's
/// `sandbox workspace push|pull`. The operator's `~/.ssh/config`
/// (managed by the daemon's ssh-config machinery) resolves
/// `sandbox-<id>` to the full per-session `ProxyCommand` stanza.
/// Re-exported so `sandbox-cli::ssh_commands` can use it when
/// delegating argv construction to [`build_workspace_rsync_argv`].
pub const SSH_TRANSPORT_TOKEN: &str = "ssh";

/// Direction of a workspace rsync mirror. Push: host → guest; Pull:
/// guest → host. Carried into [`build_workspace_rsync_argv`] so the
/// builder emits the correct src/dst ordering. A flat enum rather
/// than a bool so future directions (e.g. a bidirectional `sync`)
/// can be added without re-spelling existing call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Host → guest. Source is `<host>/`, destination is
    /// `sandbox-<id>:<guest>/`.
    Push,
    /// Guest → host. Source is `sandbox-<id>:<guest>/`, destination is
    /// `<host>/`.
    Pull,
}

/// Tagged inputs for [`build_workspace_rsync_argv`]. Aggregating into
/// a struct (vs. a long positional argument list) makes call sites
/// self-documenting and lets new flags slot in without churning every
/// test fixture.
///
/// **Field semantics.**
///
/// - `backend` — picks the rsync shell-transport (`-e <shell>`) value
///   when `custom_transport` is `None`: `"limactl shell"` for Lima,
///   `"docker exec -i"` for container. Mirrors the convention
///   `plan_sync_command` uses.
/// - `custom_transport` — when `Some`, overrides the backend-derived
///   transport. The CLI's SSH-alias path sets this to `"ssh"` (via
///   [`SSH_TRANSPORT_TOKEN`]) so the operator's `~/.ssh/config`
///   stanza resolves the full proxy chain. When `None` (the default
///   for daemon-side calls), `backend` drives the selection.
/// - `session_name` — the `sandbox-<id>` form the backends accept on
///   the shell transport. Concatenated into the
///   `sandbox-<name>:<path>/` remote spec.
/// - `host_path` — host-side root. Trailing slash appended by the
///   builder if absent.
/// - `guest_path` — guest-side root. Same trailing-slash rule.
/// - `direction` — push vs pull. Drives src/dst ordering and the
///   `sandbox-<name>:<guest>/` token's position.
/// - `no_gitignore` — when `true`, the `--filter=:- .gitignore`
///   token is omitted entirely.
/// - `dry_run` — when `true`, appends `--dry-run` between `-e
///   <shell>`/`--mkpath` and the src/dst operands.
/// - `safe_links` — when `true`, replaces the combined `-aL` token
///   with the split `-a --safe-links` pair (rsync's `--safe-links`
///   does not compose with `-L`, so the planner must drop `-L`).
/// - `mkpath` — when `true`, appends `--mkpath` (rsync ≥ 3.2.3) so
///   rsync creates missing parent directories on the destination.
///   The initial create-time push uses `mkpath = true` on Linux;
///   operator-driven push/pull typically uses `false` because the
///   destination should already exist. On the macOS lite create path
///   (host rsync is Apple openrsync, which has no `--mkpath`)
///   [`run_initial_push`] sets `mkpath = false` and pre-creates the
///   destination over the transport instead.
#[derive(Debug, Clone)]
pub struct WorkspaceRsyncOptions {
    pub backend: BackendKind,
    /// When `Some`, overrides the backend-derived `-e <transport>`.
    /// Set to [`SSH_TRANSPORT_TOKEN`] by the CLI's SSH-alias path.
    pub custom_transport: Option<String>,
    /// Forwarded gateway-VM Docker socket for the container backend on macOS
    /// lite. When `Some` (and `custom_transport` is `None`, the daemon-side
    /// default), the container transport becomes
    /// `docker -H unix://<sock> exec -i` so rsync's `docker exec` reaches the
    /// container inside the gateway VM rather than the host docker daemon.
    /// `None` on Linux / host docker — the transport stays the historical
    /// `docker exec -i`. Ignored for the Lima backend and when
    /// `custom_transport` is set.
    pub docker_socket: Option<String>,
    pub session_name: String,
    pub host_path: String,
    pub guest_path: String,
    pub direction: Direction,
    pub no_gitignore: bool,
    pub dry_run: bool,
    pub safe_links: bool,
    pub mkpath: bool,
}

/// Build the rsync argv for a workspace mirror (initial create-time
/// push or operator-driven push/pull).
///
/// Pure function — no I/O, no spawning. The returned `Vec<String>`
/// does NOT include the leading `"rsync"` program name; callers pass
/// it to `Command::new("rsync").args(&argv)` directly. The CLI's
/// operator-facing planner prepends `"rsync"` itself so its test
/// fixtures and operator diagnostics see the full argv.
///
/// Argv layout:
///
/// ```text
/// [-aL | -a --safe-links] --delete [--filter=:- .gitignore]
///   -e <shell> [--mkpath] [--dry-run] <src> <dst>
/// ```
///
/// where `<shell>` is `limactl shell` (Lima) or `docker exec -i`
/// (container, with `-i` forwarding stdin so rsync's binary protocol
/// speaks both ways; no `-t` because a TTY would line-buffer and
/// corrupt the wire format). Trailing slashes are appended to both
/// endpoints if absent.
pub fn build_workspace_rsync_argv(opts: &WorkspaceRsyncOptions) -> Vec<String> {
    // Shell-transport: `-e <transport>` slots in as rsync's remote-
    // shell exec, matching the convention `plan_sync_command` uses
    // for operator-driven `sandbox sync` in the CLI.
    //
    // When `custom_transport` is set (e.g. `"ssh"` for the CLI's
    // SSH-alias path), it overrides the backend-derived default.
    let transport: String = match opts.custom_transport.as_deref() {
        Some(t) => t.to_string(),
        None => match opts.backend {
            BackendKind::Lima => LIMACTL_SHELL_TOKEN.to_string(),
            // On macOS lite the container runs inside the gateway VM, so the
            // `docker exec` must target the forwarded socket; otherwise rsync
            // hits the host docker daemon and finds no such container. Linux
            // leaves `docker_socket` `None` — the transport stays the
            // historical `docker exec -i`. The agent builds the same string on
            // the macOS brokered path, so the shape is single-sourced.
            BackendKind::Container => sandbox_docker_argv::exec_rsh_transport(
                opts.docker_socket.as_deref().map(std::path::Path::new),
            ),
        },
    };

    // Trailing-slash rule: both
    // endpoints always carry `/` so rsync mirrors the *contents* of
    // the directory rather than the directory entry itself. We
    // append only when absent so caller-supplied paths that already
    // end in `/` are not doubled.
    let with_slash = |p: &str| -> String {
        if p.ends_with('/') {
            p.to_string()
        } else {
            format!("{p}/")
        }
    };

    let host_arg = with_slash(&opts.host_path);
    let remote_arg = format!("{}:{}", opts.session_name, with_slash(&opts.guest_path));
    let (src, dst) = match opts.direction {
        Direction::Push => (host_arg, remote_arg),
        Direction::Pull => (remote_arg, host_arg),
    };

    let mut argv: Vec<String> = Vec::with_capacity(10);

    // Symlink-handling flag: default `-aL` (archive + dereference
    // all). With `safe_links == true`, split into `-a --safe-links`
    // (archive on its own + rsync's `--safe-links`, which preserves
    // in-tree symlinks and skips out-of-tree ones). The split is
    // load-bearing: rsync's `--safe-links` does not compose with
    // `-L`, so the single `-aL` cannot be augmented — the planner
    // must drop `-L` entirely.
    if opts.safe_links {
        argv.push("-a".to_string());
        argv.push("--safe-links".to_string());
    } else {
        // `-a` — archive (perms, ownership, times, recursion).
        // `-L` — follow symlinks during transfer (copy resolved
        // files). Same baseline the design defines for both create-
        // time push and operator-driven push/pull.
        argv.push("-aL".to_string());
    }
    // `--delete` — mirror semantics: destination entries absent on
    // the source are removed. Combined with `--filter`, gitignored
    // destination entries are protected from deletion.
    argv.push("--delete".to_string());
    if !opts.no_gitignore {
        // Per-directory merge of `.gitignore` files; matched entries
        // are excluded from both transfer and deletion consideration.
        argv.push("--filter=:- .gitignore".to_string());
    }
    argv.push("-e".to_string());
    argv.push(transport);
    if opts.mkpath {
        // `--mkpath` lets rsync create missing parent directories on
        // the destination (rsync ≥ 3.2.3). Both the Lima base image
        // and the lite container image ship rsync 3.2.7+ (Ubuntu
        // 24.04 noble) per the `REQUIRED` cloud-init declaration in
        // `lima.rs`. Create-time push enables this; operator-driven
        // push/pull leaves it off since the destination already
        // exists.
        argv.push("--mkpath".to_string());
    }
    if opts.dry_run {
        // `--dry-run` is placed after `-e <shell>` (and `--mkpath`
        // if present) and before the src/dst operands. rsync accepts
        // it anywhere among the options, but pinning a stable
        // position keeps argv test fixtures readable.
        argv.push("--dry-run".to_string());
    }
    argv.push(src);
    argv.push(dst);
    argv
}

/// Run the create-time `rsync` push from a host directory into the
/// guest.
///
/// Blocking from the caller's perspective — the future does not resolve
/// until rsync exits or the future is dropped. Drop semantics: the
/// underlying [`tokio::process::Child`] is tagged `kill_on_drop(true)`,
/// so a dropped request future tears the rsync child down via
/// `SIGKILL`.
///
/// `session_name` is the `sandbox-<id>` form the backends accept on the
/// shell transport. Callers in `sandboxd::create_session` build it as
/// `format!("sandbox-{session_id}")` to match the convention used by
/// `sandbox sync` (`plan_sync_command` in the CLI).
///
/// On zero exit: returns `Ok(())`. On non-zero exit: returns
/// [`SandboxError::Internal`] with the captured stderr embedded
/// verbatim (lossy UTF-8 decoding) so the operator sees rsync's own
/// diagnostic (e.g. `permission denied`, `mkdir failed: EROFS`).
///
/// ## Apple openrsync caveat (`docker_socket.is_some()` path)
///
/// On macOS the daemon spawns the **host** `rsync`, which is Apple
/// **openrsync** — it has no `--mkpath` (that flag is rsync ≥ 3.2.3) and
/// aborts before any transport runs if it is passed. The macOS lite create
/// path is the sole caller that supplies a forwarded `docker_socket`, so
/// `docker_socket.is_some()` is the macOS-lite discriminator: in that case
/// `--mkpath` is dropped and the guest destination directory is created up
/// front over the same transport (`docker -H <sock> exec <ctr> mkdir -p
/// <guest>`). Linux passes `docker_socket = None`, keeps `--mkpath`, and
/// skips the pre-mkdir entirely — byte-identical to the prior behaviour.
pub async fn run_initial_push(
    backend: BackendKind,
    docker: Option<&DockerRoute>,
    docker_socket: Option<&str>,
    session_name: &str,
    host_path: &str,
    guest_path: &str,
    no_gitignore: bool,
) -> Result<(), SandboxError> {
    // Apple openrsync (host rsync on macOS) rejects `--mkpath`. The forwarded
    // socket is only ever set on the macOS lite create path, so its presence
    // selects the openrsync-safe shape: pre-create the guest destination
    // directory over the transport, then run rsync without `--mkpath`. Linux
    // leaves `docker_socket` `None` and keeps the rsync-driven parent create.
    let use_mkpath = docker_socket.is_none();
    if let Some(route) = docker {
        // Container backend only: the route addresses the in-VM Docker
        // daemon, so `docker exec <ctr> mkdir -p <guest>` materialises the
        // destination root before rsync runs. The Lima backend never supplies
        // a route (it uses the helper-pivoted push), so this branch is
        // container-only in practice.
        if backend == BackendKind::Container {
            premkdir_guest_dir(route.clone(), session_name, guest_path).await?;
        }
    }

    // Create-time push is fixed-shape: host → guest direction, no dry-run,
    // no safe-links toggle. `--mkpath` is enabled only when the host rsync
    // supports it (Linux); on macOS lite the destination was pre-created
    // above and `--mkpath` is dropped (Apple openrsync rejects it).
    // Operator-driven push/ pull (CLI side) builds the same options struct
    // with different flags but goes through the same shared builder.
    //
    // `docker_socket` is `None` on Linux / host docker (transport stays
    // `docker exec -i`); on macOS lite the forwarded gateway-VM socket
    // rewrites the container transport to `docker -H unix://<sock> exec -i`
    // so rsync's `docker exec` reaches the container inside the gateway VM.
    // Ignored for the Lima backend.
    let argv = build_workspace_rsync_argv(&WorkspaceRsyncOptions {
        backend,
        custom_transport: None,
        docker_socket: docker_socket.map(str::to_string),
        session_name: session_name.to_string(),
        host_path: host_path.to_string(),
        guest_path: guest_path.to_string(),
        direction: Direction::Push,
        no_gitignore,
        dry_run: false,
        safe_links: false,
        mkpath: use_mkpath,
    });

    info!(
        backend = ?backend,
        session = %session_name,
        host_path = %host_path,
        guest_path = %guest_path,
        no_gitignore = no_gitignore,
        "local-workspace rsync: starting initial push"
    );

    let mut command = Command::new("rsync");
    command
        .args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Request future drop ⇒ child killed.
        // timeout: no daemon-side `tokio::time::timeout`; the operator-
        // facing budget is the CLI's `CLI_HTTP_TIMEOUT`.
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(|e| {
        SandboxError::Internal(format!("failed to spawn local-workspace rsync: {e}"))
    })?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SandboxError::Internal("failed to capture rsync stdout".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| SandboxError::Internal("failed to capture rsync stderr".into()))?;

    // Drain stdout line-by-line to INFO so daemon-log consumers see
    // transfer summaries. Stderr is accumulated for the error path so
    // non-zero exits can surface the operator-facing diagnostic verbatim.
    let stdout_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            info!(target: "sandbox_core::workspace_rsync", "rsync stdout: {line}");
        }
    });

    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::<u8>::new();
        let mut reader = BufReader::new(stderr);
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf).await;
        buf
    });

    let status = child
        .wait()
        .await
        .map_err(|e| SandboxError::Internal(format!("failed to wait for rsync exit: {e}")))?;

    // Always join the drain tasks so any in-flight stdout/stderr is
    // captured before we build the error message. `JoinError` on the
    // pumpers is non-fatal — the exit status is the source of truth —
    // but the stderr buffer is load-bearing for the failure message.
    let _ = stdout_task.await;
    let stderr_bytes = stderr_task.await.unwrap_or_default();

    if status.success() {
        return Ok(());
    }

    let code = status
        .code()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "signal".to_string());
    let stderr_text = String::from_utf8_lossy(&stderr_bytes);
    Err(SandboxError::Internal(format!(
        "local-workspace rsync failed (exit {code}): {stderr_text}"
    )))
}

/// Timeout for the pre-rsync `mkdir -p`. A short ceiling: it is a single
/// fast in-VM `docker exec`.
const PREMKDIR_TIMEOUT: Duration = Duration::from_secs(30);

/// Create the guest destination directory inside the in-VM container before
/// the macOS-lite rsync push.
///
/// Apple openrsync (the host rsync on macOS) has no `--mkpath`, so the
/// destination root must already exist when rsync starts. `session_name`
/// doubles as the container name (`sandbox-<id>`), matching the rsync remote
/// spec the same call site builds. Non-zero exit is fatal (fail-closed: a
/// missing destination would make the subsequent rsync fail with a less
/// actionable error).
async fn premkdir_guest_dir(
    docker: DockerRoute,
    session_name: &str,
    guest_path: &str,
) -> Result<(), SandboxError> {
    info!(
        session = %session_name,
        guest_path = %guest_path,
        "local-workspace rsync: pre-creating guest dir (openrsync, no --mkpath)"
    );
    let op = DockerOp::ContainerExec {
        name: session_name.to_string(),
        command: ContainerCommand::MakeDirectory {
            path: guest_path.to_string(),
        },
    };
    let label = "docker exec mkdir -p (guest workspace dir)";
    let output = tokio::task::spawn_blocking(move || docker.run(op, PREMKDIR_TIMEOUT, label))
        .await
        .map_err(|e| SandboxError::Internal(format!("spawn_blocking join failed: {e}")))?
        .map_err(|e| match e {
            SandboxError::Internal(msg) if msg.contains("failed to spawn") => {
                SandboxError::Internal(format!(
                    "failed to spawn docker mkdir -p for local-workspace dest: {msg}"
                ))
            }
            other => other,
        })?;
    if output.status.success() {
        return Ok(());
    }
    let code = output
        .status
        .code()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "signal".to_string());
    let stderr_text = String::from_utf8_lossy(&output.stderr);
    Err(SandboxError::Internal(format!(
        "cannot create local: workspace directory '{guest_path}' inside the sandbox \
         container (docker exec mkdir -p exited {code}: {stderr_text}). \
         The sandbox container root filesystem is read-only, so a path outside a \
         writable mount cannot be created there. To place the workspace in a writable \
         location, pass an explicit guest path: \
         local:<host-path>:<guest-path> (e.g. /home/sandbox/workspace as the guest path)."
    )))
}

/// Timeout for the helper-pivoted rsync push.
///
/// Mirrors the CLI's `CLI_HTTP_TIMEOUT`; the daemon-side budget is the
/// operator's own HTTP request deadline. A generous 10-minute ceiling
/// covers large repositories on slow connections while still bounding
/// a stuck rsync child.
const RSYNC_VIA_HELPER_TIMEOUT: Duration = Duration::from_secs(600);

/// Run the create-time `rsync` push pivoted through `sandbox-lima-helper`.
///
/// This is the cross-user-correct replacement for direct-spawn rsync.
/// The daemon (uid 999) cannot `change_dir` into operator-owned host
/// workspace directories (mode 0700, owned by the operator uid).
/// `sandbox-lima-helper run-rsync` holds `cap_setuid+ep`, pivots to
/// `op_uid` via `setresuid`, then `execvpe`s `rsync` — so rsync
/// inherits the operator's uid and can read the host workspace source.
/// For the Lima backend this also means the `-e "limactl shell"` transport
/// runs as the operator uid, which is the uid that owns `limactl`'s SSH
/// keys.  For the container backend the docker socket is accessible to
/// any group-docker member; running as the operator uid has no adverse
/// effect and unblocks the host-path read.
///
/// The helper is invoked inside `tokio::task::spawn_blocking` per the
/// project convention for one-shot `std::process::Command` calls.
///
/// On zero exit: returns `Ok(())`. On non-zero exit: returns
/// [`SandboxError::Internal`] with the captured stderr embedded
/// verbatim (lossy UTF-8) so the operator sees rsync's own diagnostic.
/// On timeout: returns [`SandboxError::Timeout`].
pub async fn run_initial_push_via_helper(
    executor: &Arc<dyn LimaExecutor>,
    op_uid: u32,
    backend: BackendKind,
    session_name: &str,
    host_path: &str,
    guest_path: &str,
    no_gitignore: bool,
) -> Result<(), SandboxError> {
    info!(
        backend = ?backend,
        session = %session_name,
        host_path = %host_path,
        guest_path = %guest_path,
        no_gitignore = no_gitignore,
        "local-workspace rsync: starting initial push (via helper)"
    );

    let executor = Arc::clone(executor);
    let session_name = session_name.to_owned();
    let host_path = host_path.to_owned();
    let guest_path = guest_path.to_owned();

    let result = tokio::task::spawn_blocking(move || {
        executor.run(
            op_uid,
            LimaOp::RunRsync {
                backend,
                session_name: &session_name,
                host_path: &host_path,
                guest_path: &guest_path,
                no_gitignore,
            },
            RSYNC_VIA_HELPER_TIMEOUT,
            "sandbox-lima-helper run-rsync",
        )
    })
    .await
    .map_err(|e| {
        SandboxError::Internal(format!("spawn_blocking join failed for run-rsync: {e}"))
    })?;

    let output = result?;

    if output.status.success() {
        return Ok(());
    }

    let code = output
        .status
        .code()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "signal".to_string());
    // The helper execvpe's rsync, so the helper's stderr IS rsync's
    // stderr once the exec succeeds. If execvpe fails the helper prints
    // a single diagnostic line instead; both cases are useful to the
    // operator.
    let stderr_text = String::from_utf8_lossy(&output.stderr);
    Err(SandboxError::Internal(format!(
        "local-workspace rsync failed (exit {code}): {stderr_text}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a create-time-push options struct (the daemon's
    /// only call shape today). Mirrors the signature of the original
    /// private `build_argv` so the test bodies stay readable.
    fn push_opts(
        backend: BackendKind,
        session_name: &str,
        host_path: &str,
        guest_path: &str,
        no_gitignore: bool,
    ) -> WorkspaceRsyncOptions {
        WorkspaceRsyncOptions {
            backend,
            custom_transport: None,
            docker_socket: None,
            session_name: session_name.to_string(),
            host_path: host_path.to_string(),
            guest_path: guest_path.to_string(),
            direction: Direction::Push,
            no_gitignore,
            dry_run: false,
            safe_links: false,
            mkpath: true,
        }
    }

    /// Lima backend with default gitignore filter: argv carries the
    /// `limactl shell` transport, the `--filter=:- .gitignore` flag, and
    /// the `sandbox-<id>:<guest>/` destination form.
    #[test]
    fn build_argv_lima_default_filter() {
        let argv = build_workspace_rsync_argv(&push_opts(
            BackendKind::Lima,
            "sandbox-abc123",
            "/home/op/work",
            "/home/sandbox/workspace",
            false,
        ));
        assert_eq!(
            argv,
            vec![
                "-aL",
                "--delete",
                "--filter=:- .gitignore",
                "-e",
                LIMACTL_SHELL_TOKEN,
                "--mkpath",
                "/home/op/work/",
                "sandbox-abc123:/home/sandbox/workspace/",
            ]
        );
    }

    /// Container backend with default gitignore filter: same argv shape
    /// as Lima except the `-e` value is `docker exec -i`.
    #[test]
    fn build_argv_container_default_filter() {
        let argv = build_workspace_rsync_argv(&push_opts(
            BackendKind::Container,
            "sandbox-def456",
            "/srv/proj",
            "/home/sandbox/workspace",
            false,
        ));
        assert_eq!(
            argv,
            vec![
                "-aL",
                "--delete",
                "--filter=:- .gitignore",
                "-e",
                "docker exec -i",
                "--mkpath",
                "/srv/proj/",
                "sandbox-def456:/home/sandbox/workspace/",
            ]
        );
    }

    /// macOS lite: a forwarded Docker socket rewrites the container transport
    /// to `docker -H unix://<sock> exec -i` so rsync's `docker exec` reaches
    /// the container inside the gateway VM. The rest of the argv is unchanged.
    #[test]
    fn build_argv_container_injects_socket_into_transport() {
        let mut opts = push_opts(
            BackendKind::Container,
            "sandbox-mac1",
            "/srv/proj",
            "/home/sandbox/workspace",
            false,
        );
        opts.docker_socket = Some("/var/lib/sandboxd/501/gateway-docker.sock".to_string());
        let argv = build_workspace_rsync_argv(&opts);
        assert_eq!(
            argv,
            vec![
                "-aL",
                "--delete",
                "--filter=:- .gitignore",
                "-e",
                "docker -H unix:///var/lib/sandboxd/501/gateway-docker.sock exec -i",
                "--mkpath",
                "/srv/proj/",
                "sandbox-mac1:/home/sandbox/workspace/",
            ]
        );
    }

    /// Linux / host docker: with `docker_socket = None` the container
    /// transport stays the historical `docker exec -i` (no `-H`). Pins the
    /// byte-identical Linux argv.
    #[test]
    fn build_argv_container_without_socket_is_host_docker() {
        let opts = push_opts(
            BackendKind::Container,
            "sandbox-lin1",
            "/srv/proj",
            "/home/sandbox/workspace",
            false,
        );
        let argv = build_workspace_rsync_argv(&opts);
        let e_idx = argv.iter().position(|a| a == "-e").expect("-e present");
        assert_eq!(
            argv[e_idx + 1],
            "docker exec -i",
            "host-docker transport must not carry -H: {argv:?}"
        );
    }

    /// The Lima backend ignores `docker_socket` — it only affects the
    /// container transport.
    #[test]
    fn build_argv_lima_ignores_docker_socket() {
        let mut opts = push_opts(
            BackendKind::Lima,
            "sandbox-lima1",
            "/srv/proj",
            "/home/sandbox/workspace",
            false,
        );
        opts.docker_socket = Some("/var/lib/sandboxd/501/gateway-docker.sock".to_string());
        let argv = build_workspace_rsync_argv(&opts);
        let e_idx = argv.iter().position(|a| a == "-e").expect("-e present");
        assert_eq!(argv[e_idx + 1], LIMACTL_SHELL_TOKEN);
    }

    /// `no_gitignore == true` drops the `--filter` flag entirely. The
    /// rest of the argv (transport, `--mkpath`, trailing slashes) is
    /// unchanged. Mirrors `--no-gitignore` clap flag semantics from
    /// Phase 2 wire-DTO.
    #[test]
    fn build_argv_drops_filter_when_no_gitignore_true() {
        let argv = build_workspace_rsync_argv(&push_opts(
            BackendKind::Lima,
            "sandbox-ghi789",
            "/data/x",
            "/home/sandbox/workspace",
            true,
        ));
        // No `--filter=...` entry anywhere in the argv.
        assert!(
            argv.iter().all(|a| !a.starts_with("--filter")),
            "--filter present despite no_gitignore=true: {argv:?}"
        );
        // The flag drop must not shift the other positions: `-e` is
        // followed by the transport, and `--mkpath` precedes the src/dst
        // operands.
        assert_eq!(
            argv,
            vec![
                "-aL",
                "--delete",
                "-e",
                LIMACTL_SHELL_TOKEN,
                "--mkpath",
                "/data/x/",
                "sandbox-ghi789:/home/sandbox/workspace/",
            ]
        );
    }

    /// Trailing-slash rule: both source
    /// and destination always end with `/`. This test pins the rule
    /// when the caller passes paths *without* trailing slashes — the
    /// builder must append them.
    #[test]
    fn build_argv_appends_trailing_slash_to_both_endpoints() {
        let argv = build_workspace_rsync_argv(&push_opts(
            BackendKind::Lima,
            "sandbox-xyz",
            "/a/b",
            "/c/d",
            false,
        ));
        let src = argv.iter().rev().nth(1).expect("src arg");
        let dst = argv.last().expect("dst arg");
        assert_eq!(src, "/a/b/");
        assert_eq!(dst, "sandbox-xyz:/c/d/");
    }

    /// Trailing-slash rule, idempotent variant: when the caller already
    /// passed a trailing slash, the builder does not double it. The
    /// "always append if absent" rule keeps the builder branch-free
    /// without producing pathological `//` paths.
    #[test]
    fn build_argv_does_not_double_existing_trailing_slash() {
        let argv = build_workspace_rsync_argv(&push_opts(
            BackendKind::Container,
            "sandbox-q",
            "/a/b/",
            "/c/d/",
            false,
        ));
        let src = argv.iter().rev().nth(1).expect("src arg");
        let dst = argv.last().expect("dst arg");
        assert_eq!(src, "/a/b/");
        assert_eq!(dst, "sandbox-q:/c/d/");
    }

    /// `--mkpath` is present in the create-time-push argv (Phase 3
    /// picks the rsync-driven parent-create path per the design
    /// directory creation, since base + lite images ship rsync ≥
    /// 3.2.7). Operator-driven push/pull opts out via
    /// `mkpath: false` because the destination should already exist.
    #[test]
    fn build_argv_always_includes_mkpath() {
        for backend in [BackendKind::Lima, BackendKind::Container] {
            for no_gitignore in [false, true] {
                let argv = build_workspace_rsync_argv(&push_opts(
                    backend,
                    "sandbox-mk",
                    "/x",
                    "/y",
                    no_gitignore,
                ));
                assert!(
                    argv.iter().any(|a| a == "--mkpath"),
                    "--mkpath missing for backend={backend:?} no_gitignore={no_gitignore}: {argv:?}"
                );
            }
        }
    }

    /// The destination remote-spec uses the `sandbox-<id>` prefix the
    /// backends accept on the shell transport (`limactl shell
    /// sandbox-<id>`, `docker exec sandbox-<id>`). The session name is
    /// passed in verbatim by the caller; this test pins the
    /// `<name>:<path>` join shape.
    #[test]
    fn build_argv_uses_session_name_prefix_in_destination() {
        let argv = build_workspace_rsync_argv(&push_opts(
            BackendKind::Lima,
            "sandbox-7f3e9a1b",
            "/home/op/code",
            "/home/sandbox/workspace",
            false,
        ));
        let dst = argv.last().expect("dst arg");
        assert!(
            dst.starts_with("sandbox-7f3e9a1b:"),
            "destination missing sandbox-<id> prefix: {dst}"
        );
        assert!(
            dst.ends_with(":/home/sandbox/workspace/"),
            "destination missing :<guest>/ tail: {dst}"
        );
    }

    /// macOS lite openrsync pre-mkdir: `docker exec <ctr> mkdir -p <guest>`.
    /// The container name is the `sandbox-<id>` session name (the same token
    /// the rsync remote spec uses) and the guest path is passed verbatim.
    /// This is the up-front directory create that replaces `--mkpath` on
    /// Apple openrsync.
    ///
    /// Which Docker daemon hears it is the route's decision, so the op names
    /// no target — asserted here because the pre-mkdir reaching the host
    /// instead of the VM would create a directory in the wrong filesystem and
    /// then fail the push with a confusing error.
    #[test]
    fn premkdir_op_targets_the_container_by_name_only() {
        let argv = DockerOp::ContainerExec {
            name: "sandbox-mac1".to_string(),
            command: ContainerCommand::MakeDirectory {
                path: "/home/sandbox/workspace".to_string(),
            },
        }
        .argv()
        .expect("pre-mkdir renders");
        assert_eq!(
            argv,
            vec![
                "exec",
                "sandbox-mac1",
                "mkdir",
                "-p",
                "/home/sandbox/workspace",
            ]
        );
        assert!(!argv.iter().any(|a| a == "-H"));
    }

    /// The macOS-lite shape of `run_initial_push` (`docker_socket = Some`)
    /// must NOT emit `--mkpath` — Apple openrsync rejects it. The builder
    /// is exercised directly with `mkpath: false` here (the value
    /// `run_initial_push` computes from `docker_socket.is_some()`), pinning
    /// that the openrsync-safe argv carries no `--mkpath`.
    #[test]
    fn macos_lite_push_argv_omits_mkpath() {
        let mut opts = push_opts(
            BackendKind::Container,
            "sandbox-mac1",
            "/srv/proj",
            "/home/sandbox/workspace",
            false,
        );
        opts.docker_socket = Some("/var/lib/sandboxd/501/gateway-docker.sock".to_string());
        opts.mkpath = false; // run_initial_push sets this when docker_socket.is_some()
        let argv = build_workspace_rsync_argv(&opts);
        assert!(
            !argv.iter().any(|a| a == "--mkpath"),
            "macOS lite (openrsync) push argv must omit --mkpath: {argv:?}"
        );
        // The forwarded-socket transport is still present.
        let e_idx = argv.iter().position(|a| a == "-e").expect("-e present");
        assert_eq!(
            argv[e_idx + 1],
            "docker -H unix:///var/lib/sandboxd/501/gateway-docker.sock exec -i",
        );
    }

    /// `Direction::Pull` swaps the src/dst operands: the remote spec
    /// (`sandbox-<id>:<guest>/`) sits in the src position, and the
    /// host path (`<host>/`) sits in the dst position. This is the
    /// new exit point that the daemon/CLI builder consolidation
    /// enables; the daemon-side `build_argv` only ever produced Push.
    #[test]
    fn build_argv_pull_swaps_src_and_dst() {
        let argv = build_workspace_rsync_argv(&WorkspaceRsyncOptions {
            backend: BackendKind::Lima,
            custom_transport: None,
            docker_socket: None,
            session_name: "sandbox-pull1".to_string(),
            host_path: "/home/op/work".to_string(),
            guest_path: "/home/sandbox/workspace".to_string(),
            direction: Direction::Pull,
            no_gitignore: false,
            dry_run: false,
            safe_links: false,
            // Operator-driven pull leaves `--mkpath` off; the host
            // destination already exists by precondition.
            mkpath: false,
        });
        assert_eq!(
            argv,
            vec![
                "-aL",
                "--delete",
                "--filter=:- .gitignore",
                "-e",
                LIMACTL_SHELL_TOKEN,
                "sandbox-pull1:/home/sandbox/workspace/",
                "/home/op/work/",
            ]
        );
    }
}
