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

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::info;

use crate::backend::BackendKind;
use crate::error::SandboxError;
use crate::process::run_with_timeout;

/// Caller-side rsync `-e` transport token for Lima sessions.
/// Passed to rsync as the remote-shell argument; rsync (running as the
/// operator uid on the CLI side) exec's `limactl shell <vm> <cmd>`.
/// The daemon never spawns this command directly — this is a string
/// token in an argv array built for rsync, not a daemon `Command::new`.
const LIMACTL_SHELL_TOKEN: &str = "limactl shell";

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
/// - `backend` — picks the rsync shell-transport (`-e <shell>`) value:
///   `"limactl shell"` for Lima, `"docker exec -i"` for container.
///   Mirrors the convention `plan_sync_command` uses.
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
///   The initial create-time push uses `mkpath = true`; operator-
///   driven push/pull typically uses `false` because the destination
///   should already exist.
#[derive(Debug, Clone)]
pub struct WorkspaceRsyncOptions {
    pub backend: BackendKind,
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
    let transport = match opts.backend {
        BackendKind::Lima => LIMACTL_SHELL_TOKEN,
        // `-i` forwards stdin into the container so rsync can speak
        // its binary protocol both ways. No `-t` — a TTY would line-
        // buffer and corrupt the wire format. Mirrors
        // `plan_sync_command`.
        BackendKind::Container => "docker exec -i",
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
    argv.push(transport.to_string());
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
pub async fn run_initial_push(
    backend: BackendKind,
    session_name: &str,
    host_path: &str,
    guest_path: &str,
    no_gitignore: bool,
) -> Result<(), SandboxError> {
    // Create-time push is fixed-shape: host → guest direction,
    // `--mkpath` enabled so rsync materialises the guest workspace
    // root, no dry-run, no safe-links toggle. Operator-driven push/
    // pull (CLI side) builds the same options struct with different
    // flags but goes through the same shared builder.
    let argv = build_workspace_rsync_argv(&WorkspaceRsyncOptions {
        backend,
        session_name: session_name.to_string(),
        host_path: host_path.to_string(),
        guest_path: guest_path.to_string(),
        direction: Direction::Push,
        no_gitignore,
        dry_run: false,
        safe_links: false,
        mkpath: true,
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
    helper_path: &Path,
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

    let backend_str = match backend {
        BackendKind::Lima => "lima",
        BackendKind::Container => "container",
    };

    let helper_path = helper_path.to_owned();
    let op_uid_str = op_uid.to_string();
    let session_name = session_name.to_owned();
    let host_path = host_path.to_owned();
    let guest_path = guest_path.to_owned();

    let result = tokio::task::spawn_blocking(move || {
        let mut cmd = std::process::Command::new(&helper_path);
        cmd.arg("run-rsync")
            .arg("--op-uid")
            .arg(&op_uid_str)
            .arg("--backend")
            .arg(backend_str)
            .arg("--session-name")
            .arg(&session_name)
            .arg("--host-path")
            .arg(&host_path)
            .arg("--guest-path")
            .arg(&guest_path);
        if no_gitignore {
            cmd.arg("--no-gitignore");
        }
        run_with_timeout(
            &mut cmd,
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
            "/home/agent/workspace",
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
                "sandbox-abc123:/home/agent/workspace/",
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
            "/home/agent/workspace",
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
                "sandbox-def456:/home/agent/workspace/",
            ]
        );
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
            "/home/agent/workspace",
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
                "sandbox-ghi789:/home/agent/workspace/",
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
            "/home/agent/workspace",
            false,
        ));
        let dst = argv.last().expect("dst arg");
        assert!(
            dst.starts_with("sandbox-7f3e9a1b:"),
            "destination missing sandbox-<id> prefix: {dst}"
        );
        assert!(
            dst.ends_with(":/home/agent/workspace/"),
            "destination missing :<guest>/ tail: {dst}"
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
            session_name: "sandbox-pull1".to_string(),
            host_path: "/home/op/work".to_string(),
            guest_path: "/home/agent/workspace".to_string(),
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
                "sandbox-pull1:/home/agent/workspace/",
                "/home/op/work/",
            ]
        );
    }
}
