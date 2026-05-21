//! Daemon-side `rsync` orchestration for `local:` workspace mode.
//!
//! Exports [`run_initial_push`], the async function that
//! `sandboxd::create_session` invokes after the VM/container reaches
//! `Running` to mirror the host workspace into the guest. The module is
//! deliberately small and free of `sandboxd`-internal types so the
//! same primitives can later back operator-driven `sandbox workspace
//! push/pull` from a CLI-side planner.
//!
//! ## Argv shape
//!
//! Per spec § Default rsync invocation:
//!
//! ```text
//! rsync -aL --delete --filter=':- .gitignore' \
//!   -e <shell-transport> --mkpath \
//!   <host>/ sandbox-<id>:<guest>/
//! ```
//!
//! where `<shell-transport>` is `limactl shell` (Lima) or
//! `docker exec -i` (container). The `--filter=':- .gitignore'` flag is
//! dropped when `no_gitignore == true`. Both `<host>` and `<guest>` are
//! given trailing `/` per spec § Trailing-slash rule so rsync mirrors
//! directory contents rather than the directory entry itself.
//! `--mkpath` (rsync ≥ 3.2.3) delegates parent-directory creation to
//! rsync; the base + lite images ship rsync 3.2.7+ via cloud-init.
//!
//! ## Cancellation
//!
//! The spawned `rsync` child is tagged `kill_on_drop(true)`. When the
//! HTTP request future is dropped (operator Ctrl+C, daemon SIGTERM
//! during graceful shutdown, CLI HTTP timeout), `tokio::process::Child`
//! sends `SIGKILL` to the rsync process — see spec § Cancellation and
//! timeout.
//!
//! ## Error mapping
//!
//! Non-zero rsync exits collapse to
//! `SandboxError::Internal(format!("local-workspace rsync failed (exit
//! {code}): {stderr}"))` per spec § Rsync invocation → Exit codes.
//! All non-zero exits are fatal (codes 23 "partial transfer" and 24
//! "vanished source" are not special-cased — the uniform "all-non-zero-
//! fatal" rule keeps the contract simple). The captured stderr is
//! decoded lossy (UTF-8 with U+FFFD replacement chars) so binary noise
//! never panics the error path.

use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::info;

use crate::backend::BackendKind;
use crate::error::SandboxError;

/// Build the rsync argv for an initial host→guest push.
///
/// Pure function — no I/O, no spawning. Factored out of
/// [`run_initial_push`] so the argv shape is unit-testable without
/// rsync, Lima, or Docker on `$PATH`. The wire shape is pinned by the
/// inline tests below.
fn build_argv(
    backend: BackendKind,
    session_name: &str,
    host_path: &str,
    guest_path: &str,
    no_gitignore: bool,
) -> Vec<String> {
    // Shell-transport: `-e <transport>` slots in as rsync's remote-shell
    // exec, matching the convention `plan_sync_command` uses for
    // operator-driven `sandbox sync` in the CLI.
    let transport = match backend {
        BackendKind::Lima => "limactl shell",
        // `-i` forwards stdin into the container so rsync can speak its
        // binary protocol both ways. No `-t` — a TTY would line-buffer
        // and corrupt the wire format. Mirrors `plan_sync_command`.
        BackendKind::Container => "docker exec -i",
    };

    // Trailing-slash rule (spec § Trailing-slash rule): both endpoints
    // always carry `/` so rsync mirrors the *contents* of the directory
    // rather than the directory entry itself. We always append, even if
    // the caller already passed a slash, because `rsync` tolerates the
    // doubled trailing slash and the uniform "always append" rule keeps
    // the builder branch-free.
    let host_arg = if host_path.ends_with('/') {
        host_path.to_string()
    } else {
        format!("{host_path}/")
    };
    let guest_with_slash = if guest_path.ends_with('/') {
        guest_path.to_string()
    } else {
        format!("{guest_path}/")
    };
    let dst_arg = format!("{session_name}:{guest_with_slash}");

    let mut argv: Vec<String> = vec![
        // `-a` — archive (perms, ownership, times, recursion). `-L` —
        // follow symlinks during transfer (copy resolved files). Same
        // baseline the spec defines for both create-time push and
        // operator-driven push/pull.
        "-aL".to_string(),
        // `--delete` — mirror semantics: destination entries absent on
        // the source are removed. Combined with `--filter`, gitignored
        // destination entries are protected from deletion (spec §
        // Default rsync invocation).
        "--delete".to_string(),
    ];
    if !no_gitignore {
        // Per-directory merge of `.gitignore` files; matched entries are
        // excluded from both transfer and deletion consideration. Spec
        // § Filter interaction documents the operator-facing semantics.
        argv.push("--filter=:- .gitignore".to_string());
    }
    argv.push("-e".to_string());
    argv.push(transport.to_string());
    // `--mkpath` lets rsync create missing parent directories on the
    // destination (rsync ≥ 3.2.3). Both the Lima base image and the
    // lite container image ship rsync 3.2.7+ (Ubuntu 24.04 noble) per
    // the `REQUIRED` cloud-init declaration in `lima.rs`.
    argv.push("--mkpath".to_string());
    argv.push(host_arg);
    argv.push(dst_arg);
    argv
}

/// Run the create-time `rsync` push from a host directory into the
/// guest.
///
/// Blocking from the caller's perspective — the future does not resolve
/// until rsync exits or the future is dropped. Drop semantics: the
/// underlying [`tokio::process::Child`] is tagged `kill_on_drop(true)`,
/// so a dropped request future tears the rsync child down via
/// `SIGKILL` (spec § Cancellation and timeout).
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
    let argv = build_argv(backend, session_name, host_path, guest_path, no_gitignore);

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
        // Request future drop ⇒ child killed. Spec § Cancellation and
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
    // transfer summaries (spec § Rsync invocation → Stdout). Stderr is
    // accumulated for the error path so non-zero exits can surface the
    // operator-facing diagnostic verbatim (spec § Rsync invocation →
    // Stderr).
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Lima backend with default gitignore filter: argv carries the
    /// `limactl shell` transport, the `--filter=:- .gitignore` flag, and
    /// the `sandbox-<id>:<guest>/` destination form.
    #[test]
    fn build_argv_lima_default_filter() {
        let argv = build_argv(
            BackendKind::Lima,
            "sandbox-abc123",
            "/home/op/work",
            "/home/agent/workspace",
            false,
        );
        assert_eq!(
            argv,
            vec![
                "-aL",
                "--delete",
                "--filter=:- .gitignore",
                "-e",
                "limactl shell",
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
        let argv = build_argv(
            BackendKind::Container,
            "sandbox-def456",
            "/srv/proj",
            "/home/agent/workspace",
            false,
        );
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
        let argv = build_argv(
            BackendKind::Lima,
            "sandbox-ghi789",
            "/data/x",
            "/home/agent/workspace",
            true,
        );
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
                "limactl shell",
                "--mkpath",
                "/data/x/",
                "sandbox-ghi789:/home/agent/workspace/",
            ]
        );
    }

    /// Trailing-slash rule (spec § Trailing-slash rule): both source
    /// and destination always end with `/`. This test pins the rule
    /// when the caller passes paths *without* trailing slashes — the
    /// builder must append them.
    #[test]
    fn build_argv_appends_trailing_slash_to_both_endpoints() {
        let argv = build_argv(BackendKind::Lima, "sandbox-xyz", "/a/b", "/c/d", false);
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
        let argv = build_argv(BackendKind::Container, "sandbox-q", "/a/b/", "/c/d/", false);
        let src = argv.iter().rev().nth(1).expect("src arg");
        let dst = argv.last().expect("dst arg");
        assert_eq!(src, "/a/b/");
        assert_eq!(dst, "sandbox-q:/c/d/");
    }

    /// `--mkpath` is unconditionally present in the argv (Phase 3 picks
    /// the rsync-driven parent-create path per spec § Parent-directory
    /// creation, since base + lite images ship rsync ≥ 3.2.7).
    #[test]
    fn build_argv_always_includes_mkpath() {
        for backend in [BackendKind::Lima, BackendKind::Container] {
            for no_gitignore in [false, true] {
                let argv = build_argv(backend, "sandbox-mk", "/x", "/y", no_gitignore);
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
        let argv = build_argv(
            BackendKind::Lima,
            "sandbox-7f3e9a1b",
            "/home/op/code",
            "/home/agent/workspace",
            false,
        );
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
}
