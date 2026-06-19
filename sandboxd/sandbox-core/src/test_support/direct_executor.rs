/// macOS integration-test Lima executor that calls `limactl` directly.
///
/// Mirrors `broker::run_limactl_direct` in the daemon crate: env-clear,
/// LIMA_HOME, PATH prepend, umask 0o077, then `limactl <args>`.
///
/// This is the degenerate single-uid path: the test process runs as the
/// operator, so `op_uid == current uid` and no privilege pivot is needed.
/// Only valid on macOS — the `sandbox-lima-helper` used on Linux is a
/// separate binary not present on the macOS host.
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::backend::AsyncReadWrite;
use crate::error::SandboxError;
use crate::lima::{LimaExecutor, LimaOp, operator_lima_home};
use crate::process::run_with_timeout;

/// Direct `limactl` executor for integration tests.
///
/// Calls `limactl` in the current process context using `run_limactl_direct`
/// semantics. Only valid when `op_uid == current_uid`.
pub struct DirectLimaExecutor;

impl DirectLimaExecutor {
    /// Return a shared reference to a new `DirectLimaExecutor` as a boxed
    /// `LimaExecutor` trait object. Named `arc` rather than `new` because the
    /// return type is `Arc<dyn LimaExecutor>`, not `Self`.
    pub fn arc() -> Arc<dyn LimaExecutor> {
        Arc::new(Self)
    }
}

#[async_trait]
impl LimaExecutor for DirectLimaExecutor {
    fn run(
        &self,
        op_uid: u32,
        op: LimaOp<'_>,
        timeout: Duration,
        label: &str,
    ) -> Result<std::process::Output, SandboxError> {
        run_limactl_direct(op_uid, op, timeout, label)
    }

    async fn guest_socat(
        &self,
        op_uid: u32,
        vm: &str,
    ) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>, SandboxError> {
        use tokio::process::Command;

        let lima_home = operator_lima_home(op_uid);
        let lima_home_str = lima_home.to_string_lossy().into_owned();
        let current_path = std::env::var("PATH").unwrap_or_default();
        let path_value = format!("/opt/homebrew/bin:/usr/local/bin:{current_path}");
        let home = std::env::var("HOME").unwrap_or_default();

        let mut child = Command::new("limactl")
            .args(["shell", vm, "--", "socat", "-", "TCP:127.0.0.1:5123"])
            .env_clear()
            .env("LIMA_HOME", &lima_home_str)
            .env("PATH", &path_value)
            .env("HOME", &home)
            .env("TERM", "dumb")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                SandboxError::Internal(format!("failed to spawn limactl shell socat: {e}"))
            })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| SandboxError::Internal("limactl socat: no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SandboxError::Internal("limactl socat: no stdout".into()))?;

        Ok(Box::new(DirectSocatStream {
            stdin,
            stdout,
            _child: child,
        }))
    }
}

/// Run a `limactl` operation directly as the current user.
///
/// Mirrors `broker::run_limactl_direct` (env-clear, LIMA_HOME, PATH, HOME).
/// Only the operations needed by integration tests are translated; missing
/// ops return an error rather than silently producing incorrect behaviour.
fn run_limactl_direct(
    op_uid: u32,
    op: LimaOp<'_>,
    timeout: Duration,
    label: &str,
) -> Result<std::process::Output, SandboxError> {
    let lima_home = operator_lima_home(op_uid);
    let lima_home_str = lima_home.to_string_lossy().into_owned();
    let current_path = std::env::var("PATH").unwrap_or_default();
    let path_value = format!("/opt/homebrew/bin:/usr/local/bin:{current_path}");
    let home = std::env::var("HOME").unwrap_or_default();

    let mut cmd = std::process::Command::new("limactl");
    cmd.env_clear()
        .env("LIMA_HOME", &lima_home_str)
        .env("PATH", &path_value)
        .env("HOME", &home)
        .env("TERM", "dumb");

    // Note: the production path (broker::run_limactl_direct) sets umask 0o077
    // via pre_exec so SSH key files land at mode 0600. Integration tests do
    // not check file modes, so we skip the umask here to avoid pulling libc
    // (which is not a sandbox-core dependency) or hand-rolling an unsafe
    // extern block that would require `unsafe extern` in Rust edition 2024.

    match op {
        LimaOp::Create { vm, yaml_path, .. } => {
            cmd.args([
                "create",
                "--name",
                vm,
                &yaml_path.to_string_lossy(),
                "--tty=false",
            ]);
        }
        LimaOp::Start {
            vm,
            qemu_wrapper,
            hardened,
            memory_mb,
            cpus,
            start_timeout_s,
            bridge,
            unrestricted_slirp_for_provisioning,
        } => {
            let timeout_flag = format!("--timeout={start_timeout_s}s");
            cmd.args(["start", vm, &timeout_flag, "--tty=false"]);

            let wrapper_str = qemu_wrapper.to_string_lossy().into_owned();
            if !wrapper_str.is_empty() {
                cmd.env("QEMU_SYSTEM_AARCH64", &wrapper_str);
                // Set SANDBOX_RESTRICT_MARKER so the wrapper writes the
                // rewritten -netdev token for verify_restrict_on.
                let marker = format!("{lima_home_str}/{vm}/sandboxd-restrict-marker");
                cmd.env("SANDBOX_RESTRICT_MARKER", &marker);
            }
            let hardened_str = if hardened { "1" } else { "0" };
            cmd.env("SANDBOX_QEMU_HARDENED", hardened_str)
                .env("SANDBOX_QEMU_MEMORY_MB", memory_mb.to_string())
                .env("SANDBOX_QEMU_CPUS", cpus.to_string());
            if let Some((bridge_name, vm_mac)) = bridge {
                cmd.env("SANDBOX_DOCKER_BRIDGE", bridge_name)
                    .env("SANDBOX_VM_MAC", vm_mac);
                if unrestricted_slirp_for_provisioning {
                    cmd.env("SANDBOX_UNRESTRICTED_SLIRP_FOR_PROVISIONING", "1");
                }
            }
        }
        LimaOp::Stop { vm, force } => {
            if force {
                cmd.args(["stop", "--force", vm, "--tty=false"]);
            } else {
                cmd.args(["stop", vm, "--tty=false"]);
            }
        }
        LimaOp::Delete { vm } => {
            cmd.args(["delete", "--force", vm, "--tty=false"]);
        }
        LimaOp::Clone {
            base,
            vm,
            cpus,
            memory_gib,
            disk_gb,
            ..
        } => {
            cmd.args([
                "clone",
                base,
                vm,
                &format!("--cpus={cpus}"),
                &format!("--memory={memory_gib}"),
                &format!("--disk={disk_gb}"),
            ]);
        }
        LimaOp::ListJson => {
            cmd.args(["list", "--json"]);
        }
        LimaOp::InstallGuestAgent { vm } => {
            cmd.args([
                "shell",
                vm,
                "--",
                "sudo",
                "/usr/local/bin/sandbox-install-guest-agent",
            ]);
        }
        LimaOp::ReadUserKey => {
            // Not used in integration tests. Return empty success.
            return Ok(std::process::Output {
                status: std::process::ExitStatus::default(),
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
        }
        LimaOp::RunRsync { .. } => {
            return Err(SandboxError::Internal(
                "DirectLimaExecutor: RunRsync not supported in integration tests".into(),
            ));
        }
        LimaOp::ReadOwnerMarker { vm } => {
            let marker = format!("{lima_home_str}/{vm}/sandboxd-owner");
            match std::fs::read_to_string(&marker) {
                Ok(contents) => {
                    return Ok(std::process::Output {
                        status: std::process::ExitStatus::default(),
                        stdout: contents.into_bytes(),
                        stderr: Vec::new(),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    use std::os::unix::process::ExitStatusExt;
                    return Ok(std::process::Output {
                        status: std::process::ExitStatus::from_raw(1 << 8),
                        stdout: Vec::new(),
                        stderr: format!("not found: {marker}").into_bytes(),
                    });
                }
                Err(e) => {
                    return Err(SandboxError::Internal(format!(
                        "read owner marker {marker}: {e}"
                    )));
                }
            }
        }
        LimaOp::RestrictOnVerify { vm } => {
            // Integration-test path: read the wrapper marker file directly,
            // matching the SetuidHelperExecutor fallback on Linux.
            let marker = format!("{lima_home_str}/{vm}/sandboxd-restrict-marker");
            match std::fs::read_to_string(&marker) {
                Ok(contents) if contents.contains("restrict=on") => {
                    return Ok(std::process::Output {
                        status: std::process::ExitStatus::default(),
                        stdout: contents.trim().as_bytes().to_vec(),
                        stderr: Vec::new(),
                    });
                }
                Ok(contents) => {
                    return Err(SandboxError::Internal(format!(
                        "{label}: restrict marker at {marker} does not contain 'restrict=on'; \
                         contents: {contents:?}"
                    )));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(SandboxError::Internal(format!(
                        "{label}: restrict marker not found at {marker}"
                    )));
                }
                Err(e) => {
                    return Err(SandboxError::Internal(format!(
                        "{label}: failed to read restrict marker at {marker}: {e}"
                    )));
                }
            }
        }
    }

    run_with_timeout(&mut cmd, timeout, label)
}

// ---------------------------------------------------------------------------
// Socat stream type (mirrors LimaHelperSocatStream in lima.rs)
// ---------------------------------------------------------------------------

struct DirectSocatStream {
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    _child: tokio::process::Child,
}

impl tokio::io::AsyncRead for DirectSocatStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for DirectSocatStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stdin).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdin).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

// AsyncReadWrite is implemented automatically via the blanket impl in backend::mod.rs
// (impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}).
