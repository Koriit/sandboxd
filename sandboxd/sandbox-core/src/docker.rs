//! Typed Docker operations and the seam that executes them.
//!
//! # Why a seam
//!
//! On Linux the daemon and the Docker daemon it drives share a host: a bare
//! `docker` invocation reaches the right place and the daemon's own uid is
//! the authority. On macOS there is no host Docker at all — every container,
//! network, volume and image lives inside a Lima VM, and once that VM belongs
//! to an operator rather than to `_sandboxd` the daemon cannot open its
//! socket. The work has to be asked for rather than done.
//!
//! [`DockerOp`] is the vocabulary of that request and [`DockerExecutor`] is
//! the seam that carries it. The set is closed on purpose: the daemon names
//! an operation and supplies its typed field values, and the side that runs
//! `docker` builds the command line. There is deliberately **no** variant
//! carrying an argv, a shell string, or a free-form format template — a
//! single such variant would make every other one decorative, because a
//! compromised daemon could ask the operator's account to run anything.
//!
//! # How a call site chooses
//!
//! A call site holds a [`DockerRoute`], not a socket path. `Host` is the
//! Linux shape and runs `docker` locally, with the ambient environment left
//! alone. `Vm` carries the operator uid and an executor; whether that
//! executor runs `docker` itself (the daemon is the operator) or forwards the
//! op to the operator's agent is the executor's business, not the call site's.
//!
//! The two routes treat the environment differently on purpose — see the
//! environment rule on [`DockerRoute`] before changing either.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sandbox_docker_argv::container::{
    ContainerCommand, ContainerCreateSpec, InspectFlag, InspectFormat, RemoveForce,
};
use sandbox_docker_argv::gateway::StdinCommand;
use sandbox_docker_argv::image::StagedImage;
use sandbox_docker_argv::network::NetworkCreateSpec;

use crate::error::SandboxError;

/// The closed set of Docker operations the daemon may request.
///
/// In-process representation — the wire-serializable counterpart lives in the
/// broker protocol crate and is mapped from this one by an exhaustive match,
/// so a variant added here without a wire mapping is a compile error rather
/// than a silent gap.
///
/// Owned rather than borrowed, unlike its Lima sibling. Every caller hands
/// an op to `spawn_blocking`, which requires `'static`; a borrowed op would
/// push that lifetime problem out to two dozen call sites in exchange for
/// allocations nobody can measure at these frequencies.
#[derive(Debug, Clone)]
pub enum DockerOp {
    // -- Container lifecycle -------------------------------------------------
    /// Create a session container from its typed specification.
    ContainerCreate { spec: ContainerCreateSpec },
    /// Start an existing container.
    ContainerStart { name: String },
    /// Stop a running container, giving it `grace_secs` to exit.
    ContainerStop {
        name: String,
        grace_secs: u32,
        /// Which spelling of the grace-period flag this call site uses.
        long_flag: bool,
    },
    /// Restart a container in place.
    ContainerRestart { name: String },
    /// Remove a container.
    ContainerRemove { name: String, force: RemoveForce },
    /// Read one enumerated field of a container's state.
    ContainerInspect {
        name: String,
        format: InspectFormat,
        flag: InspectFlag,
    },
    /// List container names matching a name prefix and, optionally, an owner
    /// pool label.
    ContainerList {
        name_prefix: String,
        owner_pool: Option<String>,
    },
    /// Run one of the enumerated commands inside a container.
    ContainerExec {
        name: String,
        command: ContainerCommand,
    },
    /// Run one of the enumerated stdin-fed commands inside a container,
    /// with `body` on its standard input.
    ///
    /// This is the shape the egress-plane artifacts travel in: an nftables
    /// ruleset or a policy file is too large for an argv and contains
    /// newlines, so it goes to the child's stdin. `command` is a closed
    /// enum and `body` is data — the child reads it as content, never as a
    /// command line.
    ContainerExecStdin {
        name: String,
        command: StdinCommand,
        body: String,
    },
    /// Run the one-shot init container that chowns a session's home volume.
    HomeVolumeChown {
        session_id: String,
        image_tag: String,
        operator_uid: u32,
        operator_gid: u32,
    },
    /// Run a session's gateway container.
    GatewayContainerRun {
        session_id: String,
        image_tag: String,
        network: String,
        owner_pool: Option<String>,
        coredns_upstream: Option<String>,
    },

    // -- Network lifecycle ---------------------------------------------------
    /// Create a Docker network from its typed specification.
    NetworkCreate { spec: NetworkCreateSpec },
    /// Remove a Docker network.
    NetworkRemove { name: String },
    /// Inspect a Docker network (presence check).
    NetworkInspect { name: String },
    /// Attach a container to a network, optionally pinning its address.
    NetworkConnect {
        network: String,
        container: String,
        ip: Option<String>,
    },
    /// List network names matching a prefix and, optionally, an owner pool.
    NetworkList {
        name_prefix: String,
        owner_pool: Option<String>,
    },

    // -- Volume lifecycle ----------------------------------------------------
    /// Create a named volume with the session and owner labels.
    VolumeCreate {
        name: String,
        session_id: Option<String>,
        owner_pool: Option<String>,
    },
    /// Remove a named volume.
    VolumeRemove { name: String },
    /// List volume names matching a prefix and, optionally, an owner pool.
    VolumeList {
        name_prefix: String,
        owner_pool: Option<String>,
    },

    // -- Image lifecycle -----------------------------------------------------
    /// Check whether an image tag is present.
    ImageInspect { tag: String },
    /// Load one of the staged image tarballs into the target daemon.
    ///
    /// The tarball is streamed from the staging directory into the child's
    /// stdin by whichever side runs the command; which tarball is named by
    /// the enum, not by a path the daemon supplies.
    ImageLoad { image: StagedImage },

    // -- Daemon --------------------------------------------------------------
    /// Probe that the target Docker daemon answers.
    DaemonInfo,
}

impl DockerOp {
    /// The argv following the program name, with no `-H` prefix.
    ///
    /// Both sides of the seam render an op through this function, so the
    /// daemon's idea of an op and the agent's cannot drift.
    pub fn argv(&self) -> Result<Vec<String>, SandboxError> {
        use sandbox_docker_argv::{container, image, network, volume};

        let argv = match self {
            DockerOp::ContainerCreate { spec } => container::container_create_argv(spec)
                .map_err(|e| SandboxError::InvalidArgument(e.into_message()))?,
            DockerOp::ContainerStart { name } => container::container_start_argv(name),
            DockerOp::ContainerStop {
                name,
                grace_secs,
                long_flag,
            } => {
                if *long_flag {
                    container::container_stop_long_argv(name, *grace_secs)
                } else {
                    container::container_stop_argv(name, *grace_secs)
                }
            }
            DockerOp::ContainerRestart { name } => container::container_restart_argv(name),
            DockerOp::ContainerRemove { name, force } => {
                container::container_remove_argv(name, *force)
            }
            DockerOp::ContainerInspect { name, format, flag } => {
                container::container_inspect_argv(name, *format, *flag)
            }
            DockerOp::ContainerList {
                name_prefix,
                owner_pool,
            } => container::container_list_argv(name_prefix, owner_pool.as_deref()),
            DockerOp::ContainerExec { name, command } => {
                container::container_exec_argv(name, command)
            }
            DockerOp::ContainerExecStdin { name, command, .. } => {
                container::container_exec_stdin_argv(name, *command)
            }
            DockerOp::HomeVolumeChown {
                session_id,
                image_tag,
                operator_uid,
                operator_gid,
            } => {
                container::home_chown_run_argv(session_id, image_tag, *operator_uid, *operator_gid)
            }
            DockerOp::GatewayContainerRun {
                session_id,
                image_tag,
                network: net,
                owner_pool,
                coredns_upstream,
            } => container::gateway_container_run_argv(
                session_id,
                image_tag,
                net,
                owner_pool.as_deref(),
                coredns_upstream.as_deref(),
            ),
            DockerOp::NetworkCreate { spec } => network::network_create_argv(spec),
            DockerOp::NetworkRemove { name } => network::network_remove_argv(name),
            DockerOp::NetworkInspect { name } => network::network_inspect_argv(name),
            DockerOp::NetworkConnect {
                network: net,
                container: ctr,
                ip,
            } => network::network_connect_argv(net, ctr, ip.as_deref()),
            DockerOp::NetworkList {
                name_prefix,
                owner_pool,
            } => network::network_list_argv(name_prefix, owner_pool.as_deref()),
            DockerOp::VolumeCreate {
                name,
                session_id,
                owner_pool,
            } => volume::volume_create_argv(name, session_id.as_deref(), owner_pool.as_deref()),
            DockerOp::VolumeRemove { name } => volume::volume_remove_argv(name),
            DockerOp::VolumeList {
                name_prefix,
                owner_pool,
            } => volume::volume_list_argv(name_prefix, owner_pool.as_deref()),
            DockerOp::ImageInspect { tag } => image::image_inspect_argv(tag),
            DockerOp::ImageLoad { .. } => image::image_load_argv(),
            DockerOp::DaemonInfo => image::daemon_info_argv(),
        };
        Ok(argv)
    }

    /// The staged tarball this op streams on stdin, if any.
    ///
    /// Only `ImageLoad` has one. Returning it here rather than making every
    /// executor match on the variant keeps the stdin decision in one place.
    pub fn stdin_tarball(&self) -> Option<StagedImage> {
        match self {
            DockerOp::ImageLoad { image } => Some(*image),
            _ => None,
        }
    }

    /// The artifact this op writes to the child's standard input, if any.
    ///
    /// Distinct from [`Self::stdin_tarball`], which names a file the
    /// executing side opens: this one is content the daemon supplied and
    /// the op carries. Only the egress-plane writes have it.
    pub fn stdin_body(&self) -> Option<&str> {
        match self {
            DockerOp::ContainerExecStdin { body, .. } => Some(body),
            _ => None,
        }
    }
}

/// Runs typed Docker operations somewhere the caller cannot reach directly.
///
/// [`DockerExecutor::run`] is one-shot and blocking, matching
/// [`crate::lima::LimaExecutor::run`]: the caller wraps it in
/// `spawn_blocking`. [`DockerExecutor::open_stream`] is the opposite in every
/// respect and deliberately so — see its own documentation.
#[async_trait::async_trait]
pub trait DockerExecutor: Send + Sync {
    /// Run one op as `op_uid` and return the captured output.
    fn run(
        &self,
        op_uid: u32,
        op: DockerOp,
        timeout: Duration,
        label: &str,
    ) -> Result<std::process::Output, SandboxError>;

    /// Open one long-lived byte stream into a container as `op_uid`.
    ///
    /// # Why this one is async and has no timeout
    ///
    /// It is the async-I/O carve-out in trait form (`CLAUDE.md` § Async-I/O
    /// carve-out). The three streams this opens are held for as long as the
    /// thing at the far end lasts: an SSH session under a remote-development
    /// client runs for hours. A `spawn_blocking` wrapper would hold a
    /// blocking-task slot for that whole time and deadlock the executor under
    /// load, which is why `run`'s convention explicitly does not extend here.
    ///
    /// It takes no `timeout` for the same reason. A wall-clock budget on a
    /// stream would be a budget on the session inside it, and there is no
    /// value that is both long enough for a working SSH connection and short
    /// enough to catch anything. What *is* bounded is the **open**: the
    /// brokered implementation fails if the agent does not acknowledge within
    /// the control connection's per-op deadline, or does not connect back
    /// within the pending-stream timeout, and both of those fail the one op
    /// rather than the connection.
    async fn open_stream(
        &self,
        op_uid: u32,
        stream: DockerStream,
    ) -> Result<DockerStreamConn, SandboxError>;
}

/// The closed set of long-lived byte streams the daemon may open into a
/// container.
///
/// The in-process counterpart of the broker protocol's `DockerStreamOp`,
/// mapped by an exhaustive match for the same reason [`DockerOp`] is. There
/// is no variant carrying a port or a socket path: a stream is a raw byte
/// pipe, so the destination is the entire authority, and the three that exist
/// are the three the product has.
#[derive(Debug, Clone)]
pub enum DockerStream {
    /// The in-session `sandbox-guest` agent — sandboxd's structured guest
    /// protocol, one stream per guest request.
    GuestAgent { container: String },
    /// The in-session `sshd` behind the proxy WebSocket — one stream per SSH
    /// session, held open for its whole duration.
    Sshd { container: String },
    /// The gateway container's DNS-policy gate socket — one stream per DNS
    /// query, on the egress-allow decision path.
    DnsGate { container: String },
}

impl DockerStream {
    /// The container this stream enters.
    pub fn container(&self) -> &str {
        match self {
            DockerStream::GuestAgent { container }
            | DockerStream::Sshd { container }
            | DockerStream::DnsGate { container } => container,
        }
    }

    /// The in-container endpoint this stream reaches.
    pub fn target(&self) -> sandbox_docker_argv::stream::StreamTarget {
        use sandbox_docker_argv::stream::StreamTarget;
        match self {
            DockerStream::GuestAgent { .. } => StreamTarget::GuestAgent,
            DockerStream::Sshd { .. } => StreamTarget::Sshd,
            DockerStream::DnsGate { .. } => StreamTarget::DnsGate,
        }
    }

    /// The `docker` arguments that open this stream against `socket`.
    pub fn argv(&self, socket: Option<&Path>) -> Vec<String> {
        sandbox_docker_argv::stream::stream_exec_argv(socket, self.container(), self.target())
    }
}

/// An open long-lived stream, and — when this process ran the child itself —
/// the means to find out how it ended.
///
/// The two halves are separate because they have different lifetimes at
/// different call sites. The SSH proxy hands the bytes to a ferry that
/// consumes them and then wants the child's exit status to choose a WebSocket
/// close code; the guest transport wants the child kept alive for exactly as
/// long as the bytes are and no longer. Bundling the child into the byte
/// stream would serve the second and make the first impossible.
pub struct DockerStreamConn {
    /// The bytes. Dropping this alone does not reap the child — [`Self::exit`]
    /// owns it, and is `kill_on_drop`.
    pub io: Box<dyn crate::backend::AsyncReadWrite + Send + Unpin>,
    /// Present only when the stream is a child of *this* process. The
    /// brokered path leaves it `None`: the child belongs to the operator's
    /// agent, and the stream closing is the whole of what the daemon
    /// observes. A caller that reports on it must therefore treat `None` as
    /// "no diagnosis available", not as "clean".
    pub exit: Option<LocalStreamChild>,
}

/// The child process behind a locally-spawned [`DockerStreamConn`].
///
/// Held by the caller across the byte pump so the child stays alive for it
/// (`kill_on_drop` reaps it when the caller lets go) and so the caller can
/// ask how it ended afterwards.
pub struct LocalStreamChild {
    child: tokio::process::Child,
    stderr: Option<tokio::process::ChildStderr>,
}

impl LocalStreamChild {
    /// Reap the child and return its exit status and whatever it wrote to
    /// stderr.
    ///
    /// Callers interpret the pair themselves: what a non-zero exit means
    /// differs between a proxy session that ended and a gate listener whose
    /// container went away.
    pub async fn wait(mut self) -> (Option<std::process::ExitStatus>, Vec<u8>) {
        use tokio::io::AsyncReadExt;
        let status = self.child.wait().await.ok();
        let mut buf = Vec::new();
        if let Some(mut err) = self.stderr.take() {
            let _ = err.read_to_end(&mut buf).await;
        }
        (status, buf)
    }
}

/// Where a call site's `docker` operations go.
///
/// # The environment rule
///
/// **A route that names its target scrubs the environment. A route that does
/// not name a target inherits it.** The two variants below sit on opposite
/// sides of that rule, and the asymmetry is the rule working, not an
/// inconsistency in it.
///
/// Environment scrubbing exists for exactly one purpose here: to stop
/// anything ambient from overriding `-H`. That is worth doing only where
/// `-H` is load-bearing.
///
/// Getting it wrong in either direction has a specific consequence:
///
/// - **Scrub [`Self::Host`]** and the daemon stops addressing the Docker
///   the operator actually configured. Concretely, the rootless probe in
///   `container_rootless_probe` — which exists to *detect* rootless Docker
///   and refuse it — would fail to reach a rootless daemon at all and
///   report "Docker daemon unreachable" instead of the accurate
///   "rootless is unsupported"; the orphan reaper would enumerate an empty
///   host and silently reap nothing.
/// - **Fail to scrub [`Self::Vm`]** and the ambient environment becomes a
///   second channel for choosing the endpoint — one that bypasses the
///   socket-derivation invariant without touching the op set at all.
#[derive(Clone)]
pub enum DockerRoute {
    /// The host's own Docker daemon: no `-H`, and — deliberately — no
    /// environment scrubbing.
    ///
    /// This is the variant that is *supposed* to take its target from its
    /// surroundings: with no `-H`, the environment is how the client is told
    /// which daemon to talk to, and a rootless install says so through
    /// `DOCKER_HOST`.
    ///
    /// **Why opting out of a hardening measure is acceptable here.** This
    /// route runs in the daemon's own context, against the daemon's own
    /// Docker — no uid pivot, no other account's endpoint. The environment it
    /// inherits is the one the daemon's own launcher set, so it is not a
    /// privilege boundary: anyone who can write it can already run code as
    /// the daemon, and scrubbing it would take nothing away from them. The
    /// scrub on the other route is not optional for the same reason in
    /// reverse — there, `-H` names a Docker daemon belonging to a *different*
    /// account, and it is the only thing that says which.
    Host,
    /// A Docker daemon inside a VM, reached through the typed op seam.
    ///
    /// Invocations on this route name their target with `-H` and run with a
    /// scrubbed environment, per the rule on this enum.
    Vm {
        /// The operator whose VM hosts the daemon.
        op_uid: u32,
        executor: Arc<dyn DockerExecutor>,
    },
}

impl std::fmt::Debug for DockerRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DockerRoute::Host => f.write_str("DockerRoute::Host"),
            DockerRoute::Vm { op_uid, .. } => {
                write!(f, "DockerRoute::Vm {{ op_uid: {op_uid} }}")
            }
        }
    }
}

impl DockerRoute {
    /// Run one typed op on this route.
    ///
    /// Blocking; callers in async contexts wrap this in `spawn_blocking` per
    /// the project's `std::process::Command` convention.
    pub fn run(
        &self,
        op: DockerOp,
        timeout: Duration,
        label: &str,
    ) -> Result<std::process::Output, SandboxError> {
        match self {
            DockerRoute::Host => run_docker_locally(None, op, timeout, label),
            DockerRoute::Vm { op_uid, executor } => executor.run(*op_uid, op, timeout, label),
        }
    }

    /// Open one long-lived byte stream on this route.
    ///
    /// Async and un-budgeted, unlike [`Self::run`] — see
    /// [`DockerExecutor::open_stream`] for why both of those are deliberate,
    /// and `CLAUDE.md` § Async-I/O carve-out for the convention it departs
    /// from.
    pub async fn open_stream(
        &self,
        stream: DockerStream,
    ) -> Result<DockerStreamConn, SandboxError> {
        match self {
            DockerRoute::Host => open_stream_locally(None, stream).await,
            DockerRoute::Vm { op_uid, executor } => executor.open_stream(*op_uid, stream).await,
        }
    }

    /// Whether this route targets a VM rather than the host daemon.
    pub fn is_vm(&self) -> bool {
        matches!(self, DockerRoute::Vm { .. })
    }

    /// The operator uid this route runs as, or `None` for the host daemon.
    pub fn op_uid(&self) -> Option<u32> {
        match self {
            DockerRoute::Host => None,
            DockerRoute::Vm { op_uid, .. } => Some(*op_uid),
        }
    }
}

/// Runs typed ops against a Docker daemon this process can open itself.
///
/// This is the executor the daemon uses when the VM is its own — the
/// degenerate case where "act as the operator" and "act as yourself" are the
/// same thing. It is also what the daemon falls back to on a single-uid
/// foreground-dev host.
pub struct LocalSocketDockerExecutor {
    socket: PathBuf,
    /// Directory holding the staged image tarballs, for `ImageLoad`.
    staging_dir: PathBuf,
}

impl LocalSocketDockerExecutor {
    /// Target the Docker daemon reachable at `socket`, loading staged image
    /// tarballs from `staging_dir`.
    pub fn new(socket: impl Into<PathBuf>, staging_dir: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            staging_dir: staging_dir.into(),
        }
    }

    /// The socket this executor targets.
    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

#[async_trait::async_trait]
impl DockerExecutor for LocalSocketDockerExecutor {
    fn run(
        &self,
        _op_uid: u32,
        op: DockerOp,
        timeout: Duration,
        label: &str,
    ) -> Result<std::process::Output, SandboxError> {
        if let Some(image) = op.stdin_tarball() {
            let tarball = self.staging_dir.join(image.tarball_filename());
            return run_docker_load_locally(Some(&self.socket), &tarball, label);
        }
        run_docker_locally(Some(&self.socket), op, timeout, label)
    }

    async fn open_stream(
        &self,
        _op_uid: u32,
        stream: DockerStream,
    ) -> Result<DockerStreamConn, SandboxError> {
        open_stream_locally(Some(&self.socket), stream).await
    }
}

/// Spawn one long-lived `docker exec … socat` child in this process and hand
/// back its stdio as a stream.
///
/// **ASYNC-I/O CARVE-OUT.** `tokio::process::Command` with async pipes is
/// mandatory here and the project's `spawn_blocking` convention does not
/// apply: this child is held open for the life of the stream — an entire SSH
/// session for the `Sshd` target — so a blocking-task slot occupied for its
/// duration would deadlock the executor under load. See the carve-out
/// doc-comment in `sandboxd/src/proxy_http.rs` for the full rationale, and
/// `CLAUDE.md` § Async-I/O carve-out. Do not wrap this site.
async fn open_stream_locally(
    socket: Option<&Path>,
    stream: DockerStream,
) -> Result<DockerStreamConn, SandboxError> {
    use std::process::Stdio;

    let argv = stream.argv(socket);
    let mut command = tokio::process::Command::new(sandbox_docker_argv::DOCKER_BIN);
    // Same environment rule as the one-shot route: a named target scrubs, an
    // unnamed one inherits. `-H` is the sole authority for which Docker daemon
    // a stream lands in, so nothing ambient may redirect it.
    if socket.is_some() {
        let current_path = std::env::var("PATH").unwrap_or_default();
        command
            .env_clear()
            .env(
                "PATH",
                format!("/opt/homebrew/bin:/usr/local/bin:{current_path}"),
            )
            .env("HOME", std::env::var("HOME").unwrap_or_default());
    }
    command
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(|e| {
        SandboxError::Gateway(format!(
            "failed to spawn the {} stream for {}: {e}",
            stream.target().label(),
            stream.container()
        ))
    })?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| SandboxError::Internal("docker exec child has no stdin".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SandboxError::Internal("docker exec child has no stdout".into()))?;
    let stderr = child.stderr.take();

    Ok(DockerStreamConn {
        io: Box::new(ChildStdio { stdin, stdout }),
        exit: Some(LocalStreamChild { child, stderr }),
    })
}

/// A child's stdin/stdout presented as one bidirectional stream.
///
/// Deliberately does **not** own the child: [`DockerStreamConn::exit`] does,
/// so a caller that wants the exit status can hold it across the byte pump.
struct ChildStdio {
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
}

impl tokio::io::AsyncRead for ChildStdio {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ChildStdio {
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

/// Environment applied to a `docker` invocation that names its target with
/// `-H`.
///
/// `-H` is the sole authority for which daemon is addressed, so the ambient
/// environment must not be able to redirect it: `env_clear` strips
/// `DOCKER_HOST`, `DOCKER_CONFIG`, `DOCKER_TLS_VERIFY` and everything else,
/// and only what the client needs to find its own dependencies is put back.
///
/// This is applied **only** where a target is named. The host-daemon route
/// deliberately does not get it, and that asymmetry is deliberate — the rule
/// and its consequences are on [`DockerRoute`]. Do not "fix" the
/// inconsistency by applying this uniformly.
fn apply_pinned_target_env(cmd: &mut std::process::Command) {
    let current_path = std::env::var("PATH").unwrap_or_default();
    let path_value = format!("/opt/homebrew/bin:/usr/local/bin:{current_path}");
    let home = std::env::var("HOME").unwrap_or_default();
    if home.is_empty() {
        tracing::warn!(
            "docker op: HOME is unset; the docker CLI may fail to locate its config dir"
        );
    }
    cmd.env_clear().env("PATH", &path_value).env("HOME", home);
}

/// Build the `docker` command for an op, with the `-H` prefix and the
/// matching environment discipline.
fn docker_command(socket: Option<&Path>, argv: &[String]) -> std::process::Command {
    let mut cmd = std::process::Command::new(sandbox_docker_argv::DOCKER_BIN);
    if socket.is_some() {
        apply_pinned_target_env(&mut cmd);
    }
    cmd.args(sandbox_docker_argv::host_args(socket));
    cmd.args(argv);
    cmd
}

/// Run a typed op against a Docker daemon this process can open.
fn run_docker_locally(
    socket: Option<&Path>,
    op: DockerOp,
    timeout: Duration,
    label: &str,
) -> Result<std::process::Output, SandboxError> {
    if op.stdin_tarball().is_some() {
        return Err(SandboxError::Internal(format!(
            "{label}: image-load ops must be run through an executor that knows \
             where the staged tarballs live"
        )));
    }
    let argv = op.argv()?;
    let mut cmd = docker_command(socket, &argv);
    match op.stdin_body() {
        Some(body) => {
            crate::process::run_with_timeout_stdin(&mut cmd, body.as_bytes(), timeout, label)
        }
        None => crate::process::run_with_timeout(&mut cmd, timeout, label),
    }
}

/// Stream a staged tarball into `docker load`.
///
/// Kept separate from [`run_docker_locally`] because the tarball is hundreds
/// of megabytes: it is copied from the file to the child's stdin rather than
/// read into memory, which no captured-output helper does.
///
/// Deliberately unbounded rather than given the op's wall-clock budget. The
/// transfer's duration is a function of the tarball's size and the target
/// daemon's disk, so any ceiling short enough to catch a wedged load is also
/// short enough to abort a healthy one on a slow host — and a half-loaded
/// image is worse than a slow one. This matches the behaviour of the call
/// sites this replaced.
fn run_docker_load_locally(
    socket: Option<&Path>,
    tarball: &Path,
    label: &str,
) -> Result<std::process::Output, SandboxError> {
    use std::io::Write;
    use std::process::Stdio;

    if !tarball.exists() {
        return Err(SandboxError::Internal(format!(
            "{label}: image tarball not found at {}",
            tarball.display()
        )));
    }

    let argv = sandbox_docker_argv::image::image_load_argv();
    let mut cmd = docker_command(socket, &argv);
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            SandboxError::Internal(format!("{label}: failed to spawn docker load: {e}"))
        })?;

    let mut stdin = child.stdin.take().ok_or_else(|| {
        SandboxError::Internal(format!("{label}: failed to take docker load stdin"))
    })?;
    let mut file = std::fs::File::open(tarball).map_err(|e| {
        SandboxError::Internal(format!(
            "{label}: failed to open image tarball {}: {e}",
            tarball.display()
        ))
    })?;
    let copy = std::io::copy(&mut file, &mut stdin).and_then(|_| stdin.flush());
    drop(stdin);
    if let Err(e) = copy {
        let _ = child.kill();
        let _ = child.wait();
        return Err(SandboxError::Internal(format!(
            "{label}: failed to stream image tarball into docker load: {e}"
        )));
    }

    child
        .wait_with_output()
        .map_err(|e| SandboxError::Internal(format!("{label}: docker load did not complete: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_docker_argv::container::WorkspaceBindSpec;
    use sandbox_docker_argv::network::{NetworkDriver, NetworkOption};

    fn create_spec() -> ContainerCreateSpec {
        ContainerCreateSpec {
            session_id: "abc".to_string(),
            docker_network: "sandbox-net-abc".to_string(),
            container_ip: "10.209.0.3".to_string(),
            gateway_ip: "10.209.0.2".to_string(),
            image_tag: "sandboxd-lite:0.1.0".to_string(),
            user_uid: 501,
            user_gid: 20,
            memory_mb: 2048,
            cpus: 2.0,
            owner_pool: None,
            workspace_bind: None,
            ca_host_path: None,
            ssh_host_dir: None,
            guest_bind_source: None,
        }
    }

    /// The property the whole op set rests on: no rendered argv may carry a
    /// `-H` flag. The target authority is added by whichever side runs the
    /// command, from a socket it owns — never from the op.
    #[test]
    fn no_op_renders_its_own_target_authority() {
        let net_spec = NetworkCreateSpec {
            name: "sandbox-net-abc".to_string(),
            driver: NetworkDriver::Bridge,
            subnet: Some("10.209.0.0/28".to_string()),
            gateway: None,
            session_id: Some("abc".to_string()),
            owner_pool: None,
            options: vec![NetworkOption::BridgeMasquerade(false)],
        };
        let ops = vec![
            DockerOp::ContainerCreate {
                spec: create_spec(),
            },
            DockerOp::ContainerStart {
                name: "c".to_string(),
            },
            DockerOp::ContainerStop {
                name: "c".to_string(),
                grace_secs: 10,
                long_flag: false,
            },
            DockerOp::ContainerRestart {
                name: "c".to_string(),
            },
            DockerOp::ContainerRemove {
                name: "c".to_string(),
                force: RemoveForce::Short,
            },
            DockerOp::ContainerInspect {
                name: "c".to_string(),
                format: InspectFormat::StatePid,
                flag: InspectFlag::Short,
            },
            DockerOp::ContainerList {
                name_prefix: "sandbox-".to_string(),
                owner_pool: None,
            },
            DockerOp::ContainerExec {
                name: "c".to_string(),
                command: ContainerCommand::GatewayHealthcheck,
            },
            DockerOp::ContainerExecStdin {
                name: "c".to_string(),
                command: StdinCommand::ApplyNftRuleset,
                body: "table inet sandbox_dnat {}\n".to_string(),
            },
            DockerOp::HomeVolumeChown {
                session_id: "abc".to_string(),
                image_tag: "img".to_string(),
                operator_uid: 501,
                operator_gid: 20,
            },
            DockerOp::GatewayContainerRun {
                session_id: "abc".to_string(),
                image_tag: "img".to_string(),
                network: "sandboxd-egress".to_string(),
                owner_pool: None,
                coredns_upstream: None,
            },
            DockerOp::NetworkCreate { spec: net_spec },
            DockerOp::NetworkRemove {
                name: "n".to_string(),
            },
            DockerOp::NetworkInspect {
                name: "n".to_string(),
            },
            DockerOp::NetworkConnect {
                network: "n".to_string(),
                container: "c".to_string(),
                ip: Some("10.209.0.2".to_string()),
            },
            DockerOp::NetworkList {
                name_prefix: "sandbox-net-".to_string(),
                owner_pool: None,
            },
            DockerOp::VolumeCreate {
                name: "v".to_string(),
                session_id: Some("abc".to_string()),
                owner_pool: None,
            },
            DockerOp::VolumeRemove {
                name: "v".to_string(),
            },
            DockerOp::VolumeList {
                name_prefix: "sandbox-home-".to_string(),
                owner_pool: None,
            },
            DockerOp::ImageInspect {
                tag: "t".to_string(),
            },
            DockerOp::ImageLoad {
                image: StagedImage::Gateway,
            },
            DockerOp::DaemonInfo,
        ];
        // Every variant of the enum is represented above. When a variant is
        // added this count fails first, which is the reminder to extend the
        // list rather than to bump the number.
        assert_eq!(ops.len(), 22, "every DockerOp variant must be covered here");
        for op in ops {
            let argv = op.argv().expect("every op above renders");
            assert!(
                !argv.iter().any(|a| a == "-H" || a.starts_with("unix://")),
                "op rendered its own target authority: {argv:?}"
            );
            assert!(!argv.is_empty(), "an op must render at least a subcommand");
        }
    }

    /// The two stdin channels are disjoint, and each op uses at most one:
    /// a tarball is a file the executing side opens, a body is content the
    /// op carries. An op claiming both would leave the executor choosing.
    #[test]
    fn an_op_streams_a_tarball_or_a_body_but_never_both() {
        let write = DockerOp::ContainerExecStdin {
            name: "sandbox-gw-abc".to_string(),
            command: StdinCommand::WriteGatewayFile {
                file: sandbox_docker_argv::gateway::GatewayFile::CorednsPolicy,
                delivery: sandbox_docker_argv::gateway::FileDelivery::Replace,
            },
            body: "policy\n".to_string(),
        };
        assert_eq!(write.stdin_body(), Some("policy\n"));
        assert!(write.stdin_tarball().is_none());

        let load = DockerOp::ImageLoad {
            image: StagedImage::Gateway,
        };
        assert!(load.stdin_body().is_none());
        assert!(load.stdin_tarball().is_some());

        assert!(DockerOp::DaemonInfo.stdin_body().is_none());
    }

    #[test]
    fn only_image_load_streams_a_tarball_on_stdin() {
        assert_eq!(
            DockerOp::ImageLoad {
                image: StagedImage::Lite
            }
            .stdin_tarball(),
            Some(StagedImage::Lite)
        );
        assert!(DockerOp::DaemonInfo.stdin_tarball().is_none());
        assert!(
            DockerOp::ContainerStart {
                name: "c".to_string()
            }
            .stdin_tarball()
            .is_none()
        );
    }

    #[test]
    fn a_refused_argv_surfaces_as_an_invalid_argument() {
        let mut spec = create_spec();
        spec.workspace_bind = Some(WorkspaceBindSpec {
            host_path: "/tmp/a,b".to_string(),
            guest_path: "/home/sandbox/workspace".to_string(),
        });
        let err = DockerOp::ContainerCreate { spec }
            .argv()
            .expect_err("option-list syntax must be refused");
        assert!(matches!(err, SandboxError::InvalidArgument(_)), "{err:?}");
    }

    #[test]
    fn the_host_route_reports_no_operator_uid() {
        assert_eq!(DockerRoute::Host.op_uid(), None);
        assert!(!DockerRoute::Host.is_vm());
    }

    /// The host route must not be handed a `-H` flag: adding one would make
    /// the ambient-environment inheritance it relies on incoherent.
    #[test]
    fn the_host_route_builds_a_bare_docker_command() {
        let argv = DockerOp::DaemonInfo.argv().expect("info renders");
        let cmd = docker_command(None, &argv);
        let args: Vec<&str> = cmd
            .get_args()
            .map(|a| a.to_str().unwrap_or_default())
            .collect();
        assert_eq!(args, vec!["info"]);
    }

    /// The environment rule, in both directions, as a test rather than only
    /// as a paragraph.
    ///
    /// `Command` exposes no accessor for the clear flag, so this asserts the
    /// observable consequence instead: the host route overrides nothing, and
    /// the pinned route rebuilds exactly the two variables the client needs.
    /// That is the right thing to pin anyway — "make these consistent" is a
    /// plausible-looking edit in either direction, and applying the scrub
    /// uniformly would give the host case the same rebuilt pair, which fails
    /// here.
    ///
    /// Both directions break something: scrubbing the host route loses the
    /// Docker the operator configured; not scrubbing the pinned route lets
    /// the environment override `-H`.
    #[test]
    fn only_a_named_target_rebuilds_its_environment() {
        let argv = DockerOp::DaemonInfo.argv().expect("info renders");

        let host = docker_command(None, &argv);
        let host_overrides: Vec<String> = host
            .get_envs()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert!(
            host_overrides.is_empty(),
            "the host route must inherit its environment untouched; scrubbing \
             it would point the daemon at a Docker the operator never \
             configured. Got overrides: {host_overrides:?}"
        );

        let pinned = docker_command(Some(Path::new("/run/gw.sock")), &argv);
        let mut pinned_overrides: Vec<String> = pinned
            .get_envs()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        pinned_overrides.sort();
        assert_eq!(
            pinned_overrides,
            vec!["HOME".to_string(), "PATH".to_string()],
            "a route that names its target must rebuild only what the client \
             needs to find its own dependencies — anything else is a channel \
             for overriding -H"
        );
        for redirector in ["DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY"] {
            assert!(
                !pinned_overrides.iter().any(|k| k == redirector),
                "{redirector} must not be reinstated after the scrub"
            );
        }
    }

    #[test]
    fn a_pinned_target_leads_with_the_host_flag() {
        let argv = DockerOp::DaemonInfo.argv().expect("info renders");
        let cmd = docker_command(Some(Path::new("/run/gw.sock")), &argv);
        let args: Vec<&str> = cmd
            .get_args()
            .map(|a| a.to_str().unwrap_or_default())
            .collect();
        assert_eq!(args, vec!["-H", "unix:///run/gw.sock", "info"]);
    }
}
