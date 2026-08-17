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
//! Linux shape and runs `docker` locally with the ambient environment left
//! alone — that matters, because a rootless Docker install puts its socket in
//! `DOCKER_HOST` and scrubbing the environment would break it. `Vm` carries
//! the operator uid and an executor; whether that executor runs `docker`
//! itself (the daemon is the operator) or forwards the op to the operator's
//! agent is the executor's business, not the call site's.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sandbox_docker_argv::container::{
    ContainerCommand, ContainerCreateSpec, InspectFlag, InspectFormat, RemoveForce,
};
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
}

/// Runs typed Docker operations somewhere the caller cannot reach directly.
///
/// One-shot and blocking, matching [`crate::lima::LimaExecutor::run`]: the
/// caller wraps it in `spawn_blocking`. There is no streaming method — the
/// long-lived Docker streams are a separate concern with their own lifetime
/// rules (see the async-I/O carve-out in `CLAUDE.md`).
pub trait DockerExecutor: Send + Sync {
    /// Run one op as `op_uid` and return the captured output.
    fn run(
        &self,
        op_uid: u32,
        op: DockerOp,
        timeout: Duration,
        label: &str,
    ) -> Result<std::process::Output, SandboxError>;
}

/// Where a call site's `docker` operations go.
#[derive(Clone)]
pub enum DockerRoute {
    /// The host's own Docker daemon.
    ///
    /// No `-H` flag, and — deliberately — no environment scrubbing. A
    /// rootless Docker install advertises its socket through `DOCKER_HOST`,
    /// so clearing the environment here would point the daemon at a socket
    /// that does not exist. This is the variant that is *supposed* to inherit
    /// its target from its surroundings.
    Host,
    /// A Docker daemon inside a VM, reached through the typed op seam.
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
}

/// Environment applied to a `docker` invocation that names its target with
/// `-H`.
///
/// `-H` is the sole authority for which daemon is addressed, so the ambient
/// environment must not be able to redirect it: `env_clear` strips
/// `DOCKER_HOST`, `DOCKER_CONFIG`, `DOCKER_TLS_VERIFY` and everything else,
/// and only what the client needs to find its own dependencies is put back.
///
/// The host-daemon route deliberately does **not** get this treatment — see
/// [`DockerRoute::Host`].
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
    crate::process::run_with_timeout(&mut cmd, timeout, label)
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
        assert_eq!(ops.len(), 21, "every DockerOp variant must be covered here");
        for op in ops {
            let argv = op.argv().expect("every op above renders");
            assert!(
                !argv.iter().any(|a| a == "-H" || a.starts_with("unix://")),
                "op rendered its own target authority: {argv:?}"
            );
            assert!(!argv.is_empty(), "an op must render at least a subcommand");
        }
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
