//! `sandbox-agent-protocol` — the broker wire-protocol types shared between
//! the per-operator agent binary (`sandbox-agent`) and the daemon (`sandboxd`).
//!
//! Both sides of the broker channel serialize and deserialize the same
//! `BrokerRequest` / `BrokerResponse` / `BrokerOp` / `BrokerResult` types.
//! Defining them once in a library target eliminates any drift between the
//! two serialization surfaces.
//!
//! The library is macOS-only: on Linux the operator-execution seam uses
//! `sandbox-lima-helper` (a setcap binary) and the broker channel does not
//! exist.

// The broker protocol is macOS-only. Exporting on other platforms would
// pull in macOS-only deps (libc, serde, serde_json) unnecessarily.
#[cfg(target_os = "macos")]
pub use protocol::{BridgePair, BrokerOp, BrokerRequest, BrokerResponse, BrokerResult};

/// The Docker op set and the typed values it carries. Exported so the daemon
/// can construct the same requests the agent validates.
#[cfg(target_os = "macos")]
pub use protocol::{
    ContainerCommand, ContainerCreateSpec, DockerOp, FileDelivery, GatewayComponent, GatewayFile,
    InspectFlag, InspectFormat, NetworkCreateSpec, NetworkDriver, NetworkOption, NftTable,
    RemoveForce, StagedImage, StdinCommand, WorkspaceBindSpec, docker_argv,
};

#[cfg(target_os = "macos")]
pub use protocol::{RESTRICT_MARKER_FILENAME, RESTRICT_ON_MARKER, STREAM_CONNECT_PREFIX};

/// The agent's own Docker-op validator, exported so the daemon side can
/// assert that every op it constructs is one the agent accepts.
///
/// **This is not a pre-check the agent then trusts.** The agent calls this
/// itself, on every op, from `handle_docker` — that call is the control.
/// Exporting it lets a test on the sending side notice at build time that
/// the two halves have drifted, instead of a production op being refused by
/// an agent nobody could ask.
#[cfg(target_os = "macos")]
pub use validation::{MAX_GATEWAY_ARTIFACT_BYTES, validate_docker_op};

#[cfg(target_os = "macos")]
mod protocol;

// The binary target compiles its own copy of this module and uses all of
// it; the library target needs only the Docker validator above. The rest is
// dead here by construction, not by neglect.
#[cfg(target_os = "macos")]
#[allow(dead_code)]
mod validation;
