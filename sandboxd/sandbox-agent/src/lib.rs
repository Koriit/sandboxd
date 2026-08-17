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
    ContainerCommand, ContainerCreateSpec, DockerOp, GatewayComponent, InspectFlag, InspectFormat,
    NetworkCreateSpec, NetworkDriver, NetworkOption, RemoveForce, StagedImage, WorkspaceBindSpec,
    docker_argv,
};

#[cfg(target_os = "macos")]
pub use protocol::{RESTRICT_MARKER_FILENAME, RESTRICT_ON_MARKER, STREAM_CONNECT_PREFIX};

#[cfg(target_os = "macos")]
mod protocol;
