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
    ContainerCommand, ContainerCreateSpec, DockerOp, EnvoyStat, FileDelivery, GatewayComponent,
    GatewayFile, InspectFlag, InspectFormat, NetworkCreateSpec, NetworkDriver, NetworkOption,
    NftTable, RemoveForce, StagedImage, StdinCommand, WorkspaceBindSpec, docker_argv,
};

#[cfg(target_os = "macos")]
pub use protocol::{RESTRICT_MARKER_FILENAME, RESTRICT_ON_MARKER, STREAM_CONNECT_PREFIX};

#[cfg(target_os = "macos")]
mod protocol;

// `validation` is deliberately NOT compiled into this library target, even
// though exporting `validate_docker_op` from here would let the daemon's
// tests assert that every op it builds is one the agent accepts.
//
// The binary target already declares its own `mod validation`, so adding a
// second declaration here compiles the module twice — and runs its ~90 unit
// tests twice, once per target. That inflates the workspace test count by a
// figure unrelated to any test anybody wrote, which is how a baseline stops
// being comparable across revisions. It was measured, not theorised: adding
// it took `make test` from 2325 to 2418 without a single new assertion.
//
// The cross-check that export was for lives on the agent side instead, in
// `validation`'s own tests, where the op list it validates sits next to the
// list `broker.rs` sends; the two are held in step by a shared count
// assertion. Making the binary consume this library's modules rather than
// recompiling them would give back the export for free, but that is a
// restructuring of the agent crate and does not belong to a change about
// the egress plane.
