//! Capability surface shared by every [`super::SessionRuntime`] impl.
//!
//! See spec §"Capabilities model" for the rationale. Each backend declares
//! a single [`Capabilities`] value which is consulted at request time by
//! [`super::SessionSpec::validate`] and surfaced (in a future phase) on
//! the `GET /backends` HTTP endpoint.
//!
//! The types here are the request-time validation surface. Runtime
//! implementations live in `lima.rs` / `container.rs`.

use enumset::EnumSet;
use serde::{Deserialize, Serialize};

use crate::session::WorkspaceModeKind;

/// Identifies which backend a [`Capabilities`] value or
/// [`super::SessionSpec`] belongs to.
///
/// Serialised lower-case (`"lima"` / `"container"`) so the on-the-wire
/// representation matches the persisted `sessions.backend` column added
/// by the V005 migration and the `BackendSpecific` variant tag.
///
/// See spec §"Capabilities model" — `BackendKind` and `BackendSpecific`.
///
/// `Default = Lima` so legacy on-disk rows that predate the V005
/// `sessions.backend` column (and any older JSON snapshots that omit
/// the field) round-trip as Lima sessions, matching the SQL column's
/// `DEFAULT 'lima'`. New code paths choosing a backend must do so
/// explicitly — never rely on this default for fresh sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    /// QEMU/Lima virtual-machine backend (today's only backend).
    #[default]
    Lima,
    /// Docker container backend (introduced by M11 lite mode).
    Container,
}

impl std::str::FromStr for BackendKind {
    type Err = String;

    /// Parse the lower-case tag stored in the SQLite `sessions.backend`
    /// column back into a [`BackendKind`]. Uses the same string set as
    /// [`BackendKind::as_str`] / the `#[serde(rename_all = "lowercase")]`
    /// wire form so persistence and wire stay in lock-step.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "lima" => Ok(Self::Lima),
            "container" => Ok(Self::Container),
            other => Err(format!("unknown backend kind: {other:?}")),
        }
    }
}

impl BackendKind {
    /// Stable string identifier used by the persisted `sessions.backend`
    /// column and by the `BackendSpecific` serde tag. Must match the
    /// `CHECK` constraint declared by the V005 migration.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lima => "lima",
            Self::Container => "container",
        }
    }
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How strongly a backend isolates session workloads from the host.
///
/// See spec §"Capabilities model" — `IsolationLevel`. `Vm` denotes
/// hardware-accelerated VM isolation (Lima/QEMU); `Container` denotes
/// Linux-namespace + cgroup isolation (Docker lite mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IsolationLevel {
    /// Hardware-virtualised guest (Lima/QEMU).
    Vm,
    /// Linux container (namespaces + cgroups).
    Container,
}

/// Static capability descriptor returned by [`super::SessionRuntime::capabilities`].
///
/// `#[non_exhaustive]` so callers must construct values via per-backend
/// constructors (or `..` syntax against a baseline) — adding a new
/// capability never silently picks up a `false` default.
///
/// See spec §"Capabilities model" — `Capabilities`. The `kind` field is
/// included here (rather than passed as a separate argument to
/// [`super::SessionSpec::validate`]) so a `Capabilities` value carries
/// everything the validator needs to attribute an
/// [`UnsupportedFeature`] to the correct backend without an extra
/// parameter.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Which backend this descriptor describes — needed to construct
    /// [`UnsupportedFeature::WorkspaceMode`] / [`UnsupportedFeature::PerSessionNoCache`]
    /// inside [`super::SessionSpec::validate`] without a separate
    /// argument.
    pub kind: BackendKind,
    /// Strength of guest-from-host isolation provided by this backend.
    pub isolation: IsolationLevel,
    /// Whether the backend can run nested virtualisation inside a
    /// session. Lima exposes KVM; the container backend does not.
    pub nested_virt: bool,
    /// Whether the backend permits privileged operations inside the
    /// session (e.g. `mount`, raw `iptables`). Implies `raw_network`
    /// in practice; kept as a separate flag for clarity.
    pub privileged_ops: bool,
    /// Whether the backend exposes raw L2 networking inside the
    /// session. Lima yes (full QEMU NIC); container no (loopback only).
    pub raw_network: bool,
    /// Whether the backend honours the QEMU hardening flag (locked-down
    /// device set, cgroup limits via `systemd-run`). Lima only.
    pub hardening_flag: bool,
    /// Whether the backend supports the `--no-cache` per-session
    /// invalidation flag (Lima only — clones vs. golden image).
    pub per_session_no_cache: bool,
    /// Set of [`WorkspaceModeKind`]s the backend can satisfy.
    ///
    /// The spec sketches this as `EnumSet<WorkspaceMode>`; in practice
    /// `WorkspaceMode` is data-bearing and cannot derive
    /// `EnumSetType`, so the kind discriminator is used. See
    /// [`WorkspaceModeKind`].
    ///
    /// Deserialized via [`crate::session::deserialize_workspace_mode_kind_set`]
    /// so that an older client reading a newer daemon's capability
    /// response silently drops unknown variants instead of failing the
    /// response wholesale.
    #[serde(deserialize_with = "crate::session::deserialize_workspace_mode_kind_set")]
    pub workspace_modes: EnumSet<WorkspaceModeKind>,
}

impl Capabilities {
    /// Static capability descriptor for the Lima/QEMU backend.
    ///
    /// Each field is justified by the design spec
    /// (`.tasks/specs/2026-04-22-lite-mode-container-backend-design`)
    /// — see the per-field comments. This constructor is the canonical
    /// source of truth used by [`super::lima::LimaRuntime::new`]
    /// (Phase 1B+); a regression test in `backend::lima::tests` pins
    /// each field so a silent drift fails CI.
    pub fn for_lima() -> Self {
        Self {
            // Spec § "Capabilities model" — `kind` discriminates the
            // backend so `UnsupportedFeature` carries it onward.
            kind: BackendKind::Lima,
            // Spec § "Architecture / Two implementations" — Lima is
            // the VM-isolation backend (QEMU + KVM).
            isolation: IsolationLevel::Vm,
            // Spec § "What this breaks" — Lima exposes KVM, so
            // nested-virt workloads (e.g. inner containers using KVM)
            // are honourable.
            nested_virt: true,
            // Spec § "What this breaks" — VMs have full kernel
            // surface, so `mount`, raw `iptables`, etc. work.
            privileged_ops: true,
            // Spec § "What this breaks" — Lima sessions get a real
            // QEMU NIC, no `cap-drop` envelope around the guest.
            raw_network: true,
            // Spec § "Capabilities model" / "Hardening" — Lima's QEMU
            // wrapper honours the `--hardened` flag (device lockdown,
            // `systemd-run` cgroup limits).
            hardening_flag: true,
            // Spec § "CLI & UX / `sandbox create --no-cache`" — the
            // `--no-cache` flag triggers a per-session full VM build
            // instead of golden-image clone; only meaningful on Lima.
            per_session_no_cache: true,
            // Spec § "Workspace modes" — Lima supports both 9p
            // shared-mount and clone-into-VM modes.
            workspace_modes: EnumSet::all(),
        }
    }
}

/// Reason a [`super::SessionSpec`] cannot be honoured by a given
/// [`Capabilities`].
///
/// `#[non_exhaustive]` — adding a new capability mismatch is expected
/// to ripple through the CLI's error printer; an exhaustive `match` on
/// this enum forces that review.
///
/// See spec §"Capabilities model" — `UnsupportedFeature`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedFeature {
    /// The spec asked for the QEMU `--hardened` flag but the target
    /// backend does not support it.
    Hardening,
    /// The spec asked for a workspace mode the target backend cannot
    /// satisfy. Carries the requested kind plus the backend that
    /// rejected it for operator-facing error messages.
    WorkspaceMode(WorkspaceModeKind, BackendKind),
    /// The spec asked for `--no-cache` against a backend that does not
    /// support per-session cache invalidation.
    PerSessionNoCache(BackendKind),
}

impl std::fmt::Display for UnsupportedFeature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hardening => f.write_str("hardening flag is not supported by the target backend"),
            Self::WorkspaceMode(kind, backend) => {
                write!(
                    f,
                    "workspace mode '{kind:?}' is not supported by the {backend} backend"
                )
            }
            Self::PerSessionNoCache(backend) => {
                write!(
                    f,
                    "per-session --no-cache is not supported by the {backend} backend"
                )
            }
        }
    }
}

impl std::error::Error for UnsupportedFeature {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: backend kinds round-trip through serde with the
    /// lower-case representation that matches the V005 schema CHECK
    /// and the `BackendSpecific` discriminator.
    #[test]
    fn backend_kind_serde_lowercase() {
        let json = serde_json::to_string(&BackendKind::Lima).unwrap();
        assert_eq!(json, "\"lima\"");
        let parsed: BackendKind = serde_json::from_str("\"container\"").unwrap();
        assert_eq!(parsed, BackendKind::Container);
    }

    #[test]
    fn backend_kind_as_str_matches_serde() {
        // Both representations must agree — the persisted column and
        // the BackendSpecific tag rely on this consistency.
        for kind in [BackendKind::Lima, BackendKind::Container] {
            let s = serde_json::to_string(&kind).unwrap();
            let unquoted = s.trim_matches('"');
            assert_eq!(unquoted, kind.as_str(), "kind={kind:?}");
        }
    }

    /// `Capabilities` is `#[non_exhaustive]`. This test documents the
    /// expected construction style: callers either go through a
    /// per-backend constructor (added in Phase 1B) or via `..` from a
    /// baseline literal in the same crate. A struct literal that omits
    /// a field outside the defining crate would fail to compile —
    /// future readers can therefore trust capability evolution to
    /// surface as compile errors at every call site.
    #[test]
    fn capabilities_constructs_within_crate() {
        let caps = Capabilities {
            kind: BackendKind::Lima,
            isolation: IsolationLevel::Vm,
            nested_virt: true,
            privileged_ops: true,
            raw_network: true,
            hardening_flag: true,
            per_session_no_cache: true,
            workspace_modes: EnumSet::all(),
        };
        assert_eq!(caps.kind, BackendKind::Lima);
        assert!(caps.workspace_modes.contains(WorkspaceModeKind::Shared));
        assert!(caps.workspace_modes.contains(WorkspaceModeKind::Clone));
    }
}
