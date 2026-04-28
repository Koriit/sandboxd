//! Request-time session specification, the input to
//! [`super::SessionRuntime::create`].
//!
//! `SessionSpec` is the daemon's authoritative view of "create a session
//! shaped like *this*"; it is validated against a backend's
//! [`super::Capabilities`] both client-side (CLI, fast feedback) and
//! server-side (defense in depth) per spec §"Validation sites".
//!
//! Forward-compatibility on the wire follows the CLAUDE.md blob-field
//! rule: any new field landing here must be `Option<T>` with
//! `#[serde(default)]` so records authored by older daemons still
//! deserialise.

use serde::{Deserialize, Serialize};

use crate::session::WorkspaceMode;

use super::capabilities::{BackendKind, Capabilities, UnsupportedFeature};

/// Backend-discriminated configuration carried by [`SessionSpec`].
///
/// `#[serde(tag = "backend", rename_all = "lowercase")]` — the
/// discriminator field is `"backend"` (matching the persisted
/// `sessions.backend` column from V005), and the variant tag is the
/// lower-case backend kind (`"lima"` / `"container"`). The on-the-wire
/// shape per variant is exactly:
///
/// ```json
/// { "backend": "lima",      "hardened": true, "memory_mb": 4096, "cpus": 2 }
/// { "backend": "container",                   "memory_mb": 4096, "cpus": 1.5 }
/// ```
///
/// The container variant is intentionally a near-clone of Lima's minus
/// `hardened`; carrying both as a tagged enum (rather than collapsing
/// into Lima's variant) means future divergence — extra fields,
/// new defaults — does not require a schema migration. See spec
/// §"Capabilities model" — `BackendKind` and `BackendSpecific`.
///
/// CPU type per backend reflects what the backend actually accepts:
/// Lima/QEMU pins integer cores (the Lima YAML and QEMU `-smp` flag
/// both take whole CPUs), while Docker accepts a 1-decimal fraction
/// (`--cpus 1.5`) as the cgroup CPU-quota knob. Container's `cpus`
/// is therefore `f32` — preserving the spec § "Resource defaults —
/// container only" 1-decimal precision end-to-end (M11-S7 todo #67).
/// Pre-todo-#67 the container variant was `cpus: u32` with an
/// implicit `as f64` widening in `ContainerRuntime::resource_ceilings`,
/// which silently truncated `1.5` to `1`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum BackendSpecific {
    /// Lima/QEMU backend. Carries the QEMU `--hardened` flag in
    /// addition to the resource sizing.
    Lima {
        /// Enable the QEMU hardening flag (device lockdown,
        /// `systemd-run` cgroup limits). See
        /// [`crate::session::SessionConfig::hardened`].
        hardened: bool,
        /// Memory in megabytes.
        memory_mb: u32,
        /// Number of CPU cores. Lima/QEMU pins integers; the
        /// container backend uses `f32` to honour the docker
        /// `--cpus` 1-decimal grammar — see the type-level doc above.
        cpus: u32,
    },
    /// Docker container ("lite") backend.
    Container {
        /// Memory in megabytes.
        memory_mb: u32,
        /// Number of CPU cores, with 1-decimal precision (e.g. `0.8`,
        /// `1.5`, `2.0`). See the type-level doc above for why this
        /// is `f32` rather than `u32`. The HTTP request boundary
        /// rounds to one decimal at parse time so the value stored
        /// here is always on the one-decimal grid.
        cpus: f32,
    },
}

impl BackendSpecific {
    /// Which [`BackendKind`] this variant targets.
    pub fn kind(&self) -> BackendKind {
        match self {
            Self::Lima { .. } => BackendKind::Lima,
            Self::Container { .. } => BackendKind::Container,
        }
    }
}

/// Request-time session specification.
///
/// Constructed by the daemon from an HTTP `CreateSessionRequest` (and by
/// the CLI from its parsed flags); fed to
/// [`super::SessionRuntime::create`] after validation against the
/// matching backend's [`Capabilities`].
///
/// New fields land here as `Option<T>` with `#[serde(default)]` per the
/// CLAUDE.md blob-field forward-compatibility rule (records authored by
/// older daemons must still deserialise). `disk_gb` is Lima-only at
/// runtime but lives at the [`SessionSpec`] level rather than inside
/// `BackendSpecific::Lima` because the daemon may surface it on
/// inspect output for both backends; a future container backend could
/// also honour it for storage-size hints.
///
/// See spec §"Capabilities model" — `BackendSpecific` / `SessionSpec`.
///
/// `Eq` is intentionally not derived because `BackendSpecific::Container`
/// carries `cpus: f32` (M11-S7 todo #67); float types only implement
/// `PartialEq`. Tests that previously asserted `Eq`-style equality
/// continue to work via `PartialEq` (`assert_eq!`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionSpec {
    /// Backend selector + sizing.
    pub backend_specific: BackendSpecific,
    /// How the workspace is provided to the session, if at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_mode: Option<WorkspaceMode>,
    /// Optional git URL cloned into `/home/agent/workspace/` on first
    /// boot. Captured for `sandbox inspect` parity with
    /// [`crate::session::SessionConfig::repo`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Command run inside the session once setup completes.
    /// See [`crate::session::SessionConfig::boot_cmd`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_cmd: Option<String>,
    /// Optional path to a custom Lima YAML template. Lima-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Disk size in gigabytes. Lima-only at runtime; carried at
    /// [`SessionSpec`] level for forward-compat per CLAUDE.md.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_gb: Option<u32>,
    // Forward-compat: new fields go here as Option<T> with
    // #[serde(default)].
}

impl SessionSpec {
    /// Which [`BackendKind`] this spec targets.
    pub fn backend(&self) -> BackendKind {
        self.backend_specific.kind()
    }

    /// Validate the spec against a backend's [`Capabilities`].
    ///
    /// Returns the first [`UnsupportedFeature`] mismatch found, or
    /// `Ok(())` if the spec is satisfiable. The body matches
    /// exhaustively on `BackendSpecific` so adding a new variant
    /// produces a compile-time signal here. Capability flags
    /// (workspace modes, future per-session-no-cache, etc.) are
    /// checked in their own blocks below.
    ///
    /// See spec §"Validation sites" — called both by the CLI (after
    /// parse, before any network I/O) and by the daemon on every
    /// authoritative request.
    pub fn validate(&self, caps: &Capabilities) -> Result<(), UnsupportedFeature> {
        // Hardening: a Lima-shaped spec asking for hardened=true is
        // only honourable if caps.hardening_flag is set. We drive off
        // caps.hardening_flag rather than caps.kind so the validate
        // function does not bake in "Lima always supports hardening"
        // — that's the backend's job to declare via its capabilities.
        match &self.backend_specific {
            BackendSpecific::Lima { hardened: true, .. } if !caps.hardening_flag => {
                return Err(UnsupportedFeature::Hardening);
            }
            BackendSpecific::Lima { .. } | BackendSpecific::Container { .. } => {}
        }

        // Workspace mode: only the kind discriminator matters for
        // capability checks; payloads (paths, URLs) are validated
        // elsewhere.
        if let Some(mode) = &self.workspace_mode {
            let kind = mode.kind();
            if !caps.workspace_modes.contains(kind) {
                return Err(UnsupportedFeature::WorkspaceMode(kind, caps.kind));
            }
        }

        // PerSessionNoCache: not validatable from Phase 1A SessionSpec.
        // TODO(M11-S4): once SessionSpec carries `no_cache`, return
        // Err(UnsupportedFeature::PerSessionNoCache(caps.kind)) when
        // requested against a backend whose caps.per_session_no_cache
        // is false.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enumset::EnumSet;

    use crate::backend::capabilities::IsolationLevel;
    use crate::session::WorkspaceModeKind;

    /// Baseline `Capabilities` value for a "Lima-shaped" backend, used
    /// in tests to keep struct literals in one place. Matches the
    /// per-backend defaults documented in spec § "What this breaks"
    /// and § "Hardening" — Lima offers full VM isolation, hardening,
    /// per-session cache invalidation, and both workspace modes.
    fn lima_caps() -> Capabilities {
        Capabilities {
            kind: BackendKind::Lima,
            isolation: IsolationLevel::Vm,
            nested_virt: true,
            privileged_ops: true,
            raw_network: true,
            hardening_flag: true,
            per_session_no_cache: true,
            workspace_modes: EnumSet::all(),
        }
    }

    /// Baseline `Capabilities` value for a "container-shaped" backend
    /// — namespace + cgroup isolation only, no QEMU hardening flag, no
    /// per-session cache invalidation. Matches spec § "What this
    /// breaks". Workspace modes default to `Clone` only here for the
    /// validate test that exercises the WorkspaceMode mismatch; a
    /// Phase 1B `Capabilities::default_for_container()` may evolve
    /// this set.
    fn container_caps_clone_only() -> Capabilities {
        Capabilities {
            kind: BackendKind::Container,
            isolation: IsolationLevel::Container,
            nested_virt: false,
            privileged_ops: false,
            raw_network: false,
            hardening_flag: false,
            per_session_no_cache: false,
            workspace_modes: EnumSet::only(WorkspaceModeKind::Clone),
        }
    }

    fn lima_spec(hardened: bool, workspace_mode: Option<WorkspaceMode>) -> SessionSpec {
        SessionSpec {
            backend_specific: BackendSpecific::Lima {
                hardened,
                memory_mb: 4096,
                cpus: 2,
            },
            workspace_mode,
            repo: None,
            boot_cmd: None,
            template: None,
            disk_gb: None,
        }
    }

    fn container_spec(workspace_mode: Option<WorkspaceMode>) -> SessionSpec {
        SessionSpec {
            backend_specific: BackendSpecific::Container {
                memory_mb: 4096,
                cpus: 2.0,
            },
            workspace_mode,
            repo: None,
            boot_cmd: None,
            template: None,
            disk_gb: None,
        }
    }

    /// Serde shape for `BackendSpecific::Lima` matches the spec
    /// (`{ "backend": "lima", ... }`).
    #[test]
    fn backend_specific_lima_serde_shape() {
        let value = BackendSpecific::Lima {
            hardened: true,
            memory_mb: 4096,
            cpus: 2,
        };
        let v: serde_json::Value = serde_json::to_value(&value).unwrap();
        assert_eq!(v["backend"], "lima");
        assert_eq!(v["hardened"], true);
        assert_eq!(v["memory_mb"], 4096);
        assert_eq!(v["cpus"], 2);

        let parsed: BackendSpecific = serde_json::from_value(v).unwrap();
        assert_eq!(parsed, value);
    }

    /// Serde shape for `BackendSpecific::Container` matches the spec
    /// (`{ "backend": "container", ... }`, no `hardened` field).
    ///
    /// `cpus` is `f32` (M11-S7 todo #67) so the serde-rendered value is
    /// a JSON number whose textual form preserves the 1-decimal grid.
    #[test]
    fn backend_specific_container_serde_shape() {
        let value = BackendSpecific::Container {
            memory_mb: 2048,
            cpus: 1.5,
        };
        let v: serde_json::Value = serde_json::to_value(&value).unwrap();
        assert_eq!(v["backend"], "container");
        assert_eq!(v["memory_mb"], 2048);
        // `1.5` round-trips as a float on the wire — not as the truncated
        // integer the pre-todo-#67 `u32` shape would have produced.
        assert_eq!(v["cpus"].as_f64().expect("cpus is a number"), 1.5);
        assert!(
            v.get("hardened").is_none(),
            "container variant must not carry a hardened field; got {v:?}"
        );

        let parsed: BackendSpecific = serde_json::from_value(v).unwrap();
        assert_eq!(parsed, value);
    }

    /// Round-trip: serialise → deserialise reconstructs the original
    /// value for both variants. The container variant's `cpus` field
    /// must round-trip a 1-decimal value (todo #67) without precision
    /// drift — the regression that this test pins is `1.5 → 1` (the
    /// pre-todo-#67 `u32` truncation bug).
    #[test]
    fn backend_specific_roundtrip() {
        // Lima fixture: integer cores, unchanged from pre-todo-#67.
        let lima = BackendSpecific::Lima {
            hardened: false,
            memory_mb: 8192,
            cpus: 4,
        };
        let json = serde_json::to_string(&lima).unwrap();
        let parsed: BackendSpecific = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, lima, "json={json}");

        // Container fixture: a fractional value that the pre-todo-#67
        // `u32` shape would have truncated. Round-trip must preserve it
        // exactly — `f32` represents `1.5` exactly so `assert_eq!`
        // (PartialEq) is safe here.
        let container = BackendSpecific::Container {
            memory_mb: 1024,
            cpus: 1.5,
        };
        let json = serde_json::to_string(&container).unwrap();
        let parsed: BackendSpecific = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, container, "json={json}");
    }

    /// Round-trip the spec § "Resource defaults — container only"
    /// 1-decimal grid through serde without precision drift. Pins
    /// the contract todo #67 enforces: `0.8`, `1.5`, `2.0` survive
    /// the parse → store → serialize round-trip with bit-equality.
    #[test]
    fn backend_specific_container_cpus_one_decimal_grid_roundtrip() {
        for cpus in [0.8_f32, 1.5_f32, 2.0_f32] {
            let original = BackendSpecific::Container {
                memory_mb: 2048,
                cpus,
            };
            let json = serde_json::to_string(&original).unwrap();
            let parsed: BackendSpecific = serde_json::from_str(&json).unwrap();
            match parsed {
                BackendSpecific::Container {
                    cpus: parsed_cpus, ..
                } => {
                    // The 1-decimal grid values `0.8`, `1.5`, `2.0` are
                    // each exactly representable in f32, so we can
                    // assert bit-equality with `==` rather than an
                    // epsilon comparison.
                    assert_eq!(
                        parsed_cpus, cpus,
                        "1-decimal cpus value must round-trip exactly; \
                         original={cpus} parsed={parsed_cpus} json={json}"
                    );
                }
                other => panic!("expected Container variant, got {other:?}"),
            }
        }
    }

    /// Forward-compat: per CLAUDE.md blob-field rule, a JSON document
    /// with extra fields the current crate does not know about must
    /// deserialise cleanly — serde's default is to ignore unknown
    /// fields, and we explicitly verify that here so the contract
    /// stays visible.
    #[test]
    fn backend_specific_tolerates_unknown_fields() {
        let json = r#"{
            "backend": "lima",
            "hardened": true,
            "memory_mb": 4096,
            "cpus": 2,
            "future_field": "ignored-by-older-daemons"
        }"#;
        let parsed: BackendSpecific = serde_json::from_str(json).expect("unknown field tolerated");
        assert_eq!(
            parsed,
            BackendSpecific::Lima {
                hardened: true,
                memory_mb: 4096,
                cpus: 2,
            }
        );
    }

    /// Forward-compat: a `SessionSpec` blob with fields the current
    /// crate does not know about deserialises cleanly. Mirrors the
    /// `SessionConfig` legacy-record test in `session.rs`.
    #[test]
    fn session_spec_tolerates_unknown_fields_and_legacy_records() {
        // Newer daemon writes an extra "experimental_flag"; older
        // daemon (us, in this test) must still parse the record.
        let json = r#"{
            "backend_specific": { "backend": "container", "memory_mb": 1024, "cpus": 1 },
            "experimental_flag": "from-the-future"
        }"#;
        let parsed: SessionSpec = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.backend(), BackendKind::Container);
        assert!(parsed.workspace_mode.is_none());
        assert!(parsed.repo.is_none());
        assert!(parsed.boot_cmd.is_none());
        assert!(parsed.template.is_none());
        assert!(parsed.disk_gb.is_none());
    }

    /// `SessionSpec::backend()` is a thin wrapper over
    /// `BackendSpecific::kind()`.
    #[test]
    fn session_spec_backend_matches_variant() {
        assert_eq!(lima_spec(false, None).backend(), BackendKind::Lima);
        assert_eq!(container_spec(None).backend(), BackendKind::Container);
    }

    /// Validate happy path: Lima spec + Lima caps with hardening on.
    #[test]
    fn validate_lima_with_hardening_succeeds() {
        let spec = lima_spec(true, None);
        spec.validate(&lima_caps())
            .expect("lima caps support hardening");
    }

    /// Validate happy path: Container spec + container caps.
    #[test]
    fn validate_container_succeeds() {
        let spec = container_spec(None);
        spec.validate(&container_caps_clone_only())
            .expect("container caps support a no-workspace spec");
    }

    /// Hardening mismatch: Lima spec with hardened=true against caps
    /// whose hardening_flag is false yields `UnsupportedFeature::Hardening`.
    #[test]
    fn validate_rejects_hardening_when_caps_disable_it() {
        // Take Lima caps and flip hardening off so the spec's request
        // for hardened=true is refused.
        let mut caps = lima_caps();
        caps.hardening_flag = false;

        let spec = lima_spec(true, None);
        let err = spec
            .validate(&caps)
            .expect_err("hardened=true must be rejected when hardening_flag is off");
        assert_eq!(err, UnsupportedFeature::Hardening);
    }

    /// Hardening flag is irrelevant when the spec asks for
    /// `hardened: false` — even on caps with hardening disabled the
    /// validate succeeds.
    #[test]
    fn validate_allows_unhardened_lima_against_unhardened_caps() {
        let mut caps = lima_caps();
        caps.hardening_flag = false;

        let spec = lima_spec(false, None);
        spec.validate(&caps)
            .expect("hardened=false has nothing to validate");
    }

    /// Workspace-mode mismatch: a spec asking for `Shared` against
    /// caps that only advertise `Clone` yields the right
    /// `UnsupportedFeature::WorkspaceMode(kind, backend)` pair.
    #[test]
    fn validate_rejects_unsupported_workspace_mode() {
        let spec = container_spec(Some(WorkspaceMode::Shared {
            host_path: "/tmp".into(),
        }));
        let err = spec
            .validate(&container_caps_clone_only())
            .expect_err("container caps reject Shared workspace");
        assert_eq!(
            err,
            UnsupportedFeature::WorkspaceMode(WorkspaceModeKind::Shared, BackendKind::Container)
        );
    }

    /// Workspace-mode happy path: `Clone` against caps that advertise
    /// it.
    #[test]
    fn validate_accepts_supported_workspace_mode() {
        let spec = container_spec(Some(WorkspaceMode::Clone {
            repo_url: "https://example.invalid/repo.git".into(),
        }));
        spec.validate(&container_caps_clone_only())
            .expect("clone is in the caps set");
    }

    // PerSessionNoCache: not reachable from Phase 1A SessionSpec —
    // SessionSpec does not yet carry a `no_cache` field. Wired up in
    // M11-S4 ("--no-cache" flag). When that lands, add a test akin
    // to:
    //
    //   #[test]
    //   fn validate_rejects_per_session_no_cache_when_caps_disable_it() {
    //       let spec = container_spec_with_no_cache(true);
    //       let err = spec.validate(&container_caps_clone_only()).unwrap_err();
    //       assert_eq!(err, UnsupportedFeature::PerSessionNoCache(BackendKind::Container));
    //   }
}
