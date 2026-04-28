//! Domain → DTO conversions for the public HTTP API.
//!
//! This module is the **only** place where [`crate::session::Session`],
//! [`crate::session::SessionConfig`], [`crate::policy::Policy`], and their
//! nested types are translated into the wire types declared in
//! [`super::dto`].  Keeping the mapping explicit here means that adding
//! a new domain field is **inert** on the wire — nothing shows up
//! externally until the mapper is edited to populate the corresponding
//! DTO field.
//!
//! The conversions intentionally take `&T` rather than `T` so handlers
//! can build a DTO without consuming the owned domain value (which is
//! often still needed elsewhere in the response path).

use crate::backend::{BackendKind, compute_default_resource_limits};
use crate::policy::{AssuranceLevel, Policy, PolicyRule};
use crate::session::{Session, SessionConfig, WorkspaceMode};

use super::dto::{
    PolicyDto, PolicyLevelDto, PolicyRuleDto, SessionConfigDto, SessionDto, SessionMountInfo,
    SessionNetworkInfo, SessionRootlessDocker as SessionRootlessDockerDto,
};

// ---------------------------------------------------------------------------
// Session mapping
// ---------------------------------------------------------------------------

impl From<&Session> for SessionDto {
    fn from(session: &Session) -> Self {
        // Backend-aware resolved-default surfacing for the wire-only
        // `resolved_cpus`/`resolved_memory_mb` fields. The container
        // backend persists `0` as the "unset" sentinel and lets
        // `ContainerRuntime::resource_ceilings` substitute the daemon's
        // host-80% default at create-time (spec § "Resource defaults —
        // container only"); surfacing that resolved pair on the wire
        // lets HTTP-level callers confirm the actually-applied
        // ceiling without inspecting cgroup files. Lima sessions don't
        // use the sentinel — `cpus`/`memory_mb` are already the
        // applied values.
        let mut config: SessionConfigDto = (&session.config).into();
        // Container backend: substitute the daemon's host-80% defaults
        // for any `0`-sentinel persisted value. The "stored" cpus
        // value is `config.cpus_decimal` when set (the precise float
        // M11-S7 todo #67 plumbed in) or the integer `config.cpus`
        // cast to f64 otherwise. Lima passes through verbatim — the
        // sentinel only applies to container sessions.
        let stored_cpus_f64 = session
            .config
            .cpus_decimal
            .map(|c| c as f64)
            .unwrap_or(session.config.cpus as f64);
        let (resolved_cpus, resolved_memory_mb) = match session.backend {
            BackendKind::Container => {
                let (default_memory_mb, default_cpus) = compute_default_resource_limits();
                let cpus = if stored_cpus_f64 == 0.0 {
                    default_cpus
                } else {
                    stored_cpus_f64
                };
                let memory_mb = if session.config.memory_mb == 0 {
                    default_memory_mb
                } else {
                    session.config.memory_mb
                };
                (cpus, memory_mb)
            }
            BackendKind::Lima => (stored_cpus_f64, session.config.memory_mb),
        };
        config.resolved_cpus = resolved_cpus;
        config.resolved_memory_mb = resolved_memory_mb;

        Self {
            id: session.id,
            name: session.name.clone(),
            state: session.state,
            created_at: session.created_at,
            updated_at: session.updated_at,
            config,
            guest_agent_status: None,
            gateway_status: None,
            policy: None,
            warnings: Vec::new(),
            backend: session.backend,
            network: None,
            mounts: None,
            rootless: None,
        }
    }
}

impl SessionDto {
    /// Populate the optional health fields without touching the policy.
    ///
    /// Returned by value so call sites can chain:
    ///
    /// ```ignore
    /// let dto = SessionDto::from(&session)
    ///     .with_status(agent_status, gateway_status);
    /// ```
    pub fn with_status(
        mut self,
        guest_agent_status: Option<String>,
        gateway_status: Option<String>,
    ) -> Self {
        self.guest_agent_status = guest_agent_status;
        self.gateway_status = gateway_status;
        self
    }

    /// Attach an applied policy to the DTO.
    ///
    /// Distinct from the `From<&Session>` path so `GET /sessions`
    /// (which deliberately omits the policy for a lean list response)
    /// cannot accidentally include it.
    pub fn with_policy(mut self, policy: Option<&Policy>) -> Self {
        self.policy = policy.map(PolicyDto::from);
        self
    }

    /// Attach operator-facing warnings to the DTO.
    ///
    /// Currently exercised only by `POST /sessions` for the container
    /// backend's first-use lite-image build notice (M11-S3 Phase 3D);
    /// kept generic so future warnings (e.g. resource ceiling
    /// substitutions) can plumb through the same path. An empty
    /// `Vec` is a no-op and round-trips as the wire field being
    /// omitted entirely (`#[serde(skip_serializing_if = "Vec::is_empty")]`
    /// on the DTO field).
    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }

    /// Attach the backend-neutral per-session networking summary.
    ///
    /// Distinct from `From<&Session>` so the list endpoint
    /// (`GET /sessions`, which deliberately keeps the wire payload
    /// lean) cannot accidentally include it; `GET /sessions/{id}`
    /// is the sole caller.
    pub fn with_network(mut self, network: Option<SessionNetworkInfo>) -> Self {
        self.network = network;
        self
    }

    /// Attach the backend-neutral per-session mount surface.
    ///
    /// Same lean-list rationale as [`SessionDto::with_network`]: the
    /// list endpoint never populates this, so the wire stays cheap;
    /// `GET /sessions/{id}` is the sole caller.
    pub fn with_mounts(mut self, mounts: Option<SessionMountInfo>) -> Self {
        self.mounts = mounts;
        self
    }

    /// Attach the rootless-Docker probe outcome captured at session-
    /// create time (M11-S8 Wave 2).
    ///
    /// Same lean-list rationale as [`SessionDto::with_network`] and
    /// [`SessionDto::with_mounts`]: the list endpoint deliberately
    /// omits this so `GET /sessions` keeps a small payload;
    /// `GET /sessions/{id}` and `POST /sessions` populate it from
    /// the persisted [`crate::session::SessionConfig::rootless_docker`].
    /// The mapper does not probe — it only projects state that the
    /// daemon already stamped onto the session at create time
    /// (deliverable 3 of the M11-S8 Wave 2 plumbing).
    ///
    /// `None` keeps the wire-key absent (`#[serde(skip_serializing_if]
    /// = "Option::is_none"]`), matching the per-backend semantics on
    /// the parent: Lima sessions never carry it, container sessions
    /// always do. Pre-Wave-2 container records that lack the
    /// persisted state also surface as `None` here.
    pub fn with_rootless(mut self, rootless: Option<SessionRootlessDockerDto>) -> Self {
        self.rootless = rootless;
        self
    }
}

impl From<&crate::session::SessionRootlessDocker> for SessionRootlessDockerDto {
    fn from(s: &crate::session::SessionRootlessDocker) -> Self {
        Self {
            detected: s.detected,
            forced: s.forced,
        }
    }
}

impl From<&SessionConfig> for SessionConfigDto {
    /// Project the persisted [`SessionConfig`] onto the wire DTO.
    ///
    /// `resolved_cpus` / `resolved_memory_mb` start at the persisted
    /// values here (Lima-style passthrough); the backend-aware
    /// resolution lives in [`SessionDto::from`], which has access to
    /// the session's backend kind. Callers that build a
    /// `SessionConfigDto` outside of the `SessionDto` path therefore
    /// see a Lima-shaped passthrough — accurate for VM sessions, and
    /// safely the same as the persisted value for container sessions
    /// that explicitly set non-zero `cpus`/`memory_mb`.
    ///
    /// `cpus` is sourced from [`SessionConfig::cpus_decimal`] when
    /// `Some` (M11-S7 todo #67 — the precise 1-decimal value the
    /// operator supplied for a container session); otherwise it
    /// falls back to the integer [`SessionConfig::cpus`] cast to
    /// `f32`, which is exact for every value the persisted column
    /// can hold (`u32` → `f32` is exact for inputs ≤ 2^24).
    fn from(config: &SessionConfig) -> Self {
        let cpus_wire = config.cpus_decimal.unwrap_or(config.cpus as f32);
        Self {
            cpus: cpus_wire,
            memory_mb: config.memory_mb,
            disk_gb: config.disk_gb,
            resolved_cpus: cpus_wire as f64,
            resolved_memory_mb: config.memory_mb,
            workspace_mode: config.workspace_mode.as_ref().map(render_workspace_mode),
            hardened: config.hardened,
            repo: config.repo.clone(),
            boot_cmd: config.boot_cmd.clone(),
            template: config.template.clone(),
        }
    }
}

/// Render a workspace mode as a short string (`"shared:<path>"` or
/// `"clone:<url>"`) for the wire representation.
///
/// Kept as a free function (not an `impl Display for WorkspaceMode`) so
/// that the wire surface and any future debug/log formatting stay
/// decoupled — changing one must not silently change the other.
fn render_workspace_mode(mode: &WorkspaceMode) -> String {
    match mode {
        WorkspaceMode::Shared { host_path } => format!("shared:{host_path}"),
        WorkspaceMode::Clone { repo_url } => format!("clone:{repo_url}"),
    }
}

// ---------------------------------------------------------------------------
// Policy mapping
// ---------------------------------------------------------------------------

impl From<&Policy> for PolicyDto {
    fn from(policy: &Policy) -> Self {
        Self {
            version: policy.version.clone(),
            rules: policy.rules.iter().map(PolicyRuleDto::from).collect(),
        }
    }
}

impl From<&PolicyRule> for PolicyRuleDto {
    fn from(rule: &PolicyRule) -> Self {
        Self {
            host: rule.host.clone(),
            port: rule.port,
            protocol: rule.protocol,
            level: (&rule.level).into(),
            reason: rule.reason.clone(),
        }
    }
}

impl From<&AssuranceLevel> for PolicyLevelDto {
    fn from(level: &AssuranceLevel) -> Self {
        match level {
            AssuranceLevel::Deny => PolicyLevelDto::Deny,
            AssuranceLevel::Transport => PolicyLevelDto::Transport,
            AssuranceLevel::Tls => PolicyLevelDto::Tls,
            AssuranceLevel::Http { http_filters } => PolicyLevelDto::Http {
                http_filters: http_filters.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Destination, HttpFilter, HttpMethod, Protocol};

    use crate::session::Session;

    #[test]
    fn session_dto_omits_policy_when_none() {
        let session = Session::new(Some("wire-check".into()));
        let dto = SessionDto::from(&session);
        assert!(dto.policy.is_none());

        let json = serde_json::to_string(&dto).unwrap();
        assert!(
            !json.contains("\"policy\""),
            "policy key must be absent from wire when None; json = {json}"
        );
    }

    #[test]
    fn session_dto_omits_warnings_when_empty() {
        // No `warnings` populated → wire must not contain the key,
        // matching the "additive on the wire" contract for Phase 3D.
        let session = Session::new(Some("warnings-empty".into()));
        let dto = SessionDto::from(&session);
        assert!(dto.warnings.is_empty());

        let json = serde_json::to_string(&dto).unwrap();
        assert!(
            !json.contains("\"warnings\""),
            "warnings key must be omitted when empty; json = {json}"
        );
    }

    #[test]
    fn session_dto_includes_warnings_when_attached() {
        let session = Session::new(Some("warnings-set".into()));
        let dto = SessionDto::from(&session).with_warnings(vec![
            "lite: first use on this daemon version — building lite image".into(),
        ]);

        let json = serde_json::to_value(&dto).unwrap();
        let arr = json["warnings"].as_array().expect("warnings array on wire");
        assert_eq!(arr.len(), 1);
        assert_eq!(
            arr[0],
            serde_json::json!("lite: first use on this daemon version — building lite image")
        );
    }

    #[test]
    fn session_dto_includes_policy_when_attached() {
        let session = Session::new(Some("attached".into()));
        let policy = Policy {
            version: "2.0.0".into(),
            rules: vec![PolicyRule {
                host: Destination::Domain("example.com".into()),
                port: 443,
                protocol: Protocol::Tcp,
                reason: None,
                level: AssuranceLevel::Transport,
            }],
        };

        let dto = SessionDto::from(&session).with_policy(Some(&policy));
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains("\"policy\""), "json = {json}");
        assert!(json.contains("\"version\":\"2.0.0\""), "json = {json}");
    }

    #[test]
    fn policy_dto_serializes_http_variant_with_flattened_filters() {
        // The wire shape for an http-level rule is:
        //   {"host": "...", "port": 443, "protocol": "tcp",
        //    "level": "http",
        //    "http_filters": [{"method": "GET", "path": "/*"}]}
        // With `level` and `http_filters` at the rule object's top level.
        let policy = Policy {
            version: "2.0.0".into(),
            rules: vec![PolicyRule {
                host: Destination::Domain("api.example.com".into()),
                port: 443,
                protocol: Protocol::Tcp,
                reason: Some("api access".into()),
                level: AssuranceLevel::Http {
                    http_filters: vec![
                        HttpFilter {
                            method: HttpMethod::Get,
                            path: "/v1/*".into(),
                        },
                        HttpFilter {
                            method: HttpMethod::Post,
                            path: "/v1/upload".into(),
                        },
                    ],
                },
            }],
        };

        let dto = PolicyDto::from(&policy);
        let json = serde_json::to_value(&dto).unwrap();

        // Pull apart the single rule object.
        let rule = &json["rules"][0];
        assert_eq!(rule["level"], "http");
        // http_filters lives at the rule top level (flattened), not nested
        // under a `constraints` or `level` object.
        let filters = rule["http_filters"]
            .as_array()
            .expect("http_filters should be an array at rule top level");
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0]["method"], "GET");
        assert_eq!(filters[0]["path"], "/v1/*");
        assert_eq!(filters[1]["method"], "POST");
        assert_eq!(filters[1]["path"], "/v1/upload");
    }

    #[test]
    fn policy_dto_non_http_variants_omit_http_filters_on_wire() {
        // `deny`, `transport`, `tls` must not emit an `http_filters` key.
        let policy = Policy {
            version: "2.0.0".into(),
            rules: vec![
                PolicyRule {
                    host: Destination::Domain("a.test".into()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    reason: None,
                    level: AssuranceLevel::Deny,
                },
                PolicyRule {
                    host: Destination::Domain("b.test".into()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    reason: None,
                    level: AssuranceLevel::Transport,
                },
                PolicyRule {
                    host: Destination::Domain("c.test".into()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    reason: None,
                    level: AssuranceLevel::Tls,
                },
            ],
        };

        let dto = PolicyDto::from(&policy);
        let json = serde_json::to_string(&dto).unwrap();
        assert!(
            !json.contains("http_filters"),
            "non-http rules must not carry http_filters on the wire; json = {json}"
        );
    }

    #[test]
    fn session_config_dto_propagates_new_fields() {
        let config = SessionConfig {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: true,
            repo: Some("https://github.com/example/app.git".into()),
            boot_cmd: Some("make setup".into()),
            template: Some("/tmp/custom.yaml".into()),
            cpus_decimal: None,
            rootless_docker: None,
        };
        let dto: SessionConfigDto = (&config).into();
        assert_eq!(
            dto.repo.as_deref(),
            Some("https://github.com/example/app.git")
        );
        assert_eq!(dto.boot_cmd.as_deref(), Some("make setup"));
        assert_eq!(dto.template.as_deref(), Some("/tmp/custom.yaml"));
    }

    #[test]
    fn session_config_dto_renders_workspace_mode_as_string() {
        let config = SessionConfig {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: Some(WorkspaceMode::Shared {
                host_path: "/home/olek/project".into(),
            }),
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };
        let dto: SessionConfigDto = (&config).into();
        assert_eq!(
            dto.workspace_mode.as_deref(),
            Some("shared:/home/olek/project")
        );

        let clone_cfg = SessionConfig {
            workspace_mode: Some(WorkspaceMode::Clone {
                repo_url: "https://github.com/example/app.git".into(),
            }),
            ..config
        };
        let clone_dto: SessionConfigDto = (&clone_cfg).into();
        assert_eq!(
            clone_dto.workspace_mode.as_deref(),
            Some("clone:https://github.com/example/app.git")
        );
    }

    #[test]
    fn session_dto_resolves_container_zero_sentinels_to_host_defaults() {
        // Container session with the `0`-sentinel persisted shape (caller
        // did not pass `--cpus`/`--memory`). The DTO must surface the
        // daemon's host-80% default in `resolved_*`, not the stored 0,
        // so HTTP clients can verify the actually-applied ceiling.
        let config = SessionConfig {
            cpus: 0,
            memory_mb: 0,
            disk_gb: 20,
            workspace_mode: None,
            hardened: false,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };
        let session = Session::with_config_and_backend(
            Some("lite-resolve".into()),
            config,
            crate::backend::BackendKind::Container,
        );
        let dto = SessionDto::from(&session);

        // Stored values pass through untouched. `cpus` is `f32`
        // post-todo-#67; `0` parses on the wire as `0.0_f32`.
        assert_eq!(dto.config.cpus, 0.0_f32);
        assert_eq!(dto.config.memory_mb, 0);

        // Resolved values match `compute_default_resource_limits`.
        let (default_memory_mb, default_cpus) = compute_default_resource_limits();
        assert!(
            (dto.config.resolved_cpus - default_cpus).abs() < f64::EPSILON,
            "resolved_cpus should equal compute_default_resource_limits.1; \
             got {}, expected {}",
            dto.config.resolved_cpus,
            default_cpus,
        );
        assert_eq!(
            dto.config.resolved_memory_mb, default_memory_mb,
            "resolved_memory_mb should equal compute_default_resource_limits.0",
        );
    }

    #[test]
    fn session_dto_passes_explicit_container_resources_through_resolved_fields() {
        // Container session with non-zero `cpus`/`memory_mb` (caller
        // passed `--cpus`/`--memory`). The DTO must echo those values
        // verbatim under `resolved_*` — no host-80% substitution.
        let config = SessionConfig {
            cpus: 4,
            memory_mb: 8192,
            disk_gb: 20,
            workspace_mode: None,
            hardened: false,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };
        let session = Session::with_config_and_backend(
            Some("lite-explicit".into()),
            config,
            crate::backend::BackendKind::Container,
        );
        let dto = SessionDto::from(&session);

        assert_eq!(dto.config.cpus, 4.0_f32);
        assert_eq!(dto.config.memory_mb, 8192);
        assert!(
            (dto.config.resolved_cpus - 4.0).abs() < f64::EPSILON,
            "explicit cpus must round-trip as f64",
        );
        assert_eq!(dto.config.resolved_memory_mb, 8192);
    }

    #[test]
    fn session_dto_lima_resolved_fields_mirror_stored() {
        // Lima sessions never use the `0`-sentinel — `resolved_*`
        // mirrors `cpus`/`memory_mb` as plain f64/u32 so consumers
        // can rely on a single field for the applied value.
        let session = Session::new(Some("lima-default".into()));
        let dto = SessionDto::from(&session);
        assert_eq!(dto.backend, crate::backend::BackendKind::Lima);
        // `cpus` is `f32` post-todo-#67; widened to f64 for the
        // resolved-field comparison.
        assert!(
            (dto.config.cpus as f64 - dto.config.resolved_cpus).abs() < f64::EPSILON,
            "lima resolved_cpus must mirror cpus; got cpus={} resolved={}",
            dto.config.cpus,
            dto.config.resolved_cpus
        );
        assert_eq!(dto.config.memory_mb, dto.config.resolved_memory_mb);
    }

    /// M11-S7 todo #67: a container session whose persisted
    /// `cpus_decimal` carries a fractional value (`1.5`) surfaces
    /// that exact value on the wire `cpus` field — not the rounded-
    /// down integer `cpus` column the older daemon's view would have
    /// returned. Pins the round-trip the daemon's create handler
    /// stamps when it parses `--cpus 1.5`.
    #[test]
    fn session_dto_surfaces_fractional_cpus_decimal_on_wire() {
        let config = SessionConfig {
            cpus: 1, // floor of the precise value
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: false,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: Some(1.5),
            rootless_docker: None,
        };
        let session = Session::with_config_and_backend(
            Some("lite-fractional".into()),
            config,
            crate::backend::BackendKind::Container,
        );
        let dto = SessionDto::from(&session);
        assert_eq!(dto.config.cpus, 1.5_f32);
        assert!(
            (dto.config.resolved_cpus - 1.5).abs() < f64::EPSILON,
            "resolved_cpus must mirror the precise stored value; got {}",
            dto.config.resolved_cpus
        );
    }

    // -- M11-S7 Bundle Y: SessionNetworkInfo / SessionMountInfo wire shape ---

    #[test]
    fn session_dto_omits_network_and_mounts_when_none() {
        // Default `From<&Session>` path (used by `GET /sessions` and
        // by `POST /sessions` on the create response) must NOT carry
        // either block — the daemon attaches them only on
        // `GET /sessions/{id}`. The DTO field's
        // `skip_serializing_if = "Option::is_none"` guarantees the
        // keys disappear entirely, not as `null` placeholders.
        let session = Session::new(Some("net-mounts-empty".into()));
        let dto = SessionDto::from(&session);
        assert!(dto.network.is_none());
        assert!(dto.mounts.is_none());

        let json = serde_json::to_string(&dto).unwrap();
        assert!(
            !json.contains("\"network\""),
            "network key must be omitted when None; json = {json}"
        );
        assert!(
            !json.contains("\"mounts\""),
            "mounts key must be omitted when None; json = {json}"
        );
    }

    #[test]
    fn session_dto_with_network_renders_complete_block() {
        let session = Session::new(Some("net-attached".into()));
        let net = SessionNetworkInfo {
            gateway_ip: "10.209.0.2".into(),
            session_ip: "10.209.0.3".into(),
            session_subnet_cidr: "10.209.0.0/28".into(),
        };
        let dto = SessionDto::from(&session).with_network(Some(net.clone()));

        let value = serde_json::to_value(&dto).unwrap();
        let block = &value["network"];
        assert_eq!(block["gateway_ip"], "10.209.0.2");
        assert_eq!(block["session_ip"], "10.209.0.3");
        assert_eq!(block["session_subnet_cidr"], "10.209.0.0/28");

        // Round-trips back to an equal struct via `#[serde(default)]`
        // on the parent — the explicit lock for both directions of
        // forward-/backward-compat per CLAUDE.md persistence rules.
        let json = serde_json::to_string(&dto).unwrap();
        let deser: SessionDto = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.network.as_ref(), Some(&net));
    }

    #[test]
    fn session_dto_with_mounts_container_shape_round_trips() {
        // Container session shape: every field populated.
        let session = Session::with_config_and_backend(
            Some("mounts-container".into()),
            SessionConfig {
                cpus: 0,
                memory_mb: 0,
                disk_gb: 20,
                workspace_mode: Some(WorkspaceMode::Shared {
                    host_path: "/home/olek/proj".into(),
                }),
                hardened: false,
                repo: None,
                boot_cmd: None,
                template: None,
                cpus_decimal: None,
                rootless_docker: None,
            },
            crate::backend::BackendKind::Container,
        );
        let mounts = SessionMountInfo {
            workspace_path: "/home/agent/workspace/".into(),
            workspace_host_path: Some("/home/olek/proj".into()),
            ca_bundle_path: Some("/etc/ssl/certs/sandbox-ca.pem".into()),
            home_volume: Some("sandbox-home-aabbccddeeff".into()),
        };
        let dto = SessionDto::from(&session).with_mounts(Some(mounts.clone()));

        let value = serde_json::to_value(&dto).unwrap();
        let block = &value["mounts"];
        assert_eq!(block["workspace_path"], "/home/agent/workspace/");
        assert_eq!(block["workspace_host_path"], "/home/olek/proj");
        assert_eq!(block["ca_bundle_path"], "/etc/ssl/certs/sandbox-ca.pem");
        assert_eq!(block["home_volume"], "sandbox-home-aabbccddeeff");

        let json = serde_json::to_string(&dto).unwrap();
        let deser: SessionDto = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.mounts.as_ref(), Some(&mounts));
    }

    #[test]
    fn session_dto_with_mounts_lima_omits_container_only_keys() {
        // Lima session: ca_bundle_path is None (CA injected via guest
        // agent, no bind), home_volume is None (no Docker volume).
        // Both `Option<String>` fields with
        // `skip_serializing_if = "Option::is_none"` so the wire JSON
        // simply omits them — operators get a clean per-backend view.
        let session = Session::new(Some("mounts-lima".into()));
        let mounts = SessionMountInfo {
            workspace_path: "/home/agent/workspace/".into(),
            workspace_host_path: None,
            ca_bundle_path: None,
            home_volume: None,
        };
        let dto = SessionDto::from(&session).with_mounts(Some(mounts.clone()));

        let value = serde_json::to_value(&dto).unwrap();
        let block = value["mounts"]
            .as_object()
            .expect("mounts must be an object on the wire");
        assert_eq!(
            block.get("workspace_path").and_then(|v| v.as_str()),
            Some("/home/agent/workspace/")
        );
        assert!(
            !block.contains_key("workspace_host_path"),
            "workspace_host_path must be omitted when None; mounts = {value:?}"
        );
        assert!(
            !block.contains_key("ca_bundle_path"),
            "ca_bundle_path must be omitted when None on Lima; mounts = {value:?}"
        );
        assert!(
            !block.contains_key("home_volume"),
            "home_volume must be omitted when None on Lima; mounts = {value:?}"
        );

        let json = serde_json::to_string(&dto).unwrap();
        let deser: SessionDto = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.mounts.as_ref(), Some(&mounts));
    }

    // -- M11-S8 Wave 2: SessionRootlessDocker wire shape ---------------------

    #[test]
    fn session_dto_omits_rootless_when_none() {
        // Default `From<&Session>` path (used by `GET /sessions`)
        // must NOT carry the block — the daemon attaches it only on
        // `GET /sessions/{id}` / `POST /sessions` for container
        // sessions. The DTO field's
        // `skip_serializing_if = "Option::is_none"` guarantees the
        // key disappears entirely (not as a `null` placeholder),
        // matching the network/mounts shape pattern.
        let session = Session::new(Some("rootless-empty".into()));
        let dto = SessionDto::from(&session);
        assert!(dto.rootless.is_none());

        let json = serde_json::to_string(&dto).unwrap();
        assert!(
            !json.contains("\"rootless\""),
            "rootless key must be omitted when None; json = {json}"
        );
    }

    #[test]
    fn session_dto_with_rootless_default_hardened_round_trips() {
        // Container session on a default-hardened host: probe
        // returned `false`, no force flag involved. Wire shape pins
        // `{detected: false, forced: false}`; both keys present so
        // the operator can disambiguate "Lima session (key absent)"
        // from "container session on default-hardened (both fields
        // false)".
        let session = Session::with_config_and_backend(
            Some("rootless-default".into()),
            SessionConfig::default(),
            crate::backend::BackendKind::Container,
        );
        let rootless = SessionRootlessDockerDto {
            detected: false,
            forced: false,
        };
        let dto = SessionDto::from(&session).with_rootless(Some(rootless));

        let value = serde_json::to_value(&dto).unwrap();
        let block = &value["rootless"];
        assert_eq!(block["detected"], serde_json::json!(false));
        assert_eq!(block["forced"], serde_json::json!(false));

        let json = serde_json::to_string(&dto).unwrap();
        let deser: SessionDto = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.rootless.as_ref(), Some(&rootless));
    }

    #[test]
    fn session_dto_with_rootless_forced_overrides_round_trip() {
        // Container session on a rootless host with the operator's
        // `--force-rootless-docker` opt-in honored: probe returned
        // `true`, the daemon proceeded, both fields are `true`.
        let session = Session::with_config_and_backend(
            Some("rootless-forced".into()),
            SessionConfig::default(),
            crate::backend::BackendKind::Container,
        );
        let rootless = SessionRootlessDockerDto {
            detected: true,
            forced: true,
        };
        let dto = SessionDto::from(&session).with_rootless(Some(rootless));

        let value = serde_json::to_value(&dto).unwrap();
        let block = &value["rootless"];
        assert_eq!(block["detected"], serde_json::json!(true));
        assert_eq!(block["forced"], serde_json::json!(true));

        let json = serde_json::to_string(&dto).unwrap();
        let deser: SessionDto = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.rootless.as_ref(), Some(&rootless));
    }

    /// Pre-Wave-2 records (and Lima sessions) lack the `rootless`
    /// key entirely. Forward-compat via `#[serde(default)]` on the
    /// parent — the deserializer must accept the absent key without
    /// error.
    #[test]
    fn session_dto_legacy_record_without_rootless_round_trips() {
        let v0_json = r#"{
            "id": "0123456789ab",
            "state": "running",
            "created_at": "2026-04-22T00:00:00Z",
            "updated_at": "2026-04-22T00:00:00Z",
            "config": {
                "cpus": 2,
                "memory_mb": 4096,
                "disk_gb": 20,
                "hardened": true
            },
            "backend": "container"
        }"#;

        let dto: SessionDto = serde_json::from_str(v0_json)
            .expect("pre-Wave-2 record must round-trip via #[serde(default)]");
        assert!(
            dto.rootless.is_none(),
            "missing `rootless` key must default to None"
        );
    }

    /// Mapper from the persisted `SessionRootlessDocker` to the wire
    /// DTO is field-for-field identity. Pinned so a future shape
    /// change in the persisted struct trips this test before reaching
    /// the wire surface.
    #[test]
    fn session_rootless_docker_persisted_to_dto_round_trip() {
        let persisted = crate::session::SessionRootlessDocker {
            detected: true,
            forced: false,
        };
        let dto: SessionRootlessDockerDto = (&persisted).into();
        assert_eq!(dto.detected, persisted.detected);
        assert_eq!(dto.forced, persisted.forced);
    }

    #[test]
    fn session_dto_v0_record_without_network_or_mounts_round_trips() {
        // CLAUDE.md persistence rule: records written by an older
        // daemon (which never carried `network` / `mounts`) must
        // deserialize without error on the newer reader, defaulting
        // both blocks to `None`. This exercises the
        // `#[serde(default)]` attribute on the parent fields.
        let v0_json = r#"{
            "id": "0123456789ab",
            "state": "running",
            "created_at": "2026-04-22T00:00:00Z",
            "updated_at": "2026-04-22T00:00:00Z",
            "config": {
                "cpus": 2,
                "memory_mb": 4096,
                "disk_gb": 20,
                "hardened": true
            },
            "backend": "lima"
        }"#;

        let dto: SessionDto = serde_json::from_str(v0_json)
            .expect("pre-Wave-2 v0 record must round-trip via #[serde(default)]");
        assert!(
            dto.network.is_none(),
            "missing `network` key must default to None"
        );
        assert!(
            dto.mounts.is_none(),
            "missing `mounts` key must default to None"
        );
        // Spot-check that the rest of the fields didn't lose data.
        assert_eq!(dto.id.as_str(), "0123456789ab");
        assert_eq!(dto.config.cpus, 2.0_f32);
        assert_eq!(dto.backend, crate::backend::BackendKind::Lima);
    }
}
