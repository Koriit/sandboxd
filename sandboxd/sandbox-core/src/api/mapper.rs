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

use crate::policy::{AssuranceLevel, Policy, PolicyRule};
use crate::session::{Session, SessionConfig, WorkspaceMode};

use super::dto::{PolicyDto, PolicyLevelDto, PolicyRuleDto, SessionConfigDto, SessionDto};

// ---------------------------------------------------------------------------
// Session mapping
// ---------------------------------------------------------------------------

impl From<&Session> for SessionDto {
    fn from(session: &Session) -> Self {
        Self {
            id: session.id,
            name: session.name.clone(),
            state: session.state,
            created_at: session.created_at,
            updated_at: session.updated_at,
            config: (&session.config).into(),
            guest_agent_status: None,
            gateway_status: None,
            policy: None,
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
}

impl From<&SessionConfig> for SessionConfigDto {
    fn from(config: &SessionConfig) -> Self {
        Self {
            cpus: config.cpus,
            memory_mb: config.memory_mb,
            disk_gb: config.disk_gb,
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
}
