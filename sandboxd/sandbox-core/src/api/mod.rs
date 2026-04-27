use serde::{Deserialize, Serialize};

use crate::session::SessionId;

pub mod dto;
pub mod event_dto;
pub mod event_mapper;
pub mod events_filter;
pub mod events_query_dto;
pub mod mapper;

pub use dto::{PolicyDto, PolicyLevelDto, PolicyRuleDto, SessionConfigDto, SessionDto};
pub use event_dto::{
    DenyLoggerEventBodyDto, DenyLoggerEventDto, DenyProtocolDto, DnsEventBodyDto, DnsEventDto,
    EnvoyConnectionDto, EnvoyEventBodyDto, EnvoyEventDto, EventDto, GatewayShutdownReasonDto,
    HealthComponentDto, LifecycleEventBodyDto, LifecycleEventDto, MitmproxyEventBodyDto,
    MitmproxyEventDto, PolicyApplyStatusDto,
};
pub use event_mapper::event_to_jsonl_line;
pub use events_filter::{EventName, EventsFilter, LayerKind};
pub use events_query_dto::{DecisionKind, EventsQueryDto};

// ---------------------------------------------------------------------------
// Health types
// ---------------------------------------------------------------------------

/// Detailed health status for a sandbox session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHealth {
    pub session_id: SessionId,
    pub vm_status: String,
    pub guest_agent: String,
    pub gateway: GatewayHealth,
    pub network: NetworkHealth,
}

/// Health status of gateway components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayHealth {
    pub container_status: String,
    pub envoy: String,
    pub mitmproxy: String,
    pub coredns: String,
}

/// Health status of network resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealth {
    pub bridge_exists: bool,
    pub tap_exists: bool,
}

/// Wire-level response shape for
/// `GET /sessions/{id}/policy/propagation-status`.
///
/// Produced by the daemon ([`sandboxd::policy_http`]) and consumed by
/// the `sandbox policy status [--wait]` CLI subcommand and the E2E
/// suite. Both sides share this type so a field rename at the HTTP
/// layer cannot silently drift from the CLI's wait loop.
///
/// # Fields
///
/// * `expected_hash` — hash of the policy most recently handed to the
///   distributor. `None` when no policy has ever been applied to the
///   session.
/// * `propagated_hash` — hash of the policy most recently observed to
///   have fully reconciled across all three enforcement layers. `None`
///   until the first reconciliation edge; cleared whenever
///   `expected_hash` changes. Equal to `expected_hash` iff
///   `propagated` is `true`.
/// * `propagated` — convenience boolean, true iff both hashes are
///   `Some` and equal.
/// * `seconds_since_apply` — wall-clock seconds since `expected_hash`
///   last changed. `0` when no policy has ever been applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationStatusResponse {
    /// Hash of the policy most recently handed to the distributor.
    pub expected_hash: Option<String>,
    /// Hash of the policy most recently observed to have fully
    /// reconciled across all three enforcement layers.
    pub propagated_hash: Option<String>,
    /// Convenience: `true` iff the two hashes are `Some` and equal.
    pub propagated: bool,
    /// Wall-clock seconds since `expected_hash` last changed.
    pub seconds_since_apply: u64,
}

/// Request body for `POST /sessions`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CreateSessionRequest {
    /// Optional human-readable name for the session.
    pub name: Option<String>,
    /// Number of CPU cores (default: 2).
    pub cpus: Option<u32>,
    /// Memory in megabytes (default: 4096).
    pub memory_mb: Option<u32>,
    /// Disk size in gigabytes (default: 20).
    pub disk_gb: Option<u32>,
    /// Path to a custom Lima template (overrides auto-generation).
    pub template: Option<String>,
    /// Optional policy to apply immediately after session creation.
    pub policy: Option<crate::policy::Policy>,
    /// Optional git repository URL to clone into `/home/agent/workspace/` after setup.
    ///
    /// Mutually exclusive with `workspace`. If both are provided, `workspace`
    /// takes precedence.
    pub repo: Option<String>,
    /// Optional command to execute after clone (or after setup if no repo).
    pub boot_cmd: Option<String>,
    /// Optional workspace mode string, e.g. `"shared:/home/user/project"`.
    ///
    /// Mutually exclusive with `repo`. When set to a `shared:` mode, the
    /// host directory is mounted into the VM at `/home/agent/workspace`
    /// via 9p.
    pub workspace: Option<String>,
    /// Enable QEMU hardening (device lockdown, cgroup limits).
    ///
    /// Defaults to `true`. Set to `false` for debugging or when the
    /// hardened configuration causes compatibility issues.
    pub hardened: Option<bool>,
    /// Skip the pre-baked golden image and use the full create path.
    ///
    /// When `true`, the daemon always creates a fresh VM from scratch
    /// instead of cloning from the base image.
    pub no_cache: Option<bool>,
    /// Original `--preset` invocation strings forwarded by the CLI.
    ///
    /// Populated by the CLI (M10-S5) when presets expanded into the
    /// policy document above, so the daemon can surface them on the
    /// `policy_applied` lifecycle event for operator debugging and
    /// audit. Optional and additive on the wire: older CLIs that do
    /// not send the field deserialize to an empty vector; newer
    /// daemons reading records written without the field do the
    /// same.
    ///
    /// The daemon never expands presets itself — preset expansion is
    /// strictly a CLI-local feature (spec Part 2 "Presets are CLI-
    /// local"). This field is a pure passthrough for attribution.
    #[serde(default)]
    pub source_presets: Vec<String>,
    /// Which backend should host the session.
    ///
    /// Optional on the wire (M11-S3 Phase 3D): older CLIs that omit
    /// the field decode to `None`, which the daemon treats as the
    /// historical default of `BackendKind::Lima`. Setting this to
    /// `Container` enables the lite-mode container backend (M11);
    /// the daemon validates the request against the chosen backend's
    /// capability matrix (e.g. rejects `--hardened` for Container)
    /// and persists the choice in the `sessions.backend` SQLite
    /// column so subsequent dispatch routes to the right runtime.
    #[serde(default)]
    pub backend: Option<crate::backend::BackendKind>,
}

/// Request body for `POST /sessions/{id}/upload`.
#[derive(Debug, Clone, Deserialize)]
pub struct FileUploadRequest {
    /// Path inside the VM to write the file to.
    pub path: String,
    /// Base64-encoded file data.
    pub data: String,
    /// Optional Unix file mode (e.g. 0o644).
    pub mode: Option<u32>,
}

/// Request body for `POST /sessions/{id}/download`.
#[derive(Debug, Clone, Deserialize)]
pub struct FileDownloadRequest {
    /// Path inside the VM to read.
    pub path: String,
}

/// Response body for `POST /sessions/{id}/download`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDownloadResponse {
    /// Base64-encoded file data.
    pub data: String,
}

/// Request body for `POST /sessions/{id}/policy`.
///
/// Contains the full policy document to compile and distribute to the
/// session's gateway components.
///
/// `source_presets` carries the CLI's original `--preset` invocation
/// strings, if any, so the daemon can stamp them onto the emitted
/// `policy_updated` lifecycle event. The field is additive and
/// optional on the wire (`#[serde(default)]`): records from older
/// CLIs decode cleanly, and the daemon never inspects the field for
/// policy semantics — preset expansion stays CLI-local per spec
/// Part 2.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpdatePolicyRequest {
    /// The policy document to apply.
    #[serde(flatten)]
    pub policy: crate::policy::Policy,
    /// Original `--preset` invocation strings forwarded by the CLI.
    ///
    /// Serialized when the field is non-empty; skipped when empty so
    /// older daemons that still parse v1 policy JSON as a raw `Policy`
    /// (via `#[serde(flatten)]`) see a bitwise-identical body when no
    /// presets contributed to the update. M10-S5 CLI wiring populates
    /// this from `--preset` invocations; callers without presets leave
    /// it empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_presets: Vec<String>,
}

/// Request body for `POST /sessions/{id}/exec`.
#[derive(Debug, Clone, Deserialize)]
pub struct ExecRequest {
    /// The command to execute inside the sandbox.
    pub command: String,
    /// Arguments to the command.
    #[serde(default)]
    pub args: Vec<String>,
}

/// Response body for `POST /sessions/{id}/exec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_empty_object() {
        let req: CreateSessionRequest = serde_json::from_str("{}").unwrap();
        assert!(req.name.is_none());
        assert!(req.cpus.is_none());
        assert!(req.memory_mb.is_none());
        assert!(req.disk_gb.is_none());
        assert!(req.template.is_none());
        assert!(req.policy.is_none());
        assert!(req.repo.is_none());
        assert!(req.boot_cmd.is_none());
        assert!(req.workspace.is_none());
        assert!(req.hardened.is_none());
        assert!(req.no_cache.is_none());
        assert!(
            req.source_presets.is_empty(),
            "source_presets must default to empty on an empty request object"
        );
        assert!(
            req.backend.is_none(),
            "backend must default to None so older CLIs round-trip as Lima"
        );
    }

    #[test]
    fn deserialize_backend_container() {
        // Wire shape: lower-case tag matches `BackendKind`'s
        // `#[serde(rename_all = "lowercase")]` attribute and the
        // SQLite column's CHECK constraint.
        let req: CreateSessionRequest =
            serde_json::from_str(r#"{"backend": "container"}"#).unwrap();
        assert_eq!(req.backend, Some(crate::backend::BackendKind::Container));
    }

    #[test]
    fn deserialize_backend_lima() {
        let req: CreateSessionRequest = serde_json::from_str(r#"{"backend": "lima"}"#).unwrap();
        assert_eq!(req.backend, Some(crate::backend::BackendKind::Lima));
    }

    #[test]
    fn deserialize_full_request() {
        let json = r#"{
            "name": "test",
            "cpus": 4,
            "memory_mb": 8192,
            "disk_gb": 50,
            "template": "/tmp/custom.yaml"
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("test"));
        assert_eq!(req.cpus, Some(4));
        assert_eq!(req.memory_mb, Some(8192));
        assert_eq!(req.disk_gb, Some(50));
        assert_eq!(req.template.as_deref(), Some("/tmp/custom.yaml"));
    }

    #[test]
    fn deserialize_partial_request() {
        let json = r#"{"name": "partial", "cpus": 8}"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("partial"));
        assert_eq!(req.cpus, Some(8));
        assert!(req.memory_mb.is_none());
        assert!(req.disk_gb.is_none());
        assert!(req.template.is_none());
    }

    #[test]
    fn deserialize_exec_request() {
        let json = r#"{"command": "uname", "args": ["-a"]}"#;
        let req: ExecRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.command, "uname");
        assert_eq!(req.args, vec!["-a"]);
    }

    #[test]
    fn deserialize_exec_request_no_args() {
        let json = r#"{"command": "whoami"}"#;
        let req: ExecRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.command, "whoami");
        assert!(req.args.is_empty());
    }

    #[test]
    fn exec_response_serialization() {
        let resp = ExecResponse {
            exit_code: 0,
            stdout: "hello\n".into(),
            stderr: String::new(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deserialized: ExecResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.exit_code, 0);
        assert_eq!(deserialized.stdout, "hello\n");
        assert!(deserialized.stderr.is_empty());
    }

    #[test]
    fn session_health_serialization() {
        let health = SessionHealth {
            session_id: SessionId::parse("000000000000").unwrap(),
            vm_status: "running".into(),
            guest_agent: "healthy".into(),
            gateway: GatewayHealth {
                container_status: "running".into(),
                envoy: "healthy".into(),
                mitmproxy: "healthy".into(),
                coredns: "healthy".into(),
            },
            network: NetworkHealth {
                bridge_exists: true,
                tap_exists: true,
            },
        };
        let json = serde_json::to_string(&health).unwrap();
        let deser: SessionHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.vm_status, "running");
        assert_eq!(deser.guest_agent, "healthy");
        assert_eq!(deser.gateway.container_status, "running");
        assert_eq!(deser.gateway.envoy, "healthy");
        assert_eq!(deser.gateway.mitmproxy, "healthy");
        assert_eq!(deser.gateway.coredns, "healthy");
        assert!(deser.network.bridge_exists);
        assert!(deser.network.tap_exists);
    }

    #[test]
    fn session_health_unhealthy_serialization() {
        let health = SessionHealth {
            session_id: SessionId::parse("000000000000").unwrap(),
            vm_status: "stopped".into(),
            guest_agent: "unknown".into(),
            gateway: GatewayHealth {
                container_status: "not_found".into(),
                envoy: "unknown".into(),
                mitmproxy: "unknown".into(),
                coredns: "unknown".into(),
            },
            network: NetworkHealth {
                bridge_exists: false,
                tap_exists: false,
            },
        };
        let json = serde_json::to_string(&health).unwrap();
        let deser: SessionHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.vm_status, "stopped");
        assert_eq!(deser.gateway.container_status, "not_found");
        assert!(!deser.network.bridge_exists);
        assert!(!deser.network.tap_exists);
    }

    #[test]
    fn gateway_health_round_trip() {
        let gw = GatewayHealth {
            container_status: "running".into(),
            envoy: "healthy".into(),
            mitmproxy: "unhealthy".into(),
            coredns: "healthy".into(),
        };
        let json = serde_json::to_string(&gw).unwrap();
        assert!(json.contains("\"envoy\":\"healthy\""));
        assert!(json.contains("\"mitmproxy\":\"unhealthy\""));
        let deser: GatewayHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.envoy, "healthy");
        assert_eq!(deser.mitmproxy, "unhealthy");
    }

    #[test]
    fn network_health_round_trip() {
        let net = NetworkHealth {
            bridge_exists: true,
            tap_exists: false,
        };
        let json = serde_json::to_string(&net).unwrap();
        let deser: NetworkHealth = serde_json::from_str(&json).unwrap();
        assert!(deser.bridge_exists);
        assert!(!deser.tap_exists);
    }

    #[test]
    fn deserialize_update_policy_request() {
        let json = r#"{
            "version": "2.0.0",
            "rules": [
                {
                    "host": "github.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "transport"
                }
            ]
        }"#;

        let req: UpdatePolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.policy.version, "2.0.0");
        assert_eq!(req.policy.rules.len(), 1);
    }

    #[test]
    fn deserialize_create_request_with_policy() {
        let json = r#"{
            "name": "with-policy",
            "cpus": 2,
            "policy": {
                "version": "2.0.0",
                "rules": [
                    {
                        "host": "example.com",
                        "port": 443,
                        "protocol": "tcp",
                        "level": "transport"
                    }
                ]
            }
        }"#;

        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("with-policy"));
        assert!(req.policy.is_some());
        let policy = req.policy.unwrap();
        assert_eq!(policy.version, "2.0.0");
        assert_eq!(policy.rules.len(), 1);
    }

    #[test]
    fn deserialize_create_request_without_policy() {
        let json = r#"{"name": "no-policy"}"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("no-policy"));
        assert!(req.policy.is_none());
    }

    #[test]
    fn deserialize_create_request_with_repo() {
        let json = r#"{"name": "with-repo", "repo": "https://github.com/octocat/Hello-World.git"}"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("with-repo"));
        assert_eq!(
            req.repo.as_deref(),
            Some("https://github.com/octocat/Hello-World.git")
        );
        assert!(req.boot_cmd.is_none());
    }

    #[test]
    fn deserialize_create_request_with_boot_cmd() {
        let json = r#"{"name": "with-boot", "boot_cmd": "npm install"}"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("with-boot"));
        assert_eq!(req.boot_cmd.as_deref(), Some("npm install"));
        assert!(req.repo.is_none());
    }

    #[test]
    fn deserialize_create_request_with_repo_and_boot_cmd() {
        let json = r#"{
            "name": "full-setup",
            "repo": "https://github.com/example/repo.git",
            "boot_cmd": "make build"
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("full-setup"));
        assert_eq!(
            req.repo.as_deref(),
            Some("https://github.com/example/repo.git")
        );
        assert_eq!(req.boot_cmd.as_deref(), Some("make build"));
    }

    #[test]
    fn deserialize_create_request_with_workspace() {
        let json = r#"{"name": "shared-ws", "workspace": "shared:/home/user/project"}"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("shared-ws"));
        assert_eq!(req.workspace.as_deref(), Some("shared:/home/user/project"));
        assert!(req.repo.is_none());
    }

    #[test]
    fn deserialize_create_request_with_hardened_false() {
        let json = r#"{"name": "debug-mode", "hardened": false}"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("debug-mode"));
        assert_eq!(req.hardened, Some(false));
    }

    #[test]
    fn deserialize_create_request_hardened_defaults_none() {
        let json = r#"{"name": "normal"}"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert!(
            req.hardened.is_none(),
            "hardened should be None when absent from request"
        );
    }

    #[test]
    fn deserialize_create_request_with_no_cache() {
        let json = r#"{"name": "no-cache-test", "no_cache": true}"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("no-cache-test"));
        assert_eq!(req.no_cache, Some(true));
    }

    #[test]
    fn deserialize_create_request_no_cache_defaults_none() {
        let json = r#"{"name": "normal"}"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert!(
            req.no_cache.is_none(),
            "no_cache should be None when absent from request"
        );
    }

    #[test]
    fn deserialize_create_request_without_source_presets_is_empty_vec() {
        // Backward-compat: pre-M10-S5 CLIs never send source_presets.
        // The default decode must be an empty vector, not an error.
        let json = r#"{"name": "legacy-cli"}"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert!(
            req.source_presets.is_empty(),
            "source_presets must default to empty Vec when absent"
        );
    }

    #[test]
    fn deserialize_create_request_with_source_presets() {
        let json = r#"{
            "name": "preset-aware",
            "source_presets": ["cargo", "github:api"]
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.source_presets,
            vec!["cargo".to_string(), "github:api".to_string()]
        );
    }

    #[test]
    fn deserialize_update_policy_request_without_source_presets_is_empty_vec() {
        // Flattened Policy + additive source_presets at the top level —
        // older CLIs that don't send the field still decode cleanly.
        let json = r#"{
            "version": "2.0.0",
            "rules": [
                {
                    "host": "github.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "transport"
                }
            ]
        }"#;
        let req: UpdatePolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.policy.version, "2.0.0");
        assert!(
            req.source_presets.is_empty(),
            "source_presets must default to empty Vec when absent"
        );
    }

    #[test]
    fn deserialize_update_policy_request_with_source_presets() {
        let json = r#"{
            "version": "2.0.0",
            "rules": [
                {
                    "host": "github.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "transport"
                }
            ],
            "source_presets": ["npm"]
        }"#;
        let req: UpdatePolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.policy.version, "2.0.0");
        assert_eq!(req.source_presets, vec!["npm".to_string()]);
    }

    #[test]
    fn deserialize_file_upload_request() {
        let json = r#"{"path": "/root/test.txt", "data": "aGVsbG8=", "mode": 420}"#;
        let req: FileUploadRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.path, "/root/test.txt");
        assert_eq!(req.data, "aGVsbG8=");
        assert_eq!(req.mode, Some(420));
    }

    #[test]
    fn deserialize_file_upload_request_no_mode() {
        let json = r#"{"path": "/root/test.txt", "data": "aGVsbG8="}"#;
        let req: FileUploadRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.path, "/root/test.txt");
        assert!(req.mode.is_none());
    }

    #[test]
    fn deserialize_file_download_request() {
        let json = r#"{"path": "/root/test.txt"}"#;
        let req: FileDownloadRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.path, "/root/test.txt");
    }

    #[test]
    fn file_download_response_serialization() {
        let resp = FileDownloadResponse {
            data: "aGVsbG8=".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let deser: FileDownloadResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.data, "aGVsbG8=");
    }
}
