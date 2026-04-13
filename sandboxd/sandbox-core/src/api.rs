use serde::{Deserialize, Serialize};

use crate::session::{Session, SessionConfig, SessionState};

// ---------------------------------------------------------------------------
// Health types
// ---------------------------------------------------------------------------

/// Detailed health status for a sandbox session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHealth {
    pub session_id: uuid::Uuid,
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

/// Enriched session response with optional guest agent health status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub id: uuid::Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub state: SessionState,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub config: SessionConfig,
    /// Guest agent connectivity status: "connected", "unreachable", or null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_agent_status: Option<String>,
    /// Gateway container status: "running", "stopped", "not_found", or null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_status: Option<String>,
}

impl SessionResponse {
    /// Create from a `Session` without guest agent status.
    pub fn from_session(session: Session) -> Self {
        Self {
            id: session.id,
            name: session.name,
            state: session.state,
            created_at: session.created_at,
            updated_at: session.updated_at,
            config: session.config,
            guest_agent_status: None,
            gateway_status: None,
        }
    }

    /// Create from a `Session` with guest agent and gateway status.
    pub fn from_session_with_status(
        session: Session,
        agent_status: Option<String>,
        gateway_status: Option<String>,
    ) -> Self {
        Self {
            id: session.id,
            name: session.name,
            state: session.state,
            created_at: session.created_at,
            updated_at: session.updated_at,
            config: session.config,
            guest_agent_status: agent_status,
            gateway_status,
        }
    }
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
    fn session_response_from_session() {
        let session = Session::new(Some("test".into()));
        let resp = SessionResponse::from_session(session.clone());
        assert_eq!(resp.id, session.id);
        assert_eq!(resp.name, session.name);
        assert!(resp.guest_agent_status.is_none());
    }

    #[test]
    fn session_response_with_status() {
        let session = Session::new(Some("test".into()));
        let resp = SessionResponse::from_session_with_status(
            session.clone(),
            Some("connected".into()),
            Some("healthy".into()),
        );
        assert_eq!(resp.id, session.id);
        assert_eq!(resp.guest_agent_status, Some("connected".into()));
        assert_eq!(resp.gateway_status, Some("healthy".into()));
    }

    #[test]
    fn session_response_serialization_omits_none() {
        let session = Session::new(None);
        let resp = SessionResponse::from_session(session);
        let json = serde_json::to_string(&resp).unwrap();
        // name, guest_agent_status, and gateway_status should be omitted when None
        assert!(!json.contains("name"));
        assert!(!json.contains("guest_agent_status"));
        assert!(!json.contains("gateway_status"));
    }

    #[test]
    fn session_health_serialization() {
        let health = SessionHealth {
            session_id: uuid::Uuid::nil(),
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
            session_id: uuid::Uuid::nil(),
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
    fn session_response_with_gateway_status() {
        let session = Session::new(Some("gw-test".into()));
        let resp = SessionResponse::from_session_with_status(
            session.clone(),
            Some("connected".into()),
            Some("running".into()),
        );
        assert_eq!(resp.gateway_status, Some("running".into()));

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"gateway_status\":\"running\""));
    }
}
