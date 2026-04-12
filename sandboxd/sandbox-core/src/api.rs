use serde::{Deserialize, Serialize};

use crate::session::{Session, SessionConfig, SessionState};

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
        }
    }

    /// Create from a `Session` with guest agent status.
    pub fn from_session_with_status(session: Session, status: Option<String>) -> Self {
        Self {
            id: session.id,
            name: session.name,
            state: session.state,
            created_at: session.created_at,
            updated_at: session.updated_at,
            config: session.config,
            guest_agent_status: status,
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
        );
        assert_eq!(resp.id, session.id);
        assert_eq!(resp.guest_agent_status, Some("connected".into()));
    }

    #[test]
    fn session_response_serialization_omits_none() {
        let session = Session::new(None);
        let resp = SessionResponse::from_session(session);
        let json = serde_json::to_string(&resp).unwrap();
        // name and guest_agent_status should be omitted when None
        assert!(!json.contains("name"));
        assert!(!json.contains("guest_agent_status"));
    }
}
