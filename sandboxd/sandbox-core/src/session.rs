use std::path::Path;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How the workspace directory is made available inside the VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkspaceMode {
    /// Mount a host directory into the VM via 9p (bidirectional, live).
    Shared {
        /// Absolute path on the host to mount.
        host_path: String,
    },
    /// Clone a git repository into the VM at /home/agent/workspace/.
    Clone {
        /// Git repository URL.
        repo_url: String,
    },
}

impl WorkspaceMode {
    /// Parse a workspace mode from the CLI `--workspace` flag value.
    ///
    /// Accepted formats:
    /// - `shared:/absolute/host/path`
    pub fn parse_flag(value: &str) -> Result<Self, String> {
        if let Some(path) = value.strip_prefix("shared:") {
            if path.is_empty() {
                return Err("shared workspace path must not be empty".into());
            }
            if !Path::new(path).is_absolute() {
                return Err(format!(
                    "shared workspace path must be absolute, got: {path}"
                ));
            }
            if !Path::new(path).exists() {
                return Err(format!(
                    "shared workspace path does not exist: {path}"
                ));
            }
            Ok(Self::Shared {
                host_path: path.to_string(),
            })
        } else {
            Err(format!(
                "unknown workspace mode: {value}. Expected 'shared:<host-path>'"
            ))
        }
    }
}

/// Current state of a sandbox session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Creating,
    Running,
    Stopped,
    Error,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Creating => write!(f, "Creating"),
            Self::Running => write!(f, "Running"),
            Self::Stopped => write!(f, "Stopped"),
            Self::Error => write!(f, "Error"),
        }
    }
}

impl FromStr for SessionState {
    type Err = crate::SandboxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Creating" => Ok(Self::Creating),
            "Running" => Ok(Self::Running),
            "Stopped" => Ok(Self::Stopped),
            "Error" => Ok(Self::Error),
            other => Err(crate::SandboxError::Internal(format!(
                "unknown session state: {other}"
            ))),
        }
    }
}

/// Resource configuration for a sandbox session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Number of CPU cores allocated.
    pub cpus: u32,
    /// Memory in megabytes.
    pub memory_mb: u32,
    /// Disk size in gigabytes.
    pub disk_gb: u32,
    /// How the workspace is provided to the VM (if at all).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_mode: Option<WorkspaceMode>,
    /// Enable QEMU hardening (device lockdown, seccomp).
    ///
    /// When `true` (the default), the QEMU wrapper disables unnecessary
    /// devices and enables seccomp sandboxing.  Set to `false` for debugging
    /// or when the hardened configuration causes compatibility issues.
    #[serde(default = "default_hardened")]
    pub hardened: bool,
}

fn default_hardened() -> bool {
    true
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: true,
        }
    }
}

/// A sandbox session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub state: SessionState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub config: SessionConfig,
}

impl Session {
    /// Create a new session with the given name and default config.
    pub fn new(name: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            state: SessionState::Creating,
            created_at: now,
            updated_at: now,
            config: SessionConfig::default(),
        }
    }

    /// Create a new session with a specific config.
    pub fn with_config(name: Option<String>, config: SessionConfig) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            state: SessionState::Creating,
            created_at: now,
            updated_at: now,
            config,
        }
    }

    /// Transition to a new state, updating the `updated_at` timestamp.
    ///
    /// Valid transitions:
    /// - Creating -> Running | Error
    /// - Running -> Stopped | Error
    /// - Stopped -> Running | Error
    /// - Error -> (terminal, no transitions)
    pub fn transition_to(
        &mut self,
        new_state: SessionState,
    ) -> Result<(), crate::SandboxError> {
        let valid = matches!(
            (self.state, new_state),
            (SessionState::Creating, SessionState::Running)
                | (SessionState::Creating, SessionState::Error)
                | (SessionState::Running, SessionState::Stopped)
                | (SessionState::Running, SessionState::Error)
                | (SessionState::Stopped, SessionState::Running)
                | (SessionState::Stopped, SessionState::Error)
        );

        if !valid {
            return Err(crate::SandboxError::InvalidState(format!(
                "cannot transition from {} to {}",
                self.state, new_state
            )));
        }

        self.state = new_state;
        self.updated_at = Utc::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_has_creating_state() {
        let session = Session::new(Some("test".into()));
        assert_eq!(session.state, SessionState::Creating);
        assert_eq!(session.name, Some("test".into()));
        assert_eq!(session.config.cpus, 2);
        assert_eq!(session.config.memory_mb, 4096);
        assert_eq!(session.config.disk_gb, 20);
    }

    #[test]
    fn new_session_without_name() {
        let session = Session::new(None);
        assert_eq!(session.state, SessionState::Creating);
        assert!(session.name.is_none());
    }

    #[test]
    fn session_with_custom_config() {
        let config = SessionConfig {
            cpus: 4,
            memory_mb: 8192,
            disk_gb: 50,
            workspace_mode: None,
            hardened: true,
        };
        let session = Session::with_config(Some("custom".into()), config);
        assert_eq!(session.config.cpus, 4);
        assert_eq!(session.config.memory_mb, 8192);
        assert_eq!(session.config.disk_gb, 50);
    }

    #[test]
    fn valid_state_transitions() {
        let mut session = Session::new(None);
        assert_eq!(session.state, SessionState::Creating);

        // Creating -> Running
        session.transition_to(SessionState::Running).unwrap();
        assert_eq!(session.state, SessionState::Running);

        // Running -> Stopped
        session.transition_to(SessionState::Stopped).unwrap();
        assert_eq!(session.state, SessionState::Stopped);

        // Stopped -> Running (restart)
        session.transition_to(SessionState::Running).unwrap();
        assert_eq!(session.state, SessionState::Running);
    }

    #[test]
    fn invalid_state_transition() {
        let mut session = Session::new(None);
        // Creating -> Stopped is not valid
        let result = session.transition_to(SessionState::Stopped);
        assert!(result.is_err());
        // State should be unchanged
        assert_eq!(session.state, SessionState::Creating);
    }

    #[test]
    fn error_state_is_terminal() {
        let mut session = Session::new(None);
        session.transition_to(SessionState::Error).unwrap();
        assert_eq!(session.state, SessionState::Error);

        // Cannot transition out of Error
        let result = session.transition_to(SessionState::Running);
        assert!(result.is_err());
        assert_eq!(session.state, SessionState::Error);
    }

    #[test]
    fn transition_updates_timestamp() {
        let mut session = Session::new(None);
        let original = session.updated_at;

        // Small sleep to ensure timestamps differ
        std::thread::sleep(std::time::Duration::from_millis(10));

        session.transition_to(SessionState::Running).unwrap();
        assert!(session.updated_at > original);
    }

    #[test]
    fn serialization_round_trip() {
        let session = Session::new(Some("round-trip".into()));
        let json = serde_json::to_string(&session).unwrap();
        let deserialized: Session = serde_json::from_str(&json).unwrap();

        assert_eq!(session.id, deserialized.id);
        assert_eq!(session.name, deserialized.name);
        assert_eq!(session.state, deserialized.state);
        assert_eq!(session.created_at, deserialized.created_at);
        assert_eq!(session.config.cpus, deserialized.config.cpus);
        assert_eq!(session.config.memory_mb, deserialized.config.memory_mb);
        assert_eq!(session.config.disk_gb, deserialized.config.disk_gb);
    }

    #[test]
    fn session_state_serialization() {
        // Verify snake_case serialization
        let json = serde_json::to_string(&SessionState::Creating).unwrap();
        assert_eq!(json, "\"creating\"");

        let json = serde_json::to_string(&SessionState::Running).unwrap();
        assert_eq!(json, "\"running\"");

        let json = serde_json::to_string(&SessionState::Stopped).unwrap();
        assert_eq!(json, "\"stopped\"");

        let json = serde_json::to_string(&SessionState::Error).unwrap();
        assert_eq!(json, "\"error\"");

        // Round-trip
        let state: SessionState = serde_json::from_str("\"running\"").unwrap();
        assert_eq!(state, SessionState::Running);
    }

    #[test]
    fn default_session_config() {
        let config = SessionConfig::default();
        assert_eq!(config.cpus, 2);
        assert_eq!(config.memory_mb, 4096);
        assert_eq!(config.disk_gb, 20);
        assert!(config.workspace_mode.is_none());
        assert!(config.hardened, "hardened should default to true");
    }

    #[test]
    fn hardened_defaults_true_on_deserialization() {
        // When the `hardened` field is missing from JSON, it should
        // default to true via the serde default function.
        let json = r#"{"cpus": 2, "memory_mb": 4096, "disk_gb": 20}"#;
        let config: SessionConfig = serde_json::from_str(json).unwrap();
        assert!(
            config.hardened,
            "hardened should default to true when absent from JSON"
        );
    }

    #[test]
    fn hardened_false_roundtrip() {
        let config = SessionConfig {
            cpus: 2,
            memory_mb: 4096,
            disk_gb: 20,
            workspace_mode: None,
            hardened: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deser: SessionConfig = serde_json::from_str(&json).unwrap();
        assert!(
            !deser.hardened,
            "hardened=false should survive serialization round-trip"
        );
    }

    #[test]
    fn workspace_mode_parse_shared() {
        // We cannot test with a real path that must exist, so test the
        // validation logic for non-absolute and empty paths.
        let err = WorkspaceMode::parse_flag("shared:").unwrap_err();
        assert!(err.contains("must not be empty"), "err = {err}");

        let err = WorkspaceMode::parse_flag("shared:relative/path").unwrap_err();
        assert!(err.contains("must be absolute"), "err = {err}");

        let err = WorkspaceMode::parse_flag("shared:/nonexistent/path/xyzzy").unwrap_err();
        assert!(err.contains("does not exist"), "err = {err}");

        // Use /tmp which is guaranteed to exist.
        let mode = WorkspaceMode::parse_flag("shared:/tmp").unwrap();
        assert_eq!(
            mode,
            WorkspaceMode::Shared {
                host_path: "/tmp".into()
            }
        );
    }

    #[test]
    fn workspace_mode_parse_unknown() {
        let err = WorkspaceMode::parse_flag("foobar:/some/path").unwrap_err();
        assert!(err.contains("unknown workspace mode"), "err = {err}");
    }

    #[test]
    fn workspace_mode_serialization_shared() {
        let mode = WorkspaceMode::Shared {
            host_path: "/home/user/project".into(),
        };
        let json = serde_json::to_string(&mode).unwrap();
        let deser: WorkspaceMode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, mode);
    }

    #[test]
    fn workspace_mode_serialization_clone() {
        let mode = WorkspaceMode::Clone {
            repo_url: "https://github.com/example/repo.git".into(),
        };
        let json = serde_json::to_string(&mode).unwrap();
        let deser: WorkspaceMode = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, mode);
    }
}
