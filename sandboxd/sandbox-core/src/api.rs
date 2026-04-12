use serde::Deserialize;

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
}
