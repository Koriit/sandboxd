use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::error::SandboxError;
use crate::session::{Session, SessionConfig, SessionState};

mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("migrations");
}

/// Persistent store for sandbox sessions backed by SQLite.
///
/// Thread-safe via an internal `Mutex<Connection>`. The daemon wraps
/// `SessionStore` in an `Arc` for sharing across async handlers.
pub struct SessionStore {
    conn: Mutex<Connection>,
    base_dir: PathBuf,
}

impl SessionStore {
    /// Open (or create) the session database at `{base_dir}/sessions.db`.
    ///
    /// Enables WAL mode and runs any pending migrations.
    pub fn new(base_dir: PathBuf) -> Result<Self, SandboxError> {
        fs::create_dir_all(&base_dir)?;

        let db_path = base_dir.join("sessions.db");
        let mut conn = Connection::open(&db_path)?;

        // Enable WAL mode for better concurrent read performance.
        conn.pragma_update(None, "journal_mode", "WAL")?;

        // Run embedded migrations.
        embedded::migrations::runner()
            .run(&mut conn)
            .map_err(|e| SandboxError::Internal(format!("migration error: {e}")))?;

        Ok(Self {
            conn: Mutex::new(conn),
            base_dir,
        })
    }

    /// Return the base directory used by this store.
    pub fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    /// Directory for per-session data: `{base_dir}/sessions/{id}/`.
    fn session_dir(&self, id: &Uuid) -> PathBuf {
        self.base_dir.join("sessions").join(id.to_string())
    }

    /// Create a new session, insert it into the database, and create its
    /// per-session directory.
    pub fn create_session(
        &self,
        config: SessionConfig,
        name: Option<String>,
    ) -> Result<Session, SandboxError> {
        let session = Session::with_config(name, config);

        let config_json =
            serde_json::to_string(&session.config).map_err(|e| {
                SandboxError::Internal(format!("failed to serialize config: {e}"))
            })?;

        let conn = self.conn.lock().map_err(|e| {
            SandboxError::Internal(format!("lock poisoned: {e}"))
        })?;

        conn.execute(
            "INSERT INTO sessions (id, name, state, config, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                session.id.to_string(),
                session.name,
                session.state.to_string(),
                config_json,
                session.created_at.to_rfc3339(),
                session.updated_at.to_rfc3339(),
            ],
        )?;

        // Create the per-session directory.
        fs::create_dir_all(self.session_dir(&session.id))?;

        Ok(session)
    }

    /// Retrieve a session by ID, or `None` if it does not exist.
    pub fn get_session(&self, id: &Uuid) -> Result<Option<Session>, SandboxError> {
        let conn = self.conn.lock().map_err(|e| {
            SandboxError::Internal(format!("lock poisoned: {e}"))
        })?;

        let mut stmt = conn.prepare(
            "SELECT id, name, state, config, created_at, updated_at
             FROM sessions WHERE id = ?1",
        )?;

        let mut rows = stmt.query(params![id.to_string()])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_session(row)?)),
            None => Ok(None),
        }
    }

    /// List all sessions.
    pub fn list_sessions(&self) -> Result<Vec<Session>, SandboxError> {
        let conn = self.conn.lock().map_err(|e| {
            SandboxError::Internal(format!("lock poisoned: {e}"))
        })?;

        let mut stmt = conn.prepare(
            "SELECT id, name, state, config, created_at, updated_at
             FROM sessions ORDER BY created_at ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            row_to_session(row).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())),
                )
            })
        })?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(row?);
        }
        Ok(sessions)
    }

    /// Update the state of a session and refresh its `updated_at` timestamp.
    ///
    /// Validates that the transition is allowed by the session state machine
    /// (see [`SessionState::can_transition_to`]).  Returns
    /// `SandboxError::InvalidState` if the transition is not valid.
    ///
    /// For reconciliation or crash-recovery code that must force a state
    /// regardless of the current value, use [`update_state_forced`] instead.
    pub fn update_state(
        &self,
        id: &Uuid,
        new_state: SessionState,
    ) -> Result<(), SandboxError> {
        let conn = self.conn.lock().map_err(|e| {
            SandboxError::Internal(format!("lock poisoned: {e}"))
        })?;

        // Fetch the current state so we can validate the transition.
        let current_state = {
            let mut stmt = conn.prepare(
                "SELECT state FROM sessions WHERE id = ?1",
            )?;
            let mut rows = stmt.query(params![id.to_string()])?;
            match rows.next()? {
                Some(row) => {
                    let state_str: String = row.get(0)?;
                    SessionState::from_str(&state_str)?
                }
                None => return Err(SandboxError::SessionNotFound(id.to_string())),
            }
        };

        if !current_state.can_transition_to(new_state) {
            return Err(SandboxError::InvalidState(format!(
                "cannot transition from {} to {}",
                current_state, new_state
            )));
        }

        let now = Utc::now();
        conn.execute(
            "UPDATE sessions SET state = ?1, updated_at = ?2 WHERE id = ?3",
            params![new_state.to_string(), now.to_rfc3339(), id.to_string()],
        )?;

        Ok(())
    }

    /// Forcibly set the state of a session, bypassing state machine validation.
    ///
    /// This is intended **only** for reconciliation and crash-recovery code
    /// that must align the DB with external reality (e.g. a VM that was
    /// found running when the DB says Stopped).  Normal handler code should
    /// use [`update_state`] which enforces the state machine.
    pub fn update_state_forced(
        &self,
        id: &Uuid,
        state: SessionState,
    ) -> Result<(), SandboxError> {
        let now = Utc::now();

        let conn = self.conn.lock().map_err(|e| {
            SandboxError::Internal(format!("lock poisoned: {e}"))
        })?;

        let rows_affected = conn.execute(
            "UPDATE sessions SET state = ?1, updated_at = ?2 WHERE id = ?3",
            params![state.to_string(), now.to_rfc3339(), id.to_string()],
        )?;

        if rows_affected == 0 {
            return Err(SandboxError::SessionNotFound(id.to_string()));
        }

        Ok(())
    }

    /// Look up a session by name or UUID string.
    ///
    /// Tries to parse `query` as a UUID first; if that fails, searches by name.
    /// Returns `None` if no session matches.
    pub fn get_session_by_name_or_id(
        &self,
        query: &str,
    ) -> Result<Option<Session>, SandboxError> {
        // Try UUID first.
        if let Ok(uuid) = Uuid::parse_str(query) {
            return self.get_session(&uuid);
        }

        // Fall back to name lookup.
        let conn = self.conn.lock().map_err(|e| {
            SandboxError::Internal(format!("lock poisoned: {e}"))
        })?;

        let mut stmt = conn.prepare(
            "SELECT id, name, state, config, created_at, updated_at
             FROM sessions WHERE name = ?1",
        )?;

        let mut rows = stmt.query(params![query])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_session(row)?)),
            None => Ok(None),
        }
    }

    /// Store network info for a session (serialized as JSON).
    pub fn set_network_info(
        &self,
        id: &Uuid,
        info: &crate::network::NetworkInfo,
    ) -> Result<(), SandboxError> {
        let json = serde_json::to_string(info).map_err(|e| {
            SandboxError::Internal(format!("failed to serialize network info: {e}"))
        })?;

        let conn = self.conn.lock().map_err(|e| {
            SandboxError::Internal(format!("lock poisoned: {e}"))
        })?;

        let rows_affected = conn.execute(
            "UPDATE sessions SET network_info = ?1 WHERE id = ?2",
            params![json, id.to_string()],
        )?;

        if rows_affected == 0 {
            return Err(SandboxError::SessionNotFound(id.to_string()));
        }

        Ok(())
    }

    /// Retrieve network info for a session, if it has been set.
    pub fn get_network_info(
        &self,
        id: &Uuid,
    ) -> Result<Option<crate::network::NetworkInfo>, SandboxError> {
        let conn = self.conn.lock().map_err(|e| {
            SandboxError::Internal(format!("lock poisoned: {e}"))
        })?;

        let mut stmt = conn.prepare(
            "SELECT network_info FROM sessions WHERE id = ?1",
        )?;

        let mut rows = stmt.query(params![id.to_string()])?;
        match rows.next()? {
            Some(row) => {
                let json: Option<String> = row.get(0)?;
                match json {
                    Some(j) => {
                        let info: crate::network::NetworkInfo =
                            serde_json::from_str(&j).map_err(|e| {
                                SandboxError::Internal(format!(
                                    "invalid network_info JSON in database: {e}"
                                ))
                            })?;
                        Ok(Some(info))
                    }
                    None => Ok(None),
                }
            }
            None => Err(SandboxError::SessionNotFound(id.to_string())),
        }
    }

    /// Load all sessions that have network info, for rebuilding allocator state.
    pub fn list_sessions_with_network_info(
        &self,
    ) -> Result<Vec<(Uuid, crate::network::NetworkInfo)>, SandboxError> {
        let conn = self.conn.lock().map_err(|e| {
            SandboxError::Internal(format!("lock poisoned: {e}"))
        })?;

        let mut stmt = conn.prepare(
            "SELECT id, network_info FROM sessions WHERE network_info IS NOT NULL",
        )?;

        let rows = stmt.query_map([], |row| {
            let id_str: String = row.get(0)?;
            let json: String = row.get(1)?;
            Ok((id_str, json))
        })?;

        let mut result = Vec::new();
        for row in rows {
            let (id_str, json) = row?;
            let id = Uuid::parse_str(&id_str).map_err(|e| {
                SandboxError::Internal(format!("invalid UUID in database: {e}"))
            })?;
            let info: crate::network::NetworkInfo =
                serde_json::from_str(&json).map_err(|e| {
                    SandboxError::Internal(format!(
                        "invalid network_info JSON in database: {e}"
                    ))
                })?;
            result.push((id, info));
        }

        Ok(result)
    }

    /// Delete a session from the database and remove its per-session directory.
    pub fn delete_session(&self, id: &Uuid) -> Result<(), SandboxError> {
        let conn = self.conn.lock().map_err(|e| {
            SandboxError::Internal(format!("lock poisoned: {e}"))
        })?;

        let rows_affected = conn.execute(
            "DELETE FROM sessions WHERE id = ?1",
            params![id.to_string()],
        )?;

        if rows_affected == 0 {
            return Err(SandboxError::SessionNotFound(id.to_string()));
        }

        // Remove the per-session directory (ignore if it doesn't exist).
        let dir = self.session_dir(id);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }

        Ok(())
    }
}

/// Parse a row from the sessions table into a `Session`.
fn row_to_session(row: &rusqlite::Row<'_>) -> Result<Session, SandboxError> {
    let id_str: String = row.get(0)?;
    let name: Option<String> = row.get(1)?;
    let state_str: String = row.get(2)?;
    let config_json: String = row.get(3)?;
    let created_at_str: String = row.get(4)?;
    let updated_at_str: String = row.get(5)?;

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        SandboxError::Internal(format!("invalid UUID in database: {e}"))
    })?;

    let state = SessionState::from_str(&state_str)?;

    let config: SessionConfig = serde_json::from_str(&config_json).map_err(|e| {
        SandboxError::Internal(format!("invalid config JSON in database: {e}"))
    })?;

    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map_err(|e| {
            SandboxError::Internal(format!("invalid created_at timestamp: {e}"))
        })?
        .with_timezone(&Utc);

    let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
        .map_err(|e| {
            SandboxError::Internal(format!("invalid updated_at timestamp: {e}"))
        })?
        .with_timezone(&Utc);

    Ok(Session {
        id,
        name,
        state,
        config,
        created_at,
        updated_at,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;
    use tempfile::TempDir;

    /// Create a `SessionStore` in a fresh temporary directory.
    fn test_store() -> (SessionStore, TempDir) {
        let dir = TempDir::new().expect("failed to create temp dir");
        let store =
            SessionStore::new(dir.path().to_path_buf()).expect("failed to create store");
        (store, dir)
    }

    #[test]
    fn test_create_and_get_session() {
        let (store, _dir) = test_store();

        let config = SessionConfig::default();
        let session = store
            .create_session(config, None)
            .expect("create failed");

        assert_eq!(session.state, SessionState::Creating);
        assert!(session.name.is_none());

        let fetched = store
            .get_session(&session.id)
            .expect("get failed")
            .expect("session should exist");

        assert_eq!(fetched.id, session.id);
        assert_eq!(fetched.state, session.state);
        assert_eq!(fetched.config.cpus, session.config.cpus);
        assert_eq!(fetched.config.memory_mb, session.config.memory_mb);
        assert_eq!(fetched.config.disk_gb, session.config.disk_gb);
        assert_eq!(fetched.created_at, session.created_at);
        assert_eq!(fetched.updated_at, session.updated_at);
    }

    #[test]
    fn test_create_session_with_name() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), Some("my-sandbox".into()))
            .expect("create failed");

        assert_eq!(session.name, Some("my-sandbox".into()));

        let fetched = store
            .get_session(&session.id)
            .expect("get failed")
            .expect("session should exist");

        assert_eq!(fetched.name, Some("my-sandbox".into()));
    }

    #[test]
    fn test_list_sessions() {
        let (store, _dir) = test_store();

        let s1 = store
            .create_session(SessionConfig::default(), Some("first".into()))
            .expect("create s1");
        let s2 = store
            .create_session(SessionConfig::default(), Some("second".into()))
            .expect("create s2");
        let s3 = store
            .create_session(SessionConfig::default(), None)
            .expect("create s3");

        let list = store.list_sessions().expect("list failed");
        assert_eq!(list.len(), 3);

        let ids: Vec<Uuid> = list.iter().map(|s| s.id).collect();
        assert!(ids.contains(&s1.id));
        assert!(ids.contains(&s2.id));
        assert!(ids.contains(&s3.id));
    }

    #[test]
    fn test_update_state() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None)
            .expect("create");

        let original_updated_at = session.updated_at;

        // Small sleep so the timestamp changes.
        std::thread::sleep(std::time::Duration::from_millis(10));

        store
            .update_state(&session.id, SessionState::Running)
            .expect("update state");

        let fetched = store
            .get_session(&session.id)
            .expect("get")
            .expect("exists");

        assert_eq!(fetched.state, SessionState::Running);
        assert!(fetched.updated_at > original_updated_at);
    }

    #[test]
    fn test_delete_session() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None)
            .expect("create");

        store.delete_session(&session.id).expect("delete");

        let fetched = store.get_session(&session.id).expect("get");
        assert!(fetched.is_none());
    }

    #[test]
    fn test_delete_removes_directory() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None)
            .expect("create");

        let session_dir = store.session_dir(&session.id);
        assert!(session_dir.exists(), "session dir should exist after create");

        store.delete_session(&session.id).expect("delete");
        assert!(
            !session_dir.exists(),
            "session dir should be removed after delete"
        );
    }

    #[test]
    fn test_get_nonexistent() {
        let (store, _dir) = test_store();

        let result = store.get_session(&Uuid::new_v4()).expect("get");
        assert!(result.is_none());
    }

    #[test]
    fn test_state_transition_via_store() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None)
            .expect("create");

        assert_eq!(session.state, SessionState::Creating);

        store
            .update_state(&session.id, SessionState::Running)
            .expect("to running");
        let s = store
            .get_session(&session.id)
            .expect("get")
            .expect("exists");
        assert_eq!(s.state, SessionState::Running);

        store
            .update_state(&session.id, SessionState::Stopped)
            .expect("to stopped");
        let s = store
            .get_session(&session.id)
            .expect("get")
            .expect("exists");
        assert_eq!(s.state, SessionState::Stopped);
    }

    #[test]
    fn test_concurrent_access() {
        let (store, _dir) = test_store();
        let store = Arc::new(store);

        let mut handles = Vec::new();

        // Spawn threads that each create a session and read it back.
        for i in 0..8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let name = format!("thread-{i}");
                let session = store
                    .create_session(SessionConfig::default(), Some(name.clone()))
                    .expect("create");

                let fetched = store
                    .get_session(&session.id)
                    .expect("get")
                    .expect("exists");

                assert_eq!(fetched.name, Some(name));
                session.id
            }));
        }

        let ids: Vec<Uuid> = handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .collect();

        let list = store.list_sessions().expect("list");
        assert_eq!(list.len(), 8);
        for id in &ids {
            assert!(list.iter().any(|s| s.id == *id));
        }
    }

    #[test]
    fn test_migrations_run_on_new_db() {
        let (store, _dir) = test_store();

        let conn = store.conn.lock().expect("lock");
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'",
            )
            .expect("prepare");
        let exists = stmt.exists([]).expect("query");
        assert!(exists, "sessions table should exist after migrations");
    }

    #[test]
    fn test_wal_mode_enabled() {
        let (store, _dir) = test_store();

        let conn = store.conn.lock().expect("lock");
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("query journal_mode");
        assert_eq!(mode, "wal");
    }

    #[test]
    fn test_update_state_nonexistent() {
        let (store, _dir) = test_store();

        let result = store.update_state(&Uuid::new_v4(), SessionState::Running);
        assert!(matches!(result, Err(SandboxError::SessionNotFound(_))));
    }

    #[test]
    fn test_delete_nonexistent() {
        let (store, _dir) = test_store();

        let result = store.delete_session(&Uuid::new_v4());
        assert!(matches!(result, Err(SandboxError::SessionNotFound(_))));
    }

    #[test]
    fn test_custom_config_roundtrip() {
        let (store, _dir) = test_store();

        let config = SessionConfig {
            cpus: 8,
            memory_mb: 16384,
            disk_gb: 100,
            workspace_mode: None,
            hardened: true,
        };

        let session = store
            .create_session(config, Some("custom".into()))
            .expect("create");

        let fetched = store
            .get_session(&session.id)
            .expect("get")
            .expect("exists");

        assert_eq!(fetched.config.cpus, 8);
        assert_eq!(fetched.config.memory_mb, 16384);
        assert_eq!(fetched.config.disk_gb, 100);
    }

    #[test]
    fn test_session_directory_created() {
        let (store, dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None)
            .expect("create");

        let expected = dir
            .path()
            .join("sessions")
            .join(session.id.to_string());
        assert!(expected.exists());
        assert!(expected.is_dir());
    }

    #[test]
    fn test_get_by_name_or_id_with_uuid() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), Some("named".into()))
            .expect("create");

        let fetched = store
            .get_session_by_name_or_id(&session.id.to_string())
            .expect("get by uuid")
            .expect("should exist");

        assert_eq!(fetched.id, session.id);
    }

    #[test]
    fn test_get_by_name_or_id_with_name() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), Some("lookup-test".into()))
            .expect("create");

        let fetched = store
            .get_session_by_name_or_id("lookup-test")
            .expect("get by name")
            .expect("should exist");

        assert_eq!(fetched.id, session.id);
        assert_eq!(fetched.name, Some("lookup-test".into()));
    }

    #[test]
    fn test_get_by_name_or_id_not_found() {
        let (store, _dir) = test_store();

        let result = store
            .get_session_by_name_or_id("nonexistent")
            .expect("should not error");

        assert!(result.is_none());
    }

    #[test]
    fn test_get_by_name_or_id_with_unknown_uuid() {
        let (store, _dir) = test_store();

        let result = store
            .get_session_by_name_or_id(&Uuid::new_v4().to_string())
            .expect("should not error");

        assert!(result.is_none());
    }

    // -- NetworkInfo persistence tests ---------------------------------------

    #[test]
    fn test_set_and_get_network_info() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None)
            .expect("create");

        // Initially no network info.
        let info = store
            .get_network_info(&session.id)
            .expect("get_network_info");
        assert!(info.is_none());

        // Set network info.
        let net_info = crate::network::NetworkInfo {
            bridge_name: "sb-test123456".to_string(),
            subnet: "10.209.0.0/28".to_string(),
            gateway_ip: "10.209.0.2".to_string(),
            vm_ip: "10.209.0.3".to_string(),
            docker_network_name: format!("sandbox-net-{}", session.id),
        };

        store
            .set_network_info(&session.id, &net_info)
            .expect("set_network_info");

        // Retrieve it.
        let fetched = store
            .get_network_info(&session.id)
            .expect("get_network_info")
            .expect("should have network info");

        assert_eq!(fetched.bridge_name, net_info.bridge_name);
        assert_eq!(fetched.subnet, net_info.subnet);
        assert_eq!(fetched.gateway_ip, net_info.gateway_ip);
        assert_eq!(fetched.vm_ip, net_info.vm_ip);
        assert_eq!(
            fetched.docker_network_name,
            net_info.docker_network_name
        );
    }

    #[test]
    fn test_set_network_info_nonexistent_session() {
        let (store, _dir) = test_store();

        let net_info = crate::network::NetworkInfo {
            bridge_name: "sb-test".to_string(),
            subnet: "10.209.0.0/28".to_string(),
            gateway_ip: "10.209.0.2".to_string(),
            vm_ip: "10.209.0.3".to_string(),
            docker_network_name: "sandbox-net-xxx".to_string(),
        };

        let result = store.set_network_info(&Uuid::new_v4(), &net_info);
        assert!(matches!(result, Err(SandboxError::SessionNotFound(_))));
    }

    #[test]
    fn test_get_network_info_nonexistent_session() {
        let (store, _dir) = test_store();

        let result = store.get_network_info(&Uuid::new_v4());
        assert!(matches!(result, Err(SandboxError::SessionNotFound(_))));
    }

    #[test]
    fn test_list_sessions_with_network_info() {
        let (store, _dir) = test_store();

        let s1 = store
            .create_session(SessionConfig::default(), Some("s1".into()))
            .expect("create s1");
        let s2 = store
            .create_session(SessionConfig::default(), Some("s2".into()))
            .expect("create s2");
        let _s3 = store
            .create_session(SessionConfig::default(), Some("s3".into()))
            .expect("create s3");

        // Set network info on s1 and s2, leave s3 without.
        let info1 = crate::network::NetworkInfo {
            bridge_name: "sb-aaa".to_string(),
            subnet: "10.209.0.0/28".to_string(),
            gateway_ip: "10.209.0.2".to_string(),
            vm_ip: "10.209.0.3".to_string(),
            docker_network_name: format!("sandbox-net-{}", s1.id),
        };
        let info2 = crate::network::NetworkInfo {
            bridge_name: "sb-bbb".to_string(),
            subnet: "10.209.0.16/28".to_string(),
            gateway_ip: "10.209.0.18".to_string(),
            vm_ip: "10.209.0.19".to_string(),
            docker_network_name: format!("sandbox-net-{}", s2.id),
        };

        store.set_network_info(&s1.id, &info1).expect("set s1");
        store.set_network_info(&s2.id, &info2).expect("set s2");

        let entries = store
            .list_sessions_with_network_info()
            .expect("list with network info");

        assert_eq!(entries.len(), 2);

        let ids: Vec<Uuid> = entries.iter().map(|(id, _)| *id).collect();
        assert!(ids.contains(&s1.id));
        assert!(ids.contains(&s2.id));
    }

    // -- State machine validation tests ------------------------------------

    #[test]
    fn test_update_state_validates_transition() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None)
            .expect("create");

        // Creating -> Running: valid
        store
            .update_state(&session.id, SessionState::Running)
            .expect("Creating -> Running should succeed");

        // Running -> Stopped: valid
        store
            .update_state(&session.id, SessionState::Stopped)
            .expect("Running -> Stopped should succeed");

        // Stopped -> Running: valid
        store
            .update_state(&session.id, SessionState::Running)
            .expect("Stopped -> Running should succeed");
    }

    #[test]
    fn test_update_state_rejects_invalid_transition() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None)
            .expect("create");

        // Creating -> Stopped: invalid
        let result = store.update_state(&session.id, SessionState::Stopped);
        assert!(
            matches!(result, Err(SandboxError::InvalidState(_))),
            "Creating -> Stopped should be rejected, got: {result:?}"
        );

        // Advance to Error
        store
            .update_state(&session.id, SessionState::Error)
            .expect("Creating -> Error should succeed");

        // Error -> Running: invalid (Error is terminal)
        let result = store.update_state(&session.id, SessionState::Running);
        assert!(
            matches!(result, Err(SandboxError::InvalidState(_))),
            "Error -> Running should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_update_state_forced_bypasses_validation() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None)
            .expect("create");

        // Creating -> Stopped: normally invalid, but forced should work
        store
            .update_state_forced(&session.id, SessionState::Stopped)
            .expect("forced Creating -> Stopped should succeed");

        let fetched = store
            .get_session(&session.id)
            .expect("get")
            .expect("exists");
        assert_eq!(fetched.state, SessionState::Stopped);

        // Set to Error, then force back to Running
        store
            .update_state_forced(&session.id, SessionState::Error)
            .expect("forced -> Error");
        store
            .update_state_forced(&session.id, SessionState::Running)
            .expect("forced Error -> Running should succeed");

        let fetched = store
            .get_session(&session.id)
            .expect("get")
            .expect("exists");
        assert_eq!(fetched.state, SessionState::Running);
    }

    #[test]
    fn test_update_state_forced_nonexistent() {
        let (store, _dir) = test_store();

        let result = store.update_state_forced(&Uuid::new_v4(), SessionState::Running);
        assert!(matches!(result, Err(SandboxError::SessionNotFound(_))));
    }
}
