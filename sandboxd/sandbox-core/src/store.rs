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
    pub fn update_state(
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
}
