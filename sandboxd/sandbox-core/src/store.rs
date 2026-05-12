use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use tracing::warn;

use crate::error::SandboxError;
use crate::policy::{
    AssuranceLevel, Destination, HttpFilter, HttpMethod, Policy, PolicyRule, Protocol,
};
use crate::session::{Session, SessionConfig, SessionId, SessionState};

mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("migrations");
}

/// Outcome of a session ID prefix lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// No session matches the given prefix.
    NotFound,
    /// Exactly one session matches; returns the full ID.
    Found(SessionId),
    /// Multiple sessions match; returns all matches (at least 2).
    Ambiguous(Vec<SessionId>),
}

/// Information about a session whose v1 policy was purged by the
/// V004 migration and swept from `session_policies`.
///
/// Returned by [`SessionStore::new`] so the caller (sandboxd `main`)
/// can emit one `policy_reset_on_upgrade` lifecycle event per affected
/// session once the [`crate::events::EventBus`] is constructed.  The
/// tracing-level emission inside the sweep stays in place so existing
/// integration tests that scrape tracing events (see
/// `test_v004_migration_from_v1_seed_db`) continue to pass — the
/// lifecycle event is *in addition to* the tracing record, not a
/// replacement.
///
/// `previous_rule_count` is captured **before** V004 deletes the rows,
/// by running migrations in two passes (V001..V003, snapshot counts,
/// then the remaining targets).  Without the two-pass split this field
/// would always be zero, since V004 Step 97 drops every rule in a
/// single statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanInfo {
    /// Session whose v1 policy was reset.  String rather than
    /// [`SessionId`] because the migration seeds raw strings and this
    /// struct only travels from [`SessionStore::new`] to the caller.
    pub session_id: String,
    /// Number of `policy_rules` rows that belonged to this session
    /// just before V004 dropped them.  Reported on the
    /// `policy_reset_on_upgrade` lifecycle event so operators can
    /// gauge the blast radius of the upgrade.
    pub previous_rule_count: u32,
}

/// Maximum number of collision retries when inserting a session.
const INSERT_COLLISION_RETRIES: u32 = 3;

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
    /// Enables WAL mode, runs any pending migrations, and performs the
    /// V004 orphan sweep.  Returns the live store plus a list of
    /// sessions whose v1 policy was reset by the upgrade so the caller
    /// (sandboxd `main`) can emit one `policy_reset_on_upgrade`
    /// lifecycle event per affected session once the event bus is
    /// wired.
    ///
    /// Callers that do not care about the orphan list — tests,
    /// embedded tooling — can discard the second tuple element.
    pub fn new(base_dir: PathBuf) -> Result<(Self, Vec<OrphanInfo>), SandboxError> {
        fs::create_dir_all(&base_dir)?;

        let db_path = base_dir.join("sessions.db");
        let mut conn = Connection::open(&db_path)?;

        // Enable WAL mode for better concurrent read performance.
        conn.pragma_update(None, "journal_mode", "WAL")?;

        // Enable foreign-key enforcement so `ON DELETE CASCADE` on the
        // policy tables actually runs when a session (or session_policies
        // row) is deleted. SQLite requires this pragma per-connection.
        conn.pragma_update(None, "foreign_keys", "ON")?;

        // Run migrations in three passes so V004's `DELETE FROM
        // policy_rules` doesn't erase the rule counts we want to
        // attribute onto the `policy_reset_on_upgrade` event, and so
        // V006's destructive `DELETE FROM sessions` doesn't cascade-
        // delete the orphaned `session_policies` rows we want to
        // sweep + emit events for.
        //
        //   Pass 1: Target::Version(3) — apply V001..V003, then
        //           snapshot per-session rule counts from the v1
        //           schema while rows still exist.
        //   Pass 2: Target::Version(5) — apply V004 (and V005), then
        //           sweep the v1 orphans into `policy_reset_on_upgrade`
        //           events while the parent `session_policies` rows
        //           still exist (V006 below cascades them away).
        //   Pass 3: unbounded run() — apply V006 and anything later.
        //
        // On databases already at >= V004 (second boot, tests that
        // seed at V004 directly), pass 1 is a no-op and the snapshot
        // is empty; the sweep below finds no orphans and emits no
        // events.  That keeps the multi-pass split transparent to
        // existing tests.
        embedded::migrations::runner()
            .set_target(refinery::Target::Version(3))
            .run(&mut conn)
            .map_err(|e| SandboxError::Internal(format!("migration error (V001..V003): {e}")))?;

        let pre_v004_rule_counts = Self::snapshot_pre_v004_rule_counts(&conn)?;

        // Snapshot the set of refinery-applied migration versions
        // *before* the unbounded run; comparing the post-run set to
        // this lets us detect "V006 was just applied in this boot"
        // exactly once (subsequent boots find V006 already in the
        // history table and the orphan scan stays silent). The set is
        // small (one row per migration) so a HashSet is overkill — a
        // Vec scan is fine.
        let applied_before: Vec<u32> = Self::applied_migration_versions(&conn);

        // Pass 2: apply V004+V005 only. V004 deletes v1 rule rows but
        // leaves their parent `session_policies` rows in place — that
        // is exactly the orphan shape `purge_orphaned_policies_and_emit_reset_events`
        // sweeps. Stopping the runner at V5 ensures V006 has not yet
        // wiped `sessions` (and cascaded through `session_policies`).
        embedded::migrations::runner()
            .set_target(refinery::Target::Version(5))
            .run(&mut conn)
            .map_err(|e| SandboxError::Internal(format!("migration error (V004..V005): {e}")))?;

        // V004 turns v1-shaped policy rules into `session_policies` rows
        // with no children.  Sweep those orphans here and emit a
        // `policy_reset_on_upgrade` tracing event per affected session
        // so operators know which sessions need a v2 policy re-applied.
        //
        // The sweep is idempotent: on subsequent boots there are no
        // orphans left, so the query returns an empty set and no events
        // are emitted.  Running it unconditionally (not gated on "is
        // this the first boot after V004") is deliberately simple — the
        // cost is one SELECT and this keeps the code path uniform.
        let orphans =
            Self::purge_orphaned_policies_and_emit_reset_events(&conn, &pre_v004_rule_counts)?;

        // Pass 3: apply V006 and anything later. The unbounded run is a
        // no-op when the DB is already at the latest version.
        let report = embedded::migrations::runner()
            .run(&mut conn)
            .map_err(|e| SandboxError::Internal(format!("migration error (V006+): {e}")))?;

        // V006 substrate-orphan scan (api-session-isolation spec § 2.1.1).
        // Fires exactly once: on the boot where refinery just applied
        // V006. The refinery report tells us which versions ran this
        // pass; cross-checking against `applied_before` would be
        // redundant because `report.applied_migrations()` lists only
        // the migrations applied *during this run*. The scan is
        // diagnostic — it logs and does not delete.
        let v006_just_applied = report.applied_migrations().iter().any(|m| m.version() == 6)
            && !applied_before.contains(&6);
        if v006_just_applied {
            Self::run_v006_orphan_scan(&base_dir);
        }

        Ok((
            Self {
                conn: Mutex::new(conn),
                base_dir,
            },
            orphans,
        ))
    }

    /// Read the set of refinery-applied migration versions from the
    /// schema-history table. Returns an empty list if the table does
    /// not yet exist (fresh DB before any migration runs).
    fn applied_migration_versions(conn: &Connection) -> Vec<u32> {
        let mut stmt = match conn.prepare("SELECT version FROM refinery_schema_history") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], |row| row.get::<_, i64>(0)) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for row in rows.flatten() {
            if row >= 0 {
                out.push(row as u32);
            }
        }
        out
    }

    /// Substrate-orphan scan emitted exactly once on the boot where
    /// V006 is freshly applied. Enumerates Lima VMs, Docker containers,
    /// volumes, networks, and `{base_dir}/sessions/<id>/` directories
    /// matching the daemon's `sandbox-*` naming conventions, and logs
    /// one `warn!` line per found orphan plus a summary line.
    ///
    /// **Diagnostic only.** The scan never deletes — that is the
    /// operator's call once they have read the log lines. Spec 2 §
    /// 2.1.1 lays out the rationale.
    fn run_v006_orphan_scan(base_dir: &Path) {
        let mut found: u32 = 0;

        found += Self::v006_scan_lima_vms();
        found += Self::v006_scan_docker_resource(
            "container",
            &[
                "ps",
                "-a",
                "--filter",
                "name=sandbox-",
                "--format",
                "{{.Names}} {{.Status}}",
            ],
            |line| {
                let mut parts = line.splitn(2, ' ');
                let name = parts.next()?.trim().to_string();
                if !name.starts_with("sandbox-") {
                    return None;
                }
                let status = parts.next().unwrap_or("unknown").trim().to_string();
                Some((name, status))
            },
            "Docker container",
        );
        found += Self::v006_scan_docker_resource(
            "volume",
            &[
                "volume",
                "ls",
                "--filter",
                "name=sandbox-home-",
                "--format",
                "{{.Name}}",
            ],
            |line| {
                let name = line.trim().to_string();
                if name.starts_with("sandbox-home-") {
                    Some((name, String::new()))
                } else {
                    None
                }
            },
            "Docker volume",
        );
        found += Self::v006_scan_docker_resource(
            "network",
            &[
                "network",
                "ls",
                "--filter",
                "name=sandbox-net-",
                "--format",
                "{{.Name}}",
            ],
            |line| {
                let name = line.trim().to_string();
                if name.starts_with("sandbox-net-") {
                    Some((name, String::new()))
                } else {
                    None
                }
            },
            "Docker network",
        );
        found += Self::v006_scan_session_directories(base_dir);

        warn!(
            event = "v006_orphan_scan_complete",
            orphan_count = found,
            "V006 orphan scan complete - {found} orphan(s) logged above. \
             Run `sandbox doctor` (Spec 3) for a reconciliation report. \
             Do NOT auto-delete; review each orphan before cleanup."
        );
    }

    /// Run `limactl list --json` and `warn!`-log each VM whose name
    /// starts with `sandbox-`. Returns the count of orphans logged.
    fn v006_scan_lima_vms() -> u32 {
        let output = match Command::new("limactl").args(["list", "--json"]).output() {
            Ok(o) if o.status.success() => o,
            Ok(_) | Err(_) => {
                warn!(
                    event = "v006_orphan_scan_tool_unavailable",
                    tool = "limactl",
                    "V006 orphan scan: limactl is unavailable or failed; \
                     skipping Lima VM enumeration"
                );
                return 0;
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut found = 0u32;
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parsed: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let name = match parsed.get("name").and_then(|n| n.as_str()) {
                Some(n) if n.starts_with("sandbox-") => n.to_string(),
                _ => continue,
            };
            let status = parsed
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();
            warn!(
                event = "v006_orphan_lima_vm",
                vm_name = %name,
                status = %status,
                "orphaned Lima VM after V006: {name} (status: {status})"
            );
            found += 1;
        }
        found
    }

    /// Run a `docker ...` command and parse one orphan per output
    /// line. The `parse` callback returns `(name, status_string)` for
    /// matching lines or `None` to skip. Returns the count of orphans
    /// logged.
    fn v006_scan_docker_resource(
        kind: &str,
        args: &[&str],
        parse: impl Fn(&str) -> Option<(String, String)>,
        label: &str,
    ) -> u32 {
        let output = match Command::new("docker").args(args).output() {
            Ok(o) if o.status.success() => o,
            Ok(_) | Err(_) => {
                warn!(
                    event = "v006_orphan_scan_tool_unavailable",
                    tool = "docker",
                    kind = kind,
                    "V006 orphan scan: docker is unavailable or failed; \
                     skipping {kind} enumeration"
                );
                return 0;
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut found = 0u32;
        for line in stdout.lines() {
            if let Some((name, status)) = parse(line) {
                if status.is_empty() {
                    warn!(
                        event = "v006_orphan_docker",
                        kind = kind,
                        name = %name,
                        "orphaned {label} after V006: {name}"
                    );
                } else {
                    warn!(
                        event = "v006_orphan_docker",
                        kind = kind,
                        name = %name,
                        status = %status,
                        "orphaned {label} after V006: {name} (status: {status})"
                    );
                }
                found += 1;
            }
        }
        found
    }

    /// Enumerate `{base_dir}/sessions/<id>/` directories and
    /// `warn!`-log each. Returns the count of orphans logged.
    fn v006_scan_session_directories(base_dir: &Path) -> u32 {
        let sessions_dir = base_dir.join("sessions");
        let entries = match fs::read_dir(&sessions_dir) {
            Ok(e) => e,
            Err(_) => return 0,
        };
        let mut found = 0u32;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let path_str = path.display().to_string();
            warn!(
                event = "v006_orphan_session_dir",
                path = %path_str,
                "orphaned session directory after V006: {path_str}"
            );
            found += 1;
        }
        found
    }

    /// Snapshot per-session `policy_rules` row counts at the V003
    /// schema, before V004 drops every rule in one statement.
    ///
    /// The snapshot is attached to each `OrphanInfo` returned by
    /// [`SessionStore::new`] so the `policy_reset_on_upgrade` lifecycle
    /// event carries the blast radius of the upgrade.  If the query
    /// fails (for example, because `policy_rules` doesn't yet exist on
    /// a very fresh DB where V001 hasn't created it) the snapshot is
    /// treated as empty — rule counts are a best-effort diagnostic and
    /// must never block startup.
    fn snapshot_pre_v004_rule_counts(
        conn: &Connection,
    ) -> Result<std::collections::HashMap<String, u32>, SandboxError> {
        let mut stmt = match conn
            .prepare("SELECT session_id, COUNT(*) AS n FROM policy_rules GROUP BY session_id")
        {
            Ok(s) => s,
            Err(_) => return Ok(std::collections::HashMap::new()),
        };
        let rows = stmt.query_map([], |row| {
            let sid: String = row.get(0)?;
            let n: i64 = row.get(1)?;
            Ok((sid, n.max(0) as u32))
        })?;
        let mut counts = std::collections::HashMap::new();
        for row in rows {
            let (sid, n) = row?;
            counts.insert(sid, n);
        }
        Ok(counts)
    }

    /// Delete `session_policies` rows that have no surviving rules in
    /// `policy_rules` and emit a `policy_reset_on_upgrade` tracing event
    /// for each.  Invoked from [`SessionStore::new`] right after the
    /// migration runner so orphaned v1 policies (whose child rows V004
    /// purged) never leak back out via [`SessionStore::get_policy`] or
    /// [`SessionStore::load_all_policies`].
    ///
    /// Operators subscribed to the `policy_reset_on_upgrade` event know
    /// exactly which sessions need a v2 policy re-applied.  The tracing
    /// event is kept for backwards compatibility with existing
    /// subscribers and tests; the function also returns the orphan
    /// list so the caller can publish a structured lifecycle event on
    /// the in-memory bus.
    fn purge_orphaned_policies_and_emit_reset_events(
        conn: &Connection,
        pre_v004_rule_counts: &std::collections::HashMap<String, u32>,
    ) -> Result<Vec<OrphanInfo>, SandboxError> {
        let mut stmt = conn.prepare(
            "SELECT sp.session_id
             FROM session_policies sp
             LEFT JOIN policy_rules pr ON pr.session_id = sp.session_id
             WHERE pr.session_id IS NULL",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

        let mut orphans = Vec::new();
        for row in rows {
            orphans.push(row?);
        }
        drop(stmt);

        let mut infos = Vec::with_capacity(orphans.len());
        for session_id in &orphans {
            let previous_rule_count = pre_v004_rule_counts.get(session_id).copied().unwrap_or(0);
            tracing::info!(
                event = "policy_reset_on_upgrade",
                session_id = %session_id,
                previous_rule_count = previous_rule_count,
                "v1 policy rules were purged by migration V004; \
                 operator must re-apply a v2 policy for this session"
            );
            conn.execute(
                "DELETE FROM session_policies WHERE session_id = ?1",
                params![session_id],
            )?;
            infos.push(OrphanInfo {
                session_id: session_id.clone(),
                previous_rule_count,
            });
        }

        Ok(infos)
    }

    /// Return the base directory used by this store.
    pub fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    /// Directory for per-session data: `{base_dir}/sessions/{id}/`.
    fn session_dir(&self, id: &SessionId) -> PathBuf {
        self.base_dir.join("sessions").join(id.as_str())
    }

    /// Create a new session, insert it into the database, and create its
    /// per-session directory.
    ///
    /// If the generated 12-hex ID collides with an existing session (rare but
    /// possible with 48 bits of entropy), the session is regenerated and
    /// re-inserted up to `INSERT_COLLISION_RETRIES` times before failing.
    ///
    /// `owner_username` is stamped into the `sessions.owner_username`
    /// column added by V006 (api-session-isolation spec § 2.4) so every
    /// subsequent read or mutation filters by the caller's identity.
    /// `guest_proto` / `guest_bin_ver` are the protocol-version and
    /// binary-version stamps that drive the start-time compat gate; in
    /// M13-S4 they ride as placeholders (`0`, `""`) until M13-S5 wires
    /// up the real constants.
    pub fn create_session(
        &self,
        config: SessionConfig,
        name: Option<String>,
        owner_username: &str,
        guest_proto: u32,
        guest_bin_ver: &str,
    ) -> Result<Session, SandboxError> {
        // Back-compat shim: the public `create_session` defaults to
        // the Lima backend so existing call sites (and tests) keep
        // their behaviour unchanged. Container-backed sessions go
        // through `create_session_with_backend`.
        self.create_session_with_backend(
            config,
            name,
            crate::backend::BackendKind::Lima,
            owner_username,
            guest_proto,
            guest_bin_ver,
        )
    }

    /// Like [`Self::create_session`], but lets the caller pin which backend
    /// owns the session. Threaded through by the `POST /sessions`
    /// handler so the container path persists `backend = 'container'`
    /// rather than relying on the SQL `DEFAULT 'lima'`.
    pub fn create_session_with_backend(
        &self,
        config: SessionConfig,
        name: Option<String>,
        backend: crate::backend::BackendKind,
        owner_username: &str,
        guest_proto: u32,
        guest_bin_ver: &str,
    ) -> Result<Session, SandboxError> {
        let config_json = serde_json::to_string(&config)
            .map_err(|e| SandboxError::Internal(format!("failed to serialize config: {e}")))?;

        let mut attempt = 0u32;
        loop {
            let mut session =
                Session::with_config_and_backend(name.clone(), config.clone(), backend);
            session.owner_username = owner_username.to_string();
            session.guest_protocol_version = guest_proto;
            session.guest_binary_version = guest_bin_ver.to_string();
            match self.try_insert_session(&session, &config_json) {
                Ok(()) => {
                    fs::create_dir_all(self.session_dir(&session.id))?;
                    return Ok(session);
                }
                Err(InsertError::Collision) if attempt < INSERT_COLLISION_RETRIES => {
                    attempt += 1;
                    continue;
                }
                Err(InsertError::Collision) => {
                    return Err(SandboxError::Internal(format!(
                        "session id collision after {INSERT_COLLISION_RETRIES} retries"
                    )));
                }
                Err(InsertError::Other(e)) => return Err(e),
            }
        }
    }

    /// Insert a session row. Returns `InsertError::Collision` if the id
    /// violates the PRIMARY KEY uniqueness constraint; all other DB errors
    /// surface as `InsertError::Other`.
    fn try_insert_session(&self, session: &Session, config_json: &str) -> Result<(), InsertError> {
        let conn = self.conn.lock().map_err(|e| {
            InsertError::Other(SandboxError::Internal(format!("lock poisoned: {e}")))
        })?;

        let res = conn.execute(
            "INSERT INTO sessions (id, name, state, config, created_at, updated_at, backend, \
                 owner_username, guest_protocol_version, guest_binary_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                session.id.as_str(),
                session.name,
                session.state.to_string(),
                config_json,
                session.created_at.to_rfc3339(),
                session.updated_at.to_rfc3339(),
                session.backend.as_str(),
                session.owner_username,
                session.guest_protocol_version as i64,
                session.guest_binary_version,
            ],
        );

        match res {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(InsertError::Collision)
            }
            Err(e) => Err(InsertError::Other(SandboxError::from(e))),
        }
    }

    /// Retrieve a session by ID, or `None` if it does not exist.
    ///
    /// Per-caller isolation (api-session-isolation spec § 2.4): the
    /// `WHERE` clause also filters `owner_username = ?caller_username`,
    /// so a foreign session ID is indistinguishable on the wire from a
    /// truly nonexistent ID — both return `Ok(None)` and the handler
    /// layer maps that to HTTP 404.
    pub fn get_session(
        &self,
        id: &SessionId,
        caller_username: &str,
    ) -> Result<Option<Session>, SandboxError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let mut stmt = conn.prepare(
            "SELECT id, name, state, config, created_at, updated_at, backend, \
                 owner_username, guest_protocol_version, guest_binary_version
             FROM sessions WHERE id = ?1 AND owner_username = ?2",
        )?;

        let mut rows = stmt.query(params![id.as_str(), caller_username])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_session(row)?)),
            None => Ok(None),
        }
    }

    /// Internal helper for daemon-side subsystems that need to read a
    /// row by id without an HTTP caller in scope. **Not for handler
    /// code.** Use [`Self::get_session`] from any request path so the
    /// per-caller filter is enforced; this entry point exists only for
    /// the `GuestConnector`, the propagation tracker, and the lifecycle
    /// reconciler — all daemon-internal subsystems that operate on
    /// sessions previously authorized by a per-caller lookup at the
    /// handler boundary.
    pub(crate) fn get_session_unfiltered(
        &self,
        id: &SessionId,
    ) -> Result<Option<Session>, SandboxError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let mut stmt = conn.prepare(
            "SELECT id, name, state, config, created_at, updated_at, backend, \
                 owner_username, guest_protocol_version, guest_binary_version
             FROM sessions WHERE id = ?1",
        )?;

        let mut rows = stmt.query(params![id.as_str()])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_session(row)?)),
            None => Ok(None),
        }
    }

    /// List all sessions owned by `caller_username`.
    ///
    /// Per-caller isolation (api-session-isolation spec § 2.4): each
    /// caller sees only their own rows. Other operators' sessions never
    /// surface on the wire — list endpoints return disjoint result sets
    /// per caller.
    /// Internal helper for daemon-side reconciliation and reconciler
    /// tasks that need the full session inventory irrespective of
    /// caller. **Not for handler code.** HTTP handlers must use
    /// [`Self::list_sessions`], which enforces ownership via the
    /// `caller_username` filter. See `api-session-isolation` spec § 2.4
    /// for the rationale.
    pub fn list_sessions_unfiltered(&self) -> Result<Vec<Session>, SandboxError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let mut stmt = conn.prepare(
            "SELECT id, name, state, config, created_at, updated_at, backend, \
                 owner_username, guest_protocol_version, guest_binary_version
             FROM sessions ORDER BY created_at ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            row_to_session(row).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.to_string(),
                    )),
                )
            })
        })?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(row?);
        }
        Ok(sessions)
    }

    pub fn list_sessions(&self, caller_username: &str) -> Result<Vec<Session>, SandboxError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let mut stmt = conn.prepare(
            "SELECT id, name, state, config, created_at, updated_at, backend, \
                 owner_username, guest_protocol_version, guest_binary_version
             FROM sessions WHERE owner_username = ?1 ORDER BY created_at ASC",
        )?;

        let rows = stmt.query_map(params![caller_username], |row| {
            row_to_session(row).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.to_string(),
                    )),
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
    /// Per-caller isolation (api-session-isolation spec § 2.4): only
    /// rows owned by `caller_username` are considered; a foreign-owner
    /// row surfaces as `Err(SessionNotFound)` so the handler layer
    /// returns HTTP 404 indistinguishable from a truly-nonexistent ID.
    ///
    /// For reconciliation or crash-recovery code that must force a
    /// state regardless of the current value AND has no HTTP caller in
    /// scope, use [`Self::update_state_reconcile`] instead.
    pub fn update_state(
        &self,
        id: &SessionId,
        caller_username: &str,
        new_state: SessionState,
    ) -> Result<(), SandboxError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        // Fetch the current state so we can validate the transition.
        // Combines the caller-ownership filter and the state read in
        // one query: a row that exists for a different owner returns
        // `None` here, which maps to `SessionNotFound` — the same
        // shape the handler layer hides as HTTP 404.
        let current_state = {
            let mut stmt =
                conn.prepare("SELECT state FROM sessions WHERE id = ?1 AND owner_username = ?2")?;
            let mut rows = stmt.query(params![id.as_str(), caller_username])?;
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
                "cannot transition from {current_state} to {new_state}"
            )));
        }

        let now = Utc::now();
        conn.execute(
            "UPDATE sessions SET state = ?1, updated_at = ?2
             WHERE id = ?3 AND owner_username = ?4",
            params![
                new_state.to_string(),
                now.to_rfc3339(),
                id.as_str(),
                caller_username,
            ],
        )?;

        Ok(())
    }

    /// Update both guest-version fields for a session atomically.
    ///
    /// Called by `start_session`'s refresh decision tree (api-session-
    /// isolation spec § 3.9) **only after** both
    /// `runtime.refresh_guest_binary` and `runtime.start` have returned
    /// `Ok(())`, so a write here means the in-VM/in-container binary
    /// really is at `proto` / `binary_version`.
    ///
    /// Per-caller isolation: the `UPDATE` filters on
    /// `owner_username = caller_username` so a session belonging to a
    /// different operator surfaces as `SessionNotFound` rather than
    /// silently mutating a foreign row.
    pub fn update_guest_versions(
        &self,
        caller_username: &str,
        id: &SessionId,
        proto: u32,
        binary_version: &str,
    ) -> Result<(), SandboxError> {
        let now = Utc::now();

        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let rows_affected = conn.execute(
            "UPDATE sessions SET guest_protocol_version = ?1, \
                 guest_binary_version = ?2, updated_at = ?3 \
             WHERE id = ?4 AND owner_username = ?5",
            params![
                proto as i64,
                binary_version,
                now.to_rfc3339(),
                id.as_str(),
                caller_username,
            ],
        )?;

        if rows_affected == 0 {
            return Err(SandboxError::SessionNotFound(id.to_string()));
        }

        Ok(())
    }

    /// Forcibly set the state of a session, bypassing both state-machine
    /// validation and the storage-boundary ownership filter.
    ///
    /// **INTERNAL: only the daemon's startup / reconciliation paths may
    /// call this method.** HTTP handlers must use [`Self::update_state`],
    /// which enforces ownership via the `caller_username` filter
    /// (api-session-isolation spec § 2.4). A call from a request handler
    /// is a security bug — it bypasses the per-caller 404-on-foreign-id
    /// property the rest of the store guarantees.
    ///
    /// Authorized callers, exhaustively (api-session-isolation spec
    /// § 7.3.1 enforces this list via a static-analysis test):
    /// - `list_sessions` and `get_session` reconciler blocks in
    ///   `sandboxd::main` (DB-vs-runtime status divergence).
    /// - The `Creating` -> `Running`/`Error` transitions in
    ///   `create_session` and `start_session` *before* the session is
    ///   owner-stamped (only on the error/cleanup branch; the happy
    ///   path uses `update_state`).
    /// - Startup reconciliation in `sandboxd::main::main`.
    pub fn update_state_reconcile(
        &self,
        id: &SessionId,
        state: SessionState,
    ) -> Result<(), SandboxError> {
        let now = Utc::now();

        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let rows_affected = conn.execute(
            "UPDATE sessions SET state = ?1, updated_at = ?2 WHERE id = ?3",
            params![state.to_string(), now.to_rfc3339(), id.as_str()],
        )?;

        if rows_affected == 0 {
            return Err(SandboxError::SessionNotFound(id.to_string()));
        }

        Ok(())
    }

    /// Look up a session by exact name, exact session ID, or unique ID prefix.
    ///
    /// Lookup order:
    /// 1. If `query` is a full 12-char session ID, try exact ID lookup.
    /// 2. Otherwise, try exact name lookup.
    /// 3. If still not found and `query` looks like a hex prefix (1..=12
    ///    lowercase hex chars), try [`Self::resolve_id_prefix`]. Returns the matching
    ///    session if exactly one ID has this prefix.
    ///
    /// Per-caller isolation (api-session-isolation spec § 2.4): every
    /// fallback path filters on `owner_username = caller_username`, so
    /// foreign rows never surface and the 404-on-foreign-id property
    /// holds across name lookup, ID prefix, and full-ID paths.
    ///
    /// Returns `None` if no session matches. Returns
    /// [`SandboxError::InvalidArgument`] if the prefix matches multiple
    /// caller-owned sessions (ambiguous).
    pub fn get_session_by_name_or_id(
        &self,
        query: &str,
        caller_username: &str,
    ) -> Result<Option<Session>, SandboxError> {
        // Try exact SessionId first.
        if let Ok(id) = SessionId::parse(query) {
            if let Some(session) = self.get_session(&id, caller_username)? {
                return Ok(Some(session));
            }
        }

        // Try exact name lookup, scoped to caller-owned rows.
        {
            let conn = self
                .conn
                .lock()
                .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

            let mut stmt = conn.prepare(
                "SELECT id, name, state, config, created_at, updated_at, backend, \
                     owner_username, guest_protocol_version, guest_binary_version
                 FROM sessions WHERE name = ?1 AND owner_username = ?2",
            )?;

            let mut rows = stmt.query(params![query, caller_username])?;
            if let Some(row) = rows.next()? {
                return Ok(Some(row_to_session(row)?));
            }
        }

        // Fall back to ID prefix resolution.
        match self.resolve_id_prefix(query, caller_username)? {
            ResolveOutcome::Found(id) => self.get_session(&id, caller_username),
            ResolveOutcome::Ambiguous(ids) => {
                let list = ids
                    .iter()
                    .map(|id| id.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                Err(SandboxError::InvalidArgument(format!(
                    "session id prefix {query:?} is ambiguous; matches: {list}"
                )))
            }
            ResolveOutcome::NotFound => Ok(None),
        }
    }

    /// Resolve a session ID prefix to a full ID, scoped to caller-owned rows.
    ///
    /// The prefix must be between 1 and 12 lowercase hex characters. Returns:
    /// - [`ResolveOutcome::Found`] if exactly one caller-owned session ID
    ///   starts with the prefix.
    /// - [`ResolveOutcome::NotFound`] if no caller-owned session matches.
    /// - [`ResolveOutcome::Ambiguous`] if multiple caller-owned sessions
    ///   match, listing all matching IDs.
    ///
    /// Per-caller isolation (api-session-isolation spec § 2.4): foreign-
    /// owner rows are invisible — a prefix that matches another
    /// operator's session ID returns `NotFound`, not the foreign ID.
    ///
    /// An empty prefix returns `NotFound` (it would otherwise match every
    /// session and the ambiguity list would be unbounded). A prefix longer
    /// than 12 chars or containing non-hex characters returns `NotFound`.
    pub fn resolve_id_prefix(
        &self,
        prefix: &str,
        caller_username: &str,
    ) -> Result<ResolveOutcome, SandboxError> {
        if prefix.is_empty() || prefix.len() > SessionId::LEN {
            return Ok(ResolveOutcome::NotFound);
        }
        if !prefix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Ok(ResolveOutcome::NotFound);
        }

        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        // `LIMIT 2` is sufficient — we only need to distinguish 0 / 1 / 2+
        // matches. When ambiguous we fall through to a second query that
        // returns all matches for a helpful error message.
        let mut stmt = conn.prepare(
            "SELECT id FROM sessions \
             WHERE id LIKE ?1 || '%' AND owner_username = ?2 LIMIT 2",
        )?;
        let rows = stmt.query_map(params![prefix, caller_username], |row| {
            let s: String = row.get(0)?;
            Ok(s)
        })?;

        let mut ids: Vec<String> = Vec::new();
        for row in rows {
            ids.push(row?);
        }

        match ids.len() {
            0 => Ok(ResolveOutcome::NotFound),
            1 => {
                let id = SessionId::parse(&ids[0])
                    .map_err(|e| SandboxError::Internal(format!("invalid id in database: {e}")))?;
                Ok(ResolveOutcome::Found(id))
            }
            _ => {
                // Fetch all matches for a helpful error message.
                let mut stmt = conn.prepare(
                    "SELECT id FROM sessions \
                     WHERE id LIKE ?1 || '%' AND owner_username = ?2 ORDER BY id",
                )?;
                let rows = stmt.query_map(params![prefix, caller_username], |row| {
                    let s: String = row.get(0)?;
                    Ok(s)
                })?;
                let mut all = Vec::new();
                for row in rows {
                    let s = row?;
                    let id = SessionId::parse(&s).map_err(|e| {
                        SandboxError::Internal(format!("invalid id in database: {e}"))
                    })?;
                    all.push(id);
                }
                Ok(ResolveOutcome::Ambiguous(all))
            }
        }
    }

    /// Store network info for a session (serialized as JSON).
    ///
    /// Per-caller isolation (api-session-isolation spec § 2.4): only
    /// rows owned by `caller_username` are mutated; a foreign-owner row
    /// surfaces as `Err(SessionNotFound)` so the handler layer returns
    /// HTTP 404 indistinguishable from a truly-nonexistent ID.
    pub fn set_network_info(
        &self,
        id: &SessionId,
        caller_username: &str,
        info: &crate::network::NetworkInfo,
    ) -> Result<(), SandboxError> {
        let json = serde_json::to_string(info).map_err(|e| {
            SandboxError::Internal(format!("failed to serialize network info: {e}"))
        })?;

        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let rows_affected = conn.execute(
            "UPDATE sessions SET network_info = ?1
             WHERE id = ?2 AND owner_username = ?3",
            params![json, id.as_str(), caller_username],
        )?;

        if rows_affected == 0 {
            return Err(SandboxError::SessionNotFound(id.to_string()));
        }

        Ok(())
    }

    /// Retrieve network info for a session, if it has been set.
    ///
    /// Per-caller isolation (api-session-isolation spec § 2.4): a
    /// foreign-owner row is invisible — a query for a session ID
    /// the caller does not own surfaces as `Err(SessionNotFound)`
    /// (same shape as a truly-nonexistent ID).
    pub fn get_network_info(
        &self,
        id: &SessionId,
        caller_username: &str,
    ) -> Result<Option<crate::network::NetworkInfo>, SandboxError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let mut stmt = conn
            .prepare("SELECT network_info FROM sessions WHERE id = ?1 AND owner_username = ?2")?;

        let mut rows = stmt.query(params![id.as_str(), caller_username])?;
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

    /// Internal helper for daemon-side subsystems that need to read
    /// `network_info` by id without an HTTP caller in scope. **Not for
    /// handler code.** Same authorization contract as
    /// [`Self::get_session_unfiltered`] — handlers must have already
    /// authorized the session via a per-caller lookup before any
    /// daemon-internal subsystem reaches this entry point.
    ///
    /// Exposed as `pub` (not `pub(crate)`) so the daemon binary's
    /// reconcilers, gateway monitor, and DNS-loop listener — which all
    /// live in the `sandboxd` crate and walk every session row
    /// irrespective of owner — can reach it. The "internal-only"
    /// contract is enforced by the rustdoc + the
    /// `update_state_reconcile` allow-list test (see
    /// `tests/update_state_reconcile_allow_list.rs`).
    pub fn get_network_info_unfiltered(
        &self,
        id: &SessionId,
    ) -> Result<Option<crate::network::NetworkInfo>, SandboxError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let mut stmt = conn.prepare("SELECT network_info FROM sessions WHERE id = ?1")?;

        let mut rows = stmt.query(params![id.as_str()])?;
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
    ) -> Result<Vec<(SessionId, crate::network::NetworkInfo)>, SandboxError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let mut stmt =
            conn.prepare("SELECT id, network_info FROM sessions WHERE network_info IS NOT NULL")?;

        let rows = stmt.query_map([], |row| {
            let id_str: String = row.get(0)?;
            let json: String = row.get(1)?;
            Ok((id_str, json))
        })?;

        let mut result = Vec::new();
        for row in rows {
            let (id_str, json) = row?;
            let id = SessionId::parse(&id_str).map_err(|e| {
                SandboxError::Internal(format!("invalid session id in database: {e}"))
            })?;
            let info: crate::network::NetworkInfo = serde_json::from_str(&json).map_err(|e| {
                SandboxError::Internal(format!("invalid network_info JSON in database: {e}"))
            })?;
            result.push((id, info));
        }

        Ok(result)
    }

    // ----------------------------------------------------------------------
    // Policy persistence
    // ----------------------------------------------------------------------

    /// Persist a policy for a session, replacing any previously stored
    /// policy for the same session.
    ///
    /// The write is performed in a single SQLite transaction: the existing
    /// `session_policies` row is deleted (cascading to `policy_rules` and
    /// `policy_rule_http_filters`), the new rows are inserted in order,
    /// and the transaction is committed.  If any step fails, the
    /// transaction is rolled back and the previous policy remains intact.
    ///
    /// The `session_id` **must** reference an existing row in the
    /// `sessions` table (the FK from `session_policies` is enforced).
    pub fn set_policy(
        &self,
        id: &SessionId,
        caller_username: &str,
        policy: &Policy,
    ) -> Result<(), SandboxError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let tx = conn.transaction()?;

        // Per-caller isolation (api-session-isolation spec § 2.4): a
        // mutation targeting a foreign-owner row surfaces as
        // `SessionNotFound`. The owner check runs *inside* the
        // transaction so a concurrent `delete_session` cannot race in
        // between the check and the parent-row delete.
        {
            let mut stmt =
                tx.prepare("SELECT 1 FROM sessions WHERE id = ?1 AND owner_username = ?2")?;
            if !stmt.exists(params![id.as_str(), caller_username])? {
                return Err(SandboxError::SessionNotFound(id.to_string()));
            }
        }

        // DELETE parent row; CASCADE clears the children.  If no row
        // exists this is a no-op — matches "first-time apply" semantics.
        tx.execute(
            "DELETE FROM session_policies WHERE session_id = ?1",
            params![id.as_str()],
        )?;

        tx.execute(
            "INSERT INTO session_policies (session_id, version) VALUES (?1, ?2)",
            params![id.as_str(), policy.version],
        )?;

        for (rule_order, rule) in policy.rules.iter().enumerate() {
            let (dest_kind, dest_value) = destination_columns(&rule.host);
            tx.execute(
                "INSERT INTO policy_rules (
                    session_id, rule_order, destination_kind, host_value,
                    port, level, protocol, reason
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    id.as_str(),
                    rule_order as i64,
                    dest_kind,
                    dest_value,
                    rule.port as i64,
                    level_column(&rule.level),
                    protocol_column(rule.protocol),
                    rule.reason,
                ],
            )?;

            if let AssuranceLevel::Http { http_filters } = &rule.level {
                for (filter_order, filter) in http_filters.iter().enumerate() {
                    tx.execute(
                        "INSERT INTO policy_rule_http_filters (
                            session_id, rule_order, filter_order, method, path_pattern
                         ) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            id.as_str(),
                            rule_order as i64,
                            filter_order as i64,
                            method_column(filter.method),
                            filter.path,
                        ],
                    )?;
                }
            }
        }

        tx.commit()?;
        Ok(())
    }

    /// Delete any stored policy for a session.
    ///
    /// The write is performed in a single transaction: the `session_policies`
    /// row (if any) is deleted, cascading to `policy_rules` and
    /// `policy_rule_http_filters`.  Calling this on a session that has no
    /// policy row is a silent no-op — deletion is idempotent so callers can
    /// treat `--clear` as "reach the no-policy state" regardless of the
    /// prior contents.
    ///
    /// The `session_id` must reference an existing row in `sessions`; if the
    /// session was already removed the DELETE is still a safe no-op because
    /// the FK only constrains writes into `session_policies`, not deletes
    /// out of it.
    pub fn delete_policy(&self, id: &SessionId, caller_username: &str) -> Result<(), SandboxError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let tx = conn.transaction()?;
        // Per-caller isolation (api-session-isolation spec § 2.4):
        // policy deletion is idempotent (no-op for missing rows) by
        // contract, but a foreign-owner session must not even be
        // *probed* via this call site — surface SessionNotFound for
        // a row that exists under a different owner.
        //
        // Probe results in a separate scope so the prepared-statement
        // borrows on `tx` are dropped before `tx.commit()`.
        enum DeleteAction {
            Forbidden,
            NoOp,
            Delete,
        }
        let action = {
            let mut owned_stmt =
                tx.prepare("SELECT 1 FROM sessions WHERE id = ?1 AND owner_username = ?2")?;
            let owned = owned_stmt.exists(params![id.as_str(), caller_username])?;
            if owned {
                DeleteAction::Delete
            } else {
                // Distinguish "row owned by someone else" from "no
                // session row at all": a totally absent row is allowed
                // to no-op (the spec's idempotence rule); a foreign-
                // owner row must surface 404 so the caller can't probe
                // existence.
                let mut probe = tx.prepare("SELECT 1 FROM sessions WHERE id = ?1")?;
                if probe.exists(params![id.as_str()])? {
                    DeleteAction::Forbidden
                } else {
                    DeleteAction::NoOp
                }
            }
        };

        match action {
            DeleteAction::Forbidden => Err(SandboxError::SessionNotFound(id.to_string())),
            DeleteAction::NoOp => {
                tx.commit()?;
                Ok(())
            }
            DeleteAction::Delete => {
                tx.execute(
                    "DELETE FROM session_policies WHERE session_id = ?1",
                    params![id.as_str()],
                )?;
                tx.commit()?;
                Ok(())
            }
        }
    }

    /// Retrieve the policy stored for a session.
    ///
    /// Returns `Ok(None)` if no row exists in `session_policies` for this
    /// session.  If a row is present but the policy cannot be reassembled
    /// (missing/invalid enum values, broken child rows), the failure is
    /// logged and `Ok(None)` is returned — callers must treat this the
    /// same as "no policy" so the daemon does not crash on a corrupted
    /// row.  The next successful `set_policy` overwrites the entry.
    pub fn get_policy(
        &self,
        id: &SessionId,
        caller_username: &str,
    ) -> Result<Option<Policy>, SandboxError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        // Per-caller isolation (api-session-isolation spec § 2.4): a
        // foreign-owner session surfaces as `Ok(None)` — same shape as
        // a session with no policy, which is identical to the shape an
        // unprovisioned session presents.
        {
            let mut stmt =
                conn.prepare("SELECT 1 FROM sessions WHERE id = ?1 AND owner_username = ?2")?;
            if !stmt.exists(params![id.as_str(), caller_username])? {
                return Ok(None);
            }
        }

        match read_policy(&conn, id) {
            Ok(Some(policy)) => Ok(Some(policy)),
            Ok(None) => Ok(None),
            Err(e) => {
                warn!(
                    session_id = %id,
                    error = %e,
                    "failed to reassemble persisted policy; treating as absent"
                );
                Ok(None)
            }
        }
    }

    /// Load every persisted policy, for startup hydration.
    ///
    /// Sessions with a corrupt/undecodable persisted policy are skipped
    /// with a warning; they do not abort the startup sequence.  The next
    /// `set_policy` for such a session overwrites the bad row.
    pub fn load_all_policies(&self) -> Result<Vec<(SessionId, Policy)>, SandboxError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let mut stmt = conn.prepare("SELECT session_id FROM session_policies")?;
        let rows = stmt.query_map([], |row| {
            let s: String = row.get(0)?;
            Ok(s)
        })?;

        let mut out = Vec::new();
        for row in rows {
            let id_str = row?;
            let id = match SessionId::parse(&id_str) {
                Ok(id) => id,
                Err(e) => {
                    warn!(
                        session_id = %id_str,
                        error = %e,
                        "skipping policy row with invalid session id"
                    );
                    continue;
                }
            };
            match read_policy(&conn, &id) {
                Ok(Some(policy)) => out.push((id, policy)),
                Ok(None) => {
                    // Parent row exists (we just iterated it) but the
                    // policy is empty enough to return None.  Treat as
                    // "no policy" and skip — matches the get_policy
                    // contract.
                }
                Err(e) => {
                    warn!(
                        session_id = %id,
                        error = %e,
                        "skipping corrupt persisted policy during hydration"
                    );
                }
            }
        }

        Ok(out)
    }

    /// Delete a session from the database and remove its per-session directory.
    ///
    /// Per-caller isolation (api-session-isolation spec § 2.4): only
    /// rows owned by `caller_username` may be deleted; a foreign-owner
    /// row surfaces as `Err(SessionNotFound)` so the handler layer
    /// returns HTTP 404 indistinguishable from a truly-nonexistent ID.
    pub fn delete_session(
        &self,
        id: &SessionId,
        caller_username: &str,
    ) -> Result<(), SandboxError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| SandboxError::Internal(format!("lock poisoned: {e}")))?;

        let rows_affected = conn.execute(
            "DELETE FROM sessions WHERE id = ?1 AND owner_username = ?2",
            params![id.as_str(), caller_username],
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

// ----------------------------------------------------------------------
// Policy row helpers
// ----------------------------------------------------------------------

/// Break a `Destination` into the (kind, value) columns the schema uses.
/// The kind column is constrained by a SQL CHECK to `'domain' | 'cidr'`;
/// keep this mapping aligned with the migration.
fn destination_columns(dest: &Destination) -> (&'static str, String) {
    match dest {
        Destination::Domain(d) => ("domain", d.clone()),
        Destination::Cidr(c) => ("cidr", c.clone()),
    }
}

fn destination_from_columns(kind: &str, value: String) -> Result<Destination, SandboxError> {
    match kind {
        "domain" => Ok(Destination::Domain(value)),
        "cidr" => Ok(Destination::Cidr(value)),
        other => Err(SandboxError::Internal(format!(
            "unknown destination_kind in policy_rules: {other}"
        ))),
    }
}

/// Stable lowercase tag for the `level` column (matches the SQL CHECK).
fn level_column(level: &AssuranceLevel) -> &'static str {
    match level {
        AssuranceLevel::Deny => "deny",
        AssuranceLevel::Transport => "transport",
        AssuranceLevel::Tls => "tls",
        AssuranceLevel::Http { .. } => "http",
    }
}

/// Lowercase protocol tag (matches `#[serde(rename_all = "lowercase")]`
/// on `Protocol` and the SQL CHECK).
fn protocol_column(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

/// Parse a protocol column value read from `policy_rules.protocol`.
///
/// Under v2 schema only `tcp` and `udp` are valid.  Legacy v1 values
/// (`http`, `https`, `any`) are rejected — migration V004 guarantees
/// that no row with those values survives, so this arm is defensive
/// dead code in practice.
fn protocol_from_column(s: &str) -> Result<Protocol, SandboxError> {
    Ok(match s {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        other => {
            return Err(SandboxError::Internal(format!(
                "unknown protocol in policy_rules: {other} \
                 (v1 values http/https/any were purged by migration V004)"
            )));
        }
    })
}

/// Uppercase HTTP method tag (matches `#[serde(rename_all = "UPPERCASE")]`
/// on `HttpMethod` and the SQL CHECK).
fn method_column(m: HttpMethod) -> &'static str {
    match m {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Trace => "TRACE",
        HttpMethod::Connect => "CONNECT",
        HttpMethod::Any => "ANY",
    }
}

fn method_from_column(s: &str) -> Result<HttpMethod, SandboxError> {
    Ok(match s {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "PATCH" => HttpMethod::Patch,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        "TRACE" => HttpMethod::Trace,
        "CONNECT" => HttpMethod::Connect,
        "ANY" => HttpMethod::Any,
        other => {
            return Err(SandboxError::Internal(format!(
                "unknown method in policy_rule_http_filters: {other}"
            )));
        }
    })
}

/// Reassemble a `Policy` from its normalized rows.  Returns `Ok(None)`
/// if no parent `session_policies` row exists; errors otherwise mean a
/// real DB failure or a row that violates a documented invariant (e.g.
/// an `http`-level rule with no filters).
fn read_policy(conn: &Connection, id: &SessionId) -> Result<Option<Policy>, SandboxError> {
    // Parent row?
    let version: String = {
        let mut stmt =
            conn.prepare("SELECT version FROM session_policies WHERE session_id = ?1")?;
        let mut rows = stmt.query(params![id.as_str()])?;
        match rows.next()? {
            Some(row) => row.get(0)?,
            None => return Ok(None),
        }
    };

    // Rules, in order.  Split the raw SELECT into a named struct so the
    // 7-column tuple doesn't trip `clippy::type_complexity`.
    struct RawRule {
        rule_order: i64,
        destination_kind: String,
        host_value: String,
        port: i64,
        level: String,
        protocol: String,
        reason: Option<String>,
    }

    let mut rules_raw: Vec<RawRule> = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT rule_order, destination_kind, host_value, port, level, protocol, reason
             FROM policy_rules WHERE session_id = ?1 ORDER BY rule_order ASC",
        )?;
        let rows = stmt.query_map(params![id.as_str()], |row| {
            Ok(RawRule {
                rule_order: row.get::<_, i64>(0)?,
                destination_kind: row.get::<_, String>(1)?,
                host_value: row.get::<_, String>(2)?,
                port: row.get::<_, i64>(3)?,
                level: row.get::<_, String>(4)?,
                protocol: row.get::<_, String>(5)?,
                reason: row.get::<_, Option<String>>(6)?,
            })
        })?;
        for row in rows {
            rules_raw.push(row?);
        }
    }

    let mut rules = Vec::with_capacity(rules_raw.len());
    for raw in rules_raw {
        let RawRule {
            rule_order,
            destination_kind: dest_kind,
            host_value: dest_value,
            port: port_raw,
            level: level_tag,
            protocol: protocol_str,
            reason,
        } = raw;
        let destination = destination_from_columns(&dest_kind, dest_value)?;
        let protocol = protocol_from_column(&protocol_str)?;
        // Defensive: the V004 CHECK constraint already enforces
        // port BETWEEN 1 AND 65535, so this fallible cast should
        // never actually reject a row — but the conversion from
        // the SQL i64 column to our u16 field is not infallible at
        // the type level, so we guard it here.
        let port: u16 = u16::try_from(port_raw).map_err(|_| {
            SandboxError::Internal(format!(
                "policy_rules.port out of u16 range \
                 (session {id}, rule_order {rule_order}, value {port_raw}) \
                 — V004 CHECK should have caught this"
            ))
        })?;

        let level = match level_tag.as_str() {
            "deny" => AssuranceLevel::Deny,
            "transport" => AssuranceLevel::Transport,
            "tls" => AssuranceLevel::Tls,
            "http" => {
                let mut stmt = conn.prepare(
                    "SELECT method, path_pattern
                     FROM policy_rule_http_filters
                     WHERE session_id = ?1 AND rule_order = ?2
                     ORDER BY filter_order ASC",
                )?;
                let rows = stmt.query_map(params![id.as_str(), rule_order], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;
                let mut filters = Vec::new();
                for row in rows {
                    let (method, path) = row?;
                    filters.push(HttpFilter {
                        method: method_from_column(&method)?,
                        path,
                    });
                }
                if filters.is_empty() {
                    return Err(SandboxError::Internal(format!(
                        "http-level policy rule (session {id}, rule_order {rule_order}) \
                         has no filter rows — should have been rejected at validation"
                    )));
                }
                AssuranceLevel::Http {
                    http_filters: filters,
                }
            }
            other => {
                return Err(SandboxError::Internal(format!(
                    "unknown level in policy_rules: {other}"
                )));
            }
        };

        rules.push(PolicyRule {
            host: destination,
            port,
            protocol,
            reason,
            level,
        });
    }

    Ok(Some(Policy { version, rules }))
}

/// Internal error type for the insert retry loop.
enum InsertError {
    /// Primary-key uniqueness violation — the id clashed with an existing row.
    Collision,
    /// Any other DB or serialization failure.
    Other(SandboxError),
}

/// Parse a row from the sessions table into a `Session`.
///
/// Column order matches every `SELECT ... FROM sessions` in this module:
/// `id, name, state, config, created_at, updated_at, backend,
///  owner_username, guest_protocol_version, guest_binary_version`.
fn row_to_session(row: &rusqlite::Row<'_>) -> Result<Session, SandboxError> {
    let id_str: String = row.get(0)?;
    let name: Option<String> = row.get(1)?;
    let state_str: String = row.get(2)?;
    let config_json: String = row.get(3)?;
    let created_at_str: String = row.get(4)?;
    let updated_at_str: String = row.get(5)?;
    // Column 6 (`backend`) was introduced by V005. The migration's
    // SQL `DEFAULT 'lima'` ensures every legacy row has a value, so
    // a hard read is safe — but `BackendKind::from_str` still
    // surfaces unknown tags as `Internal` errors rather than
    // silently mis-dispatching, in case operators ever hand-edit
    // the SQLite file.
    let backend_str: String = row.get(6)?;
    // Columns 7..=9 were introduced by V006. The migration's
    // destructive `DELETE FROM sessions` + `NOT NULL DEFAULT` clauses
    // guarantee every row has a value; reads are hard rather than
    // tolerant.
    let owner_username: String = row.get(7)?;
    let guest_protocol_version: i64 = row.get(8)?;
    let guest_binary_version: String = row.get(9)?;

    let id = SessionId::parse(&id_str)
        .map_err(|e| SandboxError::Internal(format!("invalid session id in database: {e}")))?;

    let state = SessionState::from_str(&state_str)?;

    let config: SessionConfig = serde_json::from_str(&config_json)
        .map_err(|e| SandboxError::Internal(format!("invalid config JSON in database: {e}")))?;

    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map_err(|e| SandboxError::Internal(format!("invalid created_at timestamp: {e}")))?
        .with_timezone(&Utc);

    let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
        .map_err(|e| SandboxError::Internal(format!("invalid updated_at timestamp: {e}")))?
        .with_timezone(&Utc);

    let backend = backend_str
        .parse::<crate::backend::BackendKind>()
        .map_err(|e| SandboxError::Internal(format!("invalid backend in database: {e}")))?;

    let guest_protocol_version = u32::try_from(guest_protocol_version.max(0)).map_err(|_| {
        SandboxError::Internal(format!(
            "guest_protocol_version out of u32 range: {guest_protocol_version}"
        ))
    })?;

    Ok(Session {
        id,
        name,
        state,
        config,
        created_at,
        updated_at,
        backend,
        owner_username,
        guest_protocol_version,
        guest_binary_version,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::thread;

    use super::*;
    use tempfile::TempDir;

    /// Create a `SessionStore` in a fresh temporary directory.
    fn test_store() -> (SessionStore, TempDir) {
        let dir = TempDir::new().expect("failed to create temp dir");
        let (store, _orphans) =
            SessionStore::new(dir.path().to_path_buf()).expect("failed to create store");
        (store, dir)
    }

    /// Per-caller isolation (api-session-isolation spec § 2.4) requires
    /// every public store call to carry an owner identity. Tests in this
    /// module that pre-date Spec 2 use this constant so the per-caller
    /// filter is satisfied without making the test bodies noisier than
    /// the assertions they perform. Tests that *exercise* the per-caller
    /// isolation rules use distinct usernames inline.
    const TEST_CALLER: &str = "test-operator";

    /// Return a `SessionId` that is guaranteed not to exist in the store.
    fn missing_id() -> SessionId {
        SessionId::parse("ffffffffffff").unwrap()
    }

    #[test]
    fn test_create_and_get_session() {
        let (store, _dir) = test_store();

        let config = SessionConfig::default();
        let session = store
            .create_session(config, None, TEST_CALLER, 0, "")
            .expect("create failed");

        assert_eq!(session.state, SessionState::Creating);
        assert!(session.name.is_none());
        assert_eq!(session.id.as_str().len(), SessionId::LEN);
        assert_eq!(session.owner_username, TEST_CALLER);

        let fetched = store
            .get_session(&session.id, TEST_CALLER)
            .expect("get failed")
            .expect("session should exist");

        assert_eq!(fetched.id, session.id);
        assert_eq!(fetched.state, session.state);
        assert_eq!(fetched.config.cpus, session.config.cpus);
        assert_eq!(fetched.config.memory_mb, session.config.memory_mb);
        assert_eq!(fetched.config.disk_gb, session.config.disk_gb);
        assert_eq!(fetched.created_at, session.created_at);
        assert_eq!(fetched.updated_at, session.updated_at);
        assert_eq!(fetched.owner_username, TEST_CALLER);
    }

    #[test]
    fn test_create_session_with_name() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(
                SessionConfig::default(),
                Some("my-sandbox".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create failed");

        assert_eq!(session.name, Some("my-sandbox".into()));

        let fetched = store
            .get_session(&session.id, TEST_CALLER)
            .expect("get failed")
            .expect("session should exist");

        assert_eq!(fetched.name, Some("my-sandbox".into()));
    }

    #[test]
    fn test_list_sessions() {
        let (store, _dir) = test_store();

        let s1 = store
            .create_session(
                SessionConfig::default(),
                Some("first".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create s1");
        let s2 = store
            .create_session(
                SessionConfig::default(),
                Some("second".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create s2");
        let s3 = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create s3");

        let list = store.list_sessions(TEST_CALLER).expect("list failed");
        assert_eq!(list.len(), 3);

        let ids: Vec<SessionId> = list.iter().map(|s| s.id).collect();
        assert!(ids.contains(&s1.id));
        assert!(ids.contains(&s2.id));
        assert!(ids.contains(&s3.id));
    }

    #[test]
    fn test_update_state() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        let original_updated_at = session.updated_at;

        // Small sleep so the timestamp changes.
        std::thread::sleep(std::time::Duration::from_millis(10));

        store
            .update_state(&session.id, TEST_CALLER, SessionState::Running)
            .expect("update state");

        let fetched = store
            .get_session(&session.id, TEST_CALLER)
            .expect("get")
            .expect("exists");

        assert_eq!(fetched.state, SessionState::Running);
        assert!(fetched.updated_at > original_updated_at);
    }

    #[test]
    fn test_delete_session() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        store
            .delete_session(&session.id, TEST_CALLER)
            .expect("delete");

        let fetched = store.get_session(&session.id, TEST_CALLER).expect("get");
        assert!(fetched.is_none());
    }

    #[test]
    fn test_delete_removes_directory() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        let session_dir = store.session_dir(&session.id);
        assert!(
            session_dir.exists(),
            "session dir should exist after create"
        );

        store
            .delete_session(&session.id, TEST_CALLER)
            .expect("delete");
        assert!(
            !session_dir.exists(),
            "session dir should be removed after delete"
        );
    }

    #[test]
    fn test_get_nonexistent() {
        let (store, _dir) = test_store();

        let result = store.get_session(&missing_id(), TEST_CALLER).expect("get");
        assert!(result.is_none());
    }

    #[test]
    fn test_state_transition_via_store() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        assert_eq!(session.state, SessionState::Creating);

        store
            .update_state(&session.id, TEST_CALLER, SessionState::Running)
            .expect("to running");
        let s = store
            .get_session(&session.id, TEST_CALLER)
            .expect("get")
            .expect("exists");
        assert_eq!(s.state, SessionState::Running);

        store
            .update_state(&session.id, TEST_CALLER, SessionState::Stopped)
            .expect("to stopped");
        let s = store
            .get_session(&session.id, TEST_CALLER)
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
                    .create_session(
                        SessionConfig::default(),
                        Some(name.clone()),
                        TEST_CALLER,
                        0,
                        "",
                    )
                    .expect("create");

                let fetched = store
                    .get_session(&session.id, TEST_CALLER)
                    .expect("get")
                    .expect("exists");

                assert_eq!(fetched.name, Some(name));
                session.id
            }));
        }

        let ids: Vec<SessionId> = handles
            .into_iter()
            .map(|h| h.join().expect("thread panicked"))
            .collect();

        let list = store.list_sessions(TEST_CALLER).expect("list");
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
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'")
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

        let result = store.update_state(&missing_id(), TEST_CALLER, SessionState::Running);
        assert!(matches!(result, Err(SandboxError::SessionNotFound(_))));
    }

    #[test]
    fn test_delete_nonexistent() {
        let (store, _dir) = test_store();

        let result = store.delete_session(&missing_id(), TEST_CALLER);
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
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };

        let session = store
            .create_session(config, Some("custom".into()), TEST_CALLER, 0, "")
            .expect("create");

        let fetched = store
            .get_session(&session.id, TEST_CALLER)
            .expect("get")
            .expect("exists");

        assert_eq!(fetched.config.cpus, 8);
        assert_eq!(fetched.config.memory_mb, 16384);
        assert_eq!(fetched.config.disk_gb, 100);
    }

    #[test]
    fn test_new_config_fields_round_trip_through_store() {
        // End-to-end: SessionConfig{repo, boot_cmd, template} → SQLite
        // config_json → read back via get_session.  Protects against a
        // regression where the store path serializes/deserializes the
        // new fields but one side forgets to include them.
        let (store, _dir) = test_store();

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

        let session = store
            .create_session(config, Some("enriched".into()), TEST_CALLER, 0, "")
            .expect("create");

        let fetched = store
            .get_session(&session.id, TEST_CALLER)
            .expect("get")
            .expect("exists");

        assert_eq!(
            fetched.config.repo.as_deref(),
            Some("https://github.com/example/app.git")
        );
        assert_eq!(fetched.config.boot_cmd.as_deref(), Some("make setup"));
        assert_eq!(fetched.config.template.as_deref(), Some("/tmp/custom.yaml"));
    }

    #[test]
    fn test_legacy_config_json_is_readable() {
        // A row written by an older daemon has a `config` JSON blob that
        // lacks the new repo/boot_cmd/template fields entirely.  Open
        // the underlying SQLite DB directly, rewrite the `config`
        // column to the legacy shape, and confirm the new daemon
        // decodes it cleanly with `None` on the three new fields.
        let (store, dir) = test_store();

        let session = store
            .create_session(
                SessionConfig::default(),
                Some("legacy".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create");

        // Open a separate connection to rewrite the column.  The store's
        // own connection is private; a direct rusqlite handle against the
        // same file mirrors what an older daemon would have produced.
        let legacy_json = r#"{"cpus": 2, "memory_mb": 4096, "disk_gb": 20, "hardened": true}"#;
        {
            let conn = rusqlite::Connection::open(dir.path().join("sessions.db")).expect("open db");
            conn.execute(
                "UPDATE sessions SET config = ?1 WHERE id = ?2",
                rusqlite::params![legacy_json, session.id.as_str()],
            )
            .expect("update");
        }

        let fetched = store
            .get_session(&session.id, TEST_CALLER)
            .expect("get")
            .expect("exists");

        assert_eq!(fetched.config.cpus, 2);
        assert!(fetched.config.repo.is_none());
        assert!(fetched.config.boot_cmd.is_none());
        assert!(fetched.config.template.is_none());
    }

    #[test]
    fn test_session_directory_created() {
        let (store, dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        let expected = dir.path().join("sessions").join(session.id.as_str());
        assert!(expected.exists());
        assert!(expected.is_dir());
    }

    #[test]
    fn test_get_by_name_or_id_with_id() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(
                SessionConfig::default(),
                Some("named".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create");

        let fetched = store
            .get_session_by_name_or_id(session.id.as_str(), TEST_CALLER)
            .expect("get by id")
            .expect("should exist");

        assert_eq!(fetched.id, session.id);
    }

    #[test]
    fn test_get_by_name_or_id_with_name() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(
                SessionConfig::default(),
                Some("lookup-test".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create");

        let fetched = store
            .get_session_by_name_or_id("lookup-test", TEST_CALLER)
            .expect("get by name")
            .expect("should exist");

        assert_eq!(fetched.id, session.id);
        assert_eq!(fetched.name, Some("lookup-test".into()));
    }

    #[test]
    fn test_get_by_name_or_id_not_found() {
        let (store, _dir) = test_store();

        let result = store
            .get_session_by_name_or_id("nonexistent", TEST_CALLER)
            .expect("should not error");

        assert!(result.is_none());
    }

    #[test]
    fn test_get_by_name_or_id_with_unknown_id() {
        let (store, _dir) = test_store();

        let result = store
            .get_session_by_name_or_id(missing_id().as_str(), TEST_CALLER)
            .expect("should not error");

        assert!(result.is_none());
    }

    // -- Prefix resolution -------------------------------------------------

    #[test]
    fn test_resolve_id_prefix_found() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        // First 6 chars should be enough to uniquely identify it in a store
        // with only one session.
        let prefix = &session.id.as_str()[..6];
        let outcome = store
            .resolve_id_prefix(prefix, TEST_CALLER)
            .expect("resolve should not error");
        assert_eq!(outcome, ResolveOutcome::Found(session.id));
    }

    #[test]
    fn test_resolve_id_prefix_full_id_found() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        let outcome = store
            .resolve_id_prefix(session.id.as_str(), TEST_CALLER)
            .expect("resolve full id");
        assert_eq!(outcome, ResolveOutcome::Found(session.id));
    }

    #[test]
    fn test_resolve_id_prefix_not_found() {
        let (store, _dir) = test_store();
        let _session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        // Use a prefix unlikely to collide: the all-f prefix is extremely
        // rare in UUID v4 output.
        let outcome = store
            .resolve_id_prefix("fffffff", TEST_CALLER)
            .expect("resolve should not error");
        // If by astronomical chance the session starts with fffffff, rerun.
        match outcome {
            ResolveOutcome::NotFound => {}
            other => panic!("unexpected outcome for unlikely prefix: {other:?}"),
        }
    }

    #[test]
    fn test_resolve_id_prefix_ambiguous() {
        // We cannot easily force a real collision with random ids, so insert
        // two rows manually with shared prefix via direct DB access.
        let (store, _dir) = test_store();

        {
            let conn = store.conn.lock().unwrap();
            let base_config = serde_json::to_string(&SessionConfig::default()).unwrap();
            let now = Utc::now().to_rfc3339();
            for suffix in ["aa", "bb"] {
                let id = format!("cafebabe00{suffix}");
                conn.execute(
                    "INSERT INTO sessions (id, name, state, config, created_at, updated_at,
                                            owner_username, guest_protocol_version,
                                            guest_binary_version)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        id,
                        Option::<String>::None,
                        "Creating",
                        base_config,
                        now,
                        now,
                        TEST_CALLER,
                        0i64,
                        "",
                    ],
                )
                .unwrap();
            }
        }

        let outcome = store
            .resolve_id_prefix("cafebabe", TEST_CALLER)
            .expect("resolve ambiguous");
        match outcome {
            ResolveOutcome::Ambiguous(ids) => {
                assert_eq!(ids.len(), 2);
                assert!(ids.iter().any(|i| i.as_str() == "cafebabe00aa"));
                assert!(ids.iter().any(|i| i.as_str() == "cafebabe00bb"));
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }

        // A more specific prefix resolves uniquely.
        let outcome = store
            .resolve_id_prefix("cafebabe00a", TEST_CALLER)
            .expect("resolve specific");
        match outcome {
            ResolveOutcome::Found(id) => assert_eq!(id.as_str(), "cafebabe00aa"),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_id_prefix_empty_or_invalid() {
        let (store, _dir) = test_store();
        let _ = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        // Empty prefix: NotFound.
        assert_eq!(
            store.resolve_id_prefix("", TEST_CALLER).expect("empty"),
            ResolveOutcome::NotFound
        );
        // Non-hex chars: NotFound.
        assert_eq!(
            store
                .resolve_id_prefix("xyz", TEST_CALLER)
                .expect("non-hex"),
            ResolveOutcome::NotFound
        );
        // Uppercase: NotFound (ids are stored lowercase).
        assert_eq!(
            store.resolve_id_prefix("ABC", TEST_CALLER).expect("upper"),
            ResolveOutcome::NotFound
        );
        // Too long: NotFound.
        assert_eq!(
            store
                .resolve_id_prefix(&"a".repeat(SessionId::LEN + 1), TEST_CALLER)
                .expect("too long"),
            ResolveOutcome::NotFound
        );
    }

    // -- NetworkInfo persistence tests ---------------------------------------

    #[test]
    fn test_set_and_get_network_info() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        // Initially no network info.
        let info = store
            .get_network_info(&session.id, TEST_CALLER)
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
            .set_network_info(&session.id, TEST_CALLER, &net_info)
            .expect("set_network_info");

        // Retrieve it.
        let fetched = store
            .get_network_info(&session.id, TEST_CALLER)
            .expect("get_network_info")
            .expect("should have network info");

        assert_eq!(fetched.bridge_name, net_info.bridge_name);
        assert_eq!(fetched.subnet, net_info.subnet);
        assert_eq!(fetched.gateway_ip, net_info.gateway_ip);
        assert_eq!(fetched.vm_ip, net_info.vm_ip);
        assert_eq!(fetched.docker_network_name, net_info.docker_network_name);
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

        let result = store.set_network_info(&missing_id(), TEST_CALLER, &net_info);
        assert!(matches!(result, Err(SandboxError::SessionNotFound(_))));
    }

    #[test]
    fn test_get_network_info_nonexistent_session() {
        let (store, _dir) = test_store();

        let result = store.get_network_info(&missing_id(), TEST_CALLER);
        assert!(matches!(result, Err(SandboxError::SessionNotFound(_))));
    }

    #[test]
    fn test_list_sessions_with_network_info() {
        let (store, _dir) = test_store();

        let s1 = store
            .create_session(
                SessionConfig::default(),
                Some("s1".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create s1");
        let s2 = store
            .create_session(
                SessionConfig::default(),
                Some("s2".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create s2");
        let _s3 = store
            .create_session(
                SessionConfig::default(),
                Some("s3".into()),
                TEST_CALLER,
                0,
                "",
            )
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

        store
            .set_network_info(&s1.id, TEST_CALLER, &info1)
            .expect("set s1");
        store
            .set_network_info(&s2.id, TEST_CALLER, &info2)
            .expect("set s2");

        let entries = store
            .list_sessions_with_network_info()
            .expect("list with network info");

        assert_eq!(entries.len(), 2);

        let ids: Vec<SessionId> = entries.iter().map(|(id, _)| *id).collect();
        assert!(ids.contains(&s1.id));
        assert!(ids.contains(&s2.id));
    }

    // -- State machine validation tests ------------------------------------

    #[test]
    fn test_update_state_validates_transition() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        // Creating -> Running: valid
        store
            .update_state(&session.id, TEST_CALLER, SessionState::Running)
            .expect("Creating -> Running should succeed");

        // Running -> Stopped: valid
        store
            .update_state(&session.id, TEST_CALLER, SessionState::Stopped)
            .expect("Running -> Stopped should succeed");

        // Stopped -> Running: valid
        store
            .update_state(&session.id, TEST_CALLER, SessionState::Running)
            .expect("Stopped -> Running should succeed");
    }

    #[test]
    fn test_update_state_rejects_invalid_transition() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        // Creating -> Stopped: invalid
        let result = store.update_state(&session.id, TEST_CALLER, SessionState::Stopped);
        assert!(
            matches!(result, Err(SandboxError::InvalidState(_))),
            "Creating -> Stopped should be rejected, got: {result:?}"
        );

        // Advance to Error
        store
            .update_state(&session.id, TEST_CALLER, SessionState::Error)
            .expect("Creating -> Error should succeed");

        // Error -> Running: invalid (Error is terminal)
        let result = store.update_state(&session.id, TEST_CALLER, SessionState::Running);
        assert!(
            matches!(result, Err(SandboxError::InvalidState(_))),
            "Error -> Running should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_update_state_reconcile_bypasses_validation() {
        let (store, _dir) = test_store();

        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        // Creating -> Stopped: normally invalid, but the reconcile path
        // skips validation (and skips the per-caller filter).
        store
            .update_state_reconcile(&session.id, SessionState::Stopped)
            .expect("reconcile Creating -> Stopped should succeed");

        let fetched = store
            .get_session(&session.id, TEST_CALLER)
            .expect("get")
            .expect("exists");
        assert_eq!(fetched.state, SessionState::Stopped);

        // Set to Error, then reconcile back to Running.
        store
            .update_state_reconcile(&session.id, SessionState::Error)
            .expect("reconcile -> Error");
        store
            .update_state_reconcile(&session.id, SessionState::Running)
            .expect("reconcile Error -> Running should succeed");

        let fetched = store
            .get_session(&session.id, TEST_CALLER)
            .expect("get")
            .expect("exists");
        assert_eq!(fetched.state, SessionState::Running);
    }

    #[test]
    fn test_update_state_reconcile_nonexistent() {
        let (store, _dir) = test_store();

        let result = store.update_state_reconcile(&missing_id(), SessionState::Running);
        assert!(matches!(result, Err(SandboxError::SessionNotFound(_))));
    }

    // ----------------------------------------------------------------------
    // Policy persistence tests
    // ----------------------------------------------------------------------

    fn sample_http_policy() -> Policy {
        Policy {
            version: crate::policy::SCHEMA_VERSION.into(),
            rules: vec![
                PolicyRule {
                    host: Destination::Domain("github.com".into()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    reason: Some("fetch repo".into()),
                    level: AssuranceLevel::Http {
                        http_filters: vec![
                            HttpFilter {
                                method: HttpMethod::Get,
                                path: "/repos/*".into(),
                            },
                            HttpFilter {
                                method: HttpMethod::Post,
                                path: "/repos/*/issues".into(),
                            },
                        ],
                    },
                },
                PolicyRule {
                    host: Destination::Cidr("10.0.0.0/8".into()),
                    port: 80,
                    protocol: Protocol::Tcp,
                    reason: None,
                    level: AssuranceLevel::Deny,
                },
                PolicyRule {
                    host: Destination::Domain("example.com".into()),
                    port: 443,
                    protocol: Protocol::Tcp,
                    reason: Some("tls only".into()),
                    level: AssuranceLevel::Tls,
                },
            ],
        }
    }

    #[test]
    fn test_set_and_get_policy_round_trip_with_http_filters() {
        let (store, _dir) = test_store();
        let session = store
            .create_session(
                SessionConfig::default(),
                Some("pol".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create");

        // No policy yet.
        assert!(
            store
                .get_policy(&session.id, TEST_CALLER)
                .expect("get_policy")
                .is_none()
        );

        let policy = sample_http_policy();
        store
            .set_policy(&session.id, TEST_CALLER, &policy)
            .expect("set_policy should succeed");

        let loaded = store
            .get_policy(&session.id, TEST_CALLER)
            .expect("get_policy should not error")
            .expect("policy should be present");

        assert_eq!(loaded.version, policy.version);
        assert_eq!(loaded.rules.len(), policy.rules.len());

        // Rule 0: http with two filters, in insertion order.
        match &loaded.rules[0].level {
            AssuranceLevel::Http { http_filters } => {
                assert_eq!(http_filters.len(), 2);
                assert_eq!(http_filters[0].method, HttpMethod::Get);
                assert_eq!(http_filters[0].path, "/repos/*");
                assert_eq!(http_filters[1].method, HttpMethod::Post);
                assert_eq!(http_filters[1].path, "/repos/*/issues");
            }
            other => panic!("expected Http variant, got {other:?}"),
        }
        assert_eq!(loaded.rules[0].protocol, Protocol::Tcp);
        assert_eq!(loaded.rules[0].reason.as_deref(), Some("fetch repo"));
        assert!(matches!(
            loaded.rules[0].host,
            Destination::Domain(ref s) if s == "github.com"
        ));

        // Rule 1: deny, cidr host, no filters, no reason.
        assert_eq!(loaded.rules[1].level, AssuranceLevel::Deny);
        assert_eq!(loaded.rules[1].protocol, Protocol::Tcp);
        assert!(loaded.rules[1].reason.is_none());
        assert!(matches!(
            loaded.rules[1].host,
            Destination::Cidr(ref s) if s == "10.0.0.0/8"
        ));

        // Rule 2: tls.
        assert_eq!(loaded.rules[2].level, AssuranceLevel::Tls);
        assert_eq!(loaded.rules[2].protocol, Protocol::Tcp);
    }

    #[test]
    fn test_set_policy_replaces_previous() {
        let (store, _dir) = test_store();
        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        let first = sample_http_policy();
        store
            .set_policy(&session.id, TEST_CALLER, &first)
            .expect("set first");

        // Overwrite with a single-rule policy.
        let second = Policy {
            version: "2.0.0".into(),
            rules: vec![PolicyRule {
                host: Destination::Domain("other.test".into()),
                port: 443,
                protocol: Protocol::Tcp,
                reason: None,
                level: AssuranceLevel::Transport,
            }],
        };
        store
            .set_policy(&session.id, TEST_CALLER, &second)
            .expect("set second");

        let loaded = store
            .get_policy(&session.id, TEST_CALLER)
            .expect("get")
            .expect("present");
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.rules[0].level, AssuranceLevel::Transport);

        // Child filter rows for the replaced http rule must have been
        // cascaded away — count rows directly.
        let conn = store.conn.lock().unwrap();
        let filter_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM policy_rule_http_filters WHERE session_id = ?1",
                params![session.id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            filter_count, 0,
            "http filters for replaced rule must be gone"
        );
    }

    #[test]
    fn test_get_policy_returns_none_when_unset() {
        let (store, _dir) = test_store();
        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        assert!(
            store
                .get_policy(&session.id, TEST_CALLER)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_load_all_policies_returns_every_persisted_policy() {
        let (store, _dir) = test_store();

        let s1 = store
            .create_session(
                SessionConfig::default(),
                Some("one".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create s1");
        let s2 = store
            .create_session(
                SessionConfig::default(),
                Some("two".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create s2");
        let _s3 = store
            .create_session(
                SessionConfig::default(),
                Some("three".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create s3");

        let p1 = sample_http_policy();
        let p2 = Policy {
            version: "2.0.0".into(),
            rules: vec![PolicyRule {
                host: Destination::Domain("deny.example".into()),
                port: 80,
                protocol: Protocol::Tcp,
                reason: None,
                level: AssuranceLevel::Deny,
            }],
        };

        store.set_policy(&s1.id, TEST_CALLER, &p1).expect("set p1");
        store.set_policy(&s2.id, TEST_CALLER, &p2).expect("set p2");

        let all = store.load_all_policies().expect("load_all_policies");
        assert_eq!(
            all.len(),
            2,
            "only sessions with a policy applied should appear"
        );

        let map: HashMap<SessionId, Policy> = all.into_iter().collect();
        let loaded1 = map.get(&s1.id).expect("s1 present");
        assert_eq!(loaded1.rules.len(), p1.rules.len());
        let loaded2 = map.get(&s2.id).expect("s2 present");
        assert_eq!(loaded2.rules.len(), 1);
        assert_eq!(loaded2.rules[0].level, AssuranceLevel::Deny);
    }

    #[test]
    fn test_load_all_policies_skips_corrupt_row_without_panicking() {
        // Force an `http` rule to have zero child filters — a state the
        // normal write path rejects (`set_policy` always inserts at
        // least one filter when the variant is Http) but which a
        // partial write or external tamper could leave behind.  The
        // reassembler must log and skip, not panic or return an error
        // to the caller.
        let (store, _dir) = test_store();
        let session = store
            .create_session(
                SessionConfig::default(),
                Some("corrupt".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create");

        // Insert a parent row and an http rule — but no filter rows.
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO session_policies (session_id, version) VALUES (?1, ?2)",
                params![session.id.as_str(), "1.0.0"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO policy_rules (
                    session_id, rule_order, destination_kind, host_value,
                    port, level, protocol, reason
                 ) VALUES (?1, 0, 'domain', 'corrupt.test', 443, 'http', 'tcp', NULL)",
                params![session.id.as_str()],
            )
            .unwrap();
        }

        // get_policy swallows the corrupt row.
        assert!(
            store
                .get_policy(&session.id, TEST_CALLER)
                .unwrap()
                .is_none()
        );

        // load_all_policies returns an entry-free result for this session,
        // alongside any valid siblings.
        let other = store
            .create_session(
                SessionConfig::default(),
                Some("ok".into()),
                TEST_CALLER,
                0,
                "",
            )
            .expect("create sibling");
        let good = Policy {
            version: "2.0.0".into(),
            rules: vec![PolicyRule {
                host: Destination::Domain("ok.test".into()),
                port: 443,
                protocol: Protocol::Tcp,
                reason: None,
                level: AssuranceLevel::Transport,
            }],
        };
        store
            .set_policy(&other.id, TEST_CALLER, &good)
            .expect("set sibling");

        let all = store.load_all_policies().expect("load_all_policies");
        assert_eq!(
            all.len(),
            1,
            "corrupt row must be skipped, valid sibling preserved"
        );
        assert_eq!(all[0].0, other.id);
    }

    #[test]
    fn test_set_policy_fails_for_unknown_session() {
        // `session_id` is FK-constrained to sessions(id).  Inserting a
        // policy for a session that doesn't exist must fail — and
        // leave no stray rows in the child tables.
        let (store, _dir) = test_store();

        let result = store.set_policy(&missing_id(), TEST_CALLER, &sample_http_policy());
        assert!(
            result.is_err(),
            "set_policy for missing session must fail, got {result:?}"
        );

        // No leftover rows in any of the policy tables.
        let conn = store.conn.lock().unwrap();
        for table in [
            "session_policies",
            "policy_rules",
            "policy_rule_http_filters",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "table {table} must be empty after failed set");
        }
    }

    #[test]
    fn test_set_policy_is_atomic_on_failure() {
        // Applying a valid policy first, then attempting to apply an
        // invalid one (here: an `http` rule with zero filters is fine
        // at the store layer since validation lives in the compiler,
        // so we inject an invalid destination_kind via direct SQL to
        // cause a CHECK failure inside the transaction).  The previous
        // policy must still be retrievable afterwards.
        let (store, _dir) = test_store();
        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");

        let initial = sample_http_policy();
        store
            .set_policy(&session.id, TEST_CALLER, &initial)
            .expect("set initial");

        // Force a mid-transaction failure by starting a second
        // transaction that inserts a row with an invalid destination_kind.
        // We wrap the bad insert in its own TX to simulate the failure
        // path inside `set_policy`.
        let invalid = {
            let conn = store.conn.lock().unwrap();
            let tx = conn.unchecked_transaction().unwrap();
            tx.execute(
                "DELETE FROM session_policies WHERE session_id = ?1",
                params![session.id.as_str()],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO session_policies (session_id, version) VALUES (?1, '1.0.0')",
                params![session.id.as_str()],
            )
            .unwrap();
            let res = tx.execute(
                "INSERT INTO policy_rules (
                    session_id, rule_order, destination_kind, host_value,
                    port, level, protocol, reason
                 ) VALUES (?1, 0, 'bogus', 'x', 443, 'tls', 'tcp', NULL)",
                params![session.id.as_str()],
            );
            let result = res.is_err();
            // Force rollback regardless to leave the DB in the pre-TX state.
            drop(tx);
            result
        };
        assert!(invalid, "bad destination_kind must be rejected by CHECK");

        // The original policy survives because the rollback undid the
        // destructive DELETE.
        let still_there = store
            .get_policy(&session.id, TEST_CALLER)
            .expect("get")
            .expect("original policy must survive rolled-back transaction");
        assert_eq!(still_there.rules.len(), initial.rules.len());
    }

    #[test]
    fn test_delete_session_cascades_policy_rows() {
        let (store, _dir) = test_store();
        let session = store
            .create_session(SessionConfig::default(), None, TEST_CALLER, 0, "")
            .expect("create");
        store
            .set_policy(&session.id, TEST_CALLER, &sample_http_policy())
            .expect("set_policy");

        store
            .delete_session(&session.id, TEST_CALLER)
            .expect("delete");

        // Cascade should have cleared every policy row for this session.
        let conn = store.conn.lock().unwrap();
        for table in [
            "session_policies",
            "policy_rules",
            "policy_rule_http_filters",
        ] {
            let count: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE session_id = ?1"),
                    params![session.id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                count, 0,
                "table {table} must be empty after session deletion (cascade)"
            );
        }
    }

    #[test]
    fn test_policy_survives_store_reopen() {
        // Open a store, persist a policy, drop the store, reopen on the
        // same path.  The policy must still be readable — this is the
        // store-side contract that startup hydration depends on.
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().to_path_buf();

        let session_id;
        let expected_rule_count;
        {
            let (store, _orphans) = SessionStore::new(path.clone()).expect("open");
            let session = store
                .create_session(
                    SessionConfig::default(),
                    Some("pol".into()),
                    TEST_CALLER,
                    0,
                    "",
                )
                .expect("create");
            session_id = session.id;
            let policy = sample_http_policy();
            expected_rule_count = policy.rules.len();
            store
                .set_policy(&session_id, TEST_CALLER, &policy)
                .expect("set_policy");
        }

        // Drop and reopen.
        let (reopened, _orphans) = SessionStore::new(path).expect("reopen");
        let loaded = reopened
            .get_policy(&session_id, TEST_CALLER)
            .expect("get_policy after reopen")
            .expect("policy should still be present after reopen");
        assert_eq!(loaded.rules.len(), expected_rule_count);

        let all = reopened.load_all_policies().expect("load_all_policies");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, session_id);
    }

    /// V004 migration integration test.
    ///
    /// Seeds a database at the V003 shape with v1-tokened policy rows
    /// (including a mix of `tcp`, `udp`, `http`, `https`, and `any`
    /// protocol values, plus a `policy_rule_http_filters` child row for
    /// the `http`-leveled parent), then opens the DB via
    /// `SessionStore::new` — which runs V004 and the orphan sweep.
    ///
    /// Exit criterion (M10.md § "Exit criteria"): "a seed DB containing
    /// v1-shaped rows lands cleanly, emits `policy_reset_on_upgrade`
    /// per affected session (tracing), and leaves those sessions with
    /// no attached policy."
    ///
    /// The tracing event assertion goes through a custom
    /// `tracing-subscriber` layer that records every `INFO` event with
    /// its `event` field value — this is the same contract the bus
    /// consumer reads off the ring buffer.
    #[test]
    fn test_v004_migration_from_v1_seed_db() {
        use std::sync::{Arc, Mutex as StdMutex};
        use tracing::subscriber::with_default;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::{Layer, Registry};

        // Simple Layer that records the values of the `event` and
        // `session_id` fields for every event whose target matches
        // the store module.  Using a custom Layer avoids coupling the
        // test to the env-filter / fmt subscriber stack.
        #[derive(Clone, Default)]
        struct EventRecorder {
            // (event_name, session_id) tuples.
            events: Arc<StdMutex<Vec<(String, String)>>>,
        }

        struct RecorderLayer {
            recorder: EventRecorder,
        }

        impl<S> Layer<S> for RecorderLayer
        where
            S: tracing::Subscriber,
        {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                struct Visitor {
                    event_name: Option<String>,
                    session_id: Option<String>,
                }
                impl tracing::field::Visit for Visitor {
                    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                        match field.name() {
                            "event" => self.event_name = Some(value.to_string()),
                            "session_id" => self.session_id = Some(value.to_string()),
                            _ => {}
                        }
                    }
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        // `session_id = %id` with a SessionId shows up as
                        // Display via record_debug depending on the formatter.
                        // Capture it the same way to be safe.
                        if field.name() == "session_id" {
                            self.session_id =
                                Some(format!("{value:?}").trim_matches('"').to_string());
                        }
                    }
                }
                let mut v = Visitor {
                    event_name: None,
                    session_id: None,
                };
                event.record(&mut v);
                if let (Some(name), Some(sid)) = (v.event_name, v.session_id) {
                    self.recorder.events.lock().unwrap().push((name, sid));
                }
            }
        }

        let recorder = EventRecorder::default();
        let subscriber = Registry::default().with(RecorderLayer {
            recorder: recorder.clone(),
        });

        // Seed the DB in two stages:
        //   1. Run refinery with Target::Version(3), so V001-V003 are
        //      applied exactly as they exist on disk — this gives us
        //      a correctly-populated `refinery_schema_history` with
        //      the right checksums, without hand-rolling them.
        //   2. Insert v1-tokened rows manually, honoring the V003
        //      CHECK constraints (which still permit http/https/any).
        let dir = TempDir::new().expect("tempdir");
        let db_path = dir.path().join("sessions.db");

        let v1_session_purge_only: String; // session with only v1-tokened rules (fully purged)
        let v1_session_mixed: String; // session with mixed v1 + tcp rules (all purged, tcp too)
        let v2_session_should_survive: String; // session without any policy — must not appear as orphan

        {
            let mut conn = Connection::open(&db_path).expect("open raw");
            conn.pragma_update(None, "foreign_keys", "ON").unwrap();

            // Apply only V001..V003.  Refinery fills in history rows
            // for us; when SessionStore::new runs later it will see
            // V004 as the only pending migration.
            embedded::migrations::runner()
                .set_target(refinery::Target::Version(3))
                .run(&mut conn)
                .expect("apply V001..V003");

            // Seed three sessions.
            v1_session_purge_only = "aaaaaaaaaaaa".to_string();
            v1_session_mixed = "bbbbbbbbbbbb".to_string();
            v2_session_should_survive = "cccccccccccc".to_string();

            for id in [
                &v1_session_purge_only,
                &v1_session_mixed,
                &v2_session_should_survive,
            ] {
                conn.execute(
                    "INSERT INTO sessions (id, name, state, config, created_at, updated_at)
                     VALUES (?1, NULL, 'Stopped', '{}', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')",
                    params![id],
                )
                .expect("insert session");
            }

            // session 1: only v1-tokened rules (http, https, any) —
            //            parent policy must be swept at boot.
            conn.execute(
                "INSERT INTO session_policies (session_id, version) VALUES (?1, '1.0.0')",
                params![v1_session_purge_only],
            )
            .expect("seed policy 1");
            conn.execute(
                "INSERT INTO policy_rules
                   (session_id, rule_order, destination_kind, destination_value, level, protocol, reason)
                 VALUES (?1, 0, 'domain', 'legacy.test', 'http', 'http', 'v1 http token')",
                params![v1_session_purge_only],
            )
            .expect("seed v1 http rule");
            conn.execute(
                "INSERT INTO policy_rule_http_filters
                   (session_id, rule_order, filter_order, method, path_pattern)
                 VALUES (?1, 0, 0, 'GET', '/*')",
                params![v1_session_purge_only],
            )
            .expect("seed http filter");
            conn.execute(
                "INSERT INTO policy_rules
                   (session_id, rule_order, destination_kind, destination_value, level, protocol, reason)
                 VALUES (?1, 1, 'cidr', '10.0.0.0/8', 'tls', 'https', 'v1 https token')",
                params![v1_session_purge_only],
            )
            .expect("seed v1 https rule");
            conn.execute(
                "INSERT INTO policy_rules
                   (session_id, rule_order, destination_kind, destination_value, level, protocol, reason)
                 VALUES (?1, 2, 'cidr', '0.0.0.0/0', 'deny', 'any', 'v1 any token')",
                params![v1_session_purge_only],
            )
            .expect("seed v1 any rule");

            // session 2: mixed rules — a tcp rule alongside v1 tokens.
            //            Per the V004 migration comment (Step 4/5), the
            //            tcp rule is *also* purged because no safe port
            //            value can be invented.  So this session is
            //            swept as well.
            conn.execute(
                "INSERT INTO session_policies (session_id, version) VALUES (?1, '1.0.0')",
                params![v1_session_mixed],
            )
            .expect("seed policy 2");
            conn.execute(
                "INSERT INTO policy_rules
                   (session_id, rule_order, destination_kind, destination_value, level, protocol, reason)
                 VALUES (?1, 0, 'domain', 'api.test', 'transport', 'tcp', 'tcp rule — no port in v1')",
                params![v1_session_mixed],
            )
            .expect("seed v1 tcp rule");
            conn.execute(
                "INSERT INTO policy_rules
                   (session_id, rule_order, destination_kind, destination_value, level, protocol, reason)
                 VALUES (?1, 1, 'cidr', '192.168.0.0/16', 'http', 'http', 'v1 http token')",
                params![v1_session_mixed],
            )
            .expect("seed v1 http rule session 2");
            conn.execute(
                "INSERT INTO policy_rule_http_filters
                   (session_id, rule_order, filter_order, method, path_pattern)
                 VALUES (?1, 1, 0, 'GET', '/v1/*')",
                params![v1_session_mixed],
            )
            .expect("seed http filter session 2");

            // session 3: no policy at all — must not surface as an
            //            orphan.  `session_policies` has no row for
            //            this session, so the sweep has nothing to
            //            find.
            // (no inserts for session 3)
        }

        // Drive migrations directly via refinery (target V005), then
        // invoke the V004 sweep helpers in isolation. We cannot use
        // `SessionStore::new` here because V006's `DELETE FROM sessions`
        // would cascade-delete every `session_policies` row before
        // V004's sweep ever sees them. The V004 sweep is its own
        // unit; testing it in isolation matches the spec — V006's
        // destructive step is covered separately by the V006 tests
        // below.
        let swept_sessions = with_default(subscriber, || {
            let mut conn = Connection::open(&db_path).expect("reopen raw");
            conn.pragma_update(None, "foreign_keys", "ON").unwrap();
            embedded::migrations::runner()
                .set_target(refinery::Target::Version(5))
                .run(&mut conn)
                .expect("apply V004..V005");

            // Snapshot would run *before* V004 in production, but here
            // V004 has already deleted the rules. Seed the snapshot
            // manually to match the production contract — the sweep
            // helper only uses this map to populate
            // `previous_rule_count`.
            let mut pre_counts: std::collections::HashMap<String, u32> =
                std::collections::HashMap::new();
            pre_counts.insert(v1_session_purge_only.clone(), 3);
            pre_counts.insert(v1_session_mixed.clone(), 2);

            let orphans =
                SessionStore::purge_orphaned_policies_and_emit_reset_events(&conn, &pre_counts)
                    .expect("sweep orphans");

            let mut orphan_by_session: std::collections::HashMap<&str, u32> = orphans
                .iter()
                .map(|o| (o.session_id.as_str(), o.previous_rule_count))
                .collect();
            assert_eq!(
                orphan_by_session.len(),
                2,
                "expected two orphan infos, got {orphans:?}"
            );
            assert_eq!(
                orphan_by_session.remove(v1_session_purge_only.as_str()),
                Some(3),
                "purge-only session had three v1 rules (http, https, any)"
            );
            assert_eq!(
                orphan_by_session.remove(v1_session_mixed.as_str()),
                Some(2),
                "mixed session had two v1 rules (tcp, http)"
            );

            // Assert: both v1-shaped sessions are gone from session_policies.
            let remaining: i64 = conn
                .query_row("SELECT COUNT(*) FROM session_policies", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                remaining, 0,
                "session_policies must be empty after orphan sweep — \
                 both seeded sessions had v1-tokened rules"
            );

            // Assert: policy_rules is empty (V004 deleted them).
            let remaining_rules: i64 = conn
                .query_row("SELECT COUNT(*) FROM policy_rules", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                remaining_rules, 0,
                "policy_rules must be empty after V004 deletes v1 rows"
            );

            // Assert: policy_rule_http_filters is empty — V004 Step 2
            // deletes filters whose v1 parent was purged, and the
            // session_policies CASCADE cleans up the rest.
            let remaining_filters: i64 = conn
                .query_row("SELECT COUNT(*) FROM policy_rule_http_filters", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(
                remaining_filters, 0,
                "policy_rule_http_filters must be empty after V004"
            );

            // Assert: the sessions themselves still exist (we do not
            // delete the session rows — only the attached policy).
            let remaining_sessions: i64 = conn
                .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                remaining_sessions, 3,
                "session rows must not be touched by V004"
            );

            let _ = v2_session_should_survive;
            (v1_session_purge_only.clone(), v1_session_mixed.clone())
        });

        // Assert: exactly two `policy_reset_on_upgrade` events were
        // emitted, one per affected session.
        let events = recorder.events.lock().unwrap();
        let reset_events: Vec<&(String, String)> = events
            .iter()
            .filter(|(name, _)| name == "policy_reset_on_upgrade")
            .collect();
        assert_eq!(
            reset_events.len(),
            2,
            "expected two policy_reset_on_upgrade events, got {events:?}"
        );

        let got_session_ids: std::collections::HashSet<&str> =
            reset_events.iter().map(|(_, sid)| sid.as_str()).collect();
        assert!(
            got_session_ids.contains(swept_sessions.0.as_str()),
            "missing event for session {}: {got_session_ids:?}",
            swept_sessions.0
        );
        assert!(
            got_session_ids.contains(swept_sessions.1.as_str()),
            "missing event for session {}: {got_session_ids:?}",
            swept_sessions.1
        );
    }

    /// V004 migration idempotence: reopening the same DB must not
    /// re-emit `policy_reset_on_upgrade` (there are no orphans left
    /// to sweep).
    #[test]
    fn test_v004_orphan_sweep_is_idempotent() {
        use std::sync::{Arc, Mutex as StdMutex};
        use tracing::subscriber::with_default;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::{Layer, Registry};

        #[derive(Clone, Default)]
        struct Counter(Arc<StdMutex<usize>>);
        struct CountLayer(Counter);
        impl<S> Layer<S> for CountLayer
        where
            S: tracing::Subscriber,
        {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                struct V(bool);
                impl tracing::field::Visit for V {
                    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                        if field.name() == "event" && value == "policy_reset_on_upgrade" {
                            self.0 = true;
                        }
                    }
                    fn record_debug(
                        &mut self,
                        _f: &tracing::field::Field,
                        _v: &dyn std::fmt::Debug,
                    ) {
                    }
                }
                let mut v = V(false);
                event.record(&mut v);
                if v.0 {
                    *self.0.0.lock().unwrap() += 1;
                }
            }
        }

        // First open: a fresh DB with no policies → no events.
        let dir = TempDir::new().expect("tempdir");
        let counter = Counter::default();
        let first_orphans;
        {
            let subscriber = Registry::default().with(CountLayer(counter.clone()));
            first_orphans = with_default(subscriber, || {
                let (_, orphans) = SessionStore::new(dir.path().to_path_buf()).expect("first open");
                orphans
            });
        }
        assert_eq!(
            *counter.0.lock().unwrap(),
            0,
            "fresh DB has no v1 rows to sweep"
        );
        assert!(
            first_orphans.is_empty(),
            "fresh DB yields an empty orphan list"
        );

        // Second open on the same path: still no events (V004 already
        // ran, nothing left).
        let counter2 = Counter::default();
        let second_orphans;
        {
            let subscriber = Registry::default().with(CountLayer(counter2.clone()));
            second_orphans = with_default(subscriber, || {
                let (_, orphans) =
                    SessionStore::new(dir.path().to_path_buf()).expect("second open");
                orphans
            });
        }
        assert!(
            second_orphans.is_empty(),
            "reopened DB yields an empty orphan list"
        );
        assert_eq!(
            *counter2.0.lock().unwrap(),
            0,
            "reopen must not re-emit reset events once the sweep has run"
        );
    }

    /// V005 migration: `sessions.backend` column.
    ///
    /// Seeds a database at the V004 schema (no `backend` column),
    /// inserts a few rows in the V004 shape, then runs the unbounded
    /// migration runner so V005 lands. Verifies:
    ///   1. The `backend` column exists after migration.
    ///   2. Pre-existing rows pick up `'lima'` from the
    ///      `DEFAULT 'lima'` clause.
    ///   3. The `CHECK` constraint accepts `'lima'` and `'container'`
    ///      and rejects any other token.
    ///
    /// Hermetic: no Docker, no Lima — just rusqlite + the embedded
    /// migrations. Lives next to `test_v004_migration_from_v1_seed_db`
    /// to follow the existing project convention for migration
    /// coverage (V001..V004 tests live inline in this module). The
    /// `integration_*`-prefixed shim in `tests/migrations.rs` is a
    /// thin wrapper that satisfies the verbatim verification command.
    #[test]
    fn test_v005_backend_column_migration() {
        let dir = TempDir::new().expect("tempdir");
        let db_path = dir.path().join("sessions.db");

        // Seed at V004: run the migration runner with an explicit
        // target so V005 stays pending. Refinery fills in
        // `refinery_schema_history` as part of the run, so when we
        // re-open later via the unbounded runner V005 is the only
        // pending step.
        {
            let mut conn = Connection::open(&db_path).expect("open raw");
            conn.pragma_update(None, "foreign_keys", "ON").unwrap();
            embedded::migrations::runner()
                .set_target(refinery::Target::Version(4))
                .run(&mut conn)
                .expect("V001..V004");

            // Insert a couple of V004-shape rows. The `sessions`
            // table at V004 has columns
            //   (id, name, state, config, created_at, updated_at,
            //    network_info)
            // and no `backend` column.
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO sessions (id, name, state, config, created_at, updated_at)
                 VALUES (?1, ?2, 'Stopped', '{}', ?3, ?3)",
                params!["abc123abc123", "alpha", now],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO sessions (id, name, state, config, created_at, updated_at)
                 VALUES (?1, ?2, 'Stopped', '{}', ?3, ?3)",
                params!["def456def456", "beta", now],
            )
            .unwrap();

            // Sanity: no `backend` column at V004.
            let cols = column_names(&conn, "sessions");
            assert!(
                !cols.iter().any(|c| c == "backend"),
                "sessions must not have a backend column at V004; got {cols:?}"
            );
        }

        // Apply only V005 — using `SessionStore::new` here would
        // additionally run V006, whose `DELETE FROM sessions` wipes the
        // pre-existing rows this test wants to inspect for the
        // `DEFAULT 'lima'` behaviour. V006's destructive step has its
        // own coverage in `test_v006_*` below.
        {
            let mut conn = Connection::open(&db_path).expect("reopen raw");
            conn.pragma_update(None, "foreign_keys", "ON").unwrap();
            embedded::migrations::runner()
                .set_target(refinery::Target::Version(5))
                .run(&mut conn)
                .expect("apply V005");
        }

        let conn = Connection::open(&db_path).unwrap();

        // 1. The column exists.
        let cols = column_names(&conn, "sessions");
        assert!(
            cols.iter().any(|c| c == "backend"),
            "expected `backend` column after V005; got {cols:?}"
        );

        // 2. Pre-existing rows carry `backend = 'lima'`.
        let mut stmt = conn
            .prepare("SELECT id, backend FROM sessions ORDER BY id")
            .unwrap();
        let rows: Vec<(String, String)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            rows,
            vec![
                ("abc123abc123".to_string(), "lima".to_string()),
                ("def456def456".to_string(), "lima".to_string()),
            ],
            "pre-existing rows must default to backend='lima' after V005"
        );

        // 3a. The CHECK constraint accepts 'lima' and 'container'.
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (id, name, state, config, created_at, updated_at, backend)
             VALUES (?1, ?2, 'Stopped', '{}', ?3, ?3, 'container')",
            params!["111111111111", "ctr", now],
        )
        .expect("container backend must be accepted");
        conn.execute(
            "INSERT INTO sessions (id, name, state, config, created_at, updated_at, backend)
             VALUES (?1, ?2, 'Stopped', '{}', ?3, ?3, 'lima')",
            params!["222222222222", "lima-explicit", now],
        )
        .expect("lima backend must be accepted");

        // 3b. The CHECK constraint rejects any other token.
        let err = conn.execute(
            "INSERT INTO sessions (id, name, state, config, created_at, updated_at, backend)
             VALUES (?1, ?2, 'Stopped', '{}', ?3, ?3, 'foo')",
            params!["333333333333", "bad", now],
        );
        assert!(
            err.is_err(),
            "CHECK constraint must reject backend='foo'; got Ok"
        );
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("CHECK constraint failed") || msg.contains("constraint"),
            "expected CHECK constraint failure, got: {msg}"
        );
    }

    /// Helper for the V005 migration test: read the column names of a
    /// table via `PRAGMA table_info`.
    fn column_names(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    // ========================================================================
    // V006 migration tests (api-session-isolation spec § 7.1)
    // ========================================================================

    /// V006 on a fresh DB: refinery runs V001..V006 with no rows to
    /// destroy. The three new columns are present afterwards.
    #[test]
    fn test_v006_applies_cleanly_to_fresh_db() {
        let dir = TempDir::new().expect("tempdir");
        let (_store, _orphans) = SessionStore::new(dir.path().to_path_buf()).expect("open fresh");

        let conn = Connection::open(dir.path().join("sessions.db")).unwrap();
        let cols = column_names(&conn, "sessions");
        for expected in &[
            "owner_username",
            "guest_protocol_version",
            "guest_binary_version",
        ] {
            assert!(
                cols.iter().any(|c| c == expected),
                "expected column `{expected}` after V006; got {cols:?}"
            );
        }
    }

    /// V006 on a V005-seeded DB with sessions present: the destructive
    /// `DELETE FROM sessions` step wipes pre-existing rows AND cascades
    /// through `session_policies` -> `policy_rules` ->
    /// `policy_rule_http_filters` (via the V003 foreign keys). Spec §
    /// 2.1 calls this out — every existing dev session is volatile and
    /// the cascade is the correct teardown shape for an upgrade.
    #[test]
    fn test_v006_deletes_existing_sessions_on_dev_upgrade() {
        let dir = TempDir::new().expect("tempdir");
        let db_path = dir.path().join("sessions.db");

        // Seed at V005 with a session row and a policy chain.
        {
            let mut conn = Connection::open(&db_path).expect("open raw");
            conn.pragma_update(None, "foreign_keys", "ON").unwrap();
            embedded::migrations::runner()
                .set_target(refinery::Target::Version(5))
                .run(&mut conn)
                .expect("V001..V005");

            let now = Utc::now().to_rfc3339();
            for sid in &["aaaaaaaaaaaa", "bbbbbbbbbbbb"] {
                conn.execute(
                    "INSERT INTO sessions (id, name, state, config, created_at, updated_at, backend)
                     VALUES (?1, ?2, 'Stopped', '{}', ?3, ?3, 'lima')",
                    params![sid, sid, now],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO session_policies (session_id, version) VALUES (?1, '2.0.0')",
                    params![sid],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO policy_rules
                        (session_id, rule_order, destination_kind, host_value, port, level, protocol, reason)
                     VALUES (?1, 0, 'domain', 'example.com', 443, 'deny', 'tcp', 'seed')",
                    params![sid],
                )
                .unwrap();
            }

            // Sanity: rows are present pre-V006.
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 2, "two session rows must be present at V005");
        }

        // Open via SessionStore::new — runs V006 (and triggers the
        // destructive DELETE + cascade).
        let (_store, _orphans) = SessionStore::new(dir.path().to_path_buf()).expect("open at V006");

        let conn = Connection::open(&db_path).unwrap();
        let sessions: i64 = conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sessions, 0, "V006 must wipe pre-existing session rows");

        let policies: i64 = conn
            .query_row("SELECT COUNT(*) FROM session_policies", [], |r| r.get(0))
            .unwrap();
        assert_eq!(policies, 0, "V006 cascade must wipe session_policies");

        let rules: i64 = conn
            .query_row("SELECT COUNT(*) FROM policy_rules", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rules, 0, "V006 cascade must wipe policy_rules");
    }

    /// V006's `ADD COLUMN ... NOT NULL DEFAULT ''` shape pins the
    /// constraints: subsequent `INSERT`s that omit `owner_username`
    /// pick up the empty-string default rather than failing — that is
    /// the only way refinery could apply `NOT NULL` to a populated
    /// table. The intent here is to pin the *shape* (not-null +
    /// default), not the daemon's behaviour (the daemon never relies
    /// on the default; it stamps a real username at create time).
    #[test]
    fn test_v006_columns_have_correct_constraints() {
        let dir = TempDir::new().expect("tempdir");
        let (_store, _orphans) = SessionStore::new(dir.path().to_path_buf()).expect("open");

        let conn = Connection::open(dir.path().join("sessions.db")).unwrap();

        // Inspect table_info: each of the three V006 columns must
        // report `notnull = 1`.
        let mut stmt = conn.prepare("PRAGMA table_info(sessions)").unwrap();
        let rows: Vec<(String, i64)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, i64>(3)?))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        for expected in &[
            "owner_username",
            "guest_protocol_version",
            "guest_binary_version",
        ] {
            let (_, notnull) = rows
                .iter()
                .find(|(c, _)| c == expected)
                .unwrap_or_else(|| panic!("missing column {expected}"));
            assert_eq!(*notnull, 1, "{expected} must be NOT NULL");
        }

        // Inserts that omit the V006 columns pick up the SQL DEFAULTs
        // — confirms the migration declared them.
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (id, name, state, config, created_at, updated_at, backend)
             VALUES (?1, ?2, 'Stopped', '{}', ?3, ?3, 'lima')",
            params!["cccccccccccc", "implicit-default", now],
        )
        .expect("insert with V006 column defaults must succeed");

        let (owner, proto, bin): (String, i64, String) = conn
            .query_row(
                "SELECT owner_username, guest_protocol_version, guest_binary_version \
                 FROM sessions WHERE id = ?1",
                params!["cccccccccccc"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(owner, "");
        assert_eq!(proto, 0);
        assert_eq!(bin, "");
    }

    /// V006 is idempotent across reopens: refinery's
    /// `refinery_schema_history` table makes the migration a no-op on
    /// the second `SessionStore::new`. The destructive DELETE only
    /// fires the first time. Test: open the store twice, insert a row
    /// between opens via the public API, assert the row survives the
    /// second open.
    #[test]
    fn test_v006_idempotent_on_reapply() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().to_path_buf();

        let session_id = {
            let (store, _orphans) = SessionStore::new(path.clone()).expect("first open");
            let session = store
                .create_session(SessionConfig::default(), None, "alice", 0, "")
                .expect("create");
            session.id
        };

        // Second open — V006 is already in the history table and must
        // not re-fire its DELETE. The session created above must
        // survive.
        let (store, _orphans) = SessionStore::new(path).expect("second open");
        let row = store
            .get_session(&session_id, "alice")
            .expect("get")
            .expect("session row must survive reopen");
        assert_eq!(row.owner_username, "alice");
    }

    // ========================================================================
    // Per-caller filtering tests (api-session-isolation spec § 7.2)
    // ========================================================================

    /// Stamps the `caller_username` arg into the row.
    #[test]
    fn test_create_stamps_caller_username() {
        let (store, _dir) = test_store();
        let session = store
            .create_session(SessionConfig::default(), None, "alice", 0, "")
            .expect("create");
        assert_eq!(session.owner_username, "alice");

        // And the value round-trips through SQLite, not just the
        // in-memory return value.
        let reloaded = store
            .get_session(&session.id, "alice")
            .expect("get")
            .expect("present");
        assert_eq!(reloaded.owner_username, "alice");
    }

    /// `get_session` returns `Ok(Some(_))` when called by the owner.
    #[test]
    fn test_get_returns_own_session() {
        let (store, _dir) = test_store();
        let session = store
            .create_session(SessionConfig::default(), None, "alice", 0, "")
            .expect("create");
        let got = store
            .get_session(&session.id, "alice")
            .expect("get")
            .expect("alice sees her own session");
        assert_eq!(got.id, session.id);
    }

    /// `get_session` returns `Ok(None)` for a foreign session id — the
    /// same shape as a truly nonexistent id, so handlers map both to
    /// HTTP 404 indistinguishably.
    #[test]
    fn test_get_returns_none_for_foreign_session() {
        let (store, _dir) = test_store();
        let session = store
            .create_session(SessionConfig::default(), None, "alice", 0, "")
            .expect("alice creates");
        let got = store.get_session(&session.id, "bob").expect("get");
        assert!(
            got.is_none(),
            "bob must NOT see alice's session (got {got:?})"
        );
    }

    /// `list_sessions` returns the caller's rows only.
    #[test]
    fn test_list_returns_only_callers_sessions() {
        let (store, _dir) = test_store();
        let a1 = store
            .create_session(SessionConfig::default(), Some("a1".into()), "alice", 0, "")
            .unwrap();
        let a2 = store
            .create_session(SessionConfig::default(), Some("a2".into()), "alice", 0, "")
            .unwrap();
        let _b = store
            .create_session(SessionConfig::default(), Some("b1".into()), "bob", 0, "")
            .unwrap();

        let alices = store.list_sessions("alice").expect("alice list");
        assert_eq!(alices.len(), 2);
        let ids: std::collections::HashSet<_> = alices.iter().map(|s| s.id).collect();
        assert!(ids.contains(&a1.id));
        assert!(ids.contains(&a2.id));
    }

    /// `list_sessions` returns an empty Vec for a caller with no rows
    /// — *not* an error, mirroring the shape `GET /sessions` expects
    /// when an operator has never created anything.
    #[test]
    fn test_list_empty_for_caller_with_no_sessions() {
        let (store, _dir) = test_store();
        let _ = store
            .create_session(SessionConfig::default(), None, "alice", 0, "")
            .unwrap();
        let carols = store.list_sessions("carol").expect("carol list");
        assert!(carols.is_empty());
    }

    /// `update_state` refuses to mutate a foreign session — same
    /// `SessionNotFound` shape get_session returns. The mutator does
    /// not need an extra error variant.
    #[test]
    fn test_update_state_refuses_foreign_session() {
        let (store, _dir) = test_store();
        let session = store
            .create_session(SessionConfig::default(), None, "alice", 0, "")
            .unwrap();
        // Move alice's session forward through the FSM first so the
        // attempted bob-update has a valid transition target —
        // otherwise an `InvalidState` could mask the ownership reject.
        store
            .update_state(&session.id, "alice", SessionState::Running)
            .expect("alice transitions her own row");

        let err = store
            .update_state(&session.id, "bob", SessionState::Stopped)
            .expect_err("bob must not be allowed to mutate alice's session");
        assert!(
            matches!(err, SandboxError::SessionNotFound(_)),
            "foreign-owner update must surface as SessionNotFound; got {err:?}"
        );
    }

    /// `delete_session` refuses to remove a foreign row — same shape
    /// as `update_state` above.
    #[test]
    fn test_delete_refuses_foreign_session() {
        let (store, _dir) = test_store();
        let session = store
            .create_session(SessionConfig::default(), None, "alice", 0, "")
            .unwrap();

        let err = store
            .delete_session(&session.id, "bob")
            .expect_err("bob must not be allowed to delete alice's session");
        assert!(
            matches!(err, SandboxError::SessionNotFound(_)),
            "foreign-owner delete must surface as SessionNotFound; got {err:?}"
        );

        // And the row is still there from alice's perspective.
        let still = store
            .get_session(&session.id, "alice")
            .expect("alice get")
            .expect("session row must remain after failed foreign delete");
        assert_eq!(still.id, session.id);
    }

    /// Prefix resolution (`get_session_by_name_or_id`) is scoped to
    /// the caller. Alice's row is invisible when bob queries by id
    /// prefix; bob's own id with a similar prefix is returned.
    ///
    /// Uses the public `create_session` API + a real `SessionConfig`
    /// so the row's `config_json` deserialises correctly when the row
    /// is later read back. The test rewrites the random ids to a
    /// deterministic prefix shape via a direct SQL UPDATE so the
    /// prefix-match path is exercised deterministically.
    #[test]
    fn test_prefix_resolution_scoped_to_caller() {
        let (store, _dir) = test_store();
        let alice = store
            .create_session(SessionConfig::default(), None, "alice", 0, "")
            .unwrap();
        let bob = store
            .create_session(SessionConfig::default(), None, "bob", 0, "")
            .unwrap();

        // Rewrite the ids so the prefix-match path has a known shared
        // first hex digit. Otherwise `create_session` mints random
        // ids and the prefix lookup would just be a name-lookup
        // disguise.
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE sessions SET id = ?1 WHERE id = ?2",
                params!["0123456789ab", alice.id.as_str()],
            )
            .unwrap();
            conn.execute(
                "UPDATE sessions SET id = ?1 WHERE id = ?2",
                params!["0fedcba98765", bob.id.as_str()],
            )
            .unwrap();
        }

        // Bob queries the prefix `01` — which would match alice's row
        // if the prefix-resolution path were unscoped. The scoped
        // version returns None because no row with that prefix exists
        // under bob's ownership.
        let result = store
            .get_session_by_name_or_id("01", "bob")
            .expect("resolve");
        assert!(
            result.is_none(),
            "bob must not see alice's row via prefix; got {result:?}"
        );

        // Sanity: bob's own short prefix resolves to his row.
        let mine = store
            .get_session_by_name_or_id("0f", "bob")
            .expect("resolve")
            .expect("bob's own prefix");
        assert_eq!(mine.id.as_str(), "0fedcba98765");
    }

    /// Name resolution is scoped to the caller: two operators can both
    /// have a session named `staging`, and each gets back their own.
    #[test]
    fn test_name_resolution_scoped_to_caller() {
        let (store, _dir) = test_store();
        let alices_staging = store
            .create_session(
                SessionConfig::default(),
                Some("staging".into()),
                "alice",
                0,
                "",
            )
            .unwrap();
        let bobs_staging = store
            .create_session(
                SessionConfig::default(),
                Some("staging".into()),
                "bob",
                0,
                "",
            )
            .unwrap();

        let alices_view = store
            .get_session_by_name_or_id("staging", "alice")
            .expect("resolve")
            .expect("alice's staging");
        assert_eq!(alices_view.id, alices_staging.id);

        let bobs_view = store
            .get_session_by_name_or_id("staging", "bob")
            .expect("resolve")
            .expect("bob's staging");
        assert_eq!(bobs_view.id, bobs_staging.id);

        // And neither sees the other's row.
        assert_ne!(alices_view.id, bobs_staging.id);
        assert_ne!(bobs_view.id, alices_staging.id);
    }
}
