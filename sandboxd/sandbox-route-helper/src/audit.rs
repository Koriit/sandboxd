//! Append-only JSON-Lines audit log for the route helper.
//!
//! One record per helper invocation, written before exit, on every
//! allowed-and-denied path. The shape is fixed by spec § 3.5:
//!
//! ```json
//! {"ts":"2026-05-11T14:23:09.123Z","decision":"allowed","caller":"alice","for_user":"alice","pool":"10.209.0.0/20","gateway_ip":"10.209.0.2","pid":12345}
//! {"ts":"2026-05-11T14:23:11.477Z","decision":"denied","reason":"pair-check failed","caller":"alice","for_user":"bob","pool":"10.210.0.0/20","gateway_ip":"10.210.0.2","pid":12346}
//! ```
//!
//! ## Write-failure asymmetry
//!
//! Spec § 3.5 distinguishes the two paths' tolerance for a failed write:
//!
//! - **Allow path** — log a structured stderr line and continue. The
//!   privilege has already been granted; an audit-log infrastructure
//!   failure (disk full, ENOSPC, missing parent dir) must not be a
//!   denial of service to session creation. Routing-path-availability
//!   wins.
//! - **Deny path** — log the same stderr line **and** exit `DENY_EXIT`
//!   (1). The deny itself was never in doubt (it happens before the log
//!   write); the escalation here surfaces the missing forensic record so
//!   the operator's investigation trail does not evaporate silently.
//!
//! Callers handle the asymmetry by inspecting [`AuditOutcome::Ok`] vs
//! [`AuditOutcome::WriteFailed`] from [`write_record`]; this module
//! intentionally does **not** call `exit()` itself — that lives in
//! `main.rs` next to the rest of the deny-exit shape so the contract is
//! grep-able in one place.

use std::path::PathBuf;

use serde_json::json;

/// Production audit-log path (today; daemon runs as operator).
///
/// Spec § 3.5 swings this to `/var/lib/sandbox/route-helper-audit.log`
/// in Spec 3 when the daemon moves to a dedicated `sandbox` user.
const DEFAULT_AUDIT_LOG_RELATIVE: &str = "sandboxd/route-helper-audit.log";

/// Env-var override for the audit-log path, honored **only** in
/// `test-env-override` builds. The production cap'd binary ignores it
/// — same privilege story as [`SANDBOX_USERS_CONF`](sandbox_core::users_conf::USERS_CONF_PATH_ENV):
/// a cap'd binary that honored an attacker-controlled env var to
/// redirect its audit log would let a local attacker hide forensic
/// records of their own attempts.
#[cfg(feature = "test-env-override")]
pub const SANDBOX_ROUTE_HELPER_AUDIT_LOG_ENV: &str = "SANDBOX_ROUTE_HELPER_AUDIT_LOG";

/// Resolve the audit-log path.
///
/// Resolution order:
/// 1. (test-env-override builds only) `SANDBOX_ROUTE_HELPER_AUDIT_LOG`
///    env var if set.
/// 2. `$XDG_RUNTIME_DIR/sandboxd/route-helper-audit.log`.
/// 3. `$HOME/.local/share/sandboxd/route-helper-audit.log`.
/// 4. `/tmp/sandboxd/route-helper-audit.log` (last-resort fallback for
///    containerised environments without HOME or XDG_RUNTIME_DIR).
pub fn audit_log_path() -> PathBuf {
    #[cfg(feature = "test-env-override")]
    if let Ok(p) = std::env::var(SANDBOX_ROUTE_HELPER_AUDIT_LOG_ENV) {
        return PathBuf::from(p);
    }
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join(DEFAULT_AUDIT_LOG_RELATIVE);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join(DEFAULT_AUDIT_LOG_RELATIVE);
    }
    PathBuf::from("/tmp").join(DEFAULT_AUDIT_LOG_RELATIVE)
}

/// One field captured for the `caller` / `for_user` audit objects per
/// spec § 3.5. The spec illustrates them as bare strings; we encode them
/// as strings on the wire (the typed shape inside the helper is
/// implementation choice).
#[derive(Clone, Copy)]
pub enum Decision<'a> {
    /// Allow path. No `reason` field is emitted.
    Allowed,
    /// Deny path. `reason` field is a short tag (e.g.
    /// `"pair-check failed"`, `"gateway-ip not in any subnet"`).
    Denied { reason: &'a str },
}

impl Decision<'_> {
    fn as_str(&self) -> &'static str {
        match self {
            Decision::Allowed => "allowed",
            Decision::Denied { .. } => "denied",
        }
    }
}

/// Fields for one audit record. Borrowed so the helper need not clone
/// strings just to log them.
pub struct AuditRecord<'a> {
    pub decision: Decision<'a>,
    pub caller: &'a str,
    pub for_user: &'a str,
    /// CIDR string (e.g. `"10.209.0.0/20"`). `None` when the gateway IP
    /// did not match any configured subnet (spec § 3.5 — `pool` is
    /// absent on `"gateway-ip not in any subnet"`).
    pub pool: Option<&'a str>,
    pub gateway_ip: &'a str,
    pub pid: i32,
}

/// Outcome of [`write_record`]. The deny-path escalation lives in the
/// caller (main.rs) — callers inspect this enum and decide.
pub enum AuditOutcome {
    /// Record was appended successfully.
    Ok,
    /// Open or write failed. The string carries the underlying I/O error
    /// for the caller to forward to stderr verbatim.
    WriteFailed(String),
}

/// Append one JSON-Lines record to `path`, creating the parent directory
/// and the file if they do not exist.
///
/// On success, returns [`AuditOutcome::Ok`]. On failure, returns
/// [`AuditOutcome::WriteFailed`] carrying the error string — callers
/// must surface it to stderr and apply the per-path asymmetry.
pub fn write_record(path: &std::path::Path, record: &AuditRecord<'_>) -> AuditOutcome {
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut obj = serde_json::Map::new();
    obj.insert("ts".to_string(), json!(ts));
    obj.insert("decision".to_string(), json!(record.decision.as_str()));
    if let Decision::Denied { reason } = record.decision {
        obj.insert("reason".to_string(), json!(reason));
    }
    obj.insert("caller".to_string(), json!(record.caller));
    obj.insert("for_user".to_string(), json!(record.for_user));
    if let Some(pool) = record.pool {
        obj.insert("pool".to_string(), json!(pool));
    }
    obj.insert("gateway_ip".to_string(), json!(record.gateway_ip));
    obj.insert("pid".to_string(), json!(record.pid));

    let line = match serde_json::to_string(&serde_json::Value::Object(obj)) {
        Ok(s) => s,
        Err(e) => return AuditOutcome::WriteFailed(format!("serialize audit record: {e}")),
    };

    // Create parent dir lazily — first-ever helper invocation on a host
    // will not have `$XDG_RUNTIME_DIR/sandboxd/` yet.
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return AuditOutcome::WriteFailed(format!(
                "create audit-log parent dir {}: {e}",
                parent.display()
            ));
        }
    }

    use std::io::Write;
    let mut f = match std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            return AuditOutcome::WriteFailed(format!("open {}: {e}", path.display()));
        }
    };
    if let Err(e) = writeln!(f, "{line}") {
        return AuditOutcome::WriteFailed(format!("write {}: {e}", path.display()));
    }
    AuditOutcome::Ok
}
