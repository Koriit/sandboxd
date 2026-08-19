//! Append-only JSON-Lines audit log for the route helper.
//!
//! At most one record per helper invocation, attempted before exit, on the
//! allow and deny branches of the standard host path. Three qualifications,
//! each of which is load-bearing:
//!
//! - **Not every path attempts one.** An argv parse failure — step 1 of the
//!   flow in `main` — has no caller/for-user pair to name and writes nothing.
//!   Neither does the `--vm-gateway-mode` path, on any outcome: inside the
//!   gateway VM the resolved path names nothing an operator collects, and
//!   `run_vm_gateway_mode` says what covers those invocations instead.
//! - **An attempt can fail.** [`write_record`] returns
//!   [`AuditOutcome::WriteFailed`] when the parent directory cannot be
//!   created, or the file cannot be opened or appended to. The decision never
//!   waits on the record — see the asymmetry below for what each path does
//!   with the failure.
//! - **The caller has a say in where it lands.** [`audit_log_path`] resolves
//!   through the caller's own `XDG_RUNTIME_DIR` / `HOME`, so a caller can
//!   aim its own record at a path whose write fails, or at one only it can
//!   read. What that does not change is the outcome: a deny still exits
//!   `DENY_EXIT` and still prints its reason to stderr. Read this log as the
//!   record of what a *cooperating* caller did, not as evidence about an
//!   uncooperative one.
//!
//! What is fixed is the field set and when each field appears. `ts`,
//! `decision`, `caller`, `for_user`, `gateway_ip` and `pid` are on every
//! record; `reason` appears on deny records only; `pool` appears only when one
//! was chosen before the record was written (see [`AuditRecord::pool`]).
//!
//! Key *order* is not part of that contract, and a consumer must parse the
//! object rather than match on position. [`write_record`] builds the object in
//! a hand-picked order — `ts`, `decision`, `reason`, `caller`, `for_user`,
//! `pool`, `gateway_ip`, `pid` — but `serde_json::Map` is a `BTreeMap` unless
//! the `preserve_order` feature is enabled, so what reaches the file is sorted
//! by key:
//!
//! ```json
//! {"caller":"alice","decision":"allowed","for_user":"alice","gateway_ip":"10.209.0.2","pid":12345,"pool":"10.209.0.0/20","ts":"2026-05-11T14:23:09.123Z"}
//! {"caller":"alice","decision":"denied","for_user":"bob","gateway_ip":"10.210.0.2","pid":12346,"pool":"10.210.0.0/20","reason":"pair-check failed","ts":"2026-05-11T14:23:11.477Z"}
//! ```
//!
//! ## Write-failure asymmetry
//!
//! Both paths continue past an audit-log write failure — neither blocks on
//! it, and neither changes its verdict because of it. What differs is the
//! exit each was already headed for, and why leaving it alone is right:
//!
//! - **Allow path** — log a structured stderr line and continue to exit `0`.
//!   The privilege has already been granted; an audit-log infrastructure
//!   failure (disk full, ENOSPC, missing parent dir) must not be a
//!   denial of service to session creation. Routing-path-availability
//!   wins.
//! - **Deny path** — log the same stderr line and continue to exit
//!   `DENY_EXIT` (1). The verdict was reached before `deny_with_audit` was
//!   called and nothing about the write can reach back and change it; the
//!   stderr line is there so the missing forensic record does not evaporate
//!   silently on the operator.
//!
//! Neither caller branches on [`write_record`]'s answer beyond reporting it:
//! `deny_with_audit` and `allow_audit` in `main.rs` both turn an
//! [`AuditOutcome::WriteFailed`] into the same stderr line and carry on. So
//! the asymmetry above is a property of those two functions — of the exit each
//! was already returning — rather than of anything in this module, and it is
//! not visible in the function they share (`emit_audit`), which has no branch
//! in it at all.
//!
//! This module intentionally does **not** call `exit()`; returning
//! [`AuditOutcome`] is what leaves every exit in `main.rs`.

use std::path::PathBuf;

use serde_json::json;

/// Production audit-log path (today; daemon runs as operator).
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
///
/// Steps 2 and 3 read the environment of whoever exec'd the helper, so the
/// destination is caller-influenced in production builds too — not only under
/// the test override. The module docs say what that does and does not mean
/// for the record's evidential weight.
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

/// The verdict a record carries: the helper allowed the route install, or it
/// denied it.
///
/// On the wire this is the `decision` field, `"allowed"` or `"denied"`. The
/// deny arm's reason tag is emitted as its own `reason` field rather than
/// folded into `decision`; an allow record has no such field at all, so a
/// consumer distinguishes them by presence and not by an empty string.
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
    /// CIDR string (e.g. `"10.209.0.0/20"`), or `None` when no pool had been
    /// chosen by the time the record was written.
    ///
    /// An absent `pool` is not a statement about the gateway IP. Six deny
    /// reasons write `None`, and only one of them concerns subnet matching:
    /// `gateway-ip not in any subnet`. The other five deny before the subnet
    /// lookup runs at all — `caller-uid-unresolvable`,
    /// `caller-uid-resolution-error`, `for-user-unresolvable`,
    /// `for-user-resolution-error`, `users-conf-load-failed`. A consumer
    /// treating absent-`pool` as "the gateway IP matched nothing" is wrong on
    /// five of the six; `reason` is the field that separates them.
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
