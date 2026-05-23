//! Static-analysis guard for `SessionStore::update_state_reconcile`.
//!
//! The method is the daemon's escape hatch for moving a session row
//! into a target state **without** the storage-boundary per-caller
//! filter. Reconcilers, error/cleanup branches, and startup-time fixups
//! need it; HTTP request handlers must **never** call it — they have an
//! `OperatorIdentity` in scope and must go through
//! [`SessionStore::update_state`] so the per-caller filter rejects a
//! foreign session id as `SessionNotFound`.
//!
//! A hermetic test greps the workspace source tree for every
//! `update_state_reconcile` call and asserts the resulting set of
//! `<file>:<enclosing-function>` pairs is **exactly** the allow-list
//! pinned below. Both directions are caught:
//!
//! - A new caller added without updating `ALLOW_LIST` fails the test
//!   ("a request handler accidentally bypassed the filter").
//! - A listed caller removed without updating `ALLOW_LIST` also fails
//!   ("the allow-list drifted away from the code").
//!
//! The walk is line-based string matching — no Rust parser — because
//! the method name is distinctive and the false-positive surface is
//! negligible. A trailing `(` is required so identifier prefixes
//! (`update_state_reconcile_foo`) cannot match by accident.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Authorized `<workspace-relative-path>:<enclosing-fn>` pairs.
///
/// Mirrors the doc-comment on `SessionStore::update_state_reconcile`.
/// Editing this list is a code review concern — adding a new entry
/// means "this is a daemon-internal site, not a request handler" and
/// requires an explicit rationale in the PR.
const ALLOW_LIST: &[&str] = &[
    // Reconciler block inside the list-sessions handler: refreshes
    // every visible row's state against the live runtime *before*
    // serialising. Walks rows already filtered by `list_sessions`'
    // per-caller scope, so the reconcile write is back-stamping
    // observed state, not bypassing authorization.
    "sandboxd/src/main.rs:list_sessions",
    // Same shape as above, but for the single-session GET handler.
    "sandboxd/src/main.rs:get_session",
    // Background reconciler that walks every session row regardless
    // of owner and reconciles persisted state against runtime state.
    "sandboxd/src/main.rs:reconcile",
];

/// Paths excluded from the call-site scan. The crate-root file
/// containing the method *definition* (`store.rs`) is excluded —
/// every occurrence inside that file is metadata (signature,
/// doc-comment, the method body), not a call site. The allow-list
/// test file itself is excluded for the same reason (it names the
/// method in prose and in the `ALLOW_LIST` strings).
///
/// `/tests/` is **not** blanket-excluded: no test today calls
/// `update_state_reconcile`, and the scan should fail loudly the
/// first time one is added so the call site can be reviewed
/// (test-side callers either belong in `ALLOW_LIST` with a
/// rationale or should be rewritten to use `update_state`).
fn is_excluded(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains("/target/")
        || s.contains("/sandbox-core/src/store.rs")
        || s.contains("/sandbox-core/tests/update_state_reconcile_allow_list.rs")
}

/// Walk `dir` recursively, returning every `*.rs` file. Symlinks and
/// non-UTF-8 names are silently skipped — the workspace contains
/// neither so this is correct in practice.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip target/ and any hidden directories outright; the
            // workspace tree is small enough that recursing into
            // every Cargo workspace member is fine otherwise.
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name == "target" || name.starts_with('.') {
                    continue;
                }
            }
            rust_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Workspace root, computed from this test crate's `CARGO_MANIFEST_DIR`
/// (`sandbox-core/`) by going one level up.
fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .expect("sandbox-core has a parent (the workspace root)")
        .to_path_buf()
}

/// Locate the enclosing `fn` or `async fn` name for `line_idx` in
/// `lines`. Returns `None` if no `fn` precedes the line (file-level
/// statement, macro body, etc.) — the test treats that case as a hard
/// error because every call site we care about lives inside a named
/// function.
fn enclosing_fn(lines: &[&str], line_idx: usize) -> Option<String> {
    for line in lines[..=line_idx].iter().rev() {
        // Match `fn foo(` and `async fn foo(` and `pub fn foo(` etc.
        // We do not anchor at column 0 because indented `fn` (impl
        // blocks, mod blocks) is the norm.
        if let Some(idx) = line.find("fn ") {
            // Filter out `&fn` / `dyn fn` / `extern fn` false hits —
            // the prefix character before `fn ` must be whitespace or
            // start-of-line. The `find` we just did is on the first
            // `fn `, but if a comment line says `// dyn fn foo` we
            // still match. Tolerable: the rest of the parser will
            // either find a real fn earlier or fail at the bracket
            // search below.
            let before = &line[..idx];
            let is_decl = before.is_empty()
                || before.ends_with(' ')
                || before.ends_with('\t')
                || before == "pub "
                || before.ends_with("pub ")
                || before.ends_with("async ");
            if !is_decl {
                continue;
            }
            let after = &line[idx + 3..];
            // The function name runs up to the first `(`, `<`, or
            // whitespace. We accept identifier characters: ASCII
            // alphanumeric + underscore.
            let name: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

/// Build the discovered `<rel-path>:<fn-name>` set for `update_state_reconcile(`.
fn discovered_call_sites() -> BTreeSet<String> {
    let root = workspace_root();
    let mut files = Vec::new();
    rust_files(&root, &mut files);

    let mut sites = BTreeSet::new();
    for path in files {
        if is_excluded(&path) {
            continue;
        }
        let content = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            if !line.contains("update_state_reconcile(") {
                continue;
            }
            // Skip rustdoc / comment lines so the doc-comment on the
            // method definition (or this test's doc-comment) does not
            // pollute the discovered set.
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            let fn_name = enclosing_fn(&lines, idx).unwrap_or_else(|| {
                panic!(
                    "no enclosing fn found for update_state_reconcile call at \
                     {}:{}",
                    path.display(),
                    idx + 1
                )
            });
            let rel = path.strip_prefix(&root).unwrap_or(&path);
            sites.insert(format!("{}:{}", rel.display(), fn_name));
        }
    }
    sites
}

/// Every caller of `update_state_reconcile` must appear in `ALLOW_LIST`
/// — and every entry in `ALLOW_LIST` must correspond to a real caller.
/// Both directions catch drift.
#[test]
fn test_update_state_reconcile_caller_whitelist() {
    let discovered = discovered_call_sites();
    let allow: BTreeSet<String> = ALLOW_LIST.iter().map(|s| (*s).to_string()).collect();

    let unexpected: Vec<&String> = discovered.difference(&allow).collect();
    let missing: Vec<&String> = allow.difference(&discovered).collect();

    let mut msg = String::new();
    if !unexpected.is_empty() {
        msg.push_str(
            "Unexpected `update_state_reconcile` call site(s) — these bypass \
             the per-caller filter and must either be moved to \
             `update_state` (which enforces ownership) or added to the \
             allow-list with a rationale comment:\n",
        );
        for site in &unexpected {
            msg.push_str("  + ");
            msg.push_str(site);
            msg.push('\n');
        }
    }
    if !missing.is_empty() {
        msg.push_str(
            "Allow-list entries with no matching call site — the code drifted \
             away from this list and the entry should be removed:\n",
        );
        for site in &missing {
            msg.push_str("  - ");
            msg.push_str(site);
            msg.push('\n');
        }
    }
    assert!(msg.is_empty(), "{msg}");
}

/// Belt-and-suspenders against the "developer adds a *new* handler
/// that calls `update_state_reconcile`" foot-gun. Asserts no
/// **non-allow-listed** caller's enclosing function carries an axum
/// `Extension<OperatorIdentity>` extractor within ±10 lines of the
/// `fn` declaration.
///
/// Two existing allow-listed callers (`list_sessions` / `get_session`)
/// legitimately carry the extractor: they run a reconciler block
/// inside the read handler — the caller-scoped filter is honoured by
/// the *list* step, and the reconcile is a back-stamp on observed
/// state, not an authorization gate. Anything **else** carrying the
/// extractor is a foot-gun (a freshly-introduced handler with the
/// extractor in scope that bypasses the per-caller filter), and that
/// is what this test catches.
#[test]
fn update_state_reconcile_not_called_from_request_handlers() {
    let allow: BTreeSet<String> = ALLOW_LIST.iter().map(|s| (*s).to_string()).collect();
    let root = workspace_root();
    let mut files = Vec::new();
    rust_files(&root, &mut files);

    for path in files {
        if is_excluded(&path) {
            continue;
        }
        let content = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            if !line.contains("update_state_reconcile(") {
                continue;
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            // Walk backwards to find the `fn` declaration line.
            let mut decl_idx: Option<usize> = None;
            for j in (0..=idx).rev() {
                if lines[j].contains("fn ") {
                    decl_idx = Some(j);
                    break;
                }
            }
            let decl_idx = match decl_idx {
                Some(i) => i,
                None => continue,
            };
            // Skip allow-listed call sites — the test above (the
            // primary, mandatory one) already pins them. The
            // secondary check is only meaningful for *new* call
            // sites that have not been added to `ALLOW_LIST` yet.
            let fn_name = enclosing_fn(&lines, idx).unwrap_or_default();
            let rel = path.strip_prefix(&root).unwrap_or(&path);
            let site_key = format!("{}:{}", rel.display(), fn_name);
            if allow.contains(&site_key) {
                continue;
            }
            // Look at the next 10 lines after the `fn` declaration —
            // axum extractors are usually parameter-1 or 2.
            let end = (decl_idx + 10).min(lines.len());
            let signature_window = lines[decl_idx..end].join("\n");
            assert!(
                !signature_window.contains("Extension<OperatorIdentity>"),
                "update_state_reconcile must not be called from a request \
                 handler — the enclosing function at {}:{} carries an \
                 `Extension<OperatorIdentity>` extractor, which is the \
                 signature axum uses for an HTTP handler that has a \
                 caller identity in scope. Use `update_state(.., \
                 caller_username, ..)` instead.",
                path.display(),
                decl_idx + 1,
            );
        }
    }
}
