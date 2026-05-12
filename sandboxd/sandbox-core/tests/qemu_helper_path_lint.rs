//! Workspace-wide CI lints: the QEMU bridge helper's filesystem path
//! and the rootless-Docker enabler env var must not be referenced from
//! daemon source.
//!
//! Sandboxd no longer pins the `qemu-bridge-helper` install path. QEMU
//! resolves the helper via its compile-time `libexecdir` default
//! (different on Ubuntu/Debian vs RHEL/Fedora); we omit the parameter
//! entirely. The rootless-Docker code path that previously
//! substituted an nsenter wrapper for the real helper has been
//! deleted along with the `SANDBOX_BRIDGE_HELPER` env override that
//! pointed it at a custom binary for testing.
//!
//! These tests are line-based grep guards that walk the workspace's
//! `*/src/` trees and fail-loud if either token slips back in.
//! The Makefile (dev-mode install-time setuid target) is explicitly
//! out of scope — `QEMU_BRIDGE_HELPER_PATH` there is install
//! metadata, not daemon config. The tests below only scan source.
//!
//! Spec reference: daemon-productionization §§ 9.1-9.3 + § 11.5.

use std::fs;
use std::path::{Path, PathBuf};

/// Workspace root, computed from this test crate's `CARGO_MANIFEST_DIR`
/// (`sandbox-core/`) by going one level up.
fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .expect("sandbox-core has a parent (the workspace root)")
        .to_path_buf()
}

/// Recursively collect every `*.rs` file under the per-crate `src/`
/// directories named in `crates`. Symlinks and non-UTF-8 names are
/// silently skipped — the workspace contains neither.
fn rust_src_files(crates: &[&str]) -> Vec<PathBuf> {
    let root = workspace_root();
    let mut out = Vec::new();
    for c in crates {
        let dir = root.join(c).join("src");
        if dir.is_dir() {
            walk(&dir, &mut out);
        }
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name == "target" || name.starts_with('.') {
                    continue;
                }
            }
            walk(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Per-file allowlist of tokens that may legitimately appear (the
/// regression-test files themselves name the forbidden tokens inside
/// string literals so the assertions can pin them). Path matching is
/// suffix-based against the workspace-relative path so the test does
/// not couple to an absolute CARGO_MANIFEST_DIR.
fn is_self_referencing_test_file(rel_path: &str) -> bool {
    // The hermetic regression tests inside `lima.rs` and the
    // workspace-wide grep tests in this file name the forbidden
    // tokens inside `assert!` literals. They are not real call sites
    // and must be excluded.
    rel_path.ends_with("sandbox-core/src/lima.rs")
        || rel_path.ends_with("sandbox-core/tests/qemu_helper_path_lint.rs")
}

/// Per-test scan: returns the list of `(file, line_number, line)`
/// hits whose `path::workspace-relative-form` is not in the
/// self-referencing-test allowlist.
fn scan(files: &[PathBuf], needle: &str) -> Vec<(PathBuf, usize, String)> {
    let root = workspace_root();
    let mut hits = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(&root)
            .unwrap_or(f)
            .to_string_lossy()
            .into_owned();
        if is_self_referencing_test_file(&rel) {
            continue;
        }
        let content = match fs::read_to_string(f) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for (idx, line) in content.lines().enumerate() {
            if line.contains(needle) {
                hits.push((f.clone(), idx + 1, line.to_string()));
            }
        }
    }
    hits
}

/// `/usr/lib/qemu/qemu-bridge-helper` must not appear anywhere in
/// daemon source. QEMU resolves the helper via its compile-time
/// `libexecdir`; pinning the path defeats distro portability.
#[test]
fn grep_test_no_hardcoded_helper_path_in_source() {
    let files = rust_src_files(&[
        "sandbox-core",
        "sandboxd",
        "sandbox-cli",
        "sandbox-guest",
        "sandbox-route-helper",
        "sandbox-event-emitter",
        "sandbox-nft-allow-logger",
        "sandbox-nft-deny-logger",
    ]);
    let hits = scan(&files, "/usr/lib/qemu/qemu-bridge-helper");
    if !hits.is_empty() {
        let summary = hits
            .iter()
            .map(|(p, n, l)| format!("  {}:{n}: {l}", p.display()))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "Found {} hardcoded `/usr/lib/qemu/qemu-bridge-helper` reference(s) in source — \
             distro-portability requires deferring to QEMU's compile-time libexecdir default:\n{summary}",
            hits.len()
        );
    }
}

/// `SANDBOX_BRIDGE_HELPER` was the rootless-wrapper override; with
/// the rootless code path removed there is no remaining caller. The
/// env var must not reappear in source.
#[test]
fn grep_test_no_sandbox_bridge_helper_env_var() {
    let files = rust_src_files(&[
        "sandbox-core",
        "sandboxd",
        "sandbox-cli",
        "sandbox-guest",
        "sandbox-route-helper",
        "sandbox-event-emitter",
        "sandbox-nft-allow-logger",
        "sandbox-nft-deny-logger",
    ]);
    let hits = scan(&files, "SANDBOX_BRIDGE_HELPER");
    if !hits.is_empty() {
        let summary = hits
            .iter()
            .map(|(p, n, l)| format!("  {}:{n}: {l}", p.display()))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "Found {} `SANDBOX_BRIDGE_HELPER` reference(s) in source — the env var was the \
             rootless wrapper's override and has been retired:\n{summary}",
            hits.len()
        );
    }
}
