//! Build script for `sandbox-core`.
//!
//! Exposes the `sandbox-guest` crate's `Cargo.toml` `version` field to
//! the source as a compile-time env var, so
//! `sandbox-core::guest::SANDBOX_GUEST_VERSION` reflects the version of
//! the guest binary built in this workspace without manually mirroring
//! it. the documented contract calls for this so the daemon's `create_session` /
//! refresh paths stamp `sessions.guest_binary_version` with the
//! authoritative value.

use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set during build");
    let guest_manifest: PathBuf = [&manifest_dir, "..", "sandbox-guest", "Cargo.toml"]
        .iter()
        .collect();

    println!("cargo:rerun-if-changed={}", guest_manifest.display());

    let contents = fs::read_to_string(&guest_manifest)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", guest_manifest.display()));

    // Tiny ad-hoc parser: find the first `version = "..."` line under the
    // top-level `[package]` section. Avoids pulling in a TOML dependency
    // for one field.
    let mut in_package = false;
    let mut version: Option<String> = None;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if let Some(rest) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_package = rest.trim() == "package";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(rest) = line.strip_prefix("version") {
            let rest = rest.trim_start();
            if let Some(eq) = rest.strip_prefix('=') {
                let value = eq.trim();
                if let Some(stripped) = value.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                    version = Some(stripped.to_string());
                    break;
                }
            }
        }
    }

    let version = version.unwrap_or_else(|| {
        panic!(
            "could not find `version = \"...\"` under [package] in {}",
            guest_manifest.display()
        )
    });

    println!("cargo:rustc-env=SANDBOX_GUEST_VERSION={version}");
}
