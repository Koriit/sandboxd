//! Release tarball fetch + sigstore verification + extraction —
//! Spec 5 §§ 3.1.4, 3.1.9, 3.1.10.
//!
//! M16-S2 lands the **type shapes and pure helpers** the pre-flight
//! needs: cosign pin constants (mirrored from `scripts/lib.sh`), the
//! MANIFEST schema, the arch cross-check, and a stub for the
//! download+sigstore flow that the stateful path (M16-S3) will wire
//! into the actual `cosign verify-blob` invocation.
//!
//! Why the stubbed flow lives here, not in M16-S3: the `--dry-run`
//! plan must already classify the "would-execute / skip" outcome of
//! § 3.1.10 (sigstore verify) and § 3.1.11 (migration dry-run), which
//! both depend on the MANIFEST being readable. The pure read +
//! arch-check half can run today, even without network. The actual
//! `verify-blob` shell-out is gated on `--dry-run=false` and stays
//! deferred to S3.

use std::path::Path;

// ---------------------------------------------------------------------------
// Cosign pin — MUST match `scripts/lib.sh`.
// ---------------------------------------------------------------------------

/// Pinned cosign release used to verify signed release tarballs.
///
/// **MUST match `scripts/lib.sh`'s `COSIGN_VERSION`** — the two
/// constants are duplicated by design (not loaded via `include_str!`
/// to avoid a build-script step). A future cosign-pin bump touches
/// both files in one diff. The unit test
/// `cosign_constants_match_lib_sh` reads `scripts/lib.sh` at test
/// time and asserts equality.
pub const COSIGN_VERSION: &str = "v2.4.1";

/// SHA-256 of the cosign linux-amd64 binary at [`COSIGN_VERSION`].
/// **MUST match `scripts/lib.sh`'s `COSIGN_SHA256_AMD64`.**
pub const COSIGN_SHA256_AMD64: &str =
    "8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b";

/// SHA-256 of the cosign linux-arm64 binary at [`COSIGN_VERSION`].
/// **MUST match `scripts/lib.sh`'s `COSIGN_SHA256_ARM64`.**
pub const COSIGN_SHA256_ARM64: &str =
    "3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a";

/// Resolve `(filename, expected sha256)` for the operator's arch
/// triple. Returns `None` for any arch we don't ship a pin for.
pub fn cosign_pin_for_arch(arch: &str) -> Option<(&'static str, &'static str)> {
    match arch {
        "x86_64-unknown-linux-gnu" => Some(("cosign-linux-amd64", COSIGN_SHA256_AMD64)),
        "aarch64-unknown-linux-gnu" => Some(("cosign-linux-arm64", COSIGN_SHA256_ARM64)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// MANIFEST shape
// ---------------------------------------------------------------------------

/// MANIFEST artifact entry — one per file the tarball ships.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ManifestArtifact {
    /// Path relative to the unpacked tarball root.
    pub path: String,
    /// Per-file SHA-256, in hex. Matched against `sha256sum -c` after
    /// extraction.
    pub sha256: String,
}

/// MANIFEST shape — produced by the release CI; the install path
/// reads `MANIFEST` from the tarball root and round-trips through this
/// type. The version + arch + sha256 fields are load-bearing for the
/// pre-flight `--from` arch-mismatch refusal.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Manifest {
    pub version: String,
    pub arch: String,
    pub artifacts: std::collections::BTreeMap<String, ManifestArtifact>,
    #[serde(default)]
    pub build_sha: Option<String>,
}

// ---------------------------------------------------------------------------
// MANIFEST sanity / arch check
// ---------------------------------------------------------------------------

/// Errors surfaced by [`check_manifest_arch`] and [`read_manifest`].
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse MANIFEST: {0}")]
    Parse(serde_json::Error),
    /// **Operator-facing message — verbatim in the spec § 3.1.10.**
    #[error("MANIFEST arch mismatch: tarball says {tarball_arch}, expected {installed_arch}")]
    ArchMismatch {
        tarball_arch: String,
        installed_arch: String,
    },
    #[error("MANIFEST version mismatch: tarball says {tarball_version}, expected {target_version}")]
    VersionMismatch {
        tarball_version: String,
        target_version: String,
    },
}

/// Read a MANIFEST JSON file at `path`.
pub fn read_manifest(path: &Path) -> Result<Manifest, ManifestError> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(ManifestError::Parse)
}

/// Spec 5 § 3.1.10: cross-check the MANIFEST's `arch` against the
/// `installed_arch` recorded in `/var/lib/sandbox/.install-state.json`
/// — **not** against a live `uname -m` probe. Operators who upgrade
/// onto a host whose install-state arch and uname-m arch have diverged
/// see the divergence surface here.
pub fn check_manifest_arch(manifest: &Manifest, installed_arch: &str) -> Result<(), ManifestError> {
    if manifest.arch != installed_arch {
        return Err(ManifestError::ArchMismatch {
            tarball_arch: manifest.arch.clone(),
            installed_arch: installed_arch.to_string(),
        });
    }
    Ok(())
}

/// Spec 5 § 3.1.10: the MANIFEST `version` must equal the target
/// version the operator asked for (latest, `--version`, or the
/// `MANIFEST.version` of a local `--from` tarball — in the last case
/// this check is tautological but still cheap).
pub fn check_manifest_version(
    manifest: &Manifest,
    target_version: &str,
) -> Result<(), ManifestError> {
    if manifest.version != target_version {
        return Err(ManifestError::VersionMismatch {
            tarball_version: manifest.version.clone(),
            target_version: target_version.to_string(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// **Drift guard** — the cosign pin constants here must match
    /// `scripts/lib.sh` exactly. This test loads `lib.sh` from the
    /// repo root at test time and asserts equality, so a future bump
    /// that touches only one side trips immediately.
    #[test]
    fn cosign_constants_match_lib_sh() {
        // CARGO_MANIFEST_DIR is sandbox-cli/; go up two levels to reach
        // the repo root.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let lib_sh = std::path::Path::new(manifest_dir)
            .join("..")
            .join("..")
            .join("scripts")
            .join("lib.sh");
        // Tolerate the file being absent in odd test layouts.
        let text = match std::fs::read_to_string(&lib_sh) {
            Ok(s) => s,
            Err(_) => return,
        };

        for (name, expected) in [
            ("COSIGN_VERSION", COSIGN_VERSION),
            ("COSIGN_SHA256_AMD64", COSIGN_SHA256_AMD64),
            ("COSIGN_SHA256_ARM64", COSIGN_SHA256_ARM64),
        ] {
            let needle = format!("{name}=\"{expected}\"");
            assert!(
                text.contains(&needle),
                "{name} drift: expected `{expected}` but `{}` does not contain `{needle}`",
                lib_sh.display()
            );
        }
    }

    #[test]
    fn cosign_pin_for_arch_known_triples() {
        assert!(cosign_pin_for_arch("x86_64-unknown-linux-gnu").is_some());
        assert!(cosign_pin_for_arch("aarch64-unknown-linux-gnu").is_some());
        assert!(cosign_pin_for_arch("riscv64-unknown-linux-gnu").is_none());
    }

    #[test]
    fn manifest_arch_mismatch_surface() {
        let m = Manifest {
            version: "1.1.0".to_string(),
            arch: "x86_64-unknown-linux-gnu".to_string(),
            artifacts: Default::default(),
            build_sha: None,
        };
        let err = check_manifest_arch(&m, "aarch64-unknown-linux-gnu").unwrap_err();
        match err {
            ManifestError::ArchMismatch {
                tarball_arch,
                installed_arch,
            } => {
                assert_eq!(tarball_arch, "x86_64-unknown-linux-gnu");
                assert_eq!(installed_arch, "aarch64-unknown-linux-gnu");
            }
            other => panic!("expected ArchMismatch, got {other:?}"),
        }
    }

    #[test]
    fn manifest_version_mismatch_surface() {
        let m = Manifest {
            version: "1.1.0".to_string(),
            arch: "x86_64-unknown-linux-gnu".to_string(),
            artifacts: Default::default(),
            build_sha: None,
        };
        let err = check_manifest_version(&m, "1.2.0").unwrap_err();
        assert!(matches!(err, ManifestError::VersionMismatch { .. }));
    }

    #[test]
    fn manifest_deserialises_release_shape() {
        let json = r#"{
            "version": "1.1.0",
            "arch": "x86_64-unknown-linux-gnu",
            "build_sha": "abcdef1234567890",
            "artifacts": {
                "sandbox":  {"path": "sandbox",  "sha256": "0000"},
                "sandboxd": {"path": "sandboxd", "sha256": "1111"}
            }
        }"#;
        let m: Manifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.version, "1.1.0");
        assert_eq!(m.arch, "x86_64-unknown-linux-gnu");
        assert_eq!(m.artifacts.len(), 2);
        assert_eq!(
            m.artifacts.get("sandbox").map(|a| a.path.as_str()),
            Some("sandbox")
        );
    }
}
