//! Release tarball fetch + sigstore verification + extraction.
//!
//! Three responsibilities:
//!
//! 1. **Cosign pin** — versioned constants mirrored from
//!    `scripts/lib.sh`. A unit test reads `lib.sh` at test time and
//!    asserts the two sides match; a future cosign bump must touch
//!    both files in lockstep.
//! 2. **MANIFEST parse + arch / version cross-check** — the
//!    operator-facing "tarball doesn't match installed arch" refusal
//!    surfaces here, before any state mutation.
//! 3. **Tarball extraction + latest-version resolution** — when an
//!    operator runs `sandbox update --from <tarball.tar.gz>` we `tar
//!    -xzf` into a staging directory whose layout matches install.sh's
//!    `STAGE` (the directory that holds `bin/`, `images/`,
//!    `systemd/`, `MANIFEST`). When no `--from` is passed we resolve
//!    the latest tag from the GitHub Releases API (`curl
//!    https://api.github.com/repos/Koriit/sandboxd/releases/latest`).

use std::path::{Path, PathBuf};
use std::process::Command;

use ring::digest;

// ---------------------------------------------------------------------------
// Cosign / sigstore paths
// ---------------------------------------------------------------------------

/// On-disk location of the `cosign` binary used for `verify-blob`.
/// install.sh's `cosign_bootstrap` step is the canonical
/// installer; `sandbox update` reuses the result. If the file is missing
/// the update flow refuses with [`FetchError::CosignNotFound`] pointing
/// the operator at the install docs — bootstrapping cosign from the
/// update flow is deliberately out of scope.
pub const COSIGN_BIN_PATH: &str = "/usr/local/bin/cosign";

/// Fulcio certificate-identity regexp matching tarballs signed by the
/// official release workflow. **MUST stay byte-identical to install.sh's
/// `sigstore_verify`** (`scripts/install.sh`) — divergence would make
/// either side accept tarballs the other refuses.
pub const COSIGN_CERT_IDENTITY_REGEXP: &str =
    r"^https://github\.com/Koriit/sandboxd/\.github/workflows/release\.yml@";

/// OIDC issuer matching the GitHub Actions workflow that signs official
/// release tarballs. **MUST stay byte-identical to install.sh's
/// `sigstore_verify`.**
pub const COSIGN_CERT_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

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
    /// **Operator-facing message — verbatim; must not be changed.**
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

// ---------------------------------------------------------------------------
// Sigstore verification + per-file digest check
// ---------------------------------------------------------------------------

/// Errors surfaced by [`verify_signature`] and [`verify_artifact_digests`].
/// Kept distinct from [`ManifestError`] because these are the trust-chain
/// refusals — the operator-visible message at the call site needs to make
/// the security implication explicit.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// `/usr/local/bin/cosign` is absent. Surfaced when the operator
    /// never ran install.sh on this host, or has uninstalled cosign
    /// out-of-band. The update flow does not bootstrap cosign — that is
    /// install.sh's responsibility (separation of
    /// concerns).
    #[error(
        "cosign binary not found at {path} — \
         run install.sh once on this host first (it stages the pinned cosign), \
         or stage it manually under {path}"
    )]
    CosignNotFound { path: String },
    /// Sibling `<tarball>.sigstore` is missing and no `--cosign-bundle`
    /// was passed. Surfaced before the cosign subprocess is even
    /// invoked.
    #[error(
        "no cosign bundle: pass --cosign-bundle or place a `<tarball>.sigstore` \
         file next to the release tarball"
    )]
    BundleNotFound { tarball: String },
    /// `cosign verify-blob` returned a non-zero exit status. Stderr is
    /// captured verbatim so the operator can copy-paste it into a bug
    /// report.
    #[error("sigstore verification failed: {stderr}")]
    SignatureVerifyFailed { stderr: String },
    /// A file unpacked from the tarball hashed to bytes that do not
    /// match the value recorded in MANIFEST. Surfaces before any
    /// extracted artefact is installed.
    #[error("MANIFEST artefact digest mismatch for {path}: expected {expected}, got {got}")]
    ArtifactDigestMismatch {
        path: String,
        expected: String,
        got: String,
    },
}

/// Resolve the cosign bundle path that pairs with `tarball`. If
/// `bundle_override` is `Some` (operator passed `--cosign-bundle`), that
/// wins. Otherwise we look for `<tarball>.sigstore` as a sibling — same
/// convention install.sh uses.
fn resolve_bundle_path(
    tarball: &Path,
    bundle_override: Option<&Path>,
) -> Result<PathBuf, FetchError> {
    if let Some(b) = bundle_override {
        if !b.exists() {
            return Err(FetchError::BundleNotFound {
                tarball: tarball.display().to_string(),
            });
        }
        return Ok(b.to_path_buf());
    }
    let sibling = {
        let mut s = tarball.as_os_str().to_owned();
        s.push(".sigstore");
        PathBuf::from(s)
    };
    if sibling.exists() {
        return Ok(sibling);
    }
    Err(FetchError::BundleNotFound {
        tarball: tarball.display().to_string(),
    })
}

/// Invoke `cosign verify-blob` against the release
/// tarball before any extraction. Mirrors install.sh's `sigstore_verify`
/// byte-for-byte on the flags so a tarball that install.sh accepts is
/// also accepted here (and vice versa).
///
/// Pre-conditions:
/// * `/usr/local/bin/cosign` exists. The update flow does not bootstrap
///   cosign — operators get cosign by running install.sh once. Surfaces
///   [`FetchError::CosignNotFound`] otherwise.
/// * A signature bundle is locatable — either passed as `bundle` or
///   found as `<tarball>.sigstore` sibling.
///
/// On success the operator's tarball is cryptographically attested to
/// have come from the official release workflow.
pub fn verify_signature(tarball: &Path, bundle: Option<&Path>) -> Result<(), FetchError> {
    let cosign = Path::new(COSIGN_BIN_PATH);
    if !cosign.exists() {
        return Err(FetchError::CosignNotFound {
            path: COSIGN_BIN_PATH.to_string(),
        });
    }
    let bundle_path = resolve_bundle_path(tarball, bundle)?;
    let mut cmd = Command::new(COSIGN_BIN_PATH);
    cmd.arg("verify-blob")
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--certificate-identity-regexp")
        .arg(COSIGN_CERT_IDENTITY_REGEXP)
        .arg("--certificate-oidc-issuer")
        .arg(COSIGN_CERT_OIDC_ISSUER);

    // Test-only trust-material redirect, gated behind the
    // `test-env-override` Cargo feature so the env-var name strings
    // never appear in a release binary. The install-e2e harness builds
    // `sandbox-cli` with `--features test-env-override` and signs its
    // local tarball against an in-tree Sigstore stack; the four
    // SANDBOX_UPDATE_TEST_* env vars below let the harness substitute
    // the trust roots so the real cosign verify-blob code path is
    // exercised end-to-end against locally-signed material.
    //
    // Production release builds compile this block out entirely — an
    // attacker who controls the daemon's process environment cannot
    // silently substitute the cryptographic trust root, because the
    // env-var reads do not exist in the binary. Mirrors the pattern on
    // `sandbox-core`'s `test-env-override` feature (route-helper
    // users.conf redirect) and the daemon's gateway/Lima test
    // overrides.
    #[cfg(feature = "test-env-override")]
    {
        if let Ok(path) = std::env::var("SANDBOX_UPDATE_TEST_FULCIO_ROOT")
            && !path.is_empty()
        {
            cmd.arg("--certificate-chain").arg(&path);
        }
        if let Ok(url) = std::env::var("SANDBOX_UPDATE_TEST_REKOR_URL")
            && !url.is_empty()
        {
            cmd.arg("--rekor-url").arg(&url);
        }
        // cosign reads SIGSTORE_REKOR_PUBLIC_KEY /
        // SIGSTORE_CT_LOG_PUBLIC_KEY_FILE directly from the environment;
        // replant them under cosign's name when the harness supplied
        // them. Empty strings are treated as unset to keep the no-op
        // default tight.
        if let Ok(path) = std::env::var("SANDBOX_UPDATE_TEST_REKOR_PUBLIC_KEY")
            && !path.is_empty()
        {
            cmd.env("SIGSTORE_REKOR_PUBLIC_KEY", path);
        }
        if let Ok(path) = std::env::var("SANDBOX_UPDATE_TEST_CT_LOG_PUBLIC_KEY")
            && !path.is_empty()
        {
            cmd.env("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", path);
        }
    }

    let out = cmd.arg(tarball).output()?;
    if !out.status.success() {
        return Err(FetchError::SignatureVerifyFailed {
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(())
}

/// After the tarball is extracted, every entry in
/// `manifest.artifacts` must hash-match its on-disk file under
/// `stage.stage_dir`. Mirrors install.sh's `sha256sum -c` step. The
/// trust chain is `cosign(tarball) → manifest(tarball-bytes) → sha256(file
/// vs manifest)`; this function pins the third link.
pub fn verify_artifact_digests(stage: &StagedTarball) -> Result<(), FetchError> {
    for (_key, entry) in stage.manifest.artifacts.iter() {
        let file_path = stage.stage_dir.join(&entry.path);
        let got = sha256_hex_of_file(&file_path)?;
        if !got.eq_ignore_ascii_case(&entry.sha256) {
            return Err(FetchError::ArtifactDigestMismatch {
                path: entry.path.clone(),
                expected: entry.sha256.clone(),
                got,
            });
        }
    }
    Ok(())
}

/// Stream-hash a file with SHA-256 and return the hex digest. Reuses the
/// `ring` crate already pulled in by `update::backup` for the backup-set
/// manifest hashes; not factored to a shared helper because that helper
/// is privately-typed against `BackupError` and a cross-module
/// dependency would couple two otherwise-independent error surfaces.
fn sha256_hex_of_file(path: &Path) -> Result<String, FetchError> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut ctx = digest::Context::new(&digest::SHA256);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let bytes = ctx.finish();
    let mut s = String::with_capacity(bytes.as_ref().len() * 2);
    const HEX: &[u8] = b"0123456789abcdef";
    for b in bytes.as_ref() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    Ok(s)
}

/// Read a MANIFEST JSON file at `path`.
pub fn read_manifest(path: &Path) -> Result<Manifest, ManifestError> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(ManifestError::Parse)
}

/// Cross-check the MANIFEST's `arch` against the
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

/// The MANIFEST `version` must equal the target
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
// Tarball extraction
// ---------------------------------------------------------------------------

/// The staged-tarball layout. Mirrors install.sh's `STAGE` shape so
/// the downstream consumers (`docker load`, binary install, systemd
/// unit copy) can use the same relative paths.
#[derive(Debug, Clone)]
pub struct StagedTarball {
    /// The staging root: `<tmpdir>/sandboxd-<version>-<arch>/`.
    pub stage_dir: PathBuf,
    /// Parsed MANIFEST at `<stage>/MANIFEST`.
    pub manifest: Manifest,
}

impl StagedTarball {
    /// `<stage>/bin/sandboxd`.
    pub fn sandboxd_bin(&self) -> PathBuf {
        self.stage_dir.join("bin/sandboxd")
    }
    /// `<stage>/bin/sandbox`.
    pub fn sandbox_bin(&self) -> PathBuf {
        self.stage_dir.join("bin/sandbox")
    }
    /// `<stage>/bin/sandbox-route-helper`.
    pub fn route_helper_bin(&self) -> PathBuf {
        self.stage_dir.join("bin/sandbox-route-helper")
    }
    /// `<stage>/bin/sandbox-guest`. The tarball uses a flat `bin/`
    /// layout; install.sh repoints to `/usr/local/libexec/sandboxd/`
    /// when laying it down on the host.
    pub fn guest_bin(&self) -> PathBuf {
        self.stage_dir.join("bin/sandbox-guest")
    }
    /// `<stage>/systemd/sandboxd.service`.
    pub fn systemd_unit(&self) -> PathBuf {
        self.stage_dir.join("systemd/sandboxd.service")
    }
    /// `<stage>/images/sandbox-gateway-<version>.tar`.
    pub fn gateway_image_tar(&self) -> PathBuf {
        self.stage_dir.join(format!(
            "images/sandbox-gateway-{}.tar",
            self.manifest.version
        ))
    }
}

/// Extract a release tarball into `dest_dir` and return the staged
/// tree's root + parsed MANIFEST. Mirrors install.sh's
/// `extract_tarball` shape: `tar -xzf <tarball> -C <dest>` produces a
/// single top-level directory `sandboxd-<version>-<arch>/` containing
/// `bin/`, `systemd/`, `images/`, `MANIFEST`.
///
/// Pre-flight has already read the MANIFEST via [`read_manifest`]
/// against the *embedded* file inside the tarball (via `tar -O`); this
/// function re-reads it from the unpacked directory and is the
/// authoritative source for the artifact paths.
pub fn extract_tarball(tarball: &Path, dest_dir: &Path) -> Result<StagedTarball, ManifestError> {
    std::fs::create_dir_all(dest_dir)?;
    let status = Command::new("tar")
        .args(["-xzf", tarball.to_str().unwrap(), "-C"])
        .arg(dest_dir)
        .output()?;
    if !status.status.success() {
        return Err(ManifestError::Io(std::io::Error::other(format!(
            "tar -xzf {} failed (exit {:?}): {}",
            tarball.display(),
            status.status.code(),
            String::from_utf8_lossy(&status.stderr).trim()
        ))));
    }
    // Find the staged directory: it's the single subdirectory of dest
    // matching `sandboxd-*-*-linux-*`. We pick the first entry — there
    // is exactly one in a well-formed release tarball.
    let mut stage_dir = None;
    for entry in std::fs::read_dir(dest_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir()
            && path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.starts_with("sandboxd-"))
                .unwrap_or(false)
        {
            stage_dir = Some(path);
            break;
        }
    }
    let stage_dir = stage_dir.ok_or_else(|| {
        ManifestError::Io(std::io::Error::other(
            "extracted tarball did not contain a top-level sandboxd-*-* directory",
        ))
    })?;
    let manifest = read_manifest(&stage_dir.join("MANIFEST"))?;
    Ok(StagedTarball {
        stage_dir,
        manifest,
    })
}

/// Read the MANIFEST out of a tarball without extracting it. Used by
/// the pre-flight to surface arch / version mismatches against the
/// installed state **before** the stateful phase touches anything on
/// disk. Mirrors install.sh's `tar -O -xf "$FROM" --wildcards
/// '*/MANIFEST'` pattern.
pub fn peek_manifest_in_tarball(tarball: &Path) -> Result<Manifest, ManifestError> {
    let out = Command::new("tar")
        .args([
            "-O",
            "-xzf",
            tarball.to_str().unwrap(),
            "--wildcards",
            "*/MANIFEST",
        ])
        .output()?;
    if !out.status.success() {
        return Err(ManifestError::Io(std::io::Error::other(format!(
            "tar -O -xzf {} '*/MANIFEST' failed (exit {:?}): {}",
            tarball.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))));
    }
    serde_json::from_slice(&out.stdout).map_err(ManifestError::Parse)
}

// ---------------------------------------------------------------------------
// Latest-version resolution
// ---------------------------------------------------------------------------

/// GitHub Releases API endpoint for the latest tag. Used by the
/// version-resolution path when the operator passes `--version
/// latest` (the default) and no `--from`.
pub const GH_RELEASES_LATEST_URL: &str =
    "https://api.github.com/repos/Koriit/sandboxd/releases/latest";

/// Resolve the latest released version via the GitHub Releases API.
/// Shells out to `curl` (already a prereq) and `jq` (also a prereq) so
/// we don't pull in a JSON-over-HTTPS Rust dependency just for this
/// one call. Returns the bare version string (e.g. `"1.1.0"`) without
/// the leading `v`.
///
/// On any network / parse failure returns an `Err(String)` — the
/// caller surfaces the message to stderr and falls back to the
/// hard-refusal path. There is no silent fallback because the operator
/// needs to know they're not actually on `latest`.
pub fn resolve_latest_version_via_github() -> Result<String, String> {
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "--retry",
            "3",
            "--retry-delay",
            "2",
            "-H",
            "Accept: application/vnd.github+json",
            GH_RELEASES_LATEST_URL,
        ])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl {GH_RELEASES_LATEST_URL} failed (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    // The release object's `tag_name` is `v<version>` per the
    // repo's release-tag convention. Strip the leading `v`.
    #[derive(serde::Deserialize)]
    struct Release {
        tag_name: String,
    }
    let release: Release = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("parse GitHub release JSON: {e}"))?;
    let tag = release.tag_name;
    let bare = tag.strip_prefix('v').unwrap_or(&tag);
    if bare.is_empty() {
        return Err(format!(
            "GitHub release endpoint returned empty tag_name: {tag:?}"
        ));
    }
    Ok(bare.to_string())
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

    /// Round-trip: synthesise a fake release tarball under a tempdir,
    /// extract it, and verify the [`StagedTarball`] helper paths land
    /// in the right place. Uses GNU tar (a build-time prereq).
    #[test]
    fn extract_tarball_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let stage_name = "sandboxd-9.9.9-x86_64-unknown-linux-gnu";
        let stage_dir = tmp.path().join(stage_name);
        std::fs::create_dir_all(stage_dir.join("bin")).unwrap();
        std::fs::create_dir_all(stage_dir.join("systemd")).unwrap();
        std::fs::create_dir_all(stage_dir.join("images")).unwrap();
        std::fs::write(stage_dir.join("bin/sandboxd"), b"fake-sandboxd").unwrap();
        std::fs::write(stage_dir.join("bin/sandbox"), b"fake-sandbox").unwrap();
        std::fs::write(stage_dir.join("bin/sandbox-route-helper"), b"fake-rh").unwrap();
        std::fs::write(stage_dir.join("bin/sandbox-guest"), b"fake-guest").unwrap();
        std::fs::write(stage_dir.join("systemd/sandboxd.service"), b"[Unit]\n").unwrap();
        std::fs::write(
            stage_dir.join("images/sandbox-gateway-9.9.9.tar"),
            b"fake-image-tar",
        )
        .unwrap();
        let manifest = serde_json::json!({
            "version": "9.9.9",
            "arch": "x86_64-unknown-linux-gnu",
            "artifacts": {
                "sandbox":  {"path": "bin/sandbox",  "sha256": "00"},
                "sandboxd": {"path": "bin/sandboxd", "sha256": "11"}
            }
        });
        std::fs::write(
            stage_dir.join("MANIFEST"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let tarball_path = tmp.path().join("release.tar.gz");
        let status = std::process::Command::new("tar")
            .args(["-czf"])
            .arg(&tarball_path)
            .args(["-C", tmp.path().to_str().unwrap(), stage_name])
            .status()
            .expect("run tar");
        assert!(status.success(), "tar should pack");
        std::fs::remove_dir_all(&stage_dir).unwrap();

        let dest = tmp.path().join("unpacked");
        let staged = extract_tarball(&tarball_path, &dest).expect("extract ok");
        assert_eq!(staged.manifest.version, "9.9.9");
        assert!(staged.sandboxd_bin().exists());
        assert!(staged.sandbox_bin().exists());
        assert!(staged.route_helper_bin().exists());
        assert!(staged.guest_bin().exists());
        assert!(staged.systemd_unit().exists());
        assert!(staged.gateway_image_tar().exists());
    }

    /// `peek_manifest_in_tarball` reads the MANIFEST without
    /// extracting — used by the pre-flight to surface arch/version
    /// mismatches before any state mutation.
    #[test]
    fn peek_manifest_in_tarball_reads_embedded_json() {
        let tmp = tempfile::tempdir().unwrap();
        let stage_name = "sandboxd-9.9.9-x86_64-unknown-linux-gnu";
        let stage_dir = tmp.path().join(stage_name);
        std::fs::create_dir_all(&stage_dir).unwrap();
        let manifest = serde_json::json!({
            "version": "9.9.9",
            "arch": "aarch64-unknown-linux-gnu",
            "artifacts": {}
        });
        std::fs::write(
            stage_dir.join("MANIFEST"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let tarball_path = tmp.path().join("release.tar.gz");
        let status = std::process::Command::new("tar")
            .args(["-czf"])
            .arg(&tarball_path)
            .args(["-C", tmp.path().to_str().unwrap(), stage_name])
            .status()
            .expect("run tar");
        assert!(status.success());
        let m = peek_manifest_in_tarball(&tarball_path).expect("peek ok");
        assert_eq!(m.version, "9.9.9");
        assert_eq!(m.arch, "aarch64-unknown-linux-gnu");
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
