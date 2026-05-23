//! Subprocess-free integration tests for the post-extraction trust
//! check that pairs with sigstore verification.
//!
//! The signature-verify half is exercised end-to-end by the Lima E2E
//! suite (real cosign binary, real release bundle); these tests cover
//! the per-file digest half, which is hermetic enough to run inside the
//! workspace integration profile.
//!
//! Trust chain: sigstore(tarball) → MANIFEST →
//! sha256(file vs MANIFEST). The check pinned here is the third link:
//! a MANIFEST that lists artefacts with sha256 values that do not match
//! the on-disk bytes must surface `FetchError::ArtifactDigestMismatch`
//! before any binary lands on disk.
//!
//! Named `integration_*` per the project convention
//! (`sandboxd/.config/nextest.toml`).

use std::collections::BTreeMap;

use sandbox_cli::update::fetch::{self, FetchError, Manifest, ManifestArtifact, StagedTarball};

/// SHA-256 of the empty byte string. Hard-coded to keep the test
/// authoritative: the implementation MUST agree on the well-known
/// digest for this input.
const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Build a [`StagedTarball`] under `dest` with one artefact file (empty
/// bytes) and a MANIFEST that records `recorded_sha` for it. Returns
/// the staged shape ready for `verify_artifact_digests`.
fn stage_with_one_artefact(dest: &std::path::Path, recorded_sha: &str) -> StagedTarball {
    let stage_dir = dest.join("sandboxd-9.9.9-x86_64-unknown-linux-gnu");
    let bin_dir = stage_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    // Empty file — its sha256 is the well-known constant above.
    std::fs::write(bin_dir.join("sandbox"), b"").unwrap();

    let mut artifacts: BTreeMap<String, ManifestArtifact> = BTreeMap::new();
    artifacts.insert(
        "sandbox".to_string(),
        ManifestArtifact {
            path: "bin/sandbox".to_string(),
            sha256: recorded_sha.to_string(),
        },
    );
    let manifest = Manifest {
        version: "9.9.9".to_string(),
        arch: "x86_64-unknown-linux-gnu".to_string(),
        artifacts,
        build_sha: None,
    };
    StagedTarball {
        stage_dir,
        manifest,
    }
}

/// **Fetch-integrity anchor:** a MANIFEST that lists a tampered sha256
/// must produce `FetchError::ArtifactDigestMismatch { path, expected,
/// got }` with all three fields populated faithfully. This is the
/// production guarantee — without it, a tampered tarball with a valid
/// MANIFEST shape but mutated artefact bytes lands unverified content
/// on the host as root.
#[test]
fn integration_artifact_digest_mismatch_surfaces_typed_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bad_sha = "deadbeef".repeat(8); // 64 hex chars, deliberately wrong
    let staged = stage_with_one_artefact(tmp.path(), &bad_sha);

    let err = fetch::verify_artifact_digests(&staged)
        .expect_err("MANIFEST with wrong sha256 must refuse");
    match err {
        FetchError::ArtifactDigestMismatch {
            path,
            expected,
            got,
        } => {
            assert_eq!(
                path, "bin/sandbox",
                "mismatch must name the failing artefact path"
            );
            assert_eq!(
                expected, bad_sha,
                "expected field must echo the MANIFEST-recorded sha verbatim"
            );
            assert_eq!(
                got, SHA256_EMPTY,
                "got field must hold the actual on-disk sha256 of the staged file"
            );
        }
        other => panic!("expected ArtifactDigestMismatch, got: {other:?}"),
    }
}

/// Companion to the negative test above: a MANIFEST whose sha256 matches
/// the on-disk bytes must succeed. Pins the positive arm against the
/// well-known empty-file digest.
#[test]
fn integration_artifact_digest_match_passes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let staged = stage_with_one_artefact(tmp.path(), SHA256_EMPTY);
    fetch::verify_artifact_digests(&staged).expect("matching shas must pass");
}

/// Operator-pasted MANIFEST values often arrive in upper-case hex from
/// some tools; the design calls for `sha256sum -c` semantics which are
/// case-insensitive. Pin that here so a future refactor doesn't make
/// case the wrong kind of trust boundary.
#[test]
fn integration_artifact_digest_match_is_case_insensitive() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let upper = SHA256_EMPTY.to_uppercase();
    let staged = stage_with_one_artefact(tmp.path(), &upper);
    fetch::verify_artifact_digests(&staged)
        .expect("upper-case MANIFEST sha must still match lowercase on-disk hash");
}
