# lib.sh — shared shell constants for sandboxd installer and updater.
#
# Sourced by `scripts/install.sh` and by the `sandbox update` shell
# paths so both fetch the same pinned cosign version and matching
# SHA-256 checksums. A future Rust-side cosign-bootstrap helper consumes
# the same values via `include_str!` or a parallel `const`-mirror;
# whichever, the source of truth is this file.
#
# POSIX `sh`-compatible. No bashisms.

# Pinned cosign release used to verify signed release tarballs. The
# variables below are referenced by `cosign_bootstrap` in install.sh
# and the matching Rust-side helper in `sandbox-cli/src/update/fetch.rs`.
# The lint pass against this stand-alone file does not see those
# consumers, so we silence SC2034 (apparently-unused) on each constant.

# shellcheck disable=SC2034
COSIGN_VERSION="v2.4.1"

# sha256 of cosign's published Linux binaries for the pinned version
# above. Source:
# https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign_checksums.txt
# shellcheck disable=SC2034
COSIGN_SHA256_AMD64="8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b"
# shellcheck disable=SC2034
COSIGN_SHA256_ARM64="3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a"
