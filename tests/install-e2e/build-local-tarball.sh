#!/bin/sh
# build-local-tarball.sh — assemble a release tarball locally that mirrors
# the artifact `.github/workflows/release.yml` would produce. Drives the
# Lima install/uninstall E2E harness (see tests/install-e2e/).
#
# Output:
#   tests/install-e2e/dist/sandboxd-<ver>-<arch>.tar.gz
#   tests/install-e2e/dist/sandboxd-<ver>-<arch>.tar.gz.sigstore   (stub)
#
# The .sigstore stub is a zero-byte placeholder — install.sh's
# verify-blob path is patched out in the test harness by replacing
# `cosign` with a stub that always returns 0. The harness exercises the
# script's idempotency / layout / state code paths; signature trust is
# tested by the release pipeline itself, not here.
#
# ── Glibc portability ──────────────────────────────────────────────────────
# The release pipeline (.github/workflows/release.yml) runs on
# `ubuntu-22.04` GitHub-hosted runners, so its tarballs are
# glibc-2.35-floored and run on every distro in our Lima matrix
# (Ubuntu 22.04 / Debian 12 / Fedora 41). A host build on a newer
# distro (e.g. Ubuntu 24.04 / glibc 2.39) links against GLIBC_2.39 and
# crashes inside the older VMs with `version 'GLIBC_2.39' not found`.
#
# To stay matrix-portable, we build the release binaries inside an
# `ubuntu:22.04` docker container whenever the host glibc is newer than
# 2.35. Hosts that already meet the 2.35 floor (Ubuntu 22.04, CI
# release runners) build natively — saves ~3 min apt+rustup bootstrap.
#
# Override:
#   SANDBOX_RELEASE_PORTABLE_BUILD=1   force the docker indirection
#   SANDBOX_RELEASE_PORTABLE_BUILD=0   force a native (host) build
# Default: auto-detect via `ldd --version`.
#
# First-time portable build is slow (~4–6 min: apt-get + rustup +
# cargo from scratch). Subsequent runs reuse the host cargo registry
# (bind-mounted) and a dedicated target dir under
# `sandboxd/target/portable`, so incremental builds are ~30 s.
#
# Usage:
#   tests/install-e2e/build-local-tarball.sh
#
# Inputs (env, optional):
#   SANDBOX_RELEASE_TARBALL_DIR   override the output dir
#                                  (default: tests/install-e2e/dist)
#   SANDBOX_RELEASE_SKIP_BUILD    set to 1 to skip `cargo build --release`
#                                  (useful for re-tarring an existing build)
#   SANDBOX_RELEASE_SKIP_GATEWAY  set to 1 to skip `make gateway-image`
#   SANDBOX_RELEASE_PORTABLE_BUILD  see above (auto if unset)
#   SANDBOX_RELEASE_BUMP_VERSION   build the workspace at this synthetic
#                                  version instead of the current
#                                  CARGO_PKG_VERSION. Every crate's
#                                  Cargo.toml is sed-rewritten before the
#                                  build and restored on EXIT (trap).
#                                  Output dir flips to
#                                  `sandboxd/target/portable-bumped/release`
#                                  so the bumped and base builds keep
#                                  independent cargo fingerprints — switching
#                                  between them does not trigger a full
#                                  re-compile. The resulting tarball reports
#                                  the bumped version in both filename and
#                                  MANIFEST, and the daemon's `/version`
#                                  endpoint (CARGO_PKG_VERSION) genuinely
#                                  reports the bumped version. This is the
#                                  multi-version harness Spec 5 § 9.1's
#                                  `test_update_fresh_install_to_next_version`
#                                  depends on. The first bumped build is
#                                  slower than incremental rebuilds since
#                                  every crate's CARGO_PKG_VERSION env var
#                                  changes — `cargo` rebuilds anything that
#                                  picked it up via `env!`.
#
# This script is POSIX sh; do not introduce bashisms (CI runs
# `shellcheck -s sh -S style`).

set -eu

# ----------------------------------------------------------------------------
# Resolve project root.
# ----------------------------------------------------------------------------

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
cd "$ROOT"

OUT_DIR="${SANDBOX_RELEASE_TARBALL_DIR:-$SCRIPT_DIR/dist}"
mkdir -p "$OUT_DIR"

# ----------------------------------------------------------------------------
# Resolve workspace version and arch.
# ----------------------------------------------------------------------------

BASE_VER=$(awk -F'"' '/^version/ { print $2; exit }' \
    "$ROOT/sandboxd/sandboxd/Cargo.toml")
if [ -z "$BASE_VER" ]; then
    printf 'build-local-tarball.sh: could not read version from sandboxd/sandboxd/Cargo.toml\n' >&2
    exit 1
fi

# Effective build version — either the Cargo.toml value or the operator-
# supplied bump. The bump path sed-rewrites every crate's Cargo.toml
# before invoking cargo, then restores them via an EXIT trap.
VER="${SANDBOX_RELEASE_BUMP_VERSION:-$BASE_VER}"

case "$(uname -m)" in
    x86_64)  ARCH="x86_64-unknown-linux-gnu" ;;
    aarch64) ARCH="aarch64-unknown-linux-gnu" ;;
    *)
        printf 'build-local-tarball.sh: unsupported host arch %s\n' "$(uname -m)" >&2
        exit 1
        ;;
esac

STAGE_NAME="sandboxd-${VER}-${ARCH}"
TARBALL="${OUT_DIR}/${STAGE_NAME}.tar.gz"

if [ "$VER" = "$BASE_VER" ]; then
    printf 'build-local-tarball.sh: version=%s arch=%s out=%s\n' \
        "$VER" "$ARCH" "$TARBALL"
else
    printf 'build-local-tarball.sh: version=%s (bumped from %s) arch=%s out=%s\n' \
        "$VER" "$BASE_VER" "$ARCH" "$TARBALL"
fi

# ----------------------------------------------------------------------------
# Cargo.toml version bump + restore.
#
# The crates do not inherit `package.version` from the workspace root —
# each crate's `Cargo.toml` carries its own literal `version = "X.Y.Z"`.
# To produce a binary whose `CARGO_PKG_VERSION` differs from the
# committed source, we sed-rewrite every crate's literal in place, run
# the build, then restore the originals via a trap that fires on EXIT
# (success or failure).
#
# The trap is installed unconditionally — it is a no-op when no files
# have been rewritten. We use `cp -p` so the saved copy preserves the
# original mtime; restoring it that way prevents stale cargo cache
# fingerprints from drifting incremental-build accounting.
# ----------------------------------------------------------------------------

# Snapshot/restore wired up only when the bump is non-empty AND differs
# from the committed version. Idempotent: running the script with
# SANDBOX_RELEASE_BUMP_VERSION equal to the on-disk version is a no-op.
BUMP_SNAPSHOT_DIR=""
BUMP_LOCK_SNAPSHOT=""
if [ -n "${SANDBOX_RELEASE_BUMP_VERSION:-}" ] \
   && [ "$SANDBOX_RELEASE_BUMP_VERSION" != "$BASE_VER" ]; then
    BUMP_SNAPSHOT_DIR=$(mktemp -d)
    # Find every crate Cargo.toml under sandboxd/ (excludes the
    # workspace root because the root file does not carry a literal
    # `version = "X.Y.Z"` — version lives in each crate).
    BUMP_FILES=$(find "$ROOT/sandboxd" -mindepth 2 -maxdepth 2 \
        -name Cargo.toml -print)
    if [ -z "$BUMP_FILES" ]; then
        printf 'build-local-tarball.sh: bump requested but no crate Cargo.toml found\n' >&2
        exit 1
    fi
    # Cargo.lock is overwritten by `cargo build` to reflect the bumped
    # crate versions. Snapshot it so we can restore the committed
    # version after the build.
    if [ -f "$ROOT/sandboxd/Cargo.lock" ]; then
        BUMP_LOCK_SNAPSHOT="$BUMP_SNAPSHOT_DIR/Cargo.lock"
        cp -p "$ROOT/sandboxd/Cargo.lock" "$BUMP_LOCK_SNAPSHOT"
    fi
fi

# The restore trap runs on EXIT (success or failure). The single-quoted
# body is re-evaluated at trap time so the variables are read live.
restore_cargo_versions() {
    if [ -z "$BUMP_SNAPSHOT_DIR" ] || [ ! -d "$BUMP_SNAPSHOT_DIR" ]; then
        return 0
    fi
    # Walk the snapshot dir; each saved file's basename encodes the
    # original crate name. We sed-restored the literal version, but
    # the safest restore is to copy the snapshot file back verbatim.
    for snap in "$BUMP_SNAPSHOT_DIR"/*.cargo-toml; do
        [ -f "$snap" ] || continue
        crate=$(basename "$snap" .cargo-toml)
        dst="$ROOT/sandboxd/$crate/Cargo.toml"
        if [ -f "$dst" ]; then
            cp -p "$snap" "$dst"
        fi
    done
    # Restore Cargo.lock too — `cargo build` would have rewritten it
    # with the bumped versions during the build.
    if [ -n "$BUMP_LOCK_SNAPSHOT" ] && [ -f "$BUMP_LOCK_SNAPSHOT" ]; then
        cp -p "$BUMP_LOCK_SNAPSHOT" "$ROOT/sandboxd/Cargo.lock"
    fi
    rm -rf "$BUMP_SNAPSHOT_DIR"
    BUMP_SNAPSHOT_DIR=""
    BUMP_LOCK_SNAPSHOT=""
}

# Trap EXIT (covers normal exit + most error paths under `set -e`).
trap restore_cargo_versions EXIT INT TERM

if [ -n "$BUMP_SNAPSHOT_DIR" ]; then
    printf 'build-local-tarball.sh: rewriting Cargo.toml version=%s -> %s in every crate\n' \
        "$BASE_VER" "$VER"
    # POSIX sh has no arrays; iterate the newline-delimited list via a
    # heredoc-fed `while` (no pipe — a pipe forks a subshell and the
    # `exit 1` inside the loop would not terminate the outer script).
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        crate=$(basename "$(dirname "$f")")
        cp -p "$f" "$BUMP_SNAPSHOT_DIR/${crate}.cargo-toml"
        # Match the first `version = "..."` line (the package version
        # always lives in the file's first 10 lines, before any
        # `[dependencies]` or other tables that might carry their own
        # `version = "..."` for deps). We anchor to `^version`.
        sed -i.bak -e "0,/^version = \"[^\"]*\"\$/{s/^version = \"[^\"]*\"\$/version = \"${VER}\"/}" "$f"
        rm -f "${f}.bak"
        # Confirm the rewrite landed.
        if ! grep -q "^version = \"${VER}\"\$" "$f"; then
            printf 'build-local-tarball.sh: failed to rewrite version in %s\n' "$f" >&2
            exit 1
        fi
    done <<EOF
$BUMP_FILES
EOF
fi

# ----------------------------------------------------------------------------
# Decide native vs. portable (docker) build.
#
# We need the resulting binaries to run on glibc 2.35 (Ubuntu 22.04 floor).
# Hosts at or below 2.35 build natively; newer hosts build inside
# `ubuntu:22.04` so the dynamic linker is satisfied on every distro in
# the test matrix.
# ----------------------------------------------------------------------------

host_glibc=$(ldd --version 2>/dev/null | awk '/^ldd/ { print $NF; exit }')
case "$host_glibc" in
    [0-9]*.[0-9]*) : ;;
    *) host_glibc="" ;;
esac

# Compare host_glibc to the 2.35 floor using awk (POSIX sh has no float
# arithmetic). Result: 1 = host > floor, 0 = host <= floor or unknown.
host_newer_than_floor=0
if [ -n "$host_glibc" ]; then
    host_newer_than_floor=$(awk -v h="$host_glibc" -v f="2.35" 'BEGIN {
        # split "2.39" into major/minor; lexicographic compare on (major,minor)
        nh = split(h, hp, ".");
        nf = split(f, fp, ".");
        for (i = 1; i <= (nh > nf ? nh : nf); i++) {
            a = (i <= nh ? hp[i] + 0 : 0);
            b = (i <= nf ? fp[i] + 0 : 0);
            if (a > b) { print 1; exit }
            if (a < b) { print 0; exit }
        }
        print 0
    }')
fi

case "${SANDBOX_RELEASE_PORTABLE_BUILD:-auto}" in
    1|true|yes|on)
        portable_build=1
        portable_reason="forced by SANDBOX_RELEASE_PORTABLE_BUILD=$SANDBOX_RELEASE_PORTABLE_BUILD"
        ;;
    0|false|no|off)
        portable_build=0
        portable_reason="disabled by SANDBOX_RELEASE_PORTABLE_BUILD=$SANDBOX_RELEASE_PORTABLE_BUILD"
        ;;
    auto|"")
        if [ "$host_newer_than_floor" = "1" ]; then
            portable_build=1
            portable_reason="host glibc ${host_glibc} > 2.35 floor"
        else
            portable_build=0
            portable_reason="host glibc ${host_glibc:-unknown} <= 2.35 floor"
        fi
        ;;
    *)
        printf 'build-local-tarball.sh: invalid SANDBOX_RELEASE_PORTABLE_BUILD=%s\n' \
            "$SANDBOX_RELEASE_PORTABLE_BUILD" >&2
        exit 1
        ;;
esac

printf 'build-local-tarball.sh: portable_build=%s (%s)\n' \
    "$portable_build" "$portable_reason"

# When building portably we redirect cargo into a dedicated target dir
# so portable and native artifacts do not invalidate each other's
# fingerprints. Native builds use the default `target/release`.
#
# The bumped build (SANDBOX_RELEASE_BUMP_VERSION) layers a `-bumped`
# suffix so switching between the base and bumped builds does not
# invalidate the other's incremental cache — every crate's
# `CARGO_PKG_VERSION` env-var changes between the two builds, which
# would otherwise force a full rebuild on every flip.
TARGET_VARIANT="portable"
if [ "$portable_build" = "0" ]; then
    TARGET_VARIANT="release"
fi
if [ -n "$BUMP_SNAPSHOT_DIR" ]; then
    TARGET_VARIANT="${TARGET_VARIANT}-bumped"
fi
case "$TARGET_VARIANT" in
    portable)         CARGO_TARGET_SUBDIR="target/portable" ;;
    portable-bumped)  CARGO_TARGET_SUBDIR="target/portable-bumped" ;;
    release)          CARGO_TARGET_SUBDIR="target" ;;
    release-bumped)   CARGO_TARGET_SUBDIR="target/bumped" ;;
esac
RELEASE_DIR="$ROOT/sandboxd/${CARGO_TARGET_SUBDIR}/release"

# ----------------------------------------------------------------------------
# Build workspace (release profile).
# ----------------------------------------------------------------------------

if [ "${SANDBOX_RELEASE_SKIP_BUILD:-0}" = "1" ]; then
    printf 'build-local-tarball.sh: SKIP_BUILD=1, reusing existing release artifacts\n'
elif [ "$portable_build" = "1" ]; then
    if ! command -v docker >/dev/null 2>&1; then
        printf 'build-local-tarball.sh: portable build requires docker, not found in PATH\n' >&2
        exit 1
    fi

    # Dedicated cache root for the portable build, isolated from the
    # user's host cargo (we run docker as root and don't want root-
    # owned files in $HOME/.cargo).
    #
    # First-time bootstrap (apt + rustup + cargo fetch + cargo build
    # from scratch) takes ~4–6 min. Subsequent runs reuse this cache
    # and a dedicated target dir, so incremental rebuilds are ~30 s.
    BUILD_CACHE="${SANDBOX_RELEASE_BUILD_CACHE:-$SCRIPT_DIR/.build-cache}"
    mkdir -p "$BUILD_CACHE/cargo-home/registry" \
             "$BUILD_CACHE/cargo-home/git" \
             "$BUILD_CACHE/rustup"
    # apt state lives inside the throwaway container layer — bind-
    # mounting /var/cache/apt and /var/lib/apt over the image's
    # pre-populated dirs strips required subdirs (archives/partial,
    # lists/auxfiles) and wedges apt-get update. We re-pay the apt
    # round-trip on every fresh container (~10–20 s); the dominant
    # cost is the cargo build, and that IS cached.

    UID_HOST=$(id -u)
    GID_HOST=$(id -g)

    printf 'build-local-tarball.sh: cargo build --workspace --release (docker: ubuntu:22.04) ...\n'

    # Pin toolchain to match release.yml (1.88.0); the workspace's
    # `sandboxd/rust-toolchain.toml` also lists 1.88.0 and is picked
    # up automatically by rustup once cargo is on PATH.
    #
    # We run as root inside the container so apt-get and rustup can
    # write their state, then chown the build outputs back to the host
    # user. The artifact dir (`target/portable`) lives under the
    # bind-mounted sandboxd workspace; everything else lives under
    # $BUILD_CACHE which is fine to leave root-owned.
    docker run --rm \
        -v "$ROOT/sandboxd:/work/sandboxd:rw" \
        -v "$BUILD_CACHE/cargo-home:/cargo-home:rw" \
        -v "$BUILD_CACHE/rustup:/rustup:rw" \
        -e CARGO_HOME=/cargo-home \
        -e RUSTUP_HOME=/rustup \
        -e CARGO_TARGET_DIR="/work/sandboxd/${CARGO_TARGET_SUBDIR}" \
        -e HOST_UID="$UID_HOST" \
        -e HOST_GID="$GID_HOST" \
        -e CARGO_TARGET_SUBDIR="$CARGO_TARGET_SUBDIR" \
        -w /work/sandboxd \
        ubuntu:22.04 \
        sh -c '
            set -eu
            export DEBIAN_FRONTEND=noninteractive
            if ! command -v cc >/dev/null 2>&1 \
               || ! command -v curl >/dev/null 2>&1; then
                apt-get update -qq
                apt-get install -y -qq --no-install-recommends \
                    curl ca-certificates build-essential pkg-config
            fi
            if ! [ -x "$CARGO_HOME/bin/cargo" ]; then
                curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
                    | sh -s -- -y \
                        --default-toolchain 1.88.0 \
                        --profile minimal \
                        --no-modify-path
            fi
            export PATH="$CARGO_HOME/bin:$PATH"
            cargo --version
            cargo build --workspace --release
            # Chown the produced artifacts so the host user can stage,
            # tar, and (eventually) clean them without sudo.
            chown -R "$HOST_UID:$HOST_GID" "/work/sandboxd/${CARGO_TARGET_SUBDIR}"
        '
else
    printf 'build-local-tarball.sh: cargo build --workspace --release (host) ...\n'
    ( cd "$ROOT/sandboxd" && cargo build --workspace --release )
fi

for bin in sandboxd sandbox sandbox-route-helper sandbox-guest; do
    if [ ! -x "$RELEASE_DIR/$bin" ]; then
        printf 'build-local-tarball.sh: missing release binary: %s/%s\n' \
            "$RELEASE_DIR" "$bin" >&2
        exit 1
    fi
done

# ----------------------------------------------------------------------------
# Build gateway image and `docker save` it.
#
# This step stays on the host: it produces a docker image with its own
# base layer (alpine/distroless variants per Dockerfile), so the host
# glibc never enters the artifact.
# ----------------------------------------------------------------------------

GATEWAY_TAG="sandbox-gateway:${VER}"
GATEWAY_TAR="${OUT_DIR}/sandbox-gateway-${VER}.tar"

# Bumped builds: the gateway image bytes do not depend on the
# workspace's Cargo.toml version (the Dockerfile sources its own base
# images). When SANDBOX_RELEASE_BUMP_VERSION is set we can short-
# circuit the docker-save step by tagging the base-version image and
# copying its already-saved tarball instead of re-saving identical
# bytes. This also lets the bumped tarball ship even when the host
# never had docker access to build the gateway directly.
if [ -n "$BUMP_SNAPSHOT_DIR" ] && [ ! -f "$GATEWAY_TAR" ]; then
    BASE_GATEWAY_TAR="${OUT_DIR}/sandbox-gateway-${BASE_VER}.tar"
    if [ -f "$BASE_GATEWAY_TAR" ]; then
        printf 'build-local-tarball.sh: bumped build reusing base gateway tar %s -> %s\n' \
            "$BASE_GATEWAY_TAR" "$GATEWAY_TAR"
        cp "$BASE_GATEWAY_TAR" "$GATEWAY_TAR"
    fi
    if command -v docker >/dev/null 2>&1 \
       && docker image inspect "sandbox-gateway:${BASE_VER}" >/dev/null 2>&1; then
        # Make the bumped tag exist locally too — install.sh's docker-
        # load step inspects this tag when it runs inside the test VM.
        docker tag "sandbox-gateway:${BASE_VER}" "$GATEWAY_TAG" 2>/dev/null || true
    fi
fi

if [ "${SANDBOX_RELEASE_SKIP_GATEWAY:-0}" = "1" ]; then
    printf 'build-local-tarball.sh: SKIP_GATEWAY=1, reusing existing gateway image tarball\n'
    if [ ! -f "$GATEWAY_TAR" ]; then
        printf 'build-local-tarball.sh: SKIP_GATEWAY=1 but %s is missing\n' \
            "$GATEWAY_TAR" >&2
        exit 1
    fi
else
    if ! docker image inspect "$GATEWAY_TAG" >/dev/null 2>&1; then
        printf 'build-local-tarball.sh: gateway image %s missing, running make gateway-image\n' \
            "$GATEWAY_TAG"
        ( cd "$ROOT" && make gateway-image )
    fi
    printf 'build-local-tarball.sh: docker save %s -> %s\n' \
        "$GATEWAY_TAG" "$GATEWAY_TAR"
    docker save "$GATEWAY_TAG" -o "$GATEWAY_TAR"
fi

# ----------------------------------------------------------------------------
# Stage the tarball contents.
# ----------------------------------------------------------------------------

STAGE_DIR="${OUT_DIR}/${STAGE_NAME}"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/bin" \
         "$STAGE_DIR/libexec" \
         "$STAGE_DIR/systemd" \
         "$STAGE_DIR/images" \
         "$STAGE_DIR/attestations"

install -m 0755 "$RELEASE_DIR/sandboxd" \
    "$STAGE_DIR/bin/sandboxd"
install -m 0755 "$RELEASE_DIR/sandbox" \
    "$STAGE_DIR/bin/sandbox"
install -m 0755 "$RELEASE_DIR/sandbox-route-helper" \
    "$STAGE_DIR/bin/sandbox-route-helper"
# sandbox-guest is a daemon-internal helper; install.sh lands it
# under /usr/local/libexec/sandboxd/ on the host (FHS § 4.7).
# The tarball uses a flat bin/ layout for simplicity — install.sh
# owns the FHS placement.
install -m 0755 "$RELEASE_DIR/sandbox-guest" \
    "$STAGE_DIR/bin/sandbox-guest"
install -m 0644 "$ROOT/sandboxd/contrib/systemd/sandboxd.service" \
    "$STAGE_DIR/systemd/sandboxd.service"
cp "$GATEWAY_TAR" "$STAGE_DIR/images/sandbox-gateway-${VER}.tar"

# ----------------------------------------------------------------------------
# Generate MANIFEST.
# ----------------------------------------------------------------------------

BUILD_SHA=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || printf 'local-build')

python3 - "$STAGE_DIR" "$VER" "$ARCH" "$BUILD_SHA" <<'PY'
import hashlib
import json
import os
import sys
import datetime

stage, ver, arch, build_sha = sys.argv[1:5]

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()

artifacts = {
    "sandboxd":              {"path": "bin/sandboxd"},
    "sandbox":               {"path": "bin/sandbox"},
    "sandbox-route-helper":  {"path": "bin/sandbox-route-helper"},
    "sandbox-guest":         {"path": "bin/sandbox-guest"},
    "gateway-image":         {"path": f"images/sandbox-gateway-{ver}.tar",
                              "docker_tag": f"sandbox-gateway:{ver}"},
    "systemd-unit":          {"path": "systemd/sandboxd.service"},
}
for entry in artifacts.values():
    entry["sha256"] = sha256(os.path.join(stage, entry["path"]))

manifest = {
    "version":    ver,
    "arch":       arch,
    "build_sha":  build_sha,
    "build_time": datetime.datetime.now(datetime.timezone.utc)
                          .strftime("%Y-%m-%dT%H:%M:%SZ"),
    "artifacts":  artifacts,
}

with open(os.path.join(stage, "MANIFEST"), "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
PY

# ----------------------------------------------------------------------------
# Tar it up.
# ----------------------------------------------------------------------------

( cd "$OUT_DIR" && tar -czf "${STAGE_NAME}.tar.gz" "$STAGE_NAME" )

# A zero-byte sigstore stub. The harness patches cosign verify-blob to
# always succeed, so the bundle is consumed but never parsed.
: > "${TARBALL}.sigstore"

# Cleanup intermediate stage dir but keep the gateway tar around in case
# of SKIP_GATEWAY=1 reuse.
rm -rf "$STAGE_DIR"

SIZE=$(du -h "$TARBALL" 2>/dev/null | awk '{print $1}')
printf 'build-local-tarball.sh: wrote %s (%s)\n' "$TARBALL" "$SIZE"
