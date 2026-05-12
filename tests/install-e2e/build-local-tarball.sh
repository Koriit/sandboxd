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
# Usage:
#   tests/install-e2e/build-local-tarball.sh
#
# Inputs (env, optional):
#   SANDBOX_RELEASE_TARBALL_DIR  override the output dir
#                                 (default: tests/install-e2e/dist)
#   SANDBOX_RELEASE_SKIP_BUILD   set to 1 to skip `cargo build --release`
#                                 (useful for re-tarring an existing build)
#   SANDBOX_RELEASE_SKIP_GATEWAY set to 1 to skip `make gateway-image`
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

VER=$(awk -F'"' '/^version/ { print $2; exit }' \
    "$ROOT/sandboxd/sandboxd/Cargo.toml")
if [ -z "$VER" ]; then
    printf 'build-local-tarball.sh: could not read version from sandboxd/sandboxd/Cargo.toml\n' >&2
    exit 1
fi

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

printf 'build-local-tarball.sh: version=%s arch=%s out=%s\n' \
    "$VER" "$ARCH" "$TARBALL"

# ----------------------------------------------------------------------------
# Build workspace (release profile).
# ----------------------------------------------------------------------------

if [ "${SANDBOX_RELEASE_SKIP_BUILD:-0}" = "1" ]; then
    printf 'build-local-tarball.sh: SKIP_BUILD=1, reusing existing release artifacts\n'
else
    printf 'build-local-tarball.sh: cargo build --workspace --release ...\n'
    ( cd "$ROOT/sandboxd" && cargo build --workspace --release )
fi

for bin in sandboxd sandbox sandbox-route-helper; do
    if [ ! -x "$ROOT/sandboxd/target/release/$bin" ]; then
        printf 'build-local-tarball.sh: missing release binary: %s\n' "$bin" >&2
        exit 1
    fi
done

# ----------------------------------------------------------------------------
# Build gateway image and `docker save` it.
# ----------------------------------------------------------------------------

GATEWAY_TAG="sandbox-gateway:${VER}"
GATEWAY_TAR="${OUT_DIR}/sandbox-gateway-${VER}.tar"

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

install -m 0755 "$ROOT/sandboxd/target/release/sandboxd" \
    "$STAGE_DIR/bin/sandboxd"
install -m 0755 "$ROOT/sandboxd/target/release/sandbox" \
    "$STAGE_DIR/bin/sandbox"
install -m 0755 "$ROOT/sandboxd/target/release/sandbox-route-helper" \
    "$STAGE_DIR/bin/sandbox-route-helper"
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
