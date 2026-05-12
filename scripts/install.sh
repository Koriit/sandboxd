#!/bin/sh
# install.sh — sandboxd installer (POSIX shell).
#
# Usage:
#   curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash
#   curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash -s -- --version 1.1.0
#   curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash -s -- --from /tmp/sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz
#
# Source of truth: scripts/install.sh in the Koriit/sandboxd repo. The site
# build copies this file into site/public/ before the docs deploy so the URL
# above resolves to a verbatim copy.
#
# This script is intentionally POSIX sh; do not introduce bashisms.

set -eu

# ----------------------------------------------------------------------------
# Pinned constants (trust root).
# ----------------------------------------------------------------------------

COSIGN_VERSION="v2.4.1"
# sha256 of cosign's published Linux binaries for the pinned version above.
# See § 7.3 of the install-infrastructure design spec for the bump process.
# Source: https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign_checksums.txt
COSIGN_SHA256_AMD64="8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b"
COSIGN_SHA256_ARM64="3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a"

DEFAULT_SOURCE_URL="https://github.com/Koriit/sandboxd/releases/download"
LATEST_API_URL="https://api.github.com/repos/Koriit/sandboxd/releases/latest"

INSTALL_LOG="/var/log/sandbox-install.log"
STATE_PATH="/var/lib/sandbox/.install-state.json"
SCRIPT_NAME="install.sh"

# ----------------------------------------------------------------------------
# Defaults / flag-controlled state.
# ----------------------------------------------------------------------------

VERSION="latest"
FROM=""
COSIGN_BUNDLE=""
SOURCE_URL="$DEFAULT_SOURCE_URL"
YES=0
VERBOSE=0
QUIET=0
NO_COLOR=0

# Step-discovered state (consumed by step 23 when writing install-state).
ARCH=""
TARGET_VER=""
SANDBOX_USER_CREATED=0
OPERATORS_ADDED=""
WE_SET_BRIDGE_HELPER_SETUID=0
WE_CREATED_USERS_CONF=0
ADDED_BRIDGE_CONF_RULES=""
BRIDGE_HELPER=""
TARBALL_SHA256=""
MANIFEST_BUILD_SHA=""

RED=""
GREEN=""
YELLOW=""
BLUE=""
RESET=""

TMPDIR_INSTALL=""

# ----------------------------------------------------------------------------
# Helper functions.
# ----------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: install.sh [OPTIONS]

Install sandboxd from a signed release tarball.

Options:
  --version <semver>        Pin install to the given release tag (default: latest).
  --from <path>             Use a local tarball instead of downloading.
  --cosign-bundle <path>    Use a local sigstore bundle (requires --from).
  --source-url <url>        Override base URL for tarball download.
  --yes                     Skip every confirmation prompt.
  --verbose                 Echo every command before invocation.
  --quiet                   Suppress non-error output.
  --no-color                Force plain text output.
  --help                    Print this message and exit.

Examples:
  # Latest tagged release.
  curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash

  # Air-gapped (operator already has the tarball locally).
  curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash -s -- \\
      --from /path/to/sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz

See https://Koriit.github.io/sandboxd/start/installation/ for the full guide.
EOF
}

emit() {
    if [ "$QUIET" -eq 0 ]; then
        printf '%b\n' "$*"
    fi
}

log_line() {
    # Append one record to $INSTALL_LOG. Args: full key=value tail.
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    line="$ts $SCRIPT_NAME $* pid=$$"
    if [ -w "$INSTALL_LOG" ] || { [ ! -e "$INSTALL_LOG" ] && [ -w "$(dirname "$INSTALL_LOG")" ]; }; then
        printf '%s\n' "$line" >> "$INSTALL_LOG" 2>/dev/null || true
    else
        # Best-effort via sudo. Suppress failures so early-flag-parse logging
        # before the log file is created cannot fault the whole script.
        printf '%s\n' "$line" | sudo -k tee -a "$INSTALL_LOG" >/dev/null 2>&1 || true
    fi
}

log_ok() {
    log_line "$*" "status=ok"
}

log_warn() {
    log_line "$*" "status=warn"
}

log_fail() {
    log_line "$*" "status=fail"
}

die() {
    msg="$1"
    emit "${RED}x${RESET} ${msg}"
    log_fail "step=die error='${msg}'"
    exit 1
}

setup_colors() {
    if [ -t 1 ] && [ "$NO_COLOR" -eq 0 ]; then
        RED=$(printf '\033[0;31m')
        GREEN=$(printf '\033[0;32m')
        YELLOW=$(printf '\033[0;33m')
        BLUE=$(printf '\033[0;34m')
        RESET=$(printf '\033[0m')
    else
        RED=""
        GREEN=""
        YELLOW=""
        BLUE=""
        RESET=""
    fi
}

ensure_install_log() {
    # Create the install log on first run. Mode 0640 root:root; spec § 4.6.
    if [ -e "$INSTALL_LOG" ]; then
        return 0
    fi
    if sudo -k touch "$INSTALL_LOG" 2>/dev/null; then
        sudo -k chmod 0640 "$INSTALL_LOG" 2>/dev/null || true
        sudo -k chown root:root "$INSTALL_LOG" 2>/dev/null || true
    fi
}

cleanup_tmpdir() {
    if [ -n "$TMPDIR_INSTALL" ] && [ -d "$TMPDIR_INSTALL" ]; then
        rm -rf "$TMPDIR_INSTALL"
    fi
}

# ----------------------------------------------------------------------------
# Step 1 — Arg parsing.
# ----------------------------------------------------------------------------

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)
                [ $# -ge 2 ] || die "--version requires an argument"
                VERSION="$2"
                shift 2
                ;;
            --version=*)
                VERSION="${1#--version=}"
                shift
                ;;
            --from)
                [ $# -ge 2 ] || die "--from requires an argument"
                FROM="$2"
                shift 2
                ;;
            --from=*)
                FROM="${1#--from=}"
                shift
                ;;
            --cosign-bundle)
                [ $# -ge 2 ] || die "--cosign-bundle requires an argument"
                COSIGN_BUNDLE="$2"
                shift 2
                ;;
            --cosign-bundle=*)
                COSIGN_BUNDLE="${1#--cosign-bundle=}"
                shift
                ;;
            --source-url)
                [ $# -ge 2 ] || die "--source-url requires an argument"
                SOURCE_URL="$2"
                shift 2
                ;;
            --source-url=*)
                SOURCE_URL="${1#--source-url=}"
                shift
                ;;
            --yes)
                YES=1
                shift
                ;;
            --verbose)
                VERBOSE=1
                shift
                ;;
            --quiet)
                QUIET=1
                shift
                ;;
            --no-color)
                NO_COLOR=1
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                printf 'install.sh: unknown option: %s\n' "$1" >&2
                printf 'Try --help.\n' >&2
                exit 2
                ;;
        esac
    done

    if [ -n "$COSIGN_BUNDLE" ] && [ -z "$FROM" ]; then
        die "--cosign-bundle requires --from"
    fi

    if [ "$VERBOSE" -eq 1 ]; then
        set -x
    fi

    log_ok "step=parse_args version=$VERSION from=${FROM:-'-'} yes=$YES"
}

# ----------------------------------------------------------------------------
# Step 2 — OS detection.
# ----------------------------------------------------------------------------

detect_os() {
    case "$(uname -s)" in
        Linux) ;;
        *) die "sandboxd installs on Linux only (got: $(uname -s))" ;;
    esac
    log_ok "step=os_detect os=Linux"
}

# ----------------------------------------------------------------------------
# Step 3 — Arch detection.
# ----------------------------------------------------------------------------

detect_arch() {
    case "$(uname -m)" in
        x86_64)  ARCH="x86_64-unknown-linux-gnu" ;;
        aarch64) ARCH="aarch64-unknown-linux-gnu" ;;
        *)       die "unsupported architecture: $(uname -m)" ;;
    esac
    log_ok "step=arch_detect arch=$ARCH"
}

# ----------------------------------------------------------------------------
# Step 4 — TTY detection + color setup.
# ----------------------------------------------------------------------------

detect_tty() {
    setup_colors
    tty_state="no"
    color_state="no"
    if [ -t 1 ]; then tty_state="yes"; fi
    if [ -n "$GREEN" ]; then color_state="yes"; fi
    log_ok "step=tty_detect tty=$tty_state color=$color_state"
}

# ----------------------------------------------------------------------------
# Step 5 — Pre-existing install detection.
# ----------------------------------------------------------------------------

resolve_target_version() {
    if [ "$VERSION" = "latest" ] && [ -z "$FROM" ]; then
        emit "  resolving latest release tag ..."
        # Strip a leading 'v' from the tag if present.
        resolved=$(curl -fsSL "$LATEST_API_URL" 2>/dev/null \
            | grep '"tag_name"' \
            | head -n 1 \
            | sed -e 's/.*"tag_name": *"//' -e 's/".*//' \
            | sed -e 's/^v//')
        if [ -z "$resolved" ]; then
            die "could not resolve latest sandboxd release tag from $LATEST_API_URL"
        fi
        VERSION="$resolved"
    fi
    TARGET_VER="$VERSION"
}

detect_preexisting() {
    if [ -x /usr/local/bin/sandboxd ]; then
        existing_ver=$(/usr/local/bin/sandboxd --version 2>/dev/null | awk '{print $2}')
        # Fallback: if the binary cannot report its version (e.g. it was built
        # against a newer glibc than the host, missing shared libs, or any
        # other run-time failure), consult the install-state file written by
        # the previous successful install. Without this fallback a broken-but-
        # present binary masks the version comparison and we incorrectly fall
        # through to the refuse path on a same-version re-install.
        if [ -z "$existing_ver" ] && [ -r "$STATE_PATH" ]; then
            existing_ver=$(sed -n 's/.*"installed_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
                "$STATE_PATH" 2>/dev/null \
                | head -n 1)
        fi
        if [ -z "$TARGET_VER" ]; then
            # Couldn't resolve target version yet (e.g. --from path). Trust
            # the local binary's version as the comparison key for skip.
            TARGET_VER="$existing_ver"
        fi
        if [ -n "$existing_ver" ] && [ "$existing_ver" = "$TARGET_VER" ]; then
            log_ok "step=preexist version=$existing_ver action=skip"
            emit "${GREEN}+${RESET} sandboxd $existing_ver is already installed"
            cleanup_tmpdir
            exit 0
        fi
        emit "${YELLOW}!${RESET} sandboxd ${existing_ver:-(unknown)} is already installed."
        emit "  install.sh installs from scratch only."
        emit "  To upgrade or downgrade, run:"
        emit "      sudo sandbox update --version $TARGET_VER"
        emit "  (Not yet available — re-run install.sh once update lands.)"
        log_warn "step=preexist version=${existing_ver:-unknown} target=$TARGET_VER action=refuse"
        exit 1
    fi
    log_ok "step=preexist version=none action=continue"
}

# ----------------------------------------------------------------------------
# Step 6 — Prerequisite check.
# ----------------------------------------------------------------------------

check_kernel_version() {
    rel=$(uname -r)
    major=$(printf '%s\n' "$rel" | cut -d. -f1)
    minor=$(printf '%s\n' "$rel" | cut -d. -f2)
    if [ -z "$major" ] || [ -z "$minor" ]; then
        return 1
    fi
    if [ "$major" -gt 5 ]; then return 0; fi
    if [ "$major" -eq 5 ] && [ "$minor" -ge 8 ]; then return 0; fi
    return 1
}

find_ovmf() {
    for f in \
        /usr/share/OVMF/OVMF_CODE.fd \
        /usr/share/edk2/ovmf/OVMF_CODE.fd \
        /usr/share/edk2-ovmf/OVMF_CODE.fd \
        /usr/share/qemu/OVMF_CODE.fd
    do
        if [ -f "$f" ]; then return 0; fi
    done
    return 1
}

check_prereqs() {
    qemu_arch="x86_64"
    case "$ARCH" in
        aarch64-*) qemu_arch="aarch64" ;;
    esac

    missing=""
    add_missing() { missing="$missing $1"; }

    check_kernel_version || add_missing "kernel-5.8+"

    if command -v docker >/dev/null 2>&1; then
        if ! docker info >/dev/null 2>&1; then
            # docker installed but daemon unreachable from this user;
            # not fatal at this step (operator-group-add fixes it),
            # but call it out.
            emit "${YELLOW}!${RESET} docker is installed but not reachable from this user."
        fi
    else
        add_missing "docker"
    fi

    command -v limactl  >/dev/null 2>&1 || add_missing "lima"
    command -v "qemu-system-$qemu_arch" >/dev/null 2>&1 || add_missing "qemu-system-$qemu_arch"
    find_ovmf || add_missing "ovmf"
    command -v setcap  >/dev/null 2>&1 || add_missing "setcap"
    command -v jq      >/dev/null 2>&1 || add_missing "jq"
    command -v curl    >/dev/null 2>&1 || add_missing "curl"
    command -v sha256sum >/dev/null 2>&1 || add_missing "sha256sum"
    command -v tar     >/dev/null 2>&1 || add_missing "tar"

    if [ -n "$missing" ]; then
        emit "${RED}x${RESET} missing prerequisites:"
        for m in $missing; do
            emit "    - $m"
        done
        emit "  Install these, then re-run install.sh."
        log_fail "step=prereq missing=$(printf '%s' "$missing" | tr ' ' ',')"
        exit 1
    fi
    log_ok "step=prereq missing=none"
}

# ----------------------------------------------------------------------------
# Step 7 — Disk space pre-flight.
# ----------------------------------------------------------------------------

free_kb_at() {
    df -Pk "$1" 2>/dev/null | awk 'NR==2 {print $4}'
}

check_disk() {
    # /var/lib/sandbox/ does not exist on a clean host; fall back to /var/lib
    # or /var or /.
    var_anchor=/var/lib/sandbox
    if [ ! -d "$var_anchor" ]; then var_anchor=/var/lib; fi
    if [ ! -d "$var_anchor" ]; then var_anchor=/var; fi
    if [ ! -d "$var_anchor" ]; then var_anchor=/; fi

    docker_anchor=/var/lib/docker
    if [ ! -d "$docker_anchor" ]; then docker_anchor=/var/lib; fi
    if [ ! -d "$docker_anchor" ]; then docker_anchor=/var; fi
    if [ ! -d "$docker_anchor" ]; then docker_anchor=/; fi

    usr_free=$(free_kb_at /usr/local)
    var_free=$(free_kb_at "$var_anchor")
    docker_free=$(free_kb_at "$docker_anchor")

    fail=0
    if [ -z "$usr_free" ] || [ "$usr_free" -lt 50000 ]; then
        emit "${RED}x${RESET} /usr/local has less than 50 MB free (${usr_free:-?} KB)"
        fail=1
    fi
    if [ -z "$var_free" ] || [ "$var_free" -lt 200000 ]; then
        emit "${RED}x${RESET} $var_anchor has less than 200 MB free (${var_free:-?} KB)"
        fail=1
    fi
    if [ -z "$docker_free" ] || [ "$docker_free" -lt 500000 ]; then
        emit "${RED}x${RESET} $docker_anchor has less than 500 MB free (${docker_free:-?} KB)"
        fail=1
    fi
    if [ "$fail" -eq 1 ]; then
        log_fail "step=disk_check usr_free=${usr_free:-?}KB var_free=${var_free:-?}KB"
        exit 1
    fi

    log_ok "step=disk_check usr_free=${usr_free}KB var_free=${var_free}KB docker_free=${docker_free}KB"
}

# ----------------------------------------------------------------------------
# Step 8 — Cosign bootstrap.
# ----------------------------------------------------------------------------

cosign_bootstrap() {
    case "$ARCH" in
        x86_64-unknown-linux-gnu)  cosign_bin="cosign-linux-amd64"; expected="$COSIGN_SHA256_AMD64" ;;
        aarch64-unknown-linux-gnu) cosign_bin="cosign-linux-arm64"; expected="$COSIGN_SHA256_ARM64" ;;
        *) die "no pinned cosign binary for $ARCH" ;;
    esac

    cosign_url="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/${cosign_bin}"
    dest="$TMPDIR_INSTALL/cosign"
    source_kind="download"

    if curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$cosign_url" 2>/dev/null; then
        actual=$(sha256sum "$dest" | awk '{print $1}')
        if [ "$actual" != "$expected" ]; then
            die "cosign checksum mismatch (expected $expected got $actual)"
        fi
        chmod +x "$dest"
    elif [ -x /usr/local/bin/cosign ]; then
        # Air-gapped fallback: operator pre-staged cosign.
        cp /usr/local/bin/cosign "$dest"
        actual=$(sha256sum "$dest" | awk '{print $1}')
        if [ "$actual" != "$expected" ]; then
            die "pre-staged /usr/local/bin/cosign sha256 mismatch (expected $expected got $actual)"
        fi
        chmod +x "$dest"
        source_kind="local"
    else
        die "cannot download cosign from $cosign_url and /usr/local/bin/cosign is absent"
    fi

    COSIGN="$dest"
    log_ok "step=cosign_bootstrap version=$COSIGN_VERSION source=$source_kind"
}

# ----------------------------------------------------------------------------
# Step 9 — Tarball fetch.
# ----------------------------------------------------------------------------

tarball_fetch() {
    tarball_dest="$TMPDIR_INSTALL/release.tar.gz"
    bundle_dest="$TMPDIR_INSTALL/release.tar.gz.sigstore"

    if [ -n "$FROM" ]; then
        [ -f "$FROM" ] || die "tarball not found: $FROM"
        cp "$FROM" "$tarball_dest"
        if [ -n "$COSIGN_BUNDLE" ]; then
            [ -f "$COSIGN_BUNDLE" ] || die "cosign bundle not found: $COSIGN_BUNDLE"
            cp "$COSIGN_BUNDLE" "$bundle_dest"
        else
            # Try a sibling .sigstore file next to the tarball.
            if [ -f "${FROM}.sigstore" ]; then
                cp "${FROM}.sigstore" "$bundle_dest"
            else
                die "no cosign bundle: pass --cosign-bundle or place a .sigstore file next to the tarball"
            fi
        fi
        source_label="local:$FROM"
    else
        tag="v${VERSION}"
        tarball_name="sandboxd-${VERSION}-${ARCH}.tar.gz"
        tarball_url="${SOURCE_URL}/${tag}/${tarball_name}"
        bundle_url="${tarball_url}.sigstore"

        if [ "$QUIET" -eq 0 ]; then
            curl -fsSL -S --retry 3 --retry-delay 2 -o "$tarball_dest" "$tarball_url" \
                || die "failed to download $tarball_url"
            curl -fsSL -S --retry 3 --retry-delay 2 -o "$bundle_dest" "$bundle_url" \
                || die "failed to download $bundle_url"
        else
            curl -fsSL --retry 3 --retry-delay 2 -o "$tarball_dest" "$tarball_url" \
                || die "failed to download $tarball_url"
            curl -fsSL --retry 3 --retry-delay 2 -o "$bundle_dest" "$bundle_url" \
                || die "failed to download $bundle_url"
        fi

        source_label="$tarball_url"
    fi

    size_kb=$(du -k "$tarball_dest" 2>/dev/null | awk '{print $1}')
    TARBALL_SHA256=$(sha256sum "$tarball_dest" | awk '{print $1}')
    log_ok "step=tarball_fetch source=$source_label version=$VERSION size=${size_kb}KB"
}

# ----------------------------------------------------------------------------
# Step 10 — Sigstore verification.
# ----------------------------------------------------------------------------

sigstore_verify() {
    "$COSIGN" verify-blob \
        --bundle "$TMPDIR_INSTALL/release.tar.gz.sigstore" \
        --certificate-identity-regexp '^https://github\.com/Koriit/sandboxd/\.github/workflows/release\.yml@' \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        "$TMPDIR_INSTALL/release.tar.gz" \
        >/dev/null 2>&1 \
        || die "sigstore verification failed for $TMPDIR_INSTALL/release.tar.gz"
    log_ok "step=sigstore_verify bundle=release.tar.gz.sigstore identity=Koriit/sandboxd/release.yml"
}

# ----------------------------------------------------------------------------
# Step 11 — Tarball extraction + MANIFEST verification.
# ----------------------------------------------------------------------------

extract_tarball() {
    tar -xzf "$TMPDIR_INSTALL/release.tar.gz" -C "$TMPDIR_INSTALL"
    STAGE="$TMPDIR_INSTALL/sandboxd-${VERSION}-${ARCH}"
    [ -d "$STAGE" ] || die "tarball did not contain expected top-level directory sandboxd-${VERSION}-${ARCH}"

    manifest="$STAGE/MANIFEST"
    [ -f "$manifest" ] || die "tarball missing MANIFEST"

    mver=$(jq -r '.version' "$manifest")
    march=$(jq -r '.arch' "$manifest")
    [ "$mver" = "$VERSION" ] || die "MANIFEST version mismatch: tarball says $mver, expected $VERSION"
    [ "$march" = "$ARCH" ] || die "MANIFEST arch mismatch: tarball says $march, expected $ARCH"

    MANIFEST_BUILD_SHA=$(jq -r '.build_sha // empty' "$manifest")

    # Per-artifact sha256 checks.
    jq -r '.artifacts | to_entries[] | "\(.value.sha256)  \(.value.path)"' "$manifest" \
        | (cd "$STAGE" && sha256sum -c --status -) \
        || die "MANIFEST sha256 check failed for at least one artifact"

    log_ok "step=extract version=$VERSION arch=$ARCH manifest_ok=true"
}

# ----------------------------------------------------------------------------
# Step 12 — Create the sandbox system user.
# ----------------------------------------------------------------------------

create_sandbox_user() {
    if getent passwd sandbox >/dev/null 2>&1; then
        log_ok "step=useradd action=skip reason=exists"
        SANDBOX_USER_CREATED=0
    else
        sudo -k useradd \
            --system \
            --user-group \
            --no-create-home \
            --home-dir /var/lib/sandbox \
            --shell /usr/sbin/nologin \
            --comment "sandboxd - isolated environment broker" \
            sandbox
        SANDBOX_USER_CREATED=1
        log_ok "step=useradd action=create"
    fi

    # Group adds are idempotent: usermod -aG on an existing member is a no-op.
    if getent group docker >/dev/null 2>&1; then
        sudo -k usermod -aG docker sandbox
    fi
    if getent group kvm >/dev/null 2>&1; then
        sudo -k usermod -aG kvm sandbox
    fi
    log_ok "step=usermod_groups groups=docker,kvm we_created=$SANDBOX_USER_CREATED"
}

# ----------------------------------------------------------------------------
# Step 13 — Add invoking operator to the sandbox group.
# ----------------------------------------------------------------------------

add_operator_to_group() {
    operator="${SUDO_USER:-}"
    if [ -z "$operator" ] || [ "$operator" = "root" ]; then
        emit "${YELLOW}!${RESET} install.sh was not invoked via sudo (or invoked as root)."
        emit "  Skipping operator-group-add. To add operators later:"
        emit "      sudo usermod -aG sandbox <operator-username>"
        log_warn "step=operator_add operator=none action=skip"
        OPERATORS_ADDED=""
        return 0
    fi

    if ! getent passwd "$operator" >/dev/null 2>&1; then
        emit "${YELLOW}!${RESET} SUDO_USER='$operator' does not exist in /etc/passwd."
        emit "  Skipping operator-group-add. Add manually after install:"
        emit "      sudo usermod -aG sandbox <operator-username>"
        log_warn "step=operator_add operator=$operator action=skip reason=unresolvable"
        OPERATORS_ADDED=""
        return 0
    fi

    if id -nG "$operator" 2>/dev/null | tr ' ' '\n' | grep -qx sandbox; then
        log_ok "step=operator_add operator=$operator action=skip reason=already-member"
        OPERATORS_ADDED=""
        return 0
    fi

    sudo -k usermod -aG sandbox "$operator"
    OPERATORS_ADDED="$operator"
    log_ok "step=operator_add operator=$operator action=add"
}

# ----------------------------------------------------------------------------
# Step 14 — Install binaries.
# ----------------------------------------------------------------------------

install_binary() {
    src="$1"
    dst="$2"
    mode="$3"

    [ -f "$src" ] || die "missing artifact in tarball: $src"

    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
        log_ok "step=install_binary path=$dst action=skip reason=identical"
        return 0
    fi
    sudo -k install -D -m "$mode" -o root -g root "$src" "$dst"
    sha=$(sha256sum "$dst" | awk '{print $1}')
    log_ok "step=install_binary path=$dst sha256=$sha action=install"
}

install_binaries() {
    install_binary "$STAGE/bin/sandboxd" /usr/local/bin/sandboxd 0755
    install_binary "$STAGE/bin/sandbox"  /usr/local/bin/sandbox  0755
    install_binary "$STAGE/bin/sandbox-route-helper" \
        /usr/local/libexec/sandboxd/sandbox-route-helper 0755
}

# ----------------------------------------------------------------------------
# Step 15 — Setcap on route-helper.
# ----------------------------------------------------------------------------

setcap_route_helper() {
    helper=/usr/local/libexec/sandboxd/sandbox-route-helper
    expected="cap_net_admin,cap_sys_admin=eip"
    # `getcap` output format varies by libcap version. Older libcap
    # ( < ~2.30) emits ``<path> = <caps>+ep``; newer libcap emits
    # ``<path> <caps>=eip`` (Ubuntu 22.04+, Fedora 36+). Use awk to
    # take the last whitespace-separated field so both formats parse.
    current=$(getcap "$helper" 2>/dev/null | awk '{print $NF}')
    if [ "$current" = "$expected" ]; then
        log_ok "step=setcap caps=$expected action=skip reason=already-set"
        return 0
    fi
    sudo -k setcap "$expected" "$helper"
    new=$(getcap "$helper" 2>/dev/null | awk '{print $NF}')
    [ "$new" = "$expected" ] || die "setcap verification failed: got '$new'"
    log_ok "step=setcap caps=$expected action=set"
}

# ----------------------------------------------------------------------------
# Step 16 — Probe for qemu-bridge-helper.
# ----------------------------------------------------------------------------

probe_bridge_helper() {
    for candidate in \
        /usr/lib/qemu/qemu-bridge-helper \
        /usr/libexec/qemu-bridge-helper \
        /usr/local/lib/qemu/qemu-bridge-helper \
        /usr/local/libexec/qemu-bridge-helper
    do
        if [ -x "$candidate" ]; then
            BRIDGE_HELPER="$candidate"
            break
        fi
    done
    [ -n "$BRIDGE_HELPER" ] \
        || die "qemu-bridge-helper not found at any known path; install qemu (and qemu-utils on Debian-likes)"
    log_ok "step=bridge_helper_probe path=$BRIDGE_HELPER"
}

# ----------------------------------------------------------------------------
# Step 17 — Setuid on qemu-bridge-helper.
# ----------------------------------------------------------------------------

setuid_bridge_helper() {
    if [ -u "$BRIDGE_HELPER" ]; then
        log_ok "step=bridge_helper_setuid path=$BRIDGE_HELPER action=skip reason=already-setuid"
        WE_SET_BRIDGE_HELPER_SETUID=0
        return 0
    fi
    sudo -k chmod u+s "$BRIDGE_HELPER"
    WE_SET_BRIDGE_HELPER_SETUID=1
    log_ok "step=bridge_helper_setuid path=$BRIDGE_HELPER action=set we_set=1"
}

# ----------------------------------------------------------------------------
# Step 18 — Install /etc/qemu/bridge.conf.
# ----------------------------------------------------------------------------

install_bridge_conf() {
    target_rule='allow sb-*'
    if [ -f /etc/qemu/bridge.conf ]; then
        if grep -qxE 'allow (all|sb-\*)' /etc/qemu/bridge.conf 2>/dev/null; then
            log_ok "step=bridge_conf action=skip reason=already-authorized"
            ADDED_BRIDGE_CONF_RULES=""
            return 0
        fi
        printf '%s\n' "$target_rule" | sudo -k tee -a /etc/qemu/bridge.conf >/dev/null
        ADDED_BRIDGE_CONF_RULES="$target_rule"
        log_ok "step=bridge_conf action=append rule='$target_rule'"
    else
        sudo -k mkdir -p /etc/qemu
        printf '%s\n' "$target_rule" | sudo -k tee /etc/qemu/bridge.conf >/dev/null
        sudo -k chmod 0644 /etc/qemu/bridge.conf
        ADDED_BRIDGE_CONF_RULES="$target_rule"
        log_ok "step=bridge_conf action=create rule='$target_rule'"
    fi
}

# ----------------------------------------------------------------------------
# Step 19 — Install /etc/sandboxd/users.conf.
# ----------------------------------------------------------------------------

install_users_conf() {
    if [ -f /etc/sandboxd/users.conf ]; then
        log_ok "step=users_conf action=skip reason=exists"
        WE_CREATED_USERS_CONF=0
        return 0
    fi
    sudo -k mkdir -p /etc/sandboxd
    operator_for_pool="${OPERATORS_ADDED:-sandbox}"

    staged="$TMPDIR_INSTALL/users.conf"
    cat > "$staged" <<EOF
{
  "_schema_version": 1,
  "subnets": [
    {
      "comment": "Production pool. Daemon user is 'sandbox'; the installing operator is also listed.",
      "cidr": "10.209.0.0/20",
      "allow_users": ["sandbox", "$operator_for_pool"]
    }
  ]
}
EOF
    sudo -k install -m 0644 -o root -g root "$staged" /etc/sandboxd/users.conf
    WE_CREATED_USERS_CONF=1
    log_ok "step=users_conf action=create pool=10.209.0.0/20 allow_users='sandbox,$operator_for_pool'"
}

# ----------------------------------------------------------------------------
# Step 20 — docker load the gateway image.
# ----------------------------------------------------------------------------

docker_load_gateway() {
    tag="sandbox-gateway:${VERSION}"
    if docker image inspect "$tag" >/dev/null 2>&1; then
        log_ok "step=docker_load image=$tag action=skip reason=already-loaded"
        return 0
    fi
    image_path="$STAGE/images/sandbox-gateway-${VERSION}.tar"
    [ -f "$image_path" ] || die "tarball missing gateway image at $image_path"
    sudo -k docker load -i "$image_path" >/dev/null
    docker image inspect "$tag" >/dev/null 2>&1 \
        || die "docker load did not produce expected tag $tag"
    log_ok "step=docker_load image=$tag action=load"
}

# ----------------------------------------------------------------------------
# Step 21 — Install systemd unit.
# ----------------------------------------------------------------------------

install_systemd_unit() {
    unit_src="$STAGE/systemd/sandboxd.service"
    unit_dst="/etc/systemd/system/sandboxd.service"
    [ -f "$unit_src" ] || die "tarball missing systemd/sandboxd.service"
    if [ -f "$unit_dst" ] && cmp -s "$unit_src" "$unit_dst"; then
        log_ok "step=install_unit action=skip reason=identical"
        return 0
    fi
    sudo -k install -m 0644 -o root -g root "$unit_src" "$unit_dst"
    sha=$(sha256sum "$unit_dst" | awk '{print $1}')
    log_ok "step=install_unit path=$unit_dst sha256=$sha action=install"
}

# ----------------------------------------------------------------------------
# Step 22 — systemctl daemon-reload.
# ----------------------------------------------------------------------------

systemd_daemon_reload() {
    sudo -k systemctl daemon-reload
    log_ok "step=daemon_reload"
}

# ----------------------------------------------------------------------------
# Step 23 — Write /var/lib/sandbox/.install-state.json.
# ----------------------------------------------------------------------------

bool_lit() {
    if [ "$1" = "1" ] || [ "$1" = "true" ]; then printf 'true'; else printf 'false'; fi
}

json_str() {
    # JSON-escape a shell string. Handles backslash and double-quote; other
    # control characters are out-of-scope (the values we feed in come from
    # paths, usernames, and sha256 hashes — all safe ASCII).
    s=$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
    printf '"%s"' "$s"
}

write_install_state() {
    sudo -k mkdir -p /var/lib/sandbox
    sudo -k chown sandbox:sandbox /var/lib/sandbox
    sudo -k chmod 0750 /var/lib/sandbox

    installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    installed_by_operator="${SUDO_USER:-(direct-root)}"

    if [ -n "$OPERATORS_ADDED" ]; then
        ops_json="[$(json_str "$OPERATORS_ADDED")]"
    else
        ops_json="[]"
    fi
    if [ -n "$ADDED_BRIDGE_CONF_RULES" ]; then
        rules_json="[$(json_str "$ADDED_BRIDGE_CONF_RULES")]"
    else
        rules_json="[]"
    fi

    users_conf_sha="null"
    if [ "$WE_CREATED_USERS_CONF" = "1" ] && [ -f /etc/sandboxd/users.conf ]; then
        h=$(sudo -k sha256sum /etc/sandboxd/users.conf | awk '{print $1}')
        users_conf_sha=$(json_str "$h")
    fi
    if [ -n "$MANIFEST_BUILD_SHA" ]; then
        manifest_sha_json=$(json_str "$MANIFEST_BUILD_SHA")
    else
        manifest_sha_json="null"
    fi
    if [ -n "$TARBALL_SHA256" ]; then
        tarball_sha_json=$(json_str "$TARBALL_SHA256")
    else
        tarball_sha_json="null"
    fi

    staged="$TMPDIR_INSTALL/install-state.json"
    {
        printf '{\n'
        printf '  "bridge_helper_path_at_install": %s,\n' "$(json_str "$BRIDGE_HELPER")"
        printf '  "installed_arch": %s,\n'                "$(json_str "$ARCH")"
        printf '  "installed_at": %s,\n'                  "$(json_str "$installed_at")"
        printf '  "installed_by_operator": %s,\n'         "$(json_str "$installed_by_operator")"
        printf '  "installed_version": %s,\n'             "$(json_str "$VERSION")"
        printf '  "manifest_build_sha": %s,\n'            "$manifest_sha_json"
        printf '  "operators_added_to_group": %s,\n'      "$ops_json"
        printf '  "tarball_sha256": %s,\n'                "$tarball_sha_json"
        printf '  "users_conf_sha256_at_install": %s,\n'  "$users_conf_sha"
        printf '  "we_added_bridge_conf_rules": %s,\n'    "$rules_json"
        printf '  "we_created_sandbox_user": %s,\n'       "$(bool_lit "$SANDBOX_USER_CREATED")"
        printf '  "we_created_users_conf": %s,\n'         "$(bool_lit "$WE_CREATED_USERS_CONF")"
        printf '  "we_set_bridge_helper_setuid": %s\n'    "$(bool_lit "$WE_SET_BRIDGE_HELPER_SETUID")"
        printf '}\n'
    } > "$staged"

    # Sanity-check the file we wrote.
    if command -v jq >/dev/null 2>&1; then
        jq -e . "$staged" >/dev/null \
            || die "internal error: install-state.json failed jq parse"
    fi

    sudo -k install -m 0640 -o sandbox -g sandbox "$staged" "$STATE_PATH"
    log_ok "step=install_state path=$STATE_PATH"
}

# ----------------------------------------------------------------------------
# Step 24 — Print next-steps.
# ----------------------------------------------------------------------------

print_next_steps() {
    emit ""
    emit "${GREEN}+${RESET} sandboxd $VERSION installed."
    emit ""
    emit "Next:"
    if [ -n "$OPERATORS_ADDED" ]; then
        emit "  1. Activate group membership: ${BLUE}log out and back in,${RESET} or ${BLUE}run: newgrp sandbox${RESET}"
    fi
    emit "  2. Start the daemon:           ${BLUE}sudo systemctl enable --now sandboxd${RESET}"
    emit "  3. Verify the install:         ${BLUE}sandbox doctor${RESET}"
    emit ""
    emit "Install state recorded at: $STATE_PATH"
    emit "Install log:               $INSTALL_LOG"
    log_ok "step=done version=$VERSION"
}

# ----------------------------------------------------------------------------
# Main.
# ----------------------------------------------------------------------------

main() {
    parse_args "$@"
    detect_os
    detect_arch
    detect_tty

    TMPDIR_INSTALL=$(mktemp -d "/tmp/sandbox-install.XXXXXX")
    trap cleanup_tmpdir EXIT INT TERM HUP

    ensure_install_log

    resolve_target_version
    detect_preexisting
    check_prereqs
    check_disk

    cosign_bootstrap
    tarball_fetch
    sigstore_verify
    extract_tarball

    create_sandbox_user
    add_operator_to_group

    install_binaries
    setcap_route_helper
    probe_bridge_helper
    setuid_bridge_helper
    install_bridge_conf
    install_users_conf
    docker_load_gateway
    install_systemd_unit
    systemd_daemon_reload

    write_install_state
    print_next_steps
}

main "$@"
