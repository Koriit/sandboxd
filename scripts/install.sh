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
# Shared constants — bootstrap copy of scripts/lib.sh.
#
# These constants MUST stay byte-identical to the values in
# `scripts/lib.sh`. The drift-check test
# `tests/install-e2e/test_lib_sh_drift.py` enforces this.
#
# Why duplicate? `install.sh` is delivered via `curl ... | bash`, so the
# bash process reading from stdin has no adjacent lib.sh to source. The
# canonical lib.sh remains authoritative for `sandbox update` (which is
# delivered as part of the tarball where lib.sh ships beside its
# consumers); install.sh carries the values inline so the curl-bash UX
# works without a second network fetch. When invoked from a local
# checkout, install.sh prefers the on-disk lib.sh (resolution order
# below) so a developer editing lib.sh sees their changes immediately
# without re-running the drift sync.
COSIGN_VERSION="v2.4.1"
COSIGN_SHA256_AMD64="8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b"
COSIGN_SHA256_ARM64="3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a"

# Optional override: source lib.sh if found on disk (in-tree dev
# workflow). Resolution order:
#   1. `$SANDBOX_LIB_SH` env override (used by the in-tree test suite).
#   2. `$(dirname "$0")/lib.sh` when invoked from a local checkout.
#   3. A bare `lib.sh` in the current working directory.
# Falls through silently if none match — the inline constants above are
# the production trust root.
__sandbox_lib_sh_resolve() {
    if [ -n "${SANDBOX_LIB_SH:-}" ] && [ -r "$SANDBOX_LIB_SH" ]; then
        printf '%s' "$SANDBOX_LIB_SH"
        return 0
    fi
    case "$0" in
        */*)
            __script_dir=$(dirname -- "$0")
            if [ -r "$__script_dir/lib.sh" ]; then
                printf '%s' "$__script_dir/lib.sh"
                return 0
            fi
            ;;
    esac
    if [ -r "./lib.sh" ]; then
        printf '%s' "./lib.sh"
        return 0
    fi
    return 1
}

__sandbox_lib_sh_path=$(__sandbox_lib_sh_resolve) && {
    # shellcheck disable=SC1090
    . "$__sandbox_lib_sh_path"
}

DEFAULT_SOURCE_URL="https://github.com/Koriit/sandboxd/releases/download"
LATEST_API_URL="https://api.github.com/repos/Koriit/sandboxd/releases/latest"

# Install log destination. Defaults to `/var/log/sandbox-install.log`.
# Operators on hosts where `/var/log` is read-only —
# container-build chroots, read-only-root images, ephemeral CI VMs —
# can override via `$SANDBOXD_INSTALL_LOG`. The override is honoured
# verbatim; an empty or unset variable falls back to the canonical
# path. `sandbox update` reads the same env var for parity (see
# `sandbox-cli/src/update/mod.rs::resolve_install_log_path`).
INSTALL_LOG="${SANDBOXD_INSTALL_LOG:-/var/log/sandbox-install.log}"
# STATE_PATH is not a static constant: it is derived from the sandbox user's
# uid after create_sandbox_user resolves SANDBOX_UID. See resolve_state_path().
STATE_PATH=""
SCRIPT_NAME="install.sh"

# ----------------------------------------------------------------------------
# Defaults / flag-controlled state.
# ----------------------------------------------------------------------------

VERSION="latest"
EXPLICIT_VERSION=0
FROM=""
COSIGN_BUNDLE=""
SOURCE_URL="$DEFAULT_SOURCE_URL"
YES=0
VERBOSE=0
QUIET=0
NO_COLOR=0

# Step-discovered state (consumed by the privileged child when writing install-state).
ARCH=""
TARGET_VER=""
# Resolved after compute_plan (if sandbox user already exists) or after
# the privileged child runs useradd. BASE_DIR = /var/lib/sandboxd/$SANDBOX_UID.
SANDBOX_UID=""
BASE_DIR=""
# The we_* provenance flags and OPERATORS_ADDED are tracked inside the
# privileged child (which writes them to install-state.json). They are
# NOT set in the parent's process — the parent reads the final state back
# from the installed JSON file via print_next_steps.
BRIDGE_HELPER=""
TARBALL_SHA256=""
MANIFEST_BUILD_SHA=""

# Operator identity: the user running this script (before any sudo).
# Passed into the privileged child as an argument to fix the silent
# skip bug when the script is run via plain `curl | bash` (where
# $SUDO_USER would be empty).
OPERATOR_NAME=""

RED=""
GREEN=""
YELLOW=""
BLUE=""
RESET=""

# Rich UI mode — 1 when full interactive UI (alt-screen, bar, spinners, live
# checklist) is available; 0 in all degraded paths (no TTY, --no-color,
# --quiet, tput unavailable). Set once by detect_tty; never changed again.
# All Phase-3 UI code is strictly gated on this flag so the non-TTY path
# (the install-e2e harness) is byte-for-byte unchanged.
RICH_UI=0

# Set to 1 while the alt-screen is active so the EXIT trap can restore it.
ALT_SCREEN_ACTIVE=0

TMPDIR_INSTALL=""

# Active spinner background PID (0 when no spinner is running).
SPINNER_PID=0

# Path to the temp file that buffers the durable summary for after rmcup.
# Empty when not yet created.
SUMMARY_FILE=""

# ----------------------------------------------------------------------------
# Plan state — populated by compute_plan(), consumed by render_plan()
# and the privileged child.
# ----------------------------------------------------------------------------

# Each variable documents what action the privileged step will take.
# Values: "create", "skip", "add", "append", "install", "set", "skip-setuid",
# "skip-caps", "load", "skip-load", "migrate", "skip-migrate", "skip-identical"

PLAN_SANDBOX_USER=""          # create | skip
PLAN_SANDBOX_UID_EXISTING=""  # uid of existing sandbox user (or empty)
PLAN_GROUPS_ADD=""            # space-separated list of groups to add sandbox to
PLAN_OPERATOR_ADD=""          # add | skip | skip-no-operator
PLAN_ROUTE_HELPER_CAPS=""     # set | skip
PLAN_LIMA_HELPER_CAPS=""      # set | skip
PLAN_BRIDGE_HELPER_SETUID=""  # set | skip
PLAN_BRIDGE_CONF=""           # create | append | skip
PLAN_USERS_CONF=""            # create | skip
PLAN_GATEWAY_IMAGE=""         # load | skip
PLAN_BINARIES=""              # install | skip-identical  (colon-separated per-binary list)
PLAN_UNIT=""                  # install | skip-identical
PLAN_LEGACY_MIGRATE=""        # migrate | skip

# Resolved in compute_plan so render_plan can display full paths/strings.
PLAN_ROUTE_HELPER_PATH="/usr/local/libexec/sandboxd/sandbox-route-helper"
PLAN_LIMA_HELPER_PATH="/usr/local/libexec/sandboxd/sandbox-lima-helper"
PLAN_ROUTE_CAPS_STR="cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip"
PLAN_LIMA_CAPS_STR="cap_setuid+ep"
PLAN_UNIT_DST="/etc/systemd/system/sandboxd.service"
PLAN_USERS_CONF_CONTENT=""
PLAN_BRIDGE_CONF_APPEND=""

# FIFO path used for the line-progress protocol between the privileged
# child and the parent. Written by the child on a dedicated fd; read by
# the parent. Placed inside TMPDIR_INSTALL so cleanup_tmpdir handles it.
PRIV_PROGRESS_FIFO=""
PRIV_SCRIPT=""

# ----------------------------------------------------------------------------
# Helper functions.
# ----------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: install.sh [OPTIONS]

Install sandboxd from a signed release tarball.

Options:
  --version <semver>        Pin install to the given release tag (default: latest).
                            Optional when --from is set: the version is read
                            from the tarball's embedded (sigstore-signed)
                            MANIFEST, not the tarball's filename. If both
                            --version and --from are given, the strings must
                            match the MANIFEST or the install aborts before
                            any state change.
  --from <path>             Use a local tarball instead of downloading. The
                            path must point at a real
                            sandboxd-<v>-<arch>.tar.gz produced by the release
                            pipeline (the filename is operator-controlled and
                            is not trusted — the MANIFEST is).
  --cosign-bundle <path>    Use a local sigstore bundle (requires --from).
  --source-url <url>        Override base URL for tarball download.
  --yes                     Skip the privileged-changes confirmation prompt.
  --verbose                 Echo every command before invocation.
  --quiet                   Suppress non-error output.
  --no-color                Force plain text output.
  --help                    Print this message and exit.

Environment variables:
  SANDBOXD_INSTALL_LOG      Override the install-log path (default
                            /var/log/sandbox-install.log). Useful on
                            hosts where /var/log is read-only.

Examples:
  # Latest tagged release.
  curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash

  # Pin a specific version (network download).
  curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash -s -- \\
      --version 1.0.0

  # Air-gapped (operator already has the tarball locally).
  # --version is optional here: the version is read from the tarball's
  # MANIFEST, so the filename you pass to --from is never trusted on its own.
  curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash -s -- \\
      --from /path/to/sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz

  # Air-gapped + local sigstore bundle (no network at all).
  curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash -s -- \\
      --from /path/to/sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz \\
      --cosign-bundle /path/to/sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz.sigstore

See https://Koriit.github.io/sandboxd/start/installation/ for the full guide.
EOF
}

emit() {
    if [ "$QUIET" -eq 0 ]; then
        printf '%b\n' "$*"
    fi
}

# osc8_link — emit an OSC 8 hyperlink if the terminal supports it, else
# return the label only. Used for docs-link section headers.
# Usage: osc8_link URL LABEL
osc8_link() {
    _url="$1"
    _label="$2"
    if [ -t 1 ] && [ -n "$GREEN" ]; then
        # shellcheck disable=SC1003
        printf '\033]8;;%s\033\\%s\033]8;;\033\\' "$_url" "$_label"
    else
        printf '%s' "$_label"
    fi
}

log_line() {
    # Append one record to $INSTALL_LOG. Args: full key=value tail.
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    line="$ts $SCRIPT_NAME $* pid=$$"
    if [ -w "$INSTALL_LOG" ] || { [ ! -e "$INSTALL_LOG" ] && [ -w "$(dirname "$INSTALL_LOG")" ]; }; then
        printf '%s\n' "$line" >> "$INSTALL_LOG" 2>/dev/null || true
    else
        # Best-effort via NON-INTERACTIVE sudo (`-n`): a log write must never
        # trigger a password prompt. If no usable credential is available the
        # write is silently dropped (|| true) — the on-host install log is
        # best-effort.
        printf '%s\n' "$line" | sudo -n tee -a "$INSTALL_LOG" >/dev/null 2>&1 || true
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

# is_utf8 — return 0 if the active locale is UTF-8, 1 otherwise.
# Checked once; used by tarball_fetch bar to choose style B vs C.
is_utf8() {
    # Consult LC_ALL, LC_CTYPE, LANG in priority order (POSIX locale rules).
    _lc="${LC_ALL:-${LC_CTYPE:-${LANG:-}}}"
    case "$_lc" in
        *[Uu][Tt][Ff]8*|*[Uu][Tt][Ff]-8*) return 0 ;;
    esac
    return 1
}

ensure_install_log() {
    # Create the install log on first run. Mode 0640 root:root.
    # In the new model this is done non-interactively; the privileged child
    # will create it if absent. For the parent we only attempt the
    # best-effort non-interactive path (no password prompts here).
    if [ -e "$INSTALL_LOG" ]; then
        return 0
    fi
    if sudo -n touch "$INSTALL_LOG" 2>/dev/null; then
        sudo -n chmod 0640 "$INSTALL_LOG" 2>/dev/null || true
        sudo -n chown root:root "$INSTALL_LOG" 2>/dev/null || true
    fi
}

cleanup_tmpdir() {
    # Kill any active spinner so the terminal is not left with dangling
    # cursor artifacts if the script dies (die(), Ctrl-C, etc.).
    if [ "$SPINNER_PID" -ne 0 ]; then
        kill "$SPINNER_PID" 2>/dev/null || true
        wait "$SPINNER_PID" 2>/dev/null || true
        printf '\r\033[K' >&2
        SPINNER_PID=0
    fi
    # Restore the alt-screen before any output so the terminal is not left
    # in alt-screen state on Ctrl-C or unexpected exit.
    if [ "$ALT_SCREEN_ACTIVE" -eq 1 ]; then
        tput rmcup 2>/dev/null || true
        ALT_SCREEN_ACTIVE=0
    fi
    if [ -n "$TMPDIR_INSTALL" ] && [ -d "$TMPDIR_INSTALL" ]; then
        rm -rf "$TMPDIR_INSTALL"
    fi
    if [ -n "$SUMMARY_FILE" ] && [ -f "$SUMMARY_FILE" ]; then
        rm -f "$SUMMARY_FILE"
    fi
}

# ui_enter_alt_screen — switch to the alternate screen buffer. No-op in plain
# mode. Sets ALT_SCREEN_ACTIVE=1 so cleanup_tmpdir knows to restore.
ui_enter_alt_screen() {
    if [ "$RICH_UI" -eq 1 ]; then
        tput smcup 2>/dev/null || true
        ALT_SCREEN_ACTIVE=1
    fi
}

# ui_leave_alt_screen — restore the primary screen. Prints the durable
# summary that was buffered in $1 (a temp file) to real stdout after the
# screen is restored, so it persists in the scrollback.
# In plain mode this is a no-op (the durable output was already on stdout).
ui_leave_alt_screen() {
    _summary_file="${1:-}"
    if [ "$ALT_SCREEN_ACTIVE" -eq 1 ]; then
        tput rmcup 2>/dev/null || true
        ALT_SCREEN_ACTIVE=0
        # Print the durable summary to real stdout (now the primary screen).
        if [ -n "$_summary_file" ] && [ -r "$_summary_file" ]; then
            cat "$_summary_file"
        fi
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
                EXPLICIT_VERSION=1
                shift 2
                ;;
            --version=*)
                VERSION="${1#--version=}"
                EXPLICIT_VERSION=1
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
    rich_state="no"
    if [ -t 1 ]; then tty_state="yes"; fi
    if [ -n "$GREEN" ]; then color_state="yes"; fi

    # Rich UI requires: stdout is a TTY, /dev/tty is usable, tput + a working
    # terminfo entry are present, and neither --no-color nor --quiet is set.
    # We probe tput smcup/rmcup to confirm terminfo is functional; if tput
    # itself is missing or the terminal type has no smcup capability the probe
    # exits non-zero and we fall back to plain mode.
    if [ "$tty_state" = "yes" ] \
        && [ "$NO_COLOR" -eq 0 ] \
        && [ "$QUIET" -eq 0 ] \
        && [ -e /dev/tty ] \
        && command -v tput >/dev/null 2>&1 \
        && tput smcup >/dev/null 2>&1 \
        && tput rmcup >/dev/null 2>&1; then
        RICH_UI=1
        rich_state="yes"
    fi

    log_ok "step=tty_detect tty=$tty_state color=$color_state rich=$rich_state"
}

# ----------------------------------------------------------------------------
# Step 5 — Pre-existing install detection.
# ----------------------------------------------------------------------------

resolve_target_version() {
    if [ -n "$FROM" ] && [ "$EXPLICIT_VERSION" -eq 0 ]; then
        # `--from` with no `--version`: the tarball is the canonical source.
        # The filename can be tampered with; the MANIFEST is the sigstore-
        # signed payload, so parse the version directly out of it without
        # unpacking the whole archive. We read the embedded MANIFEST here
        # (before sigstore_verify); verify() runs afterwards and asserts
        # the same tarball+bundle pair, so a tampered MANIFEST would fail
        # verification and abort the install before any state changes.
        [ -f "$FROM" ] || die "tarball not found: $FROM"
        manifest_blob=$(tar -O -xf "$FROM" --wildcards '*/MANIFEST' 2>/dev/null \
            | head -c 4096)
        resolved=$(printf '%s' "$manifest_blob" \
            | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
            | head -n 1)
        [ -n "$resolved" ] \
            || die "could not read version from MANIFEST in $FROM"
        VERSION="$resolved"
        log_ok "step=resolve_version source=manifest version=$VERSION"
    elif [ "$VERSION" = "latest" ] && [ -z "$FROM" ]; then
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
    _preexist_bin="/usr/local/libexec/sandboxd/sandboxd"
    if [ -x "$_preexist_bin" ]; then
        existing_ver=$("$_preexist_bin" --version 2>/dev/null | awk '{print $2}')
        # Fallback: if the binary cannot report its version (e.g. it was built
        # against a newer glibc than the host, missing shared libs, or any
        # other run-time failure), consult the install-state file written by
        # the previous successful install. Without this fallback a broken-but-
        # present binary masks the version comparison and we incorrectly fall
        # through to the refuse path on a same-version re-install.
        #
        # STATE_PATH is not yet resolved (create_sandbox_user has not run);
        # probe the per-uid path directly (if the sandbox user already exists)
        # then fall back to the legacy path.
        # Always probe the install-state file: we need it both as a version
        # fallback (when the binary can't report its version) and to check
        # install status (complete vs. failed/in-progress) for resume logic.
        _probe_state_path=""
        if getent passwd sandbox >/dev/null 2>&1; then
            _probe_uid=$(id -u sandbox 2>/dev/null || true)
            if [ -n "$_probe_uid" ]; then
                _probe_state_path="/var/lib/sandboxd/$_probe_uid/.install-state.json"
            fi
        fi
        if [ -z "$_probe_state_path" ] || [ ! -r "$_probe_state_path" ]; then
            _probe_state_path="/var/lib/sandbox/.install-state.json"
        fi
        # Use state-file version only as a fallback when binary reports nothing.
        if [ -z "$existing_ver" ] && [ -r "$_probe_state_path" ]; then
            existing_ver=$(sed -n 's/.*"installed_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
                "$_probe_state_path" 2>/dev/null \
                | head -n 1)
        fi
        if [ -z "$TARGET_VER" ]; then
            # Couldn't resolve target version yet (e.g. --from path). Trust
            # the local binary's version as the comparison key for skip.
            TARGET_VER="$existing_ver"
        fi
        if [ -n "$existing_ver" ] && [ "$existing_ver" = "$TARGET_VER" ]; then
            # Version matches — check the install-state status to decide
            # whether to skip or resume a partial install.
            _prior_status=""
            if [ -r "$_probe_state_path" ] && command -v jq >/dev/null 2>&1; then
                _prior_status=$(jq -r '.status // ""' "$_probe_state_path" 2>/dev/null || true)
            fi
            case "$_prior_status" in
                failed|in-progress)
                    # A previous install attempt reached the privileged batch
                    # but did not complete. Fall through to the planning pass
                    # which will re-detect completed steps and skip them,
                    # effectively resuming the install.
                    log_ok "step=preexist version=$existing_ver status=$_prior_status action=resume"
                    emit "${YELLOW}!${RESET} Resuming partial install of sandboxd $existing_ver (prior status: $_prior_status)."
                    ;;
                *)
                    # status=complete (or absent / unknown) — already installed.
                    log_ok "step=preexist version=$existing_ver action=skip"
                    emit "${GREEN}+${RESET} sandboxd $existing_ver is already installed"
                    cleanup_tmpdir
                    exit 0
                    ;;
            esac
        else
            emit "${YELLOW}!${RESET} sandboxd ${existing_ver:-(unknown)} is already installed."
            emit "  install.sh installs from scratch only."
            emit "  To upgrade or downgrade, run:"
            emit "      sudo sandbox update --version $TARGET_VER"
            emit "  (Not yet available — re-run install.sh once update lands.)"
            log_warn "step=preexist version=${existing_ver:-unknown} target=$TARGET_VER action=refuse"
            exit 1
        fi
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
    # We deliberately do NOT check for UEFI firmware (OVMF/AAVMF). It sits two
    # layers below us — sandboxd drives `limactl`, Lima drives QEMU, and QEMU
    # discovers its own firmware (via /usr/share/qemu/firmware/*.json and its
    # built-in search). Firmware file names/paths churn across distros (the
    # _4M/secboot split, x64/ subdirs, .bin, the aarch64 set), so any fixed
    # path list here false-negatives and hard-blocks installs on hosts where
    # Lima boots VMs perfectly well. Lima's own startup is the authority and
    # surfaces the accurate error if firmware is genuinely absent.
    command -v setcap  >/dev/null 2>&1 || add_missing "setcap"
    command -v jq      >/dev/null 2>&1 || add_missing "jq"
    command -v curl    >/dev/null 2>&1 || add_missing "curl"
    command -v sha256sum >/dev/null 2>&1 || add_missing "sha256sum"
    command -v tar     >/dev/null 2>&1 || add_missing "tar"

    if [ -n "$missing" ]; then
        emit "${RED}x${RESET} missing prerequisites:"
        mgr=$(detect_pkg_mgr 2>/dev/null || true)
        for m in $missing; do
            pkg=""
            if [ -n "$mgr" ]; then
                pkg=$(pkg_name_for "$m" "$mgr" 2>/dev/null || true)
            fi
            if [ -n "$pkg" ]; then
                hint=$(pkg_hint_for "$m")
                if [ -n "$hint" ]; then
                    emit "    - $m:    $mgr install $pkg     $hint"
                else
                    emit "    - $m:    $mgr install $pkg"
                fi
            else
                emit "    - $m"
            fi
        done
        emit "  Install these, then re-run install.sh."
        log_fail "step=prereq missing=$(printf '%s' "$missing" | tr ' ' ',')"
        exit 1
    fi
    log_ok "step=prereq missing=none"
}

# Detect the host's package manager from /etc/os-release's ID/ID_LIKE.
# Emits one of {apt, dnf, pacman, zypper} on stdout and returns 0 on a
# recognised distro family; returns 1 otherwise (caller falls back to a
# bare-name list).
detect_pkg_mgr() {
    [ -r /etc/os-release ] || return 1
    # shellcheck disable=SC1091
    . /etc/os-release 2>/dev/null
    for id in ${ID:-} ${ID_LIKE:-}; do
        case "$id" in
            debian|ubuntu)        echo apt;    return 0 ;;
            fedora|rhel|centos)   echo dnf;    return 0 ;;
            arch)                 echo pacman; return 0 ;;
            opensuse*|suse|sles)  echo zypper; return 0 ;;
        esac
    done
    return 1
}

# Map a sandboxd prereq name to a package name for the given manager.
# Returns 1 with no output if the prereq is not packaged (e.g. kernel
# version, where the fix is an OS upgrade, not a package install).
pkg_name_for() {
    prereq=$1
    mgr=$2
    case "$prereq" in
        docker)
            case "$mgr" in apt) echo docker.io ;; *) echo docker ;; esac ;;
        lima)
            echo lima ;;
        qemu-system-x86_64)
            case "$mgr" in
                apt|dnf) echo qemu-system-x86 ;;
                pacman)  echo qemu-base ;;
                zypper)  echo qemu-x86 ;;
                *)       echo qemu ;;
            esac ;;
        qemu-system-aarch64)
            case "$mgr" in
                apt)    echo qemu-system-arm ;;
                dnf)    echo qemu-system-aarch64 ;;
                pacman) echo qemu-arch-extra ;;
                zypper) echo qemu-arm ;;
                *)      echo qemu ;;
            esac ;;
        setcap)
            case "$mgr" in
                apt)         echo libcap2-bin ;;
                dnf|pacman)  echo libcap ;;
                zypper)      echo libcap-progs ;;
                *)           echo libcap ;;
            esac ;;
        jq|curl|tar) echo "$prereq" ;;
        sha256sum)   echo coreutils ;;
        kernel-5.8+) return 1 ;;
        *)           echo "$prereq" ;;
    esac
}

# Special-case URL hints appended after the install command — for
# prereqs whose distro packages are commonly out-of-date or unavailable
# in default repos and where upstream docs are the canonical install
# path.
pkg_hint_for() {
    case "$1" in
        docker) echo "# or follow https://docs.docker.com/engine/install/" ;;
        lima)   echo "# or download from https://github.com/lima-vm/lima/releases" ;;
        *)      ;;
    esac
}

# ----------------------------------------------------------------------------
# Step 7 — Disk space pre-flight.
# ----------------------------------------------------------------------------

free_kb_at() {
    df -Pk "$1" 2>/dev/null | awk 'NR==2 {print $4}'
}

check_disk() {
    # /var/lib/sandboxd may not exist on a clean host; fall back to /var/lib
    # or /var or /.
    var_anchor=/var/lib/sandboxd
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
# Phase-3 UI helpers — spinner and download bar.
#
# All functions in this section check RICH_UI and degrade gracefully; the
# non-TTY / plain-mode paths are unchanged from Phase 1/2.
# ----------------------------------------------------------------------------

# SPINNER_CHARS — four-frame classic spinner, POSIX-safe (no Unicode).
SPINNER_CHARS="/-\|"

# _spinner_frame — print one spinner frame to stdout for redraw.
# Args: $1=elapsed_seconds $2=label
_spinner_frame() {
    _sf_elapsed="$1"
    _sf_label="$2"
    _sf_idx=$((_sf_elapsed % 4))
    # Extract one char from SPINNER_CHARS at position _sf_idx.
    _sf_char=$(printf '%s' "$SPINNER_CHARS" | cut -c$((_sf_idx + 1)))
    # \r moves to start of line; print frame; leave cursor at start for next.
    printf '\r  %s %s  [%ss]  ' "$_sf_char" "$_sf_label" "$_sf_elapsed" >&2
}

# spinner_start — begin a spinner animation in the background (rich mode only).
# In plain mode this is a no-op: the calling code continues unchanged.
# Sets the global SPINNER_PID to the spinner background process id.
# The caller MUST call spinner_stop when the operation is done.
# The EXIT trap in cleanup_tmpdir will kill any lingering spinner on die().
#
# Usage: spinner_start LABEL
spinner_start() {
    _ss_label="$1"

    if [ "$RICH_UI" -ne 1 ]; then
        SPINNER_PID=0
        return 0
    fi

    # Launch the spinner animation loop in the background.
    # It writes to stderr so it does not mix with stdout content.
    (
        _t=0
        while true; do
            _spinner_frame "$_t" "$_ss_label"
            sleep 1
            _t=$((_t + 1))
        done
    ) &
    SPINNER_PID=$!
}

# spinner_stop — stop the spinner and print a ✔ or ✗ settle line.
# Args: $1=0 for success, non-zero for failure; $2=label to print.
# In plain mode: no-op (no spinner was started).
spinner_stop() {
    _sto_exit="${1:-0}"
    _sto_label="$2"

    if [ "$RICH_UI" -ne 1 ] || [ "$SPINNER_PID" -eq 0 ]; then
        SPINNER_PID=0
        return 0
    fi

    kill "$SPINNER_PID" 2>/dev/null || true
    wait "$SPINNER_PID" 2>/dev/null || true
    printf '\r\033[K' >&2
    SPINNER_PID=0

    if [ "$_sto_exit" -eq 0 ]; then
        emit "  ${GREEN}+${RESET} ${_sto_label}"
    else
        emit "  ${RED}x${RESET} ${_sto_label}"
    fi
}

# spinner_run — convenience wrapper: spinner_start + run cmd + spinner_stop.
# Plain mode: runs the command with no extra output (preserving Phase 1/2 behavior).
# Rich mode: animates a spinner during the command execution.
# The command runs in the FOREGROUND so global variables it sets propagate.
# Usage: spinner_run LABEL CMD [ARGS...]
spinner_run() {
    _sr_label="$1"
    shift

    spinner_start "$_sr_label"
    "$@"
    _sr_exit=$?
    spinner_stop "$_sr_exit" "$_sr_label"
    return "$_sr_exit"
}

# _bar_style_b — render a style-B (UTF-8 true eighths) progress bar.
# Args: $1=progress_eighths_total $2=total_cells $3=pct $4=done_mb $5=total_mb $6=speed_kbps
#
# progress_eighths_total = (done_kb * total_cells * 8) / total_kb  (integer)
# The caller computes this; we slice it into full cells + a fractional leader.
# Eighths characters (U+2588 down to U+2581): █▇▆▅▄▃▂▁
# We use ascending fill: index 1=▏ through 8=█ (U+258F..U+2588).
_bar_style_b() {
    _bsb_eighths="$1"   # total sub-cell progress (full_cells * 8 + frac_eighths)
    _bsb_total="$2"
    _bsb_pct="$3"
    _bsb_done_mb="$4"
    _bsb_total_mb="$5"
    _bsb_speed="$6"

    _bsb_full=$((_bsb_eighths / 8))
    _bsb_frac=$((_bsb_eighths % 8))

    # Build bar: full cells, then a fractional leading-edge cell, then spaces.
    # Eighth-block characters in ascending fill order (1/8 → 8/8):
    _bsb_bar=""
    _bsb_i=0
    while [ "$_bsb_i" -lt "$_bsb_total" ]; do
        if [ "$_bsb_i" -lt "$_bsb_full" ]; then
            _bsb_bar="${_bsb_bar}█"
        elif [ "$_bsb_i" -eq "$_bsb_full" ] && [ "$_bsb_frac" -gt 0 ]; then
            # Pick the sub-cell glyph for the fractional part.
            case "$_bsb_frac" in
                1) _bsb_bar="${_bsb_bar}▏" ;;
                2) _bsb_bar="${_bsb_bar}▎" ;;
                3) _bsb_bar="${_bsb_bar}▍" ;;
                4) _bsb_bar="${_bsb_bar}▌" ;;
                5) _bsb_bar="${_bsb_bar}▋" ;;
                6) _bsb_bar="${_bsb_bar}▊" ;;
                7) _bsb_bar="${_bsb_bar}▉" ;;
            esac
        else
            _bsb_bar="${_bsb_bar} "
        fi
        _bsb_i=$((_bsb_i + 1))
    done
    printf '\r  [%s] %3s%% %s/%s MB  %s KB/s  ' \
        "$_bsb_bar" "$_bsb_pct" "$_bsb_done_mb" "$_bsb_total_mb" "$_bsb_speed" >&2
}

# _bar_style_c — render a style-C (ASCII) progress bar.
# Args: $1=filled_cells $2=total_cells $3=pct $4=done_mb $5=total_mb $6=speed_kbps
_bar_style_c() {
    _bsc_filled="$1"
    _bsc_total="$2"
    _bsc_pct="$3"
    _bsc_done_mb="$4"
    _bsc_total_mb="$5"
    _bsc_speed="$6"

    _bsc_bar=""
    _bsc_i=0
    while [ "$_bsc_i" -lt "$_bsc_total" ]; do
        if [ "$_bsc_i" -lt "$_bsc_filled" ]; then
            _bsc_bar="${_bsc_bar}="
        elif [ "$_bsc_i" -eq "$_bsc_filled" ]; then
            _bsc_bar="${_bsc_bar}>"
        else
            _bsc_bar="${_bsc_bar} "
        fi
        _bsc_i=$((_bsc_i + 1))
    done
    printf '\r  [%s] %3s%% %s/%s MB  %s KB/s  ' \
        "$_bsc_bar" "$_bsc_pct" "$_bsc_done_mb" "$_bsc_total_mb" "$_bsc_speed" >&2
}

# _kb_to_mb_1dp — convert KB integer to MB string with one decimal place.
# Uses only integer arithmetic (POSIX sh has no floats).
_kb_to_mb_1dp() {
    _kk="$1"
    _mb_int=$((_kk / 1024))
    _mb_frac=$(( (_kk % 1024) * 10 / 1024 ))
    printf '%s.%s' "$_mb_int" "$_mb_frac"
}

# download_with_bar — download URL to DEST, showing a progress bar in rich
# mode or periodic log lines in plain mode.
# Args: $1=URL $2=DEST
# Sets global DOWNLOAD_BAR_FAILED=1 if the download fails.
DOWNLOAD_BAR_FAILED=0
download_with_bar() {
    _dwb_url="$1"
    _dwb_dest="$2"
    DOWNLOAD_BAR_FAILED=0

    # Probe Content-Length via HEAD (best-effort; not all servers honour it).
    _dwb_total_kb=0
    _dwb_cl=$(curl -fsSL --head --retry 2 --retry-delay 1 "$_dwb_url" 2>/dev/null \
        | grep -i '^Content-Length:' \
        | tail -n1 \
        | awk '{print $2}' \
        | tr -d '\r')
    if printf '%s' "${_dwb_cl:-0}" | grep -qE '^[0-9]+$'; then
        _dwb_total_kb=$((_dwb_cl / 1024))
    fi

    # Start download in the background; curl writes to dest.
    curl -fsSL --retry 3 --retry-delay 2 -o "$_dwb_dest" "$_dwb_url" 2>/dev/null &
    _dwb_curl_pid=$!

    if [ "$RICH_UI" -eq 1 ] && [ "$_dwb_total_kb" -gt 0 ]; then
        # Rich mode with known size: show a determinate bar.
        _dwb_cols=$(tput cols 2>/dev/null || printf '80')
        # Bar width: columns minus ~30 chars for pct/size/speed annotation.
        _dwb_bar_w=$((_dwb_cols - 32))
        if [ "$_dwb_bar_w" -lt 10 ]; then _dwb_bar_w=10; fi
        if [ "$_dwb_bar_w" -gt 50 ]; then _dwb_bar_w=50; fi

        _dwb_use_utf8=0
        is_utf8 && _dwb_use_utf8=1

        _dwb_last_kb=0
        _dwb_speed_kb=0
        while kill -0 "$_dwb_curl_pid" 2>/dev/null; do
            _dwb_done_kb=0
            if [ -f "$_dwb_dest" ]; then
                _dwb_done_kb=$(du -k "$_dwb_dest" 2>/dev/null | awk '{print $1}')
                _dwb_done_kb="${_dwb_done_kb:-0}"
            fi
            _dwb_pct=0
            if [ "$_dwb_total_kb" -gt 0 ]; then
                _dwb_pct=$((_dwb_done_kb * 100 / _dwb_total_kb))
                if [ "$_dwb_pct" -gt 100 ]; then _dwb_pct=100; fi
            fi
            _dwb_done_mb=$(_kb_to_mb_1dp "$_dwb_done_kb")
            _dwb_total_mb=$(_kb_to_mb_1dp "$_dwb_total_kb")

            # Speed: instantaneous KB/s from the previous sample delta.
            # Poll is 0.25 s, so multiply delta by 4 to get KB/s.
            _dwb_delta_kb=$((_dwb_done_kb - _dwb_last_kb))
            if [ "$_dwb_delta_kb" -gt 0 ]; then
                _dwb_speed_kb=$((_dwb_delta_kb * 4))
            fi
            _dwb_last_kb=$_dwb_done_kb

            if [ "$_dwb_use_utf8" -eq 1 ]; then
                # Compute sub-cell eighths: (done_kb * bar_cells * 8) / total_kb.
                _dwb_eighths=$((_dwb_done_kb * _dwb_bar_w * 8 / _dwb_total_kb))
                if [ "$_dwb_eighths" -gt $((_dwb_bar_w * 8)) ]; then
                    _dwb_eighths=$((_dwb_bar_w * 8))
                fi
                _bar_style_b "$_dwb_eighths" "$_dwb_bar_w" "$_dwb_pct" \
                    "$_dwb_done_mb" "$_dwb_total_mb" "$_dwb_speed_kb"
            else
                _dwb_filled=$((_dwb_pct * _dwb_bar_w / 100))
                _bar_style_c "$_dwb_filled" "$_dwb_bar_w" "$_dwb_pct" \
                    "$_dwb_done_mb" "$_dwb_total_mb" "$_dwb_speed_kb"
            fi
            sleep 0.25
        done
        # Erase the bar line.
        printf '\r\033[K' >&2

    elif [ "$RICH_UI" -eq 0 ] && [ "$_dwb_total_kb" -gt 0 ]; then
        # Plain mode with known size: emit periodic log lines (~10% increments).
        _dwb_last_pct_reported=-10
        while kill -0 "$_dwb_curl_pid" 2>/dev/null; do
            _dwb_done_kb=0
            if [ -f "$_dwb_dest" ]; then
                _dwb_done_kb=$(du -k "$_dwb_dest" 2>/dev/null | awk '{print $1}')
                _dwb_done_kb="${_dwb_done_kb:-0}"
            fi
            _dwb_pct=0
            if [ "$_dwb_total_kb" -gt 0 ]; then
                _dwb_pct=$((_dwb_done_kb * 100 / _dwb_total_kb))
                if [ "$_dwb_pct" -gt 100 ]; then _dwb_pct=100; fi
            fi
            # Report roughly every 10 percentage points.
            if [ "$((_dwb_pct - _dwb_last_pct_reported))" -ge 10 ]; then
                _dwb_done_mb=$(_kb_to_mb_1dp "$_dwb_done_kb")
                _dwb_total_mb=$(_kb_to_mb_1dp "$_dwb_total_kb")
                emit "  ... ${_dwb_pct}% (${_dwb_done_mb}/${_dwb_total_mb} MB)"
                _dwb_last_pct_reported=$_dwb_pct
            fi
            sleep 1
        done
    else
        # No size info (unknown Content-Length) or rich mode: just wait for curl.
        # Capture exit code directly here; skip the outer wait below.
        wait "$_dwb_curl_pid" || DOWNLOAD_BAR_FAILED=1
        return 0
    fi

    # For the rich-bar and plain-bar branches, the poll loop exits when the
    # process dies; capture the final exit code here.
    wait "$_dwb_curl_pid" || DOWNLOAD_BAR_FAILED=1
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

    # spinner_run handles plain-mode "begin / end" output and rich-mode
    # spinner animation. Both paths run the curl in the same process context
    # (background in rich, foreground in plain) — the curl exit code is
    # propagated by spinner_run.
    if spinner_run "downloading cosign ${COSIGN_VERSION}" \
        curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$cosign_url" 2>/dev/null; then
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

        # Use download_with_bar for the tarball (determinate bar in rich mode,
        # periodic log lines in plain mode with known Content-Length).
        download_with_bar "$tarball_url" "$tarball_dest"
        [ "$DOWNLOAD_BAR_FAILED" -eq 0 ] || die "failed to download $tarball_url"

        # Sigstore bundle is small — plain curl, no bar.
        curl -fsSL --retry 3 --retry-delay 2 -o "$bundle_dest" "$bundle_url" \
            || die "failed to download $bundle_url"

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
    # BEGIN_TEST_ENV — stripped from published install.sh at docs-deploy time
    #
    # Test env vars below are intentionally not present in the artifact
    # operators run via `curl … | bash` (.github/workflows/docs.yml
    # sed-strips every BEGIN_TEST_ENV…END_TEST_ENV span before staging
    # site/public/install.sh). The source tree keeps them so the
    # install-e2e harness can drive the real cosign-verify path against
    # the local Sigstore stack without forking a parallel installer.
    #
    # SANDBOX_INSTALL_SKIP_SIGSTORE — short-circuit verify entirely.
    # The air-gapped test assembles unsigned local-build tarballs and
    # exercises the rest of the script with this set; the un-patched
    # cosign_bootstrap + comprehensive egress block are the actual code
    # under test. THIS ENV VAR MUST NEVER BE SET IN PRODUCTION — it
    # disables the cryptographic trust root that protects against
    # tampered tarballs.
    if [ "${SANDBOX_INSTALL_SKIP_SIGSTORE:-0}" = "1" ]; then
        log_warn "step=sigstore_verify action=skip reason=test-env-override"
        return 0
    fi
    # END_TEST_ENV

    cert_chain_arg=""
    rekor_url_arg=""
    # BEGIN_TEST_ENV
    #
    # Trust-material redirect. The install-e2e harness boots a local
    # Sigstore stack (Fulcio + Rekor + CT log) and signs the local-build
    # tarball against it, so the real cosign verify-blob path can be
    # exercised end-to-end without reaching the production sigstore.dev
    # TUF mirror. The four SANDBOX_INSTALL_TEST_* env vars below let the
    # harness substitute the trust roots; the identity values
    # (certificate-identity-regexp, certificate-oidc-issuer) stay
    # byte-identical to production because the local stack mints tokens
    # that satisfy them.
    if [ -n "${SANDBOX_INSTALL_TEST_FULCIO_ROOT:-}" ]; then
        cert_chain_arg="--certificate-chain=${SANDBOX_INSTALL_TEST_FULCIO_ROOT}"
    fi
    if [ -n "${SANDBOX_INSTALL_TEST_REKOR_URL:-}" ]; then
        rekor_url_arg="--rekor-url=${SANDBOX_INSTALL_TEST_REKOR_URL}"
    fi
    # cosign reads these env vars directly when present; passing them
    # via the script's process environment is sufficient.
    if [ -n "${SANDBOX_INSTALL_TEST_REKOR_PUBLIC_KEY:-}" ]; then
        export SIGSTORE_REKOR_PUBLIC_KEY="${SANDBOX_INSTALL_TEST_REKOR_PUBLIC_KEY}"
    fi
    if [ -n "${SANDBOX_INSTALL_TEST_CT_LOG_PUBLIC_KEY:-}" ]; then
        export SIGSTORE_CT_LOG_PUBLIC_KEY_FILE="${SANDBOX_INSTALL_TEST_CT_LOG_PUBLIC_KEY}"
    fi
    # END_TEST_ENV

    # Start spinner before the cosign call (rich mode only; no-op in plain).
    # If die() fires inside the verify, the EXIT trap kills the spinner.
    spinner_start "verifying sigstore signature"

    # BEGIN_TEST_ENV
    #
    # Diagnostic toggle. In production cosign's stdout/stderr are
    # suppressed; that makes test triage impossible when verify-blob
    # fails inside a Lima VM. When SANDBOX_INSTALL_TEST_DEBUG_COSIGN_STDERR=1
    # is set, route cosign output to a fixed log file BEFORE die() fires
    # so the test harness can read what cosign actually said.
    cosign_debug_log="/tmp/sandbox-install-cosign-debug.log"
    # END_TEST_ENV
    # shellcheck disable=SC2086 # cert_chain_arg + rekor_url_arg are
    # deliberately unquoted so empty values expand to nothing rather
    # than passing a bare `''` argv slot that cosign would reject.
    # BEGIN_TEST_ENV
    if [ "${SANDBOX_INSTALL_TEST_DEBUG_COSIGN_STDERR:-0}" = "1" ]; then
        "$COSIGN" verify-blob \
            --bundle "$TMPDIR_INSTALL/release.tar.gz.sigstore" \
            --certificate-identity-regexp '^https://github\.com/Koriit/sandboxd/\.github/workflows/release\.yml@' \
            --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
            $cert_chain_arg \
            $rekor_url_arg \
            "$TMPDIR_INSTALL/release.tar.gz" \
            >"$cosign_debug_log" 2>&1 \
            || { spinner_stop 1 "verifying sigstore signature"; \
                 die "sigstore verification failed for $TMPDIR_INSTALL/release.tar.gz (cosign log: $cosign_debug_log)"; }
    else
    # END_TEST_ENV
        "$COSIGN" verify-blob \
            --bundle "$TMPDIR_INSTALL/release.tar.gz.sigstore" \
            --certificate-identity-regexp '^https://github\.com/Koriit/sandboxd/\.github/workflows/release\.yml@' \
            --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
            $cert_chain_arg \
            $rekor_url_arg \
            "$TMPDIR_INSTALL/release.tar.gz" \
            >/dev/null 2>&1 \
            || { spinner_stop 1 "verifying sigstore signature"; \
                 die "sigstore verification failed for $TMPDIR_INSTALL/release.tar.gz"; }
    # BEGIN_TEST_ENV
    fi
    # END_TEST_ENV
    spinner_stop 0 "verifying sigstore signature"
    log_ok "step=sigstore_verify bundle=release.tar.gz.sigstore identity=Koriit/sandboxd/release.yml"
}

# ----------------------------------------------------------------------------
# Step 11 — Tarball extraction + MANIFEST verification.
# ----------------------------------------------------------------------------

extract_tarball() {
    spinner_start "extracting and verifying tarball"

    tar -xzf "$TMPDIR_INSTALL/release.tar.gz" -C "$TMPDIR_INSTALL"
    STAGE="$TMPDIR_INSTALL/sandboxd-${VERSION}-${ARCH}"
    [ -d "$STAGE" ] || { spinner_stop 1 "extracting and verifying tarball"; \
        die "tarball did not contain expected top-level directory sandboxd-${VERSION}-${ARCH}"; }

    manifest="$STAGE/MANIFEST"
    [ -f "$manifest" ] || { spinner_stop 1 "extracting and verifying tarball"; \
        die "tarball missing MANIFEST"; }

    mver=$(jq -r '.version' "$manifest")
    march=$(jq -r '.arch' "$manifest")
    [ "$mver" = "$VERSION" ] || { spinner_stop 1 "extracting and verifying tarball"; \
        die "MANIFEST version mismatch: tarball says $mver, expected $VERSION"; }
    [ "$march" = "$ARCH" ] || { spinner_stop 1 "extracting and verifying tarball"; \
        die "MANIFEST arch mismatch: tarball says $march, expected $ARCH"; }

    MANIFEST_BUILD_SHA=$(jq -r '.build_sha // empty' "$manifest")

    # Per-artifact sha256 checks.
    jq -r '.artifacts | to_entries[] | "\(.value.sha256)  \(.value.path)"' "$manifest" \
        | (cd "$STAGE" && sha256sum -c --status -) \
        || { spinner_stop 1 "extracting and verifying tarball"; \
             die "MANIFEST sha256 check failed for at least one artifact"; }

    spinner_stop 0 "extracting and verifying tarball"
    log_ok "step=extract version=$VERSION arch=$ARCH manifest_ok=true"
}

# ----------------------------------------------------------------------------
# Step 12 (unprivileged) — Detect operator identity.
# ----------------------------------------------------------------------------

detect_operator() {
    # Primary: the process's own identity. In the standard curl|bash use-case
    # the script runs as the operator (non-root), so id -un returns the right
    # name without needing $SUDO_USER. This fixes the old bug where a plain
    # `curl | bash` invocation left $SUDO_USER empty and silently skipped the
    # operator-group-add step.
    OPERATOR_NAME=$(id -un 2>/dev/null || true)
    if [ -z "$OPERATOR_NAME" ] || [ "$OPERATOR_NAME" = "root" ]; then
        # Running as root. Fall back to $SUDO_USER to handle the case where
        # the caller wrapped the whole script in `sudo bash` (e.g. the test
        # harness or an operator that force-ran as root). If $SUDO_USER is
        # also empty, we have no operator to add to the group.
        OPERATOR_NAME="${SUDO_USER:-}"
        if [ "$OPERATOR_NAME" = "root" ]; then
            OPERATOR_NAME=""
        fi
    fi
    log_ok "step=detect_operator operator=${OPERATOR_NAME:-(root/none)}"
}

# ----------------------------------------------------------------------------
# Step 13 (new) — Planning pass: read-only detection of what needs doing.
#
# All "skip if already done" probes that previously lived inside each
# privileged step function now run here, as the unprivileged operator,
# to compute the minimal action list before any privileged work begins.
# ----------------------------------------------------------------------------

# probe_bridge_helper_path — find qemu-bridge-helper path; sets BRIDGE_HELPER.
probe_bridge_helper_path() {
    for candidate in \
        /usr/lib/qemu/qemu-bridge-helper \
        /usr/libexec/qemu-bridge-helper \
        /usr/local/lib/qemu/qemu-bridge-helper \
        /usr/local/libexec/qemu-bridge-helper
    do
        if [ -x "$candidate" ]; then
            BRIDGE_HELPER="$candidate"
            log_ok "step=bridge_helper_probe path=$BRIDGE_HELPER"
            return 0
        fi
    done
    die "qemu-bridge-helper not found at any known path; install qemu (and qemu-utils on Debian-likes)"
}

compute_plan() {
    # ---- sandbox system user ----
    if getent passwd sandbox >/dev/null 2>&1; then
        PLAN_SANDBOX_USER="skip"
        PLAN_SANDBOX_UID_EXISTING=$(id -u sandbox 2>/dev/null || true)
        # Resolve BASE_DIR for steps that follow (unit cmp, state path).
        if [ -n "$PLAN_SANDBOX_UID_EXISTING" ]; then
            BASE_DIR="/var/lib/sandboxd/$PLAN_SANDBOX_UID_EXISTING"
            SANDBOX_UID="$PLAN_SANDBOX_UID_EXISTING"
            STATE_PATH="$BASE_DIR/.install-state.json"
        fi
    else
        PLAN_SANDBOX_USER="create"
        # We don't know the uid yet (useradd will assign it); use a sentinel
        # so the unit diff section notes this is host-assigned.
        PLAN_SANDBOX_UID_EXISTING=""
    fi

    # ---- sandbox group membership (docker, kvm) ----
    PLAN_GROUPS_ADD=""
    if getent group docker >/dev/null 2>&1; then
        if ! id -nG sandbox 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
            PLAN_GROUPS_ADD="$PLAN_GROUPS_ADD docker"
        fi
    fi
    if getent group kvm >/dev/null 2>&1; then
        if ! id -nG sandbox 2>/dev/null | tr ' ' '\n' | grep -qx kvm; then
            PLAN_GROUPS_ADD="$PLAN_GROUPS_ADD kvm"
        fi
    fi

    # ---- operator sandbox-group add ----
    if [ -z "$OPERATOR_NAME" ]; then
        PLAN_OPERATOR_ADD="skip-no-operator"
    elif ! getent passwd "$OPERATOR_NAME" >/dev/null 2>&1; then
        PLAN_OPERATOR_ADD="skip-no-operator"
    elif id -nG "$OPERATOR_NAME" 2>/dev/null | tr ' ' '\n' | grep -qx sandbox; then
        PLAN_OPERATOR_ADD="skip"
    else
        PLAN_OPERATOR_ADD="add"
    fi

    # ---- route-helper capabilities ----
    expected_route_caps="cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip"
    current_route_caps=$(getcap "$PLAN_ROUTE_HELPER_PATH" 2>/dev/null | awk '{print $NF}')
    if [ "$current_route_caps" = "$expected_route_caps" ]; then
        PLAN_ROUTE_HELPER_CAPS="skip"
    else
        PLAN_ROUTE_HELPER_CAPS="set"
    fi

    # ---- lima-helper capabilities ----
    expected_lima_caps="cap_setuid=ep"
    current_lima_caps=$(getcap "$PLAN_LIMA_HELPER_PATH" 2>/dev/null | awk '{print $NF}' | tr '+' '=')
    if [ "$current_lima_caps" = "$expected_lima_caps" ]; then
        PLAN_LIMA_HELPER_CAPS="skip"
    else
        PLAN_LIMA_HELPER_CAPS="set"
    fi

    # ---- qemu-bridge-helper setuid ----
    probe_bridge_helper_path
    if [ -u "$BRIDGE_HELPER" ]; then
        PLAN_BRIDGE_HELPER_SETUID="skip"
    else
        PLAN_BRIDGE_HELPER_SETUID="set"
    fi

    # ---- /etc/qemu/bridge.conf ----
    target_rule="allow sb-*"
    PLAN_BRIDGE_CONF_APPEND="$target_rule"
    if [ -f /etc/qemu/bridge.conf ]; then
        if grep -qxE 'allow (all|sb-\*)' /etc/qemu/bridge.conf 2>/dev/null; then
            PLAN_BRIDGE_CONF="skip"
        else
            PLAN_BRIDGE_CONF="append"
        fi
    else
        PLAN_BRIDGE_CONF="create"
    fi

    # ---- /etc/sandboxd/users.conf ----
    if [ -f /etc/sandboxd/users.conf ]; then
        PLAN_USERS_CONF="skip"
        PLAN_USERS_CONF_CONTENT=""
    else
        PLAN_USERS_CONF="create"
        # Build the content string for plan rendering. The operator field
        # is filled from OPERATOR_NAME if available, else "sandbox".
        _op_for_pool="${OPERATOR_NAME:-sandbox}"
        PLAN_USERS_CONF_CONTENT=$(printf '{
  "_schema_version": 1,
  "subnets": [
    {
      "comment": "Production pool. Daemon user is '"'"'sandbox'"'"'; the installing operator is also listed.",
      "cidr": "10.209.0.0/20",
      "allow_users": ["sandbox", "%s"]
    }
  ]
}' "$_op_for_pool")
    fi

    # ---- binaries (cmp each against staged copy) ----
    _bin_plan=""
    for _b in \
        "$STAGE/bin/sandboxd:/usr/local/libexec/sandboxd/sandboxd:0755" \
        "$STAGE/bin/sandbox:/usr/local/bin/sandbox:0755" \
        "$STAGE/bin/sandbox-route-helper:/usr/local/libexec/sandboxd/sandbox-route-helper:0755" \
        "$STAGE/bin/sandbox-lima-helper:/usr/local/libexec/sandboxd/sandbox-lima-helper:0755" \
        "$STAGE/bin/sandbox-guest:/usr/local/libexec/sandboxd/sandbox-guest:0755"
    do
        _src="${_b%%:*}"
        _rest="${_b#*:}"
        _dst="${_rest%%:*}"
        if [ -f "$_dst" ] && cmp -s "$_src" "$_dst"; then
            _bin_plan="${_bin_plan}skip-identical:${_dst};"
        else
            _bin_plan="${_bin_plan}install:${_dst};"
        fi
    done
    PLAN_BINARIES="$_bin_plan"

    # ---- systemd unit (cmp rendered vs installed) ----
    unit_src="$STAGE/systemd/sandboxd.service"
    unit_dst="$PLAN_UNIT_DST"
    [ -f "$unit_src" ] || die "tarball missing systemd/sandboxd.service"
    if [ -n "$BASE_DIR" ]; then
        # Render the substituted unit now so we can cmp it.
        _rendered_unit="$TMPDIR_INSTALL/sandboxd.service.plan-rendered"
        sed "s|@SANDBOX_BASE_DIR@|$BASE_DIR|g" "$unit_src" > "$_rendered_unit"
        if [ -f "$unit_dst" ] && cmp -s "$_rendered_unit" "$unit_dst"; then
            PLAN_UNIT="skip-identical"
        else
            PLAN_UNIT="install"
        fi
    else
        # sandbox user doesn't exist yet; uid unknown; unit will be installed.
        PLAN_UNIT="install"
    fi

    # ---- docker gateway image ----
    gateway_tag="sandbox-gateway:${VERSION}"
    if docker image inspect "$gateway_tag" >/dev/null 2>&1; then
        PLAN_GATEWAY_IMAGE="skip"
    else
        PLAN_GATEWAY_IMAGE="load"
    fi

    # ---- legacy state migration ----
    if [ -d /var/lib/sandbox ]; then
        if [ -n "$BASE_DIR" ] && [ -f "$BASE_DIR/sessions.db" ]; then
            PLAN_LEGACY_MIGRATE="skip"
        else
            PLAN_LEGACY_MIGRATE="migrate"
        fi
    else
        PLAN_LEGACY_MIGRATE="skip"
    fi

    log_ok "step=compute_plan sandbox_user=$PLAN_SANDBOX_USER operator_add=$PLAN_OPERATOR_ADD bridge_conf=$PLAN_BRIDGE_CONF unit=$PLAN_UNIT"
}

# ----------------------------------------------------------------------------
# Step 14 (new) — Render the plan (plain text this phase).
# ----------------------------------------------------------------------------

render_plan() {
    DOCS_BASE="https://koriit.github.io/sandboxd/start/installation/"

    emit ""
    emit "${BLUE}sandboxd $VERSION — privileged change plan${RESET}"
    emit "$(osc8_link "${DOCS_BASE}" "Installation guide: ${DOCS_BASE}")"
    emit ""
    emit "The following changes require root. Review them before confirming."
    emit ""

    # ---- System user ----
    hdr="System user"
    emit "  $(osc8_link "${DOCS_BASE}#system-user" "$hdr")"
    if [ "$PLAN_SANDBOX_USER" = "skip" ]; then
        emit "    ${GREEN}+ sandbox user already exists (uid $PLAN_SANDBOX_UID_EXISTING) — skip${RESET}"
    else
        emit "    ${YELLOW}+ create system user 'sandbox' (system account, no home, nologin)${RESET}"
        emit "      useradd --system --user-group --no-create-home"
        emit "              --home-dir /nonexistent --shell /usr/sbin/nologin sandbox"
    fi
    if [ -n "$PLAN_GROUPS_ADD" ]; then
        for _g in $PLAN_GROUPS_ADD; do
            emit "    ${YELLOW}+ add sandbox to group '$_g'${RESET}"
            emit "      usermod -aG $_g sandbox"
        done
    fi
    if [ "$PLAN_OPERATOR_ADD" = "add" ]; then
        emit "    ${YELLOW}+ add operator '$OPERATOR_NAME' to group 'sandbox'${RESET}"
        emit "      usermod -aG sandbox $OPERATOR_NAME"
    elif [ "$PLAN_OPERATOR_ADD" = "skip" ]; then
        emit "    ${GREEN}+ operator '$OPERATOR_NAME' already in group 'sandbox' — skip${RESET}"
    else
        emit "    ${YELLOW}! no operator to add to sandbox group (running as root or no effective user)${RESET}"
    fi
    emit ""

    # ---- Binaries ----
    hdr="Binaries"
    emit "  $(osc8_link "${DOCS_BASE}#binaries" "$hdr")"
    _old_IFS="$IFS"
    IFS=";"
    for _entry in $PLAN_BINARIES; do
        IFS="$_old_IFS"
        [ -z "$_entry" ] && continue
        _action="${_entry%%:*}"
        _dst="${_entry#*:}"
        if [ "$_action" = "skip-identical" ]; then
            emit "    ${GREEN}+ $_dst — identical, skip${RESET}"
        else
            emit "    ${YELLOW}+ install $_dst (mode 0755, root:root)${RESET}"
        fi
        IFS=";"
    done
    IFS="$_old_IFS"
    emit ""

    # ---- Capabilities ----
    hdr="File capabilities"
    emit "  $(osc8_link "${DOCS_BASE}#capabilities" "$hdr")"
    if [ "$PLAN_ROUTE_HELPER_CAPS" = "skip" ]; then
        emit "    ${GREEN}+ $PLAN_ROUTE_HELPER_PATH — $PLAN_ROUTE_CAPS_STR already set, skip${RESET}"
    else
        emit "    ${YELLOW}+ setcap $PLAN_ROUTE_CAPS_STR $PLAN_ROUTE_HELPER_PATH${RESET}"
    fi
    if [ "$PLAN_LIMA_HELPER_CAPS" = "skip" ]; then
        emit "    ${GREEN}+ $PLAN_LIMA_HELPER_PATH — $PLAN_LIMA_CAPS_STR already set, skip${RESET}"
    else
        emit "    ${YELLOW}+ setcap $PLAN_LIMA_CAPS_STR $PLAN_LIMA_HELPER_PATH${RESET}"
    fi
    emit ""

    # ---- QEMU bridge helper ----
    hdr="QEMU bridge helper"
    emit "  $(osc8_link "${DOCS_BASE}#qemu-bridge-helper" "$hdr")"
    if [ "$PLAN_BRIDGE_HELPER_SETUID" = "skip" ]; then
        emit "    ${GREEN}+ $BRIDGE_HELPER — setuid already set, skip${RESET}"
    else
        emit "    ${YELLOW}+ chmod u+s $BRIDGE_HELPER (setuid for unprivileged TAP creation)${RESET}"
    fi
    emit ""

    # ---- /etc/qemu/bridge.conf ----
    hdr="/etc/qemu/bridge.conf"
    emit "  $(osc8_link "${DOCS_BASE}#bridge-conf" "$hdr")"
    if [ "$PLAN_BRIDGE_CONF" = "skip" ]; then
        emit "    ${GREEN}+ /etc/qemu/bridge.conf — rule already present, skip${RESET}"
    elif [ "$PLAN_BRIDGE_CONF" = "append" ]; then
        emit "    ${YELLOW}+ append to /etc/qemu/bridge.conf:${RESET}"
        emit "        $PLAN_BRIDGE_CONF_APPEND"
    else
        emit "    ${YELLOW}+ create /etc/qemu/bridge.conf:${RESET}"
        emit "        $PLAN_BRIDGE_CONF_APPEND"
    fi
    emit ""

    # ---- /etc/sandboxd/users.conf ----
    hdr="/etc/sandboxd/users.conf"
    emit "  $(osc8_link "${DOCS_BASE}#users-conf" "$hdr")"
    if [ "$PLAN_USERS_CONF" = "skip" ]; then
        emit "    ${GREEN}+ /etc/sandboxd/users.conf already exists, skip${RESET}"
    else
        emit "    ${YELLOW}+ create /etc/sandboxd/users.conf (mode 0644, root:root):${RESET}"
        printf '%s\n' "$PLAN_USERS_CONF_CONTENT" | while IFS= read -r _line; do
            emit "        $_line"
        done
    fi
    emit ""

    # ---- Gateway image ----
    hdr="Gateway container image"
    emit "  $(osc8_link "${DOCS_BASE}#gateway-image" "$hdr")"
    if [ "$PLAN_GATEWAY_IMAGE" = "skip" ]; then
        emit "    ${GREEN}+ sandbox-gateway:${VERSION} already loaded in Docker, skip${RESET}"
    else
        emit "    ${YELLOW}+ docker load sandbox-gateway:${VERSION} from tarball${RESET}"
    fi
    emit ""

    # ---- systemd unit ----
    hdr="Systemd unit"
    emit "  $(osc8_link "${DOCS_BASE}#systemd-unit" "$hdr")"
    if [ "$PLAN_UNIT" = "skip-identical" ]; then
        emit "    ${GREEN}+ $PLAN_UNIT_DST — identical, skip${RESET}"
    else
        emit "    ${YELLOW}+ install $PLAN_UNIT_DST (mode 0644, root:root)${RESET}"
        if [ -n "$BASE_DIR" ]; then
            emit "      host-specific substitution: @SANDBOX_BASE_DIR@ -> $BASE_DIR"
        else
            emit "      host-specific substitution: @SANDBOX_BASE_DIR@ -> (resolved after user creation)"
        fi
        emit "      remaining content: verbatim from signed tarball"
        emit "      view full: tar -O -xf $TMPDIR_INSTALL/release.tar.gz '*/systemd/sandboxd.service' 2>/dev/null"
    fi
    emit ""

    # ---- Legacy migration ----
    if [ "$PLAN_LEGACY_MIGRATE" = "migrate" ]; then
        emit "  Migration"
        emit "    ${YELLOW}+ migrate /var/lib/sandbox -> $BASE_DIR${RESET}"
        emit ""
    fi

    # ---- Install state ----
    if [ -n "$BASE_DIR" ]; then
        emit "  Install state"
        emit "    ${YELLOW}+ write $STATE_PATH (mode 0640, sandbox:sandbox)${RESET}"
        emit ""
    fi

    emit "Documentation: ${DOCS_BASE}"
    emit ""
}

# ----------------------------------------------------------------------------
# Step 15 (new) — Confirmation gate.
# ----------------------------------------------------------------------------

confirm_plan() {
    if [ "$YES" -eq 1 ]; then
        emit "${BLUE}--yes passed; proceeding without interactive confirmation.${RESET}"
        log_ok "step=confirm action=yes-flag"
        return 0
    fi

    # No --yes: require an interactive terminal (stdout is a TTY AND /dev/tty
    # is accessible). When stdout is a pipe or a non-terminal fd (the e2e
    # harness, CI, nohup, logged pipes), we must hard-abort — there is no
    # human at the other end to confirm the privileged change set.
    if [ ! -t 1 ] || [ ! -e /dev/tty ]; then
        printf '%s\n' "Aborting: no terminal and --yes not passed." >&2
        printf '%s\n' "  Re-run with --yes to proceed non-interactively:" >&2
        printf '%s\n' "      install.sh --yes [other options]" >&2
        log_fail "step=confirm action=abort reason=no-tty"
        exit 1
    fi

    printf 'Proceed with these privileged changes? [y/N] ' >/dev/tty
    read -r _answer </dev/tty || _answer=""
    case "$_answer" in
        [yY]|[yY][eE][sS])
            log_ok "step=confirm action=yes-interactive"
            emit ""
            ;;
        *)
            emit "${YELLOW}!${RESET} Aborted. No changes were made."
            log_ok "step=confirm action=no-interactive"
            exit 0
            ;;
    esac
}

# ----------------------------------------------------------------------------
# Step 16 — Build and execute the privileged child script.
#
# The parent script has gathered all the information needed. It now writes a
# temporary privileged shell script and runs it under a single `sudo sh`.
#
# Progress protocol: the child writes lines of the form
#   STEP <n> begin <label>
#   STEP <n> ok <label>
#   STEP <n> fail <label>
# to a FIFO at $PRIV_PROGRESS_FIFO. The parent reads these and prints them
# as plain lines. The child's actual command stdout/stderr goes to
# INSTALL_LOG so the progress channel stays clean.
#
# All resolved values (paths, operator name, version, etc.) are passed to the
# child as positional arguments to avoid environment inheritance issues.
# ----------------------------------------------------------------------------

# _priv_append_log — write text to INSTALL_LOG from the privileged child.
# Defined as a shell function embedded in the child script.
#
# _priv_step_emit — write a STEP progress line to the FIFO from the child.
# Defined as a shell function embedded in the child script.

write_priv_script() {
    PRIV_PROGRESS_FIFO="$TMPDIR_INSTALL/priv-progress.fifo"
    mkfifo "$PRIV_PROGRESS_FIFO"
    PRIV_SCRIPT="$TMPDIR_INSTALL/priv-child.sh"

    # Escape values for embedding as single-quoted shell strings.
    # Single-quote wrapping: replace ' with '\''.
    _sq() { printf '%s' "$1" | sed "s/'/'\\''/g"; }

    # Serialise the PLAN_BINARIES value: replace ; with a placeholder
    # character that is safe in a single-quoted string, then unsub in child.
    # We use a tab character as a field separator in the plan encoding.
    _plan_bins_esc=$(_sq "$PLAN_BINARIES")
    _users_conf_esc=$(_sq "$PLAN_USERS_CONF_CONTENT")
    _bridge_conf_esc=$(_sq "$PLAN_BRIDGE_CONF_APPEND")
    # Capture test-hook variable from parent's environment (if set) so
    # the privileged child receives it even though sudo strips the env.
    _fail_after_esc=$(_sq "${SANDBOX_INSTALL_PRIV_CHILD_FAIL_AFTER:-}")
    _fail_before_fifo_esc=$(_sq "${SANDBOX_INSTALL_PRIV_CHILD_FAIL_BEFORE_FIFO:-}")

    cat > "$PRIV_SCRIPT" <<PRIV_SCRIPT_EOF
#!/bin/sh
# privileged child — runs as root under a single sudo invocation.
# Arguments: OPERATOR PROGRESS_FIFO INSTALL_LOG BASE_DIR_HINT SANDBOX_UID_HINT
set -eu

_OPERATOR="\$1"
_FIFO="\$2"
_LOG="\$3"
_BASE_DIR_HINT="\$4"
_SANDBOX_UID_HINT="\$5"

# BEGIN_TEST_ENV — stripped from published install.sh at docs-deploy time
#
# SANDBOX_INSTALL_PRIV_CHILD_FAIL_BEFORE_FIFO — test hook that causes the
# child to exit 1 before opening the FIFO at all. Used to verify that the
# parent does not hang when sudo fails or the child dies before the FIFO
# is opened (the anti-hang keepalive in run_priv_child covers this case).
# MUST NEVER BE SET IN PRODUCTION.
if [ '${_fail_before_fifo_esc}' = '1' ]; then
    exit 1
fi
# END_TEST_ENV

# Open the FIFO for writing on fd 3; keep it open for the entire child
# lifetime so the parent read loop sees a single continuous stream
# and does not hit spurious EOF between individual step writes.
exec 3> "\$_FIFO"

_n=0
_TOTAL_STEPS=13
# Tracks the label of the last successfully completed step (set by _step_ok).
# Used by _write_checkpoint to populate last_completed_step correctly on
# failure checkpoints (the failing step should appear in failed_step, not
# in last_completed_step which must name an actually completed step).
_last_ok_step=""
_step_begin() {
    _n=\$((_n + 1))
    _label="\$1"
    printf 'STEP %s begin %s\n' "\$_n" "\$_label" >&3
}
_step_ok() {
    printf 'STEP %s ok %s\n' "\$_n" "\$_label" >&3
    _last_ok_step="\$_label"
}
_step_fail() {
    printf 'STEP %s fail %s\n' "\$_n" "\$_label" >&3
    # Write a failed-status checkpoint if BASE_DIR is resolved so uninstall
    # can act on it. _write_checkpoint is not yet defined here; we call it
    # after its definition below. This trampoline is overwritten once defined.
    _do_fail_checkpoint
    exec 3>&-
    exit 1
}
# Placeholder: before _write_checkpoint is defined, this is a no-op.
# Overwritten after _write_checkpoint is defined.
_do_fail_checkpoint() { :; }
_log() {
    ts=\$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s install.sh %s pid=%s\n' "\$ts" "\$*" "\$\$" >> "\$_LOG" 2>/dev/null || true
}

# _write_checkpoint — write install-state.json with the current accumulated
# provenance flags, status=in-progress (or complete on final call), and
# last_completed_step. Called after every _step_ok so a failed install
# leaves a state file that records what was applied.
#
# Args: \$1 = step-label just completed, \$2 = "complete" on final call (else omit)
#
# Before BASE_DIR is known (i.e. before the sandbox-user step finishes),
# we cannot write to the per-uid path. The first checkpoint call (after
# sandbox-user) both creates the directory and installs the file.
_write_checkpoint() {
    _cp_step="\$1"
    _cp_status="\${2:-in-progress}"
    _cp_installed_at=\$(date -u +%Y-%m-%dT%H:%M:%SZ)
    _cp_installed_by="\${_OPERATOR:-(direct-root)}"

    # Provenance monotonicity: read the prior state file (if present) and
    # OR the boolean we_* flags and union array fields with the current run's
    # values. This ensures that across resumed runs, any work done in a prior
    # partial run is still recorded as done (e.g. we_created_sandbox_user=true
    # must survive a re-run where PLAN_SANDBOX_USER=skip sets SANDBOX_USER_CREATED=0).
    _cp_prev_created_user=0
    _cp_prev_set_setuid=0
    _cp_prev_created_conf=0
    _cp_prev_ops_added=""
    _cp_prev_bridge_rules=""
    if [ -n "\$STATE_PATH" ] && [ -r "\$STATE_PATH" ] && command -v jq >/dev/null 2>&1; then
        _cp_prev_created_user=\$(jq -r '.we_created_sandbox_user // false' "\$STATE_PATH" 2>/dev/null | grep -c '^true\$' || true)
        _cp_prev_set_setuid=\$(jq -r '.we_set_bridge_helper_setuid // false' "\$STATE_PATH" 2>/dev/null | grep -c '^true\$' || true)
        _cp_prev_created_conf=\$(jq -r '.we_created_users_conf // false' "\$STATE_PATH" 2>/dev/null | grep -c '^true\$' || true)
        _cp_prev_ops_added=\$(jq -r '.operators_added_to_group // [] | .[]' "\$STATE_PATH" 2>/dev/null | head -n1 || true)
        _cp_prev_bridge_rules=\$(jq -r '.we_added_bridge_conf_rules // [] | .[]' "\$STATE_PATH" 2>/dev/null | head -n1 || true)
    fi

    # Merge: OR booleans (prior true wins), union non-empty strings for arrays.
    _cp_eff_created_user="\$SANDBOX_USER_CREATED"
    if [ "\$_cp_prev_created_user" -gt 0 ]; then _cp_eff_created_user=1; fi

    _cp_eff_set_setuid="\$WE_SET_BRIDGE_HELPER_SETUID"
    if [ "\$_cp_prev_set_setuid" -gt 0 ]; then _cp_eff_set_setuid=1; fi

    _cp_eff_created_conf="\$WE_CREATED_USERS_CONF"
    if [ "\$_cp_prev_created_conf" -gt 0 ]; then _cp_eff_created_conf=1; fi

    _cp_eff_ops="\$OPERATORS_ADDED"
    if [ -z "\$_cp_eff_ops" ] && [ -n "\$_cp_prev_ops_added" ]; then
        _cp_eff_ops="\$_cp_prev_ops_added"
    fi

    _cp_eff_bridge_rules="\$WE_ADDED_BRIDGE_CONF_RULES"
    if [ -z "\$_cp_eff_bridge_rules" ] && [ -n "\$_cp_prev_bridge_rules" ]; then
        _cp_eff_bridge_rules="\$_cp_prev_bridge_rules"
    fi

    # Accumulate provenance into JSON fragments.
    if [ -n "\$_cp_eff_ops" ]; then
        _cp_ops_json="[\$(json_str "\$_cp_eff_ops")]"
    else
        _cp_ops_json="[]"
    fi
    if [ -n "\$_cp_eff_bridge_rules" ]; then
        _cp_rules_json="[\$(json_str "\$_cp_eff_bridge_rules")]"
    else
        _cp_rules_json="[]"
    fi

    _cp_users_conf_sha="null"
    if [ "\$_cp_eff_created_conf" = "1" ] && [ -f /etc/sandboxd/users.conf ]; then
        _cp_h=\$(sha256sum /etc/sandboxd/users.conf | awk '{print \$1}')
        _cp_users_conf_sha=\$(json_str "\$_cp_h")
    fi
    if [ -n "\$MANIFEST_BUILD_SHA" ]; then
        _cp_manifest_sha_json=\$(json_str "\$MANIFEST_BUILD_SHA")
    else
        _cp_manifest_sha_json="null"
    fi
    if [ -n "\$TARBALL_SHA256" ]; then
        _cp_tarball_sha_json=\$(json_str "\$TARBALL_SHA256")
    else
        _cp_tarball_sha_json="null"
    fi

    # For status=failed checkpoints, record the last successfully completed
    # step separately from the failing step (tracked in _last_ok_step).
    _cp_last_ok_step="\${_last_ok_step:-}"
    if [ "\$_cp_status" = "failed" ]; then
        _cp_last_ok_val="\$_cp_last_ok_step"
        _cp_failed_step_val="\$_cp_step"
    else
        _cp_last_ok_val="\$_cp_step"
        _cp_failed_step_val=""
    fi

    _cp_staged="\$TMPDIR_INSTALL/install-state-cp.json"
    {
        printf '{\n'
        printf '  "bridge_helper_path_at_install": %s,\n' "\$(json_str "\$BRIDGE_HELPER")"
        printf '  "installed_arch": %s,\n'                "\$(json_str "\$ARCH")"
        printf '  "installed_at": %s,\n'                  "\$(json_str "\$_cp_installed_at")"
        printf '  "installed_by_operator": %s,\n'         "\$(json_str "\$_cp_installed_by")"
        printf '  "installed_version": %s,\n'             "\$(json_str "\$VERSION")"
        printf '  "last_completed_step": %s,\n'           "\$(json_str "\$_cp_last_ok_val")"
        if [ -n "\$_cp_failed_step_val" ]; then
            printf '  "failed_step": %s,\n'               "\$(json_str "\$_cp_failed_step_val")"
        fi
        printf '  "manifest_build_sha": %s,\n'            "\$_cp_manifest_sha_json"
        printf '  "operators_added_to_group": %s,\n'      "\$_cp_ops_json"
        printf '  "status": %s,\n'                        "\$(json_str "\$_cp_status")"
        printf '  "tarball_sha256": %s,\n'                "\$_cp_tarball_sha_json"
        printf '  "users_conf_sha256_at_install": %s,\n'  "\$_cp_users_conf_sha"
        printf '  "we_added_bridge_conf_rules": %s,\n'    "\$_cp_rules_json"
        printf '  "we_created_sandbox_user": %s,\n'       "\$(bool_lit "\$_cp_eff_created_user")"
        printf '  "we_created_users_conf": %s,\n'         "\$(bool_lit "\$_cp_eff_created_conf")"
        printf '  "we_set_bridge_helper_setuid": %s\n'    "\$(bool_lit "\$_cp_eff_set_setuid")"
        printf '}\n'
    } > "\$_cp_staged"

    # Only install to disk if BASE_DIR is resolved (after sandbox-user step).
    if [ -n "\$BASE_DIR" ]; then
        install -d -o root -g root -m 0755 /var/lib/sandboxd >> "\$_LOG" 2>/dev/null || true
        install -d -o sandbox -g sandbox -m 0750 "\$BASE_DIR" >> "\$_LOG" 2>/dev/null || true
        install -m 0640 -o sandbox -g sandbox "\$_cp_staged" "\$STATE_PATH" >> "\$_LOG" 2>/dev/null || true
    fi
}

# Now that _write_checkpoint is defined, override the placeholder so that
# _step_fail actually writes a failed-status checkpoint before exiting.
_do_fail_checkpoint() {
    _write_checkpoint "\${_label:-unknown}" "failed"
}

# Emit the total step count so the parent can compute N of M in failure reports.
printf 'TOTAL %s\n' "\$_TOTAL_STEPS" >&3

# Variables encoded from parent.
PLAN_SANDBOX_USER='$(_sq "$PLAN_SANDBOX_USER")'
PLAN_SANDBOX_UID_EXISTING='$(_sq "$PLAN_SANDBOX_UID_EXISTING")'
PLAN_GROUPS_ADD='$(_sq "$PLAN_GROUPS_ADD")'
PLAN_OPERATOR_ADD='$(_sq "$PLAN_OPERATOR_ADD")'
PLAN_ROUTE_HELPER_CAPS='$(_sq "$PLAN_ROUTE_HELPER_CAPS")'
PLAN_LIMA_HELPER_CAPS='$(_sq "$PLAN_LIMA_HELPER_CAPS")'
PLAN_BRIDGE_HELPER_SETUID='$(_sq "$PLAN_BRIDGE_HELPER_SETUID")'
PLAN_BRIDGE_CONF='$(_sq "$PLAN_BRIDGE_CONF")'
PLAN_BRIDGE_CONF_APPEND='$_bridge_conf_esc'
PLAN_USERS_CONF='$(_sq "$PLAN_USERS_CONF")'
PLAN_USERS_CONF_CONTENT='$_users_conf_esc'
PLAN_GATEWAY_IMAGE='$(_sq "$PLAN_GATEWAY_IMAGE")'
PLAN_BINARIES='$_plan_bins_esc'
PLAN_UNIT='$(_sq "$PLAN_UNIT")'
PLAN_LEGACY_MIGRATE='$(_sq "$PLAN_LEGACY_MIGRATE")'
PLAN_ROUTE_HELPER_PATH='$(_sq "$PLAN_ROUTE_HELPER_PATH")'
PLAN_LIMA_HELPER_PATH='$(_sq "$PLAN_LIMA_HELPER_PATH")'
PLAN_ROUTE_CAPS_STR='$(_sq "$PLAN_ROUTE_CAPS_STR")'
PLAN_LIMA_CAPS_STR='$(_sq "$PLAN_LIMA_CAPS_STR")'
PLAN_UNIT_DST='$(_sq "$PLAN_UNIT_DST")'
BRIDGE_HELPER='$(_sq "$BRIDGE_HELPER")'
VERSION='$(_sq "$VERSION")'
ARCH='$(_sq "$ARCH")'
STAGE='$(_sq "$STAGE")'
TMPDIR_INSTALL='$(_sq "$TMPDIR_INSTALL")'
TARBALL_SHA256='$(_sq "$TARBALL_SHA256")'
MANIFEST_BUILD_SHA='$(_sq "$MANIFEST_BUILD_SHA")'

# Helpers for JSON encoding of state file.
bool_lit() {
    if [ "\$1" = "1" ] || [ "\$1" = "true" ]; then printf 'true'; else printf 'false'; fi
}
json_str() {
    s=\$(printf '%s' "\$1" | sed -e 's/\\\\/\\\\\\\\/g' -e 's/"/\\\\"/g')
    printf '"%s"' "\$s"
}

# ----- Ensure install log is writable -----
if [ ! -e "\$_LOG" ]; then
    touch "\$_LOG" 2>/dev/null || true
    chmod 0640 "\$_LOG" 2>/dev/null || true
    chown root:root "\$_LOG" 2>/dev/null || true
fi

# Initialise all provenance flags before the first step so _write_checkpoint
# can safely reference them even before the step that sets each one runs.
SANDBOX_USER_CREATED=0
OPERATORS_ADDED=""
WE_SET_BRIDGE_HELPER_SETUID=0
WE_ADDED_BRIDGE_CONF_RULES=""
WE_CREATED_USERS_CONF=0
# BASE_DIR and STATE_PATH are set after sandbox-user resolves SANDBOX_UID.
BASE_DIR=""
STATE_PATH=""
SANDBOX_UID=""

# BEGIN_TEST_ENV — stripped from published install.sh at docs-deploy time
#
# SANDBOX_INSTALL_PRIV_CHILD_FAIL_AFTER — test hook that forces the
# privileged child to exit 1 immediately after the named step completes.
# Set to the step label (e.g. "sandbox-user") to simulate a mid-batch
# failure. MUST NEVER BE SET IN PRODUCTION — it intentionally leaves the
# install in a partial state.
_fail_after='$_fail_after_esc'
_priv_maybe_fail_after() {
    if [ -n "\$_fail_after" ] && [ "\$_fail_after" = "\$1" ]; then
        printf 'STEP %s fail %s (test-hook)\n' "\$_n" "\$1" >&3
        # Write a failed-status checkpoint so test assertions can inspect it.
        _write_checkpoint "\$1" "failed"
        exec 3>&-
        exit 1
    fi
}
# END_TEST_ENV

# ----- Step: sandbox user -----
_step_begin "sandbox-user"
SANDBOX_USER_CREATED=0
if [ "\$PLAN_SANDBOX_USER" = "create" ]; then
    useradd \\
        --system \\
        --user-group \\
        --no-create-home \\
        --home-dir /nonexistent \\
        --shell /usr/sbin/nologin \\
        --comment "sandboxd - isolated environment broker" \\
        sandbox >> "\$_LOG" 2>&1 || { _log "step=useradd action=fail status=fail"; _step_fail; }
    SANDBOX_USER_CREATED=1
    _log "step=useradd action=create status=ok"
else
    _log "step=useradd action=skip status=ok"
fi
if [ -n "\$PLAN_GROUPS_ADD" ]; then
    for _g in \$PLAN_GROUPS_ADD; do
        usermod -aG "\$_g" sandbox >> "\$_LOG" 2>&1 || true
        _log "step=usermod_group group=\$_g action=add status=ok"
    done
fi
# Resolve uid now that the user is guaranteed to exist. Must happen before
# _write_checkpoint so the checkpoint function has BASE_DIR available.
SANDBOX_UID=\$(id -u sandbox)
BASE_DIR="/var/lib/sandboxd/\$SANDBOX_UID"
STATE_PATH="\$BASE_DIR/.install-state.json"
_log "step=resolve_sandbox_uid uid=\$SANDBOX_UID base_dir=\$BASE_DIR status=ok"

_step_ok
_write_checkpoint "sandbox-user"
_priv_maybe_fail_after "sandbox-user"

# ----- Step: operator group add -----
_step_begin "operator-group-add"
OPERATORS_ADDED=""
if [ "\$PLAN_OPERATOR_ADD" = "add" ] && [ -n "\$_OPERATOR" ]; then
    usermod -aG sandbox "\$_OPERATOR" >> "\$_LOG" 2>&1 || { _log "step=operator_add action=fail status=fail"; _step_fail; }
    OPERATORS_ADDED="\$_OPERATOR"
    _log "step=operator_add operator=\$_OPERATOR action=add status=ok"
else
    _log "step=operator_add action=\$PLAN_OPERATOR_ADD status=ok"
fi
_step_ok
_write_checkpoint "operator-group-add"
_priv_maybe_fail_after "operator-group-add"

# ----- Step: install binaries -----
_step_begin "install-binaries"
_old_IFS="\$IFS"
IFS=";"
for _entry in \$PLAN_BINARIES; do
    IFS="\$_old_IFS"
    [ -z "\$_entry" ] && continue
    _action="\${_entry%%:*}"
    _rest="\${_entry#*:}"
    _dst="\${_rest%%:*}"
    if [ "\$_action" = "install" ]; then
        # Determine source path from destination.
        case "\$_dst" in
            /usr/local/libexec/sandboxd/sandboxd)
                _src="\$STAGE/bin/sandboxd" ;;
            /usr/local/bin/sandbox)
                _src="\$STAGE/bin/sandbox" ;;
            /usr/local/libexec/sandboxd/sandbox-route-helper)
                _src="\$STAGE/bin/sandbox-route-helper" ;;
            /usr/local/libexec/sandboxd/sandbox-lima-helper)
                _src="\$STAGE/bin/sandbox-lima-helper" ;;
            /usr/local/libexec/sandboxd/sandbox-guest)
                _src="\$STAGE/bin/sandbox-guest" ;;
            *)
                printf 'priv-child: unknown binary dst: %s\n' "\$_dst" >> "\$_LOG" 2>&1
                _step_fail
                ;;
        esac
        install -D -m 0755 -o root -g root "\$_src" "\$_dst" >> "\$_LOG" 2>&1 \
            || { _log "step=install_binary path=\$_dst action=fail status=fail"; _step_fail; }
        _sha=\$(sha256sum "\$_dst" | awk '{print \$1}')
        _log "step=install_binary path=\$_dst sha256=\$_sha action=install status=ok"
    else
        _log "step=install_binary path=\$_dst action=skip status=ok"
    fi
    IFS=";"
done
IFS="\$_old_IFS"
_step_ok
_write_checkpoint "install-binaries"
_priv_maybe_fail_after "install-binaries"

# ----- Step: setcap route-helper -----
_step_begin "setcap-route-helper"
if [ "\$PLAN_ROUTE_HELPER_CAPS" = "set" ]; then
    setcap "\$PLAN_ROUTE_CAPS_STR" "\$PLAN_ROUTE_HELPER_PATH" >> "\$_LOG" 2>&1 \
        || { _log "step=setcap caps=\$PLAN_ROUTE_CAPS_STR action=fail status=fail"; _step_fail; }
    _new=\$(getcap "\$PLAN_ROUTE_HELPER_PATH" 2>/dev/null | awk '{print \$NF}')
    if [ "\$_new" != "\$PLAN_ROUTE_CAPS_STR" ]; then
        _log "step=setcap caps=\$PLAN_ROUTE_CAPS_STR action=verify-fail got='\$_new' status=fail"
        _step_fail
    fi
    _log "step=setcap caps=\$PLAN_ROUTE_CAPS_STR action=set status=ok"
else
    _log "step=setcap caps=\$PLAN_ROUTE_CAPS_STR action=skip status=ok"
fi
_step_ok
_write_checkpoint "setcap-route-helper"
_priv_maybe_fail_after "setcap-route-helper"

# ----- Step: setcap lima-helper -----
_step_begin "setcap-lima-helper"
if [ "\$PLAN_LIMA_HELPER_CAPS" = "set" ]; then
    setcap "\$PLAN_LIMA_CAPS_STR" "\$PLAN_LIMA_HELPER_PATH" >> "\$_LOG" 2>&1 \
        || { _log "step=setcap caps=\$PLAN_LIMA_CAPS_STR action=fail status=fail"; _step_fail; }
    _new=\$(getcap "\$PLAN_LIMA_HELPER_PATH" 2>/dev/null | awk '{print \$NF}' | tr '+' '=')
    if [ "\$_new" != "cap_setuid=ep" ]; then
        _log "step=setcap caps=\$PLAN_LIMA_CAPS_STR action=verify-fail got='\$_new' status=fail"
        _step_fail
    fi
    _log "step=setcap caps=\$PLAN_LIMA_CAPS_STR action=set status=ok"
else
    _log "step=setcap caps=\$PLAN_LIMA_CAPS_STR action=skip status=ok"
fi
_step_ok
_write_checkpoint "setcap-lima-helper"
_priv_maybe_fail_after "setcap-lima-helper"

# ----- Step: bridge-helper setuid -----
_step_begin "bridge-helper-setuid"
WE_SET_BRIDGE_HELPER_SETUID=0
if [ "\$PLAN_BRIDGE_HELPER_SETUID" = "set" ]; then
    chmod u+s "\$BRIDGE_HELPER" >> "\$_LOG" 2>&1 \
        || { _log "step=bridge_helper_setuid action=fail status=fail"; _step_fail; }
    WE_SET_BRIDGE_HELPER_SETUID=1
    _log "step=bridge_helper_setuid path=\$BRIDGE_HELPER action=set we_set=1 status=ok"
else
    _log "step=bridge_helper_setuid path=\$BRIDGE_HELPER action=skip status=ok"
fi
_step_ok
_write_checkpoint "bridge-helper-setuid"
_priv_maybe_fail_after "bridge-helper-setuid"

# ----- Step: bridge.conf -----
_step_begin "bridge-conf"
WE_ADDED_BRIDGE_CONF_RULES=""
if [ "\$PLAN_BRIDGE_CONF" = "append" ]; then
    printf '%s\n' "\$PLAN_BRIDGE_CONF_APPEND" >> /etc/qemu/bridge.conf \
        || { _log "step=bridge_conf action=fail status=fail"; _step_fail; }
    WE_ADDED_BRIDGE_CONF_RULES="\$PLAN_BRIDGE_CONF_APPEND"
    _log "step=bridge_conf action=append rule='\$PLAN_BRIDGE_CONF_APPEND' status=ok"
elif [ "\$PLAN_BRIDGE_CONF" = "create" ]; then
    mkdir -p /etc/qemu >> "\$_LOG" 2>&1 \
        || { _log "step=bridge_conf mkdir action=fail status=fail"; _step_fail; }
    printf '%s\n' "\$PLAN_BRIDGE_CONF_APPEND" > /etc/qemu/bridge.conf \
        || { _log "step=bridge_conf write action=fail status=fail"; _step_fail; }
    chmod 0644 /etc/qemu/bridge.conf >> "\$_LOG" 2>&1 || true
    WE_ADDED_BRIDGE_CONF_RULES="\$PLAN_BRIDGE_CONF_APPEND"
    _log "step=bridge_conf action=create rule='\$PLAN_BRIDGE_CONF_APPEND' status=ok"
else
    _log "step=bridge_conf action=skip status=ok"
fi
_step_ok
_write_checkpoint "bridge-conf"
_priv_maybe_fail_after "bridge-conf"

# ----- Step: users.conf -----
_step_begin "users-conf"
WE_CREATED_USERS_CONF=0
if [ "\$PLAN_USERS_CONF" = "create" ]; then
    mkdir -p /etc/sandboxd >> "\$_LOG" 2>&1 \
        || { _log "step=users_conf mkdir action=fail status=fail"; _step_fail; }
    _staged="\$TMPDIR_INSTALL/users.conf"
    printf '%s\n' "\$PLAN_USERS_CONF_CONTENT" > "\$_staged" \
        || { _log "step=users_conf stage action=fail status=fail"; _step_fail; }
    install -m 0644 -o root -g root "\$_staged" /etc/sandboxd/users.conf >> "\$_LOG" 2>&1 \
        || { _log "step=users_conf install action=fail status=fail"; _step_fail; }
    WE_CREATED_USERS_CONF=1
    _log "step=users_conf action=create status=ok"
else
    _log "step=users_conf action=skip status=ok"
fi
_step_ok
_write_checkpoint "users-conf"
_priv_maybe_fail_after "users-conf"

# ----- Step: docker load gateway -----
_step_begin "docker-load-gateway"
_gateway_tag="sandbox-gateway:\$VERSION"
if [ "\$PLAN_GATEWAY_IMAGE" = "load" ]; then
    _image_path="\$STAGE/images/sandbox-gateway-\${VERSION}.tar"
    if [ ! -f "\$_image_path" ]; then
        _log "step=docker_load action=fail reason=missing-image status=fail"
        _step_fail
    fi
    docker load -i "\$_image_path" >> "\$_LOG" 2>&1 \
        || { _log "step=docker_load image=\$_gateway_tag action=fail status=fail"; _step_fail; }
    docker image inspect "\$_gateway_tag" >> "\$_LOG" 2>&1 \
        || { _log "step=docker_load action=verify-fail status=fail"; _step_fail; }
    _log "step=docker_load image=\$_gateway_tag action=load status=ok"
else
    _log "step=docker_load image=\$_gateway_tag action=skip status=ok"
fi
_step_ok
_write_checkpoint "docker-load-gateway"
_priv_maybe_fail_after "docker-load-gateway"

# ----- Step: migrate legacy state -----
_step_begin "migrate-legacy-state"
_legacy_dir="/var/lib/sandbox"
if [ "\$PLAN_LEGACY_MIGRATE" = "migrate" ]; then
    install -d -o root -g root -m 0755 /var/lib/sandboxd >> "\$_LOG" 2>&1 || true
    install -d -o sandbox -g sandbox -m 0750 "\$BASE_DIR" >> "\$_LOG" 2>&1 \
        || { _log "step=migrate_legacy action=fail status=fail"; _step_fail; }
    for _name in sessions.db sessions.db-wal sessions.db-shm .install-state.json .update.lock sessions events backups; do
        _src="\$_legacy_dir/\$_name"
        _dst="\$BASE_DIR/\$_name"
        if [ -e "\$_src" ]; then
            if [ -e "\$_dst" ]; then
                _log "step=migrate_legacy item=\$_name action=skip reason=dst-exists status=warn"
            else
                mv "\$_src" "\$_dst" >> "\$_LOG" 2>&1 \
                    || _log "step=migrate_legacy item=\$_name action=mv-fail status=warn"
                _log "step=migrate_legacy item=\$_name action=mv status=ok"
            fi
        fi
    done
    if rmdir "\$_legacy_dir" 2>/dev/null; then
        _log "step=migrate_legacy action=rmdir status=ok"
    else
        _remaining=\$(ls -A "\$_legacy_dir" 2>/dev/null | grep -v '^\.lima\$' || true)
        if [ -z "\$_remaining" ]; then
            _log "step=migrate_legacy action=skip-rmdir reason=lima-remnant status=warn"
        else
            _log "step=migrate_legacy action=skip-rmdir reason=unexpected-leftovers status=warn"
        fi
    fi
    _log "step=migrate_legacy action=migrate status=ok"
else
    _log "step=migrate_legacy action=skip status=ok"
fi
_step_ok
_write_checkpoint "migrate-legacy-state"
_priv_maybe_fail_after "migrate-legacy-state"

# ----- Step: install systemd unit -----
_step_begin "install-systemd-unit"
if [ "\$PLAN_UNIT" = "install" ]; then
    _unit_src="\$STAGE/systemd/sandboxd.service"
    _unit_rendered="\$TMPDIR_INSTALL/sandboxd.service.rendered"
    sed "s|@SANDBOX_BASE_DIR@|\$BASE_DIR|g" "\$_unit_src" > "\$_unit_rendered"
    if grep -q '@SANDBOX_BASE_DIR@' "\$_unit_rendered"; then
        _log "step=install_unit action=fail reason=placeholder-not-substituted status=fail"
        _step_fail
    fi
    install -m 0644 -o root -g root "\$_unit_rendered" "\$PLAN_UNIT_DST" >> "\$_LOG" 2>&1 \
        || { _log "step=install_unit action=fail status=fail"; _step_fail; }
    _sha=\$(sha256sum "\$PLAN_UNIT_DST" | awk '{print \$1}')
    _log "step=install_unit path=\$PLAN_UNIT_DST base_dir=\$BASE_DIR sha256=\$_sha action=install status=ok"
else
    _log "step=install_unit action=skip status=ok"
fi
_step_ok
_write_checkpoint "install-systemd-unit"
_priv_maybe_fail_after "install-systemd-unit"

# ----- Step: systemctl daemon-reload -----
_step_begin "daemon-reload"
systemctl daemon-reload >> "\$_LOG" 2>&1 \
    || { _log "step=daemon_reload action=fail status=fail"; _step_fail; }
_log "step=daemon_reload status=ok"
_step_ok
_write_checkpoint "daemon-reload"
_priv_maybe_fail_after "daemon-reload"

# ----- Step: write install-state (final, status=complete) -----
_step_begin "write-install-state"
# Write the final checkpoint with status=complete. _write_checkpoint handles
# directory creation and the atomic install to STATE_PATH.
_write_checkpoint "write-install-state" "complete"

# Sanity-check the installed file under jq.
if command -v jq >/dev/null 2>&1; then
    jq -e . "\$STATE_PATH" >> "\$_LOG" 2>&1 \
        || { _log "step=install_state action=fail reason=json-parse status=fail"; _step_fail; }
fi
_log "step=install_state path=\$STATE_PATH status=ok"
_step_ok

# Signal completion; close the fd so the parent's read loop sees EOF.
printf 'DONE\n' >&3
exec 3>&-
PRIV_SCRIPT_EOF

    chmod +x "$PRIV_SCRIPT"
}

# run_priv_child — invoke the privileged child under a single sudo,
# read the STEP progress lines from the FIFO, print them as plain lines,
# and emit a structured failure report if the child exits non-zero.
run_priv_child() {
    _priv_exit=0

    # The child needs BASE_DIR to be available (it resolves it after useradd).
    # Pass any pre-known hint; child ignores empty.
    _base_dir_hint="${BASE_DIR:-}"
    _sandbox_uid_hint="${SANDBOX_UID:-}"

    # Step history for the failure report. We accumulate labels and outcomes as
    # newline-separated strings (POSIX-safe; labels contain no newlines).
    _steps_done=""       # newline-sep list of completed step labels
    _failed_step=""      # label of the step that failed (if any)
    _failed_step_n=0     # step number that failed
    _total_steps=0       # from TOTAL N message
    _current_label=""    # label of the step currently in-progress

    # Anti-hang design: the FIFO consumer runs in a BACKGROUND subshell.
    # The main process:
    #   1. Opens the FIFO write-end (O_RDWR = non-blocking on FIFOs) on fd 4
    #      so the consumer's read-open returns immediately.
    #   2. Launches sudo in the background.
    #   3. Waits for sudo/child to finish.
    #   4. Closes fd 4, which delivers EOF to the consumer (even if the child
    #      died without writing anything — the sudo auth failure case).
    #   5. Waits for the consumer subshell.
    #   6. Reads step-history results the consumer wrote to a temp file.
    #
    # This architecture eliminates the deadlock where:
    #   - done < FIFO (O_RDONLY) blocks until a writer appears, AND
    #   - the writer (child) never opens the FIFO because sudo fails.
    # With fd 4 (O_RDWR) held open by the parent, the read-open in the
    # consumer subshell returns immediately, and the main process is free to
    # wait on the child and then close fd 4 to signal EOF.

    # Temp file for the consumer to report step history back to the main process.
    _step_history_file="$TMPDIR_INSTALL/step-history.txt"

    # Open FIFO O_RDWR (non-blocking on FIFOs) as the write-end keepalive.
    exec 4<> "$PRIV_PROGRESS_FIFO"

    # Launch child. sudo's password prompt (if needed) appears on /dev/tty.
    # stdout/stderr of the child go to the install log via redirection inside
    # the child script itself.
    sudo sh "$PRIV_SCRIPT" \
        "$OPERATOR_NAME" \
        "$PRIV_PROGRESS_FIFO" \
        "$INSTALL_LOG" \
        "$_base_dir_hint" \
        "$_sandbox_uid_hint" &
    _child_pid=$!

    # Launch the FIFO consumer in a background subshell. This is necessary to
    # avoid a deadlock: if we ran the consumer loop in the foreground (main
    # process), the main process would be blocked in `read` and could never
    # close fd 4 to signal EOF. With the consumer in a subshell:
    #   1. The subshell reads the FIFO until DONE or EOF.
    #   2. The main process waits for the child (sudo), then closes fd 4.
    #   3. Closing fd 4 delivers EOF to the subshell's read, unblocking it.
    #   4. The subshell writes step-history to _step_history_file and exits.
    #   5. The main process reads the step-history file.
    (
        # Close the inherited write-end of the FIFO immediately. The consumer
        # only needs the read end. Without this, the consumer itself is a
        # writer of the FIFO, so FIFO EOF never arrives even after both the
        # child (fd 3) and the parent (fd 4) close their write-ends — the
        # consumer's own inherited fd 4 keeps the FIFO "open for writing" and
        # `read` blocks forever. Closing it here means the write-ends are
        # exactly {child fd 3, parent fd 4}; when both close the consumer sees
        # EOF and exits normally on both success and failure paths.
        exec 4>&-

        # Local checklist state (subshell-private).
        _cl_labels=""
        _cl_states=""
        _cl_rows=0

        _cl_add_row() {
            _car_lbl="$1"
            if [ -z "$_cl_labels" ]; then
                _cl_labels="$_car_lbl"
                _cl_states="pending"
            else
                _cl_labels="${_cl_labels}
${_car_lbl}"
                _cl_states="${_cl_states}
pending"
            fi
            _cl_rows=$((_cl_rows + 1))
        }

        _cl_set_state() {
            _css_idx="$1"
            _css_new="$2"
            _css_new_states=""
            _css_i=1
            while IFS= read -r _css_row; do
                [ -z "$_css_row" ] && continue
                if [ "$_css_i" -eq "$_css_idx" ]; then
                    _css_new_states="${_css_new_states}${_css_new}"
                else
                    _css_new_states="${_css_new_states}${_css_row}"
                fi
                _css_new_states="${_css_new_states}
"
                _css_i=$((_css_i + 1))
            done <<_CL_EOF
$_cl_states
_CL_EOF
            _cl_states="${_css_new_states%
}"
        }

        _cl_get_state() {
            _cgs_idx="$1"
            _cgs_i=1
            while IFS= read -r _cgs_row; do
                [ -z "$_cgs_row" ] && continue
                if [ "$_cgs_i" -eq "$_cgs_idx" ]; then
                    printf '%s' "$_cgs_row"
                    return 0
                fi
                _cgs_i=$((_cgs_i + 1))
            done <<_CGS_EOF
$_cl_states
_CGS_EOF
        }

        _cl_redraw() {
            [ "$RICH_UI" -ne 1 ] && return 0
            [ "$_cl_rows" -eq 0 ] && return 0
            printf '\033[%sA' "$_cl_rows"
            _crd_i=1
            while IFS= read -r _crd_lbl; do
                [ -z "$_crd_lbl" ] && continue
                _crd_state=$(_cl_get_state "$_crd_i")
                case "$_crd_state" in
                    ok)      _crd_icon="${GREEN}+${RESET}" ;;
                    fail)    _crd_icon="${RED}x${RESET}" ;;
                    active)  _crd_icon="${BLUE}>${RESET}" ;;
                    *)       _crd_icon="-" ;;
                esac
                printf '\r\033[K  %b %s\n' "$_crd_icon" "$_crd_lbl"
                _crd_i=$((_crd_i + 1))
            done <<_CL_LBL
$_cl_labels
_CL_LBL
        }

        # Local step-history state (written to file at end).
        _sh_steps_done=""
        _sh_failed_step=""
        _sh_failed_step_n=0
        _sh_total_steps=0

        while IFS= read -r _prog_line; do
            case "$_prog_line" in
                DONE)
                    break
                    ;;
                TOTAL\ *)
                    _sh_total_steps="${_prog_line#TOTAL }"
                    ;;
                STEP\ *\ begin\ *)
                    _current_label="${_prog_line#STEP * begin }"
                    if [ "$RICH_UI" -eq 1 ]; then
                        _sb_n="${_prog_line#STEP }"
                        _sb_n="${_sb_n%% *}"
                        if [ "$_cl_rows" -lt "$_sb_n" ]; then
                            _cl_add_row "$_current_label"
                            printf '  - %s\n' "$_current_label"
                        fi
                        _cl_set_state "$_sb_n" "active"
                        _cl_redraw
                    else
                        emit "  ${BLUE}...${RESET} $_current_label"
                    fi
                    ;;
                STEP\ *\ ok\ *)
                    _ok_label="${_prog_line#STEP * ok }"
                    _ok_n="${_prog_line#STEP }"
                    _ok_n="${_ok_n%% *}"
                    if [ -z "$_sh_steps_done" ]; then
                        _sh_steps_done="$_ok_label"
                    else
                        _sh_steps_done="${_sh_steps_done}
${_ok_label}"
                    fi
                    if [ "$RICH_UI" -eq 1 ]; then
                        _cl_set_state "$_ok_n" "ok"
                        _cl_redraw
                    else
                        emit "  ${GREEN}+${RESET} $_ok_label"
                    fi
                    ;;
                STEP\ *\ fail\ *)
                    _fail_raw="${_prog_line#STEP * fail }"
                    _fail_label="${_fail_raw% (test-hook)}"
                    _fail_n="${_prog_line#STEP }"
                    _fail_n="${_fail_n%% *}"
                    _sh_failed_step="$_fail_label"
                    _sh_failed_step_n="$_fail_n"
                    if [ "$RICH_UI" -eq 1 ]; then
                        _cl_set_state "$_fail_n" "fail"
                        _cl_redraw
                    else
                        emit "  ${RED}x${RESET} $_fail_label"
                    fi
                    ;;
                *)
                    ;;
            esac
        done < "$PRIV_PROGRESS_FIFO"

        # Write step-history to the temp file for the main process to read.
        # Format: tab-separated fields, one line each.
        # steps_done uses newlines internally; encode as base64 for safe transport.
        {
            printf 'total\t%s\n'       "$_sh_total_steps"
            printf 'failed_step\t%s\n' "$_sh_failed_step"
            printf 'failed_n\t%s\n'    "$_sh_failed_step_n"
            printf 'steps_done\t%s\n'  "$(printf '%s' "$_sh_steps_done" | base64 | tr -d '\n')"
        } > "$_step_history_file"
    ) &
    _consumer_pid=$!

    # Main process waits for the privileged child to finish.
    wait "$_child_pid" || _priv_exit=$?

    # Close the parent's write-end keeper. This delivers EOF to the consumer
    # subshell's read loop, so it exits even if the child wrote nothing
    # (e.g. sudo auth failure before the FIFO was opened by the child).
    exec 4>&-

    # Wait for the consumer subshell to finish writing the history file.
    wait "$_consumer_pid" || true

    # Read step-history back from the temp file.
    if [ -r "$_step_history_file" ]; then
        while IFS="	" read -r _sh_key _sh_val; do
            case "$_sh_key" in
                total)       _total_steps="$_sh_val" ;;
                failed_step) _failed_step="$_sh_val" ;;
                failed_n)    _failed_step_n="$_sh_val" ;;
                steps_done)
                    _steps_done=$(printf '%s' "$_sh_val" | base64 -d 2>/dev/null || true)
                    ;;
            esac
        done < "$_step_history_file"
    fi

    if [ "$_priv_exit" -ne 0 ]; then
        # Sync state paths regardless (child may have created the sandbox user).
        SANDBOX_UID=$(id -u sandbox 2>/dev/null || true)
        if [ -n "$SANDBOX_UID" ]; then
            BASE_DIR="/var/lib/sandboxd/$SANDBOX_UID"
            STATE_PATH="$BASE_DIR/.install-state.json"
        fi
        # In rich mode, capture the failure report to SUMMARY_FILE so it is
        # printed to real stdout after rmcup restores the primary screen.
        if [ "$RICH_UI" -eq 1 ] && [ -n "$SUMMARY_FILE" ]; then
            _print_failure_report "$_failed_step" "$_failed_step_n" \
                "$_total_steps" "$_steps_done" > "$SUMMARY_FILE"
            ui_leave_alt_screen "$SUMMARY_FILE"
        else
            _print_failure_report "$_failed_step" "$_failed_step_n" \
                "$_total_steps" "$_steps_done"
        fi
        log_fail "step=priv_child action=fail failed_step=${_failed_step:-unknown} exit=$_priv_exit"
        exit 1
    fi

    # Sync state back from child: read BASE_DIR and STATE_PATH from the
    # install-state.json the child wrote, keyed on the sandbox uid.
    SANDBOX_UID=$(id -u sandbox 2>/dev/null || true)
    if [ -n "$SANDBOX_UID" ]; then
        BASE_DIR="/var/lib/sandboxd/$SANDBOX_UID"
        STATE_PATH="$BASE_DIR/.install-state.json"
    fi
}

# _print_failure_report — print the structured failure report to stdout.
# Args: $1=failed_step_label, $2=failed_step_n, $3=total_steps, $4=done_list
_print_failure_report() {
    _fr_step="${1:-unknown}"
    _fr_n="${2:-?}"
    _fr_total="${3:-?}"
    _fr_done="${4:-}"

    emit ""
    emit "${RED}x${RESET} Install failed at step ${_fr_n} of ${_fr_total}: ${_fr_step}"
    emit ""

    if [ -n "$_fr_done" ]; then
        emit "  Steps applied (left in place — a re-run will skip them):"
        printf '%s\n' "$_fr_done" | while IFS= read -r _s; do
            [ -n "$_s" ] && emit "    ${GREEN}+${RESET} $_s"
        done
    else
        emit "  No steps were applied before the failure."
    fi
    emit ""
    emit "  Step that failed: ${RED}${_fr_step}${RESET}"
    emit ""
    emit "  Recovery: fix the root cause, then re-run install.sh with the"
    emit "  same arguments. The planning pass will re-detect completed work"
    emit "  and skip it — only the failed and subsequent steps will run."
    emit ""

    if [ -n "$STATE_PATH" ] && [ -r "$STATE_PATH" ]; then
        emit "  Partial install state: $STATE_PATH"
        emit "    (status=failed; we_* flags reflect what was applied)"
    fi
    emit "  Install log:           $INSTALL_LOG"
    emit ""
}

# ----------------------------------------------------------------------------
# Step 17 — Print next-steps.
# ----------------------------------------------------------------------------

print_next_steps() {
    # Determine whether operator was added (read from install-state.json).
    _ops_added=""
    if [ -r "$STATE_PATH" ]; then
        _ops_added=$(jq -r '.operators_added_to_group // [] | join(" ")' \
            "$STATE_PATH" 2>/dev/null || true)
    fi

    emit ""
    emit "${GREEN}+${RESET} sandboxd $VERSION installed."
    emit ""
    emit "Next:"
    if [ -n "$_ops_added" ]; then
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

    TMPDIR_INSTALL=$(mktemp -d "/var/tmp/sandbox-install.XXXXXX")
    SUMMARY_FILE=$(mktemp "/var/tmp/sandbox-install-summary.XXXXXX")
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

    # Detect operator identity (unprivileged parent).
    detect_operator

    # Planning pass: compute the minimal action list.
    compute_plan

    # Enter alt-screen before rendering the plan (rich mode only; no-op in plain).
    ui_enter_alt_screen

    # Render the plan for the operator to review.
    render_plan

    # Confirmation gate: operator must explicitly approve (or pass --yes).
    # Reads from /dev/tty so it works even inside the alt-screen.
    confirm_plan

    # Build the privileged child script.
    write_priv_script

    # Execute the single privileged child.
    run_priv_child

    # Capture the durable summary so it persists in scrollback after rmcup.
    if [ "$RICH_UI" -eq 1 ]; then
        print_next_steps > "$SUMMARY_FILE"
        ui_leave_alt_screen "$SUMMARY_FILE"
    else
        print_next_steps
    fi
}

main "$@"
