#!/bin/sh
# uninstall.sh — sandboxd uninstaller (POSIX shell).
#
# Usage:
#   curl -fsSL https://Koriit.github.io/sandboxd/uninstall.sh | bash -s -- --yes
#   curl -fsSL https://Koriit.github.io/sandboxd/uninstall.sh | bash -s -- --purge --yes
#
# Source of truth: scripts/uninstall.sh in the Koriit/sandboxd repo. The site
# build copies this file into site/public/ before the docs deploy.
#
# uninstall.sh reads /var/lib/sandbox/.install-state.json (created by
# install.sh) and removes only the artifacts install.sh recorded as its own.
# Without the state file, the script runs in best-effort mode: it removes
# the binaries, systemd unit, and route-helper, but leaves anything
# ambiguous (the sandbox user, bridge.conf rules, bridge-helper setuid).

set -eu

# ----------------------------------------------------------------------------
# Defaults.
# ----------------------------------------------------------------------------

INSTALL_LOG="/var/log/sandbox-install.log"
STATE_PATH="/var/lib/sandbox/.install-state.json"
SCRIPT_NAME="uninstall.sh"
SOCK_PATH="/run/sandbox/sandboxd.sock"

PURGE=0
FORCE=0
YES=0
VERBOSE=0
QUIET=0
NO_COLOR=0

HAVE_STATE=0
WE_CREATED_SANDBOX_USER="false"
WE_SET_BH_SETUID="false"
BH_PATH=""
WE_CREATED_USERS_CONF="false"
USERS_CONF_SHA_AT_INSTALL=""
ADDED_BRIDGE_RULES=""
OPS_ADDED=""
INSTALLED_VERSION=""

RED=""
GREEN=""
YELLOW=""
RESET=""

REMOVED_ITEMS=""

# ----------------------------------------------------------------------------
# Helpers.
# ----------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: uninstall.sh [OPTIONS]

Uninstall sandboxd, reversing the changes recorded by install.sh.

Options:
  --purge       Also delete /var/lib/sandbox/, the sandbox user, operator
                group memberships, sandboxd.service.d/ drop-ins, and the
                gateway docker image. Prompts unless --yes.
  --force       Proceed even if active sessions exist (default: refuse).
  --yes         Skip every confirmation prompt.
  --verbose     Echo every command before invocation.
  --quiet       Suppress non-error output.
  --no-color    Force plain text output.
  --help        Print this message and exit.

By default uninstall.sh removes only binaries, the systemd unit, the
route-helper, and any tracked install-time changes recorded in
${STATE_PATH}. State at /var/lib/sandbox/ and the sandbox user are
preserved; pass --purge to remove them.
EOF
}

emit() {
    if [ "$QUIET" -eq 0 ]; then
        printf '%b\n' "$*"
    fi
}

log_line() {
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    line="$ts $SCRIPT_NAME $* pid=$$"
    if [ -w "$INSTALL_LOG" ] || { [ ! -e "$INSTALL_LOG" ] && [ -w "$(dirname "$INSTALL_LOG")" ]; }; then
        printf '%s\n' "$line" >> "$INSTALL_LOG" 2>/dev/null || true
    else
        printf '%s\n' "$line" | sudo -k tee -a "$INSTALL_LOG" >/dev/null 2>&1 || true
    fi
}

log_ok()   { log_line "$*" "status=ok"; }
log_warn() { log_line "$*" "status=warn"; }
log_fail() { log_line "$*" "status=fail"; }

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
        RESET=$(printf '\033[0m')
    else
        RED=""
        GREEN=""
        YELLOW=""
        RESET=""
    fi
}

record_removed() {
    if [ -z "$REMOVED_ITEMS" ]; then
        REMOVED_ITEMS="$1"
    else
        REMOVED_ITEMS="$REMOVED_ITEMS
$1"
    fi
}

# ----------------------------------------------------------------------------
# Step 1 — Arg parsing.
# ----------------------------------------------------------------------------

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --purge)    PURGE=1; shift ;;
            --force)    FORCE=1; shift ;;
            --yes)      YES=1;   shift ;;
            --verbose)  VERBOSE=1; shift ;;
            --quiet)    QUIET=1; shift ;;
            --no-color) NO_COLOR=1; shift ;;
            --help|-h)  usage; exit 0 ;;
            *)
                printf 'uninstall.sh: unknown option: %s\n' "$1" >&2
                printf 'Try --help.\n' >&2
                exit 2
                ;;
        esac
    done

    if [ "$VERBOSE" -eq 1 ]; then
        set -x
    fi

    log_ok "step=parse_args purge=$PURGE force=$FORCE yes=$YES"
}

# ----------------------------------------------------------------------------
# Step 2 — Refuse if sessions are active.
# ----------------------------------------------------------------------------

check_active_sessions() {
    if [ ! -S "$SOCK_PATH" ]; then
        log_ok "step=session_check active=0 reason=no-socket"
        return 0
    fi
    if ! command -v sandbox >/dev/null 2>&1; then
        log_warn "step=session_check action=skip reason=cli-missing"
        return 0
    fi
    if ! command -v jq >/dev/null 2>&1; then
        log_warn "step=session_check action=skip reason=jq-missing"
        return 0
    fi
    active=$(sandbox session ls --output json 2>/dev/null | jq 'length // 0' 2>/dev/null || echo 0)
    if [ "${active:-0}" -gt 0 ] && [ "$FORCE" -eq 0 ]; then
        log_fail "step=session_check active=$active force=0 action=refuse"
        emit "${RED}x${RESET} Active sessions exist ($active). Stop them first:"
        emit "    sandbox session ls"
        emit "    sandbox session rm <id>"
        emit "Or use --force to proceed anyway."
        exit 1
    fi
    if [ "${active:-0}" -gt 0 ]; then
        emit "${YELLOW}!${RESET} --force: proceeding with $active active session(s); resources may leak."
        log_warn "step=session_check active=$active force=1 action=proceed"
    else
        log_ok "step=session_check active=0"
    fi
}

# ----------------------------------------------------------------------------
# Step 3 — Read install state.
# ----------------------------------------------------------------------------

read_install_state() {
    if [ ! -r "$STATE_PATH" ]; then
        log_warn "step=read_state path=$STATE_PATH reason=missing fallback=best-effort"
        HAVE_STATE=0
        return 0
    fi
    if ! command -v jq >/dev/null 2>&1; then
        log_warn "step=read_state reason=jq-missing fallback=best-effort"
        HAVE_STATE=0
        return 0
    fi

    WE_CREATED_SANDBOX_USER=$(jq -r '.we_created_sandbox_user // false'     "$STATE_PATH")
    WE_SET_BH_SETUID=$(jq -r '.we_set_bridge_helper_setuid // false'        "$STATE_PATH")
    BH_PATH=$(jq -r '.bridge_helper_path_at_install // ""'                  "$STATE_PATH")
    WE_CREATED_USERS_CONF=$(jq -r '.we_created_users_conf // false'         "$STATE_PATH")
    USERS_CONF_SHA_AT_INSTALL=$(jq -r '.users_conf_sha256_at_install // ""' "$STATE_PATH")
    ADDED_BRIDGE_RULES=$(jq -r '.we_added_bridge_conf_rules // [] | .[]'    "$STATE_PATH")
    OPS_ADDED=$(jq -r '.operators_added_to_group // [] | .[]'               "$STATE_PATH")
    INSTALLED_VERSION=$(jq -r '.installed_version // ""'                    "$STATE_PATH")
    HAVE_STATE=1
    log_ok "step=read_state have_state=1 installed_version=$INSTALLED_VERSION"
}

# ----------------------------------------------------------------------------
# Step 4 — Stop and disable systemd unit.
# ----------------------------------------------------------------------------

stop_and_disable_unit() {
    if ! command -v systemctl >/dev/null 2>&1; then
        log_warn "step=systemctl_disable action=skip reason=no-systemctl"
        return 0
    fi
    state_enabled=$(systemctl is-enabled sandboxd 2>/dev/null || true)
    state_active=$(systemctl is-active sandboxd 2>/dev/null || true)

    case "$state_enabled" in
        enabled|static|enabled-runtime)
            sudo -k systemctl disable --now sandboxd 2>/dev/null || true
            log_ok "step=systemctl_disable action=disable"
            return 0
            ;;
    esac
    if [ "$state_active" = "active" ]; then
        sudo -k systemctl stop sandboxd 2>/dev/null || true
        log_ok "step=systemctl_stop action=stop"
        return 0
    fi
    log_ok "step=systemctl_disable action=skip reason=not-active"
}

# ----------------------------------------------------------------------------
# Step 5 — Remove systemd unit.
# ----------------------------------------------------------------------------

remove_systemd_unit() {
    unit=/etc/systemd/system/sandboxd.service
    if [ -f "$unit" ]; then
        sudo -k rm -f "$unit"
        if command -v systemctl >/dev/null 2>&1; then
            sudo -k systemctl daemon-reload 2>/dev/null || true
        fi
        record_removed "$unit"
        log_ok "step=remove_unit path=$unit action=rm"
    else
        log_ok "step=remove_unit action=skip reason=absent"
    fi
}

# ----------------------------------------------------------------------------
# Step 6 — Revert qemu-bridge-helper setuid.
# ----------------------------------------------------------------------------

revert_bridge_helper_setuid() {
    if [ "$HAVE_STATE" -eq 0 ]; then
        log_ok "step=revert_setuid action=skip reason=no-state"
        return 0
    fi
    if [ "$WE_SET_BH_SETUID" != "true" ]; then
        log_ok "step=revert_setuid action=skip reason=we-did-not-set-it"
        return 0
    fi
    if [ -z "$BH_PATH" ] || [ ! -e "$BH_PATH" ]; then
        log_ok "step=revert_setuid action=skip reason=helper-absent"
        return 0
    fi
    if [ -u "$BH_PATH" ]; then
        sudo -k chmod u-s "$BH_PATH"
        record_removed "setuid bit on $BH_PATH"
        log_ok "step=revert_setuid path=$BH_PATH action=unset"
    else
        log_ok "step=revert_setuid action=skip reason=already-not-setuid"
    fi
}

# ----------------------------------------------------------------------------
# Step 7 — Remove /etc/qemu/bridge.conf rules we added.
# ----------------------------------------------------------------------------

remove_bridge_conf_rules() {
    if [ "$HAVE_STATE" -eq 0 ]; then
        log_ok "step=bridge_conf action=skip reason=no-state"
        return 0
    fi
    if [ ! -f /etc/qemu/bridge.conf ]; then
        log_ok "step=bridge_conf action=skip reason=file-absent"
        return 0
    fi
    if [ -z "$ADDED_BRIDGE_RULES" ]; then
        log_ok "step=bridge_conf action=skip reason=no-rules-recorded"
        return 0
    fi

    tmp=$(mktemp)
    sudo -k cat /etc/qemu/bridge.conf | tee "$tmp" >/dev/null
    count=0
    # ADDED_BRIDGE_RULES is one rule per line.
    printf '%s\n' "$ADDED_BRIDGE_RULES" | while IFS= read -r rule; do
        [ -n "$rule" ] || continue
        grep -vxF -- "$rule" "$tmp" > "${tmp}.new" || true
        mv "${tmp}.new" "$tmp"
        count=$((count + 1))
        printf '%s\n' "$count"
    done > /dev/null

    if [ ! -s "$tmp" ]; then
        sudo -k rm -f /etc/qemu/bridge.conf
        record_removed "/etc/qemu/bridge.conf"
        log_ok "step=bridge_conf action=remove_file reason=empty"
    elif ! cmp -s "$tmp" /etc/qemu/bridge.conf; then
        sudo -k install -m 0644 -o root -g root "$tmp" /etc/qemu/bridge.conf
        record_removed "added rules in /etc/qemu/bridge.conf"
        log_ok "step=bridge_conf action=removed_lines"
    else
        log_ok "step=bridge_conf action=skip reason=no-matching-lines"
    fi
    rm -f "$tmp" "${tmp}.new"
}

# ----------------------------------------------------------------------------
# Step 8 — Remove /etc/sandboxd/users.conf (with backup if modified).
# ----------------------------------------------------------------------------

remove_users_conf() {
    if [ "$HAVE_STATE" -eq 0 ]; then
        log_ok "step=remove_users_conf action=skip reason=no-state"
        # Still try to remove an empty /etc/sandboxd directory below.
    elif [ "$WE_CREATED_USERS_CONF" = "true" ] && [ -f /etc/sandboxd/users.conf ]; then
        current_sha=$(sudo -k sha256sum /etc/sandboxd/users.conf 2>/dev/null | awk '{print $1}')
        backup_path=""
        if [ -n "$USERS_CONF_SHA_AT_INSTALL" ] \
           && [ -n "$current_sha" ] \
           && [ "$current_sha" != "$USERS_CONF_SHA_AT_INSTALL" ]; then
            home_dir="${HOME:-}"
            if [ -z "$home_dir" ] && [ -n "${SUDO_USER:-}" ]; then
                home_dir=$(getent passwd "$SUDO_USER" | cut -d: -f6 2>/dev/null || true)
            fi
            if [ -z "$home_dir" ]; then home_dir="/tmp"; fi
            backup_dir="$home_dir/sandboxd-uninstall-backup-$(date -u +%Y%m%dT%H%M%SZ)"
            mkdir -p "$backup_dir"
            sudo -k cp /etc/sandboxd/users.conf "$backup_dir/users.conf"
            backup_path="$backup_dir/users.conf"
            emit "${YELLOW}!${RESET} /etc/sandboxd/users.conf was modified since install."
            emit "  Backup saved to: $backup_path"
            log_warn "step=backup_users_conf to=$backup_path reason=modified-since-install"
        fi
        sudo -k rm -f /etc/sandboxd/users.conf
        record_removed "/etc/sandboxd/users.conf"
        log_ok "step=remove_users_conf backup=${backup_path:-none}"
    else
        log_ok "step=remove_users_conf action=skip reason=we-did-not-create-it"
    fi

    if [ -d /etc/sandboxd ]; then
        if [ -z "$(sudo -k ls -A /etc/sandboxd 2>/dev/null)" ]; then
            sudo -k rmdir /etc/sandboxd
            record_removed "/etc/sandboxd/ (empty)"
            log_ok "step=remove_users_conf_dir"
        fi
    fi
}

# ----------------------------------------------------------------------------
# Step 9 — Note that route-helper caps are removed with the binary.
# ----------------------------------------------------------------------------

defer_route_helper_caps() {
    helper=/usr/local/libexec/sandboxd/sandbox-route-helper
    if [ -x "$helper" ]; then
        log_ok "step=helper_caps action=defer reason=will-remove-binary"
    else
        log_ok "step=helper_caps action=skip reason=absent"
    fi
}

# ----------------------------------------------------------------------------
# Step 10 — Remove binaries.
# ----------------------------------------------------------------------------

remove_binaries() {
    for bin in /usr/local/bin/sandboxd \
               /usr/local/bin/sandbox \
               /usr/local/libexec/sandboxd/sandbox-route-helper
    do
        if [ -f "$bin" ]; then
            sudo -k rm -f "$bin"
            record_removed "$bin"
            log_ok "step=remove_binary path=$bin action=rm"
        else
            log_ok "step=remove_binary path=$bin action=skip reason=absent"
        fi
    done

    if [ -d /usr/local/libexec/sandboxd ]; then
        if [ -z "$(ls -A /usr/local/libexec/sandboxd 2>/dev/null)" ]; then
            sudo -k rmdir /usr/local/libexec/sandboxd
            log_ok "step=remove_libexec_dir"
        fi
    fi
}

# ----------------------------------------------------------------------------
# Step 11 — Purge: state dir, user, drop-ins, group memberships, image.
# ----------------------------------------------------------------------------

purge_step() {
    if [ "$PURGE" -ne 1 ]; then
        log_ok "step=purge action=skip reason=not-requested"
        return 0
    fi

    if [ "$YES" -eq 0 ]; then
        emit "${RED}!${RESET} --purge will delete:"
        emit "    /var/lib/sandbox/  (sessions DB, per-session CA material, audit logs)"
        if [ "$HAVE_STATE" -eq 1 ] && [ "$WE_CREATED_SANDBOX_USER" = "true" ]; then
            emit "    the 'sandbox' system user"
        fi
        if [ -n "$OPS_ADDED" ]; then
            emit "    'sandbox' group membership for: $(printf '%s' "$OPS_ADDED" | tr '\n' ' ')"
        fi
        emit "    /etc/systemd/system/sandboxd.service.d/  (drop-in customizations)"
        printf 'Type %sPURGE%s to confirm: ' "$YELLOW" "$RESET"
        read -r confirm
        [ "$confirm" = "PURGE" ] || die "Aborted."
    fi

    if [ -d /var/lib/sandbox ]; then
        sudo -k rm -rf /var/lib/sandbox
        record_removed "/var/lib/sandbox/"
        log_ok "step=purge_state path=/var/lib/sandbox"
    fi

    if [ "$HAVE_STATE" -eq 1 ] \
       && [ "$WE_CREATED_SANDBOX_USER" = "true" ] \
       && getent passwd sandbox >/dev/null 2>&1; then
        sudo -k userdel sandbox
        record_removed "system user: sandbox"
        log_ok "step=userdel"
        if getent group sandbox >/dev/null 2>&1; then
            sudo -k groupdel sandbox 2>/dev/null || true
            log_ok "step=groupdel"
        fi
    fi

    if [ -d /etc/systemd/system/sandboxd.service.d ]; then
        sudo -k rm -rf /etc/systemd/system/sandboxd.service.d
        record_removed "/etc/systemd/system/sandboxd.service.d/"
        log_ok "step=remove_drop_ins"
    fi

    if [ "$HAVE_STATE" -eq 1 ] && [ -n "$OPS_ADDED" ]; then
        printf '%s\n' "$OPS_ADDED" | while IFS= read -r op; do
            [ -n "$op" ] || continue
            if id -nG "$op" 2>/dev/null | tr ' ' '\n' | grep -qx sandbox; then
                sudo -k gpasswd -d "$op" sandbox >/dev/null 2>&1 || true
                log_ok "step=group_revoke operator=$op"
            fi
        done
    fi

    if [ -n "$INSTALLED_VERSION" ] && command -v docker >/dev/null 2>&1; then
        image_tag="sandbox-gateway:$INSTALLED_VERSION"
        if docker image inspect "$image_tag" >/dev/null 2>&1; then
            sudo -k docker image rm "$image_tag" >/dev/null 2>&1 || true
            record_removed "docker image: $image_tag"
            log_ok "step=docker_rmi image=$image_tag"
        fi
    fi
}

# ----------------------------------------------------------------------------
# Step 12 — Final state report.
# ----------------------------------------------------------------------------

final_report() {
    emit ""
    emit "${GREEN}+${RESET} sandboxd uninstalled."
    if [ -n "$REMOVED_ITEMS" ]; then
        emit ""
        emit "Removed:"
        printf '%s\n' "$REMOVED_ITEMS" | while IFS= read -r item; do
            [ -n "$item" ] || continue
            emit "  - $item"
        done
    fi
    if [ "$PURGE" -eq 0 ]; then
        emit ""
        emit "${YELLOW}Kept (run with --purge to remove):${RESET}"
        emit "  - /var/lib/sandbox/ (state, sessions DB, audit logs)"
        emit "  - 'sandbox' system user and group"
        emit "  - sandbox-gateway docker image"
    fi
    emit ""
    emit "Uninstall log: $INSTALL_LOG"
    log_ok "step=done"
}

# ----------------------------------------------------------------------------
# Main.
# ----------------------------------------------------------------------------

main() {
    parse_args "$@"
    setup_colors

    check_active_sessions
    read_install_state
    stop_and_disable_unit
    remove_systemd_unit
    revert_bridge_helper_setuid
    remove_bridge_conf_rules
    remove_users_conf
    defer_route_helper_caps
    remove_binaries
    purge_step
    final_report
}

main "$@"
