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
# uninstall.sh reads the install-state file created by install.sh
# (/var/lib/sandboxd/<sandbox-uid>/.install-state.json on a post-migration
# host; /var/lib/sandbox/.install-state.json on a legacy host) and removes
# only the artifacts install.sh recorded as its own. Without the state file,
# the script runs in best-effort mode: it removes the binaries, systemd unit,
# and route-helper, but leaves anything ambiguous (the sandbox user,
# bridge.conf rules, bridge-helper setuid).

set -eu

# ----------------------------------------------------------------------------
# Defaults.
# ----------------------------------------------------------------------------

# Install log destination. `$SANDBOXD_INSTALL_LOG` mirrors install.sh
# so the two scripts append to the same operator-overridden file
# when set; unset / empty falls back to the canonical
# `/var/log/sandbox-install.log`.
INSTALL_LOG="${SANDBOXD_INSTALL_LOG:-/var/log/sandbox-install.log}"
# STATE_PATH is resolved at runtime: per-uid path with legacy fallback.
# Computed by resolve_state_path() after argument parsing.
STATE_PATH=""
SCRIPT_NAME="uninstall.sh"
SOCK_PATH="/run/sandbox/sandboxd.sock"
# SANDBOX_UID is resolved before any userdel so the uid is still known.
SANDBOX_UID=""

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

RICH_UI=0
PHASE_CMD_FIFO=""
PRIV_PROGRESS_FIFO=""
PRIV_SCRIPT=""
TMPDIR_UNINSTALL=""
SUMMARY_FILE=""
_phase_reader_pid=0
_consumer_pid=0

REMOVED_ITEMS=""

# ----------------------------------------------------------------------------
# Helpers.
# ----------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: uninstall.sh [OPTIONS]

Uninstall sandboxd, reversing the changes recorded by install.sh.

Options:
  --purge       Also delete the sandbox daemon's per-uid state directory
                (/var/lib/sandboxd/<sandbox-uid>/), the sandbox user,
                operator group memberships, the gateway docker image, and
                /etc/systemd/system/sandboxd.service.d/.
                Prompts unless --yes.
  --force       Proceed even if sandboxd is running (default: refuse).
                A per-session active-session probe lands with
                'sandbox update' in a future release; for now the check
                is coarse (any running daemon).
  --yes         Skip every confirmation prompt.
  --verbose     Echo every command before invocation.
  --quiet       Suppress non-error output.
  --no-color    Force plain text output.
  --help        Print this message and exit.

Environment variables:
  SANDBOXD_INSTALL_LOG      Override the install-log path (default
                            /var/log/sandbox-install.log). Mirrors
                            install.sh so both scripts append to the
                            same file under an operator override.

By default uninstall.sh removes only binaries, the systemd unit, the
route-helper, and any tracked install-time changes recorded in the
install-state file. The per-uid state directory and the sandbox user
are preserved; pass --purge to remove them.
EOF
}

__sandbox_ui_sh_resolve() {
    if [ -n "${SANDBOX_UI_SH:-}" ] && [ -r "$SANDBOX_UI_SH" ]; then
        printf '%s' "$SANDBOX_UI_SH"
        return 0
    fi
    case "$0" in
        */*)
            __ui_script_dir=$(dirname -- "$0")
            if [ -r "$__ui_script_dir/ui.sh" ]; then
                printf '%s' "$__ui_script_dir/ui.sh"
                return 0
            fi
            ;;
    esac
    if [ -r "./ui.sh" ]; then
        printf '%s' "./ui.sh"
        return 0
    fi
    return 1
}
# BEGIN_INLINE ui.sh
__sandbox_ui_sh_path=$(__sandbox_ui_sh_resolve) || {
    printf 'ui.sh not found next to this script. If you are running from a local\n' >&2
    printf 'checkout, ensure scripts/ui.sh is present. If you fetched this file\n' >&2
    printf 'directly, use the published self-contained uninstaller:\n' >&2
    printf '  curl -fsSL https://Koriit.github.io/sandboxd/uninstall.sh | sh\n' >&2
    exit 1
}
# shellcheck source=scripts/ui.sh
. "$__sandbox_ui_sh_path"
# END_INLINE ui.sh

record_removed() {
    if [ -z "$REMOVED_ITEMS" ]; then
        REMOVED_ITEMS="$1"
    else
        REMOVED_ITEMS="$REMOVED_ITEMS
$1"
    fi
}

die() {
    msg="$1"
    if [ "$RICH_UI" -eq 1 ] && [ -n "$SUMMARY_FILE" ]; then
        ui_die_report "$msg" "fix the root cause, then re-run uninstall.sh." "Uninstall log: ${INSTALL_LOG}"
    else
        emit "${RED}x${RESET} ${msg}"
    fi
    log_fail "step=die error='${msg}'"
    exit 1
}

detect_tty() {
    ui_detect_tty
    tty_state="no"
    color_state="no"
    rich_state="no"
    if [ -t 1 ]; then tty_state="yes"; fi
    if [ -n "$GREEN" ]; then color_state="yes"; fi
    if [ "$RICH_UI" -eq 1 ]; then rich_state="yes"; fi
    log_ok "step=tty_detect tty=$tty_state color=$color_state rich=$rich_state"
}

cleanup_tmpdir() {
    _ct_exit=$?
    if [ "$_phase_reader_pid" -gt 0 ]; then
        kill "$_phase_reader_pid" 2>/dev/null || true
        wait "$_phase_reader_pid" 2>/dev/null || true
    fi
    if [ "$_consumer_pid" -gt 0 ]; then
        kill "$_consumer_pid" 2>/dev/null || true
        wait "$_consumer_pid" 2>/dev/null || true
    fi
    ui_teardown
    if [ "$_ct_exit" -ne 0 ]; then
        if [ -n "$SUMMARY_FILE" ] && [ -s "$SUMMARY_FILE" ]; then
            cat "$SUMMARY_FILE"
        fi
        printf '\n'
        printf 'uninstall failed (exit %s) — see %s\n' "$_ct_exit" "${INSTALL_LOG:-/var/log/sandboxd-uninstall.log}"
    fi
    if [ -n "$TMPDIR_UNINSTALL" ] && [ -d "$TMPDIR_UNINSTALL" ]; then
        rm -rf "$TMPDIR_UNINSTALL"
    fi
    if [ -n "$SUMMARY_FILE" ] && [ -f "$SUMMARY_FILE" ]; then
        rm -f "$SUMMARY_FILE"
    fi
    # Clear the sudo timestamp on exit so no usable credential cache lingers
    # after uninstall completes or aborts.
    sudo -K 2>/dev/null || true
}

# Phase lists for the rich-UI checklist.
UI_ANALYZE_PHASES="check-daemon
read-state"

# Remove phases: base set always present, purge phases appended when PURGE=1.
# The final list is assembled by write_priv_script when PURGE is known.
UI_REMOVE_PHASES_BASE="stop-disable-unit
remove-systemd-unit
revert-bridge-helper-setuid
remove-bridge-conf-rules
remove-users-conf
remove-binaries"

UI_REMOVE_PHASES_PURGE="purge-state
purge-user
purge-group
purge-image
purge-service-drop-in"

# ----------------------------------------------------------------------------
# Resolve the install-state path.
#
# The install-state marker lives at /var/lib/sandboxd/<sandbox-uid>/.install-state.json
# on a post-migration host. For hosts that ran install.sh before the migration
# landed, it may still be at /var/lib/sandbox/.install-state.json (legacy).
#
# SANDBOX_UID must be resolved BEFORE userdel removes the user — once the
# user is deleted, `id -u sandbox` fails. This function is called from main()
# early (before purge_step's userdel).
#
# POSIX sh only; no bashisms.
# ----------------------------------------------------------------------------

resolve_state_path() {
    if getent passwd sandbox >/dev/null 2>&1; then
        SANDBOX_UID=$(id -u sandbox)
        per_uid_path="/var/lib/sandboxd/$SANDBOX_UID/.install-state.json"
        if [ -r "$per_uid_path" ]; then
            STATE_PATH="$per_uid_path"
            log_ok "step=resolve_state_path path=$STATE_PATH reason=per-uid"
            return 0
        fi
    fi
    # Legacy fallback: pre-migration install.
    legacy_path="/var/lib/sandbox/.install-state.json"
    if [ -r "$legacy_path" ]; then
        STATE_PATH="$legacy_path"
        log_ok "step=resolve_state_path path=$STATE_PATH reason=legacy-fallback"
        return 0
    fi
    # Neither exists — best-effort mode (STATE_PATH stays empty; read_install_state
    # will set HAVE_STATE=0 and continue).
    STATE_PATH=""
    log_warn "step=resolve_state_path reason=not-found fallback=best-effort"
}

# ----------------------------------------------------------------------------
# Arg parsing.
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
# Refuse if the daemon is running.
#
# A finer-grained per-session probe (refuse only when actual sessions are
# active) will land alongside `sandbox update` in a future release; that
# work requires a daemon-side JSON-emitting subcommand that does not yet
# exist. Until then this check is intentionally coarse: any responsive
# daemon socket means refuse-without-force. That is a strict downgrade
# from "active sessions" to "any daemon running" — coarser, but actually
# working (the previous probe called a non-existent CLI subcommand and
# silently always succeeded).
# ----------------------------------------------------------------------------

socket_responsive() {
    # Returns 0 iff the daemon socket exists AND a /health probe succeeds.
    # curl is a hard prereq elsewhere in the operator-install path; if it
    # is missing here we fall back to socket-existence alone (the bare
    # presence of /run/sandbox/sandboxd.sock is a strong signal a daemon
    # is up — systemd removes it on stop via the unit's RuntimeDirectory).
    [ -S "$SOCK_PATH" ] || return 1
    if ! command -v curl >/dev/null 2>&1; then
        return 0
    fi
    curl --silent --show-error --max-time 2 \
        --unix-socket "$SOCK_PATH" \
        http://localhost/health \
        >/dev/null 2>&1
}

check_daemon_running() {
    if ! socket_responsive; then
        log_ok "step=daemon_check running=0 reason=no-socket-or-unresponsive"
        return 0
    fi
    if [ "$FORCE" -eq 0 ]; then
        log_fail "step=daemon_check running=1 force=0 action=refuse"
        _emit_daemon_refuse() {
            printf '%b\n' "${RED}x${RESET} sandboxd is running; stop it first:"
            printf '%s\n'  "    sudo systemctl stop sandboxd"
            printf '%s\n'  "Or pass --force to proceed anyway."
        }
        if [ "$RICH_UI" -eq 1 ] && [ -n "$SUMMARY_FILE" ]; then
            _emit_daemon_refuse > "$SUMMARY_FILE"
        else
            _emit_daemon_refuse
        fi
        exit 1
    fi
    emit "${YELLOW}!${RESET} --force: proceeding while sandboxd is running; sessions may leak."
    log_warn "step=daemon_check running=1 force=1 action=proceed"
}

# ----------------------------------------------------------------------------
# Read install state.
# ----------------------------------------------------------------------------

read_install_state() {
    if [ -z "$STATE_PATH" ] || [ ! -r "$STATE_PATH" ]; then
        log_warn "step=read_state path=${STATE_PATH:-(unresolved)} reason=missing fallback=best-effort"
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
# Plan computation and rendering.
# ----------------------------------------------------------------------------

# compute_plan assembles the human-readable plan for the pager/confirm screen.
# The plan is a newline-separated list stored in _UNINSTALL_PLAN_LINES.
_UNINSTALL_PLAN_LINES=""

_plan_append() {
    if [ -z "$_UNINSTALL_PLAN_LINES" ]; then
        _UNINSTALL_PLAN_LINES="$1"
    else
        _UNINSTALL_PLAN_LINES="$_UNINSTALL_PLAN_LINES
$1"
    fi
}

compute_plan() {
    _UNINSTALL_PLAN_LINES=""

    _plan_append "The following changes will be made (as root):"
    _plan_append ""

    # Systemd unit
    unit=/etc/systemd/system/sandboxd.service
    if [ -f "$unit" ]; then
        _plan_append "  stop + disable + remove  $unit"
    else
        _plan_append "  skip (absent)            $unit"
    fi

    # Bridge-helper setuid
    if [ "$HAVE_STATE" -eq 1 ] && [ "$WE_SET_BH_SETUID" = "true" ] \
       && [ -n "$BH_PATH" ] && [ -e "$BH_PATH" ] && [ -u "$BH_PATH" ]; then
        _plan_append "  revert setuid bit        $BH_PATH"
    else
        _plan_append "  skip (not set by us)     bridge-helper setuid"
    fi

    # Bridge.conf rules
    if [ "$HAVE_STATE" -eq 1 ] && [ -n "$ADDED_BRIDGE_RULES" ]; then
        _plan_append "  remove our rules from    /etc/qemu/bridge.conf"
    else
        _plan_append "  skip                     /etc/qemu/bridge.conf"
    fi

    # users.conf
    if [ "$HAVE_STATE" -eq 1 ] && [ "$WE_CREATED_USERS_CONF" = "true" ] \
       && [ -f /etc/sandboxd/users.conf ]; then
        _plan_append "  remove                   /etc/sandboxd/users.conf"
    else
        _plan_append "  skip (not created by us) /etc/sandboxd/users.conf"
    fi

    # Binaries
    _plan_append "  remove (if present)      /usr/local/bin/sandbox"
    _plan_append "  remove (if present)      /usr/local/libexec/sandboxd/ (binaries)"

    if [ "$PURGE" -eq 1 ]; then
        _plan_append ""
        _plan_append "  --purge was requested — the following will also be removed:"
        if [ -n "$SANDBOX_UID" ]; then
            _plan_append "  purge                    /var/lib/sandboxd/$SANDBOX_UID/"
        fi
        if [ -d /var/lib/sandbox ]; then
            _plan_append "  purge (legacy)           /var/lib/sandbox/"
        fi
        if [ "$HAVE_STATE" -eq 1 ] && [ "$WE_CREATED_SANDBOX_USER" = "true" ]; then
            _plan_append "  userdel                  sandbox"
        fi
        if [ -n "$OPS_ADDED" ]; then
            _ops_str=$(printf '%s' "$OPS_ADDED" | tr '\n' ' ')
            _plan_append "  revoke group membership  sandbox group for: $_ops_str"
        fi
        if [ -n "$INSTALLED_VERSION" ]; then
            _plan_append "  docker image rm          sandbox-gateway:$INSTALLED_VERSION"
        fi
        _plan_append "  remove (if present)      /etc/systemd/system/sandboxd.service.d/"
        _plan_append ""
        _plan_append "  WARNING: --purge is irreversible. All session data will be lost."
    else
        _plan_append ""
        _plan_append "  The following will be KEPT (pass --purge to remove them):"
        if [ -n "$SANDBOX_UID" ]; then
            _plan_append "  keep  /var/lib/sandboxd/$SANDBOX_UID/"
            _plan_append "        (remove with: sudo rm -rf /var/lib/sandboxd/$SANDBOX_UID/)"
        fi
        _plan_append "  keep  /etc/sandboxd/users.conf"
        _plan_append "        (remove with: sudo rm -f /etc/sandboxd/users.conf)"
        _plan_append "  keep  /etc/qemu/bridge.conf (our rules, if any)"
        _plan_append "        (remove with: sudo sed -i '/^allow virbr/d' /etc/qemu/bridge.conf)"
        _plan_append "  keep  /etc/systemd/system/sandboxd.service.d/"
        _plan_append "        (remove with: sudo rm -rf /etc/systemd/system/sandboxd.service.d/)"
        _plan_append "  keep  sandbox system group and user"
        _plan_append "        (remove with: sudo userdel sandbox && sudo groupdel sandbox)"
        if [ -n "$INSTALLED_VERSION" ]; then
            _plan_append "  keep  sandbox-gateway:$INSTALLED_VERSION (Docker image)"
            _plan_append "        (remove with: sudo docker image rm sandbox-gateway:$INSTALLED_VERSION)"
        else
            _plan_append "  keep  sandbox-gateway Docker image (version unknown)"
            _plan_append "        (remove with: sudo docker image rm sandbox-gateway:<version>)"
        fi
    fi

    _plan_append ""
    _plan_append "Uninstall log: $INSTALL_LOG"
}

render_plan() {
    emit ""
    printf '%s\n' "$_UNINSTALL_PLAN_LINES" | while IFS= read -r _pl; do
        emit "$_pl"
    done
    emit ""
}

confirm_plan() {
    if [ "$YES" -eq 1 ]; then
        emit "${BLUE}--yes passed; proceeding without interactive confirmation.${RESET}"
        return 0
    fi

    if [ ! -e /dev/tty ] || { [ "$RICH_UI" -ne 1 ] && [ ! -t 1 ]; }; then
        _emit_confirm_no_tty() {
            printf '%s\n' "Aborting: no terminal and --yes not passed."
            printf '%s\n' "  Re-run with --yes to proceed non-interactively:"
            printf '%s\n' "      uninstall.sh --yes [other options]"
        }
        if [ "$RICH_UI" -eq 1 ] && [ -n "$SUMMARY_FILE" ]; then
            _emit_confirm_no_tty > "$SUMMARY_FILE"
        else
            _emit_confirm_no_tty >&2
        fi
        log_fail "step=confirm action=abort reason=no-tty"
        exit 1
    fi

    if [ "$RICH_UI" -eq 1 ]; then
        ui_pager_confirm render_plan "sandboxd · review uninstall plan" || {
            if [ -n "$SUMMARY_FILE" ]; then
                printf '%b\n' "${YELLOW}!${RESET} Aborted. No changes were made." > "$SUMMARY_FILE"
            fi
            log_ok "step=confirm action=no-interactive"
            exit 1
        }
    else
        render_plan
        printf 'Proceed with these privileged changes? [y/N] ' >/dev/tty
        read -r _answer </dev/tty || _answer=""
        case "$_answer" in
            [yY]|[yY][eE][sS])
                emit ""
                ;;
            *)
                emit "${YELLOW}!${RESET} Aborted. No changes were made."
                log_ok "step=confirm action=no-interactive"
                exit 1
                ;;
        esac
    fi

    # PURGE two-step: after plan confirmation, require typing literal PURGE
    # when --purge is requested and --yes was not passed.
    #
    # This deliberately keeps two separate confirmation gates (plan review +
    # literal PURGE keyword) rather than collapsing them into one, to give users
    # a clear decision point on the irreversible state-deletion path.
    if [ "$PURGE" -eq 1 ]; then
        if [ "$RICH_UI" -eq 1 ]; then
            printf '\033[2J\033[H'
        fi
        emit "${RED}!${RESET} --purge is irreversible. Type PURGE to confirm deletion of all state data:"
        printf 'Type %sPURGE%s to confirm: ' "$YELLOW" "$RESET" >/dev/tty
        read -r _purge_confirm </dev/tty || _purge_confirm=""
        if [ "$_purge_confirm" != "PURGE" ]; then
            _emit_purge_decline() {
                printf '%b\n' "${YELLOW}!${RESET} Aborted. No changes were made."
            }
            if [ "$RICH_UI" -eq 1 ] && [ -n "$SUMMARY_FILE" ]; then
                _emit_purge_decline > "$SUMMARY_FILE"
            else
                _emit_purge_decline
            fi
            log_ok "step=confirm action=no-interactive reason=purge-not-confirmed"
            exit 1
        fi
        log_ok "step=confirm action=purge-confirmed"
    fi
}

# ----------------------------------------------------------------------------
# Build the privileged child script.
#
# The parent has gathered all information needed. It writes a temporary
# privileged shell script and runs it under a single `sudo sh`.
#
# Progress protocol: the child writes lines of the form
#   STEP <n> begin <label>
#   STEP <n> ok <label>
#   STEP <n> fail <label>
# to a FIFO at $PRIV_PROGRESS_FIFO. The parent reads these and drives the
# checklist live. The child's actual command stdout/stderr goes to INSTALL_LOG.
# ----------------------------------------------------------------------------

write_priv_script() {
    PRIV_PROGRESS_FIFO="$TMPDIR_UNINSTALL/priv-progress.fifo"
    mkfifo "$PRIV_PROGRESS_FIFO"
    PRIV_SCRIPT="$TMPDIR_UNINSTALL/priv-child.sh"

    # Escape values for embedding as single-quoted shell strings.
    _sq() { printf '%s' "$1" | sed "s/'/'\\''/g"; }

    # Embed multi-line state values safely.
    _added_bridge_rules_esc=$(_sq "$ADDED_BRIDGE_RULES")
    _ops_added_esc=$(_sq "$OPS_ADDED")
    # Capture test-hook variable from parent's environment (if set) so
    # the privileged child receives it even though sudo strips the env.
    _fail_after_esc=$(_sq "${SANDBOX_UNINSTALL_PRIV_CHILD_FAIL_AFTER:-}")

    # Compute total steps: base 6, plus 5 purge steps if --purge.
    _total_steps=6
    if [ "$PURGE" -eq 1 ]; then
        _total_steps=$((_total_steps + 5))
    fi

    # Assemble the remove-phase list for the rich checklist re-init.
    if [ "$PURGE" -eq 1 ]; then
        UI_REMOVE_PHASES="$UI_REMOVE_PHASES_BASE
$UI_REMOVE_PHASES_PURGE"
    else
        UI_REMOVE_PHASES="$UI_REMOVE_PHASES_BASE"
    fi

    # In rich mode, re-initialise phases for the Remove screen before child runs.
    if [ "$RICH_UI" -eq 1 ]; then
        ui_init_phases "$UI_REMOVE_PHASES"
        UI_CURRENT_HEADER="sandboxd · removing"
        ui_render_checklist
    fi

    cat > "$PRIV_SCRIPT" <<PRIV_SCRIPT_EOF
#!/bin/sh
# privileged child — runs as root under a single sudo invocation.
# Arguments: PROGRESS_FIFO INSTALL_LOG
set -eu

_FIFO="\$1"
_LOG="\$2"

# Open the FIFO for writing on fd 3; keep it open for the entire child
# lifetime so the parent read loop sees a single continuous stream
# and does not hit spurious EOF between individual step writes.
exec 3> "\$_FIFO"

# EXIT trap: when set -e aborts mid-step (an unguarded command failure), the
# child exits non-zero without ever calling _step_fail, so the parent never
# sees a STEP N fail token and falls back to "unknown" in the failure report.
# This trap catches those unguarded exits: if a step was in-flight (_step_inflight=1)
# and the exit status is non-zero, emit the fail token retroactively so the
# consumer can record the correct step name. Write the last 12 log lines to
# a temp file so the parent can surface them in the failure report.
trap '_xs=\$?
if [ "\$_xs" -ne 0 ] && [ "\${_step_inflight:-0}" -eq 1 ]; then
    printf "STEP %s fail %s\n" "\$_n" "\$_label" >&3 2>/dev/null || true
fi
if [ -n "\${TMPDIR_UNINSTALL:-}" ]; then
    tail -n 12 "\$_LOG" > "\$TMPDIR_UNINSTALL/failure-log-tail.txt" 2>/dev/null || true
    chmod a+r "\$TMPDIR_UNINSTALL/failure-log-tail.txt" 2>/dev/null || true
fi
exec 3>&- 2>/dev/null || true' EXIT

_n=0
_TOTAL_STEPS=$_total_steps
_step_inflight=0
_label=""
_step_begin() {
    _n=\$((_n + 1))
    _label="\$1"
    _step_inflight=1
    printf 'STEP %s begin %s\n' "\$_n" "\$_label" >&3
}
_step_ok() {
    _step_inflight=0
    printf 'STEP %s ok %s\n' "\$_n" "\$_label" >&3
}
_step_fail() {
    _step_inflight=0
    printf 'STEP %s fail %s\n' "\$_n" "\$_label" >&3
    exec 3>&-
    exit 1
}
_log() {
    ts=\$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s uninstall.sh %s pid=%s\n' "\$ts" "\$*" "\$\$" >> "\$_LOG" 2>/dev/null || true
}

# Emit total step count so the parent can compute N of M in failure reports.
printf 'TOTAL %s\n' "\$_TOTAL_STEPS" >&3

# Production no-op stub — shadowed by the real definition inside BEGIN_TEST_ENV
# when the test block is present. This survives the build strip so the
# published uninstaller does not call an undefined function under set -eu.
_priv_maybe_fail_after() { :; }

# BEGIN_TEST_ENV — stripped from published uninstall.sh at build time
#
# SANDBOX_UNINSTALL_PRIV_CHILD_FAIL_AFTER — test hook that forces the
# privileged child to exit 1 immediately after the named step completes.
# Set to the step label (e.g. "remove-binaries") to simulate a mid-batch
# failure. MUST NEVER BE SET IN PRODUCTION — it intentionally leaves the
# uninstall in a partial state.
_fail_after='$_fail_after_esc'
_priv_maybe_fail_after() {
    if [ -n "\$_fail_after" ] && [ "\$_fail_after" = "\$1" ]; then
        printf 'STEP %s fail %s (test-hook)\n' "\$_n" "\$1" >&3
        exec 3>&-
        exit 1
    fi
}
# END_TEST_ENV

# Variables encoded from parent.
TMPDIR_UNINSTALL='$(_sq "$TMPDIR_UNINSTALL")'
HAVE_STATE='$(_sq "$HAVE_STATE")'
WE_CREATED_SANDBOX_USER='$(_sq "$WE_CREATED_SANDBOX_USER")'
WE_SET_BH_SETUID='$(_sq "$WE_SET_BH_SETUID")'
BH_PATH='$(_sq "$BH_PATH")'
WE_CREATED_USERS_CONF='$(_sq "$WE_CREATED_USERS_CONF")'
USERS_CONF_SHA_AT_INSTALL='$(_sq "$USERS_CONF_SHA_AT_INSTALL")'
ADDED_BRIDGE_RULES='$_added_bridge_rules_esc'
OPS_ADDED='$_ops_added_esc'
INSTALLED_VERSION='$(_sq "$INSTALLED_VERSION")'
SANDBOX_UID='$(_sq "$SANDBOX_UID")'
PURGE='$(_sq "$PURGE")'

# Determine home-dir for users.conf backup (resolved in parent, passed in).
_HOME_DIR='$(_sq "${HOME:-}")'
_SUDO_USER='$(_sq "${SUDO_USER:-}")'

# ----- Step 1: stop-disable-unit -----
_step_begin "stop-disable-unit"
if ! command -v systemctl >/dev/null 2>&1; then
    _log "step=systemctl_disable action=skip reason=no-systemctl"
    _step_ok
else
    state_enabled=\$(systemctl is-enabled sandboxd 2>/dev/null || true)
    state_active=\$(systemctl is-active sandboxd 2>/dev/null || true)
    case "\$state_enabled" in
        enabled|static|enabled-runtime)
            systemctl disable --now sandboxd >> "\$_LOG" 2>&1 || true
            _log "step=systemctl_disable action=disable"
            ;;
        *)
            if [ "\$state_active" = "active" ]; then
                systemctl stop sandboxd >> "\$_LOG" 2>&1 || true
                _log "step=systemctl_stop action=stop"
            else
                _log "step=systemctl_disable action=skip reason=not-active"
            fi
            ;;
    esac
    _step_ok
fi
_priv_maybe_fail_after "\$_label"

# ----- Step 2: remove-systemd-unit -----
_step_begin "remove-systemd-unit"
_unit=/etc/systemd/system/sandboxd.service
if [ -f "\$_unit" ]; then
    rm -f "\$_unit"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >> "\$_LOG" 2>&1 || true
    fi
    _log "step=remove_unit path=\$_unit action=rm"
else
    _log "step=remove_unit action=skip reason=absent"
fi
_step_ok
_priv_maybe_fail_after "\$_label"

# ----- Step 3: revert-bridge-helper-setuid -----
_step_begin "revert-bridge-helper-setuid"
if [ "\$HAVE_STATE" -eq 0 ]; then
    _log "step=revert_setuid action=skip reason=no-state"
elif [ "\$WE_SET_BH_SETUID" != "true" ]; then
    _log "step=revert_setuid action=skip reason=we-did-not-set-it"
elif [ -z "\$BH_PATH" ] || [ ! -e "\$BH_PATH" ]; then
    _log "step=revert_setuid action=skip reason=helper-absent"
elif [ -u "\$BH_PATH" ]; then
    chmod u-s "\$BH_PATH" >> "\$_LOG" 2>&1 || { _log "step=revert_setuid action=fail"; _step_fail; }
    _log "step=revert_setuid path=\$BH_PATH action=unset"
else
    _log "step=revert_setuid action=skip reason=already-not-setuid"
fi
_step_ok
_priv_maybe_fail_after "\$_label"

# ----- Step 4: remove-bridge-conf-rules -----
_step_begin "remove-bridge-conf-rules"
if [ "\$HAVE_STATE" -eq 0 ]; then
    _log "step=bridge_conf action=skip reason=no-state"
elif [ ! -f /etc/qemu/bridge.conf ]; then
    _log "step=bridge_conf action=skip reason=file-absent"
elif [ -z "\$ADDED_BRIDGE_RULES" ]; then
    _log "step=bridge_conf action=skip reason=no-rules-recorded"
else
    _tmp_bc=\$(mktemp)
    _tmp_rules=\$(mktemp)
    cp /etc/qemu/bridge.conf "\$_tmp_bc"
    _orig_lines=\$(wc -l < "\$_tmp_bc" 2>/dev/null || printf '0')
    printf '%s\n' "\$ADDED_BRIDGE_RULES" | awk 'NF' > "\$_tmp_rules"
    _rules_count=\$(wc -l < "\$_tmp_rules" 2>/dev/null || printf '0')
    awk 'NR==FNR { drop[\$0]=1; next } !(\$0 in drop)' \
        "\$_tmp_rules" "\$_tmp_bc" > "\${_tmp_bc}.new"
    mv "\${_tmp_bc}.new" "\$_tmp_bc"
    if [ ! -s "\$_tmp_bc" ] && [ "\$_rules_count" -gt 0 ] \
       && [ "\$_rules_count" -eq "\$_orig_lines" ]; then
        rm -f /etc/qemu/bridge.conf
        _log "step=bridge_conf action=remove_file reason=empty rules=\$_rules_count"
    elif ! cmp -s "\$_tmp_bc" /etc/qemu/bridge.conf; then
        install -m 0644 -o root -g root "\$_tmp_bc" /etc/qemu/bridge.conf
        _log "step=bridge_conf action=removed_lines rules=\$_rules_count"
    else
        _log "step=bridge_conf action=skip reason=no-matching-lines"
    fi
    rm -f "\$_tmp_bc" "\$_tmp_rules" "\${_tmp_bc}.new" 2>/dev/null || true
fi
_step_ok
_priv_maybe_fail_after "\$_label"

# ----- Step 5: remove-users-conf -----
_step_begin "remove-users-conf"
if [ "\$HAVE_STATE" -eq 0 ]; then
    _log "step=remove_users_conf action=skip reason=no-state"
elif [ "\$WE_CREATED_USERS_CONF" = "true" ] && [ -f /etc/sandboxd/users.conf ]; then
    _current_sha=\$(sha256sum /etc/sandboxd/users.conf 2>/dev/null | awk '{print \$1}' || true)
    _backup_path=""
    if [ -n "\$USERS_CONF_SHA_AT_INSTALL" ] \
       && [ -n "\$_current_sha" ] \
       && [ "\$_current_sha" != "\$USERS_CONF_SHA_AT_INSTALL" ]; then
        _home_dir="\$_HOME_DIR"
        if [ -z "\$_home_dir" ] && [ -n "\$_SUDO_USER" ]; then
            _home_dir=\$(getent passwd "\$_SUDO_USER" | cut -d: -f6 2>/dev/null || true)
        fi
        if [ -z "\$_home_dir" ]; then _home_dir="/tmp"; fi
        _backup_dir="\$_home_dir/sandboxd-uninstall-backup-\$(date -u +%Y%m%dT%H%M%SZ)"
        mkdir -p "\$_backup_dir"
        cp /etc/sandboxd/users.conf "\$_backup_dir/users.conf"
        _backup_path="\$_backup_dir/users.conf"
        _log "step=backup_users_conf to=\$_backup_path reason=modified-since-install"
    fi
    rm -f /etc/sandboxd/users.conf
    _log "step=remove_users_conf backup=\${_backup_path:-none}"
else
    _log "step=remove_users_conf action=skip reason=we-did-not-create-it"
fi
if [ -d /etc/sandboxd ]; then
    if [ -z "\$(ls -A /etc/sandboxd 2>/dev/null)" ]; then
        rmdir /etc/sandboxd 2>/dev/null || true
        _log "step=remove_users_conf_dir"
    fi
fi
_step_ok
_priv_maybe_fail_after "\$_label"

# ----- Step 6: remove-binaries -----
# File capabilities on sandbox-route-helper and sandbox-lima-helper are
# dropped automatically when the files are unlinked (the kernel removes
# file capabilities on unlink).
_step_begin "remove-binaries"
for _bin in /usr/local/libexec/sandboxd/sandboxd \
            /usr/local/bin/sandbox \
            /usr/local/libexec/sandboxd/sandbox-route-helper \
            /usr/local/libexec/sandboxd/sandbox-lima-helper \
            /usr/local/libexec/sandboxd/sandbox-guest
do
    if [ -f "\$_bin" ]; then
        rm -f "\$_bin"
        _log "step=remove_binary path=\$_bin action=rm"
    else
        _log "step=remove_binary path=\$_bin action=skip reason=absent"
    fi
done
if [ -d /usr/local/libexec/sandboxd ]; then
    if [ -z "\$(ls -A /usr/local/libexec/sandboxd 2>/dev/null)" ]; then
        rmdir /usr/local/libexec/sandboxd 2>/dev/null || true
        _log "step=remove_libexec_dir"
    fi
fi
_step_ok
_priv_maybe_fail_after "\$_label"

PRIV_SCRIPT_EOF

    if [ "$PURGE" -eq 1 ]; then
        cat >> "$PRIV_SCRIPT" <<PURGE_EOF

# ----- Step 7: purge-state -----
_step_begin "purge-state"
if [ -n "\$SANDBOX_UID" ]; then
    _per_uid_dir="/var/lib/sandboxd/\$SANDBOX_UID"
    if [ -d "\$_per_uid_dir" ]; then
        rm -rf "\$_per_uid_dir"
        _log "step=purge_state path=\$_per_uid_dir"
    else
        _log "step=purge_state path=\$_per_uid_dir action=skip reason=absent"
    fi
else
    _log "step=purge_state action=skip reason=no-uid"
fi
if [ -d /var/lib/sandboxd ]; then
    if rmdir /var/lib/sandboxd 2>/dev/null; then
        _log "step=purge_sandboxd_root action=rmdir"
    else
        _log "step=purge_sandboxd_root action=skip reason=not-empty"
    fi
fi
if [ -d /var/lib/sandbox ]; then
    rm -rf /var/lib/sandbox
    _log "step=purge_state path=/var/lib/sandbox reason=legacy"
fi
_step_ok
_priv_maybe_fail_after "\$_label"

# ----- Step 8: purge-user -----
_step_begin "purge-user"
if getent passwd sandbox >/dev/null 2>&1; then
    # Guard: only remove the account if its GECOS field matches the one
    # written by install.sh, confirming it is the genuine sandboxd account
    # and not an unrelated 'sandbox' user that happened to exist on this host.
    _gecos=\$(getent passwd sandbox | cut -d: -f5 2>/dev/null || true)
    # Guard: if SANDBOX_UID was resolved in the parent, confirm it still matches
    # (protects against a replacement account at a different uid).
    _actual_uid=\$(id -u sandbox 2>/dev/null || true)
    _uid_ok=1
    if [ -n "\$SANDBOX_UID" ] && [ -n "\$_actual_uid" ] \
       && [ "\$_actual_uid" != "\$SANDBOX_UID" ]; then
        _uid_ok=0
    fi
    # Remove if we created the account, OR if both guards confirm it is the
    # genuine sandboxd account (covers upgrade-lineage hosts where the flag is
    # false but the GECOS + uid match unambiguously).
    if [ "\$WE_CREATED_SANDBOX_USER" = "true" ] \
       || { [ "\$_gecos" = "sandboxd - isolated environment broker" ] \
            && [ "\$_uid_ok" -eq 1 ]; }; then
        if [ "\$WE_CREATED_SANDBOX_USER" != "true" ]; then
            _log "step=userdel note=we-did-not-create-it removing-anyway reason=purge"
        fi
        userdel sandbox >> "\$_LOG" 2>&1 || { _log "step=userdel action=fail"; _step_fail; }
        _log "step=userdel action=remove"
    else
        _log "step=userdel action=skip reason=alien-account gecos_len=\${#_gecos} uid_ok=\${_uid_ok}"
    fi
else
    _log "step=userdel action=skip reason=absent"
fi
_step_ok
_priv_maybe_fail_after "\$_label"

# ----- Step 9: purge-group -----
_step_begin "purge-group"
# Revoke sandbox group membership for all current members before groupdel.
# Derive the member list from getent rather than relying solely on OPS_ADDED —
# the recorded list may be incomplete on upgrade-lineage hosts.
_live_members=\$(getent group sandbox 2>/dev/null | cut -d: -f4 | tr ',' '\n' | awk 'NF' || true)
# Merge recorded operators with live members so neither source is missed.
_all_ops=\$(
    { printf '%s\n' "\$OPS_ADDED"; printf '%s\n' "\$_live_members"; } \
    | awk 'NF' | sort -u
)
if [ -n "\$_all_ops" ]; then
    printf '%s\n' "\$_all_ops" | while IFS= read -r _op; do
        [ -n "\$_op" ] || continue
        if getent group sandbox 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -qx "\$_op"; then
            gpasswd -d "\$_op" sandbox >> "\$_LOG" 2>/dev/null && _gp_rc=0 || _gp_rc=\$?
            if [ "\$_gp_rc" -eq 0 ]; then
                _log "step=group_revoke operator=\$_op action=remove"
            else
                _log "step=group_revoke operator=\$_op action=fail rc=\$_gp_rc"
            fi
        fi
    done
fi
if getent group sandbox >/dev/null 2>&1; then
    groupdel sandbox >> "\$_LOG" 2>&1 && _gd_rc=0 || _gd_rc=\$?
    if [ "\$_gd_rc" -eq 0 ]; then
        _log "step=groupdel action=remove"
    else
        _log "step=groupdel action=fail rc=\$_gd_rc"
        _step_fail
    fi
else
    _log "step=groupdel action=skip reason=absent"
fi
_step_ok
_priv_maybe_fail_after "\$_label"

# ----- Step 10: purge-image -----
_step_begin "purge-image"
if command -v docker >/dev/null 2>&1; then
    # Tear down any running session artifacts before removing the image.
    # Active containers pin the image and cause the image rm to fail.
    # Session IDs are exactly 12 lowercase hex characters [0-9a-f].
    # Gateway containers:    sandbox-gw-<12hex>   (from gateway::container_name)
    # Lite containers:       sandbox-<12hex>      (from backend/container.rs)
    # Networks:              sandbox-net-<12hex>  (from network.rs)
    # Docker --filter name= is a substring match; grep anchors to the exact
    # scheme so unrelated containers/networks are never touched.
    _gw_ctrs=\$(docker ps -a --filter 'name=sandbox-gw-' --format '{{.Names}}' 2>/dev/null \
        | grep -E '^sandbox-gw-[0-9a-f]{12}\$' || true)
    _lite_ctrs=\$(docker ps -a --filter 'name=sandbox-' --format '{{.Names}}' 2>/dev/null \
        | grep -E '^sandbox-[0-9a-f]{12}\$' || true)
    _nets=\$(docker network ls --filter 'name=sandbox-net-' --format '{{.Name}}' 2>/dev/null \
        | grep -E '^sandbox-net-[0-9a-f]{12}\$' || true)

    for _ctr in \$_gw_ctrs \$_lite_ctrs; do
        [ -n "\$_ctr" ] || continue
        docker stop "\$_ctr" >> "\$_LOG" 2>&1 && _stop_rc=0 || _stop_rc=\$?
        docker rm -f "\$_ctr" >> "\$_LOG" 2>&1 && _rm_rc=0 || _rm_rc=\$?
        if [ "\$_stop_rc" -eq 0 ] && [ "\$_rm_rc" -eq 0 ]; then
            _log "step=docker_rm container=\$_ctr action=stop-rm"
        else
            _log "step=docker_rm container=\$_ctr action=fail stop_rc=\$_stop_rc rm_rc=\$_rm_rc"
        fi
    done

    for _net in \$_nets; do
        [ -n "\$_net" ] || continue
        docker network rm "\$_net" >> "\$_LOG" 2>&1 && _net_rc=0 || _net_rc=\$?
        if [ "\$_net_rc" -eq 0 ]; then
            _log "step=docker_network_rm network=\$_net action=remove"
        else
            _log "step=docker_network_rm network=\$_net action=fail rc=\$_net_rc"
        fi
    done

    if [ -n "\$INSTALLED_VERSION" ]; then
        _img_tag="sandbox-gateway:\$INSTALLED_VERSION"
        if docker image inspect "\$_img_tag" >/dev/null 2>&1; then
            docker image rm "\$_img_tag" >> "\$_LOG" 2>&1 || true
            _log "step=docker_rmi image=\$_img_tag"
        else
            _log "step=docker_rmi image=\$_img_tag action=skip reason=absent"
        fi
    else
        _log "step=docker_rmi action=skip reason=no-version"
    fi
else
    _log "step=docker_rmi action=skip reason=no-docker"
fi
_step_ok
_priv_maybe_fail_after "\$_label"

# ----- Step 11: purge-service-drop-in -----
_step_begin "purge-service-drop-in"
_dropin_dir="/etc/systemd/system/sandboxd.service.d"
if [ -d "\$_dropin_dir" ]; then
    rm -rf "\$_dropin_dir"
    _log "step=purge_service_drop_in path=\$_dropin_dir action=remove"
else
    _log "step=purge_service_drop_in path=\$_dropin_dir action=skip reason=absent"
fi
_step_ok
_priv_maybe_fail_after "\$_label"
PURGE_EOF
    fi

    # Append the DONE sentinel.
    printf 'printf '"'"'DONE\n'"'"' >&3\n' >> "$PRIV_SCRIPT"

}

# run_priv_child — invoke the privileged child under a single sudo,
# read the STEP progress lines from the FIFO, drive the checklist live,
# and emit a structured failure report if the child exits non-zero.
run_priv_child() {
    _priv_exit=0

    _step_history_file="$TMPDIR_UNINSTALL/step-history.txt"

    _steps_done=""
    _failed_step=""
    _failed_step_n=0
    _total_steps=0
    _phase_reader_pid=0

    # In rich mode, create a second FIFO so the consumer subshell can send
    # set_phase commands to the main process. The consumer cannot call set_phase
    # directly because subshell variable mutations are invisible to the parent.
    if [ "$RICH_UI" -eq 1 ]; then
        PHASE_CMD_FIFO="$TMPDIR_UNINSTALL/phase-cmd.fifo"
        mkfifo "$PHASE_CMD_FIFO"
        # Open phase-cmd FIFO O_RDWR as keepalive.
        exec 5<> "$PHASE_CMD_FIFO"
        # Launch the phase-command reader in the background.
        (
            exec 5>&-
            while IFS= read -r _pcmd; do
                case "$_pcmd" in
                    SET_PHASE\ *)
                        _pc_rest="${_pcmd#SET_PHASE }"
                        _pc_n="${_pc_rest%% *}"
                        _pc_st="${_pc_rest#* }"
                        set_phase "$_pc_n" "$_pc_st"
                        ui_service_winch
                        ;;
                    DONE_PHASES)
                        break
                        ;;
                esac
            done < "$PHASE_CMD_FIFO"
        ) &
        _phase_reader_pid=$!
    fi

    # Open progress FIFO O_RDWR (non-blocking on FIFOs) as write-end keepalive.
    exec 4<> "$PRIV_PROGRESS_FIFO"

    # Launch the privileged child. sudo's password prompt appears on /dev/tty.
    sudo sh "$PRIV_SCRIPT" \
        "$PRIV_PROGRESS_FIFO" \
        "$INSTALL_LOG" &
    _child_pid=$!

    # Launch FIFO consumer in a background subshell to avoid deadlock.
    (
        # Close inherited write-end of progress FIFO immediately.
        exec 4>&-
        # Close inherited phase-cmd FIFO keepalive fd.
        exec 5>&- 2>/dev/null || true
        # Open a persistent write fd 6 for phase commands (rich mode only).
        if [ "$RICH_UI" -eq 1 ]; then
            exec 6>"$PHASE_CMD_FIFO" 2>/dev/null || true
        fi

        _sh_steps_done=""
        _sh_removed_items=""
        _sh_failed_step=""
        _sh_failed_step_n=0
        _sh_total_steps=0
        _sh_current_label=""

        while IFS= read -r _prog_line; do
            case "$_prog_line" in
                DONE)
                    break
                    ;;
                TOTAL\ *)
                    _sh_total_steps="${_prog_line#TOTAL }"
                    ;;
                STEP\ *\ begin\ *)
                    _sh_current_label="${_prog_line#STEP * begin }"
                    _sb_n="${_prog_line#STEP }"
                    _sb_n="${_sb_n%% *}"
                    if [ "$RICH_UI" -eq 1 ]; then
                        printf 'SET_PHASE %s active\n' "$_sb_n" >&6 || true
                    else
                        emit "  ${BLUE}...${RESET} $_sh_current_label"
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
                    if [ -z "$_sh_removed_items" ]; then
                        _sh_removed_items="$_ok_label"
                    else
                        _sh_removed_items="${_sh_removed_items}
${_ok_label}"
                    fi
                    if [ "$RICH_UI" -eq 1 ]; then
                        printf 'SET_PHASE %s done\n' "$_ok_n" >&6 || true
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
                        printf 'SET_PHASE %s failed\n' "$_fail_n" >&6 || true
                    else
                        emit "  ${RED}x${RESET} $_fail_label"
                    fi
                    ;;
                *)
                    ;;
            esac
        done < "$PRIV_PROGRESS_FIFO"

        if [ "$RICH_UI" -eq 1 ]; then
            printf 'DONE_PHASES\n' >&6 || true
            exec 6>&-
        fi

        {
            printf 'total\t%s\n'         "$_sh_total_steps"
            printf 'failed_step\t%s\n'   "$_sh_failed_step"
            printf 'failed_n\t%s\n'      "$_sh_failed_step_n"
            printf 'steps_done\t%s\n'    "$(printf '%s' "$_sh_steps_done"    | base64 | tr -d '\n')"
            printf 'removed_items\t%s\n' "$(printf '%s' "$_sh_removed_items" | base64 | tr -d '\n')"
        } > "$_step_history_file"
    ) &
    _consumer_pid=$!

    # Main process waits for the privileged child to finish.
    wait "$_child_pid" || _priv_exit=$?

    # Close the write-end keeper, delivering EOF to the consumer.
    exec 4>&-

    # Wait for the consumer to finish writing history.
    wait "$_consumer_pid" || true

    # In rich mode, close phase-cmd FIFO and wait for the reader.
    if [ "$RICH_UI" -eq 1 ]; then
        exec 5>&-
        wait "$_phase_reader_pid" || true
        ui_animator_stop
    fi

    # Read step-history back.
    if [ -r "$_step_history_file" ]; then
        while IFS="	" read -r _sh_key _sh_val; do
            case "$_sh_key" in
                total)       _total_steps="$_sh_val" ;;
                failed_step) _failed_step="$_sh_val" ;;
                failed_n)    _failed_step_n="$_sh_val" ;;
                steps_done)
                    _steps_done=$(printf '%s' "$_sh_val" | base64 -d 2>/dev/null || true)
                    ;;
                removed_items)
                    _removed=$(printf '%s' "$_sh_val" | base64 -d 2>/dev/null || true)
                    printf '%s\n' "$_removed" | while IFS= read -r _item; do
                        [ -n "$_item" ] || continue
                        record_removed "$_item"
                    done
                    ;;
            esac
        done < "$_step_history_file"
    fi

    if [ "$_priv_exit" -ne 0 ]; then
        if [ "$RICH_UI" -eq 1 ] && [ -n "$SUMMARY_FILE" ]; then
            _print_failure_report "$_failed_step" "$_failed_step_n" \
                "$_total_steps" "$_steps_done" > "$SUMMARY_FILE"
        else
            _print_failure_report "$_failed_step" "$_failed_step_n" \
                "$_total_steps" "$_steps_done"
        fi
        log_fail "step=priv_child action=fail failed_step=${_failed_step:-unknown} exit=$_priv_exit"
        exit 1
    fi

    # On a plain uninstall the drop-in directory is left in place; the
    # purge-service-drop-in step inside the privileged batch removes it when
    # --purge is requested.
    if [ "$PURGE" -eq 0 ]; then
        log_ok "step=remove_drop_ins action=skip reason=not-purge"
    fi
}

# _print_failure_report — print the structured failure report to stdout.
# Args: $1=failed_step_label, $2=failed_step_n, $3=total_steps, $4=done_list
_print_failure_report() {
    _fr_step="${1:-unknown}"
    _fr_n="${2:-?}"
    _fr_total="${3:-?}"
    _fr_done="${4:-}"

    if [ "$RICH_UI" -eq 1 ] && [ "$UI_PHASE_COUNT" -gt 0 ]; then
        _pfr_i=1
        printf '%s\n' "$UI_PHASE_STATUSES" | while IFS= read -r _pfr_st; do
            [ -z "$_pfr_st" ] && continue
            _pfr_name=$(printf '%s\n' "$UI_PHASE_NAMES" \
                | awk -v n="$_pfr_i" 'NR==n{print; exit}')
            case "$_pfr_st" in
                done)   printf '%b\n' "  ${GREEN}✔${RESET} ${_pfr_name}" ;;
                failed) printf '%b\n' "  ${RED}✗${RESET} ${_pfr_name}" ;;
                active) printf '%b\n' "  ${RED}✗${RESET} ${_pfr_name}" ;;
            esac
            _pfr_i=$((_pfr_i + 1))
        done
        printf '\n'
        printf '%b\n' "${RED}✗${RESET} Uninstall failed: ${_fr_step}"
        printf '\n'
        printf '%b\n' "  Recovery: fix the root cause, then re-run uninstall.sh."
        printf '%b\n' "  The uninstaller is idempotent — already-removed items will be skipped."
        printf '\n'
        printf '%b\n' "  Uninstall log: ${INSTALL_LOG}"
        if [ -f "$TMPDIR_UNINSTALL/failure-log-tail.txt" ] \
                && [ -s "$TMPDIR_UNINSTALL/failure-log-tail.txt" ]; then
            printf '\n'
            printf '  Last log lines:\n'
            while IFS= read -r _fr_line; do
                printf '    %s\n' "$_fr_line"
            done < "$TMPDIR_UNINSTALL/failure-log-tail.txt"
        fi
        printf '\n'
    else
        emit ""
        emit "${RED}x${RESET} Uninstall failed at step ${_fr_n} of ${_fr_total}: ${_fr_step}"
        emit ""

        if [ -n "$_fr_done" ]; then
            emit "  Steps applied (already removed — a re-run will skip them):"
            printf '%s\n' "$_fr_done" | while IFS= read -r _s; do
                [ -n "$_s" ] && emit "    ${GREEN}+${RESET} $_s"
            done
        else
            emit "  No steps were applied before the failure."
        fi
        emit ""
        emit "  Step that failed: ${RED}${_fr_step}${RESET}"
        emit ""
        emit "  Recovery: fix the root cause, then re-run uninstall.sh with the"
        emit "  same arguments. The uninstaller is idempotent — already-removed"
        emit "  items will be skipped."
        emit ""
        emit "  Uninstall log: $INSTALL_LOG"
        if [ -f "$TMPDIR_UNINSTALL/failure-log-tail.txt" ] \
                && [ -s "$TMPDIR_UNINSTALL/failure-log-tail.txt" ]; then
            printf '\n'
            printf '  Last log lines:\n'
            while IFS= read -r _fr_line; do
                printf '    %s\n' "$_fr_line"
            done < "$TMPDIR_UNINSTALL/failure-log-tail.txt"
        fi
        emit ""
    fi
}

# ----------------------------------------------------------------------------
# Final report.
# ----------------------------------------------------------------------------

print_next_steps() {
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
        emit "${YELLOW}Kept (pass --purge to remove):${RESET}"
        if [ -n "$SANDBOX_UID" ]; then
            emit "  - /var/lib/sandboxd/$SANDBOX_UID/  (state, sessions DB, audit logs)"
            emit "    remove: sudo rm -rf /var/lib/sandboxd/$SANDBOX_UID/"
        else
            emit "  - /var/lib/sandboxd/  (no per-uid state dir resolved — legacy install)"
            emit "    remove: sudo rm -rf /var/lib/sandboxd/"
        fi
        emit "  - /etc/sandboxd/users.conf  (operator allowlist)"
        emit "    remove: sudo rm -f /etc/sandboxd/users.conf"
        emit "  - /etc/qemu/bridge.conf  (bridge access rules)"
        emit "    remove: sudo sed -i '/^allow virbr/d' /etc/qemu/bridge.conf"
        emit "  - /etc/systemd/system/sandboxd.service.d/  (service drop-in directory)"
        emit "    remove: sudo rm -rf /etc/systemd/system/sandboxd.service.d/"
        emit "  - 'sandbox' system group and user"
        emit "    remove: sudo userdel sandbox && sudo groupdel sandbox"
        if [ -n "$INSTALLED_VERSION" ]; then
            emit "  - sandbox-gateway:$INSTALLED_VERSION  (gateway Docker image)"
            emit "    remove: sudo docker image rm sandbox-gateway:$INSTALLED_VERSION"
        else
            emit "  - sandbox-gateway Docker image  (version unknown)"
            emit "    remove: sudo docker image rm sandbox-gateway:<version>"
        fi
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
    detect_tty

    TMPDIR_UNINSTALL=$(mktemp -d "/var/tmp/sandbox-uninstall.XXXXXX")
    SUMMARY_FILE=$(mktemp "/var/tmp/sandbox-uninstall-summary.XXXXXX")
    trap cleanup_tmpdir EXIT INT TERM HUP

    # Enter alt-screen as early as possible — trap is in place so EXIT handler
    # restores the primary screen on any exit path (rich mode only; no-op in plain).
    ui_enter_alt_screen

    # ----- Analyze screen -----
    if [ "$RICH_UI" -eq 1 ]; then
        ui_init_phases "$UI_ANALYZE_PHASES"
        UI_CURRENT_HEADER="sandboxd · analyzing"
        ui_render_checklist
    fi

    set_phase 1 "active" "checking daemon"
    # resolve_state_path must run before purge_step's userdel so SANDBOX_UID
    # and STATE_PATH are available while the sandbox user still exists.
    resolve_state_path
    check_daemon_running
    set_phase 1 "done"
    ui_service_winch

    set_phase 2 "active" "reading install state"
    read_install_state
    set_phase 2 "done"
    ui_service_winch

    if [ "$RICH_UI" -eq 1 ]; then
        ui_animator_stop
    fi

    # ----- Plan + confirm screen -----
    compute_plan
    if [ "$RICH_UI" -ne 1 ]; then
        render_plan
    fi
    confirm_plan

    # Invalidate any inherited sudo timestamp so the privileged batch always
    # prompts for the password fresh, never silently piggybacks a cached credential.
    sudo -k

    # ----- Remove screen -----
    write_priv_script
    run_priv_child

    # Durable summary: written to SUMMARY_FILE in rich mode (ui_teardown cats
    # it to real stdout after restoring the primary screen), or to stdout
    # directly in plain mode.
    if [ "$RICH_UI" -eq 1 ]; then
        print_next_steps > "$SUMMARY_FILE"
    else
        print_next_steps
    fi
}

main "$@"
