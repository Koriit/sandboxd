# ui.sh — shared rich-UI fragment for sandboxd shell scripts.
#
# This file is a POSIX sh source fragment.  It has no shebang, no top-level
# side effects beyond function definitions and default-value variable
# initialisations, and is always consumed via `.` (dot-source).
#
# Callers must define the following variables before invoking any ui.sh
# function (not required at dot-source time):
#   QUIET          — 0 or 1 (suppress emit() output when 1)
#   NO_COLOR       — 0 or 1 (force plain output when 1)
#   VERBOSE        — 0 or 1 (enable verbose TTY detection in ui_detect_tty)
#   INSTALL_LOG    — writable path for log_line()
#   SCRIPT_NAME    — label injected into every log_line() record
#
# All other variables below are initialised here to safe defaults.

# ----------------------------------------------------------------------------
# Colour escape globals (populated by setup_colors).
# ----------------------------------------------------------------------------

RED=""
GREEN=""
YELLOW=""
BLUE=""
RESET=""

# ----------------------------------------------------------------------------
# Rich-UI mode flag and supporting state.
# ----------------------------------------------------------------------------

# Rich UI mode — 1 when full interactive UI (alt-screen, bar, spinners, live
# checklist) is available; 0 in all degraded paths (no TTY, --no-color,
# --quiet, tput unavailable). Set once by ui_detect_tty; never changed again.
RICH_UI=0

# Minimum terminal height (rows) required for rich mode.
RICH_UI_MIN_ROWS=9

# Set to 1 while the alt-screen is active so the caller's cleanup knows to
# restore it.
ALT_SCREEN_ACTIVE=0

# Set to 1 while the pager has put the TTY into raw mode.
STTY_RAW_ACTIVE=0
STTY_SAVED=""

# Active spinner background PID (0 when no spinner is running).
SPINNER_PID=0

# Path to the temp file that buffers the durable summary for after rmcup.
SUMMARY_FILE=""

# TTY device used for all UI output (/dev/tty in rich mode, empty in plain).
UI_TTY=""

# Terminal dimensions captured at startup; updated on WINCH.
UI_ROWS=0
UI_COLS=0

# Text shown in the header line.
UI_CURRENT_HEADER=""

# Set to 1 by the WINCH trap; cleared after a repaint.
WINCH_PENDING=0

# Phase model — three parallel newline-separated strings (one entry per phase).
UI_PHASE_NAMES=""
UI_PHASE_STATUSES=""
UI_PHASE_COUNT=0

# Detail text for the active phase (shown on the detail line by the animator).
UI_DETAIL_TEXT=""

# Background animator PID (0 when no animator is running).
UI_ANIM_PID=0

# Four-frame classic spinner characters (plain mode / download bar).
SPINNER_CHARS="/-\|"

# Set to 1 by download_with_bar if the download fails; callers check this.
DOWNLOAD_BAR_FAILED=0

# ----------------------------------------------------------------------------
# Output helpers.
# ----------------------------------------------------------------------------

emit() {
    if [ "$QUIET" -eq 0 ]; then
        printf '%b\n' "$*"
    fi
}

# osc8_link — emit an OSC 8 hyperlink if the terminal supports it, else
# return the label only.
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
        # write is silently dropped (|| true).
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
is_utf8() {
    _lc="${LC_ALL:-${LC_CTYPE:-${LANG:-}}}"
    case "$_lc" in
        *[Uu][Tt][Ff]8*|*[Uu][Tt][Ff]-8*) return 0 ;;
    esac
    return 1
}

# ----------------------------------------------------------------------------
# Shared teardown — called from the per-script cleanup function.
#
# Kills spinner + animator, restores stty and alt-screen, flushes the durable
# summary.  The caller is responsible for any script-specific cleanup (e.g.
# removing the script's own temp directory) after this returns.
# ----------------------------------------------------------------------------

ui_teardown() {
    # Disable the SIGWINCH handler immediately so no resize repaints race
    # with the cleanup sequence.
    trap - WINCH
    if [ "$SPINNER_PID" -ne 0 ]; then
        kill "$SPINNER_PID" 2>/dev/null || true
        wait "$SPINNER_PID" 2>/dev/null || true
        printf '\r\033[K' >&2
        SPINNER_PID=0
    fi
    if [ "$UI_ANIM_PID" -ne 0 ]; then
        kill "$UI_ANIM_PID" 2>/dev/null || true
        wait "$UI_ANIM_PID" 2>/dev/null || true
        if [ -n "$UI_TTY" ]; then
            printf '\r\033[K' >>"$UI_TTY" 2>/dev/null || true
        fi
        UI_ANIM_PID=0
    fi
    ui_restore_stty
    if [ "$ALT_SCREEN_ACTIVE" -eq 1 ]; then
        tput rmcup 2>/dev/null || true
        ALT_SCREEN_ACTIVE=0
    fi
    if [ "$RICH_UI" -eq 1 ] && [ -n "$UI_TTY" ]; then
        printf '\033[?25h' >>"$UI_TTY" 2>/dev/null || true
        printf '\033[?7h' >>"$UI_TTY" 2>/dev/null || true
    fi
    if [ -n "$SUMMARY_FILE" ] && [ -s "$SUMMARY_FILE" ]; then
        cat "$SUMMARY_FILE"
    fi
}

# ui_enter_alt_screen — switch to the alternate screen buffer. No-op in plain
# mode. Sets ALT_SCREEN_ACTIVE=1 so the cleanup path knows to restore.
ui_enter_alt_screen() {
    if [ "$RICH_UI" -eq 1 ]; then
        tput smcup 2>/dev/null || true
        printf '\033[?25l' >>"$UI_TTY" 2>/dev/null || true
        printf '\033[?7l' >>"$UI_TTY" 2>/dev/null || true
        ALT_SCREEN_ACTIVE=1
    fi
}

# ui_leave_alt_screen — restore the primary screen. The durable summary is
# NOT flushed here; ui_teardown is the single flush point.
# In plain mode this is a no-op.
ui_leave_alt_screen() {
    if [ "$ALT_SCREEN_ACTIVE" -eq 1 ]; then
        tput rmcup 2>/dev/null || true
        ALT_SCREEN_ACTIVE=0
    fi
}

# ----------------------------------------------------------------------------
# Phase-3 render engine — rich-mode only.
# All functions below no-op when RICH_UI=0 or UI_TTY is empty.
# ----------------------------------------------------------------------------

# tty_print — write raw text to the UI TTY. No-op when UI_TTY is empty.
tty_print() {
    [ -n "$UI_TTY" ] || return 0
    printf '%s' "$1" >>"$UI_TTY"
}

# ui_clamp — truncate STRING to at most WIDTH display columns (never wraps).
# Prints the (possibly truncated) string to stdout.
# Args: $1=width $2=string
#
# Uses awk for truncation rather than cut -c.  POSIX cut -c counts bytes in a
# C locale, so cutting at column N on a string that contains 3-byte UTF-8
# glyphs (⋮, ▸, ✔, ✗) can land mid-sequence and emit a broken partial byte.
# awk length()/substr() operate on characters (code points) in a multibyte
# locale, so they stop on whole-glyph boundaries regardless of byte width.
ui_clamp() {
    _uc_w="$1"
    _uc_s="$2"
    if [ "$_uc_w" -le 0 ]; then
        return 0
    fi
    printf '%s' "$_uc_s" | awk -v w="$_uc_w" '{
        if (length($0) <= w) { printf "%s", $0 }
        else { printf "%s", substr($0, 1, w) }
    }'
}

# ui_render_header — paint header + rule to the TTY.
# Does NOT move the cursor afterwards; callers must position as needed.
# Does NOT set UI_CURRENT_HEADER; the caller sets that before calling.
# Args: $1=header_text
ui_render_header() {
    [ "$RICH_UI" -eq 1 ] || return 0
    _urh_text="$1"
    _urh_cols="${UI_COLS:-80}"
    _urh_line=$(ui_clamp "$_urh_cols" "$_urh_text")
    _urh_rule=$(printf '%*s' "$_urh_cols" '' | tr ' ' '-' | cut -c1-"$_urh_cols")
    printf '\033[K%s\r\n\033[K%s\r\n' "$_urh_line" "$_urh_rule" >>"$UI_TTY"
}

# ui_phase_name — return the name string for phase index $1 (1-based).
# Prints the name to stdout; empty string if not found.
ui_phase_name() {
    _upn_idx="$1"
    _upn_i=1
    printf '%s\n' "$UI_PHASE_NAMES" | while IFS= read -r _upn_row; do
        [ -z "$_upn_row" ] && continue
        if [ "$_upn_i" -eq "$_upn_idx" ]; then
            printf '%s' "$_upn_row"
            return 0
        fi
        _upn_i=$((_upn_i + 1))
    done
}

# ui_phase_status — return the status string for phase index $1 (1-based).
# Prints the status to stdout; empty string if not found.
ui_phase_status() {
    _ups_idx="$1"
    _ups_i=1
    printf '%s\n' "$UI_PHASE_STATUSES" | while IFS= read -r _ups_row; do
        [ -z "$_ups_row" ] && continue
        if [ "$_ups_i" -eq "$_ups_idx" ]; then
            printf '%s' "$_ups_row"
            return 0
        fi
        _ups_i=$((_ups_i + 1))
    done
}

# ui_set_phase_status — output a new UI_PHASE_STATUSES string with entry $1
# replaced by $2.  Prints the result to stdout; caller captures via $().
# Args: $1=index (1-based) $2=new_status
ui_set_phase_status() {
    _sps_idx="$1"
    _sps_new="$2"
    _sps_i=1
    printf '%s\n' "$UI_PHASE_STATUSES" | while IFS= read -r _sps_row; do
        [ -z "$_sps_row" ] && continue
        if [ "$_sps_i" -eq "$_sps_idx" ]; then
            printf '%s\n' "$_sps_new"
        else
            printf '%s\n' "$_sps_row"
        fi
        _sps_i=$((_sps_i + 1))
    done
}

# ui_init_phases — initialise the phase model from a newline-separated list.
# Sets UI_PHASE_NAMES, UI_PHASE_COUNT, UI_PHASE_STATUSES, UI_DETAIL_TEXT.
# Leading/trailing blank lines in the input are stripped (NF trimming).
# Args: $1=newline-separated phase-name list
ui_init_phases() {
    UI_PHASE_NAMES=$(printf '%s' "$1" | awk 'NF{found=1} found && NF')
    UI_DETAIL_TEXT=""
    UI_PHASE_COUNT=$(printf '%s\n' "$UI_PHASE_NAMES" | awk 'NF{n++} END{print n+0}')
    UI_PHASE_STATUSES=$(awk -v n="$UI_PHASE_COUNT" 'BEGIN{for(i=1;i<=n;i++) print "pending"}')
}

# _ui_render_checklist_body — write the visible phase rows to the TTY.
# Implements auto-follow viewport: the active phase is always visible.
# Completed rows scrolled off the top are represented by "⋮ N done above".
# Args: $1=available_rows (how many rows the checklist region can use)
_ui_render_checklist_body() {
    [ "$RICH_UI" -eq 1 ] || return 0
    _rcb_avail="$1"
    _rcb_cols="${UI_COLS:-80}"
    _rcb_total="$UI_PHASE_COUNT"

    if [ "$_rcb_total" -eq 0 ] || [ "$_rcb_avail" -le 0 ]; then
        return 0
    fi

    # Find the 1-based index of the first "active" phase using awk (avoids
    # subshell variable-mutation issues with pipelines).
    _rcb_active_idx=$(printf '%s\n' "$UI_PHASE_STATUSES" \
        | awk '/^active$/{print NR; found=1; exit} END{if(!found) print 0}')
    # If no active phase found, default to the last phase.
    if [ "$_rcb_active_idx" -eq 0 ]; then
        _rcb_active_idx="$_rcb_total"
    fi

    # Determine viewport: show as many phases as fit, keeping active visible.
    # If all phases fit, show from row 1. Otherwise compute the scroll offset.
    _rcb_need_indicator=0
    _rcb_start=1
    if [ "$_rcb_total" -gt "$_rcb_avail" ]; then
        # Reserve one row for the "⋮ N done above" indicator.
        _rcb_content_rows=$((_rcb_avail - 1))
        if [ "$_rcb_content_rows" -lt 1 ]; then _rcb_content_rows=1; fi
        # Place active row at position 2 from the top of the visible window.
        _rcb_preferred_start=$((_rcb_active_idx - 1))
        if [ "$_rcb_preferred_start" -lt 1 ]; then _rcb_preferred_start=1; fi
        # Don't scroll past the end.
        _rcb_max_start=$((_rcb_total - _rcb_content_rows + 1))
        if [ "$_rcb_preferred_start" -gt "$_rcb_max_start" ]; then
            _rcb_preferred_start="$_rcb_max_start"
        fi
        if [ "$_rcb_preferred_start" -lt 1 ]; then _rcb_preferred_start=1; fi
        _rcb_start="$_rcb_preferred_start"
        if [ "$_rcb_start" -gt 1 ]; then
            _rcb_need_indicator=1
        fi
    fi

    # Count phases above the viewport start (for the indicator text).
    _rcb_above=0
    if [ "$_rcb_need_indicator" -eq 1 ]; then
        _rcb_above=$(( _rcb_start - 1 ))
    fi

    # Determine the last visible row index.
    _rcb_end=$((_rcb_start + _rcb_avail - 1))
    if [ "$_rcb_need_indicator" -eq 1 ]; then
        _rcb_end=$((_rcb_start + _rcb_avail - 2))
    fi
    if [ "$_rcb_end" -gt "$_rcb_total" ]; then
        _rcb_end="$_rcb_total"
    fi

    # Emit indicator line if needed.
    if [ "$_rcb_need_indicator" -eq 1 ] && [ "$_rcb_above" -gt 0 ]; then
        _rcb_ind=$(ui_clamp "$_rcb_cols" "  ⋮ $_rcb_above done above")
        printf '\033[K%s\r\n' "$_rcb_ind" >>"$UI_TTY"
    fi

    # Emit visible phase rows. The pipeline here only produces TTY output —
    # no variables need to escape the subshell, so this is safe.
    _rcb_row=1
    printf '%s\n' "$UI_PHASE_NAMES" | while IFS= read -r _rcb_name; do
        [ -z "$_rcb_name" ] && continue
        if [ "$_rcb_row" -ge "$_rcb_start" ] && [ "$_rcb_row" -le "$_rcb_end" ]; then
            _rcb_status=$(ui_phase_status "$_rcb_row")
            case "$_rcb_status" in
                active)  _rcb_glyph="${YELLOW:-}▸${RESET:-}" ;;
                done)    _rcb_glyph="${GREEN:-}✔${RESET:-}" ;;
                failed)  _rcb_glyph="${RED:-}✗${RESET:-}" ;;
                *)       _rcb_glyph="·" ;;
            esac
            _rcb_line="  $_rcb_glyph $_rcb_name"
            _rcb_clamped=$(ui_clamp "$_rcb_cols" "$_rcb_line")
            printf '\033[K%s\r\n' "$_rcb_clamped" >>"$UI_TTY"
        fi
        _rcb_row=$((_rcb_row + 1))
    done
}

# ui_term_size — query the live terminal dimensions from the controlling terminal.
# Prints "ROWS COLS" (e.g. "36 120") on success, or nothing on failure.
# Uses stty size </dev/tty so the TIOCGWINSZ ioctl runs on the real terminal
# fd rather than a pipe (which is what command substitution creates for tput,
# causing tput to fall back to the static terminfo default).
ui_term_size() {
    ( stty size </dev/tty ) 2>/dev/null || true
}

# ui_render_checklist — repaint the full checklist viewport to the TTY.
# Stops the background animator before repaint, restarts it after.
# No-op when RICH_UI=0.
ui_render_checklist() {
    [ "$RICH_UI" -eq 1 ] || return 0
    _urc_sz=$(ui_term_size)
    UI_ROWS=${_urc_sz%% *}
    case "$UI_ROWS" in ''|*[!0-9]*) UI_ROWS=$(tput lines 2>/dev/null || printf '%s' "${UI_ROWS:-24}") ;; esac
    UI_COLS=${_urc_sz##* }
    case "$UI_COLS" in ''|*[!0-9]*) UI_COLS=$(tput cols  2>/dev/null || printf '%s' "${UI_COLS:-80}") ;; esac
    _urc_anim_was_running=0
    if [ "$UI_ANIM_PID" -ne 0 ]; then
        _urc_anim_was_running=1
        kill "$UI_ANIM_PID" 2>/dev/null || true
        wait "$UI_ANIM_PID" 2>/dev/null || true
        UI_ANIM_PID=0
    fi
    _urc_available=$(( UI_ROWS - 2 - 1 - 1 ))
    if [ "$_urc_available" -lt 1 ]; then _urc_available=1; fi
    tput home >>"$UI_TTY" 2>/dev/null || true
    ui_render_header "${UI_CURRENT_HEADER}"
    _ui_render_checklist_body "$_urc_available"
    _urc_rule=$(printf '%*s' "${UI_COLS:-80}" '' | tr ' ' '-' | cut -c1-"${UI_COLS:-80}")
    printf '\033[K%s\r\n' "$_urc_rule" >>"$UI_TTY"
    printf '\033[J' >>"$UI_TTY" 2>/dev/null || true
    WINCH_PENDING=0
    if [ "$_urc_anim_was_running" -eq 1 ]; then
        ui_animator_start "$UI_DETAIL_TEXT"
    fi
}

# _ui_spinner_frame — print one braille animation frame to stdout.
# 35-frame FILL→DRAIN sequence using literal UTF-8 braille characters.
# Args: $1=frame_counter (modulo applied internally)
_ui_spinner_frame() {
    case "$(($1 % 35))" in
        0)  printf '⠁' ;;  1)  printf '⠂' ;;  2)  printf '⠄' ;;
        3)  printf '⡀' ;;  4)  printf '⡈' ;;  5)  printf '⡐' ;;
        6)  printf '⡠' ;;  7)  printf '⣀' ;;  8)  printf '⣁' ;;
        9)  printf '⣂' ;;  10) printf '⣄' ;;  11) printf '⣌' ;;
        12) printf '⣔' ;;  13) printf '⣤' ;;  14) printf '⣥' ;;
        15) printf '⣦' ;;  16) printf '⣮' ;;  17) printf '⣶' ;;
        18) printf '⣷' ;;  19) printf '⣿' ;;  20) printf '⡿' ;;
        21) printf '⠿' ;;  22) printf '⢟' ;;  23) printf '⠟' ;;
        24) printf '⡛' ;;  25) printf '⠛' ;;  26) printf '⠫' ;;
        27) printf '⢋' ;;  28) printf '⠋' ;;  29) printf '⠍' ;;
        30) printf '⡉' ;;  31) printf '⠉' ;;  32) printf '⠑' ;;
        33) printf '⠡' ;;  34) printf '⢁' ;;  *)  printf '⠁' ;;
    esac
}

# _ui_animator_body — background loop that writes the detail line animation.
# Runs as a background process (ui_animator_start forks it).
# Args: $1=detail_text
_ui_animator_body() {
    _ab_text="$1"
    _ab_tty="$UI_TTY"
    [ -n "$_ab_tty" ] || exit 0
    _ab_t=0
    while true; do
        _ab_sz=$(ui_term_size)
        _ab_cols=${_ab_sz##* }
        case "$_ab_cols" in ''|*[!0-9]*) _ab_cols=$(tput cols 2>/dev/null || printf '80') ;; esac
        _ab_frame="${BLUE:-}$(_ui_spinner_frame "$_ab_t")${RESET:-}"
        _ab_detail="  $_ab_frame $_ab_text"
        _ab_clamped=$(printf '%s' "$_ab_detail" | awk -v w="$_ab_cols" '{
            if (length($0) <= w) { printf "%s", $0 }
            else { printf "%s", substr($0, 1, w) }
        }')
        printf '\r%s\033[K' "$_ab_clamped" >>"$_ab_tty"
        sleep 0.1
        _ab_t=$((_ab_t + 1))
    done
}

# ui_animator_start — start the background detail-line animator.
# Kills any running animator first. No-op when RICH_UI=0 or UI_TTY is empty.
# Args: $1=detail_text
ui_animator_start() {
    [ "$RICH_UI" -eq 1 ] || return 0
    [ -n "$UI_TTY" ] || return 0
    if [ "$UI_ANIM_PID" -ne 0 ]; then
        kill "$UI_ANIM_PID" 2>/dev/null || true
        wait "$UI_ANIM_PID" 2>/dev/null || true
        UI_ANIM_PID=0
    fi
    UI_DETAIL_TEXT="$1"
    _ui_animator_body "$1" &
    UI_ANIM_PID=$!
}

# ui_animator_stop — stop the background animator and clear the detail line.
# No-op when RICH_UI=0.
ui_animator_stop() {
    [ "$RICH_UI" -eq 1 ] || return 0
    if [ "$UI_ANIM_PID" -ne 0 ]; then
        kill "$UI_ANIM_PID" 2>/dev/null || true
        wait "$UI_ANIM_PID" 2>/dev/null || true
        UI_ANIM_PID=0
    fi
    if [ -n "$UI_TTY" ]; then
        printf '\r\033[K' >>"$UI_TTY" 2>/dev/null || true
    fi
    UI_DETAIL_TEXT=""
}

# ui_animator_stop_noclear — stop the background animator without clearing the
# detail line (used when a progress bar will immediately overwrite it).
# No-op when RICH_UI=0.
ui_animator_stop_noclear() {
    [ "$RICH_UI" -eq 1 ] || return 0
    if [ "$UI_ANIM_PID" -ne 0 ]; then
        kill "$UI_ANIM_PID" 2>/dev/null || true
        wait "$UI_ANIM_PID" 2>/dev/null || true
        UI_ANIM_PID=0
    fi
    UI_DETAIL_TEXT=""
}

# ui_restore_stty — restore TTY settings saved before raw mode.
# Guards on /dev/tty existence rather than STTY_SAVED content so that a
# failed save still attempts a sane restore.
ui_restore_stty() {
    if [ "$STTY_RAW_ACTIVE" -eq 1 ] && [ -e /dev/tty ]; then
        stty "$STTY_SAVED" </dev/tty 2>/dev/null \
            || stty sane </dev/tty 2>/dev/null \
            || true
        STTY_RAW_ACTIVE=0
    fi
}

# ui_service_winch — process a pending SIGWINCH by repainting the checklist.
# Called from the main script loop at safe points (not inside a signal handler).
ui_service_winch() {
    [ "$WINCH_PENDING" -eq 1 ] || return 0
    [ "$RICH_UI" -eq 1 ] || return 0
    ui_render_checklist
}

# set_phase — transition phase $1 to status $2 with optional detail text $3.
# Stops the animator, updates the phase model, repaints, then restarts the
# animator if transitioning to "active".
# No-op when RICH_UI=0.
# Args: $1=phase_index $2=status $3=detail_text (optional)
set_phase() {
    [ "$RICH_UI" -eq 1 ] || return 0
    _sp_idx="$1"
    _sp_status="$2"
    _sp_detail="${3:-}"
    ui_animator_stop
    UI_PHASE_STATUSES=$(ui_set_phase_status "$_sp_idx" "$_sp_status")
    ui_render_checklist
    if [ "$_sp_status" = "active" ]; then
        ui_animator_start "$_sp_detail"
    fi
}

# ui_find_phase — return the 1-based index of the phase named $1, or 0.
ui_find_phase() {
    printf '%s\n' "$UI_PHASE_NAMES" \
        | awk -v name="$1" '$0==name{print NR; found=1; exit} END{if(!found) print 0}'
}

# _ui_winch_trap — SIGWINCH signal handler. Sets the pending flag only;
# does NOT repaint (unsafe from an async signal context).
_ui_winch_trap() {
    WINCH_PENDING=1
}

# ----------------------------------------------------------------------------
# Plain-mode spinner (Phase 1/2 compat — no alt-screen, no animator).
# ----------------------------------------------------------------------------

# _spinner_frame — print one spinner frame to stdout for redraw.
# Args: $1=elapsed_seconds $2=label
_spinner_frame() {
    _sf_elapsed="$1"
    _sf_label="$2"
    _sf_idx=$((_sf_elapsed % 4))
    _sf_char=$(printf '%s' "$SPINNER_CHARS" | cut -c$((_sf_idx + 1)))
    printf '\r  %s %s  [%ss]  ' "$_sf_char" "$_sf_label" "$_sf_elapsed" >&2
}

# spinner_start — begin a spinner animation in the background (rich mode only).
# In plain mode this is a no-op; the calling code continues unchanged.
spinner_start() {
    _ss_label="$1"

    # Both plain and rich mode: no background spinner.
    # In rich mode the Phase-6/8 animator owns the detail line; a separate
    # stderr spinner would corrupt the alt-screen.
    SPINNER_PID=0
}

# spinner_stop — stop the spinner and print a settle line.
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

# ----------------------------------------------------------------------------
# Download progress bar.
# ----------------------------------------------------------------------------

# _bar_style_b — build a style-B (UTF-8 true eighths) progress bar string.
# Args: $1=progress_eighths_total $2=total_cells
_bar_style_b() {
    _bsb_eighths="$1"
    _bsb_total="$2"

    _bsb_full=$((_bsb_eighths / 8))
    _bsb_frac=$((_bsb_eighths % 8))

    _bsb_bar=""
    _bsb_i=0
    while [ "$_bsb_i" -lt "$_bsb_total" ]; do
        if [ "$_bsb_i" -lt "$_bsb_full" ]; then
            _bsb_bar="${_bsb_bar}█"
        elif [ "$_bsb_i" -eq "$_bsb_full" ] && [ "$_bsb_frac" -gt 0 ]; then
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
    printf '%s' "$_bsb_bar"
}

# _bar_style_c — build a style-C (ASCII) progress bar string.
# Args: $1=filled_cells $2=total_cells
_bar_style_c() {
    _bsc_filled="$1"
    _bsc_total="$2"

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
    printf '%s' "$_bsc_bar"
}

# _kb_to_mb_1dp — convert KB integer to MB string with one decimal place.
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
download_with_bar() {
    _dwb_url="$1"
    _dwb_dest="$2"
    DOWNLOAD_BAR_FAILED=0

    _dwb_total_kb=0
    _dwb_cl=$(curl -fsSL --head --retry 2 --retry-delay 1 "$_dwb_url" 2>/dev/null \
        | grep -i '^Content-Length:' \
        | tail -n1 \
        | awk '{print $2}' \
        | tr -d '\r')
    if printf '%s' "${_dwb_cl:-0}" | grep -qE '^[0-9]+$'; then
        _dwb_total_kb=$((_dwb_cl / 1024))
    fi

    curl -fsSL --retry 3 --retry-delay 2 -o "$_dwb_dest" "$_dwb_url" 2>/dev/null &
    _dwb_curl_pid=$!

    if [ "$RICH_UI" -eq 1 ] && [ "$_dwb_total_kb" -gt 0 ]; then
        _dwb_title="$UI_DETAIL_TEXT"
        ui_animator_stop_noclear
        _dwb_title_len=$(printf '%s' "$_dwb_title" | wc -c | tr -d ' ')
        _dwb_bar_cells=24
        _dwb_cols="${UI_COLS:-80}"
        _dwb_fixed_with_speed=$(( _dwb_title_len + 2 + 4 + 3 + 2 + 4 + 1 + 12 + 11 ))
        _dwb_fixed_no_speed=$(( _dwb_fixed_with_speed - 11 ))
        _dwb_avail=$(( _dwb_cols - _dwb_fixed_with_speed ))
        _dwb_show_speed=1
        if [ "$_dwb_avail" -lt 4 ]; then
            _dwb_avail=$(( _dwb_cols - _dwb_fixed_no_speed ))
            _dwb_show_speed=0
        fi
        if [ "$_dwb_avail" -lt 4 ]; then _dwb_avail=4; fi
        if [ "$_dwb_avail" -lt "$_dwb_bar_cells" ]; then _dwb_bar_cells=$_dwb_avail; fi
        _dwb_frame_idx=0
        _dwb_spd_t=$(date +%s)
        _dwb_spd_kb=0
        _dwb_speed=0
        while kill -0 "$_dwb_curl_pid" 2>/dev/null; do
            _dwb_done_kb=0
            if [ -f "$_dwb_dest" ]; then
                _dwb_done_kb=$(du -k "$_dwb_dest" 2>/dev/null | awk '{print $1}')
                _dwb_done_kb="${_dwb_done_kb:-0}"
            fi
            _dwb_pct=$((_dwb_done_kb * 100 / _dwb_total_kb))
            if [ "$_dwb_pct" -gt 100 ]; then _dwb_pct=100; fi
            _dwb_done_mb=$(_kb_to_mb_1dp "$_dwb_done_kb")
            _dwb_total_mb=$(_kb_to_mb_1dp "$_dwb_total_kb")
            _dwb_now=$(date +%s)
            _dwb_elapsed=$((_dwb_now - _dwb_spd_t))
            if [ "$_dwb_elapsed" -ge 1 ]; then
                _dwb_speed=$(( (_dwb_done_kb - _dwb_spd_kb) / _dwb_elapsed ))
                _dwb_spd_t=$_dwb_now
                _dwb_spd_kb=$_dwb_done_kb
            fi
            _dwb_frame="${BLUE:-}$(_ui_spinner_frame "$_dwb_frame_idx")${RESET:-}"
            _dwb_frame_idx=$((_dwb_frame_idx + 1))
            if is_utf8; then
                _dwb_eighths=$((_dwb_done_kb * _dwb_bar_cells * 8 / _dwb_total_kb))
                _dwb_bar=$(_bar_style_b "$_dwb_eighths" "$_dwb_bar_cells")
            else
                _dwb_filled=$((_dwb_done_kb * _dwb_bar_cells / _dwb_total_kb))
                _dwb_bar=$(_bar_style_c "$_dwb_filled" "$_dwb_bar_cells")
            fi
            if [ "$_dwb_show_speed" -eq 1 ]; then
                printf '\r  %s %s  [%s%s%s] %3s%% %s/%s MB  %s KB/s\033[K' \
                    "$_dwb_frame" "$_dwb_title" \
                    "${GREEN:-}" "$_dwb_bar" "${RESET:-}" \
                    "$_dwb_pct" "$_dwb_done_mb" "$_dwb_total_mb" "$_dwb_speed" \
                    >>"$UI_TTY"
            else
                printf '\r  %s %s  [%s%s%s] %3s%% %s/%s MB\033[K' \
                    "$_dwb_frame" "$_dwb_title" \
                    "${GREEN:-}" "$_dwb_bar" "${RESET:-}" \
                    "$_dwb_pct" "$_dwb_done_mb" "$_dwb_total_mb" \
                    >>"$UI_TTY"
            fi
            sleep 0.1
        done
        wait "$_dwb_curl_pid" || DOWNLOAD_BAR_FAILED=1
        printf '\033[2K\r' >>"$UI_TTY"
    elif [ "$RICH_UI" -eq 0 ] && [ "$_dwb_total_kb" -gt 0 ]; then
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
            if [ "$((_dwb_pct - _dwb_last_pct_reported))" -ge 10 ]; then
                _dwb_done_mb=$(_kb_to_mb_1dp "$_dwb_done_kb")
                _dwb_total_mb=$(_kb_to_mb_1dp "$_dwb_total_kb")
                emit "  ... ${_dwb_pct}% (${_dwb_done_mb}/${_dwb_total_mb} MB)"
                _dwb_last_pct_reported=$_dwb_pct
            fi
            sleep 1
        done
        wait "$_dwb_curl_pid" || DOWNLOAD_BAR_FAILED=1
    else
        wait "$_dwb_curl_pid" || DOWNLOAD_BAR_FAILED=1
        return 0
    fi
}

# ----------------------------------------------------------------------------
# TTY detection — shared core; thin per-script wrapper keeps SCRIPT_NAME.
# ----------------------------------------------------------------------------

# ui_detect_tty — run the full TTY/rich-mode detection and colour setup.
# Sets RICH_UI, UI_TTY, UI_ROWS, UI_COLS, installs WINCH trap in rich mode.
# Does NOT output anything; all results are communicated via globals.
# The caller's detect_tty() wrapper adds the script-specific log_ok call.
ui_detect_tty() {
    setup_colors
    _udt_tty="no"
    _udt_color="no"
    _udt_rich="no"
    if [ -t 1 ]; then _udt_tty="yes"; fi
    if [ -n "$GREEN" ]; then _udt_color="yes"; fi
    _udt_sz=$( ( stty size </dev/tty ) 2>/dev/null || true)
    _udt_rows=${_udt_sz%% *}
    case "$_udt_rows" in ''|*[!0-9]*) _udt_rows=$(tput lines 2>/dev/null || printf '0') ;; esac
    if [ "$_udt_tty" = "yes" ] \
        && [ "$NO_COLOR" -eq 0 ] \
        && [ "$QUIET" -eq 0 ] \
        && [ "$VERBOSE" -eq 0 ] \
        && [ -e /dev/tty ] \
        && command -v tput >/dev/null 2>&1 \
        && tput smcup >/dev/null 2>&1 \
        && tput rmcup >/dev/null 2>&1 \
        && [ "$_udt_rows" -ge "$RICH_UI_MIN_ROWS" ]; then
        RICH_UI=1
        _udt_rich="yes"
        UI_TTY="/dev/tty"
        _udt_cols=${_udt_sz##* }
        case "$_udt_cols" in ''|*[!0-9]*) _udt_cols=$(tput cols 2>/dev/null || printf '80') ;; esac
        UI_ROWS="$_udt_rows"
        UI_COLS="$_udt_cols"
        trap '_ui_winch_trap' WINCH
    fi
}

# ----------------------------------------------------------------------------
# Generic pager — shared confirm-plan interactive viewport.
# ----------------------------------------------------------------------------

# ui_pager_confirm — display the output of a render callback in an interactive
# scrollable viewport. Returns 0 if the user confirmed (y/Y), 1 if aborted.
#
# Args:
#   $1 — render callback: function name called as "$1 2>/dev/null" to produce
#        the plan text (newline-separated lines).
#   $2 — title shown in the header
#
# Caller must already be in rich mode (RICH_UI=1) and have UI_TTY set.
# STTY_RAW_ACTIVE / STTY_SAVED are managed here; ui_restore_stty must be
# callable from the cleanup path so that Ctrl-C during the pager leaves the
# terminal usable.
ui_pager_confirm() {
    _upc_render_cb="$1"
    _upc_title="$2"
    _upc_text=$($_upc_render_cb 2>/dev/null)

    _upc_plan_lines=$(printf '%s' "$_upc_text" | awk 'END{print NR}')
    _upc_viewport=$(( UI_ROWS - 4 ))
    if [ "$_upc_viewport" -lt 1 ]; then _upc_viewport=1; fi

    _upc_offset=0
    _upc_done=0
    _upc_proceed=0

    _upc_esc=$(printf '\033')
    _upc_cd=$(printf '\004')
    _upc_cu=$(printf '\025')

    STTY_SAVED=$(stty -g </dev/tty 2>/dev/null || true)
    if stty raw -echo </dev/tty 2>/dev/null; then
        STTY_RAW_ACTIVE=1
    fi

    _upc_render() {
        _upcr_sz=$(ui_term_size)
        UI_ROWS=${_upcr_sz%% *}
        case "$UI_ROWS" in ''|*[!0-9]*) UI_ROWS=$(tput lines 2>/dev/null || printf '24') ;; esac
        UI_COLS=${_upcr_sz##* }
        case "$UI_COLS" in ''|*[!0-9]*) UI_COLS=$(tput cols 2>/dev/null || printf '80') ;; esac
        _upc_viewport=$(( UI_ROWS - 4 ))
        if [ "$_upc_viewport" -lt 1 ]; then _upc_viewport=1; fi
        _upcr_max=$(( _upc_plan_lines - _upc_viewport ))
        if [ "$_upcr_max" -lt 0 ]; then _upcr_max=0; fi
        if [ "$_upc_offset" -gt "$_upcr_max" ]; then _upc_offset="$_upcr_max"; fi
        WINCH_PENDING=0

        _upcr_end=$(( _upc_offset + _upc_viewport ))
        if [ "$_upcr_end" -gt "$_upc_plan_lines" ]; then _upcr_end="$_upc_plan_lines"; fi
        _upcr_a=$(( _upc_offset + 1 ))
        _upcr_b="$_upcr_end"

        printf '\033[H' >>"$UI_TTY"
        ui_render_header "$_upc_title"

        _upcr_esc=$(printf '\033')
        printf '%s\n' "$_upc_text" \
            | awk -v s="$_upcr_a" -v e="$_upcr_b" \
                  -v ORS='\r\n' -v esc="$_upcr_esc" \
                  'NR>=s && NR<=e {print esc "[K" $0}' \
            >>"$UI_TTY"

        _upcr_shown=$(( _upcr_b - _upc_offset ))
        _upcr_pad=$(( _upc_viewport - _upcr_shown ))
        _upcr_p=0
        while [ "$_upcr_p" -lt "$_upcr_pad" ]; do
            printf '\033[K\r\n' >>"$UI_TTY"
            _upcr_p=$(( _upcr_p + 1 ))
        done

        _upcr_rule=$(printf '%*s' "${UI_COLS:-80}" '' | tr ' ' '-' \
            | cut -c1-"${UI_COLS:-80}")
        printf '\033[K%s\r\n' "$_upcr_rule" >>"$UI_TTY"
        printf '\033[K[y] proceed  [n] abort  \342\206\221/\342\206\223 PgUp/PgDn scroll  lines %d\342\200\223%d of %d  ' \
            "$_upcr_a" "$_upcr_b" "$_upc_plan_lines" >>"$UI_TTY"
    }

    _upc_render

    while [ "$_upc_done" -eq 0 ]; do
        if [ "$WINCH_PENDING" -eq 1 ]; then
            _upc_render
        fi
        _upc_ch=$(dd bs=1 count=1 2>/dev/null </dev/tty)

        case "$_upc_ch" in
            y|Y)
                _upc_done=1
                _upc_proceed=1
                ;;
            n|N|q|Q)
                _upc_done=1
                _upc_proceed=0
                ;;
            "$_upc_cd")
                _upc_half=$(( _upc_viewport / 2 ))
                if [ "$_upc_half" -lt 1 ]; then _upc_half=1; fi
                _upc_max=$(( _upc_plan_lines - _upc_viewport ))
                if [ "$_upc_max" -lt 0 ]; then _upc_max=0; fi
                _upc_offset=$(( _upc_offset + _upc_half ))
                if [ "$_upc_offset" -gt "$_upc_max" ]; then _upc_offset="$_upc_max"; fi
                _upc_render
                continue
                ;;
            "$_upc_cu")
                _upc_half=$(( _upc_viewport / 2 ))
                if [ "$_upc_half" -lt 1 ]; then _upc_half=1; fi
                _upc_offset=$(( _upc_offset - _upc_half ))
                if [ "$_upc_offset" -lt 0 ]; then _upc_offset=0; fi
                _upc_render
                continue
                ;;
            "$_upc_esc")
                _upc_b2=$(dd bs=1 count=1 2>/dev/null </dev/tty)
                _upc_b3=$(dd bs=1 count=1 2>/dev/null </dev/tty)
                case "${_upc_b2}${_upc_b3}" in
                    '[A')
                        if [ "$_upc_offset" -gt 0 ]; then
                            _upc_offset=$(( _upc_offset - 1 ))
                        fi
                        ;;
                    '[B')
                        _upc_max=$(( _upc_plan_lines - _upc_viewport ))
                        if [ "$_upc_max" -lt 0 ]; then _upc_max=0; fi
                        if [ "$_upc_offset" -lt "$_upc_max" ]; then
                            _upc_offset=$(( _upc_offset + 1 ))
                        fi
                        ;;
                    '[5')
                        dd bs=1 count=1 2>/dev/null </dev/tty >/dev/null || true
                        _upc_offset=$(( _upc_offset - _upc_viewport ))
                        if [ "$_upc_offset" -lt 0 ]; then _upc_offset=0; fi
                        ;;
                    '[6')
                        dd bs=1 count=1 2>/dev/null </dev/tty >/dev/null || true
                        _upc_max=$(( _upc_plan_lines - _upc_viewport ))
                        if [ "$_upc_max" -lt 0 ]; then _upc_max=0; fi
                        _upc_offset=$(( _upc_offset + _upc_viewport ))
                        if [ "$_upc_offset" -gt "$_upc_max" ]; then
                            _upc_offset="$_upc_max"
                        fi
                        ;;
                esac
                _upc_render
                continue
                ;;
        esac

        if [ "$_upc_done" -eq 0 ]; then
            _upc_render
        fi
    done

    ui_restore_stty

    if [ "$_upc_proceed" -eq 0 ]; then
        return 1
    fi
    return 0
}

# ----------------------------------------------------------------------------
# Generic failure report — checklist-shaped die() body.
# ----------------------------------------------------------------------------

# ui_die_report — write a checklist-shaped failure summary to SUMMARY_FILE.
# Called from per-script die() implementations.
# Args:
#   $1 — error message
#   $2 — recovery hint line (e.g. "fix the root cause, then re-run install.sh.")
#   $3 — log path hint line (e.g. "Install log: /var/log/sandbox-install.log")
ui_die_report() {
    _udr_msg="$1"
    _udr_recovery="$2"
    _udr_logline="$3"

    # Flip the first active phase to failed so the checklist shows the
    # in-progress step as ✗ rather than silently omitting it.
    _udr_active=$(printf '%s\n' "$UI_PHASE_STATUSES" | awk '/^active$/{print NR; exit}')
    if [ -n "$_udr_active" ] && [ "$_udr_active" -gt 0 ]; then
        UI_PHASE_STATUSES=$(ui_set_phase_status "$_udr_active" failed)
    fi

    {
        _udr_i=1
        printf '%s\n' "$UI_PHASE_STATUSES" | while IFS= read -r _udr_st; do
            [ -z "$_udr_st" ] && continue
            _udr_name=$(printf '%s\n' "$UI_PHASE_NAMES" \
                | awk -v n="$_udr_i" 'NR==n{print; exit}')
            case "$_udr_st" in
                done)   printf '%b\n' "  ${GREEN}\342\234\224${RESET} ${_udr_name}" ;;
                failed) printf '%b\n' "  ${RED}\342\234\227${RESET} ${_udr_name}" ;;
            esac
            _udr_i=$((_udr_i + 1))
        done
        printf '%b\n' ""
        printf '%b\n' "${RED}\342\234\227${RESET} Error: ${_udr_msg}"
        printf '%b\n' ""
        printf '%b\n' "  Recovery: ${_udr_recovery}"
        printf '%b\n' "  ${_udr_logline}"
    } > "$SUMMARY_FILE"
}
