#!/bin/sh
# tests/rich-ui-dash/harness.sh
#
# Execution harness for the rich-mode (TTY) code paths of scripts/install.sh.
#
# Runs under both dash and bash.  Each scenario is executed in its own
# subshell that sources only the rich-UI function block (tty_print through
# _ui_winch_trap) extracted from install.sh.  Output from those functions
# is captured to a scratch file so there is no need for a real TTY.
#
# Usage:
#   dash  tests/rich-ui-dash/harness.sh
#   bash  tests/rich-ui-dash/harness.sh
#
# Exit 0 — all scenarios passed.
# Exit 1 — one or more failures (details printed to stderr).

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_SH="$(cd "$SCRIPT_DIR/../.." && pwd)/scripts/install.sh"

# ---------------------------------------------------------------------------
# Extract the rich-UI function block from install.sh.
# We pull from tty_print() (first function in the block) through the closing
# brace of _ui_winch_trap() (last function before "Step 1 — Arg parsing").
# Strategy: awk from the start marker to the blank line after the first "}"
# that follows the _ui_winch_trap function body.
# ---------------------------------------------------------------------------
RICH_BLOCK=$(awk '
    /^tty_print\(\)/ { in_block = 1 }
    in_block { print }
    in_block && /^_ui_winch_trap\(\)/ { in_winch = 1 }
    in_winch && /^}$/ { exit }
' "$INSTALL_SH")

# ---------------------------------------------------------------------------
# Failure tracking.
# ---------------------------------------------------------------------------
FAILS=0
PASS=0

_fail() {
    printf 'FAIL: %s\n' "$1" >&2
    FAILS=$(( FAILS + 1 ))
}

_pass() {
    printf 'ok  : %s\n' "$1"
    PASS=$(( PASS + 1 ))
}

# ---------------------------------------------------------------------------
# _run_scenario LABEL SNIPPET [ROWS [COLS]]
#
# Writes SNIPPET into a temp sh file that (1) sets up all rich-UI globals,
# (2) sources the RICH_BLOCK, and (3) runs the snippet.  Runs under `sh`.
# All output from UI functions goes to a scratch file (not a real TTY).
# ---------------------------------------------------------------------------
_H_TMPDIR=$(mktemp -d)
trap 'rm -rf "$_H_TMPDIR"' EXIT INT TERM

_run_scenario() {
    _rs_label="$1"
    _rs_snippet="$2"
    _rs_rows="${3:-24}"
    _rs_cols="${4:-80}"

    _rs_file="${_H_TMPDIR}/s$$.sh"
    _rs_tty="${_H_TMPDIR}/t$$.out"
    _rs_err="${_H_TMPDIR}/e$$.txt"

    # Write the global state setup + extracted functions + test snippet.
    # We use printf to avoid any heredoc quoting issues inside _rs_snippet.
    {
        printf '#!/bin/sh\nset -eu\n'
        # Rich-UI global state variables.
        printf 'RICH_UI=0\n'
        printf 'RICH_UI_MIN_ROWS=9\n'
        printf 'ALT_SCREEN_ACTIVE=0\n'
        printf 'STTY_RAW_ACTIVE=0\n'
        printf 'STTY_SAVED=""\n'
        printf 'SPINNER_PID=0\n'
        printf 'SUMMARY_FILE=""\n'
        printf 'UI_TTY=""\n'
        printf 'UI_ROWS=0\n'
        printf 'UI_COLS=0\n'
        printf 'UI_CURRENT_HEADER=""\n'
        printf 'WINCH_PENDING=0\n'
        printf 'UI_PHASE_NAMES=""\n'
        printf 'UI_PHASE_STATUSES=""\n'
        printf 'UI_PHASE_COUNT=0\n'
        printf 'UI_DETAIL_TEXT=""\n'
        printf 'UI_ANIM_PID=0\n'
        # Inject the extracted function block.
        printf '%s\n' "$RICH_BLOCK"
        # Configure RICH_UI=1, pointing UI_TTY at a scratch file.
        printf 'RICH_UI=1\n'
        printf 'UI_TTY="%s"\n' "$_rs_tty"
        printf 'UI_ROWS="%s"\n' "$_rs_rows"
        printf 'UI_COLS="%s"\n' "$_rs_cols"
        printf 'export TERM="${TERM:-dumb}"\n'
        # The test scenario.
        printf '%s\n' "$_rs_snippet"
    } >"$_rs_file"

    if sh "$_rs_file" 2>"$_rs_err"; then
        _pass "$_rs_label"
    else
        _rs_exit=$?
        _rs_msg=$(cat "$_rs_err" 2>/dev/null | head -3 || true)
        _fail "$_rs_label (exit=$_rs_exit) $_rs_msg"
    fi
    rm -f "$_rs_file" "$_rs_tty" "$_rs_err"
}

# ===========================================================================
# Scenarios
# ===========================================================================

# ---------------------------------------------------------------------------
# ui_clamp
# ---------------------------------------------------------------------------

_run_scenario "ui_clamp: zero width returns empty" '
out=$(ui_clamp 0 "hello")
[ -z "$out" ] || { printf "expected empty, got: %s\n" "$out" >&2; exit 1; }
'

_run_scenario "ui_clamp: positive width truncates" '
out=$(ui_clamp 3 "hello")
[ "$out" = "hel" ] || { printf "expected hel, got: %s\n" "$out" >&2; exit 1; }
'

_run_scenario "ui_clamp: width >= length returns full string" '
out=$(ui_clamp 10 "hi")
[ "$out" = "hi" ] || { printf "expected hi, got: %s\n" "$out" >&2; exit 1; }
'

_run_scenario "ui_clamp: narrow terminal 20 cols" '
out=$(ui_clamp 20 "  this is a long phase name that should be truncated")
len=$(printf "%s" "$out" | wc -c | tr -d " ")
[ "$len" -le 20 ] || { printf "expected <=20 chars, got %s\n" "$len" >&2; exit 1; }
' 24 20

_run_scenario "ui_clamp: wide terminal 200 cols" '
out=$(ui_clamp 200 "short")
[ "$out" = "short" ] || { printf "expected short, got: %s\n" "$out" >&2; exit 1; }
' 24 200

# ---------------------------------------------------------------------------
# ui_init_phases
# ---------------------------------------------------------------------------

_run_scenario "ui_init_phases: 1 phase" '
ui_init_phases "Phase A"
[ "$UI_PHASE_COUNT" -eq 1 ] || { printf "count=%s\n" "$UI_PHASE_COUNT" >&2; exit 1; }
[ "$UI_PHASE_STATUSES" = "pending" ] || { printf "statuses=%s\n" "$UI_PHASE_STATUSES" >&2; exit 1; }
'

_run_scenario "ui_init_phases: 3 phases" '
ui_init_phases "$(printf "Phase A\nPhase B\nPhase C")"
[ "$UI_PHASE_COUNT" -eq 3 ] || { printf "count=%s\n" "$UI_PHASE_COUNT" >&2; exit 1; }
'

_run_scenario "ui_init_phases: 8 phases" '
ui_init_phases "$(printf "P1\nP2\nP3\nP4\nP5\nP6\nP7\nP8")"
[ "$UI_PHASE_COUNT" -eq 8 ] || { printf "count=%s\n" "$UI_PHASE_COUNT" >&2; exit 1; }
'

_run_scenario "ui_init_phases: 15 phases" '
names=""
i=1
while [ "$i" -le 15 ]; do
    names=$(printf "%s\nPhase %d" "$names" "$i")
    i=$(( i + 1 ))
done
ui_init_phases "$names"
[ "$UI_PHASE_COUNT" -eq 15 ] || { printf "count=%s\n" "$UI_PHASE_COUNT" >&2; exit 1; }
'

# ---------------------------------------------------------------------------
# ui_set_phase_status / ui_phase_status
# ---------------------------------------------------------------------------

_run_scenario "ui_set_phase_status: change first" '
ui_init_phases "$(printf "A\nB\nC")"
UI_PHASE_STATUSES=$(ui_set_phase_status 1 active)
s=$(ui_phase_status 1)
[ "$s" = "active" ] || { printf "status=%s\n" "$s" >&2; exit 1; }
s2=$(ui_phase_status 2)
[ "$s2" = "pending" ] || { printf "status2=%s\n" "$s2" >&2; exit 1; }
'

_run_scenario "ui_set_phase_status: change middle" '
ui_init_phases "$(printf "A\nB\nC")"
UI_PHASE_STATUSES=$(ui_set_phase_status 2 done)
s=$(ui_phase_status 2)
[ "$s" = "done" ] || { printf "status=%s\n" "$s" >&2; exit 1; }
'

_run_scenario "ui_set_phase_status: change last" '
ui_init_phases "$(printf "A\nB\nC")"
UI_PHASE_STATUSES=$(ui_set_phase_status 3 failed)
s=$(ui_phase_status 3)
[ "$s" = "failed" ] || { printf "status=%s\n" "$s" >&2; exit 1; }
'

# ---------------------------------------------------------------------------
# _ui_render_checklist_body: BUG #1 regression + viewport scenarios
# ---------------------------------------------------------------------------

# BUG #1 regression: active phase in the middle must not yield "Illegal number".
_run_scenario "render_body: active at middle (BUG #1 regression)" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_PHASE_STATUSES=$(ui_set_phase_status 2 active)
_ui_render_checklist_body 10
'

_run_scenario "render_body: active at first" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_PHASE_STATUSES=$(ui_set_phase_status 1 active)
_ui_render_checklist_body 10
'

_run_scenario "render_body: active at last" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_PHASE_STATUSES=$(ui_set_phase_status 3 active)
_ui_render_checklist_body 10
'

_run_scenario "render_body: no active phase (all pending)" '
ui_init_phases "$(printf "P1\nP2\nP3")"
_ui_render_checklist_body 10
'

_run_scenario "render_body: active at middle of 8 phases" '
ui_init_phases "$(printf "P1\nP2\nP3\nP4\nP5\nP6\nP7\nP8")"
UI_PHASE_STATUSES=$(ui_set_phase_status 5 active)
_ui_render_checklist_body 10
'

_run_scenario "render_body: active at middle of 15 phases" '
names=""
i=1
while [ "$i" -le 15 ]; do
    names=$(printf "%s\nPhase %d" "$names" "$i")
    i=$(( i + 1 ))
done
ui_init_phases "$names"
UI_PHASE_STATUSES=$(ui_set_phase_status 8 active)
_ui_render_checklist_body 10
'

# avail_rows < phase_count forces auto-follow viewport.
_run_scenario "render_body: avail_rows < phase_count (viewport scroll)" '
ui_init_phases "$(printf "P1\nP2\nP3\nP4\nP5\nP6\nP7\nP8")"
UI_PHASE_STATUSES=$(ui_set_phase_status 5 active)
_ui_render_checklist_body 4
'

# avail_rows > phase_count: all phases fit, no scrolling needed.
_run_scenario "render_body: avail_rows > phase_count (no scroll)" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_PHASE_STATUSES=$(ui_set_phase_status 2 active)
_ui_render_checklist_body 20
'

_run_scenario "render_body: narrow cols=20" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_PHASE_STATUSES=$(ui_set_phase_status 2 active)
_ui_render_checklist_body 10
' 24 20

_run_scenario "render_body: wide cols=200" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_PHASE_STATUSES=$(ui_set_phase_status 2 active)
_ui_render_checklist_body 10
' 24 200

_run_scenario "render_body: zero phases (no-op)" '
ui_init_phases ""
_ui_render_checklist_body 10
'

_run_scenario "render_body: 1 phase all-pending rows=1" '
ui_init_phases "Only"
_ui_render_checklist_body 1
'

# ---------------------------------------------------------------------------
# ui_render_checklist (full repaint)
# ---------------------------------------------------------------------------

_run_scenario "ui_render_checklist: 3 phases active at 2" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_PHASE_STATUSES=$(ui_set_phase_status 2 active)
UI_CURRENT_HEADER="sandboxd · test"
ui_render_checklist
'

_run_scenario "ui_render_checklist: 8 phases active at 5, narrow 20 cols" '
ui_init_phases "$(printf "P1\nP2\nP3\nP4\nP5\nP6\nP7\nP8")"
UI_PHASE_STATUSES=$(ui_set_phase_status 5 active)
UI_CURRENT_HEADER="header"
ui_render_checklist
' 24 20

_run_scenario "ui_render_checklist: tiny terminal (rows=5)" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_PHASE_STATUSES=$(ui_set_phase_status 1 active)
UI_CURRENT_HEADER="tiny"
ui_render_checklist
' 5 40

# ---------------------------------------------------------------------------
# set_phase transitions
# ---------------------------------------------------------------------------

_run_scenario "set_phase: pending -> active -> done" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_CURRENT_HEADER="transitions"
set_phase 1 pending
set_phase 1 active "working on P1"
set_phase 1 done
'

_run_scenario "set_phase: active at first of 1 phase" '
ui_init_phases "Solo"
UI_CURRENT_HEADER="solo"
set_phase 1 active "doing solo"
set_phase 1 done
'

_run_scenario "set_phase: active at last of 3 phases" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_CURRENT_HEADER="last"
set_phase 1 done
set_phase 2 done
set_phase 3 active "last phase"
set_phase 3 done
'

_run_scenario "set_phase: full 8-phase lifecycle" '
ui_init_phases "$(printf "P1\nP2\nP3\nP4\nP5\nP6\nP7\nP8")"
UI_CURRENT_HEADER="lifecycle"
i=1
while [ "$i" -le 8 ]; do
    set_phase "$i" active "running phase $i"
    set_phase "$i" done
    i=$(( i + 1 ))
done
'

_run_scenario "set_phase: failure path" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_CURRENT_HEADER="failure"
set_phase 1 done
set_phase 2 active "P2 running"
set_phase 2 failed
'

# ---------------------------------------------------------------------------
# Animator start / stop
# ---------------------------------------------------------------------------

_run_scenario "animator: start then stop" '
ui_init_phases "$(printf "P1\nP2")"
UI_CURRENT_HEADER="anim"
set_phase 1 active "animating"
sleep 0.1
ui_animator_stop
[ "$UI_ANIM_PID" -eq 0 ] || { printf "PID not cleared: %s\n" "$UI_ANIM_PID" >&2; exit 1; }
'

_run_scenario "animator: double stop is idempotent" '
ui_animator_stop
ui_animator_stop
[ "$UI_ANIM_PID" -eq 0 ] || { printf "PID not zero after double stop\n" >&2; exit 1; }
'

_run_scenario "animator: start replaces running animator" '
ui_init_phases "P1"
set_phase 1 active "first"
set_phase 1 active "second"
ui_animator_stop
[ "$UI_ANIM_PID" -eq 0 ] || { printf "PID not zero\n" >&2; exit 1; }
'

# ---------------------------------------------------------------------------
# ui_service_winch
# ---------------------------------------------------------------------------

_run_scenario "ui_service_winch: no-op when WINCH_PENDING=0" '
ui_init_phases "$(printf "P1\nP2")"
UI_CURRENT_HEADER="winch"
WINCH_PENDING=0
ui_service_winch
'

_run_scenario "ui_service_winch: repaints and clears flag when WINCH_PENDING=1" '
ui_init_phases "$(printf "P1\nP2")"
UI_CURRENT_HEADER="winch"
WINCH_PENDING=1
ui_service_winch
[ "$WINCH_PENDING" -eq 0 ] || { printf "WINCH_PENDING not cleared\n" >&2; exit 1; }
'

# ---------------------------------------------------------------------------
# ui_find_phase
# ---------------------------------------------------------------------------

_run_scenario "ui_find_phase: finds existing phase" '
ui_init_phases "$(printf "Alpha\nBeta\nGamma")"
idx=$(ui_find_phase "Beta")
[ "$idx" -eq 2 ] || { printf "idx=%s expected 2\n" "$idx" >&2; exit 1; }
'

_run_scenario "ui_find_phase: returns 0 for missing phase" '
ui_init_phases "$(printf "Alpha\nBeta")"
idx=$(ui_find_phase "Delta")
[ "$idx" -eq 0 ] || { printf "idx=%s expected 0\n" "$idx" >&2; exit 1; }
'

# ---------------------------------------------------------------------------
# _cp_render logic (confirm_plan pager render, isolated)
#
# _cp_render is a nested function defined inside confirm_plan().  We test it
# by re-creating the surrounding state and defining the function inline.
# ---------------------------------------------------------------------------

_run_scenario "_cp_render: short plan renders without error" '
_cp_plan_text=$(printf "Line 1\nLine 2\nLine 3")
_cp_plan_lines=$(printf "%s" "$_cp_plan_text" | awk "END{print NR}")
_cp_viewport=10
_cp_offset=0
VERSION="0.0.0-test"
UI_CURRENT_HEADER="test"
_cp_render() {
    UI_ROWS="${UI_ROWS:-24}"
    UI_COLS="${UI_COLS:-80}"
    _cp_viewport=$(( UI_ROWS - 4 ))
    [ "$_cp_viewport" -ge 1 ] || _cp_viewport=1
    _cpr_max=$(( _cp_plan_lines - _cp_viewport ))
    [ "$_cpr_max" -ge 0 ] || _cpr_max=0
    [ "$_cp_offset" -le "$_cpr_max" ] || _cp_offset="$_cpr_max"
    WINCH_PENDING=0
    _cpr_end=$(( _cp_offset + _cp_viewport ))
    [ "$_cpr_end" -le "$_cp_plan_lines" ] || _cpr_end="$_cp_plan_lines"
    _cpr_a=$(( _cp_offset + 1 ))
    printf "\033[H\033[2J" >"$UI_TTY"
    ui_render_header "sandboxd $VERSION · review plan"
    printf "%s\n" "$_cp_plan_text" \
        | awk -v s="$_cpr_a" -v e="$_cpr_end" "NR>=s && NR<=e" >"$UI_TTY"
}
_cp_render
'

_run_scenario "_cp_render: offset past end clamps to max" '
_cp_plan_text=$(printf "L1\nL2\nL3\nL4\nL5")
_cp_plan_lines=5
_cp_offset=99
VERSION="0.0.0-test"
_cp_render() {
    UI_ROWS="${UI_ROWS:-24}"
    UI_COLS="${UI_COLS:-80}"
    _cp_viewport=$(( UI_ROWS - 4 ))
    [ "$_cp_viewport" -ge 1 ] || _cp_viewport=1
    _cpr_max=$(( _cp_plan_lines - _cp_viewport ))
    [ "$_cpr_max" -ge 0 ] || _cpr_max=0
    [ "$_cp_offset" -le "$_cpr_max" ] || _cp_offset="$_cpr_max"
    _cpr_a=$(( _cp_offset + 1 ))
    [ "$_cpr_a" -ge 1 ] || { printf "bad cpr_a=%s\n" "$_cpr_a" >&2; exit 1; }
    [ "$_cpr_a" -le "$(( _cp_plan_lines + 1 ))" ] \
        || { printf "cpr_a=%s out of range\n" "$_cpr_a" >&2; exit 1; }
}
_cp_render
'

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n--- %d passed, %d failed ---\n' "$PASS" "$FAILS"
if [ "$FAILS" -gt 0 ]; then
    exit 1
fi
exit 0
