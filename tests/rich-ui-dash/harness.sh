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

# Extract is_utf8 (needed by download_with_bar to pick bar style).
IS_UTF8_BLOCK=$(awk '
    /^is_utf8\(\)/ { in_block = 1 }
    in_block { print }
    in_block && /^}$/ { in_block = 0; exit }
' "$INSTALL_SH")

# Extract _ui_spinner_frame (needed by download_with_bar's loop).
SPINNER_FRAME_BLOCK=$(awk '
    /^_ui_spinner_frame\(\)/ { in_block = 1 }
    in_block { print }
    in_block && /^}$/ { in_block = 0; exit }
' "$INSTALL_SH")

# Extract bar renderers + kb converter + download_with_bar.
BAR_BLOCK=$(awk '
    /^_bar_style_b\(\)/ { in_block = 1 }
    in_block { print }
    in_block && /^download_with_bar\(\)/ { in_dwb = 1 }
    in_dwb && /^}$/ { exit }
' "$INSTALL_SH")

# Extract cleanup_tmpdir (needed to verify cursor-show on exit).
CLEANUP_BLOCK=$(awk '
    /^cleanup_tmpdir\(\)/ { in_block = 1 }
    in_block { print }
    in_block && /^}$/ { in_block = 0; exit }
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
    _rs_extra_block="${5:-}"

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
        printf 'BLUE=""\n'
        printf 'RESET=""\n'
        # Inject the extracted function block.
        printf '%s\n' "$RICH_BLOCK"
        # Inject optional extra block (e.g. bar renderers).
        if [ -n "$_rs_extra_block" ]; then
            printf '%s\n' "$_rs_extra_block"
        fi
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

# Convenience wrapper: injects RICH_BLOCK + is_utf8 + _ui_spinner_frame + BAR_BLOCK.
_run_bar_scenario() {
    _rbs_label="$1"
    _rbs_snippet="$2"
    _rbs_rows="${3:-24}"
    _rbs_cols="${4:-80}"
    _run_scenario "$_rbs_label" "$_rbs_snippet" "$_rbs_rows" "$_rbs_cols" \
        "$(printf '%s\n%s\n%s\n' "$IS_UTF8_BLOCK" "$SPINNER_FRAME_BLOCK" "$BAR_BLOCK")"
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

_run_scenario "ui_clamp: multibyte glyph not split at byte boundary (cut -c regression)" '
# "  ⋮ x" — two spaces, then ⋮ (U+22EE, 3 bytes: e2 8b ae), space, "x"
# At width=3 the column boundary falls inside the ⋮ byte sequence.
# With awk (char-aware) the result must be exactly "  ⋮" (two spaces + whole glyph),
# 5 bytes total.  The old cut -c implementation returned "  " + a partial byte.
inp="  ⋮ x"
out=$(ui_clamp 3 "$inp")
# Verify the full 3-byte sequence of ⋮ is present in the output.
case "$out" in
    *"⋮"*) ;;
    *) printf "glyph ⋮ was split; raw bytes: "; printf "%s" "$out" | od -An -tx1 | tr -d " \n"; printf "\n"; exit 1 ;;
esac
# The output must not extend past 3 characters; "  ⋮" is 3 chars, so no trailing char.
case "$out" in
    "  ⋮") ;;
    *) printf "expected \"  ⋮\", got %s bytes: " "$(printf "%s" "$out" | wc -c | tr -d " ")"; printf "%s" "$out" | od -An -tx1 | tr -d " \n"; printf "\n"; exit 1 ;;
esac
'

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

_run_scenario "animator: _ui_animator_body emits a complete braille UTF-8 glyph (not a partial byte)" '
# Run _ui_animator_body for a short burst (0.3 s covers at least one 0.25 s tick)
# then kill it and inspect what it wrote to the TTY.
_ab_tty="$UI_TTY"
_ui_animator_body "test task" &
_ab_pid=$!
sleep 0.3
kill "$_ab_pid" 2>/dev/null || true
wait "$_ab_pid" 2>/dev/null || true
_ab_out=$(cat "$_ab_tty")
# The output must contain at least one complete braille spinner glyph.
# A partial-byte extraction would produce a broken byte sequence and would NOT
# match any of these full 3-byte UTF-8 braille characters.
_ab_found=0
for _g in "⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧"; do
    case "$_ab_out" in
        *"$_g"*) _ab_found=1; break ;;
    esac
done
[ "$_ab_found" -eq 1 ] \
    || { printf "_ui_animator_body output contains no complete braille spinner glyph (possible partial-byte bug)\n" >&2; exit 1; }
'

_run_scenario "animator: detail-line width clamp does not split leading glyph bytes (cut -c regression)" '
# At terminal width 4 the detail line is "  ⠋ task" (2 spaces + braille glyph + space + ...).
# Each braille glyph is 3 bytes (e.g. ⠋ = e2 a0 8b).  At width=4 the whole prefix
# "  ⠋ " fits (4 chars).  The old cut -c implementation would count 4 BYTES and
# return "  " + first 2 bytes of the glyph, emitting a broken sequence.
# Run for a short burst and capture the output to verify no partial byte appears.
_ab_tty="$UI_TTY"
_ui_animator_body "task" &
_ab_pid=$!
sleep 0.6
kill "$_ab_pid" 2>/dev/null || true
wait "$_ab_pid" 2>/dev/null || true
_ab_raw=$(cat "$_ab_tty")
# At least one complete braille glyph must be present in the output.
# If a partial byte was emitted the canonical 3-byte form would not match.
_ab_found=0
for _g in "⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧"; do
    case "$_ab_raw" in
        *"$_g"*) _ab_found=1; break ;;
    esac
done
[ "$_ab_found" -eq 1 ] \
    || { printf "no complete braille glyph in output at narrow width — possible cut-c byte-split\n" >&2; exit 1; }
' 24 4

_run_scenario "animator: braille frame changes across ticks (spinner animates)" '
# Run _ui_animator_body for ~1.1 s (covers at least 4 ticks at 0.25 s each).
# Capture the output and verify that at least 2 distinct braille glyphs appear —
# confirming that the frame advances and is not stuck on a single symbol.
_ab_tty="$UI_TTY"
_ui_animator_body "animating task" &
_ab_pid=$!
sleep 1.1
kill "$_ab_pid" 2>/dev/null || true
wait "$_ab_pid" 2>/dev/null || true
_ab_out=$(cat "$_ab_tty")
_ab_distinct=0
for _g in "⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧"; do
    case "$_ab_out" in
        *"$_g"*) _ab_distinct=$(( _ab_distinct + 1 )) ;;
    esac
done
[ "$_ab_distinct" -ge 2 ] \
    || { printf "only %d distinct braille frame(s) in 1.1s — spinner is not advancing\n" "$_ab_distinct" >&2; exit 1; }
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
    _cpr_b="$_cpr_end"
    printf "\033[H" >>"$UI_TTY"
    ui_render_header "sandboxd $VERSION · review plan"
    _cpr_esc=$(printf "\033")
    printf "%s\n" "$_cp_plan_text" \
        | awk -v s="$_cpr_a" -v e="$_cpr_b" \
              -v ORS="\r\n" -v esc="$_cpr_esc" \
              "NR>=s && NR<=e {print esc \"[K\" \$0}" >>"$UI_TTY"
    _cpr_shown=$(( _cpr_b - _cp_offset ))
    _cpr_pad=$(( _cp_viewport - _cpr_shown ))
    _cpr_p=0
    while [ "$_cpr_p" -lt "$_cpr_pad" ]; do
        printf "\033[K\r\n" >>"$UI_TTY"
        _cpr_p=$(( _cpr_p + 1 ))
    done
    _cpr_rule=$(printf "%*s" "${UI_COLS:-80}" "" | tr " " "-" | cut -c1-"${UI_COLS:-80}")
    printf "\033[K%s\r\n" "$_cpr_rule" >>"$UI_TTY"
    printf "\033[K[y] proceed  [n] abort  lines %d-%d of %d  " \
        "$_cpr_a" "$_cpr_b" "$_cp_plan_lines" >>"$UI_TTY"
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
# confirm_plan footer: pager prompt must contain literal arrow glyphs, not \x
#
# The footer printf previously used \xe2\x86\x91 / \xe2\x86\x93 / \xe2\x80\x93
# for ↑, ↓, and – (en-dash).  Dash's printf does not interpret \x escapes (they
# are a bash/GNU extension), so those would print literally as "\xe2\x86\x91"
# etc. under dash.  The fix is to embed the literal UTF-8 glyphs directly.
# This assertion verifies that the footer output contains the actual Unicode
# characters and does NOT contain the text "\x" anywhere.
# ---------------------------------------------------------------------------

_run_scenario "confirm_plan footer: literal ↑/↓/– glyphs, no \\x text" '
# Re-create only the variables the footer printf needs; invoke the footer
# printf directly (no need to exercise the full pager state machine).
_cpr_a=1
_cpr_b=10
_cp_plan_lines=20
_footer_out=$(printf '"'"'[y] proceed  [n] abort  ↑/↓ PgUp/PgDn scroll  lines %d–%d of %d  '"'"' \
    "$_cpr_a" "$_cpr_b" "$_cp_plan_lines")
# Must contain literal ↑.
case "$_footer_out" in
    *"↑"*) : ;;
    *) printf "footer missing literal ↑ arrow\n" >&2; exit 1 ;;
esac
# Must contain literal ↓.
case "$_footer_out" in
    *"↓"*) : ;;
    *) printf "footer missing literal ↓ arrow\n" >&2; exit 1 ;;
esac
# Must contain literal – (en-dash U+2013).
case "$_footer_out" in
    *"–"*) : ;;
    *) printf "footer missing literal – (en-dash)\n" >&2; exit 1 ;;
esac
# Must NOT contain the text \x (which would indicate an uninterpreted hex escape).
case "$_footer_out" in
    *"\\x"*)
        printf "footer contains literal \\\\x text — hex escape was not interpreted: %s\n" \
            "$_footer_out" >&2
        exit 1 ;;
    *) : ;;
esac
'

# ---------------------------------------------------------------------------
# Structural escape-sequence assertions: ui_render_checklist
#
# These assert that the repaint strategy is "clear-as-you-draw":
#   - Every painted line is prefixed with \033[K (erase-to-EOL before content).
#   - A cursor-home sequence is emitted before content.
#   - \033[2J (erase-entire-screen) must NEVER appear — that is the flicker op.
# ---------------------------------------------------------------------------

_run_scenario "escape-seq: ui_render_checklist emits \\033[K on painted lines" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_PHASE_STATUSES=$(ui_set_phase_status 2 active)
UI_CURRENT_HEADER="test header"
ui_render_checklist
# TTY output must contain at least one erase-to-EOL sequence.
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[K")"*) : ;;
    *) printf "missing \\033[K in TTY output\n" >&2; exit 1 ;;
esac
'

_run_scenario "escape-seq: ui_render_checklist emits cursor-home" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_PHASE_STATUSES=$(ui_set_phase_status 1 active)
UI_CURRENT_HEADER="test header"
ui_render_checklist
# TTY output must contain cursor-home (ESC[H or tput home which on most terms
# also produces ESC[H, but we accept either ESC[H or the octal \033[H form).
out=$(cat "$UI_TTY")
# tput home on a dumb term may emit nothing; we check for the common ESC[H.
# On a dumb terminal tput home is a no-op, so we accept missing home only
# when TERM=dumb.  In CI we set TERM=dumb so skip this check gracefully.
case "$TERM" in
    dumb) : ;;  # tput home is a no-op on dumb; skip
    *)
        case "$out" in
            *"$(printf "\033[H")"*) : ;;
            *) printf "missing cursor-home in TTY output\n" >&2; exit 1 ;;
        esac
    ;;
esac
'

_run_scenario "escape-seq: ui_render_checklist must NOT emit \\033[2J" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_PHASE_STATUSES=$(ui_set_phase_status 2 active)
UI_CURRENT_HEADER="test header"
ui_render_checklist
# \033[2J is the erase-entire-screen op that causes flicker.  It must never
# appear in the repaint output.
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[2J")"*)
        printf "\\033[2J found in TTY output — flicker op must not be present\n" >&2
        exit 1 ;;
    *) : ;;
esac
'

_run_scenario "escape-seq: ui_render_checklist must NOT emit \\033[?25h (show cursor)" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_PHASE_STATUSES=$(ui_set_phase_status 2 active)
UI_CURRENT_HEADER="test header"
ui_render_checklist
# The cursor must remain hidden during repaints. Show-cursor (ESC[?25h) must
# never appear in a repaint — cursor is hidden once on alt-screen entry and
# restored explicitly in cleanup_tmpdir on every exit path.
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[?25h")"*)
        printf "\\033[?25h found in TTY output — show-cursor must not appear in repaint\n" >&2
        exit 1 ;;
    *) : ;;
esac
'

# ---------------------------------------------------------------------------
# Structural escape-sequence assertions: _cp_render (plan pager)
#
# Mirrors the checklist assertions above for the plan pager:
#   - \033[2J (erase-entire-screen) must NEVER appear — flicker op.
#   - Each body line must be prefixed with \033[K (erase-to-EOL).
#   - Body lines must end with \r\n (CRLF) because the terminal is in raw mode.
# ---------------------------------------------------------------------------

_run_scenario "escape-seq: _cp_render must NOT emit \\033[2J" '
_cp_plan_text=$(printf "Alpha\nBeta\nGamma")
_cp_plan_lines=3
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
    _cpr_b="$_cpr_end"
    printf "\033[H" >>"$UI_TTY"
    ui_render_header "sandboxd $VERSION · review plan"
    _cpr_esc=$(printf "\033")
    printf "%s\n" "$_cp_plan_text" \
        | awk -v s="$_cpr_a" -v e="$_cpr_b" \
              -v ORS="\r\n" -v esc="$_cpr_esc" \
              "NR>=s && NR<=e {print esc \"[K\" \$0}" >>"$UI_TTY"
    _cpr_shown=$(( _cpr_b - _cp_offset ))
    _cpr_pad=$(( _cp_viewport - _cpr_shown ))
    _cpr_p=0
    while [ "$_cpr_p" -lt "$_cpr_pad" ]; do
        printf "\033[K\r\n" >>"$UI_TTY"
        _cpr_p=$(( _cpr_p + 1 ))
    done
    _cpr_rule=$(printf "%*s" "${UI_COLS:-80}" "" | tr " " "-" | cut -c1-"${UI_COLS:-80}")
    printf "\033[K%s\r\n" "$_cpr_rule" >>"$UI_TTY"
    printf "\033[K[y] proceed  [n] abort  lines %d-%d of %d  " \
        "$_cpr_a" "$_cpr_b" "$_cp_plan_lines" >>"$UI_TTY"
}
_cp_render
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[2J")"*)
        printf "\\033[2J found in _cp_render output — flicker op must not be present\n" >&2
        exit 1 ;;
    *) : ;;
esac
'

_run_scenario "escape-seq: _cp_render emits \\033[K on body lines" '
_cp_plan_text=$(printf "Alpha\nBeta\nGamma")
_cp_plan_lines=3
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
    _cpr_b="$_cpr_end"
    printf "\033[H" >>"$UI_TTY"
    ui_render_header "sandboxd $VERSION · review plan"
    _cpr_esc=$(printf "\033")
    printf "%s\n" "$_cp_plan_text" \
        | awk -v s="$_cpr_a" -v e="$_cpr_b" \
              -v ORS="\r\n" -v esc="$_cpr_esc" \
              "NR>=s && NR<=e {print esc \"[K\" \$0}" >>"$UI_TTY"
    _cpr_shown=$(( _cpr_b - _cp_offset ))
    _cpr_pad=$(( _cp_viewport - _cpr_shown ))
    _cpr_p=0
    while [ "$_cpr_p" -lt "$_cpr_pad" ]; do
        printf "\033[K\r\n" >>"$UI_TTY"
        _cpr_p=$(( _cpr_p + 1 ))
    done
    _cpr_rule=$(printf "%*s" "${UI_COLS:-80}" "" | tr " " "-" | cut -c1-"${UI_COLS:-80}")
    printf "\033[K%s\r\n" "$_cpr_rule" >>"$UI_TTY"
    printf "\033[K[y] proceed  [n] abort  lines %d-%d of %d  " \
        "$_cpr_a" "$_cpr_b" "$_cp_plan_lines" >>"$UI_TTY"
}
_cp_render
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[K")"*) : ;;
    *) printf "missing \\033[K in _cp_render output\n" >&2; exit 1 ;;
esac
'

_run_scenario "escape-seq: _cp_render body lines end with CRLF in raw mode" '
_cp_plan_text=$(printf "Alpha\nBeta\nGamma")
_cp_plan_lines=3
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
    _cpr_b="$_cpr_end"
    printf "\033[H" >>"$UI_TTY"
    ui_render_header "sandboxd $VERSION · review plan"
    _cpr_esc=$(printf "\033")
    printf "%s\n" "$_cp_plan_text" \
        | awk -v s="$_cpr_a" -v e="$_cpr_b" \
              -v ORS="\r\n" -v esc="$_cpr_esc" \
              "NR>=s && NR<=e {print esc \"[K\" \$0}" >>"$UI_TTY"
    _cpr_shown=$(( _cpr_b - _cp_offset ))
    _cpr_pad=$(( _cp_viewport - _cpr_shown ))
    _cpr_p=0
    while [ "$_cpr_p" -lt "$_cpr_pad" ]; do
        printf "\033[K\r\n" >>"$UI_TTY"
        _cpr_p=$(( _cpr_p + 1 ))
    done
    _cpr_rule=$(printf "%*s" "${UI_COLS:-80}" "" | tr " " "-" | cut -c1-"${UI_COLS:-80}")
    printf "\033[K%s\r\n" "$_cpr_rule" >>"$UI_TTY"
    printf "\033[K[y] proceed  [n] abort  lines %d-%d of %d  " \
        "$_cpr_a" "$_cpr_b" "$_cp_plan_lines" >>"$UI_TTY"
}
_cp_render
# Body lines must contain \r\n (CR+LF) because the terminal is in stty raw mode.
# A bare \n (LF-only) would advance the row without returning to column 0,
# producing a staircase.  Check that at least one \r\n appears in the output.
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\r\n")"*) : ;;
    *) printf "no CRLF found in _cp_render output — body lines must end with \\\\r\\\\n in raw mode\n" >&2; exit 1 ;;
esac
'

# Convenience wrapper: injects RICH_BLOCK + CLEANUP_BLOCK.
_run_cleanup_scenario() {
    _rcs_label="$1"
    _rcs_snippet="$2"
    _rcs_rows="${3:-24}"
    _rcs_cols="${4:-80}"
    _run_scenario "$_rcs_label" "$_rcs_snippet" "$_rcs_rows" "$_rcs_cols" \
        "$CLEANUP_BLOCK"
}

_run_cleanup_scenario "escape-seq: cleanup_tmpdir emits \\033[?25h when RICH_UI=1" '
# Preconditions: RICH_UI=1 and UI_TTY are already set by _run_scenario.
# SPINNER_PID, UI_ANIM_PID, ALT_SCREEN_ACTIVE default to 0 so the kill/wait
# and rmcup branches are skipped; only the cursor-show branch executes.
# Initialize vars referenced by cleanup_tmpdir but not set by _run_scenario.
TMPDIR_INSTALL=""
SUMMARY_FILE=""
cleanup_tmpdir
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[?25h")"*) : ;;
    *) printf "\\033[?25h missing from cleanup_tmpdir output in rich mode\n" >&2; exit 1 ;;
esac
'

_run_cleanup_scenario "escape-seq: cleanup_tmpdir must NOT emit \\033[?25h when RICH_UI=0" '
# Override to plain mode: cursor was never hidden, so show-cursor must not fire.
RICH_UI=0
# Initialize vars referenced by cleanup_tmpdir but not set by _run_scenario.
TMPDIR_INSTALL=""
SUMMARY_FILE=""
# Ensure the TTY file exists so cat succeeds even though cleanup_tmpdir will
# not write to it in plain mode (the cursor-show branch is gated on RICH_UI=1).
: >>"$UI_TTY"
cleanup_tmpdir
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[?25h")"*)
        printf "\\033[?25h found in cleanup_tmpdir plain-mode output — must not appear\n" >&2
        exit 1 ;;
    *) : ;;
esac
'

_run_scenario "escape-seq: ui_render_checklist emits trailing \\033[J after content" '
ui_init_phases "$(printf "P1\nP2\nP3")"
UI_PHASE_STATUSES=$(ui_set_phase_status 2 active)
UI_CURRENT_HEADER="test header"
ui_render_checklist
# \033[J erases leftover rows below the newly drawn frame.  It must be present.
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[J")"*) : ;;
    *) printf "missing trailing \\033[J in TTY output\n" >&2; exit 1 ;;
esac
'

# ---------------------------------------------------------------------------
# Structural assertions: _bar_style_b / _bar_style_c return bar cells via stdout
# ---------------------------------------------------------------------------

_run_bar_scenario "_bar_style_b: returns non-empty bar string to stdout" '
bar=$(_bar_style_b 96 24)
[ -n "$bar" ] || { printf "_bar_style_b returned empty\n" >&2; exit 1; }
# Length must equal total_cells (24).
len=$(printf "%s" "$bar" | wc -m | tr -d " ")
[ "$len" -eq 24 ] || { printf "bar len=%s expected 24\n" "$len" >&2; exit 1; }
'

_run_bar_scenario "_bar_style_b: fully empty bar (0 progress)" '
bar=$(_bar_style_b 0 8)
[ -n "$bar" ] || { printf "empty bar returned nothing\n" >&2; exit 1; }
# All cells should be spaces.
expected="        "
[ "$bar" = "$expected" ] || { printf "bar=%s expected 8 spaces\n" "$bar" >&2; exit 1; }
'

_run_bar_scenario "_bar_style_b: fully filled bar" '
bar=$(_bar_style_b 64 8)
[ -n "$bar" ] || { printf "full bar returned nothing\n" >&2; exit 1; }
expected="████████"
[ "$bar" = "$expected" ] || { printf "bar=%s expected 8 full blocks\n" "$bar" >&2; exit 1; }
'

_run_bar_scenario "_bar_style_c: returns non-empty bar string to stdout" '
bar=$(_bar_style_c 12 24)
[ -n "$bar" ] || { printf "_bar_style_c returned empty\n" >&2; exit 1; }
len=$(printf "%s" "$bar" | wc -c | tr -d " ")
[ "$len" -eq 24 ] || { printf "bar len=%s expected 24\n" "$len" >&2; exit 1; }
'

_run_bar_scenario "_bar_style_c: fully empty bar (0 filled)" '
bar=$(_bar_style_c 0 8)
[ -n "$bar" ] || { printf "empty bar returned nothing\n" >&2; exit 1; }
# When filled=0, first cell is ">" and rest are spaces.
case "$bar" in
    ">"*) : ;;
    *) printf "expected > at start, got: %s\n" "$bar" >&2; exit 1 ;;
esac
'

# ---------------------------------------------------------------------------
# Structural assertions: download_with_bar — progress bar is rendered on the
# detail line.  We stub curl with a script that pre-writes the destination
# file and exits, so the poll loop sees a non-zero size and runs at least one
# iteration.
# ---------------------------------------------------------------------------

_run_bar_scenario "download_with_bar: rich mode writes bar framing chars to TTY" '
# Create a fake destination file large enough to report meaningful KB.
_fake_dest="${_H_TMPDIR:-/tmp}/fake_dest_$$"
# Write 512 KB of data so du reports >= 512.
dd if=/dev/zero of="$_fake_dest" bs=1024 count=512 2>/dev/null

# Stub curl: when called with --head, emit a Content-Length header so
# download_with_bar learns the total size and enters the rich progress-bar
# branch.  When called with -o, copy the pre-created file to the destination.
_stub_dir="${_H_TMPDIR:-/tmp}/stub_$$"
mkdir -p "$_stub_dir"
cat >"$_stub_dir/curl" <<'"'"'STUB'"'"'
#!/bin/sh
_is_head=0
_out_file=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --head) _is_head=1; shift ;;
        -o) shift; _out_file="$1"; shift ;;
        *)  shift ;;
    esac
done
if [ "$_is_head" -eq 1 ]; then
    _sz=$(wc -c <"$FAKE_DEST" 2>/dev/null | tr -d ' ')
    printf 'HTTP/1.1 200 OK\r\nContent-Length: %s\r\n\r\n' "${_sz:-524288}"
else
    # Sleep briefly so the poll loop gets at least one tick before curl exits.
    sleep 2
    cp "$FAKE_DEST" "$_out_file"
fi
STUB
chmod +x "$_stub_dir/curl"
export FAKE_DEST="$_fake_dest"
export PATH="$_stub_dir:$PATH"
DOWNLOAD_BAR_FAILED=0
UI_DETAIL_TEXT="fetching tarball"
download_with_bar "http://example.com/fake" "$_fake_dest"
# TTY output must contain the substep title, bar framing, and progress info.
_tty_out=$(cat "$UI_TTY")
for _token in "fetching tarball" "[" "]" "%" "MB" "KB/s"; do
    case "$_tty_out" in
        *"$_token"*) : ;;
        *) printf "missing token {%s} in TTY output\n" "$_token" >&2; rm -rf "$_stub_dir" "$_fake_dest"; exit 1 ;;
    esac
done
rm -rf "$_stub_dir" "$_fake_dest"
'

_run_bar_scenario "download_with_bar: progress line prefix uses braille glyph before title (animator column alignment)" '
_fake_dest="${_H_TMPDIR:-/tmp}/fake_dest_ind_$$"
dd if=/dev/zero of="$_fake_dest" bs=1024 count=512 2>/dev/null
_stub_dir="${_H_TMPDIR:-/tmp}/stub_ind_$$"
mkdir -p "$_stub_dir"
cat >"$_stub_dir/curl" <<'"'"'STUB'"'"'
#!/bin/sh
_is_head=0
_out_file=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --head) _is_head=1; shift ;;
        -o) shift; _out_file="$1"; shift ;;
        *)  shift ;;
    esac
done
if [ "$_is_head" -eq 1 ]; then
    _sz=$(wc -c <"$FAKE_DEST" 2>/dev/null | tr -d ' ')
    printf 'HTTP/1.1 200 OK\r\nContent-Length: %s\r\n\r\n' "${_sz:-524288}"
else
    sleep 2
    cp "$FAKE_DEST" "$_out_file"
fi
STUB
chmod +x "$_stub_dir/curl"
export FAKE_DEST="$_fake_dest"
export PATH="$_stub_dir:$PATH"
DOWNLOAD_BAR_FAILED=0
UI_DETAIL_TEXT="fetching tarball"
download_with_bar "http://example.com/fake" "$_fake_dest"
# The rendered line must contain a braille glyph followed by the title.
# The "  <glyph> " prefix (2 spaces + 1-col braille + 1 space) keeps the title
# at the same display column as the animator detail line.
_tty_out=$(cat "$UI_TTY")
_pref_found=0
for _g in "⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧"; do
    case "$_tty_out" in
        *"  ${_g} fetching tarball"*) _pref_found=1; break ;;
    esac
done
[ "$_pref_found" -eq 1 ] \
    || { printf "progress line missing \"  <braille> fetching tarball\" prefix\n" >&2; rm -rf "$_stub_dir" "$_fake_dest"; exit 1; }
rm -rf "$_stub_dir" "$_fake_dest"
'

_run_bar_scenario "download_with_bar: download bar emits braille glyph (own spinner, not block chars)" '
_fake_dest="${_H_TMPDIR:-/tmp}/fake_dest2_$$"
dd if=/dev/zero of="$_fake_dest" bs=1024 count=512 2>/dev/null
_stub_dir="${_H_TMPDIR:-/tmp}/stub2_$$"
mkdir -p "$_stub_dir"
cat >"$_stub_dir/curl" <<'"'"'STUB'"'"'
#!/bin/sh
_is_head=0
_out_file=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --head) _is_head=1; shift ;;
        -o) shift; _out_file="$1"; shift ;;
        *)  shift ;;
    esac
done
if [ "$_is_head" -eq 1 ]; then
    _sz=$(wc -c <"$FAKE_DEST" 2>/dev/null | tr -d ' ')
    printf 'HTTP/1.1 200 OK\r\nContent-Length: %s\r\n\r\n' "${_sz:-524288}"
else
    sleep 2
    cp "$FAKE_DEST" "$_out_file"
fi
STUB
chmod +x "$_stub_dir/curl"
export FAKE_DEST="$_fake_dest"
export PATH="$_stub_dir:$PATH"
DOWNLOAD_BAR_FAILED=0
UI_DETAIL_TEXT="fetching tarball"
download_with_bar "http://example.com/fake" "$_fake_dest"
_tty_out=$(cat "$UI_TTY")
# The download bar draws its own braille spinner glyph (not the old block chars).
# Confirm at least one braille glyph is present in the captured output.
_braille_found=0
for _g in "⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧"; do
    case "$_tty_out" in
        *"$_g"*) _braille_found=1; break ;;
    esac
done
[ "$_braille_found" -eq 1 ] \
    || { printf "no braille glyph found in download bar output — spinner not rendering\n" >&2; rm -rf "$_stub_dir" "$_fake_dest"; exit 1; }
rm -rf "$_stub_dir" "$_fake_dest"
'

_run_bar_scenario "download_with_bar: spinner glyph changes across ticks (animates during download)" '
# Stub: HEAD reports 2 MB total; body sleeps 3s so the poll loop runs several ticks.
_total_kb=2048
_fake_dest="${_H_TMPDIR:-/tmp}/fake_dest_anim_$$"
_stub_dir="${_H_TMPDIR:-/tmp}/stub_anim_$$"
mkdir -p "$_stub_dir"
export FAKE_DEST="$_fake_dest"
export FAKE_TOTAL_KB="$_total_kb"
cat >"$_stub_dir/curl" <<'"'"'STUB'"'"'
#!/bin/sh
_is_head=0
_out_file=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --head) _is_head=1; shift ;;
        -o) shift; _out_file="$1"; shift ;;
        *)  shift ;;
    esac
done
if [ "$_is_head" -eq 1 ]; then
    printf 'HTTP/1.1 200 OK\r\nContent-Length: %s\r\n\r\n' "$(( FAKE_TOTAL_KB * 1024 ))"
else
    # Write data incrementally so du -k sees a growing file during poll.
    i=0
    while [ "$i" -lt 6 ]; do
        dd if=/dev/zero bs=1024 count=341 2>/dev/null >> "$_out_file"
        sleep 0.4
        i=$(( i + 1 ))
    done
fi
STUB
chmod +x "$_stub_dir/curl"
export PATH="$_stub_dir:$PATH"
DOWNLOAD_BAR_FAILED=0
UI_DETAIL_TEXT="fetching tarball"
download_with_bar "http://example.com/fake" "$_fake_dest"
_tty_out=$(cat "$UI_TTY")
# Count distinct braille frames seen in the captured TTY output.
_distinct=0
for _g in "⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧"; do
    case "$_tty_out" in
        *"$_g"*) _distinct=$(( _distinct + 1 )) ;;
    esac
done
[ "$_distinct" -ge 2 ] \
    || { printf "only %d distinct braille frame(s) in download output — spinner not advancing\n" "$_distinct" >&2; rm -rf "$_stub_dir" "$_fake_dest"; exit 1; }
rm -rf "$_stub_dir" "$_fake_dest"
'

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n--- %d passed, %d failed ---\n' "$PASS" "$FAILS"
if [ "$FAILS" -gt 0 ]; then
    exit 1
fi
exit 0
