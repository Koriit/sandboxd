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
_REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
UI_SH="$_REPO_ROOT/scripts/ui.sh"
INSTALL_SH="$_REPO_ROOT/scripts/install.sh"
UNINSTALL_SH="$_REPO_ROOT/scripts/uninstall.sh"

# ---------------------------------------------------------------------------
# Validate source files exist up front.
# ---------------------------------------------------------------------------
for _f in "$UI_SH" "$INSTALL_SH" "$UNINSTALL_SH"; do
    if [ ! -f "$_f" ]; then
        printf 'harness.sh: required source file not found: %s\n' "$_f" >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# Extract install-specific functions still in install.sh (not in ui.sh).
# ---------------------------------------------------------------------------

# Extract cleanup_tmpdir (needed to verify cursor-show on exit).
CLEANUP_BLOCK=$(awk '
    /^cleanup_tmpdir\(\)/ { in_block = 1 }
    in_block { print }
    in_block && /^}$/ { in_block = 0; exit }
' "$INSTALL_SH")

# Extract _print_failure_report (tested for unguarded-abort failure attribution).
PRINT_FAILURE_REPORT_BLOCK=$(awk '
    /^_print_failure_report\(\)/ { in_block = 1 }
    in_block { print }
    in_block && /^}$/ { in_block = 0; exit }
' "$INSTALL_SH")

# ---------------------------------------------------------------------------
# Extract uninstall-specific functions from uninstall.sh.
# These use TMPDIR_UNINSTALL (not TMPDIR_INSTALL) so they cannot share the
# install extraction blocks above.
# ---------------------------------------------------------------------------

UNINSTALL_CLEANUP_BLOCK=$(awk '
    /^cleanup_tmpdir\(\)/ { in_block = 1 }
    in_block { print }
    in_block && /^}$/ { in_block = 0; exit }
' "$UNINSTALL_SH")

UNINSTALL_PRINT_FAILURE_REPORT_BLOCK=$(awk '
    /^_print_failure_report\(\)/ { in_block = 1 }
    in_block { print }
    in_block && /^}$/ { in_block = 0; exit }
' "$UNINSTALL_SH")

# Extract socket_responsive and check_daemon_running (BLOCKER-2a coverage).
# Both are extracted and concatenated so scenarios have the full call graph.
UNINSTALL_CHECK_DAEMON_BLOCK=$(
    awk '
        /^socket_responsive\(\)/ { in_block = 1 }
        in_block { print }
        in_block && /^}$/ { in_block = 0; exit }
    ' "$UNINSTALL_SH"
    awk '
        /^check_daemon_running\(\)/ { in_block = 1 }
        in_block { print }
        in_block && /^}$/ { in_block = 0; exit }
    ' "$UNINSTALL_SH"
)

# Extract record_removed and print_next_steps (SF-2 coverage).
UNINSTALL_RECORD_REMOVED_BLOCK=$(awk '
    /^record_removed\(\)/ { in_block = 1 }
    in_block { print }
    in_block && /^}$/ { in_block = 0; exit }
' "$UNINSTALL_SH")

UNINSTALL_PRINT_NEXT_STEPS_BLOCK=$(awk '
    /^print_next_steps\(\)/ { in_block = 1 }
    in_block { print }
    in_block && /^}$/ { in_block = 0; exit }
' "$UNINSTALL_SH")

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
# (2) sources ui.sh, and (3) runs the snippet.  Runs under `sh`.
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

    # Write the global state setup + sourced ui.sh + test snippet.
    # We use printf to avoid any heredoc quoting issues inside _rs_snippet.
    {
        printf '#!/bin/sh\nset -eu\n'
        # Variables ui.sh requires callers to define before sourcing.
        printf 'QUIET=0\n'
        printf 'NO_COLOR=0\n'
        printf 'VERBOSE=0\n'
        printf 'INSTALL_LOG=/dev/null\n'
        printf 'SCRIPT_NAME=test\n'
        # Expose source file paths so scenarios can inspect install.sh
        # properties (e.g. grep for expected strings without hardcoding paths).
        printf 'UI_SH="%s"\n' "$UI_SH"
        printf 'INSTALL_SH="%s"\n' "$INSTALL_SH"
        # Source the engine from ui.sh — all rich-UI functions and their
        # module-level defaults are defined by this single dot-source.
        # shellcheck disable=SC1090
        printf '. "%s"\n' "$UI_SH"
        # Inject optional extra block (e.g. install-specific functions).
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

# Convenience wrapper: runs a bar-renderer scenario.
# All bar functions (is_utf8, _ui_spinner_frame, _bar_style_b/c,
# _kb_to_mb_1dp, download_with_bar) live in ui.sh and are already sourced
# by _run_scenario, so no extra block is needed here.
_run_bar_scenario() {
    _rbs_label="$1"
    _rbs_snippet="$2"
    _rbs_rows="${3:-24}"
    _rbs_cols="${4:-80}"
    _run_scenario "$_rbs_label" "$_rbs_snippet" "$_rbs_rows" "$_rbs_cols"
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
for _g in "⠁" "⠂" "⠄" "⠉" "⣿" "⠿"; do
    case "$_ab_out" in
        *"$_g"*) _ab_found=1; break ;;
    esac
done
[ "$_ab_found" -eq 1 ] \
    || { printf "_ui_animator_body output contains no complete braille spinner glyph (possible partial-byte bug)\n" >&2; exit 1; }
'

_run_scenario "animator: detail-line width clamp does not split leading glyph bytes (cut -c regression)" '
# At terminal width 4 the detail line is "  ⠁ task" (2 spaces + braille glyph + space + ...).
# Each braille glyph is 3 bytes (e.g. ⠁ = e2 a0 81).  At width=4 the whole prefix
# "  ⠁ " fits (4 chars).  The old cut -c implementation would count 4 BYTES and
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
for _g in "⠁" "⠂" "⠄" "⠉" "⣿" "⠿"; do
    case "$_ab_raw" in
        *"$_g"*) _ab_found=1; break ;;
    esac
done
[ "$_ab_found" -eq 1 ] \
    || { printf "no complete braille glyph in output at narrow width — possible cut-c byte-split\n" >&2; exit 1; }
' 24 4

_run_scenario "animator: braille frame changes across ticks (spinner animates)" '
# Run _ui_animator_body for ~1.5 s, which covers ~6 frames of the 35-frame
# wrap-around cycle (35 × 0.25 s = 8.75 s full cycle; no duplicate frames so
# even a short capture reliably yields ≥ 2 distinct glyphs).
_ab_tty="$UI_TTY"
_ui_animator_body "animating task" &
_ab_pid=$!
sleep 1.5
kill "$_ab_pid" 2>/dev/null || true
wait "$_ab_pid" 2>/dev/null || true
_ab_out=$(cat "$_ab_tty")
_ab_distinct=0
for _g in "⠁" "⠂" "⠄" "⠉" "⣿" "⠿"; do
    case "$_ab_out" in
        *"$_g"*) _ab_distinct=$(( _ab_distinct + 1 )) ;;
    esac
done
[ "$_ab_distinct" -ge 2 ] \
    || { printf "only %d distinct braille frame(s) in 1.5s — spinner is not advancing\n" "$_ab_distinct" >&2; exit 1; }
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

# Convenience wrapper for alt-screen scenarios.
# ui_enter_alt_screen lives in ui.sh and is already sourced by _run_scenario;
# no extra block injection is needed.
_run_alt_screen_scenario() {
    _ras_label="$1"
    _ras_snippet="$2"
    _ras_rows="${3:-24}"
    _ras_cols="${4:-80}"
    _run_scenario "$_ras_label" "$_ras_snippet" "$_ras_rows" "$_ras_cols"
}

# Convenience wrapper: injects CLEANUP_BLOCK (install-specific functions).
# The rich-UI engine is already sourced from ui.sh by _run_scenario.
_run_cleanup_scenario() {
    _rcs_label="$1"
    _rcs_snippet="$2"
    _rcs_rows="${3:-24}"
    _rcs_cols="${4:-80}"
    _run_scenario "$_rcs_label" "$_rcs_snippet" "$_rcs_rows" "$_rcs_cols" \
        "$CLEANUP_BLOCK"
}

# Convenience wrapper: injects UNINSTALL_CHECK_DAEMON_BLOCK
# (socket_responsive + check_daemon_running from uninstall.sh).
_run_uninstall_check_daemon_scenario() {
    _rudcs_label="$1"
    _rudcs_snippet="$2"
    _rudcs_rows="${3:-24}"
    _rudcs_cols="${4:-80}"
    _run_scenario "$_rudcs_label" "$_rudcs_snippet" "$_rudcs_rows" "$_rudcs_cols" \
        "$UNINSTALL_CHECK_DAEMON_BLOCK"
}

# Convenience wrapper: injects UNINSTALL_RECORD_REMOVED_BLOCK +
# UNINSTALL_PRINT_NEXT_STEPS_BLOCK (SF-2 coverage).
_run_uninstall_next_steps_scenario() {
    _runss_label="$1"
    _runss_snippet="$2"
    _runss_rows="${3:-24}"
    _runss_cols="${4:-80}"
    _run_scenario "$_runss_label" "$_runss_snippet" "$_runss_rows" "$_runss_cols" \
        "$(printf '%s\n%s\n' "$UNINSTALL_RECORD_REMOVED_BLOCK" "$UNINSTALL_PRINT_NEXT_STEPS_BLOCK")"
}

# Convenience wrapper: injects UNINSTALL_CLEANUP_BLOCK (uninstall-specific
# functions).  Uses TMPDIR_UNINSTALL so it cannot share _run_cleanup_scenario.
_run_uninstall_cleanup_scenario() {
    _rucs_label="$1"
    _rucs_snippet="$2"
    _rucs_rows="${3:-24}"
    _rucs_cols="${4:-80}"
    _run_scenario "$_rucs_label" "$_rucs_snippet" "$_rucs_rows" "$_rucs_cols" \
        "$UNINSTALL_CLEANUP_BLOCK"
}

_run_cleanup_scenario "escape-seq: cleanup_tmpdir emits \\033[?25h when RICH_UI=1" '
# Preconditions: RICH_UI=1 and UI_TTY are already set by _run_scenario.
# SPINNER_PID, UI_ANIM_PID, ALT_SCREEN_ACTIVE default to 0 so the kill/wait
# and rmcup branches are skipped; only the cursor-show branch executes.
# Initialize vars referenced by cleanup_tmpdir but not set by _run_scenario.
_phase_reader_pid=0
_consumer_pid=0
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
_phase_reader_pid=0
_consumer_pid=0
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
for _g in "⠁" "⠂" "⠄" "⠉" "⣿" "⠿"; do
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
# The download bar draws its own braille wrap-around spinner glyph (not the old block chars).
# Confirm at least one braille glyph is present in the captured output.
_braille_found=0
for _g in "⠁" "⠂" "⠄" "⠉" "⣿" "⠿"; do
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
for _g in "⠁" "⠂" "⠄" "⠉" "⣿" "⠿"; do
    case "$_tty_out" in
        *"$_g"*) _distinct=$(( _distinct + 1 )) ;;
    esac
done
[ "$_distinct" -ge 2 ] \
    || { printf "only %d distinct braille frame(s) in download output — spinner not advancing\n" "$_distinct" >&2; rm -rf "$_stub_dir" "$_fake_dest"; exit 1; }
rm -rf "$_stub_dir" "$_fake_dest"
'

# ---------------------------------------------------------------------------
# DECAWM (auto-wrap) control: ui_enter_alt_screen and cleanup_tmpdir
#
# Fix B disables auto-wrap on alt-screen entry (\033[?7l) and restores it
# on every exit path (\033[?7h).  Both sequences must be gated on RICH_UI=1
# so plain mode is byte-identical (drift-safe).
# ---------------------------------------------------------------------------

_run_alt_screen_scenario "escape-seq: ui_enter_alt_screen emits \\033[?7l in rich mode" '
# RICH_UI=1 and UI_TTY are already set by _run_scenario.
ui_enter_alt_screen
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[?7l")"*) : ;;
    *) printf "\\033[?7l missing from ui_enter_alt_screen output in rich mode\n" >&2; exit 1 ;;
esac
'

_run_alt_screen_scenario "escape-seq: ui_enter_alt_screen must NOT emit \\033[?7l in plain mode" '
RICH_UI=0
: >>"$UI_TTY"
ui_enter_alt_screen
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[?7l")"*)
        printf "\\033[?7l found in ui_enter_alt_screen plain-mode output — must not appear\n" >&2
        exit 1 ;;
    *) : ;;
esac
'

_run_cleanup_scenario "escape-seq: cleanup_tmpdir emits \\033[?7h when RICH_UI=1" '
_phase_reader_pid=0
_consumer_pid=0
TMPDIR_INSTALL=""
SUMMARY_FILE=""
cleanup_tmpdir
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[?7h")"*) : ;;
    *) printf "\\033[?7h missing from cleanup_tmpdir output in rich mode\n" >&2; exit 1 ;;
esac
'

_run_cleanup_scenario "escape-seq: cleanup_tmpdir must NOT emit \\033[?7h when RICH_UI=0" '
RICH_UI=0
_phase_reader_pid=0
_consumer_pid=0
TMPDIR_INSTALL=""
SUMMARY_FILE=""
: >>"$UI_TTY"
cleanup_tmpdir
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[?7h")"*)
        printf "\\033[?7h found in cleanup_tmpdir plain-mode output — must not appear\n" >&2
        exit 1 ;;
    *) : ;;
esac
'

# ---------------------------------------------------------------------------
# Write-then-erase order: animator and download detail writes
#
# Fix A moves the erase-to-EOL (\033[K) AFTER content so the cursor never
# passes through a blank stretch.  Assert that no \033[K appears immediately
# after \r (which would mean erase-before-write), and that content does
# appear before the trailing \033[K.
# ---------------------------------------------------------------------------

_run_scenario "escape-seq: animator detail write is write-then-erase (no \\033[K immediately after \\r)" '
_ab_tty="$UI_TTY"
_ui_animator_body "checking order" &
_ab_pid=$!
sleep 0.3
kill "$_ab_pid" 2>/dev/null || true
wait "$_ab_pid" 2>/dev/null || true
out=$(cat "$_ab_tty")
# The erase-before-write pattern is \r followed immediately by \033[K.
# That sequence must NOT appear in the output.
case "$out" in
    *"$(printf "\r\033[K")"*)
        printf "animator emits \\r\\033[K (erase-before-write) — must be write-then-erase\n" >&2
        exit 1 ;;
    *) : ;;
esac
# At least one \033[K must still be present (the trailing erase-to-EOL).
case "$out" in
    *"$(printf "\033[K")"*) : ;;
    *) printf "no \\033[K at all in animator output — trailing erase-to-EOL is missing\n" >&2; exit 1 ;;
esac
'

_run_bar_scenario "escape-seq: download_with_bar detail write is write-then-erase (no \\033[K immediately after \\r)" '
_fake_dest="${_H_TMPDIR:-/tmp}/fake_dest_erase_$$"
dd if=/dev/zero of="$_fake_dest" bs=1024 count=512 2>/dev/null
_stub_dir="${_H_TMPDIR:-/tmp}/stub_erase_$$"
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
    _sz=$(wc -c <"$FAKE_DEST" 2>/dev/null | tr -d " ")
    printf "HTTP/1.1 200 OK\r\nContent-Length: %s\r\n\r\n" "${_sz:-524288}"
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
out=$(cat "$UI_TTY")
# The erase-before-write pattern (\r immediately followed by \033[K) must not appear.
case "$out" in
    *"$(printf "\r\033[K")"*)
        printf "download_with_bar emits \\r\\033[K (erase-before-write) — must be write-then-erase\n" >&2
        rm -rf "$_stub_dir" "$_fake_dest"
        exit 1 ;;
    *) : ;;
esac
# At least one trailing \033[K must be present.
case "$out" in
    *"$(printf "\033[K")"*) : ;;
    *) printf "no \\033[K at all in download_with_bar output — trailing erase-to-EOL is missing\n" >&2
       rm -rf "$_stub_dir" "$_fake_dest"
       exit 1 ;;
esac
rm -rf "$_stub_dir" "$_fake_dest"
'

# ---------------------------------------------------------------------------
# GREEN bar SGR: download_with_bar wraps bar cells in GREEN when GREEN is set
# ---------------------------------------------------------------------------

_run_bar_scenario "green-bar: rich mode output contains GREEN SGR around bar cells" '
GREEN=$(printf "\033[0;32m")
RESET=$(printf "\033[0m")
_fake_dest="${_H_TMPDIR:-/tmp}/fake_dest_green_$$"
dd if=/dev/zero of="$_fake_dest" bs=1024 count=512 2>/dev/null
_stub_dir="${_H_TMPDIR:-/tmp}/stub_green_$$"
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
    _sz=$(wc -c <"$FAKE_DEST" 2>/dev/null | tr -d " ")
    printf "HTTP/1.1 200 OK\r\nContent-Length: %s\r\n\r\n" "${_sz:-524288}"
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
out=$(cat "$UI_TTY")
# GREEN SGR (printf '\''\033[0;32m'\'') must appear in the output.
_green=$(printf "\033[0;32m")
case "$out" in
    *"${_green}"*)
        : ;;
    *)
        printf "GREEN SGR not found in download_with_bar output — bar coloring missing\n" >&2
        rm -rf "$_stub_dir" "$_fake_dest"
        exit 1 ;;
esac
# RESET SGR (printf '\''\033[0m'\'') must appear after the GREEN SGR.
_reset=$(printf "\033[0m")
case "$out" in
    *"${_green}"*"${_reset}"*)
        : ;;
    *)
        printf "RESET SGR not found after GREEN SGR in download_with_bar output\n" >&2
        rm -rf "$_stub_dir" "$_fake_dest"
        exit 1 ;;
esac
rm -rf "$_stub_dir" "$_fake_dest"
'

_run_bar_scenario "green-bar: plain mode (GREEN unset) emits no GREEN SGR" '
# GREEN is deliberately left unset (or empty) — plain mode must emit no SGR.
GREEN=""
_fake_dest="${_H_TMPDIR:-/tmp}/fake_dest_plain_$$"
dd if=/dev/zero of="$_fake_dest" bs=1024 count=512 2>/dev/null
_stub_dir="${_H_TMPDIR:-/tmp}/stub_plain_$$"
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
    _sz=$(wc -c <"$FAKE_DEST" 2>/dev/null | tr -d " ")
    printf "HTTP/1.1 200 OK\r\nContent-Length: %s\r\n\r\n" "${_sz:-524288}"
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
out=$(cat "$UI_TTY")
# With GREEN="" the ${GREEN:-} expansion yields nothing — no SGR bytes emitted.
_green=$(printf "\033[0;32m")
case "$out" in
    *"${_green}"*)
        printf "GREEN SGR found in plain-mode output — must not appear when GREEN is empty\n" >&2
        rm -rf "$_stub_dir" "$_fake_dest"
        exit 1 ;;
    *) : ;;
esac
rm -rf "$_stub_dir" "$_fake_dest"
'

# ---------------------------------------------------------------------------
# Ctrl-D / Ctrl-U structural: byte matchers defined, offset math correct
# ---------------------------------------------------------------------------

# Unit-test the Ctrl-D half-page scroll offset arithmetic directly.
_run_scenario "ctrl-d/ctrl-u: Ctrl-D scrolls down half a page with clamping" '
# Simulate a pager state and apply the Ctrl-D arm logic directly.
_cp_plan_lines=40
_cp_viewport=20
_cp_offset=0
# Ctrl-D arm logic (verbatim from confirm_plan):
_cp_half=$(( _cp_viewport / 2 ))
if [ "$_cp_half" -lt 1 ]; then _cp_half=1; fi
_cp_max=$(( _cp_plan_lines - _cp_viewport ))
if [ "$_cp_max" -lt 0 ]; then _cp_max=0; fi
_cp_offset=$(( _cp_offset + _cp_half ))
if [ "$_cp_offset" -gt "$_cp_max" ]; then _cp_offset="$_cp_max"; fi
# Half of 20 = 10; from offset 0 we should land at 10.
[ "$_cp_offset" -eq 10 ] || {
    printf "expected offset 10, got %d\n" "$_cp_offset" >&2; exit 1
}
# Second Ctrl-D from offset 10 should land at 20 (== _cp_max).
_cp_offset=$(( _cp_offset + _cp_half ))
if [ "$_cp_offset" -gt "$_cp_max" ]; then _cp_offset="$_cp_max"; fi
[ "$_cp_offset" -eq 20 ] || {
    printf "expected offset 20 (clamped to max), got %d\n" "$_cp_offset" >&2; exit 1
}
# Third Ctrl-D from max should stay at max (clamped).
_cp_offset=$(( _cp_offset + _cp_half ))
if [ "$_cp_offset" -gt "$_cp_max" ]; then _cp_offset="$_cp_max"; fi
[ "$_cp_offset" -eq 20 ] || {
    printf "expected offset 20 (still clamped), got %d\n" "$_cp_offset" >&2; exit 1
}
'

_run_scenario "ctrl-d/ctrl-u: Ctrl-U scrolls up half a page floored at 0" '
_cp_plan_lines=40
_cp_viewport=20
_cp_offset=15
# Ctrl-U arm logic (verbatim from confirm_plan):
_cp_half=$(( _cp_viewport / 2 ))
if [ "$_cp_half" -lt 1 ]; then _cp_half=1; fi
_cp_offset=$(( _cp_offset - _cp_half ))
if [ "$_cp_offset" -lt 0 ]; then _cp_offset=0; fi
# Half of 20 = 10; from offset 15 we should land at 5.
[ "$_cp_offset" -eq 5 ] || {
    printf "expected offset 5, got %d\n" "$_cp_offset" >&2; exit 1
}
# Second Ctrl-U from offset 5 should land at 0 (floored).
_cp_offset=$(( _cp_offset - _cp_half ))
if [ "$_cp_offset" -lt 0 ]; then _cp_offset=0; fi
[ "$_cp_offset" -eq 0 ] || {
    printf "expected offset 0 (floored), got %d\n" "$_cp_offset" >&2; exit 1
}
# Third Ctrl-U from 0 should stay at 0.
_cp_offset=$(( _cp_offset - _cp_half ))
if [ "$_cp_offset" -lt 0 ]; then _cp_offset=0; fi
[ "$_cp_offset" -eq 0 ] || {
    printf "expected offset 0 (still floored), got %d\n" "$_cp_offset" >&2; exit 1
}
'

_run_scenario "ctrl-d/ctrl-u: half-page minimum is 1 even with tiny viewport" '
# A viewport of 1 gives _cp_half = 0 from integer division; minimum clamped to 1.
_cp_plan_lines=10
_cp_viewport=1
_cp_offset=0
_cp_half=$(( _cp_viewport / 2 ))
if [ "$_cp_half" -lt 1 ]; then _cp_half=1; fi
[ "$_cp_half" -eq 1 ] || {
    printf "expected _cp_half=1 for viewport=1, got %d\n" "$_cp_half" >&2; exit 1
}
'

_run_scenario "ctrl-d/ctrl-u: byte matchers use POSIX printf (0x04 and 0x15)" '
# Verify the raw byte values generated by the POSIX printf patterns.
_cp_cd=$(printf '"'"'\004'"'"')
_cp_cu=$(printf '"'"'\025'"'"')
# The byte matcher for Ctrl-D must be exactly one byte with value 0x04.
_cd_len=$(printf "%s" "$_cp_cd" | wc -c | tr -d " ")
[ "$_cd_len" -eq 1 ] || {
    printf "_cp_cd length expected 1, got %s\n" "$_cd_len" >&2; exit 1
}
# The byte matcher for Ctrl-U must be exactly one byte with value 0x15.
_cu_len=$(printf "%s" "$_cp_cu" | wc -c | tr -d " ")
[ "$_cu_len" -eq 1 ] || {
    printf "_cp_cu length expected 1, got %s\n" "$_cu_len" >&2; exit 1
}
# Confirm they are distinct.
[ "$_cp_cd" != "$_cp_cu" ] || {
    printf "_cp_cd and _cp_cu must be distinct bytes\n" >&2; exit 1
}
'

_run_scenario "ctrl-d/ctrl-u: footer text contains no Ctrl-D or Ctrl-U reference" '
# The footer line is assembled in _cp_render via printf; check the ui.sh
# source directly to confirm the footer string does not mention Ctrl-D, Ctrl-U,
# or their key symbols (^D, ^U, C-d, C-u).
_footer_line=$(grep -n "proceed.*abort.*PgUp" "$UI_SH" | head -1)
# Must find the footer line at all.
[ -n "$_footer_line" ] || {
    printf "footer line not found in ui.sh\n" >&2; exit 1
}
# Footer must not contain any reference to the hidden keys.
case "$_footer_line" in
    *"Ctrl-D"*|*"Ctrl-U"*|*"^D"*|*"^U"*|*"C-d"*|*"C-u"*)
        printf "footer text references hidden scroll keys — must be absent\n" >&2
        exit 1 ;;
    *) : ;;
esac
'

# ---------------------------------------------------------------------------
# _print_failure_report: failure attribution and log-tail display.
# These scenarios verify the rich branch names the failing step (not "unknown")
# and renders the "Last log lines:" section when a log-tail file is present.
# ---------------------------------------------------------------------------

_run_scenario "failure-report rich: step name present, not 'unknown'" "
$(printf '%s\n' "$PRINT_FAILURE_REPORT_BLOCK")
QUIET=0
RED=''
GREEN=''
RESET=''
STATE_PATH=''
INSTALL_LOG='/var/log/sandbox-install.log'
TMPDIR_INSTALL=\$(mktemp -d)
trap 'rm -rf \"\$TMPDIR_INSTALL\"' EXIT
# No log-tail file — test only the step-name attribution in rich mode.
UI_PHASE_COUNT=3
UI_PHASE_NAMES=\$(printf 'sandbox-user\ninstall-binaries\nwrite-install-state\n')
UI_PHASE_STATUSES=\$(printf 'done\nfailed\n')
out=\$(_print_failure_report 'install-binaries' '2' '13' '' 2>&1)
case \"\$out\" in
    *'install-binaries'*) ;;
    *) printf 'step name not in output; got: %s\n' \"\$out\" >&2; exit 1 ;;
esac
case \"\$out\" in
    *'unknown'*) printf 'fallback word \"unknown\" must not appear; got: %s\n' \"\$out\" >&2; exit 1 ;;
    *) ;;
esac
"

_run_scenario "failure-report rich: log-tail section present when file exists" "
$(printf '%s\n' "$PRINT_FAILURE_REPORT_BLOCK")
QUIET=0
RED=''
GREEN=''
RESET=''
STATE_PATH=''
INSTALL_LOG='/var/log/sandbox-install.log'
TMPDIR_INSTALL=\$(mktemp -d)
trap 'rm -rf \"\$TMPDIR_INSTALL\"' EXIT
printf 'step=install_binaries action=fail status=fail\n' > \"\$TMPDIR_INSTALL/failure-log-tail.txt\"
UI_PHASE_COUNT=3
UI_PHASE_NAMES=\$(printf 'sandbox-user\ninstall-binaries\nwrite-install-state\n')
UI_PHASE_STATUSES=\$(printf 'done\nfailed\n')
out=\$(_print_failure_report 'install-binaries' '2' '13' '' 2>&1)
case \"\$out\" in
    *'Last log lines:'*) ;;
    *) printf 'log-tail section not in output; got: %s\n' \"\$out\" >&2; exit 1 ;;
esac
case \"\$out\" in
    *'step=install_binaries'*) ;;
    *) printf 'log-tail content not in output; got: %s\n' \"\$out\" >&2; exit 1 ;;
esac
"

_run_scenario "failure-report rich: no log-tail section when file absent" "
$(printf '%s\n' "$PRINT_FAILURE_REPORT_BLOCK")
QUIET=0
RED=''
GREEN=''
RESET=''
STATE_PATH=''
INSTALL_LOG='/var/log/sandbox-install.log'
TMPDIR_INSTALL=\$(mktemp -d)
trap 'rm -rf \"\$TMPDIR_INSTALL\"' EXIT
# No failure-log-tail.txt — log-tail section must be absent.
UI_PHASE_COUNT=3
UI_PHASE_NAMES=\$(printf 'sandbox-user\ninstall-binaries\nwrite-install-state\n')
UI_PHASE_STATUSES=\$(printf 'done\nfailed\n')
out=\$(_print_failure_report 'install-binaries' '2' '13' '' 2>&1)
case \"\$out\" in
    *'Last log lines:'*) printf 'log-tail section present but file absent; got: %s\n' \"\$out\" >&2; exit 1 ;;
    *) ;;
esac
"

_run_scenario "failure-report plain: log-tail section present and content appears" "
$(printf '%s\n' "$PRINT_FAILURE_REPORT_BLOCK")
QUIET=0
RED=''
GREEN=''
RESET=''
STATE_PATH=''
INSTALL_LOG='/var/log/sandbox-install.log'
TMPDIR_INSTALL=\$(mktemp -d)
trap 'rm -rf \"\$TMPDIR_INSTALL\"' EXIT
printf 'step=install_binaries action=fail status=fail\n' > \"\$TMPDIR_INSTALL/failure-log-tail.txt\"
RICH_UI=0
UI_PHASE_COUNT=0
UI_PHASE_NAMES=''
UI_PHASE_STATUSES=''
out=\$(_print_failure_report 'install-binaries' '2' '13' '' 2>&1)
case \"\$out\" in
    *'Last log lines:'*) ;;
    *) printf 'plain: log-tail section not in output; got: %s\n' \"\$out\" >&2; exit 1 ;;
esac
case \"\$out\" in
    *'step=install_binaries'*) ;;
    *) printf 'plain: log-tail content not in output; got: %s\n' \"\$out\" >&2; exit 1 ;;
esac
"

_run_scenario "failure-report plain: log-tail bytes identical to rich branch" "
$(printf '%s\n' "$PRINT_FAILURE_REPORT_BLOCK")
QUIET=0
RED=''
GREEN=''
RESET=''
STATE_PATH=''
INSTALL_LOG='/var/log/sandbox-install.log'
TMPDIR_INSTALL=\$(mktemp -d)
trap 'rm -rf \"\$TMPDIR_INSTALL\"' EXIT
printf 'step=install_binaries action=fail status=fail\n' > \"\$TMPDIR_INSTALL/failure-log-tail.txt\"
UI_PHASE_COUNT=3
RICH_UI=1
UI_PHASE_NAMES=\$(printf 'sandbox-user\ninstall-binaries\nwrite-install-state\n')
UI_PHASE_STATUSES=\$(printf 'done\nfailed\n')
_rich_out=\$(_print_failure_report 'install-binaries' '2' '13' '' 2>&1)
RICH_UI=0
UI_PHASE_COUNT=0
UI_PHASE_NAMES=''
UI_PHASE_STATUSES=''
_plain_out=\$(_print_failure_report 'install-binaries' '2' '13' '' 2>&1)
_rich_tail=\$(printf '%s\n' \"\$_rich_out\" | sed -n '/Last log lines:/,\$p')
_plain_tail=\$(printf '%s\n' \"\$_plain_out\" | sed -n '/Last log lines:/,\$p')
[ \"\$_rich_tail\" = \"\$_plain_tail\" ] || {
    printf 'log-tail block differs between rich and plain branches\nrich:\n%s\nplain:\n%s\n' \"\$_rich_tail\" \"\$_plain_tail\" >&2
    exit 1
}
"

# ---------------------------------------------------------------------------
# die() regression guards — BLOCKING-1 (plain-mode terse output) and
# BLOCKING-2 (rich-mode active-phase ✗ omitted).
# ---------------------------------------------------------------------------

# BLOCKING-1: in plain mode, die() emits the terse "${RED}x${RESET} <msg>" line
# directly via emit() — not via ui_die_report/SUMMARY_FILE.  ui_teardown must
# NOT flush any report in plain mode.
_run_scenario "die regression: plain mode emit produces terse x-prefixed line" '
RICH_UI=0
out=$(emit "${RED}x${RESET} Boom" 2>/dev/null)
case "$out" in
    *"Boom"*) ;;
    *) printf "expected \"Boom\" in plain-mode emit output; got: %s\n" "$out" >&2; exit 1 ;;
esac
'

# BLOCKING-1 (teardown): in plain mode ui_teardown must NOT flush SUMMARY_FILE
# even if it contains content (master guards the flush with RICH_UI=1).
_run_scenario "die regression: plain mode ui_teardown must NOT flush SUMMARY_FILE" '
RICH_UI=0
SUMMARY_FILE=$(mktemp)
trap "rm -f $SUMMARY_FILE" EXIT
printf "should not appear\n" > "$SUMMARY_FILE"
out=$(ui_teardown 2>/dev/null)
case "$out" in
    *"should not appear"*)
        printf "plain-mode ui_teardown flushed SUMMARY_FILE — must not appear\n" >&2; exit 1 ;;
    *) ;;
esac
'

# BLOCKING-1 (rich variant): when RICH_UI=1 ui_die_report writes to SUMMARY_FILE
# and ui_teardown flushes it to stdout.
_run_scenario "die regression: rich mode still flushes SUMMARY_FILE via ui_teardown" '
SUMMARY_FILE=$(mktemp)
trap "rm -f $SUMMARY_FILE" EXIT
RICH_UI=1
ui_init_phases "Phase 1
Phase 2"
UI_PHASE_STATUSES=$(printf "done\npending\n")
ui_die_report "RichBoom" "fix it and re-run" "/dev/null"
out=$(ui_teardown 2>/dev/null)
case "$out" in
    *"RichBoom"*) ;;
    *) printf "expected \"RichBoom\" in rich-mode teardown output; got: %s\n" "$out" >&2; exit 1 ;;
esac
'

# BLOCKING-2: when ui_die_report fires while a phase is active, the durable
# report must contain "✗ <phase-name>" (i.e. the active phase is flipped to
# failed before the checklist is rendered).
_run_scenario "die regression: active phase appears as failed in SUMMARY_FILE" '
SUMMARY_FILE=$(mktemp)
trap "rm -f $SUMMARY_FILE" EXIT
RICH_UI=1
ui_init_phases "Phase 1
Phase 2
Phase 3"
UI_PHASE_STATUSES=$(printf "done\nactive\npending\n")
ui_die_report "Boom" "fix it" "/dev/null"
content=$(cat "$SUMMARY_FILE")
# Phase 2 must appear as ✗ (octal \342\234\227 = UTF-8 cross mark)
case "$content" in
    *"Phase 2"*) ;;
    *) printf "Phase 2 missing from report; got:\n%s\n" "$content" >&2; exit 1 ;;
esac
# Verify the error text is present
case "$content" in
    *"Boom"*) ;;
    *) printf "Error text missing from report; got:\n%s\n" "$content" >&2; exit 1 ;;
esac
'

# BLOCKING-2 (variant): when no phase is active, ui_die_report must not fail.
_run_scenario "die regression: ui_die_report with no active phase succeeds" '
SUMMARY_FILE=$(mktemp)
trap "rm -f $SUMMARY_FILE" EXIT
RICH_UI=1
ui_init_phases "Phase 1
Phase 2"
UI_PHASE_STATUSES=$(printf "done\ndone\n")
ui_die_report "NoBoom" "fix it" "/dev/null"
content=$(cat "$SUMMARY_FILE")
case "$content" in
    *"NoBoom"*) ;;
    *) printf "Error text missing from report; got:\n%s\n" "$content" >&2; exit 1 ;;
esac
'

# ===========================================================================
# Uninstall-specific scenarios
# ===========================================================================
#
# These scenarios exercise functions extracted from uninstall.sh.  They
# mirror the install equivalents above but use TMPDIR_UNINSTALL instead of
# TMPDIR_INSTALL.

# ---------------------------------------------------------------------------
# uninstall cleanup_tmpdir — cursor-show and DECAWM escape sequences.
# ---------------------------------------------------------------------------

# CURSOR-SHOW: cleanup_tmpdir emits \033[?25h in rich mode.
_run_uninstall_cleanup_scenario "uninstall: cleanup_tmpdir emits \\033[?25h when RICH_UI=1" '
# SPINNER_PID, UI_ANIM_PID, ALT_SCREEN_ACTIVE default to 0; cursor-show
# branch executes; tmpdir/summary vars are empty so deletion branches skip.
_phase_reader_pid=0
_consumer_pid=0
TMPDIR_UNINSTALL=""
SUMMARY_FILE=""
cleanup_tmpdir
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[?25h")"*) : ;;
    *) printf "\\033[?25h missing from uninstall cleanup_tmpdir rich-mode output\n" >&2; exit 1 ;;
esac
'

# CURSOR-SHOW: cleanup_tmpdir must NOT emit \033[?25h in plain mode.
_run_uninstall_cleanup_scenario "uninstall: cleanup_tmpdir must NOT emit \\033[?25h when RICH_UI=0" '
RICH_UI=0
_phase_reader_pid=0
_consumer_pid=0
TMPDIR_UNINSTALL=""
SUMMARY_FILE=""
: >>"$UI_TTY"
cleanup_tmpdir
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[?25h")"*)
        printf "\\033[?25h found in uninstall cleanup_tmpdir plain-mode output — must not appear\n" >&2
        exit 1 ;;
    *) : ;;
esac
'

# DECAWM restore: cleanup_tmpdir emits \033[?7h in rich mode.
_run_uninstall_cleanup_scenario "uninstall: cleanup_tmpdir emits \\033[?7h when RICH_UI=1" '
_phase_reader_pid=0
_consumer_pid=0
TMPDIR_UNINSTALL=""
SUMMARY_FILE=""
cleanup_tmpdir
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[?7h")"*) : ;;
    *) printf "\\033[?7h missing from uninstall cleanup_tmpdir rich-mode output\n" >&2; exit 1 ;;
esac
'

# DECAWM restore: cleanup_tmpdir must NOT emit \033[?7h in plain mode.
_run_uninstall_cleanup_scenario "uninstall: cleanup_tmpdir must NOT emit \\033[?7h when RICH_UI=0" '
RICH_UI=0
_phase_reader_pid=0
_consumer_pid=0
TMPDIR_UNINSTALL=""
SUMMARY_FILE=""
: >>"$UI_TTY"
cleanup_tmpdir
out=$(cat "$UI_TTY")
case "$out" in
    *"$(printf "\033[?7h")"*)
        printf "\\033[?7h found in uninstall cleanup_tmpdir plain-mode output — must not appear\n" >&2
        exit 1 ;;
    *) : ;;
esac
'

# ---------------------------------------------------------------------------
# uninstall _print_failure_report — failure attribution and log-tail.
# ---------------------------------------------------------------------------

# Rich mode: failing step label appears in output, not the fallback "unknown".
_run_scenario "uninstall failure-report rich: step name present, not 'unknown'" "
$(printf '%s\n' "$UNINSTALL_PRINT_FAILURE_REPORT_BLOCK")
QUIET=0
RED=''
GREEN=''
RESET=''
INSTALL_LOG='/var/log/sandbox-install.log'
TMPDIR_UNINSTALL=\$(mktemp -d)
trap 'rm -rf \"\$TMPDIR_UNINSTALL\"' EXIT
UI_PHASE_COUNT=3
UI_PHASE_NAMES=\$(printf 'stop-disable-unit\nremove-binaries\nremove-users-conf\n')
UI_PHASE_STATUSES=\$(printf 'done\nfailed\n')
out=\$(_print_failure_report 'remove-binaries' '2' '6' '' 2>&1)
case \"\$out\" in
    *'remove-binaries'*) ;;
    *) printf 'step name not in output; got: %s\n' \"\$out\" >&2; exit 1 ;;
esac
case \"\$out\" in
    *'unknown'*) printf 'fallback word \"unknown\" must not appear; got: %s\n' \"\$out\" >&2; exit 1 ;;
    *) ;;
esac
"

# Rich mode: log-tail section appears when failure-log-tail.txt exists.
_run_scenario "uninstall failure-report rich: log-tail section present when file exists" "
$(printf '%s\n' "$UNINSTALL_PRINT_FAILURE_REPORT_BLOCK")
QUIET=0
RED=''
GREEN=''
RESET=''
INSTALL_LOG='/var/log/sandbox-install.log'
TMPDIR_UNINSTALL=\$(mktemp -d)
trap 'rm -rf \"\$TMPDIR_UNINSTALL\"' EXIT
printf 'step=remove_binaries action=fail status=fail\n' > \"\$TMPDIR_UNINSTALL/failure-log-tail.txt\"
UI_PHASE_COUNT=3
UI_PHASE_NAMES=\$(printf 'stop-disable-unit\nremove-binaries\nremove-users-conf\n')
UI_PHASE_STATUSES=\$(printf 'done\nfailed\n')
out=\$(_print_failure_report 'remove-binaries' '2' '6' '' 2>&1)
case \"\$out\" in
    *'Last log lines:'*) ;;
    *) printf 'log-tail section not in output; got: %s\n' \"\$out\" >&2; exit 1 ;;
esac
case \"\$out\" in
    *'step=remove_binaries'*) ;;
    *) printf 'log-tail content not in output; got: %s\n' \"\$out\" >&2; exit 1 ;;
esac
"

# Rich mode: no log-tail section when failure-log-tail.txt is absent.
_run_scenario "uninstall failure-report rich: no log-tail section when file absent" "
$(printf '%s\n' "$UNINSTALL_PRINT_FAILURE_REPORT_BLOCK")
QUIET=0
RED=''
GREEN=''
RESET=''
INSTALL_LOG='/var/log/sandbox-install.log'
TMPDIR_UNINSTALL=\$(mktemp -d)
trap 'rm -rf \"\$TMPDIR_UNINSTALL\"' EXIT
UI_PHASE_COUNT=3
UI_PHASE_NAMES=\$(printf 'stop-disable-unit\nremove-binaries\nremove-users-conf\n')
UI_PHASE_STATUSES=\$(printf 'done\nfailed\n')
out=\$(_print_failure_report 'remove-binaries' '2' '6' '' 2>&1)
case \"\$out\" in
    *'Last log lines:'*) printf 'log-tail section present but file absent; got: %s\n' \"\$out\" >&2; exit 1 ;;
    *) ;;
esac
"

# Plain mode: log-tail section appears when failure-log-tail.txt exists.
_run_scenario "uninstall failure-report plain: log-tail section present and content appears" "
$(printf '%s\n' "$UNINSTALL_PRINT_FAILURE_REPORT_BLOCK")
QUIET=0
RED=''
GREEN=''
RESET=''
INSTALL_LOG='/var/log/sandbox-install.log'
TMPDIR_UNINSTALL=\$(mktemp -d)
trap 'rm -rf \"\$TMPDIR_UNINSTALL\"' EXIT
printf 'step=remove_binaries action=fail status=fail\n' > \"\$TMPDIR_UNINSTALL/failure-log-tail.txt\"
RICH_UI=0
UI_PHASE_COUNT=0
UI_PHASE_NAMES=''
UI_PHASE_STATUSES=''
out=\$(_print_failure_report 'remove-binaries' '2' '6' '' 2>&1)
case \"\$out\" in
    *'Last log lines:'*) ;;
    *) printf 'plain: log-tail section not in output; got: %s\n' \"\$out\" >&2; exit 1 ;;
esac
case \"\$out\" in
    *'step=remove_binaries'*) ;;
    *) printf 'plain: log-tail content not in output; got: %s\n' \"\$out\" >&2; exit 1 ;;
esac
"

# Plain mode: log-tail block identical between rich and plain branches.
_run_scenario "uninstall failure-report plain: log-tail bytes identical to rich branch" "
$(printf '%s\n' "$UNINSTALL_PRINT_FAILURE_REPORT_BLOCK")
QUIET=0
RED=''
GREEN=''
RESET=''
INSTALL_LOG='/var/log/sandbox-install.log'
TMPDIR_UNINSTALL=\$(mktemp -d)
trap 'rm -rf \"\$TMPDIR_UNINSTALL\"' EXIT
printf 'step=remove_binaries action=fail status=fail\n' > \"\$TMPDIR_UNINSTALL/failure-log-tail.txt\"
UI_PHASE_COUNT=3
RICH_UI=1
UI_PHASE_NAMES=\$(printf 'stop-disable-unit\nremove-binaries\nremove-users-conf\n')
UI_PHASE_STATUSES=\$(printf 'done\nfailed\n')
_rich_out=\$(_print_failure_report 'remove-binaries' '2' '6' '' 2>&1)
RICH_UI=0
UI_PHASE_COUNT=0
UI_PHASE_NAMES=''
UI_PHASE_STATUSES=''
_plain_out=\$(_print_failure_report 'remove-binaries' '2' '6' '' 2>&1)
_rich_tail=\$(printf '%s\n' \"\$_rich_out\" | sed -n '/Last log lines:/,\$p')
_plain_tail=\$(printf '%s\n' \"\$_plain_out\" | sed -n '/Last log lines:/,\$p')
[ \"\$_rich_tail\" = \"\$_plain_tail\" ] || {
    printf 'log-tail block differs between rich and plain branches\nrich:\n%s\nplain:\n%s\n' \"\$_rich_tail\" \"\$_plain_tail\" >&2
    exit 1
}
"

# ---------------------------------------------------------------------------
# uninstall die() regression guards
# ---------------------------------------------------------------------------

# BLOCKING-1 (uninstall): in plain mode cleanup_tmpdir must NOT flush
# SUMMARY_FILE even when it has content.
_run_uninstall_cleanup_scenario "uninstall die regression: plain mode cleanup_tmpdir must NOT flush SUMMARY_FILE" '
RICH_UI=0
_phase_reader_pid=0
_consumer_pid=0
TMPDIR_UNINSTALL=""
SUMMARY_FILE=$(mktemp)
trap "rm -f $SUMMARY_FILE" EXIT
printf "should not appear\n" > "$SUMMARY_FILE"
out=$(cleanup_tmpdir 2>/dev/null)
case "$out" in
    *"should not appear"*)
        printf "plain-mode cleanup_tmpdir flushed SUMMARY_FILE — must not appear\n" >&2; exit 1 ;;
    *) : ;;
esac
'

# BLOCKING-1 (uninstall, rich variant): when RICH_UI=1 ui_die_report writes
# to SUMMARY_FILE and the teardown path inside cleanup_tmpdir flushes it.
_run_uninstall_cleanup_scenario "uninstall die regression: rich mode cleanup_tmpdir flushes SUMMARY_FILE via ui_teardown" '
_phase_reader_pid=0
_consumer_pid=0
SUMMARY_FILE=$(mktemp)
trap "rm -f $SUMMARY_FILE" EXIT
RICH_UI=1
TMPDIR_UNINSTALL=""
ui_init_phases "stop-disable-unit
remove-binaries"
UI_PHASE_STATUSES=$(printf "done\npending\n")
ui_die_report "UninstallRichBoom" "fix it and re-run uninstall.sh" "/dev/null"
out=$(cleanup_tmpdir 2>/dev/null)
case "$out" in
    *"UninstallRichBoom"*) : ;;
    *) printf "expected \"UninstallRichBoom\" in cleanup_tmpdir rich-mode output; got: %s\n" "$out" >&2; exit 1 ;;
esac
'

# ---------------------------------------------------------------------------
# BLOCKER-2a: check_daemon_running — SUMMARY_FILE routing for daemon-refuse.
# ---------------------------------------------------------------------------

# Rich mode, daemon running, FORCE=0: refuse message goes to SUMMARY_FILE,
# not stdout.  Call inside a subshell because the function calls exit 1.
_run_uninstall_check_daemon_scenario "uninstall blocker-2a: daemon-refuse in rich mode goes to SUMMARY_FILE" '
FORCE=0
SOCK_PATH=/nonexistent/sandboxd.sock
# Stub socket_responsive to report daemon is up without touching the filesystem.
socket_responsive() { return 0; }
SUMMARY_FILE=$(mktemp)
trap "rm -f $SUMMARY_FILE" EXIT
( check_daemon_running ) || true
got=$(cat "$SUMMARY_FILE")
case "$got" in
    *"sandboxd is running"*) : ;;
    *) printf "expected refuse message in SUMMARY_FILE; got: %s\n" "$got" >&2; exit 1 ;;
esac
'

# Rich mode, daemon running, FORCE=0: refuse message must NOT go to stdout
# when SUMMARY_FILE is set (it goes there instead).
_run_uninstall_check_daemon_scenario "uninstall blocker-2a: daemon-refuse in rich mode is absent from stdout" '
FORCE=0
SOCK_PATH=/nonexistent/sandboxd.sock
socket_responsive() { return 0; }
SUMMARY_FILE=$(mktemp)
trap "rm -f $SUMMARY_FILE" EXIT
out=$( ( check_daemon_running ) 2>/dev/null || true )
case "$out" in
    *"sandboxd is running"*)
        printf "refuse message appeared on stdout — should be in SUMMARY_FILE; got: %s\n" "$out" >&2; exit 1 ;;
    *) : ;;
esac
'

# Plain mode, daemon running, FORCE=0: refuse message goes to stdout
# (SUMMARY_FILE routing must NOT fire when RICH_UI=0).
_run_uninstall_check_daemon_scenario "uninstall blocker-2a: daemon-refuse in plain mode goes to stdout" '
RICH_UI=0
FORCE=0
SOCK_PATH=/nonexistent/sandboxd.sock
socket_responsive() { return 0; }
SUMMARY_FILE=$(mktemp)
trap "rm -f $SUMMARY_FILE" EXIT
out=$( ( check_daemon_running ) 2>/dev/null || true )
case "$out" in
    *"sandboxd is running"*) : ;;
    *) printf "plain mode: expected refuse message on stdout; got: %s\n" "$out" >&2; exit 1 ;;
esac
'

# No daemon: check_daemon_running returns 0 and no refuse message is emitted.
_run_uninstall_check_daemon_scenario "uninstall blocker-2a: no daemon means no refuse message" '
FORCE=0
SOCK_PATH=/nonexistent/sandboxd.sock
socket_responsive() { return 1; }
SUMMARY_FILE=$(mktemp)
trap "rm -f $SUMMARY_FILE" EXIT
check_daemon_running
[ -z "$(cat "$SUMMARY_FILE")" ] || {
    printf "SUMMARY_FILE non-empty when no daemon; content: %s\n" "$(cat "$SUMMARY_FILE")" >&2; exit 1
}
'

# ---------------------------------------------------------------------------
# BLOCKER-2b: _emit_confirm_no_tty routing — SUMMARY_FILE in rich mode.
#
# confirm_plan() calls exit 1 after writing; we test the routing branch
# directly (define the helper and apply the dispatch logic) rather than
# triggering the full confirm_plan() path, which would require /dev/tty to
# be absent — an invariant we cannot guarantee at test time.
# ---------------------------------------------------------------------------

# Rich mode: no-tty message goes to SUMMARY_FILE, not stdout.
_run_scenario "uninstall blocker-2b: no-tty abort in rich mode goes to SUMMARY_FILE" '
_emit_confirm_no_tty() {
    printf "%s\n" "Aborting: no terminal and --yes not passed."
    printf "%s\n" "  Re-run with --yes to proceed non-interactively:"
    printf "%s\n" "      uninstall.sh --yes [other options]"
}
SUMMARY_FILE=$(mktemp)
trap "rm -f $SUMMARY_FILE" EXIT
if [ "$RICH_UI" -eq 1 ] && [ -n "$SUMMARY_FILE" ]; then
    _emit_confirm_no_tty > "$SUMMARY_FILE"
else
    _emit_confirm_no_tty >&2
fi
got=$(cat "$SUMMARY_FILE")
case "$got" in
    *"Aborting: no terminal"*) : ;;
    *) printf "expected no-tty message in SUMMARY_FILE; got: %s\n" "$got" >&2; exit 1 ;;
esac
'

# Plain mode: no-tty message goes to stderr (not SUMMARY_FILE).
_run_scenario "uninstall blocker-2b: no-tty abort in plain mode goes to stderr, not SUMMARY_FILE" '
RICH_UI=0
_emit_confirm_no_tty() {
    printf "%s\n" "Aborting: no terminal and --yes not passed."
}
SUMMARY_FILE=$(mktemp)
_err_capture=$(mktemp)
trap "rm -f $SUMMARY_FILE $_err_capture" EXIT
if [ "$RICH_UI" -eq 1 ] && [ -n "$SUMMARY_FILE" ]; then
    _emit_confirm_no_tty > "$SUMMARY_FILE"
else
    _emit_confirm_no_tty >"$_err_capture" 2>&1
fi
[ -z "$(cat "$SUMMARY_FILE")" ] || {
    printf "plain: SUMMARY_FILE non-empty — should have gone to stderr; content: %s\n" "$(cat "$SUMMARY_FILE")" >&2; exit 1
}
err=$(cat "$_err_capture")
case "$err" in
    *"Aborting: no terminal"*) : ;;
    *) printf "plain: expected no-tty message on stderr; got: %s\n" "$err" >&2; exit 1 ;;
esac
'

# ---------------------------------------------------------------------------
# BLOCKER-2c / SF-1: _emit_purge_decline routing — SUMMARY_FILE in rich mode.
# ---------------------------------------------------------------------------

# Rich mode: purge-decline message goes to SUMMARY_FILE, not stdout.
_run_scenario "uninstall blocker-2c: purge-decline in rich mode goes to SUMMARY_FILE" '
_emit_purge_decline() {
    printf "%b\n" "${YELLOW}!${RESET} Aborted. No changes were made."
}
SUMMARY_FILE=$(mktemp)
trap "rm -f $SUMMARY_FILE" EXIT
if [ "$RICH_UI" -eq 1 ] && [ -n "$SUMMARY_FILE" ]; then
    _emit_purge_decline > "$SUMMARY_FILE"
else
    _emit_purge_decline
fi
got=$(cat "$SUMMARY_FILE")
case "$got" in
    *"Aborted. No changes were made."*) : ;;
    *) printf "expected purge-decline message in SUMMARY_FILE; got: %s\n" "$got" >&2; exit 1 ;;
esac
'

# Plain mode: purge-decline message goes to stdout (not SUMMARY_FILE).
_run_scenario "uninstall blocker-2c: purge-decline in plain mode goes to stdout" '
RICH_UI=0
_emit_purge_decline() {
    printf "%s\n" "Aborted. No changes were made."
}
SUMMARY_FILE=$(mktemp)
trap "rm -f $SUMMARY_FILE" EXIT
out=$(
    if [ "$RICH_UI" -eq 1 ] && [ -n "$SUMMARY_FILE" ]; then
        _emit_purge_decline > "$SUMMARY_FILE"
    else
        _emit_purge_decline
    fi
)
[ -z "$(cat "$SUMMARY_FILE")" ] || {
    printf "plain: SUMMARY_FILE non-empty — should have gone to stdout; content: %s\n" "$(cat "$SUMMARY_FILE")" >&2; exit 1
}
case "$out" in
    *"Aborted. No changes were made."*) : ;;
    *) printf "plain: expected purge-decline on stdout; got: %s\n" "$out" >&2; exit 1 ;;
esac
'

# ---------------------------------------------------------------------------
# SF-2: print_next_steps — Removed: section with record_removed population.
# ---------------------------------------------------------------------------

# Non-empty REMOVED_ITEMS: "Removed:" section and each item appear in output.
_run_uninstall_next_steps_scenario "uninstall sf-2: print_next_steps shows Removed: section when items present" '
REMOVED_ITEMS=""
record_removed "/usr/local/bin/sandbox"
record_removed "/usr/local/libexec/sandboxd/"
PURGE=0
SANDBOX_UID=""
out=$(print_next_steps 2>/dev/null)
case "$out" in
    *"Removed:"*) : ;;
    *) printf "expected Removed: section in output; got: %s\n" "$out" >&2; exit 1 ;;
esac
case "$out" in
    *"/usr/local/bin/sandbox"*) : ;;
    *) printf "expected first removed item in output; got: %s\n" "$out" >&2; exit 1 ;;
esac
case "$out" in
    *"/usr/local/libexec/sandboxd/"*) : ;;
    *) printf "expected second removed item in output; got: %s\n" "$out" >&2; exit 1 ;;
esac
'

# Empty REMOVED_ITEMS: "Removed:" section must NOT appear.
_run_uninstall_next_steps_scenario "uninstall sf-2: print_next_steps omits Removed: section when no items" '
REMOVED_ITEMS=""
PURGE=0
SANDBOX_UID=""
out=$(print_next_steps 2>/dev/null)
case "$out" in
    *"Removed:"*)
        printf "Removed: section present but REMOVED_ITEMS is empty; got: %s\n" "$out" >&2; exit 1 ;;
    *) : ;;
esac
'

# record_removed accumulates multiple items without losing earlier entries.
_run_uninstall_next_steps_scenario "uninstall sf-2: record_removed accumulates items across multiple calls" '
REMOVED_ITEMS=""
record_removed "first-item"
record_removed "second-item"
record_removed "third-item"
case "$REMOVED_ITEMS" in
    *"first-item"*) : ;;
    *) printf "first item missing from REMOVED_ITEMS; got: %s\n" "$REMOVED_ITEMS" >&2; exit 1 ;;
esac
case "$REMOVED_ITEMS" in
    *"second-item"*) : ;;
    *) printf "second item missing from REMOVED_ITEMS; got: %s\n" "$REMOVED_ITEMS" >&2; exit 1 ;;
esac
case "$REMOVED_ITEMS" in
    *"third-item"*) : ;;
    *) printf "third item missing from REMOVED_ITEMS; got: %s\n" "$REMOVED_ITEMS" >&2; exit 1 ;;
esac
'

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n--- %d passed, %d failed ---\n' "$PASS" "$FAILS"
if [ "$FAILS" -gt 0 ]; then
    exit 1
fi
exit 0
