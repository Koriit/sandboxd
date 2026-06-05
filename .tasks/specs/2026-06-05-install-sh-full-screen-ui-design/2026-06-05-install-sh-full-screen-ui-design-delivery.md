# Delivery Verification Map — install.sh full-screen install UI

Spec: `.tasks/specs/2026-06-05-install-sh-full-screen-ui-design/2026-06-05-install-sh-full-screen-ui-design-spec.md`
Verified against: `scripts/install.sh` (working-tree state, 3438 lines; the
rich-UI changes are unstaged on top of commit `fa98ef5`)
Review context: `.tasks/handoffs/20260605-kio-reviewer-install-rich-ui-fixes.md`
(3 blockers + 5 important issues, all fixed and re-verified; line numbers in
that handoff reference the pre-fix 3376-line state and have shifted)

---

## Summary

**What was delivered.** The rich (TTY) install experience is now a single
managed full-screen session covering the entire install — version resolution
through the privileged step batch. The implementation lands all twelve
requirement groups: a once-only mode decision in `detect_tty` (R1), a frozen
plain path gated everywhere on `RICH_UI` (R2), a row-count threshold (R3), the
three-screen Acquire / Plan / Install layout (R4), the two-writer
header+checklist / detail-line partition (R5), a fixed-shell-var phase model
with a single `set_phase` entry point (R6), a model-free background animator
(R7), a `WINCH` trap serviced at free moments (R8), an auto-follow viewport
with a `⋮ N done above` indicator (R9), an interactive plan pager with raw-mode
scroll keys (R10), a single durable-flush-on-exit mechanism (R11), and
checklist-shaped failure/abort reporting with the specified exit codes (R12).

**Overall verification posture.** Honest split between what is machine-checked
and what is reviewed:

- **Verified by automated test (plain path):** R1.3, R2 (all), R10.4, R11.2
  (plain-mode exits), R12.2/R12.3 (plain-mode abort/exit codes), AC-1, AC-8.
  The install-e2e harness invokes the installer with `--no-color --yes`
  (`tests/install-e2e/conftest.py:1024,1060`), which forces **plain mode** and
  bypasses the pager. **Freshly executed this session (ubuntu-22.04,
  `--no-color`): 13/13 plain-path tests passed with no output diffs** — the
  happy-path smoke (`test_install_happy_path.py`, log
  `.tasks/test-runs/20260605-115952-install-e2e-quick-6a5404.log`) plus a
  12-test exit-path subset across `test_install_sigstore_refusals.py`,
  `test_install_idempotency.py`, `test_install_plan_and_gate.py`, and
  `test_install_air_gapped.py` (log
  `.tasks/test-runs/20260605-124500-install-e2e-exit-paths-5fba71.log`). The
  drift test (`test_lib_sh_drift.py`) passes; `bash -n` passes. The
  FIFO-anti-hang and checkpoint-semantics fixes have dedicated e2e tests
  (`test_install_review_fixes.py`). **Breadth still pending:** the full matrix
  (all distros, and the `update` / `uninstall` / `rollback` suites) was *not*
  run this session.
- **Verified by code review (not executed):** R4–R9, R10.1–R10.3, R11.1/R11.3,
  R12.1, AC-2, AC-3, AC-5, AC-6, AC-7, AC-9. The e2e suite never opens a PTY, so
  the rich path — alt-screen render, animator, resize/WINCH, the pager scroll
  loop, and the durable-flush-after-rmcup mechanism — is **structurally
  reviewed but not exercised end-to-end**. The independent review confirmed the
  gating and control flow; nobody ran the installer on a real TTY under test.

> **The e2e suite does not prove the rich UI works.** It proves plain-mode
> invariance (AC-1) and that the non-TTY path still installs. Every rich-mode
> acceptance criterion below is marked *reviewed, not executed*.

**Known limitation — install-screen phase-reader subshell.** During
`run_priv_child`, the rich install screen is driven by a phase-command reader
launched as a **backgrounded subshell** (`scripts/install.sh:3041-3058`). That
subshell calls `set_phase` and `ui_service_winch`, but because it is a subshell
its mutations to the phase model (`UI_PHASE_STATUSES`) and to `WINCH_PENDING`
stay **subshell-local** — they do not propagate to the main process. The
install-screen checklist therefore renders from the subshell's own copy of the
model, and a resize serviced inside that subshell repaints from the subshell's
state. This is out of scope for the current spec (the spec's § Non-goals
explicitly defers the single-UI-process refactor that would remove the second
FIFO and the subshell-mutation problem; the review's IMPORTANT 3 note flags the
more ambitious refactor as future work). It is recorded here honestly rather
than claimed as full R6/R8 coverage on the install screen.

---

## R1 — Mode selection

| # | Requirement | Status | Code / Test |
|---|---|---|---|
| R1.1 | Exactly one of rich/plain per invocation; decided once in `detect_tty`; never changes | Reviewed | `detect_tty` sets `RICH_UI` once (`install.sh:982-1017`); `RICH_UI=0` default (`:132`); no other write to `RICH_UI` exists (grep: only the `:1005` assignment) |
| R1.2 | Rich only when ALL hold: stdout TTY, `--no-color` unset, `--quiet` unset, `/dev/tty` usable, `tput` present + `smcup`/`rmcup` succeed, `--verbose` unset, `tput lines` ≥ minimum | Reviewed | Single compound conditional at `install.sh:996-1004` (`[ -t 1 ]`, `NO_COLOR -eq 0`, `QUIET -eq 0`, `VERBOSE -eq 0`, `[ -e /dev/tty ]`, `command -v tput`, `tput smcup`/`rmcup`, `tput lines >= RICH_UI_MIN_ROWS`). Plain otherwise (no else branch needed; `RICH_UI` stays 0) |
| R1.3 | `--verbose` (`set -x`) forces plain | **Verified (test)** + reviewed | Disqualifier at `install.sh:999` (`VERBOSE -eq 0`); `set -x` enabled in `parse_args` at `:946-948`. AC-8 asserts `--verbose` selects plain |
| R1.4 | Decision logged as `step=tty_detect … rich=…` | Reviewed | `log_ok "step=tty_detect tty=$tty_state color=$color_state rich=$rich_state"` (`install.sh:1016`) |

---

## R2 — Plain-mode invariance (hard constraint)

| # | Requirement | Status | Code / Test |
|---|---|---|---|
| R2.1 | Plain output byte-for-byte identical to current; install-e2e + drift authoritative | **Verified (test)** | install-e2e runs the installer `--no-color` (`conftest.py:1060`) → plain path; suite asserts unchanged output. Drift test `test_lib_sh_drift.py:42` passes. The review's BLOCKER 1 (inverted `spinner_start` that leaked a stderr spinner into plain mode) is fixed: `spinner_start` now sets `SPINNER_PID=0` in **all** modes (`install.sh:1390-1400`) |
| R2.2 | `/dev/tty` render descriptor MUST NOT be opened in plain mode; no rich-only render fn runs when `RICH_UI=0` | Reviewed | `UI_TTY=""` unless `RICH_UI=1` (`:204`, set only at `:1007`); `tty_print` no-ops on empty `UI_TTY` (`:523-526`); every render helper guards on `RICH_UI -eq 1` or `[ -n "$UI_TTY" ]` (`ui_render_header:544`, `_ui_render_checklist_body:619`, `ui_render_checklist:706`, `set_phase:828`, `ui_animator_start:774-775`, `ui_animator_stop:789`, `ui_service_winch:818`). `[ -e /dev/tty ]` at `:1000` is a probe, not an open |
| R2.3 | `emit()` unchanged; only stdout writer for plain user-facing text | **Verified (test)** + reviewed | `emit()` at `install.sh:319-323` is the pre-change form (`printf '%b\n'` gated on `QUIET`). Rich-only writers target `$UI_TTY` / `$SUMMARY_FILE`, never plain stdout |
| R2.4 | Rich logic makes no decision the plain path does not also make | Reviewed | Phase outcomes, plan content, prereq/disk/version decisions all computed in shared code (`resolve_target_version`, `detect_preexisting`, `check_prereqs`, `check_disk`, `compute_plan`); rich branches only choose render target (`SUMMARY_FILE` vs `emit`). Review's IMPORTANT 2 (WINCH trap installed at file-load, leaking into plain) is fixed: the `trap '_ui_winch_trap' WINCH` is now installed inside `detect_tty` only after `RICH_UI=1` (`install.sh:1010-1013`), and `cleanup_tmpdir` does `trap - WINCH` (`:448`) |

---

## R3 — Terminal size

| # | Requirement | Status | Code / Test |
|---|---|---|---|
| R3.1 | Minimum rich row count is a single constant (~8–9: header+rule+≥3 content+rule+detail); below it → plain | **Verified (test)** + reviewed | `RICH_UI_MIN_ROWS=9` single constant (`install.sh:137`); enforced in the `detect_tty` conditional at `:1004`. AC-8 asserts a sub-threshold window selects plain |
| R3.2 | No dynamic rich↔plain switch on resize after startup | Reviewed | `RICH_UI` is written once (`:1005`); WINCH handler only sets `WINCH_PENDING=1` (`_ui_winch_trap:865-867`) and triggers a repaint, never re-evaluates the mode. Matches spec § Non-goals "Dynamic rich→plain downgrade" |

---

## R4 — Screen layout

| # | Requirement | Status | Code / Test |
|---|---|---|---|
| R4.1 | Three screens in order — Acquire, Plan+confirm, Install — one at a time; transition clears prior content | Reviewed, not executed | Acquire: `ui_init_phases "$UI_ACQUIRE_PHASES"` (`install.sh:3362`). Plan: `confirm_plan` rich pager clears with `\033[H\033[2J` (`:2253`). Install: `ui_init_phases "$UI_INSTALL_PHASES"` (`:3005`). `ui_render_checklist` does cursor-home + `tput ed` clear-to-end on each repaint (`:720-721`) |
| R4.2 | Every screen begins with one header + rule line reflecting current stage | Reviewed, not executed | `ui_render_header` emits header text + dash rule (`install.sh:543-552`); headers `"sandboxd · acquiring"` (`:3363`), `"sandboxd $VERSION · review plan"` (`:2256`), `"sandboxd · installing"` (`:3006`) |
| R4.3 | Phase row renders one of four states with stable glyph: `·` / `▸` / `✔` / `✗` | Reviewed, not executed | Glyph map in `_ui_render_checklist_body`: `active→▸`, `done→✔`, `failed→✗`, default `·` (`install.sh:688-693`) |
| R4.4 | At most one detail line below the checklist for active substep + spinner glyph | Reviewed, not executed | Layout reserves exactly one detail row (`_urc_available=$(( UI_ROWS - 2 - 1 - 1 ))`, `:729`); the animator owns it (`_ui_animator_body:752-769`); `UI_DETAIL_TEXT` is the single substep slot (`:223`) |

---

## R5 — Writer partition

| # | Requirement | Status | Code / Test |
|---|---|---|---|
| R5.1 | Header + checklist rows written only by the main process | Reviewed, not executed | `ui_render_header` / `_ui_render_checklist_body` / `ui_render_checklist` are called from main-process paths (`set_phase`, `main`); the animator body never calls them |
| R5.2 | Detail line written only by the background animator | Reviewed, not executed | `_ui_animator_body` writes `\r\033[K%s` to the detail line only (`install.sh:765`); no checklist writes inside it |
| R5.3 | No cell writable by both; animator never reads the phase model nor writes the checklist | Reviewed, not executed | `_ui_animator_body` takes only a `detail_text` arg (`:752-753`); it reads `tput cols` and its frame counter, never `UI_PHASE_*`. Model-free per Decision 1 |
| R5.4 | On every transition: stop animator → repaint checklist → restart after repaint completes | Reviewed, not executed | `set_phase` calls `ui_animator_stop` **before** mutating the model and `ui_render_checklist`, then `ui_animator_start` only if the new status is `active` (`install.sh:827-846`); `ui_render_checklist` independently stops/restarts the animator around the checklist write (`:710-717`, `:743-745`). The review confirmed this transition discipline and flagged it "do not change" |

---

## R6 — Phase model & repaint

| # | Requirement | Status | Code / Test |
|---|---|---|---|
| R6.1 | Phase state in fixed per-phase shell vars in the main process; no shared on-disk model file | Reviewed, not executed | `UI_PHASE_NAMES` / `UI_PHASE_STATUSES` / `UI_PHASE_COUNT` are shell vars (`install.sh:218-220`); no model file is written. (See Known Limitation — on the install screen these are mutated inside a subshell.) |
| R6.2 | Single entry point `set_phase <name> <status> [detail]` mutates model + triggers exactly one repaint | Reviewed, not executed | `set_phase` (`install.sh:827-846`): one `ui_set_phase_status` mutation + one `ui_render_checklist`. (Signature is index-based `set_phase <idx> <status> [detail]`, not name-based; functionally equivalent — phases are addressed by their 1-based index) |
| R6.3 | Checklist repaints only on transitions and on a WINCH at a free moment; never on a timer | Reviewed, not executed | Repaint call sites: `set_phase` (transition) and `ui_service_winch` (`:816-820`). No timer-driven repaint; the animator (the only timed loop) touches only the detail line |
| R6.4 | Repaints use cursor-home + clear-to-end (not full clear) | Reviewed, not executed | `ui_render_checklist` does `tput home` + `tput ed` (`install.sh:720-721`). (The pager `_cp_render` uses `\033[H\033[2J` full-clear at `:2253` — acceptable for the static pager screen, distinct from the live checklist) |
| R6.5 | Every rendered line clamped (truncated, never wrapped) to current width | Reviewed, not executed | `ui_clamp` cuts to width (`install.sh:531-538`); applied to header (`:548`), checklist rows (`:695`), indicator (`:677`); animator clamps via `cut -c1-"$_ab_cols"` each tick (`:763`) |

---

## R7 — Animator

| # | Requirement | Status | Code / Test |
|---|---|---|---|
| R7.1 | Runs as background process for the active phase; killed + reaped on transition and cleanup | Reviewed, not executed | `ui_animator_start` backgrounds `_ui_animator_body &` and records `UI_ANIM_PID` (`install.sh:783-784`); killed+`wait`ed in `ui_animator_stop` (`:790-794`), in `ui_render_checklist` (`:712-717`), and in `cleanup_tmpdir` (`:460-467`). Review's BLOCKER 1 fix ensures the animator (not the legacy stderr spinner) is the live element during the four blocking acquire phases — `main` sets a substep before each blocking call (`:3383-3399`) so the animator spins through `cosign_bootstrap` / `tarball_fetch` / `sigstore_verify` / `extract_tarball` |
| R7.2 | Animator owns only the detail line: advance glyph + re-clamp detail to width each tick | Reviewed, not executed | `_ui_animator_body` loop: 4-frame glyph `▌▀▐▄`, `tput cols` re-query + `cut` clamp each tick, write to detail line only (`install.sh:752-769`) |
| R7.3 | No leftover animator survives exit; EXIT/INT/TERM/HUP trap kills+reaps it and clears its line | Reviewed, not executed | `trap cleanup_tmpdir EXIT INT TERM HUP` (`install.sh:3352`); `cleanup_tmpdir` kills+`wait`s `UI_ANIM_PID` and clears the line with `\r\033[K` (`:460-467`). Review confirmed the animator-cleanup half of R7.3 holds. Pairs with AC-9 |

---

## R8 — Resize

| # | Requirement | Status | Code / Test |
|---|---|---|---|
| R8.1 | WINCH trap triggers full repaint (header+checklist) whenever main is free (between phases, plan screen, confirm prompt) | Reviewed, not executed | `_ui_winch_trap` sets `WINCH_PENDING=1` (`install.sh:865-867`); `ui_service_winch` drains it via `ui_render_checklist` (`:816-820`). Review's IMPORTANT 1 (handler defined but never drained) is fixed — call sites now exist: after each acquire phase in `main` (`:3371,3376,3381,3386,3391,3396,3401`), inside the pager loop (`:2284-2286`) and `_cp_render` (`:2243`), and in the install-screen reader (`:3050`). **Caveat:** the install-screen `ui_service_winch` call runs in the phase-reader subshell — see Known Limitation |
| R8.2 | Animator re-clamps detail to new width within one tick | Reviewed, not executed | `_ui_animator_body` re-queries `tput cols` and re-clamps every tick (~0.25 s) (`install.sh:759,763`); independent of WINCH delivery |
| R8.3 | Resize during a blocking phase MAY leave checklist at prior width until next transition; clamp-to-width ensures never garbled | Reviewed, not executed | Checklist repaint is transition-gated (R6.3); mid-blocking-op the checklist is not repainted, but every line was clamped when last drawn (R6.5), so it cannot exceed width. Matches Decision 8 |

---

## R9 — Auto-follow viewport

| # | Requirement | Status | Code / Test |
|---|---|---|---|
| R9.1 | When content exceeds rows, viewport auto-follows the active phase (active row always visible) | Reviewed, not executed | `_ui_render_checklist_body` finds the active index and computes a scroll window keeping it visible (`install.sh:630-673`) |
| R9.2 | Completed rows scrolled off top represented by `⋮ N done above`; never silently disappear | Reviewed, not executed | Indicator computed (`_rcb_above`) and emitted as `  ⋮ $_rcb_above done above` when `_rcb_start > 1` (`install.sh:660-679`) |
| R9.3 | Full final set of phases + outcomes printed to primary screen on exit (R11), regardless of viewport | Reviewed, not executed | Failure path reproduces the full checklist from the live model into `SUMMARY_FILE` (`_print_failure_report:3251-3311`, `die:378-396`); success summary via `print_next_steps` (`:3317-3338`). Flushed after `rmcup` by `cleanup_tmpdir` (`:482-484`) |
| R9.4 | Live dashboards do not accept manual scroll input | Reviewed, not executed | No input read in the Acquire or Install loops; scroll input exists only in `confirm_plan`'s pager (the plan screen, R10). Matches Decision 9 |

---

## R10 — Plan pager

| # | Requirement | Status | Code / Test |
|---|---|---|---|
| R10.1 | Page static plan text through a viewport when it exceeds rows; render statically with no scroll affordance when it fits | Reviewed, not executed | Plan captured via `render_plan` command-substitution (`install.sh:2203`); line count via `awk 'END{print NR}'` (`:2204`, review's IMPORTANT 5 fix — was `printf '%s\n' | wc -l`, which over/under-counted on stripped trailing newlines); viewport `_cp_viewport=$(( UI_ROWS - 4 ))` (`:2207`, review's IMPORTANT 4 off-by-one fix — was `- 3`). Footer shows position only when scrollable (always rendered; `lines a–b of N`) |
| R10.2 | Scroll keys (≥ ↑/↓ and PgUp/PgDn) move viewport via single-char reads from `/dev/tty` | Reviewed, not executed | `dd bs=1 count=1 </dev/tty` reads (`install.sh:2288,2301,2302`); ESC handled via a `printf '\033'`-built byte `_cp_esc` (`:2216`, review's BLOCKER 2 fix — was `$'\x1b'`, dead under dash/`#!/bin/sh`); arms `[A`/`[B`/`[5~`/`[6~` (`:2304-2329`) |
| R10.3 | Confirm folds into pager: `y`/`yes` proceeds, anything else aborts; footer shows scroll position when scrolling possible | Reviewed, not executed | `y|Y`→proceed, `n|N|q|Q`→abort (`install.sh:2290-2298`); footer `[y] proceed  [n] abort  ↑/↓ PgUp/PgDn scroll  lines a–b of N` (`:2276-2277`) |
| R10.4 | `--yes` bypasses the pager and proceeds without rendering it | **Verified (test, executed this session)** + reviewed | `confirm_plan` short-circuits on `YES -eq 1` before any pager code (`install.sh:2183-2187`). Exercised by every install-e2e test (all pass `--yes`, `conftest.py:1024`). Freshly executed: the 7 `test_install_plan_and_gate.py` cases (confirm gate yes/no/no-tty/interactive + plan listing + operator detection) all PASSED, log `.tasks/test-runs/20260605-124500-install-e2e-exit-paths-5fba71.log`. The non-TTY confirm-abort path (no `--yes`, no terminal → `exit 1`, `install.sh:2191-2196`) is covered by the same file's no-tty case |

> **R10 raw-mode safety (review BLOCKER 3, fixed).** `stty raw -echo` is now
> guarded by `STTY_RAW_ACTIVE` / `STTY_SAVED` module vars (`install.sh:146-148`),
> set when raw mode is entered (`:2220-2223`), and restored by the idempotent
> `ui_restore_stty` (`:805-812`) which `cleanup_tmpdir` calls unconditionally
> before `rmcup` (`:471`). A Ctrl-C / die() / `set -eu` failure mid-pager now
> restores the line discipline on every exit path. Reviewed, not executed.

---

## R11 — Exit & durable output

| # | Requirement | Status | Code / Test |
|---|---|---|---|
| R11.1 | All durable text on exit prints to primary screen after `rmcup` via a single flush mechanism: write to flush file; EXIT trap does `rmcup` (no-op if not in alt-screen) then cats it | Reviewed, not executed | Single flush point in `cleanup_tmpdir`: `rmcup` if `ALT_SCREEN_ACTIVE` (`install.sh:474-477`) then `cat "$SUMMARY_FILE"` gated on `RICH_UI` + `[ -s "$SUMMARY_FILE" ]` (`:482-484`). All rich exits write to `SUMMARY_FILE`, never to live stdout |
| R11.2 | These exits route through the flush mechanism in rich mode: `die()`; already-installed skip (0); version-mismatch refuse (1); missing-prereq (1); disk (1); user abort (1); success summary; privileged-child failure (existing) | Mixed: **plain paths Verified (test, executed this session)**; rich paths Reviewed | `die()` `:368-396`; already-installed skip `:1115-1116`; version-mismatch `:1131-1132`; prereq fail `:1219-1220`; disk fail `:1348-1349`; abort `:2344-2345`; success `:3431-3432`; priv-child failure `:3225-3227`. Each is gated `[ "$RICH_UI" -eq 1 ] && [ -n "$SUMMARY_FILE" ]` with a plain `else`. The **plain** branch of these was executed this session (log `.tasks/test-runs/20260605-124500-install-e2e-exit-paths-5fba71.log`): `die()`/refuse via `test_install_sigstore_refusals.py` (sigstore die + tampered-tarball abort) and `test_install_air_gapped.py` (air-gapped prereq failure); already-installed skip + partial-failure recovery via `test_install_idempotency.py`; user abort via `test_install_plan_and_gate.py`; success summary via `test_install_happy_path.py` (log `…-quick-6a5404.log`). The rich (SUMMARY_FILE + rmcup) branch remains reviewed only |
| R11.3 | EXIT/INT/TERM/HUP trap restores primary screen (`rmcup` when active) and removes all temp files; no dangling cursor/animator on any path | Reviewed, not executed | `trap cleanup_tmpdir EXIT INT TERM HUP` (`install.sh:3352`); `cleanup_tmpdir` disables WINCH, reaps spinner+animator, restores stty, `rmcup`, flushes summary, then `rm -rf "$TMPDIR_INSTALL"` + `rm -f "$SUMMARY_FILE"` (`:445-490`). Pairs with AC-9 |

---

## R12 — Failure & abort

| # | Requirement | Status | Code / Test |
|---|---|---|---|
| R12.1 | On `die()` inside the UI: failed phase marked `✗`; durable report reproduces checklist shape (✔ completed, ✗ failed, failed step name) + error detail + recovery guidance | Reviewed, not executed | `die()` marks the active phase failed via `set_phase … failed` then writes a checklist-shaped report (✔/✗ rows, `Error:`, `Recovery:`, log path) to `SUMMARY_FILE` (`install.sh:368-396`). `_print_failure_report` does the same for privileged-child failure from the live model (`:3251-3282`). AC-3 covers verify-step failure (reviewed) |
| R12.2 | Declining confirm exits non-zero (1) with `Aborted. No changes were made.` and no privileged change applied | **Verified (test, plain — executed this session)** + reviewed | Rich abort: `SUMMARY_FILE` gets `Aborted. No changes were made.`, `exit 1` (`install.sh:2343-2348`). Plain abort: `emit "… Aborted. No changes were made."`, `exit 1` (`:2362-2365`). Abort occurs before `write_priv_script`/`run_priv_child` (`main:2183/3420 vs 3423-3426`), so no privileged step runs. The plain decline was executed this session via `test_install_plan_and_gate.py` (confirm gate no/no-tty cases), log `.tasks/test-runs/20260605-124500-install-e2e-exit-paths-5fba71.log`. AC-4 (rich) reviewed |
| R12.3 | Exit codes: success 0; user/no-tty abort 1; pre-flight refuse/prereq/disk 1; install failure 1; already-installed skip 0 | **Verified (test, plain — executed this session)** + reviewed | success: implicit 0; no-tty abort `exit 1` (`:2196`); interactive abort `exit 1` (`:2348,2365`); version-mismatch `exit 1` (`:1137`); prereq `exit 1` (`:1225`); disk `exit 1` (`:1354`); priv-child fail `exit 1` (`:3233`); already-installed skip `exit 0` (`:1120`); arg-parse error `exit 2` (`:937`). Plain-path exit codes executed this session (log `.tasks/test-runs/20260605-124500-install-e2e-exit-paths-5fba71.log`): success 0 via `test_install_happy_path.py`; abort 1 via `test_install_plan_and_gate.py`; refuse/prereq 1 via `test_install_sigstore_refusals.py` + `test_install_air_gapped.py`; already-installed skip 0 + partial-failure recovery via `test_install_idempotency.py`. (Disk-fail exit 1 is reviewed against `:1354` — not isolated in this subset) |

---

## Acceptance criteria

| # | Criterion | Status | Evidence |
|---|---|---|---|
| AC-1 | Plain-mode install-e2e + drift suites pass with no output diff (R2.1) | **Verified (test, executed this session)** | **Freshly executed this session (ubuntu-22.04, `--no-color` plain path): 13/13 plain-path tests passed, no plain-mode output diffs, no assertion errors.** Happy-path smoke (`test_install_happy_path.py::test_install_fresh_then_doctor_passes[ubuntu-22.04]`), log `.tasks/test-runs/20260605-115952-install-e2e-quick-6a5404.log`; plus a 12-test exit-path subset (`test_install_sigstore_refusals.py` ×2, `test_install_idempotency.py` ×2, `test_install_plan_and_gate.py` ×7, `test_install_air_gapped.py` ×1), log `.tasks/test-runs/20260605-124500-install-e2e-exit-paths-5fba71.log`. `test_lib_sh_drift.py` passes (`1 passed`); `bash -n` clean. The BLOCKER 1 stderr-spinner regression that would have produced a plain-mode diff is fixed (`install.sh:1390-1400`) and is now demonstrated absent by these runs. **Breadth caveat:** this is one distro (ubuntu-22.04) and the install subset — the full matrix (all distros) and the `update` / `uninstall` / `rollback` suites were not run |
| AC-2 | Rich mode entered at first step; resolve/prereqs/download render inside the managed screen; durable summary appears in primary-screen scrollback after UI closes (R...) | Reviewed, not executed | Alt-screen entered right after `detect_tty` (`main:3357`); phases 1–7 wired through `set_phase` (`:3367-3401`); success summary flushed post-`rmcup` (`cleanup_tmpdir:482-484`). The e2e harness never opens a PTY, so this is reviewed only |
| AC-3 | Forced `die()` at verify renders a failure report on the primary screen reproducing the checklist with `✗ Verify signature` (R12.1) | Reviewed, not executed | `die()` marks the active phase (here phase 6 "Verify signature", `UI_ACQUIRE_PHASES:233-239`) `failed` and writes the ✔/✗ checklist to `SUMMARY_FILE` (`:371-396`). No test forces a verify-time `die()` on a TTY |
| AC-4 | Declining confirm exits 1 with abort message on primary screen and no host changes (R12.2) | Reviewed (rich) / **Verified (test, plain — executed this session)** | Rich abort writes to `SUMMARY_FILE`+`exit 1` (`:2343-2348`); the plain decline was executed this session via `test_install_plan_and_gate.py` (PASSED, log `.tasks/test-runs/20260605-124500-install-e2e-exit-paths-5fba71.log`). The rich pager-decline path is reviewed only (non-TTY harness) |
| AC-5 | Window ≥ threshold but < total content: active phase stays visible, `⋮ N done above` appears, full list prints on exit (R9) | Reviewed, not executed | Auto-follow + indicator logic in `_ui_render_checklist_body` (`:630-679`); full list on exit via summary/report. No PTY-resized test run |
| AC-6 | Maximizing between phases / at the plan repaints to full size promptly; mid-download never garbled, reflows by next transition (R8) | Reviewed, not executed | WINCH serviced at free moments (`:3371-3401`, pager `:2284`); mid-download protected by clamp-to-width (R6.5/R8.3). No interactive resize test |
| AC-7 | Plan longer than window fully reviewable via scroll keys; `y` proceeds, `n` aborts (R10) | Reviewed, not executed | Pager scroll arms + decision (`:2288-2349`). The BLOCKER 2 (dash ESC) and IMPORTANT 4/5 (viewport/line-count math) fixes are in; verifying the keys actually move the viewport requires a real TTY under dash, which was not run |
| AC-8 | `--verbose`, `--no-color`, `--quiet`, piped/non-TTY stdout, and a sub-threshold window each select plain mode (R1, R3) | **Verified (test, executed this session)** + reviewed | Disqualifiers at `detect_tty:996-1004`. This session's 13 runs all used non-TTY + `--no-color` and installed via the plain path with no output diff (logs `…-quick-6a5404.log`, `…-exit-paths-5fba71.log`), demonstrating the **piped/non-TTY** and **`--no-color`** selectors end-to-end. The `--verbose` / `--quiet` / sub-threshold selectors remain reviewed against the same conditional (not isolated as tests) |
| AC-9 | No orphaned animator or raw terminal state after Ctrl-C at any point (R7.3, R11.3) | Reviewed, not executed | `cleanup_tmpdir` reaps the animator (`:460-467`) and restores stty (`:471`, BLOCKER 3 fix) on EXIT/INT/TERM/HUP. The review's stated check (`pgrep -f _ui_animator_body` empty after exit; echo restored after mid-pager Ctrl-C) was not executed on a TTY |

---

## Gaps and caveats

- **No gap where a requirement is unimplemented.** Every R* and AC-* maps to
  concrete code. No fabricated citations; line numbers verified against the
  current 3438-line working tree.
- **The single honest limitation** is the install-screen phase-reader subshell
  (Known Limitation above): R6 model mutations and the R8.1 WINCH service on the
  *Install* screen happen in a backgrounded subshell, so those mutations are
  subshell-local. The Acquire and Plan screens drive the model from the main
  process and are unaffected. This is consistent with the spec's § Non-goals
  (the single-UI-process refactor is deferred) and the review's IMPORTANT 3
  note; it is recorded rather than claimed as full coverage.
- **Plain path: executed this session.** 13/13 plain-path tests passed on
  ubuntu-22.04 (`--no-color`), no output diffs — happy-path smoke + a 12-test
  exit-path subset (logs
  `.tasks/test-runs/20260605-115952-install-e2e-quick-6a5404.log` and
  `.tasks/test-runs/20260605-124500-install-e2e-exit-paths-5fba71.log`). This
  discharges AC-1, AC-8 (plain selectors), R10.4, and the plain-mode branches of
  R11.2 / R12.2 / R12.3 by execution rather than review.
- **Breadth still pending.** The runs covered **one distro** (ubuntu-22.04) and
  the **install** subset only. The full distro matrix and the `update` /
  `uninstall` / `rollback` suites were **not** run this session.
- **Verification ceiling — the rich (TTY) path remains reviewed, not
  executed.** The install-e2e harness is non-TTY, so the entire rich rendering
  surface (AC-2, AC-3, AC-5, AC-6, AC-7, AC-9 and R4–R9, R10.1–R10.3,
  R11.1/R11.3, R12.1) is reviewed but **not executed end-to-end** — the fresh
  plain-path runs do not touch it. The three review blockers and five important
  issues are fixed and present in the working tree; the drift test and `bash -n`
  pass. A real-TTY pass (ideally under dash, ≥9 rows) remains the way to
  discharge the reviewed-not-executed criteria.
