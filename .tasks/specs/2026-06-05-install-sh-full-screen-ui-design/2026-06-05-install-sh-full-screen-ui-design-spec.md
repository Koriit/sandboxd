# install.sh full-screen install UI

Status: design agreed, not yet implemented.

## Summary

Make the rich (TTY) install experience a single managed full-screen session
that covers the **entire** install — from version resolution through the
privileged step batch — rather than today's narrow alt-screen that wraps only
plan-review + the privileged batch. The session cleans up after itself, leaves
a durable summary in the terminal's real scrollback, and degrades to the
existing plain path with **byte-identical** output whenever the rich UI is not
available.

The load-bearing decisions are: (1) the screen is partitioned **by region**
between two writers (main process owns header + checklist; a model-free
background animator owns one detail line) so there is never a cursor race;
(2) every exit that must show durable text routes through a single
flush-then-`rmcup`-then-cat mechanism (generalizing the one such path that
already exists for privileged-step failure); (3) live dashboards **auto-follow**
the active phase rather than implementing manual scrollback, which keeps small
default windows in the full experience without an input loop; and (4) the rich
path is purely additive — plain mode is frozen byte-for-byte because the
install-e2e and lib.sh-drift harnesses assert it.

## Context

### Current behaviour (baseline)

`main()` enters the alt-screen late (`ui_enter_alt_screen`, just before
`render_plan`). Everything before it — resolve / prereqs / disk / cosign /
tarball / verify / extract — runs on the primary screen via plain `emit` and
`\r` spinners/bars. The alt-screen wraps only plan-review → confirm →
privileged batch, and `ui_leave_alt_screen` restores the primary screen and
re-prints the durable summary.

One in-alt failure path already exists — a privileged-step failure in
`run_priv_child` (`scripts/install.sh`) — and it demonstrates the
durable-flush pattern this design generalizes: capture the report to
`$SUMMARY_FILE`, then `ui_leave_alt_screen` (rmcup, then cat the file to the
primary screen).

### Driving constraints

- Done/ticked steps must never *silently* vanish.
- Must serve small/default windows (e.g. an 80×24 terminal opened before the
  user maximizes) with the full experience, not a plain-mode fallback.
- The plan can be longer than any window.
- The existing plain (non-TTY) path is exercised byte-for-byte by the
  install-e2e and lib.sh-drift harnesses and must not change.

## Architecture

### Two-writer partition (the load-bearing invariant)

During a blocking op (`curl`, `cosign`) the main process is stuck and cannot
animate; that is why animation must run in a background process. To avoid two
processes writing the same screen region, ownership is partitioned **by
region**:

- **Main process** owns the header + the fixed checklist rows. It repaints them
  only on phase transitions and on a `WINCH` at a free moment.
- **Background animator** owns exactly **one** line — the detail line below the
  checklist — and nothing else. It spins the glyph and re-clamps that line to
  the current width each tick. It is **model-free**: it never reads phase state
  and never touches the checklist.

Transition discipline keeps the two from ever overlapping: stop the animator →
main repaints the checklist (row → `✔`) → start the animator for the next
phase.

### Three-tier render model

- **Phase** — a durable checklist row (`· pending`, `▸ active`, `✔ done`,
  `✗ failed`). Repainted from the model on transitions.
- **Substep** — ephemeral text on the detail line (`checking certificate
  identity`, `unpacking`, `12.4/18.0 MB`). Transient; cleared on transition.
- **Glyph** — the spinner animation on the detail line, driven by the animator.

Phase state lives in fixed per-phase shell variables in the main process; there
is no shared on-disk model file (which would reintroduce two-writer races).

### Screens (one-line header carried across all)

Every screen shows a single evolving header + rule for continuity, e.g.
`sandboxd 0.1.2 · acquiring` → `· fetched & verified` → `· installing`.

1. **Acquire** — live dashboard: resolve / prereqs / disk / cosign / tarball /
   verify / extract (~7 rows).
2. **Plan + confirm** — interactive **pager** over static plan text (the plan
   can exceed any window). Scroll keys move a viewport; `y`/`n` decide. Footer:
   `↑/↓ PgUp/PgDn scroll · lines a–b of N · [y] proceed · [n] abort`. Input
   handling is free here because we are already blocked on `read`.
3. **Install** — live dashboard fed by the existing `PRIV_PROGRESS_FIFO`
   line-progress protocol from the privileged child (~12 rows).

On exit, `rmcup` restores the primary screen and the durable summary / failure
report / abort message is printed there — so the full history gets the
terminal's **native** scrollback for free.

### Auto-follow viewport (serves small windows)

Live dashboards do not implement manual scrollback (that would require an input
loop during blocking ops — see Non-goals). Instead the viewport **auto-follows**
the active phase, like a build log. When content exceeds the window, completed
rows above collapse into a visible `⋮ N done above` indicator — nothing
silently disappears, and the full list lands on the primary screen at the end.
This lets the rich-mode row threshold drop to ~8–9 lines, so small/default
windows still get the full experience.

### Durable-flush mechanism (the core refactor)

Generalize the existing `run_priv_child` special case into one rule: **every**
exit that must show durable text writes it to a flush file and exits; the EXIT
trap does `rmcup` (no-op if not in alt-screen) then cats the file to the
primary screen. All of it is gated on `RICH_UI`; plain mode keeps emitting
inline exactly as today.

## Decisions

| #   | Decision           | Choice                                                                          | Rationale                                                                                                                               |
| --- | ------------------ | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Animation location | Static checklist rows + one animated detail line                                | Partitions writers by region; eliminates the cursor-race class                                                                          |
| 2   | Render target      | `/dev/tty` for UI, stdout for durable artifact; rich-only                       | Correct under any `1>`/`2>` redirection; plain path untouched                                                                           |
| 3a  | `--verbose`        | Forces plain                                                                    | `set -x` xtrace is incompatible with a fixed layout                                                                                     |
| 3b  | Short terminal     | Forces plain below ~8–9 lines                                                   | Below the auto-follow minimum; no dynamic mid-run downgrade                                                                             |
| 4   | Screen continuity  | One-line evolving header + rule on every screen                                 | Ties three screens into one install; costs one row                                                                                      |
| 5   | Failure            | Leave immediately; reproduce checklist in the durable report                    | Durable beats a fleeting on-screen ✗; reuses the existing report path                                                                   |
| 6   | Abort              | exit 1 (non-zero); message flushed durably                                      | exit 0 implies "installed"; unifies with the no-tty abort                                                                               |
| 7   | Repaint            | Transition-only for checklist; animator self-drives the detail                  | Static checklist needs no timer; minimal flicker                                                                                        |
| 8   | Resize             | `WINCH` at free moments + detail-line clamp each tick; no state file            | Instant at free moments; ≤few-sec checklist reflow lag only mid-download; clamp-to-width means never garbled; keeps animator model-free |
| 9   | Scroll             | Auto-follow dashboards (`⋮ N done above`) + interactive pager for the plan only | Manual scroll during live phases needs an input loop; auto-follow gets full small-window UX without it                                  |
| 10  | Model state        | Fixed per-phase shell vars in the main process                                  | No cross-process sharing needed; simplest, debuggable                                                                                   |

## Requirements

Keywords MUST / MUST NOT / SHOULD / MAY are used in the RFC 2119 sense.

### R1. Mode selection

- **R1.1** The installer MUST run in exactly one of two modes per invocation:
  **rich** or **plain**. The mode is decided once, in `detect_tty`, and MUST NOT
  change for the process lifetime.
- **R1.2** Rich mode MUST be selected only when ALL hold: stdout is a TTY;
  `--no-color` unset; `--quiet` unset; `/dev/tty` usable; `tput` present and
  `smcup`/`rmcup` succeed; `--verbose` unset; and `tput lines` ≥ the minimum
  (R3.1). Otherwise plain mode MUST be selected.
- **R1.3** `--verbose` (`set -x`) MUST force plain mode.
- **R1.4** The decision MUST be logged as today (`step=tty_detect … rich=…`).

### R2. Plain-mode invariance (hard constraint)

- **R2.1** Plain-mode output MUST be byte-for-byte identical to the current
  implementation. The install-e2e and lib.sh-drift harnesses are authoritative.
- **R2.2** The `/dev/tty` render descriptor MUST NOT be opened in plain mode; no
  rich-only render function may execute when `RICH_UI=0`.
- **R2.3** `emit()` MUST remain unchanged and remain the only stdout writer for
  plain-mode user-facing text.
- **R2.4** Rich-mode logic MUST NOT make any decision (phase outcome, plan
  content, prereq result, failure classification) the plain path does not also
  make. Rich changes presentation only.

### R3. Terminal size

- **R3.1** The minimum rich row count MUST be a single constant (target ~8–9:
  header + rule + ≥3 content rows + rule + detail). Below it, plain is selected.
- **R3.2** The installer MUST NOT dynamically switch rich↔plain on resize after
  startup.

### R4. Screen layout

- **R4.1** Rich mode MUST present three logical screens in order — Acquire,
  Plan + confirm, Install — one visible at a time; a transition clears the prior
  screen content.
- **R4.2** Every screen MUST begin with one header line + a rule line; the
  header text MUST reflect the current stage.
- **R4.3** A phase row MUST render one of four states with a stable glyph:
  pending `·`, active `▸`, done `✔`, failed `✗`.
- **R4.4** At most one detail line MUST exist, below the checklist, for the
  active phase's substep text and spinner glyph.

### R5. Writer partition

- **R5.1** Header and checklist rows MUST be written only by the main process.
- **R5.2** The detail line MUST be written only by the background animator.
- **R5.3** No cell may be writable by both. The animator MUST NOT read the phase
  model and MUST NOT write the checklist region.
- **R5.4** On every transition the main process MUST stop the animator before
  repainting the checklist and (re)start it only after the repaint completes.

### R6. Phase model & repaint

- **R6.1** Phase state MUST be held in fixed per-phase shell variables in the
  main process; there MUST be no shared on-disk model file.
- **R6.2** A single entry point (`set_phase <name> <status> [detail]`) MUST
  mutate the model and trigger exactly one checklist repaint.
- **R6.3** The checklist MUST repaint only on transitions and on a `WINCH`
  handled at a free moment (R8); never on a timer.
- **R6.4** Repaints MUST use cursor-home + clear-to-end (not full clear).
- **R6.5** Every rendered line MUST be clamped (truncated, never wrapped) to the
  current terminal width.

### R7. Animator

- **R7.1** The animator MUST run as a background process for the duration of an
  active phase and MUST be killed and reaped on transition and on cleanup.
- **R7.2** The animator MUST own only the detail line: advance the spinner glyph
  and re-clamp the detail text to width each tick.
- **R7.3** No leftover animator may survive process exit; the EXIT/INT/TERM/HUP
  trap MUST kill and reap it and clear its line.

### R8. Resize

- **R8.1** A `WINCH` trap in the main process MUST trigger a full repaint
  (header + checklist) whenever the main process is free to service it (between
  phases, on the plan screen, at the confirm prompt).
- **R8.2** The animator MUST re-clamp the detail line to the new width within one
  tick of a resize.
- **R8.3** A resize during a blocking phase MAY leave the checklist at the prior
  width until the next transition; clamp-to-width (R6.5) MUST ensure it is never
  garbled meanwhile.

### R9. Auto-follow viewport

- **R9.1** When checklist content exceeds available rows, the viewport MUST
  auto-follow the active phase so the active row is always visible.
- **R9.2** Completed rows scrolled out of view MUST be represented by a visible
  indicator (`⋮ N done above`); they MUST NOT silently disappear.
- **R9.3** The full final set of phases and outcomes MUST be printed to the
  primary screen on exit (R11), regardless of what fit in the viewport.
- **R9.4** Live dashboards MUST NOT accept manual scroll input.

### R10. Plan pager

- **R10.1** The plan screen MUST page static plan text through a viewport when
  the plan exceeds available rows; when it fits, it MUST render statically with
  no scroll affordance.
- **R10.2** Scroll keys (at minimum ↑/↓ and PgUp/PgDn) MUST move the viewport via
  single-character reads from `/dev/tty`.
- **R10.3** The confirm decision MUST fold into the pager: `y`/`yes` proceeds,
  anything else aborts. The footer MUST show scroll position when scrolling is
  possible.
- **R10.4** `--yes` MUST bypass the pager and proceed without rendering it,
  preserving current non-interactive behaviour.

### R11. Exit & durable output

- **R11.1** All durable user-facing text on exit MUST print to the primary
  screen *after* `rmcup`, persisting in native scrollback. In rich mode this MUST
  go through a single flush mechanism: write the text to a flush file; the EXIT
  trap performs `rmcup` (no-op if not in alt-screen) then cats it.
- **R11.2** These exits MUST route through the flush mechanism in rich mode:
  `die()`; already-installed skip (exit 0); version-mismatch refuse (exit 1);
  missing-prereq failure (exit 1); disk failure (exit 1); user abort (exit 1,
  R12); success summary; privileged-child failure (existing).
- **R11.3** The EXIT/INT/TERM/HUP trap MUST restore the primary screen (`rmcup`
  when active) and remove all temp files, with no dangling cursor or animator
  artifacts, on any termination path.

### R12. Failure & abort

- **R12.1** On a `die()` inside the UI, the failed phase MUST be marked `✗` in
  the model, and the durable failure report MUST reproduce the checklist shape
  (completed `✔`, the failed `✗`, the failed step name) plus error detail and
  recovery guidance.
- **R12.2** Declining the confirm MUST exit non-zero (1) with `Aborted. No
  changes were made.` and MUST NOT have applied any privileged change.
- **R12.3** Exit codes MUST be: success 0; user/no-tty abort 1; pre-flight
  refuse/prereq/disk 1; install failure 1; already-installed skip 0.

## Acceptance criteria

- **AC-1** Plain-mode install-e2e and lib.sh-drift suites pass with no output
  diff (R2.1).
- **AC-2** Rich mode entered at the first step: resolve/prereqs/download render
  inside the managed screen; on success the durable summary appears in
  primary-screen scrollback after the UI closes.
- **AC-3** A forced `die()` at verify renders a failure report on the primary
  screen reproducing the checklist with `✗ Verify signature` (R12.1).
- **AC-4** Declining the confirm exits 1 with the abort message on the primary
  screen and no host changes (R12.2).
- **AC-5** On a window ≥ threshold but smaller than total content, the active
  phase stays visible and `⋮ N done above` appears; the full list prints on exit
  (R9).
- **AC-6** Maximizing the window between phases / at the plan repaints to full
  size promptly; maximizing mid-download is never garbled and reflows by the
  next transition (R8).
- **AC-7** A plan longer than the window is fully reviewable via scroll keys;
  `y` proceeds, `n` aborts (R10).
- **AC-8** `--verbose`, `--no-color`, `--quiet`, piped/non-TTY stdout, and a
  sub-threshold window each select plain mode (R1, R3).
- **AC-9** No orphaned animator process or raw terminal state remains after
  Ctrl-C at any point (R7.3, R11.3).

## Implementation plan (phased)

1. **Durable-flush generalization.** Promote the `run_priv_child` pattern into
   the EXIT trap: a flush file + trap that `rmcup`s then cats it. Route `die()`,
   the three pre-flight exits, and the abort path through it. Gate on `RICH_UI`.
   Prerequisite for entering the alt-screen early.
2. **Enter alt-screen right after `detect_tty`.** Add the two new disqualifiers
   (`--verbose`, `tput lines` < threshold).
3. **Render engine.** Header + rule, fixed-var phase model, `set_phase` →
   transition repaint, cursor-home + clear-to-end, clamp-to-width on every line;
   `WINCH` trap → repaint at free moments.
4. **Animator.** Model-free background loop owning the detail line: spinner glyph
   - width-clamp each tick.
5. **Auto-follow viewport.** Render the slice around the active row;
   `⋮ N done above` indicator when content exceeds the viewport.
6. **Acquire screen.** Wire the seven preamble steps through `set_phase` +
   detail-line substeps.
7. **Plan pager.** Static-text viewport with scroll keys (single-char reads via
   `stty`), confirm folded into the footer.
8. **Install screen.** Render the existing `PRIV_PROGRESS_FIFO` event stream into
   the model.
9. **Failure/abort/summary.** Reproduce the checklist in the failure report;
   verify all durable exits flush correctly.

## Non-goals (and why)

- **Manual scrollback during live phases.** Would require inverting into a single
  UI process with a raw-mode (`stty -icanon`) input loop, escape-sequence
  parsing, and bulletproof terminal-mode restoration on crash — high risk, large
  untested surface. Auto-follow + native scrollback on the primary screen after
  exit covers the need. This design is a clean stepping stone if we ever want it
  (it already establishes repaint-from-model + the state FIFO).
- **Shared model state file for the animator.** Would let the animator reflow the
  checklist on resize mid-download, but reintroduces two-writer races and
  temp-file coordination — not worth a ≤few-second cosmetic reflow lag.
- **Dynamic rich→plain downgrade** when the window shrinks below threshold
  mid-run. Tearing down the alt-screen mid-stream is fragile; the choice is made
  once at startup. Known limitation.

## Delivery

A `-delivery.md` verification map will be authored after implementation, tracing
each requirement (R*) and acceptance criterion (AC-*) to code and tests, in the
style of the other specs in `.tasks/specs/`.
