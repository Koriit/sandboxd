# uninstall.sh full-screen UI parity (shared ui.sh + build.sh)

Status: design agreed, not yet implemented.

## Summary

Bring `scripts/uninstall.sh` to full UX parity with `scripts/install.sh`'s
rich full-screen TUI — the same alt-screen session, header + auto-follow phase
checklist, model-free background animator, paged plan-review/confirm, and
durable post-`rmcup` summary — while degrading to a **byte-identical** plain
path whenever rich mode is unavailable.

The enabling refactor is to extract the rich-UI engine (today living entirely
inside `install.sh`, lines ~366–977 plus the spinner/download/pager helpers)
into a new **`scripts/ui.sh`** that is the single source of truth. It is:

- **sourced at runtime from disk** by both `install.sh` and `uninstall.sh` for
  local-checkout / dev runs (the resolver pattern already used for `lib.sh`,
  `install.sh:44–68`), and
- **inlined into both published scripts at build time** by a new
  **`scripts/build.sh`**, so the `curl | sh` artifacts at
  `https://Koriit.github.io/sandboxd/{install,uninstall}.sh` stay
  self-contained single files.

`build.sh` becomes the single publish-time assembly entrypoint: it inlines
`ui.sh` into both scripts, strips the `# BEGIN_TEST_ENV`…`# END_TEST_ENV` span
from `install.sh`, and emits the results to a `build/dist` output dir.
`.github/workflows/docs.yml` shrinks to *invoke `build.sh` and deploy its
output*; `tests/install-e2e/` builds via `build.sh` and exercises the
**assembled** artifact — exactly what a `curl | sh` user receives — so the e2e
suite doubles as a regression guard on the assembly itself.

The load-bearing decisions are: (1) the engine lives in **exactly one place**,
`ui.sh` — no inline mirror is kept in repo source (unlike the 3-constant
`lib.sh` mirror in `install.sh:33–35`); (2) `build.sh` owns **both** transforms
(inline + test-env-strip), so `docs.yml` carries no `sed`/`cat` logic and the
ordering question is decided once, in one testable place; (3) uninstall's root
operations route through the same privileged-batch + progress-FIFO model as
install (`install.sh:run_priv_child`, 3340–3598), so the checklist animates
live during `sudo` work; and (4) the rich path is purely additive — uninstall's
plain mode is frozen because `tests/install-e2e/test_uninstall.py` asserts it.

## Context

### Current state (baseline)

**`install.sh`** (3809 lines) already has the full rich UI from the prior
`2026-06-05-install-sh-full-screen-ui-design` spec. The engine is in one file
but not factored out:

| Engine concern                                                                              | install.sh lines |
| ------------------------------------------------------------------------------------------- | ---------------- |
| `die()` with `SUMMARY_FILE` checklist-shaped report                                         | 366–402          |
| `setup_colors` (RED/GREEN/YELLOW/**BLUE**/RESET)                                            | 404–418          |
| `is_utf8`                                                                                   | 422–429          |
| `cleanup_tmpdir` (EXIT trap: animator/spinner kill, `rmcup`, cursor-restore, summary flush) | 445–500          |
| `ui_enter_alt_screen` / `ui_leave_alt_screen`                                               | 504–531          |
| `tty_print`, `ui_clamp`, `ui_render_header`                                                 | 543–581          |
| `ui_phase_name`/`ui_phase_status`/`ui_set_phase_status`/`ui_init_phases`                    | 584–641          |
| `_ui_render_checklist_body` (auto-follow `⋮ N done above`)                                  | 647–729          |
| `ui_term_size`, `ui_render_checklist`                                                       | 739–795          |
| `_ui_spinner_frame` (35 braille frames, `case` not `cut -c`)                                | 803–842          |
| `_ui_animator_body`/`ui_animator_start`/`ui_animator_stop`/`_noclear`                       | 848–918          |
| `ui_restore_stty`, `ui_service_winch`                                                       | 924–939          |
| `set_phase`, `ui_find_phase`, `_ui_winch_trap`                                              | 946–977          |
| `detect_tty` + RICH_UI gate (+ WINCH trap install)                                          | 1092–1135        |
| `_spinner_frame`/`spinner_start`/`spinner_stop`/`spinner_run`                               | 1499–1577        |
| `download_with_bar` + bar renderers + `_kb_to_mb_1dp`                                       | 1577–1799        |
| `confirm_plan` raw-mode pager (`_cp_render`, scroll keys)                                   | 2409–2639        |
| `_print_failure_report` (checklist-shaped + plain)                                          | 3606–3682        |

Module-level UI variables (install.sh:121–258): `RED GREEN YELLOW BLUE RESET`,
`RICH_UI`, `RICH_UI_MIN_ROWS` (=9), `ALT_SCREEN_ACTIVE`, `STTY_RAW_ACTIVE`,
`STTY_SAVED`, `SPINNER_PID`, `SUMMARY_FILE`, `UI_TTY`, `UI_ROWS`, `UI_COLS`,
`UI_CURRENT_HEADER`, `WINCH_PENDING`, `UI_PHASE_NAMES`, `UI_PHASE_STATUSES`,
`UI_PHASE_COUNT`, `UI_DETAIL_TEXT`, `UI_ANIM_PID`. The phase-name *content*
(`UI_ACQUIRE_PHASES`, `UI_INSTALL_PHASES`, 233–253) and the FIFO machinery
state (`PRIV_PROGRESS_FIFO`, `PHASE_CMD_FIFO`, 191–258) are script-specific.

**`uninstall.sh`** (659 lines) is plain/linear with **zero** rich UI. It
copy-pastes `emit` (102–106), `log_line`/`log_ok`/`log_warn`/`log_fail`
(108–120), a 4-color `setup_colors` *without BLUE* (129–141), and a plain
`die` (122–127) from install.sh, and does **not** source `lib.sh`. Its steps:
`parse_args` (193), `resolve_state_path` (166), `check_daemon_running` (247),
`read_install_state` (267), `stop_and_disable_unit` (295), `remove_systemd_unit`
(322), `revert_bridge_helper_setuid` (340), `remove_bridge_conf_rules` (366),
`remove_users_conf` (419, conditional on `we_created_users_conf`),
`defer_route_helper_caps` (464), `remove_binaries` (477), `purge_step` (505,
the **only** confirmation today — a bare inline `Type PURGE to confirm:`
prompt, 534–536), `final_report` (606, ephemeral, no `SUMMARY_FILE`). Flags:
`--purge --force --yes --verbose --quiet --no-color`. Almost every mutating
step shells out to `sudo -k …` individually (no batched privileged child).

**`lib.sh`** (27 lines) holds only the 3 cosign constants; `install.sh` carries
an inline mirror (33–35) that `test_lib_sh_drift.py` byte-compares.

**Distribution** (`.github/workflows/docs.yml:60–73`): a single inline `run:`
block does `sed '/# BEGIN_TEST_ENV/,/# END_TEST_ENV/d' scripts/install.sh >
site/public/install.sh`, `cp scripts/uninstall.sh site/public/uninstall.sh`,
then a `grep` post-check that fails if `SANDBOX_(INSTALL|UPDATE)_TEST_` /
`_DEBUG_COSIGN_STDERR` / `_SKIP_SIGSTORE` leaked into the published install.sh.

**Test-env spans in install.sh** live at lines 1890–1983 (`sigstore_verify`)
and 2698–3008 (`write_priv_script` helpers). **None fall inside the engine
line ranges above** — verified by `grep -n BEGIN_TEST_ENV scripts/install.sh`.
This is the proof for the ordering argument in §3.

**Tests touching scripts:**

- `tests/install-e2e/test_lib_sh_drift.py` — byte-compares the 3 cosign
  constants between `lib.sh` and `install.sh`.
- `tests/install-e2e/conftest.py:_stage_scripts` (839–852) — `vm.cp`s the
  **raw** `scripts/install.sh`, `scripts/uninstall.sh`, `scripts/lib.sh` into
  `/tmp` of each VM. `INSTALL_SH/UNINSTALL_SH/LIB_SH` point at `scripts/`
  (45–47). `test_uninstall.py` runs `sudo bash /tmp/uninstall.sh …`.
- `tests/install-e2e/build-local-tarball.sh` (670 lines) — builds the **Rust
  binaries** release **tarball** (`dist/sandboxd-<ver>-<arch>.tar.gz` + a
  `.sigstore` stub). This is the artifact `install.sh` *installs from*; it has
  nothing to do with shell-script assembly. Driven by conftest's
  `release_tarball_*` fixtures and by `install-e2e.yml`.
- `tests/rich-ui-dash/harness.sh` (1722 lines) — sources rich-UI **function
  blocks** out of `install.sh` by awk markers anchored on function names
  (`/^tty_print\(\)/ … /^_ui_winch_trap\(\)/`, lines 30–85), injects the
  module-level vars by hand (129–147), and runs scenarios under both `sh`
  (dash) and `bash`. Exercises rich + plain code paths in isolation.
- `ci.yml:shellcheck` (44–54) runs `shellcheck -s sh -S style
  scripts/install.sh scripts/uninstall.sh`.

### Driving constraints

- The engine MUST live in exactly one place (`ui.sh`); no inline mirror in repo
  source. Drift like the `lib.sh`/`install.sh` 3-constant duplication is the
  thing being eliminated, not replicated.
- Published artifacts MUST remain single self-contained files (`curl | sh`).
- uninstall's plain path is asserted by `test_uninstall.py` (exit codes,
  `parse_install_log_actions` allow-list) and MUST stay behaviourally
  identical.
- `#!/bin/sh` / dash safety: no `$'…'`, no `printf '\xNN'` hex, no byte-wise
  `cut -c` on multibyte glyphs (the engine already obeys this — `ui_clamp` uses
  awk `substr`, `_ui_spinner_frame` uses a `case`).
- uninstall runs as `sudo bash /tmp/uninstall.sh` in the e2e (`test_uninstall.py`
  invokes it as root); install runs unprivileged and elevates per-batch. The
  privilege models differ — see §5 and the CLARIFY check.

## Architecture

### `scripts/ui.sh` — the single-source engine

`ui.sh` is a **sourced fragment** (no shebang-driven `main`, no top-level
side effects beyond function + default-variable definitions). It is `#!/bin/sh`
/ dash-safe and passes `shellcheck -s sh -S style`. It contains:

**Module-level variable defaults** (so a sourcing script gets sane initial
state even before it sets flags): `RED GREEN YELLOW BLUE RESET=""`, `RICH_UI=0`,
`RICH_UI_MIN_ROWS=9`, `ALT_SCREEN_ACTIVE=0`, `STTY_RAW_ACTIVE=0`, `STTY_SAVED=""`,
`SPINNER_PID=0`, `SUMMARY_FILE=""`, `UI_TTY=""`, `UI_ROWS=0`, `UI_COLS=0`,
`UI_CURRENT_HEADER=""`, `WINCH_PENDING=0`, `UI_PHASE_NAMES=""`,
`UI_PHASE_STATUSES=""`, `UI_PHASE_COUNT=0`, `UI_DETAIL_TEXT=""`, `UI_ANIM_PID=0`.
Each sourcing script keeps its **own** non-UI vars (`QUIET`, `NO_COLOR`,
`VERBOSE`, `INSTALL_LOG`, `SCRIPT_NAME`, `TMPDIR_INSTALL`, etc.) — those are not
moved.

**Functions moved verbatim** (from the install.sh line map above):
`setup_colors`, `is_utf8`, `osc8_link`, `tty_print`, `ui_clamp`,
`ui_render_header`, `ui_phase_name`, `ui_phase_status`, `ui_set_phase_status`,
`ui_init_phases`, `_ui_render_checklist_body`, `ui_term_size`,
`ui_render_checklist`, `_ui_spinner_frame`, `_ui_animator_body`,
`ui_animator_start`, `ui_animator_stop`, `ui_animator_stop_noclear`,
`ui_restore_stty`, `ui_service_winch`, `set_phase`, `ui_find_phase`,
`_ui_winch_trap`, `ui_enter_alt_screen`, `ui_leave_alt_screen`, plus the
generic spinner block (`_spinner_frame`, `spinner_start`, `spinner_stop`,
`spinner_run`).

**`download_with_bar`** and its bar renderers (`_bar_style_b`, `_bar_style_c`,
`_kb_to_mb_1dp`): moved to `ui.sh`. They are install-only *consumers* today,
but they are pure presentation and dash-safe; keeping all presentation in one
file is cleaner and the harness already treats them as an extractable block.
uninstall does not call them — that is fine; an unused function is free.

#### Functions that stay per-script (with justification)

| Function                                                   | Decision                                                                              | Why                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `die()`                                                    | **Stays per-script** (thin), but the *durable-report body* is a shared `ui.sh` helper | `die` references `INSTALL_LOG`, `SCRIPT_NAME`-specific recovery text ("re-run install.sh" vs "re-run uninstall.sh"), and each script's phase model. The checklist-shaped report writer (install.sh:378–396) is generalized into a `ui.sh` function `ui_die_report <msg> <recovery_line> <log_path>` that reads the live phase model; each script's `die()` calls it with script-specific args, then `exit 1`.                                                                             |
| `setup_colors`                                             | **Moves to ui.sh** (the install variant with BLUE)                                    | uninstall's variant lacks BLUE (uninstall.sh:129–141); the rich UI needs BLUE for the spinner (`_ui_animator_body`, install.sh:857). Both scripts adopt the 5-color version. uninstall gains BLUE — additive, no behavioural loss.                                                                                                                                                                                                                                                        |
| `detect_tty`                                               | **Stays per-script**, but delegates to a shared `ui_detect_tty` core                  | The gate logic (probe `tput smcup/rmcup`, height ≥ `RICH_UI_MIN_ROWS`, set `RICH_UI`/`UI_TTY`/`UI_ROWS`/`UI_COLS`, install the WINCH trap, `log_ok step=tty_detect …`) is identical and moves to `ui.sh` as `ui_detect_tty`. The thin per-script wrapper exists only so the `log_ok` line keeps each script's `SCRIPT_NAME`. Decision D3.                                                                                                                                                 |
| `cleanup_tmpdir`                                           | **Stays per-script**                                                                  | It mixes shared teardown (animator/spinner kill, `ui_restore_stty`, `rmcup`, cursor-restore, summary `cat`) with **script-specific** cleanup (`rm -rf "$TMPDIR_INSTALL"`, removing FIFOs). The shared teardown is factored into a `ui.sh` helper `ui_teardown` that each `cleanup_*` calls first, then does its own `rm`. Decision D4.                                                                                                                                                    |
| `emit`, `log_line`/`log_ok`/`log_warn`/`log_fail`          | **Move to ui.sh**                                                                     | Byte-identical between the two scripts except `log_line`'s `sudo -n` (install) vs `sudo -k` (uninstall) for the privileged log-append fallback (install.sh:350 vs uninstall.sh:114). Reconcile to `sudo -n` (non-interactive: a log write must never prompt) and move the unified version to `ui.sh`. This is the one behavioural change uninstall absorbs; it is strictly safer (no surprise password prompt on log write) and is covered by the e2e log-action assertions. Decision D5. |
| Phase-name lists, work steps, plan content, FIFO machinery | **Stay per-script**                                                                   | install's `UI_ACQUIRE_PHASES`/`UI_INSTALL_PHASES`, uninstall's new phase lists, `compute_plan`/`render_plan` content, and the privileged-child writers are inherently per-script. ui.sh provides the *engine*; each script provides the *model + content*.                                                                                                                                                                                                                                |

`confirm_plan`'s pager (`_cp_render` + the raw-mode read loop, install.sh:
2426–2620) **moves to ui.sh** as a generic `ui_pager_confirm <render-callback>`
— see §4. The *plan text* is supplied by each script's `render_plan`.

### Runtime sourcing (dev) — model on `__sandbox_lib_sh_resolve`

Both scripts gain a `__sandbox_ui_sh_resolve()` mirroring
`install.sh:44–63`: resolution order is (1) `$SANDBOX_UI_SH` env override (used
by the in-tree harness/e2e), (2) `$(dirname "$0")/ui.sh` for a local checkout,
(3) `./ui.sh` in cwd. Unlike the `lib.sh` resolver, **failure is fatal**:
`ui.sh` carries the entire UI, so there is no inline fallback to fall through
to. If unresolved, the script prints a clear error to stderr and exits non-zero:

```text
ui.sh not found next to this script. If you are running from a local
checkout, ensure scripts/ui.sh is present. If you fetched this file
directly, use the published self-contained installer:
  curl -fsSL https://Koriit.github.io/sandboxd/install.sh | sh
```

This die runs *before* `setup_colors`/`detect_tty` (which live in `ui.sh`), so
it uses a bare `printf … >&2; exit 1`, not `die()`. Decision D2.

### Inline-at-build (published) — marker design

Each script's runtime source line is wrapped in a marker span:

```sh
# BEGIN_INLINE ui.sh
__sandbox_ui_sh_path=$(__sandbox_ui_sh_resolve) || { printf '%s\n' "<die text>" >&2; exit 1; }
# shellcheck disable=SC1090
. "$__sandbox_ui_sh_path"
# END_INLINE ui.sh
```

`build.sh` replaces the **entire** `# BEGIN_INLINE ui.sh` … `# END_INLINE
ui.sh` span (inclusive) with the literal body of `scripts/ui.sh`. The result
is a single self-contained file with the engine inlined and no `. ui.sh` line
left. The `__sandbox_ui_sh_resolve` function definition itself lives **outside**
the marker span (it is small and harmless to keep), or is also dropped — the
spec's choice: **keep the resolver definition but drop only the invocation
span**, so the published file has an unused `__sandbox_ui_sh_resolve` (free) and
no dangling `. ui.sh`. Verification asserts no `\. .*ui\.sh` invocation and no
`# (BEGIN|END)_INLINE` marker survives (§3 / §7a).

### uninstall phase model + privileged batch

uninstall maps its mutating steps to a single **Remove** phase set fed by the
same `STEP N begin/ok/fail <label>` progress FIFO that install uses
(`install.sh:run_priv_child` 3340–3598, `write_priv_script` 2665+). Today
uninstall fires many independent `sudo -k` calls; for parity those are
consolidated into **one privileged child** run under a single `sudo sh
$PRIV_SCRIPT`, emitting progress tokens the unprivileged parent consumes to
drive the checklist live. See §5 for the full mapping and the privilege-model
reconciliation.

## Decisions

| #   | Decision                 | Choice                                                                                                 | Rationale                                                                                       |
| --- | ------------------------ | ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| D1  | Engine location          | One file `scripts/ui.sh`; no inline mirror in repo source                                              | True single source of truth; eliminates the `lib.sh`-style drift class                          |
| D2  | Dev sourcing             | `__sandbox_ui_sh_resolve` (env / `$0`-dir / cwd); **fatal** if missing                                 | No inline fallback exists; a missing engine is unrecoverable, so fail loud with guidance        |
| D3  | `detect_tty`             | Shared `ui_detect_tty` core; thin per-script wrapper for the `log_ok` line                             | Gate is identical; only `SCRIPT_NAME` differs                                                   |
| D4  | `cleanup_tmpdir`         | Stays per-script; shared teardown extracted to `ui_teardown`                                           | Mixes shared screen-restore with per-script tmpdir/FIFO cleanup                                 |
| D5  | `emit`/`log_*`           | Move to ui.sh; reconcile `sudo -k`→`sudo -n` for log append                                            | Non-interactive log write must never prompt; safer for uninstall                                |
| D6  | Build entrypoint         | New `scripts/build.sh` owns inline + test-env-strip; `docs.yml` just invokes it                        | All assembly logic local + testable; YAML carries none                                          |
| D7  | Build vs tarball builder | `build.sh` (scripts) sits **beside** `build-local-tarball.sh` (Rust binaries); neither wraps the other | They assemble disjoint artifacts; conflating them couples script publishing to a Rust toolchain |
| D8  | e2e target               | e2e stages the **built** artifacts (via `build.sh`), not raw `scripts/`                                | Tests what users actually `curl`; guards the assembly                                           |
| D9  | Strip ordering           | `build.sh` inlines ui.sh **and** strips test-env in either order — proven equivalent                   | ui.sh contains no test-env spans; the two transforms touch disjoint line sets                   |
| D10 | uninstall privilege      | Single privileged child + progress FIFO, same as install                                               | Live checklist needs a streaming progress channel; many `sudo -k` calls cannot drive it         |
| D11 | Purge confirm            | Folded into the paged confirm; `--purge` still requires typing `PURGE` *inside the pager footer*       | Preserves the destructive-confirm strength while unifying on the pager                          |

## Requirements

Keywords MUST / MUST NOT / SHOULD / MAY are RFC 2119.

### R1. ui.sh extraction & single-source

- **R1.1** All engine functions and engine module-vars enumerated in
  Architecture MUST live only in `scripts/ui.sh`. `scripts/install.sh` and
  `scripts/uninstall.sh` MUST NOT contain a second definition of any of them.
- **R1.2** `ui.sh` MUST be a side-effect-free sourced fragment: no shebang
  `main`, no top-level command execution beyond function and default-variable
  definitions. It MUST pass `shellcheck -s sh -S style`.
- **R1.3** `install.sh`'s behaviour after extraction MUST be byte-for-byte
  unchanged in both rich and plain modes (the existing install-e2e,
  rich-ui-dash, and lib.sh-drift suites are authoritative).

### R2. Runtime sourcing (dev)

- **R2.1** Both scripts MUST resolve `ui.sh` via `__sandbox_ui_sh_resolve`
  (env `$SANDBOX_UI_SH` → `$(dirname "$0")/ui.sh` → `./ui.sh`) and `.`-source
  it before any UI function or `setup_colors`/`detect_tty` call.
- **R2.2** If `ui.sh` cannot be resolved, the script MUST print the guidance
  message (§Architecture) to stderr and exit non-zero, **without** calling any
  ui.sh function.

### R3. Inline-at-build (published)

- **R3.1** Each script MUST wrap its runtime `. "$ui_sh_path"` invocation in a
  `# BEGIN_INLINE ui.sh` … `# END_INLINE ui.sh` span.
- **R3.2** `build.sh` MUST replace that span (inclusive) with the verbatim body
  of `scripts/ui.sh` for both scripts.
- **R3.3** The published `install.sh` and `uninstall.sh` MUST contain the engine
  function definitions, MUST NOT contain any `# BEGIN_INLINE`/`# END_INLINE`
  marker, and MUST NOT contain a surviving `. …/ui.sh` invocation line.
- **R3.4** The published `install.sh` MUST contain no `# BEGIN_TEST_ENV` span and
  MUST pass the existing no-test-env-leak `grep` check (now run by `build.sh`).

### R4. build.sh

- **R4.1** `scripts/build.sh` MUST be the single entrypoint that produces the
  publishable artifacts: inline ui.sh into both scripts + strip test-env from
  install.sh + emit to an output dir.
- **R4.2** `build.sh` MUST be `#!/bin/sh` / dash-safe and pass
  `shellcheck -s sh -S style`.
- **R4.3** `build.sh` MUST support selecting a subset (`--install-only`,
  `--uninstall-only`; default both) and overriding the output dir
  (`--out DIR`, default `build/dist/`).
- **R4.4** `build.sh` MUST fail (non-zero) if either marker span is malformed
  (missing BEGIN/END, or BEGIN without END) or if the post-strip leak check on
  install.sh trips.
- **R4.5** `build.sh` output MUST be reproducible: running it twice on an
  unchanged tree yields byte-identical files.

### R5. docs.yml thinning

- **R5.1** `docs.yml`'s script-staging step MUST invoke `scripts/build.sh` and
  copy its output into `site/public/`, and MUST NOT contain inline `sed`-strip
  or `cat`/concatenation logic.
- **R5.2** The published-artifact verification (no marker, no `. ui.sh`, no
  test-env leak, engine present) MUST run — either inside `build.sh` (preferred,
  so it is testable locally) with `docs.yml` relying on `build.sh`'s exit code,
  or as a thin post-step in `docs.yml`.

### R6. uninstall rich UI parity

- **R6.1** uninstall MUST select rich vs plain via the same `ui_detect_tty` gate
  as install (TTY, not `--no-color`/`--quiet`/`--verbose`, `/dev/tty` usable,
  `tput smcup/rmcup` ok, rows ≥ `RICH_UI_MIN_ROWS`). Decided once, never changed.
- **R6.2** Rich uninstall MUST present three logical screens — **Analyze**
  (read state / probe daemon), **Plan + confirm** (paged), **Remove** (live
  checklist) — each with a one-line evolving header + rule (e.g.
  `sandboxd <ver> · analyzing` → `· review removal plan` → `· removing`).
- **R6.3** The Remove checklist MUST render the four glyph states (`·`/`▸`/`✔`/
  `✗`), auto-follow the active phase, and show `⋮ N done above` when content
  exceeds the viewport — identical engine behaviour to install.
- **R6.4** The background animator MUST own only the detail line; the main
  process MUST stop it before any checklist repaint and restart it after — the
  same two-writer partition install uses.
- **R6.5** On exit (success, failure, abort, Ctrl-C) the durable summary /
  failure report / abort message MUST print to the primary screen after `rmcup`
  via the single `SUMMARY_FILE` flush in `cleanup_tmpdir`/`ui_teardown`.

### R7. uninstall plan + paged confirm

- **R7.1** uninstall MUST compute a **removal plan** (`compute_plan` analogue)
  describing what will be Stopped / Removed / Reverted / Kept, honouring
  `--purge` vs not and the conditional `users.conf` removal
  (`we_created_users_conf`), and render it through the same
  `ui_pager_confirm` pager as install. The bare `Type PURGE` prompt
  (uninstall.sh:534–536) is removed.
- **R7.2** `--yes` and `--force` MUST bypass the pager (proceed without
  rendering it), preserving current non-interactive behaviour. `--force` only
  affects the running-daemon refusal (uninstall.sh:252–258), not confirmation;
  `--yes` is the confirmation bypass.
- **R7.3** When `--purge` is set and `--yes` is **not**, the destructive-confirm
  MUST be preserved/strengthened: the pager footer MUST require typing the
  literal word `PURGE` (not a single `y`) to proceed, and MUST clearly list the
  purge-only deletions (per-uid state dir, legacy dir, sandbox user, group
  memberships, gateway image) in the plan body. Declining MUST exit 1 with
  `Aborted. No changes were made.`

### R8. uninstall privileged batch + FIFO

- **R8.1** uninstall's mutating steps MUST run inside a single privileged child
  (one `sudo sh $PRIV_SCRIPT`) that emits `STEP N begin/ok/fail <label>` over a
  progress FIFO; the unprivileged parent MUST consume it to drive the checklist
  via the same `SET_PHASE`/`PHASE_CMD_FIFO` consumer model as install
  (3387–3536).
- **R8.2** The EXIT/INT/TERM/HUP trap MUST kill+reap the animator and any
  reader/consumer subshell, `rmcup`, restore the cursor and stty, and flush
  `SUMMARY_FILE` on every termination path.
- **R8.3** On a step failure, the parent MUST attribute it (mark `✗`), reproduce
  the checklist shape in the durable failure report, and include a log tail —
  the `_print_failure_report` behaviour (3606–3682), generalized for uninstall.
- **R8.4** A second uninstall run MUST remain idempotent (every step logs a
  skip action) — `test_uninstall.py::test_uninstall_double_run_idempotent`'s
  allow-list (`{"skip"}`) is authoritative.

### R9. Plain-mode invariance & POSIX/dash safety

- **R9.1** uninstall plain-mode output and exit codes MUST stay behaviourally
  identical (the `test_uninstall.py` assertions and
  `parse_install_log_actions` allow-list are authoritative). The one accepted
  change is the `sudo -k`→`sudo -n` log-append reconciliation (D5).
- **R9.2** In plain mode `/dev/tty` MUST NOT be opened for UI and no rich-only
  function may execute (all gated on `RICH_UI`).
- **R9.3** `ui.sh`, `build.sh`, and both scripts MUST be dash-safe: no `$'…'`,
  no `printf '\xNN'` hex, no byte-wise `cut -c` on multibyte glyphs; literal
  UTF-8 glyphs embedded directly (the existing engine and harness lines
  653–682 already encode this rule).

## Acceptance criteria

- **AC-1** After extraction, `test_lib_sh_drift.py`, the rich-ui-dash harness
  (rebased on `ui.sh`), and the install plain-mode e2e all pass with no diff in
  install.sh behaviour (R1.3).
- **AC-2** `scripts/build.sh` produces `build/dist/install.sh` and
  `build/dist/uninstall.sh` that: contain the engine functions, contain no
  inline marker, contain no `. ui.sh` line, and (install.sh) contain no
  test-env span and pass the leak `grep` (R3, R4).
- **AC-3** `build.sh` run twice yields byte-identical output (R4.5).
- **AC-4** `docs.yml` contains no `sed`-strip or concatenation logic; it invokes
  `build.sh` and deploys `build/dist/` (R5).
- **AC-5** Rich uninstall on a real install enters the alt-screen at Analyze,
  shows the Remove checklist ticking live during the privileged batch, and
  leaves a durable summary in primary-screen scrollback (R6, R8).
- **AC-6** A longer-than-window removal plan is fully reviewable via scroll keys;
  `y` proceeds (non-purge) / typing `PURGE` proceeds (purge); `n` aborts with
  exit 1 and no host changes (R7).
- **AC-7** `--yes`/`--force` paths and non-TTY/piped stdout select plain mode and
  bypass the pager; the VM e2e (`sudo bash uninstall.sh --yes --no-color
  --force`) passes unchanged against the **built** artifact (R7.2, R9).
- **AC-8** A forced step failure in the uninstall privileged batch renders a
  checklist-shaped failure report on the primary screen with the failed step
  `✗` and a log tail (R8.3).
- **AC-9** Double-uninstall stays idempotent under the `{"skip"}` allow-list
  (R8.4); no orphaned animator/raw-tty after Ctrl-C at any point (R8.2).

## build.sh design (concrete)

### Relationship to `build-local-tarball.sh` (D7)

They are **siblings**, not competitors:

|             | `tests/install-e2e/build-local-tarball.sh`                  | `scripts/build.sh` (new)                        |
| ----------- | ----------------------------------------------------------- | ----------------------------------------------- |
| Produces    | Rust **binaries** release **tarball** + `.sigstore` stub    | Self-contained published **shell scripts**      |
| Output      | `tests/install-e2e/dist/sandboxd-<ver>-<arch>.tar.gz`       | `build/dist/{install,uninstall}.sh`             |
| Consumed by | `install.sh` *installs from* it (the thing being installed) | `curl | sh` users; the e2e *runs* these scripts |
| Toolchain   | cargo + docker (glibc-floor logic)                          | pure POSIX sh + `sed`/`awk`                     |

`build.sh` MUST NOT call `build-local-tarball.sh` and vice-versa. In the e2e,
the two run independently: `build-local-tarball.sh` makes the tarball the
scripts install *from*; `build.sh` makes the scripts themselves. Keeping them
separate avoids coupling script publishing to a Rust toolchain (a docs-only
change must not need cargo).

### Inputs / outputs / flags

```text
Usage: build.sh [--install-only|--uninstall-only] [--out DIR]

Inputs (repo-relative, resolved from $0):
  scripts/ui.sh, scripts/install.sh, scripts/uninstall.sh

Output (default build/dist/, override --out):
  build/dist/install.sh      (ui.sh inlined, test-env stripped)
  build/dist/uninstall.sh    (ui.sh inlined)
  build/dist/ mode mirrors the source scripts' +x bit.
```

### Assembly algorithm (per script)

1. Read `scripts/ui.sh` body once.
2. For each selected script, stream it and replace the `# BEGIN_INLINE ui.sh`
   … `# END_INLINE ui.sh` span (inclusive) with the ui.sh body. An `awk`
   state machine (anchored on the two marker lines) is the dash-safe primitive;
   it errors out (non-zero) if BEGIN is seen without a matching END or vice
   versa (R4.4).
3. For `install.sh` only, strip `# BEGIN_TEST_ENV` … `# END_TEST_ENV` spans
   (the existing `sed '/…/,/…/d'`).
4. Write to `--out`, `chmod --reference` from the source script.
5. Verify (R3, R4.4): published file has no `# (BEGIN|END)_(INLINE|TEST_ENV)`
   markers, no `^\s*\. .*ui\.sh` line, contains a known engine sentinel (e.g.
   the `_ui_spinner_frame()` definition), and for install.sh the test-env leak
   `grep` is clean. Any failure exits non-zero.

### Strip-vs-inline ordering (D9, §3 proof)

The two transforms touch **disjoint** line sets: every `BEGIN_TEST_ENV` span in
install.sh is at 1890–1983 / 2698–3008 (inside `sigstore_verify` and the
priv-script writers), none inside the engine ranges (verified by `grep -n
BEGIN_TEST_ENV scripts/install.sh`). `ui.sh` itself contains **no**
`BEGIN_TEST_ENV` spans (it is pure UI; nothing test-gated). Therefore:

- inlining first cannot introduce a test-env span (ui.sh has none), and
- stripping first cannot disturb the inline marker (the marker is not inside a
  test-env span).

So inline-then-strip and strip-then-inline are equivalent. `build.sh` does
**inline first, then strip** (matches the natural pipeline order), and the
verification step (5) is the backstop regardless. This is a *strict
improvement* over the status quo where the ordering was implicit in YAML.

### Invocation

- **docs.yml:** `run: scripts/build.sh --out site/public` (then the existing
  `chmod --reference` is unnecessary — `build.sh` sets the bit). The
  leak-`grep` post-check moves into `build.sh` (R5.2).
- **e2e harness:** a conftest fixture runs `scripts/build.sh --out
  <session-tmp>/dist-scripts` once per session; `_stage_scripts` (conftest.py:
  839–852) is rewired to `vm.cp` the **built** `install.sh`/`uninstall.sh` from
  that dir (and **drops** the `lib.sh` stage, since the published install.sh
  has the cosign constants inlined and ui.sh inlined — no adjacent files
  needed). `INSTALL_SH`/`UNINSTALL_SH` (45–46) repoint to the built paths.

## uninstall phase mapping (§5 detail)

Plain linear steps → one privileged-batch phase set fed by the FIFO:

| uninstall.sh step (line)            | Remove-phase label                                        | In priv child?             |
| ----------------------------------- | --------------------------------------------------------- | -------------------------- |
| `stop_and_disable_unit` (295)       | `stop-disable-unit`                                       | yes (`systemctl`)          |
| `remove_systemd_unit` (322)         | `remove-systemd-unit`                                     | yes (`rm` + daemon-reload) |
| `revert_bridge_helper_setuid` (340) | `revert-bridge-helper-setuid`                             | yes (`chmod u-s`)          |
| `remove_bridge_conf_rules` (366)    | `remove-bridge-conf-rules`                                | yes (`install`/`rm`)       |
| `remove_users_conf` (419)           | `remove-users-conf`                                       | yes (conditional)          |
| `remove_binaries` (477)             | `remove-binaries`                                         | yes (`rm` + rmdir)         |
| `purge_step` (505)                  | `purge-state`, `purge-user`, `purge-group`, `purge-image` | yes (purge only)           |

`check_daemon_running` (247), `resolve_state_path` (166), `read_install_state`
(267) run **unprivileged in the parent**, in the **Analyze** screen (they only
read state / probe a socket) — they are not in the privileged batch.
`defer_route_helper_caps` (464) is a no-op note and is folded into
`remove-binaries` (caps drop with the unlinked file).

### Privilege-model reconciliation (no CLARIFY)

install runs **unprivileged** and spawns one `sudo sh $PRIV_SCRIPT`; the
**unprivileged parent** owns the UI and consumes the FIFO. The FIFO lives under
the parent's `TMPDIR_INSTALL`; the privileged child only *writes* tokens to it
on fd 3 (`write_priv_script`). This is the model uninstall adopts.

The e2e invokes uninstall as `sudo bash /tmp/uninstall.sh` (test_uninstall.py:
34/66/116) — i.e. uninstall today often runs **as root already**. The FIFO
model still works root-or-not: the parent (root or not) owns the FIFO + UI and
spawns the privileged child via `sudo sh` (a no-op re-elevation when already
root, exactly as install's child is). The only nuance is that when the parent
is already root there is no unprivileged/privileged *boundary*, but the FIFO is
still the live-progress channel and the two-writer UI partition is unaffected
(the animator is a child of the parent regardless of uid). **No
privilege-model conflict blocks the FIFO approach** — the channel is about
progress streaming, not privilege separation, so the install pattern transfers
cleanly. (If a future requirement forced uninstall to run unprivileged and
elevate per-step like install, that is already the design here.)

## Test plan

### (a) Assembly-correctness test (replaces the drift concept's role)

A new `tests/install-e2e/test_build_assembly.py` (host-side, no VM) that runs
`scripts/build.sh --out <tmp>` and asserts, for both built scripts: no inline
marker, no `. ui.sh` line, the engine sentinel is present, and (install.sh) no
test-env span + clean leak `grep`. It also asserts `build.sh` is idempotent
(two runs → identical bytes). `test_lib_sh_drift.py` stays as-is — the cosign
constants are still mirrored between `lib.sh` and `install.sh` (unchanged by
this work; the inline ui.sh is a *separate* concern from the cosign pin). A
note: once ui.sh is inlined, the **built** install.sh contains the engine, but
the **source** install.sh does not — `test_lib_sh_drift.py` parses the source,
where the 3 cosign constants still live inline, so it is unaffected.

### (b) rich-ui-dash harness — uninstall scenarios + rebase

The harness's awk extraction (harness.sh:30–85) anchors on engine function
names that now live in `ui.sh`. Rebase: point `INSTALL_SH` extraction at
`scripts/ui.sh` (the functions moved there), keeping the per-script bits
(`detect_tty` wrapper, phase lists) sourced from each script as needed. Add
uninstall scenarios exercising: the Remove checklist auto-follow, the
purge-confirm pager footer (typing `PURGE`), the abort path (exit 1 +
`Aborted.`), and plain-mode `RICH_UI=0` no-op gating — each under **both** dash
and bash, matching the existing matrix.

### (c) VM-backed uninstall e2e (against the BUILT artifact)

Extend `tests/install-e2e/test_uninstall.py`: the existing clean / purge /
double-run tests already cover the plain path and now run the **built**
uninstall.sh (D8). Add a rich-mode assertion path where feasible (a PTY-backed
invocation asserting the durable summary lands in scrollback and exit codes
match), plus a `--purge` abort case (decline at the pager → exit 1, nothing
removed). The conftest build fixture (above) builds the scripts once per
session; `_stage_scripts` ships the built copies.

### (d) Effect on existing install tests

- `test_lib_sh_drift.py`: **unaffected** (parses source install.sh; cosign
  constants unchanged).
- rich-ui-dash for install.sh: **rebased** onto `ui.sh` extraction (b);
  scenarios otherwise unchanged.
- install plain-mode e2e: now runs the **built** install.sh. Behaviour must be
  byte-identical to the raw source minus the (stripped) test-env span — which
  is exactly what the harness env vars assume is present. **Open item:** the
  e2e relies on `SANDBOX_INSTALL_TEST_*` env-gated code that `build.sh`
  *strips*. The e2e must therefore run against the **un-stripped** build for
  the sigstore-stub path, or the harness keeps using the raw source for the
  signature-path tests and the built artifact for layout/idempotency tests.
  Resolution: `build.sh` gains a `--keep-test-env` flag; the e2e builds with
  `--keep-test-env` (still inlines ui.sh — the thing under test — but retains
  the test hooks the harness needs), while docs.yml builds without it. This
  preserves "e2e runs the assembled artifact" (ui.sh inlined) without losing
  the test hooks. Captured as Decision **D12**.

## Migration / rollout risk

- **Blast radius:** this touches the published `curl | sh` pipeline for a
  **root installer**. A bad inline (truncated ui.sh, surviving marker, broken
  function) ships to every operator. Mitigations: `build.sh` self-verifies
  (R4.4/§assembly step 5) and fails closed; `test_build_assembly.py` (a) gates
  CI before any deploy; the e2e (c) runs the *actual built* artifact end-to-end
  on real VMs.
- **Backward compat:** an operator running an **old** uninstall.sh against a
  **new** install state, or a new uninstall.sh against old state, is unchanged
  by this work — uninstall already reads `.install-state.json` defensively
  (`read_install_state`, jq `// default` fallbacks, uninstall.sh:279–286) and
  the state schema is untouched. The UI refactor is presentation-only.
- **docs-only changes no longer need cargo** (D7) — a strict de-risk vs. any
  design that funnelled script publishing through the tarball builder.

## Phased implementation plan

1. **Extract engine → `ui.sh`; make install.sh source it.** Move the functions
   - engine vars to `scripts/ui.sh`; add `__sandbox_ui_sh_resolve` + the
   `# BEGIN_INLINE ui.sh` span to install.sh; reconcile `emit`/`log_*`/
   `setup_colors`/`detect_tty` per D3–D5. Rebase rich-ui-dash extraction onto
   ui.sh. Prove install.sh behaviour unchanged via the existing suites
   (AC-1). No uninstall changes yet.
2. **Add `scripts/build.sh`; thin `docs.yml`.** Implement the inline + strip +
   verify pipeline, `--keep-test-env`/`--install-only`/`--uninstall-only`/
   `--out`. Point `docs.yml` at it (R5). Add `test_build_assembly.py` (AC-2/3/4).
   Rewire the e2e conftest build fixture + `_stage_scripts` to the built
   artifacts (AC-7 still green for install).
3. **Rebuild uninstall.sh on the shared engine.** Add `__sandbox_ui_sh_resolve`
   - inline span; adopt `ui_detect_tty`, the three-screen flow, `compute_plan`/
   `render_plan` for the removal plan, `ui_pager_confirm` with the purge-`PURGE`
   footer (R7), and the privileged-batch + FIFO consolidation (R8). Generalize
   `die`/`_print_failure_report`/`final_report` to use `SUMMARY_FILE`.
4. **Tests/e2e for uninstall rich path.** rich-ui-dash uninstall scenarios (b),
   VM rich-mode + purge-abort e2e (c), idempotency re-verified (AC-8/9).

Each phase is independently verifiable: phase 1 by the install suites, phase 2
by `test_build_assembly.py` + a docs dry-run, phases 3–4 by the uninstall
suites.

## Non-goals

- **Re-litigating the locked architecture** (ui.sh extraction + inline-at-build).
  Fixed by the brief.
- **Manual scrollback during live phases.** Inherits install's auto-follow +
  primary-screen-scrollback approach; no raw-mode input loop during the batch.
- **Per-session active-session probe for `--force`.** uninstall.sh:220–228
  already defers this to a future `sandbox update` release; out of scope.
- **Merging `build.sh` and `build-local-tarball.sh`** (D7). They stay separate.

## Delivery

A `-delivery.md` verification map will be authored after implementation,
tracing each requirement (R*) and acceptance criterion (AC-*) to code and
tests, in the style of the other specs in `.tasks/specs/`.

DONE: .tasks/specs/2026-06-07-uninstall-tui-parity-design-spec.md
