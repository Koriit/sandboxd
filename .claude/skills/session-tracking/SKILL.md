---
name: session-tracking
description: >
  Track progress across multi-session implementation plans. Manages
  .tasks/progress.json via the progress CLI script. Use when starting,
  logging, or closing implementation sessions, or after context compaction
  to restore orientation.
allowed-tools: Read Bash
argument-hint: "[open|log|close|status|review|block|resume|todo]"
---

# Session Tracking

This skill tracks progress across multi-session implementation plans using an append-only JSON log. All file operations are handled by the `progress` script at `${CLAUDE_SKILL_DIR}/scripts/progress` -- the agent never edits the progress file directly. The data model is defined in `progress-schema.json` in this skill's directory.

## Two-Phase Protocol

### Phase 1 -- During session (append-only current_log)

On session start, run `open` to initialize tracking. Throughout the session, append entries whenever:

- A significant **decision** is made (especially deviations from the plan)
- A non-obvious **discovery** surfaces (something the plan didn't anticipate)
- A **blocker** is encountered (use `block` for session-level blockers)
- An important **note** needs preserving

These entries are the crash-recovery mechanism: if compaction happens mid-session, `status` restores orientation instantly.

Keep entries concise -- one or two sentences. No file paths; type/module names at most.

### Post-Subagent Checkpoint

When delegating to subagents, include in the delegation prompt an instruction to report back: decisions made, discoveries, blockers encountered, and any deferred work identified. This gives you the raw material for log entries and todos at the checkpoint.

After each subagent return, check whether anything needs to be recorded:

- **Log entries** -- decisions, discoveries, or blockers surfaced by the subagent's work (see "When to Log" below).
- **Todos** -- deferred work items the subagent identified that don't belong in the current session.

A subagent finishing does not mean the session is finished. A session may involve multiple subagent runs. Do not call `close` at a post-subagent checkpoint.

### Phase 2 -- Session close

Only after all session work is verified complete, run `close`. The close command collects decisions/discoveries/blockers from current_log entries automatically. The orchestrator provides: summary (freeform) and artifacts (optional). current_log is cleared and current_state.status is set to `completed`. The session and milestone stay at the just-closed values -- the agent must explicitly `open` the next session.

Before closing, all selected todos must be resolved (completed or deferred). The script enforces this.

### Block and Resume

If a session hits a blocking issue:

1. Run `block --reason TEXT` to set status to `blocked` and auto-log the blocker entry.
2. When the blocker is resolved, run `resume` to set status back to `in_progress`.

### Todo System

Todos capture concrete, actionable work discovered during implementation that should be deferred rather than handled in the current session. They bridge the gap between "too small for a plan change" and "too important to forget." Examples: "need to revisit error handling in module X", "should add integration test for edge case Y", "dependency Z needs updating before M4".

Use todos for items that don't belong in the current session's scope. If a discovery is significant enough to change the plan itself (new session needed, session scope change), that's a plan change, not a todo.

Lifecycle:

1. **Add** -- `todo add --text TEXT` adds a todo as `selected` (picked up now) or `--defer` to park it.
2. **Select** -- `todo select ID...` pulls deferred todos into the current session.
3. **Complete** -- `todo complete ID...` marks selected todos as done.
4. **Defer** -- `todo defer ID...` pushes selected todos back to the backlog.
5. **Drop** -- `todo drop ID...` permanently removes todos from consideration.

When opening a session, the script shows deferred todos so the agent can decide what to pick up. When closing, the script refuses if any selected todos are unresolved.

### Why this works under degradation

Appending a structured entry ("I decided X") is trivially reliable even with degraded context. Synthesis (writing the summary at close) only happens once per session when the orchestrator has fresh context from the subagent's completion signal.

## When to Log

Not every subagent return needs a log entry. Log when:

- The subagent made an architectural or design choice not specified in the plan
- Something unexpected was discovered about the codebase, dependencies, or tools
- A blocker was hit (even if resolved -- future sessions may hit related issues)
- The approach diverged from the plan
- A key type, module, or interface was defined for the first time

Do NOT log:

- Routine progress ("wrote tests, they pass")
- Information already in the implementation plan
- Information recoverable from git history

## Script Reference

```bash
# One-time setup
${CLAUDE_SKILL_DIR}/scripts/progress init --total-sessions 28 --first-session M0-S1 --first-title "Cargo workspace and directory structure"

# Start a session (--next sets orientation text for current_state.next)
${CLAUDE_SKILL_DIR}/scripts/progress open M1-S1 --title "CLI framework and Unix socket API server" --next "M1-S2: Session store"

# Log entries during the session
${CLAUDE_SKILL_DIR}/scripts/progress log --type decision --note "Used axum 0.8 with unix socket listener"
${CLAUDE_SKILL_DIR}/scripts/progress log --type discovery --note "Lima vsock CID must be assigned explicitly"
${CLAUDE_SKILL_DIR}/scripts/progress log --type blocker --note "QEMU 8.x changes vsock device naming"

# Block and resume
${CLAUDE_SKILL_DIR}/scripts/progress block --reason "Waiting on rusqlite version decision"
${CLAUDE_SKILL_DIR}/scripts/progress resume

# Manage todos
${CLAUDE_SKILL_DIR}/scripts/progress todo add --text "Set up CI pipeline"
${CLAUDE_SKILL_DIR}/scripts/progress todo add --text "Revisit error handling" --defer
${CLAUDE_SKILL_DIR}/scripts/progress todo list
${CLAUDE_SKILL_DIR}/scripts/progress todo select 3 7
${CLAUDE_SKILL_DIR}/scripts/progress todo complete 3 7
${CLAUDE_SKILL_DIR}/scripts/progress todo defer 4 5
${CLAUDE_SKILL_DIR}/scripts/progress todo drop 8 9

# Check current state (quick orientation after compaction)
${CLAUDE_SKILL_DIR}/scripts/progress status

# Close the session (all selected todos must be resolved first)
${CLAUDE_SKILL_DIR}/scripts/progress close --summary "Implemented CLI with clap, axum HTTP server on Unix socket" --artifacts Session SandboxError

# Review completed sessions
${CLAUDE_SKILL_DIR}/scripts/progress review
${CLAUDE_SKILL_DIR}/scripts/progress review --milestone M1
${CLAUDE_SKILL_DIR}/scripts/progress review --last 3
${CLAUDE_SKILL_DIR}/scripts/progress review --type decision

# JSON output for programmatic use
${CLAUDE_SKILL_DIR}/scripts/progress status --json
${CLAUDE_SKILL_DIR}/scripts/progress review --json
${CLAUDE_SKILL_DIR}/scripts/progress todo list --json
```

See `scripts/progress --help` and `scripts/progress <subcommand> --help` for full usage.

## Subcommand Dispatch

When invoked as `/session-tracking <subcommand> [args]`:

```
The argument is: $ARGUMENTS
```

- If `$ARGUMENTS` is empty or unrecognized: show the protocol overview (print the Two-Phase Protocol section above).
- If `$ARGUMENTS` starts with `open`, `log`, `close`, `status`, `review`, `block`, `resume`, or `todo`: run the corresponding script command. For `open`, look up session titles from the project's plan.
- The agent should determine appropriate values from conversation context (e.g., inferring what to log, what summary to write for close).

## Context Recovery

After context compaction:

1. Run `${CLAUDE_SKILL_DIR}/scripts/progress status` for immediate orientation.
2. If mid-session (status shows active session): run `status --json` to see current_log entries and continue from where you left off.
3. Read the project's plan to recall the full plan structure.
4. Run `${CLAUDE_SKILL_DIR}/scripts/progress review --last 3` to recall recent history if needed.
5. Run `${CLAUDE_SKILL_DIR}/scripts/progress todo list` to see pending work items.
