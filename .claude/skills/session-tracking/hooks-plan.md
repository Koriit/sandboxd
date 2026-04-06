# Session Tracking — Planned Hooks

These hooks are planned but not yet implemented. This document serves as a reference for future implementation.

## PostToolUse — Agent Matcher

**Trigger:** Fires after each `Agent` tool use (when a subagent returns to the orchestrator).

**Purpose:** Remind the orchestrator to check whether a progress log entry is warranted based on what the subagent reported.

**Suggested message:**
> Subagent returned. If significant decisions, discoveries, or blockers emerged, append to current_log in .tasks/progress.json.

**Example config:**
```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Agent",
        "hooks": [
          {
            "type": "intercept",
            "command": "echo 'Subagent returned. If significant decisions, discoveries, or blockers emerged, append to current_log in .tasks/progress.json.'"
          }
        ]
      }
    ]
  }
}
```

## PostCompact

**Trigger:** Fires after context compaction.

**Purpose:** Inject context recovery instructions so the agent can reorient after losing conversation history.

**Suggested message:**
> Context was compacted. Restore orientation: (1) Read .tasks/progress.json for current state and session log, (2) Read docs/implementation-plan.md for the full plan, (3) If current_log has entries, you are mid-session — continue from where the log left off.

**Example config:**
```json
{
  "hooks": {
    "PostCompact": [
      {
        "hooks": [
          {
            "type": "intercept",
            "command": "echo 'Context was compacted. Restore orientation: (1) Read .tasks/progress.json for current state and session log, (2) Read docs/implementation-plan.md for the full plan, (3) If current_log has entries, you are mid-session — continue from where the log left off.'"
          }
        ]
      }
    ]
  }
}
```

## Stop (tentative)

**Trigger:** Fires when Claude finishes responding.

**Purpose:** Check if `current_log` is non-null and warn if the session was not properly closed. Lower priority than the other two hooks.

**Example config:**
```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "intercept",
            "command": "python3 -c \"import yaml; d=yaml.safe_load(open('.tasks/progress.json')); exit(0 if d.get('current_log') is None else 1)\" && echo '' || echo 'Warning: current_log is non-null — session may not have been properly closed. Run /session-end before stopping.'"
          }
        ]
      }
    ]
  }
}
```
