"""Tests for the progress CLI script.

Every test invokes the script as a subprocess, matching how agents use it.
"""

import json
import os

from conftest import read_progress_file, run_progress


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------


def test_init_creates_file(progress_cmd, progress_file):
    result = run_progress(
        progress_cmd, progress_file,
        'init', '--total-sessions', '28',
        '--first-session', 'M0-S1', '--first-title', 'Kickoff',
    )
    assert os.path.exists(progress_file)
    data = read_progress_file(progress_file)
    assert data["current_state"]["total_sessions"] == 28
    assert data["current_state"]["session"] == "M0-S1"
    assert data["current_state"]["milestone"] == "M0"
    assert data["current_state"]["status"] == "not_started"
    assert data["current_state"]["completed_sessions"] == 0
    assert data["current_state"]["next"] == "M0-S1: Kickoff"
    assert data["current_log"] is None
    assert data["log"] == []
    assert data["todos"] == []
    assert "Initialized" in result.stdout


def test_init_refuses_existing_file(progress_cmd, initialized_file):
    result = run_progress(
        progress_cmd, initialized_file,
        'init', '--total-sessions', '10',
        '--first-session', 'M0-S1', '--first-title', 'Again',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "already exists" in result.stderr


def test_init_force_overwrites(progress_cmd, initialized_file):
    run_progress(
        progress_cmd, initialized_file,
        'init', '--total-sessions', '5',
        '--first-session', 'M1-S1', '--first-title', 'Fresh',
        '--force',
    )
    data = read_progress_file(initialized_file)
    assert data["current_state"]["total_sessions"] == 5
    assert data["current_state"]["session"] == "M1-S1"


def test_init_validates_session_id(progress_cmd, progress_file):
    result = run_progress(
        progress_cmd, progress_file,
        'init', '--total-sessions', '10',
        '--first-session', 'bad-id', '--first-title', 'Nope',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "Invalid session ID" in result.stderr


# ---------------------------------------------------------------------------
# Open
# ---------------------------------------------------------------------------


def test_open_starts_session(progress_cmd, initialized_file):
    result = run_progress(
        progress_cmd, initialized_file,
        'open', 'M0-S1', '--title', 'First session',
    )
    data = read_progress_file(initialized_file)
    assert data["current_state"]["status"] == "in_progress"
    assert data["current_state"]["session"] == "M0-S1"
    assert data["current_state"]["milestone"] == "M0"
    assert data["current_log"] is not None
    assert data["current_log"]["session"] == "M0-S1"
    assert data["current_log"]["title"] == "First session"
    assert data["current_log"]["entries"] == []
    assert "started" in data["current_log"]
    assert "Opened" in result.stdout


def test_open_refuses_when_session_active(progress_cmd, open_session_file):
    result = run_progress(
        progress_cmd, open_session_file,
        'open', 'M0-S2', '--title', 'Another',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "still open" in result.stderr


def test_open_shows_deferred_todos(progress_cmd, initialized_file):
    # First open and add a deferred todo, then close
    run_progress(progress_cmd, initialized_file, 'open', 'M0-S1', '--title', 'S1')
    run_progress(progress_cmd, initialized_file, 'todo', 'add', '--text', 'Fix later', '--defer')
    run_progress(
        progress_cmd, initialized_file,
        'close', '--summary', 'Done',
    )

    # Open the next session -- deferred todos should be displayed
    result = run_progress(progress_cmd, initialized_file, 'open', 'M0-S2', '--title', 'S2')
    assert "Deferred todos" in result.stdout
    assert "Fix later" in result.stdout


def test_open_with_next(progress_cmd, initialized_file):
    run_progress(
        progress_cmd, initialized_file,
        'open', 'M0-S1', '--title', 'First',
        '--next', 'M0-S2: Second session',
    )
    data = read_progress_file(initialized_file)
    assert data["current_state"]["next"] == "M0-S2: Second session"


def test_open_validates_session_id(progress_cmd, initialized_file):
    result = run_progress(
        progress_cmd, initialized_file,
        'open', 'invalid', '--title', 'Nope',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "Invalid session ID" in result.stderr


# ---------------------------------------------------------------------------
# Log
# ---------------------------------------------------------------------------


def test_log_appends_entry(progress_cmd, open_session_file):
    run_progress(
        progress_cmd, open_session_file,
        'log', '--type', 'decision', '--note', 'Use stdlib only',
    )
    data = read_progress_file(open_session_file)
    entries = data["current_log"]["entries"]
    assert len(entries) == 1
    assert entries[0]["type"] == "decision"
    assert entries[0]["note"] == "Use stdlib only"


def test_log_all_types(progress_cmd, open_session_file):
    for entry_type in ("decision", "discovery", "blocker", "note"):
        run_progress(
            progress_cmd, open_session_file,
            'log', '--type', entry_type, '--note', f'A {entry_type}',
        )
    data = read_progress_file(open_session_file)
    entries = data["current_log"]["entries"]
    assert len(entries) == 4
    types = [e["type"] for e in entries]
    assert types == ["decision", "discovery", "blocker", "note"]


def test_log_refuses_without_session(progress_cmd, initialized_file):
    result = run_progress(
        progress_cmd, initialized_file,
        'log', '--type', 'note', '--note', 'Orphan',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "No active session" in result.stderr


def test_log_timestamps_are_utc(progress_cmd, open_session_file):
    run_progress(
        progress_cmd, open_session_file,
        'log', '--type', 'note', '--note', 'Check time',
    )
    data = read_progress_file(open_session_file)
    ts = data["current_log"]["entries"][0]["timestamp"]
    assert ts.endswith("Z"), f"Timestamp should end with Z, got: {ts}"


# ---------------------------------------------------------------------------
# Close
# ---------------------------------------------------------------------------


def test_close_creates_log_entry(progress_cmd, open_session_file):
    run_progress(
        progress_cmd, open_session_file,
        'log', '--type', 'decision', '--note', 'Chose approach A',
    )
    run_progress(
        progress_cmd, open_session_file,
        'close', '--summary', 'Finished first session',
    )
    data = read_progress_file(open_session_file)
    assert len(data["log"]) == 1
    entry = data["log"][0]
    assert entry["session"] == "M0-S1"
    assert entry["title"] == "Test session"
    assert entry["summary"] == "Finished first session"
    assert "completed" in entry
    assert entry["decisions"] == ["Chose approach A"]


def test_close_clears_current_log(progress_cmd, open_session_file):
    run_progress(
        progress_cmd, open_session_file,
        'close', '--summary', 'Done',
    )
    data = read_progress_file(open_session_file)
    assert data["current_log"] is None


def test_close_sets_completed(progress_cmd, open_session_file):
    run_progress(
        progress_cmd, open_session_file,
        'close', '--summary', 'Done',
    )
    data = read_progress_file(open_session_file)
    assert data["current_state"]["status"] == "completed"


def test_close_collects_decisions(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'log', '--type', 'decision', '--note', 'D1')
    run_progress(progress_cmd, open_session_file, 'log', '--type', 'decision', '--note', 'D2')
    run_progress(progress_cmd, open_session_file, 'close', '--summary', 'Done')
    data = read_progress_file(open_session_file)
    assert data["log"][0]["decisions"] == ["D1", "D2"]


def test_close_collects_discoveries(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'log', '--type', 'discovery', '--note', 'Found X')
    run_progress(progress_cmd, open_session_file, 'close', '--summary', 'Done')
    data = read_progress_file(open_session_file)
    assert data["log"][0]["discoveries"] == ["Found X"]


def test_close_collects_blockers(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'log', '--type', 'blocker', '--note', 'Blocked by Y')
    # The session becomes blocked when we log a blocker via `block` command,
    # but logging a blocker entry via `log` does NOT change session status.
    run_progress(progress_cmd, open_session_file, 'close', '--summary', 'Done')
    data = read_progress_file(open_session_file)
    assert data["log"][0]["blockers"] == ["Blocked by Y"]


def test_close_omits_empty_optional_fields(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'close', '--summary', 'Done')
    data = read_progress_file(open_session_file)
    entry = data["log"][0]
    # decisions is always present (required in schema), but discoveries/blockers
    # should be omitted when empty
    assert "discoveries" not in entry
    assert "blockers" not in entry
    assert "artifacts" not in entry


def test_close_extra_decisions(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'log', '--type', 'decision', '--note', 'Logged D')
    run_progress(
        progress_cmd, open_session_file,
        'close', '--summary', 'Done',
        '--extra-decisions', 'Extra D1', 'Extra D2',
    )
    data = read_progress_file(open_session_file)
    assert data["log"][0]["decisions"] == ["Logged D", "Extra D1", "Extra D2"]


def test_close_refuses_without_session(progress_cmd, initialized_file):
    result = run_progress(
        progress_cmd, initialized_file,
        'close', '--summary', 'Nope',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "No active session" in result.stderr


def test_close_refuses_blocked_session(progress_cmd, open_session_file):
    run_progress(
        progress_cmd, open_session_file,
        'block', '--reason', 'Stuck',
    )
    result = run_progress(
        progress_cmd, open_session_file,
        'close', '--summary', 'Nope',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "blocked" in result.stderr.lower()


def test_close_refuses_unresolved_todos(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'Must do this')
    result = run_progress(
        progress_cmd, open_session_file,
        'close', '--summary', 'Nope',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "selected todos unresolved" in result.stderr


def test_close_increments_completed_sessions(progress_cmd, open_session_file):
    data_before = read_progress_file(open_session_file)
    assert data_before["current_state"]["completed_sessions"] == 0

    run_progress(progress_cmd, open_session_file, 'close', '--summary', 'Done')

    data_after = read_progress_file(open_session_file)
    assert data_after["current_state"]["completed_sessions"] == 1


def test_close_notes_are_dropped(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'log', '--type', 'note', '--note', 'Ephemeral')
    run_progress(progress_cmd, open_session_file, 'log', '--type', 'decision', '--note', 'Kept')
    run_progress(progress_cmd, open_session_file, 'close', '--summary', 'Done')
    data = read_progress_file(open_session_file)
    entry = data["log"][0]
    # Notes are not carried into the permanent log
    assert entry["decisions"] == ["Kept"]
    # No field should contain the note text
    all_values = json.dumps(entry)
    assert "Ephemeral" not in all_values


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def test_status_human_readable(progress_cmd, initialized_file):
    result = run_progress(progress_cmd, initialized_file, 'status')
    assert "Milestone:" in result.stdout
    assert "Session:" in result.stdout
    assert "Status:" in result.stdout
    assert "Progress:" in result.stdout


def test_status_json(progress_cmd, initialized_file):
    result = run_progress(progress_cmd, initialized_file, 'status', '--json')
    data = json.loads(result.stdout)
    assert "current_state" in data
    assert "current_log" in data
    assert "todos_summary" in data


def test_status_no_active_session(progress_cmd, initialized_file):
    result = run_progress(progress_cmd, initialized_file, 'status')
    assert "No active session" in result.stdout


def test_status_with_active_session(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'log', '--type', 'decision', '--note', 'D1')
    run_progress(progress_cmd, open_session_file, 'log', '--type', 'note', '--note', 'N1')
    result = run_progress(progress_cmd, open_session_file, 'status')
    assert "Active session" in result.stdout
    assert "Entries: 2" in result.stdout


def test_status_shows_todo_counts(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'T1')
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'T2', '--defer')
    result = run_progress(progress_cmd, open_session_file, 'status')
    assert "Todos:" in result.stdout
    assert "selected" in result.stdout
    assert "deferred" in result.stdout


# ---------------------------------------------------------------------------
# Review
# ---------------------------------------------------------------------------


def _close_session(progress_cmd, file_path, session_id, title, summary,
                   decisions=None, discoveries=None):
    """Helper: open a session, log some entries, then close it."""
    run_progress(progress_cmd, file_path, 'open', session_id, '--title', title)
    if decisions:
        for d in decisions:
            run_progress(progress_cmd, file_path, 'log', '--type', 'decision', '--note', d)
    if discoveries:
        for d in discoveries:
            run_progress(progress_cmd, file_path, 'log', '--type', 'discovery', '--note', d)
    run_progress(progress_cmd, file_path, 'close', '--summary', summary)


def test_review_empty_log(progress_cmd, initialized_file):
    result = run_progress(progress_cmd, initialized_file, 'review')
    assert "No log entries" in result.stdout


def test_review_shows_all_entries(progress_cmd, initialized_file):
    _close_session(progress_cmd, initialized_file, 'M0-S1', 'First', 'Summary 1',
                   decisions=['D1'])
    result = run_progress(progress_cmd, initialized_file, 'review')
    assert "M0-S1" in result.stdout
    assert "First" in result.stdout
    assert "Summary 1" in result.stdout
    assert "D1" in result.stdout


def test_review_milestone_filter(progress_cmd, initialized_file):
    _close_session(progress_cmd, initialized_file, 'M0-S1', 'S1', 'Done 1',
                   decisions=['D1'])
    _close_session(progress_cmd, initialized_file, 'M1-S1', 'S2', 'Done 2',
                   decisions=['D2'])
    result = run_progress(progress_cmd, initialized_file, 'review', '--milestone', 'M1')
    assert "M1-S1" in result.stdout
    assert "M0-S1" not in result.stdout


def test_review_milestone_no_prefix_collision(progress_cmd, initialized_file):
    """M1 filter should not match M10-S1."""
    _close_session(progress_cmd, initialized_file, 'M0-S1', 'Zero', 'Done',
                   decisions=['D0'])
    _close_session(progress_cmd, initialized_file, 'M1-S1', 'One', 'Done',
                   decisions=['D1'])
    _close_session(progress_cmd, initialized_file, 'M10-S1', 'Ten', 'Done',
                   decisions=['D10'])

    result = run_progress(progress_cmd, initialized_file, 'review', '--milestone', 'M1')
    assert "M1-S1" in result.stdout
    assert "M10-S1" not in result.stdout


def test_review_session_filter(progress_cmd, initialized_file):
    _close_session(progress_cmd, initialized_file, 'M0-S1', 'S1', 'Done 1',
                   decisions=['D1'])
    _close_session(progress_cmd, initialized_file, 'M0-S2', 'S2', 'Done 2',
                   decisions=['D2'])
    result = run_progress(progress_cmd, initialized_file, 'review', '--session', 'M0-S2')
    assert "M0-S2" in result.stdout
    assert "M0-S1" not in result.stdout


def test_review_last_n(progress_cmd, initialized_file):
    _close_session(progress_cmd, initialized_file, 'M0-S1', 'S1', 'Done 1',
                   decisions=['D1'])
    _close_session(progress_cmd, initialized_file, 'M0-S2', 'S2', 'Done 2',
                   decisions=['D2'])
    _close_session(progress_cmd, initialized_file, 'M0-S3', 'S3', 'Done 3',
                   decisions=['D3'])
    result = run_progress(progress_cmd, initialized_file, 'review', '--last', '1')
    assert "M0-S3" in result.stdout
    assert "M0-S1" not in result.stdout
    assert "M0-S2" not in result.stdout


def test_review_type_filter(progress_cmd, initialized_file):
    _close_session(progress_cmd, initialized_file, 'M0-S1', 'S1', 'Done 1',
                   decisions=['D1'])
    _close_session(progress_cmd, initialized_file, 'M0-S2', 'S2', 'Done 2',
                   discoveries=['Disc1'])
    result = run_progress(progress_cmd, initialized_file, 'review', '--type', 'discovery')
    # Only M0-S2 has discoveries
    assert "M0-S2" in result.stdout
    assert "M0-S1" not in result.stdout


def test_review_type_then_last(progress_cmd, initialized_file):
    """--type is applied before --last, so --last N --type X gives the last N
    sessions that have items of type X."""
    _close_session(progress_cmd, initialized_file, 'M0-S1', 'S1', 'Done',
                   decisions=['D1'])
    _close_session(progress_cmd, initialized_file, 'M0-S2', 'S2', 'Done',
                   decisions=['D2'])
    _close_session(progress_cmd, initialized_file, 'M0-S3', 'S3', 'Done',
                   decisions=['D3'])
    result = run_progress(
        progress_cmd, initialized_file,
        'review', '--type', 'decision', '--last', '1',
    )
    assert "M0-S3" in result.stdout
    assert "M0-S1" not in result.stdout
    assert "M0-S2" not in result.stdout


def test_review_json(progress_cmd, initialized_file):
    _close_session(progress_cmd, initialized_file, 'M0-S1', 'S1', 'Done',
                   decisions=['D1'])
    result = run_progress(progress_cmd, initialized_file, 'review', '--json')
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["session"] == "M0-S1"


# ---------------------------------------------------------------------------
# Block / Resume
# ---------------------------------------------------------------------------


def test_block_sets_status(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'block', '--reason', 'Need info')
    data = read_progress_file(open_session_file)
    assert data["current_state"]["status"] == "blocked"


def test_block_logs_blocker_entry(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'block', '--reason', 'Stuck on X')
    data = read_progress_file(open_session_file)
    entries = data["current_log"]["entries"]
    assert len(entries) == 1
    assert entries[0]["type"] == "blocker"
    assert entries[0]["note"] == "Stuck on X"


def test_block_refuses_without_session(progress_cmd, initialized_file):
    result = run_progress(
        progress_cmd, initialized_file,
        'block', '--reason', 'No session',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "No active session" in result.stderr


def test_block_refuses_if_already_blocked(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'block', '--reason', 'First')
    result = run_progress(
        progress_cmd, open_session_file,
        'block', '--reason', 'Second',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "not in_progress" in result.stderr


def test_resume_sets_status(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'block', '--reason', 'Stuck')
    run_progress(progress_cmd, open_session_file, 'resume')
    data = read_progress_file(open_session_file)
    assert data["current_state"]["status"] == "in_progress"


def test_resume_refuses_if_not_blocked(progress_cmd, open_session_file):
    result = run_progress(
        progress_cmd, open_session_file,
        'resume',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "not blocked" in result.stderr


# ---------------------------------------------------------------------------
# Todo - Add
# ---------------------------------------------------------------------------


def test_todo_add_selected(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'Do something')
    data = read_progress_file(open_session_file)
    assert len(data["todos"]) == 1
    todo = data["todos"][0]
    assert todo["text"] == "Do something"
    assert todo["status"] == "selected"
    assert todo["added_session"] == "M0-S1"
    assert "selected_session" in todo


def test_todo_add_deferred(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'Later', '--defer')
    data = read_progress_file(open_session_file)
    todo = data["todos"][0]
    assert todo["status"] == "deferred"
    assert "selected_session" not in todo


def test_todo_add_no_session_deferred(progress_cmd, initialized_file):
    """Adding a todo without an open session auto-defers it."""
    run_progress(progress_cmd, initialized_file, 'todo', 'add', '--text', 'Auto-deferred')
    data = read_progress_file(initialized_file)
    todo = data["todos"][0]
    assert todo["status"] == "deferred"


def test_todo_add_increments_id(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'First')
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'Second')
    data = read_progress_file(open_session_file)
    assert data["todos"][0]["id"] == 1
    assert data["todos"][1]["id"] == 2


# ---------------------------------------------------------------------------
# Todo - List
# ---------------------------------------------------------------------------


def test_todo_list_all(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'T1')
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'T2', '--defer')
    result = run_progress(progress_cmd, open_session_file, 'todo', 'list')
    assert "T1" in result.stdout
    assert "T2" in result.stdout


def test_todo_list_by_status(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'Selected one')
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'Deferred one', '--defer')
    result = run_progress(
        progress_cmd, open_session_file, 'todo', 'list', '--status', 'deferred',
    )
    assert "Deferred one" in result.stdout
    assert "Selected one" not in result.stdout


def test_todo_list_empty(progress_cmd, initialized_file):
    result = run_progress(progress_cmd, initialized_file, 'todo', 'list')
    assert "No todos" in result.stdout


def test_todo_list_json(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'JSON test')
    result = run_progress(progress_cmd, open_session_file, 'todo', 'list', '--json')
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["text"] == "JSON test"


# ---------------------------------------------------------------------------
# Todo - Select
# ---------------------------------------------------------------------------


def test_todo_select_deferred(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'Pick me', '--defer')
    run_progress(progress_cmd, open_session_file, 'todo', 'select', '1')
    data = read_progress_file(open_session_file)
    todo = data["todos"][0]
    assert todo["status"] == "selected"
    assert todo["selected_session"] == "M0-S1"


def test_todo_select_invalid_id(progress_cmd, open_session_file):
    result = run_progress(
        progress_cmd, open_session_file, 'todo', 'select', '999',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "not found" in result.stderr


def test_todo_select_wrong_status(progress_cmd, open_session_file):
    # Add as selected (not deferred)
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'Already selected')
    result = run_progress(
        progress_cmd, open_session_file, 'todo', 'select', '1',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "not deferred" in result.stderr


def test_todo_select_requires_session(progress_cmd, initialized_file):
    # Add a todo without a session (auto-deferred)
    run_progress(progress_cmd, initialized_file, 'todo', 'add', '--text', 'Orphan')
    result = run_progress(
        progress_cmd, initialized_file, 'todo', 'select', '1',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "No active session" in result.stderr


def test_todo_select_multiple(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'A', '--defer')
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'B', '--defer')
    run_progress(progress_cmd, open_session_file, 'todo', 'select', '1', '2')
    data = read_progress_file(open_session_file)
    assert data["todos"][0]["status"] == "selected"
    assert data["todos"][1]["status"] == "selected"


# ---------------------------------------------------------------------------
# Todo - Complete
# ---------------------------------------------------------------------------


def test_todo_complete(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'Finish me')
    run_progress(progress_cmd, open_session_file, 'todo', 'complete', '1')
    data = read_progress_file(open_session_file)
    todo = data["todos"][0]
    assert todo["status"] == "completed"
    assert "resolved_session" in todo
    assert "resolved_timestamp" in todo


def test_todo_complete_wrong_status(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'X', '--defer')
    result = run_progress(
        progress_cmd, open_session_file, 'todo', 'complete', '1',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "not selected" in result.stderr


def test_todo_complete_multiple(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'A')
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'B')
    run_progress(progress_cmd, open_session_file, 'todo', 'complete', '1', '2')
    data = read_progress_file(open_session_file)
    assert data["todos"][0]["status"] == "completed"
    assert data["todos"][1]["status"] == "completed"
    assert "resolved_session" in data["todos"][0]
    assert "resolved_session" in data["todos"][1]


# ---------------------------------------------------------------------------
# Todo - Defer
# ---------------------------------------------------------------------------


def test_todo_defer(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'Push back')
    run_progress(progress_cmd, open_session_file, 'todo', 'defer', '1')
    data = read_progress_file(open_session_file)
    todo = data["todos"][0]
    assert todo["status"] == "deferred"
    assert "selected_session" not in todo


def test_todo_defer_wrong_status(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'X', '--defer')
    result = run_progress(
        progress_cmd, open_session_file, 'todo', 'defer', '1',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "not selected" in result.stderr


def test_todo_defer_multiple(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'A')
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'B')
    run_progress(progress_cmd, open_session_file, 'todo', 'defer', '1', '2')
    data = read_progress_file(open_session_file)
    assert data["todos"][0]["status"] == "deferred"
    assert data["todos"][1]["status"] == "deferred"
    assert "selected_session" not in data["todos"][0]
    assert "selected_session" not in data["todos"][1]


# ---------------------------------------------------------------------------
# Todo - Drop
# ---------------------------------------------------------------------------


def test_todo_drop_selected(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'Nope')
    run_progress(progress_cmd, open_session_file, 'todo', 'drop', '1')
    data = read_progress_file(open_session_file)
    todo = data["todos"][0]
    assert todo["status"] == "dropped"
    assert "resolved_session" in todo
    assert "resolved_timestamp" in todo


def test_todo_drop_deferred(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'Nah', '--defer')
    run_progress(progress_cmd, open_session_file, 'todo', 'drop', '1')
    data = read_progress_file(open_session_file)
    assert data["todos"][0]["status"] == "dropped"


def test_todo_drop_wrong_status(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'Done')
    run_progress(progress_cmd, open_session_file, 'todo', 'complete', '1')
    result = run_progress(
        progress_cmd, open_session_file, 'todo', 'drop', '1',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "cannot be dropped" in result.stderr


def test_todo_drop_multiple(progress_cmd, open_session_file):
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'A')
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'B', '--defer')
    run_progress(progress_cmd, open_session_file, 'todo', 'drop', '1', '2')
    data = read_progress_file(open_session_file)
    assert data["todos"][0]["status"] == "dropped"
    assert data["todos"][1]["status"] == "dropped"
    assert "resolved_session" in data["todos"][0]
    assert "resolved_session" in data["todos"][1]


def test_todo_batch_partial_failure(progress_cmd, open_session_file):
    """One invalid ID in a batch doesn't prevent others from succeeding."""
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'A')
    run_progress(progress_cmd, open_session_file, 'todo', 'add', '--text', 'B')
    # Complete todo 1 and nonexistent todo 999 in one call
    result = run_progress(
        progress_cmd, open_session_file, 'todo', 'complete', '1', '999', '2',
        expect_error=True,
    )
    assert result.returncode != 0
    assert "not found" in result.stderr
    # Valid todos should still have been processed
    assert "Completed todo #1" in result.stdout
    assert "Completed todo #2" in result.stdout
    data = read_progress_file(open_session_file)
    assert data["todos"][0]["status"] == "completed"
    assert data["todos"][1]["status"] == "completed"


# ---------------------------------------------------------------------------
# Integration / Lifecycle
# ---------------------------------------------------------------------------


def test_full_lifecycle(progress_cmd, progress_file):
    """init -> open -> log -> todo add -> close -> open next -> verify"""
    # Init
    run_progress(
        progress_cmd, progress_file,
        'init', '--total-sessions', '10',
        '--first-session', 'M0-S1', '--first-title', 'Setup',
    )

    # Open
    run_progress(progress_cmd, progress_file, 'open', 'M0-S1', '--title', 'Setup')

    # Log
    run_progress(progress_cmd, progress_file, 'log', '--type', 'decision', '--note', 'Use Python')
    run_progress(progress_cmd, progress_file, 'log', '--type', 'discovery', '--note', 'Found lib X')
    run_progress(progress_cmd, progress_file, 'log', '--type', 'note', '--note', 'Ephemeral note')

    # Todo add + complete
    run_progress(progress_cmd, progress_file, 'todo', 'add', '--text', 'Write tests')
    run_progress(progress_cmd, progress_file, 'todo', 'complete', '1')

    # Close
    run_progress(progress_cmd, progress_file, 'close', '--summary', 'Initial setup complete')

    data = read_progress_file(progress_file)
    assert data["current_state"]["completed_sessions"] == 1
    assert data["current_state"]["status"] == "completed"
    assert len(data["log"]) == 1
    assert data["log"][0]["decisions"] == ["Use Python"]
    assert data["log"][0]["discoveries"] == ["Found lib X"]
    # Note should be dropped
    all_text = json.dumps(data["log"][0])
    assert "Ephemeral note" not in all_text

    # Open next session
    run_progress(progress_cmd, progress_file, 'open', 'M0-S2', '--title', 'Implementation')
    data = read_progress_file(progress_file)
    assert data["current_state"]["session"] == "M0-S2"
    assert data["current_state"]["status"] == "in_progress"
    assert data["current_log"]["session"] == "M0-S2"


def test_multi_session_lifecycle(progress_cmd, progress_file):
    """Complete 3 sessions and verify the log grows correctly."""
    run_progress(
        progress_cmd, progress_file,
        'init', '--total-sessions', '10',
        '--first-session', 'M0-S1', '--first-title', 'S1',
    )

    for i, sid in enumerate(["M0-S1", "M0-S2", "M0-S3"], start=1):
        run_progress(progress_cmd, progress_file, 'open', sid, '--title', f'Session {i}')
        run_progress(progress_cmd, progress_file, 'log', '--type', 'decision', '--note', f'D{i}')
        run_progress(progress_cmd, progress_file, 'close', '--summary', f'Done {i}')

    data = read_progress_file(progress_file)
    assert len(data["log"]) == 3
    assert data["current_state"]["completed_sessions"] == 3
    sessions = [e["session"] for e in data["log"]]
    assert sessions == ["M0-S1", "M0-S2", "M0-S3"]


def test_todo_across_sessions(progress_cmd, progress_file):
    """Add todo, defer, select in next session, complete."""
    run_progress(
        progress_cmd, progress_file,
        'init', '--total-sessions', '10',
        '--first-session', 'M0-S1', '--first-title', 'S1',
    )

    # Session 1: add todo as deferred
    run_progress(progress_cmd, progress_file, 'open', 'M0-S1', '--title', 'First')
    run_progress(progress_cmd, progress_file, 'todo', 'add', '--text', 'Cross-session task', '--defer')
    run_progress(progress_cmd, progress_file, 'close', '--summary', 'Done 1')

    data = read_progress_file(progress_file)
    assert data["todos"][0]["status"] == "deferred"

    # Session 2: select and complete the todo
    run_progress(progress_cmd, progress_file, 'open', 'M0-S2', '--title', 'Second')
    run_progress(progress_cmd, progress_file, 'todo', 'select', '1')
    run_progress(progress_cmd, progress_file, 'todo', 'complete', '1')
    run_progress(progress_cmd, progress_file, 'close', '--summary', 'Done 2')

    data = read_progress_file(progress_file)
    todo = data["todos"][0]
    assert todo["status"] == "completed"
    assert todo["selected_session"] == "M0-S2"
    assert todo["resolved_session"] == "M0-S2"


def test_block_resume_close(progress_cmd, open_session_file):
    """block -> resume -> close works."""
    run_progress(progress_cmd, open_session_file, 'block', '--reason', 'Need clarification')

    data = read_progress_file(open_session_file)
    assert data["current_state"]["status"] == "blocked"

    run_progress(progress_cmd, open_session_file, 'resume')

    data = read_progress_file(open_session_file)
    assert data["current_state"]["status"] == "in_progress"

    run_progress(progress_cmd, open_session_file, 'close', '--summary', 'Unblocked and done')

    data = read_progress_file(open_session_file)
    assert data["current_state"]["status"] == "completed"
    assert data["current_log"] is None
    # The blocker entry from block should be in the permanent log
    assert "Need clarification" in data["log"][0]["blockers"]
