import json
import os
import subprocess

import pytest


def run_progress(cmd_path, file_path, *args, expect_error=False):
    """Run the progress script and return the CompletedProcess result.

    By default asserts a zero exit code. Pass expect_error=True to allow
    non-zero exits (e.g. when testing error paths).
    """
    result = subprocess.run(
        [cmd_path, *args, '--file', file_path],
        capture_output=True, text=True,
    )
    if not expect_error:
        assert result.returncode == 0, (
            f"Command failed (rc={result.returncode}):\n"
            f"  args: {args}\n"
            f"  stderr: {result.stderr}"
        )
    return result


def read_progress_file(file_path):
    """Read and parse a progress JSON file."""
    with open(file_path) as f:
        return json.load(f)


@pytest.fixture
def progress_cmd():
    """Return the absolute path to the progress script."""
    return os.path.join(os.path.dirname(__file__), '..', 'progress')


@pytest.fixture
def progress_file(tmp_path):
    """Return a temporary file path for an isolated progress.json."""
    return str(tmp_path / "progress.json")


@pytest.fixture
def initialized_file(progress_cmd, progress_file):
    """Return a progress file that has been initialized."""
    subprocess.run([
        progress_cmd, 'init', '--file', progress_file,
        '--total-sessions', '28', '--first-session', 'M0-S1',
        '--first-title', 'Test session',
    ], check=True)
    return progress_file


@pytest.fixture
def open_session_file(progress_cmd, initialized_file):
    """Return a progress file with an open session (M0-S1)."""
    subprocess.run([
        progress_cmd, 'open', '--file', initialized_file,
        'M0-S1', '--title', 'Test session',
    ], check=True)
    return initialized_file
