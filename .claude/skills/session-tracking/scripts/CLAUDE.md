# Session Tracking Scripts - Development Guide

## Runtime vs Development

The `progress` script uses **only Python stdlib** -- no pip packages, no venv needed to run it. Any Python 3.10+ installation can execute it directly.

The **test suite** is a development-only concern. It requires a virtual environment with pytest and pytest-cov installed. These dependencies are never needed at runtime.

## Setup

Create the dev venv and install dependencies:

```bash
cd .claude/skills/session-tracking/scripts
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

The venv is gitignored and should never be committed.

## Running Tests

```bash
# Run all tests
.venv/bin/pytest

# Verbose output
.venv/bin/pytest -v

# Run a specific test
.venv/bin/pytest tests/test_progress.py::test_init_creates_file
```

## Coverage

```bash
# Coverage with missing-line report
.venv/bin/pytest --cov --cov-report=term-missing

# Generate HTML coverage report
.venv/bin/pytest --cov --cov-report=html
```

## Adding Tests

- All tests live in `tests/test_progress.py`.
- Shared fixtures are in `tests/conftest.py`.
- Tests invoke the `progress` script as a **subprocess** (not as an import). This mirrors how agents use the script in practice.
- Use the `progress_cmd` fixture for the script path, `progress_file` for an isolated temp file, and the higher-level `initialized_file` / `open_session_file` fixtures for common starting states.
- Helper functions `run_progress()` and `read_progress_file()` in `conftest.py` reduce boilerplate.
