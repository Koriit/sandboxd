"""Shared fixtures for sandbox E2E tests."""

import subprocess
import pytest


# Path to the sandbox CLI binary (built via `cargo build --workspace`)
SANDBOX_BIN = "../../sandboxd/target/debug/sandbox"


@pytest.fixture
def sandbox_cli():
    """Return a helper that invokes the sandbox CLI binary."""

    def run(*args: str, check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
        return subprocess.run(
            [SANDBOX_BIN, *args],
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
        )

    return run


@pytest.fixture
def create_session(sandbox_cli):
    """Create a sandbox session and ensure it is destroyed after the test.

    Yields the session ID. Cleanup runs even if the test fails.
    """
    sessions_to_clean: list[str] = []

    def _create(*extra_args: str) -> str:
        result = sandbox_cli("create", *extra_args)
        session_id = result.stdout.strip()
        sessions_to_clean.append(session_id)
        return session_id

    yield _create

    # Cleanup: best-effort destroy of all sessions created during the test
    for sid in sessions_to_clean:
        try:
            sandbox_cli("rm", "--force", sid, check=False, timeout=60)
        except Exception:
            pass
