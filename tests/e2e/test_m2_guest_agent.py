"""E2E tests for M2 guest agent: exec, ssh, and health checks.

These tests boot real Lima/QEMU VMs and are SLOW (1-5 minutes per test).
Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_m2_guest_agent.py -v --timeout=600
"""

from __future__ import annotations

import pytest

from conftest import (
    _VM_RESOURCE_ARGS,
    parse_session_id,
    wait_for_state,
)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(600)
def test_guest_agent_health_check(sandbox_cli):
    """Create a session and verify guest agent status shows 'connected' in ps."""
    session_id = None
    try:
        # Create a session.
        result = sandbox_cli(
            "create", "--name", "health-test", *_VM_RESOURCE_ARGS, timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

        session_id = parse_session_id(result.stdout)

        # Verify it's running.
        wait_for_state(sandbox_cli, "health-test", "Running", timeout=10)

        # Check that `sandbox ps` shows "connected" in the AGENT column.
        ps_result = sandbox_cli("ps")
        assert ps_result.returncode == 0
        # Find the line for our session.
        found = False
        for line in ps_result.stdout.splitlines():
            if "health-test" in line:
                assert "connected" in line, (
                    f"Expected 'connected' in ps output for health-test, "
                    f"got line: {line}"
                )
                found = True
                break
        assert found, (
            f"Session health-test not found in ps output:\n{ps_result.stdout}"
        )

        # Clean up.
        sandbox_cli("rm", "health-test", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "health-test", timeout=120)


@pytest.mark.timeout(600)
def test_guest_agent_exec(sandbox_cli, sandbox_daemon):
    """Create a session, exec 'uname -a' via the daemon exec endpoint, verify output."""
    session_id = None
    try:
        # Create a session.
        result = sandbox_cli(
            "create", "--name", "exec-test", *_VM_RESOURCE_ARGS, timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "exec-test", "Running", timeout=10)

        # Use `sandbox exec` to run uname -a inside the VM.
        exec_result = sandbox_cli("exec", "exec-test", "--", "uname", "-a", timeout=120)
        assert exec_result.returncode == 0, (
            f"sandbox exec failed (rc={exec_result.returncode}).\n"
            f"stdout: {exec_result.stdout}\nstderr: {exec_result.stderr}"
        )
        assert "Linux" in exec_result.stdout, (
            f"Expected 'Linux' in uname output, got: {exec_result.stdout}"
        )

        # Also test a command that returns non-zero exit code.
        fail_result = sandbox_cli(
            "exec", "exec-test", "--", "false", timeout=120,
        )
        assert fail_result.returncode != 0, (
            "Expected non-zero exit code from 'false' command"
        )

        # Clean up.
        sandbox_cli("rm", "exec-test", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "exec-test", timeout=120)


@pytest.mark.timeout(600)
def test_ssh_session(sandbox_cli):
    """Create a session, run a non-interactive command via `sandbox ssh`, verify output."""
    session_id = None
    try:
        # Create a session.
        result = sandbox_cli(
            "create", "--name", "ssh-test", *_VM_RESOURCE_ARGS, timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ssh-test", "Running", timeout=10)

        # Run `sandbox ssh ssh-test -- uname -a` (non-interactive with command).
        ssh_result = sandbox_cli("ssh", "ssh-test", "--", "uname", "-a", timeout=120)
        assert ssh_result.returncode == 0, (
            f"sandbox ssh failed (rc={ssh_result.returncode}).\n"
            f"stdout: {ssh_result.stdout}\nstderr: {ssh_result.stderr}"
        )
        assert "Linux" in ssh_result.stdout, (
            f"Expected 'Linux' in ssh uname output, got: {ssh_result.stdout}"
        )

        # Clean up.
        sandbox_cli("rm", "ssh-test", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ssh-test", timeout=120)


@pytest.mark.timeout(600)
def test_exec_on_stopped_session(sandbox_cli):
    """Verify that exec fails gracefully on a stopped session."""
    session_id = None
    try:
        # Create and then stop a session.
        result = sandbox_cli(
            "create", "--name", "stop-exec-test", *_VM_RESOURCE_ARGS, timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "stop-exec-test", "Running", timeout=10)

        # Stop the session.
        stop_result = sandbox_cli("stop", "stop-exec-test", timeout=120)
        assert stop_result.returncode == 0, (
            f"sandbox stop failed (rc={stop_result.returncode}).\n"
            f"stdout: {stop_result.stdout}\nstderr: {stop_result.stderr}"
        )
        wait_for_state(sandbox_cli, "stop-exec-test", "Stopped", timeout=30)

        # Try exec on stopped session -- should fail with an error.
        exec_result = sandbox_cli(
            "exec", "stop-exec-test", "--", "echo", "hello", timeout=120,
        )
        assert exec_result.returncode != 0, (
            "Expected non-zero exit code when exec on stopped session"
        )
        assert "must be running" in exec_result.stderr.lower() or "invalid" in exec_result.stderr.lower(), (
            f"Expected error about invalid state, got stderr: {exec_result.stderr}"
        )

        # Clean up.
        sandbox_cli("rm", "stop-exec-test", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "stop-exec-test", timeout=120)
