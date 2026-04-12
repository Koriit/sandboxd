"""E2E tests for M1 VM lifecycle: create, stop, start, destroy.

These tests boot real Lima/QEMU VMs and are SLOW (1-5 minutes per test).
Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_m1_vm_lifecycle.py -v --timeout=600
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Regex to extract the session ID (UUID) from `sandbox create` output.
# The CLI prints lines like:  ID:       <uuid>
_ID_RE = re.compile(r"^ID:\s+([0-9a-f-]{36})$", re.MULTILINE)


def parse_session_id(create_output: str) -> str:
    """Extract the session UUID from `sandbox create` stdout."""
    m = _ID_RE.search(create_output)
    if not m:
        raise ValueError(
            f"Could not parse session ID from create output:\n{create_output}"
        )
    return m.group(1)


def lima_vm_name(session_id: str) -> str:
    """Return the Lima VM name for a given session ID."""
    return f"sandbox-{session_id}"


def wait_for_state(
    sandbox_cli,
    name: str,
    expected_state: str,
    timeout: int = 30,
    interval: float = 2.0,
) -> str:
    """Poll `sandbox ps` until the named session reaches the expected state.

    Returns the full ps output on success.  Raises AssertionError on timeout.
    """
    deadline = time.monotonic() + timeout
    last_output = ""
    while time.monotonic() < deadline:
        result = sandbox_cli("ps")
        last_output = result.stdout
        # The table has columns: ID, NAME, STATE, CREATED
        # We look for a line containing the session name and the expected state.
        for line in last_output.splitlines():
            if name in line and expected_state in line:
                return last_output
        time.sleep(interval)

    raise AssertionError(
        f"Session {name!r} did not reach state {expected_state!r} "
        f"within {timeout}s.\nLast ps output:\n{last_output}"
    )


def limactl_list_json() -> list[dict]:
    """Run `limactl list --json` and return parsed entries."""
    result = subprocess.run(
        ["limactl", "list", "--json"],
        capture_output=True, text=True, timeout=30,
    )
    entries = []
    for line in (result.stdout or "").strip().splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def limactl_shell(vm_name: str, *cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a command inside a Lima VM via `limactl shell`."""
    return subprocess.run(
        ["limactl", "shell", vm_name, "--", *cmd],
        capture_output=True, text=True, timeout=timeout,
    )


# Default VM resource args -- kept small so tests work on hosts with limited
# memory (e.g. 4 GB total).
_VM_RESOURCE_ARGS = ("--cpus", "1", "--memory", "1024", "--disk", "10")


def capture_lima_logs(session_id: str) -> str:
    """Best-effort capture of Lima VM logs for debugging failures."""
    vm = lima_vm_name(session_id)
    logs = []

    # ha.stderr.log is the main Lima log
    ha_log = os.path.expanduser(f"~/.lima/{vm}/ha.stderr.log")
    try:
        with open(ha_log) as f:
            content = f.read()
            if content:
                logs.append(f"--- {ha_log} (last 50 lines) ---")
                logs.extend(content.splitlines()[-50:])
    except FileNotFoundError:
        logs.append(f"(no ha.stderr.log found at {ha_log})")

    return "\n".join(logs)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(600)
def test_create_and_destroy(sandbox_cli):
    """Create a VM, verify it's running, destroy it, verify it's gone."""
    session_id = None
    try:
        # 1. Create a session
        result = sandbox_cli("create", "--name", "lifecycle-test", *_VM_RESOURCE_ARGS, timeout=600)
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

        session_id = parse_session_id(result.stdout)
        vm_name = lima_vm_name(session_id)

        # 2. Verify `sandbox ps` shows Running state
        ps_output = wait_for_state(sandbox_cli, "lifecycle-test", "Running", timeout=10)
        assert "lifecycle-test" in ps_output
        assert session_id in ps_output

        # 3. Verify we can run a command inside the VM
        shell_result = limactl_shell(vm_name, "uname", "-a", timeout=60)
        assert shell_result.returncode == 0, (
            f"limactl shell failed.\n"
            f"stdout: {shell_result.stdout}\nstderr: {shell_result.stderr}\n"
            f"{capture_lima_logs(session_id)}"
        )
        assert "Linux" in shell_result.stdout, (
            f"Expected 'Linux' in uname output, got: {shell_result.stdout}"
        )

        # 4. Destroy the session
        rm_result = sandbox_cli("rm", "lifecycle-test", timeout=120)
        assert rm_result.returncode == 0, (
            f"sandbox rm failed (rc={rm_result.returncode}).\n"
            f"stdout: {rm_result.stdout}\nstderr: {rm_result.stderr}"
        )

        # 5. Verify `sandbox ps` shows no sessions (or at least not this one)
        ps_result = sandbox_cli("ps")
        assert "lifecycle-test" not in ps_result.stdout, (
            f"Session still visible after rm:\n{ps_result.stdout}"
        )

        # 6. Verify the Lima VM is gone
        lima_vms = limactl_list_json()
        vm_names = [v.get("name", "") for v in lima_vms]
        assert vm_name not in vm_names, (
            f"Lima VM {vm_name} still exists after rm. VMs: {vm_names}"
        )

        # Mark session_id as None so the finally block doesn't try to clean up
        session_id = None

    finally:
        # Best-effort cleanup if the test failed mid-way
        if session_id is not None:
            sandbox_cli("rm", "lifecycle-test", timeout=120)


@pytest.mark.timeout(600)
def test_stop_and_start(sandbox_cli):
    """Create a VM, write a file, stop, start, verify file persists."""
    session_id = None
    try:
        # 1. Create a session
        result = sandbox_cli("create", "--name", "persist-test", *_VM_RESOURCE_ARGS, timeout=600)
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

        session_id = parse_session_id(result.stdout)
        vm_name = lima_vm_name(session_id)

        # Verify running
        wait_for_state(sandbox_cli, "persist-test", "Running", timeout=10)

        # 2. Write a file inside the VM (use home dir, not /tmp which is
        #    tmpfs and gets cleared on reboot)
        test_file = "/home/agent/persist-test.txt"
        write_result = limactl_shell(
            vm_name, "bash", "-c", f"echo hello > {test_file}",
            timeout=60,
        )
        assert write_result.returncode == 0, (
            f"Failed to write file in VM.\n"
            f"stdout: {write_result.stdout}\nstderr: {write_result.stderr}"
        )

        # 3. Stop the session
        stop_result = sandbox_cli("stop", "persist-test", timeout=120)
        assert stop_result.returncode == 0, (
            f"sandbox stop failed (rc={stop_result.returncode}).\n"
            f"stdout: {stop_result.stdout}\nstderr: {stop_result.stderr}"
        )

        # 4. Verify state is Stopped
        wait_for_state(sandbox_cli, "persist-test", "Stopped", timeout=30)

        # 5. Start the session
        start_result = sandbox_cli("start", "persist-test", timeout=600)
        assert start_result.returncode == 0, (
            f"sandbox start failed (rc={start_result.returncode}).\n"
            f"stdout: {start_result.stdout}\nstderr: {start_result.stderr}"
        )

        # 6. Verify state is Running
        wait_for_state(sandbox_cli, "persist-test", "Running", timeout=10)

        # 7. Read the file back
        read_result = limactl_shell(
            vm_name, "cat", test_file,
            timeout=60,
        )
        assert read_result.returncode == 0, (
            f"Failed to read file after restart.\n"
            f"stdout: {read_result.stdout}\nstderr: {read_result.stderr}"
        )

        # 8. Verify contents match
        assert read_result.stdout.strip() == "hello", (
            f"File contents mismatch. Expected 'hello', got: {read_result.stdout.strip()!r}"
        )

        # 9. Clean up
        rm_result = sandbox_cli("rm", "persist-test", timeout=120)
        assert rm_result.returncode == 0, (
            f"sandbox rm failed (rc={rm_result.returncode}).\n"
            f"stdout: {rm_result.stdout}\nstderr: {rm_result.stderr}"
        )

        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "persist-test", timeout=120)
