"""E2E tests for M1 VM lifecycle: create, stop, start, destroy.

These tests boot real Lima/QEMU VMs and are SLOW (1-5 minutes per test).
Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_vm_lifecycle.py -v --timeout=600

Backend coverage: **Lima only**. The assertions reach through
``limactl shell`` and ``limactl list --json`` to verify VM-level state
that has no analogue in the lite container backend. The equivalent
container-backend lifecycle / persistence contract is covered by
``test_lite.py`` (which runs unparametrised against ``--lite``);
backend-agnostic exec/lifecycle behaviour is covered by the
parametrized tests in ``test_guest_agent.py``.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from conftest import (
    LIMA_VM_HOME,
    _VM_RESOURCE_ARGS,
    capture_lima_logs,
    lima_vm_name,
    limactl_cmd,
    parse_session_id,
    wait_for_state,
)

# Whole-file Lima-only: gates the per-test Lima prereq fixture and lets
# `-m "not lima"` exclude this file on container-only runs.
pytestmark = pytest.mark.lima

# ---------------------------------------------------------------------------
# Helpers (file-specific)
# ---------------------------------------------------------------------------


def limactl_list_json() -> list[dict]:
    """Run `limactl list --json` against the per-operator LIMA_HOME and return
    parsed entries.

    Uses ``limactl_cmd()`` so the correct per-operator LIMA_HOME is set
    for the cross-user harness.
    """
    result = subprocess.run(
        limactl_cmd("list", "--json"),
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
    """Run a command inside a Lima VM via ``limactl shell``.

    Uses ``limactl_cmd()`` so the correct per-operator LIMA_HOME is set
    for the cross-user harness.
    """
    return subprocess.run(
        limactl_cmd("shell", vm_name, "--", *cmd),
        capture_output=True, text=True, timeout=timeout,
    )


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
        test_file = f"{LIMA_VM_HOME}/persist-test.txt"
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
