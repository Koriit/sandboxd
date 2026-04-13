"""E2E tests for M5 workspace features: git clone mode, boot command, and
file copy (sandbox cp) between host and VM.

These tests boot real Lima/QEMU VMs and are SLOW (3-10 minutes per test).
Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_m5_workspace.py -v --timeout=600
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Regex to extract the session ID (UUID) from `sandbox create` output.
_ID_RE = re.compile(r"^ID:\s+([0-9a-f-]{36})$", re.MULTILINE)

# Default VM resource args -- kept small for hosts with limited RAM.
_VM_RESOURCE_ARGS = ("--cpus", "1", "--memory", "1024", "--disk", "10")


def parse_session_id(create_output: str) -> str:
    """Extract the session UUID from `sandbox create` stdout."""
    m = _ID_RE.search(create_output)
    if not m:
        raise ValueError(
            f"Could not parse session ID from create output:\n{create_output}"
        )
    return m.group(1)


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
        for line in last_output.splitlines():
            if name in line and expected_state in line:
                return last_output
        time.sleep(interval)

    raise AssertionError(
        f"Session {name!r} did not reach state {expected_state!r} "
        f"within {timeout}s.\nLast ps output:\n{last_output}"
    )


def write_policy_file(policy: dict) -> str:
    """Write a policy dict to a temporary JSON file and return its path.

    The caller is responsible for cleanup (or rely on OS temp cleanup).
    The file is NOT auto-deleted so it remains available for the sandbox
    CLI to read during the test.
    """
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="sandbox-policy-", delete=False,
    )
    json.dump(policy, f)
    f.close()
    return f.name


def cleanup_policy_file(path: str) -> None:
    """Best-effort removal of a temporary policy file."""
    try:
        os.unlink(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(600)
def test_clone_repo(sandbox_cli):
    """Create a session with --repo pointing to a small public repo.
    Verify the repository is cloned into /root/workspace/.
    """
    session_id = None
    policy_path = None
    try:
        # We need a policy that allows github.com for the git clone to work.
        policy = {
            "version": "1.0.0",
            "rules": [
                {"destination": "github.com", "level": "transport"},
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create", "--name", "ws-clone",
            *_VM_RESOURCE_ARGS,
            "--policy", policy_path,
            "--repo", "https://github.com/octocat/Hello-World.git",
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-clone", "Running", timeout=10)

        # Verify /root/workspace/ exists and has expected content.
        ls_result = sandbox_cli(
            "exec", "ws-clone", "--", "ls", "/root/workspace/",
            timeout=120,
        )
        assert ls_result.returncode == 0, (
            f"ls /root/workspace/ failed.\n"
            f"stdout: {ls_result.stdout}\nstderr: {ls_result.stderr}"
        )
        # The Hello-World repo should have a README file.
        assert "README" in ls_result.stdout, (
            f"Expected README in /root/workspace/, got:\n{ls_result.stdout}"
        )

        # Verify it's a git repo.
        git_result = sandbox_cli(
            "exec", "ws-clone", "--",
            "git", "-C", "/root/workspace/", "log", "--oneline", "-1",
            timeout=120,
        )
        assert git_result.returncode == 0, (
            f"git log failed in /root/workspace/.\n"
            f"stdout: {git_result.stdout}\nstderr: {git_result.stderr}"
        )

        # Clean up.
        sandbox_cli("rm", "ws-clone", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-clone", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_cp_host_to_vm(sandbox_cli):
    """Create a session, create a temp file locally, use `sandbox cp` to
    upload it into the VM, then verify contents via `sandbox exec`.
    """
    session_id = None
    local_file = None
    try:
        result = sandbox_cli(
            "create", "--name", "ws-cp-up",
            *_VM_RESOURCE_ARGS,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-cp-up", "Running", timeout=10)

        # Create a local temp file with known content.
        fd, local_file = tempfile.mkstemp(prefix="sandbox-cp-test-", suffix=".txt")
        test_content = "hello from sandbox cp test\nline two\n"
        os.write(fd, test_content.encode())
        os.close(fd)

        # Upload the file into the VM.
        cp_result = sandbox_cli(
            "cp", local_file, "ws-cp-up:/tmp/uploaded.txt",
            timeout=120,
        )
        assert cp_result.returncode == 0, (
            f"sandbox cp upload failed (rc={cp_result.returncode}).\n"
            f"stdout: {cp_result.stdout}\nstderr: {cp_result.stderr}"
        )

        # Verify the file contents in the VM.
        cat_result = sandbox_cli(
            "exec", "ws-cp-up", "--", "cat", "/tmp/uploaded.txt",
            timeout=120,
        )
        assert cat_result.returncode == 0, (
            f"cat failed in VM.\n"
            f"stdout: {cat_result.stdout}\nstderr: {cat_result.stderr}"
        )
        assert cat_result.stdout == test_content, (
            f"File contents mismatch.\n"
            f"Expected: {test_content!r}\nGot: {cat_result.stdout!r}"
        )

        # Clean up.
        sandbox_cli("rm", "ws-cp-up", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-cp-up", timeout=120)
        if local_file is not None:
            try:
                os.unlink(local_file)
            except OSError:
                pass


@pytest.mark.timeout(600)
def test_cp_vm_to_host(sandbox_cli):
    """Create a session, create a file in the VM via `sandbox exec`, then
    use `sandbox cp` to download it to the host and verify contents.
    """
    session_id = None
    local_file = None
    try:
        result = sandbox_cli(
            "create", "--name", "ws-cp-down",
            *_VM_RESOURCE_ARGS,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-cp-down", "Running", timeout=10)

        # Create a file inside the VM.
        test_content = "content created inside VM for download test"
        exec_result = sandbox_cli(
            "exec", "ws-cp-down", "--",
            "bash", "-c", f"echo -n '{test_content}' > /tmp/vm-file.txt",
            timeout=120,
        )
        assert exec_result.returncode == 0, (
            f"Failed to create file in VM.\n"
            f"stdout: {exec_result.stdout}\nstderr: {exec_result.stderr}"
        )

        # Download the file from the VM.
        fd, local_file = tempfile.mkstemp(prefix="sandbox-cp-down-", suffix=".txt")
        os.close(fd)

        cp_result = sandbox_cli(
            "cp", "ws-cp-down:/tmp/vm-file.txt", local_file,
            timeout=120,
        )
        assert cp_result.returncode == 0, (
            f"sandbox cp download failed (rc={cp_result.returncode}).\n"
            f"stdout: {cp_result.stdout}\nstderr: {cp_result.stderr}"
        )

        # Verify the downloaded content.
        with open(local_file) as f:
            downloaded_content = f.read()
        assert downloaded_content == test_content, (
            f"Downloaded content mismatch.\n"
            f"Expected: {test_content!r}\nGot: {downloaded_content!r}"
        )

        # Clean up.
        sandbox_cli("rm", "ws-cp-down", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-cp-down", timeout=120)
        if local_file is not None:
            try:
                os.unlink(local_file)
            except OSError:
                pass
