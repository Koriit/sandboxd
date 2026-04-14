"""E2E tests for M5-S2 git remote transport: verifying the git protocol
relay between host and sandbox VM via the daemon's git endpoint.

These tests exercise the ``git-remote-sandbox`` remote helper (invoked
automatically by git for ``sandbox::`` URLs), proving that host-to-VM
git push/fetch works end-to-end via the daemon's ``POST /sessions/{id}/git``
endpoint.

These tests boot real Lima/QEMU VMs and are SLOW (3-10 minutes per test).
Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_m5_git_remote.py -v --timeout=600
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

import pytest

from conftest import (
    SandboxBinaries,
    _VM_RESOURCE_ARGS,
    parse_session_id,
    wait_for_state,
)


def _setup_remote_helper_env(
    sandbox_binaries: SandboxBinaries,
    socket_path: str,
) -> tuple[dict[str, str], str]:
    """Create a symlink ``git-remote-sandbox`` -> sandbox binary and return
    an env dict with the symlink directory prepended to PATH and
    SANDBOX_SOCKET set.

    The symlink directory is a temporary directory that the caller should
    clean up (or let the OS handle).
    """
    helper_dir = tempfile.mkdtemp(prefix="sandbox-git-helper-")
    symlink_path = os.path.join(helper_dir, "git-remote-sandbox")
    os.symlink(str(sandbox_binaries.sandbox), symlink_path)

    env = os.environ.copy()
    env["PATH"] = helper_dir + ":" + env.get("PATH", "")
    env["SANDBOX_SOCKET"] = socket_path
    return env, helper_dir

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.timeout(600)
def test_git_push_to_vm(
    sandbox_cli,
    sandbox_binaries: SandboxBinaries,
    sandbox_daemon,
):
    """Push a commit from the host INTO a VM using ``git-remote-sandbox``.

    Flow:
      1. Create a session and wait until running.
      2. Initialize a bare repo inside the VM.
      3. Create a local git repo on the host with a test commit.
      4. Add a git remote using ``sandbox::`` URL (git remote helper).
      5. ``git push sandbox main`` through the remote helper.
      6. Verify inside the VM that the pushed commit arrived.
    """
    session_id = None
    local_repo = None
    helper_dir = None
    try:
        # -- 0. Set up git-remote-sandbox symlink and env ----------------------
        socket_path = sandbox_daemon["socket"]
        git_env, helper_dir = _setup_remote_helper_env(
            sandbox_binaries, socket_path,
        )

        # -- 1. Create a session -----------------------------------------------
        result = sandbox_cli(
            "create", "--name", "git-push-vm",
            *_VM_RESOURCE_ARGS,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "git-push-vm", "Running", timeout=10)

        # -- 2. Initialize a bare repo inside the VM --------------------------
        exec_result = sandbox_cli(
            "exec", "git-push-vm", "--",
            "git", "init", "--bare", "/home/agent/workspace/repo.git",
            timeout=120,
        )
        assert exec_result.returncode == 0, (
            f"git init --bare inside VM failed.\n"
            f"stdout: {exec_result.stdout}\nstderr: {exec_result.stderr}"
        )

        # -- 3. Create a local git repo on the host with a commit -------------
        local_repo = tempfile.mkdtemp(prefix="sandbox-git-push-test-")
        subprocess.run(
            ["git", "init", local_repo],
            check=True, capture_output=True, timeout=30,
        )
        subprocess.run(
            ["git", "-C", local_repo, "config", "user.email", "test@test.com"],
            check=True, capture_output=True, timeout=10,
        )
        subprocess.run(
            ["git", "-C", local_repo, "config", "user.name", "Test"],
            check=True, capture_output=True, timeout=10,
        )
        readme_path = os.path.join(local_repo, "README.md")
        with open(readme_path, "w") as f:
            f.write("# Push Test\nPushed from host to VM.\n")
        subprocess.run(
            ["git", "-C", local_repo, "add", "README.md"],
            check=True, capture_output=True, timeout=10,
        )
        subprocess.run(
            ["git", "-C", local_repo, "commit", "-m", "host commit for push"],
            check=True, capture_output=True, timeout=10,
        )

        # Determine the default branch name (main or master).
        branch_result = subprocess.run(
            ["git", "-C", local_repo, "branch", "--show-current"],
            capture_output=True, text=True, timeout=10,
        )
        branch = branch_result.stdout.strip()
        assert branch, "Could not determine local branch name"

        # -- 4. Add a git remote using sandbox:: URL ---------------------------
        remote_url = "sandbox::git-push-vm/home/agent/workspace/repo.git"
        subprocess.run(
            ["git", "-C", local_repo, "remote", "add", "sandbox", remote_url],
            check=True, capture_output=True, timeout=10,
        )

        # -- 5. Push to the VM through the remote helper ----------------------
        push_result = subprocess.run(
            ["git", "-C", local_repo, "push", "sandbox", branch],
            capture_output=True, text=True, timeout=120,
            env=git_env,
        )
        assert push_result.returncode == 0, (
            f"git push via sandbox:: remote helper failed "
            f"(rc={push_result.returncode}).\n"
            f"stdout: {push_result.stdout}\nstderr: {push_result.stderr}"
        )

        # -- 6. Verify the commit arrived inside the VM -----------------------
        log_result = sandbox_cli(
            "exec", "git-push-vm", "--",
            "git", "-C", "/home/agent/workspace/repo.git",
            "log", "--oneline", "-1",
            timeout=120,
        )
        assert log_result.returncode == 0, (
            f"git log inside VM failed.\n"
            f"stdout: {log_result.stdout}\nstderr: {log_result.stderr}"
        )
        assert "host commit for push" in log_result.stdout, (
            f"Expected 'host commit for push' in VM git log.\n"
            f"Got: {log_result.stdout}"
        )

        # -- Clean up ----------------------------------------------------------
        sandbox_cli("rm", "git-push-vm", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "git-push-vm", timeout=120)
        if local_repo is not None:
            shutil.rmtree(local_repo, ignore_errors=True)
        if helper_dir is not None:
            shutil.rmtree(helper_dir, ignore_errors=True)


@pytest.mark.timeout(600)
def test_git_fetch_from_vm(
    sandbox_cli,
    sandbox_binaries: SandboxBinaries,
    sandbox_daemon,
):
    """Fetch a commit FROM a VM to the host using ``git-remote-sandbox``.

    Flow:
      1. Create a session and wait until running.
      2. Create a repo with a commit inside the VM.
      3. Create a local bare repo on the host (to fetch into).
      4. Add a git remote using ``sandbox::`` URL (git remote helper).
      5. ``git fetch sandbox`` through the remote helper.
      6. Verify the fetched commit matches what was created in the VM.
    """
    session_id = None
    local_repo = None
    helper_dir = None
    try:
        # -- 0. Set up git-remote-sandbox symlink and env ----------------------
        socket_path = sandbox_daemon["socket"]
        git_env, helper_dir = _setup_remote_helper_env(
            sandbox_binaries, socket_path,
        )

        # -- 1. Create a session -----------------------------------------------
        result = sandbox_cli(
            "create", "--name", "git-fetch-vm",
            *_VM_RESOURCE_ARGS,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "git-fetch-vm", "Running", timeout=10)

        # -- 2. Create a repo with a commit inside the VM ---------------------
        init_script = (
            "mkdir -p /home/agent/workspace/repo && "
            "cd /home/agent/workspace/repo && "
            "git init && "
            "git config user.email 'test@test.com' && "
            "git config user.name 'Test' && "
            "echo 'hello from VM' > file.txt && "
            "git add . && "
            "git commit -m 'vm commit for fetch'"
        )
        exec_result = sandbox_cli(
            "exec", "git-fetch-vm", "--",
            "bash", "-c", init_script,
            timeout=120,
        )
        assert exec_result.returncode == 0, (
            f"git init+commit inside VM failed.\n"
            f"stdout: {exec_result.stdout}\nstderr: {exec_result.stderr}"
        )

        # Determine the branch name used inside the VM.
        branch_result = sandbox_cli(
            "exec", "git-fetch-vm", "--",
            "git", "-C", "/home/agent/workspace/repo", "branch", "--show-current",
            timeout=30,
        )
        assert branch_result.returncode == 0, (
            f"Could not determine VM branch.\n"
            f"stdout: {branch_result.stdout}\nstderr: {branch_result.stderr}"
        )
        vm_branch = branch_result.stdout.strip()
        assert vm_branch, "VM branch name is empty"

        # -- 3. Create a local bare repo on the host --------------------------
        local_repo = tempfile.mkdtemp(prefix="sandbox-git-fetch-test-")
        subprocess.run(
            ["git", "init", "--bare", local_repo],
            check=True, capture_output=True, timeout=30,
        )

        # -- 4. Add a git remote using sandbox:: URL ---------------------------
        remote_url = "sandbox::git-fetch-vm/home/agent/workspace/repo"
        subprocess.run(
            ["git", "-C", local_repo, "remote", "add", "sandbox", remote_url],
            check=True, capture_output=True, timeout=10,
        )

        # -- 5. Fetch from the VM through the remote helper --------------------
        fetch_result = subprocess.run(
            ["git", "-C", local_repo, "fetch", "sandbox"],
            capture_output=True, text=True, timeout=120,
            env=git_env,
        )
        assert fetch_result.returncode == 0, (
            f"git fetch via sandbox:: remote helper failed "
            f"(rc={fetch_result.returncode}).\n"
            f"stdout: {fetch_result.stdout}\nstderr: {fetch_result.stderr}"
        )

        # -- 6. Verify the fetched commit matches the VM commit ----------------
        log_result = subprocess.run(
            [
                "git", "-C", local_repo, "log",
                f"sandbox/{vm_branch}", "--oneline", "-1",
            ],
            capture_output=True, text=True, timeout=10,
        )
        assert log_result.returncode == 0, (
            f"git log on fetched ref failed.\n"
            f"stdout: {log_result.stdout}\nstderr: {log_result.stderr}"
        )
        assert "vm commit for fetch" in log_result.stdout, (
            f"Expected 'vm commit for fetch' in fetched log.\n"
            f"Got: {log_result.stdout}"
        )

        # -- Clean up ----------------------------------------------------------
        sandbox_cli("rm", "git-fetch-vm", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "git-fetch-vm", timeout=120)
        if local_repo is not None:
            shutil.rmtree(local_repo, ignore_errors=True)
        if helper_dir is not None:
            shutil.rmtree(helper_dir, ignore_errors=True)
