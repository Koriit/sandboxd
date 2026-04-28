"""E2E tests for M5 workspace features: git clone mode, boot command, and
file copy (sandbox cp) between host and VM.

These tests boot real Lima/QEMU VMs and are SLOW (3-10 minutes per test).
Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_m5_workspace.py -v --timeout=600

Backend coverage: **agnostic** — parametrized over ``[lima, container]``
via the ``backend`` fixture. ``--repo``, ``sandbox cp``, and
``--workspace shared:`` are spec-required behaviours on both backends
(spec § "Workspace" lines ~570-595); ``test_lite.py`` already covers
``--workspace shared:`` for the container backend, and this
parametrization extends the rest to the matrix.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from conftest import (
    cleanup_policy_file,
    make_create_args,
    parse_session_id,
    wait_for_state,
    write_policy_file,
)
from helpers import is_rootless_docker

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(600)
def test_clone_repo(sandbox_cli, backend):
    """Create a session with --repo pointing to a small public repo.
    Verify the repository is cloned into /home/agent/workspace/.

    Backend-agnostic since M11-S7: both backends advertise
    `WorkspaceModeKind::Clone` and the daemon dispatches `git clone`
    in-guest via `GuestConnector` after the runtime starts.
    """
    session_id = None
    policy_path = None
    try:
        # We need a policy that allows github.com for the git clone to work.
        # M10-S1 v2 schema: rule identity is (host, port); protocol is L4.
        # `git clone https://…` over HTTPS → (github.com, 443, tcp).
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "github.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "transport",
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-clone",
                "--policy", policy_path,
                "--repo", "https://github.com/octocat/Hello-World.git",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-clone", "Running", timeout=10)

        # Verify /home/agent/workspace/ exists and has expected content.
        ls_result = sandbox_cli(
            "exec", "ws-clone", "--", "ls", "/home/agent/workspace/",
            timeout=120,
        )
        assert ls_result.returncode == 0, (
            f"ls /home/agent/workspace/ failed.\n"
            f"stdout: {ls_result.stdout}\nstderr: {ls_result.stderr}"
        )
        # The Hello-World repo should have a README file.
        assert "README" in ls_result.stdout, (
            f"Expected README in /home/agent/workspace/, got:\n{ls_result.stdout}"
        )

        # Verify it's a git repo.
        git_result = sandbox_cli(
            "exec", "ws-clone", "--",
            "git", "-C", "/home/agent/workspace/", "log", "--oneline", "-1",
            timeout=120,
        )
        assert git_result.returncode == 0, (
            f"git log failed in /home/agent/workspace/.\n"
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
def test_cp_host_to_vm(sandbox_cli, backend):
    """Create a session, create a temp file locally, use `sandbox cp` to
    upload it into the VM, then verify contents via `sandbox exec`.
    """
    session_id = None
    local_file = None
    try:
        result = sandbox_cli(
            "create", *make_create_args(backend, "ws-cp-up"),
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
def test_cp_vm_to_host(sandbox_cli, backend):
    """Create a session, create a file in the VM via `sandbox exec`, then
    use `sandbox cp` to download it to the host and verify contents.
    """
    session_id = None
    local_file = None
    try:
        result = sandbox_cli(
            "create", *make_create_args(backend, "ws-cp-down"),
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


@pytest.mark.timeout(600)
def test_shared_mount(sandbox_cli, backend):
    """Create a session with --workspace shared:<tmpdir>.
    Verify bidirectional file visibility between host and VM.

    Backend-agnostic since M11-S7: the container backend's bind target
    is unified with Lima's at `/home/agent/workspace/`, so the path
    assertions below work on both backends.
    """
    # Host->container file visibility requires that a file written by the
    # host operator (uid 1000) is readable inside the container by the
    # agent user (uid 1000). Default-hardened Docker keeps that mapping
    # 1:1, but rootless Docker remaps host uid 1000 through /etc/subuid
    # so the host-written file lands inside the container under a
    # sub-uid that the agent user cannot read. The lite spec forbids
    # userns-remap (§ Workspace lines 572-574: "Do not use userns-remap
    # — that would force chown on host files, which is destructive and
    # surprising") and rootless Docker is explicitly out of scope (§
    # Out of scope line 1175: "Lite's target is default-hardened Docker.
    # Alternative runtimes are a separate design"), so the failure on a
    # rootless rig is a property of the host runtime, not the lite
    # backend. The Lima parametrization is unaffected (it boots a real
    # VM and does not traverse a userns), so the skip is conditional on
    # the container backend only — mirrors the file-level skipif on
    # `test_lite.py::test_lite_workspace_uid_alignment`.
    if backend == "container" and is_rootless_docker():
        pytest.skip(
            "Workspace shared-mount host->container visibility requires "
            "default-hardened Docker. Rootless Docker remaps uids through "
            "/etc/subuid so a host-written file lands inside the container "
            "as a sub-uid that the agent user cannot read; the lite spec "
            "forbids userns-remap (§ Workspace lines 572-574: 'Do not use "
            "userns-remap — that would force chown on host files, which "
            "is destructive and surprising') and rootless Docker is "
            "explicitly out of scope (§ Out of scope line 1175: 'Lite's "
            "target is default-hardened Docker. Alternative runtimes are "
            "a separate design')."
        )
    session_id = None
    host_dir = None
    try:
        # Create a temporary directory on the host to be shared.
        host_dir = tempfile.mkdtemp(prefix="sandbox-shared-ws-")

        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-shared",
                "--workspace", f"shared:{host_dir}",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-shared", "Running", timeout=10)

        # 1. Host -> VM: create a file on the host, verify visible in the VM.
        host_file = os.path.join(host_dir, "from-host.txt")
        host_content = "hello from the host\n"
        with open(host_file, "w") as f:
            f.write(host_content)

        # The file should be visible at /home/agent/workspace/from-host.txt
        cat_result = sandbox_cli(
            "exec", "ws-shared", "--",
            "cat", "/home/agent/workspace/from-host.txt",
            timeout=120,
        )
        assert cat_result.returncode == 0, (
            f"cat from-host.txt failed in VM.\n"
            f"stdout: {cat_result.stdout}\nstderr: {cat_result.stderr}"
        )
        assert cat_result.stdout == host_content, (
            f"Host file content mismatch in VM.\n"
            f"Expected: {host_content!r}\nGot: {cat_result.stdout!r}"
        )

        # 2. VM -> Host: create a file in the VM, verify visible on the host.
        vm_content = "hello from the VM"
        exec_result = sandbox_cli(
            "exec", "ws-shared", "--",
            "bash", "-c",
            f"echo -n '{vm_content}' > /home/agent/workspace/from-vm.txt",
            timeout=120,
        )
        assert exec_result.returncode == 0, (
            f"Failed to create file in VM.\n"
            f"stdout: {exec_result.stdout}\nstderr: {exec_result.stderr}"
        )

        vm_file_on_host = os.path.join(host_dir, "from-vm.txt")
        assert os.path.exists(vm_file_on_host), (
            f"File created in VM not visible on host at {vm_file_on_host}"
        )
        with open(vm_file_on_host) as f:
            downloaded_content = f.read()
        assert downloaded_content == vm_content, (
            f"VM file content mismatch on host.\n"
            f"Expected: {vm_content!r}\nGot: {downloaded_content!r}"
        )

        # Clean up.
        sandbox_cli("rm", "ws-shared", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-shared", timeout=120)
        if host_dir is not None:
            import shutil
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass
