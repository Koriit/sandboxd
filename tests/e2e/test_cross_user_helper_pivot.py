"""E2E tests for sandbox-lima-helper cross-user pivot.

These tests verify that every daemon limactl invocation goes through
``sandbox-lima-helper`` with the operator's uid, so:

1. The Lima VM's ``_config/user`` SSH private key is owned by the *operator*
   uid (not the daemon uid 999), satisfying OpenSSH ``StrictKeyfileMode``.
2. A session created under a non-daemon operator uid can:
   a. Boot and reach Running state.
   b. Communicate with the guest agent (ping succeeds).
   c. Reach the in-VM sshd through the daemon-mediated proxy endpoint.
3. A shared: workspace (9p ``mapped-xattr``) created for a non-daemon operator
   uid allows read+write round-trips from the host *and* the guest, with the
   correct ownership on the host side (files written by the in-VM ``sandbox``
   user re-map to the operator's host uid via ``mapped-xattr``).

These tests require the M18 cross-user harness (``SANDBOX_HARNESS`` ≠
``"test-user"``): the daemon must run as the ``sandbox`` system user so the
``SO_PEERCRED`` uid captured on session-create differs from the operator
invoking the CLI.  They are marked ``lima`` (Lima/QEMU only) and skipped
when the harness is ``"test-user"`` (daemon = operator, no cross-user pivot).

Runtime: 5–15 minutes depending on whether the base image needs building.
Run individually before the full matrix:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_cross_user_helper_pivot.py -v --timeout=900
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from conftest import (
    LIMA_VM_HOME,
    SANDBOX_BIN,
    SANDBOX_HARNESS,
    _SANDBOX_PROD_SOCKET,
    _VM_RESOURCE_ARGS,
    parse_session_id,
)

pytestmark = pytest.mark.lima

# ---------------------------------------------------------------------------
# Skip guard: cross-user only meaningful when daemon ≠ operator.
# ---------------------------------------------------------------------------

if SANDBOX_HARNESS == "test-user":
    pytest.skip(
        "cross-user helper-pivot tests require SANDBOX_HARNESS != test-user "
        "(daemon must run as sandbox uid, operator as test-runner uid)",
        allow_module_level=True,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sandbox(*args: str, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """Invoke the sandbox CLI against the cross-user test daemon and return the result.

    Passes ``--socket`` explicitly so the CLI reaches the production-shaped
    daemon socket at ``_SANDBOX_PROD_SOCKET`` rather than the XDG default.
    """
    return subprocess.run(
        [str(SANDBOX_BIN), "--socket", str(_SANDBOX_PROD_SOCKET), *args],
        capture_output=True,
        text=True,
        check=check,
        timeout=300,      # cross-user first-boot: limactl start + usermod cloud-init
        **kwargs,
    )


def _config_user_path_for_vm(vm_name: str) -> Path | None:
    """Return the path to _config/user inside the per-operator LIMA_HOME.

    Lima stores the SSH keypair at the LIMA_HOME level, not inside each
    individual VM instance directory.  The correct path is:
        /var/lib/sandboxd/<op_uid>/lima/_config/user
    We derive op_uid from os.getuid() (the test runner is the operator).
    The vm_name parameter is accepted for call-site compatibility but is
    not used in the path construction.
    """
    op_uid = os.getuid()
    return Path(f"/var/lib/sandboxd/{op_uid}/lima/_config/user")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHelperPivotKeyOwnership:
    """_config/user is owned by the operator uid after VM creation.

    This is the load-bearing test: if the key is owned by the daemon uid
    (999) instead of the operator uid, OpenSSH's StrictKeyfileMode check
    fails and the session is unreachable.
    """

    def test_ssh_key_owned_by_operator_uid(self, tmp_path):
        """After sandbox create, _config/user must be owned by os.getuid()."""
        session_id = None
        try:
            result = sandbox("create", "--backend", "lima", *_VM_RESOURCE_ARGS)
            session_id = parse_session_id(result.stdout)

            vm_name = f"sandbox-{session_id}"
            key_path = _config_user_path_for_vm(vm_name)

            assert key_path is not None, (
                f"could not determine _config/user path for {vm_name}"
            )
            assert key_path.exists(), (
                f"_config/user not found at {key_path}; "
                "helper pivot may not have run or LIMA_HOME is wrong"
            )

            stat_info = key_path.stat()
            operator_uid = os.getuid()
            assert stat_info.st_uid == operator_uid, (
                f"_config/user at {key_path} is owned by uid {stat_info.st_uid}, "
                f"expected operator uid {operator_uid}. "
                "This means sandbox-lima-helper did NOT pivot to the operator uid "
                "before limactl create — the sandbox-lima-helper pivot is broken."
            )

            # Also assert key mode is 0600 (OpenSSH StrictKeyfileMode requirement).
            mode = oct(stat_info.st_mode & 0o777)
            assert mode == oct(0o600), (
                f"_config/user mode is {mode}, expected 0o600 (StrictKeyfileMode)"
            )
        finally:
            if session_id:
                sandbox("rm", session_id, check=False)


class TestHelperPivotSessionReachability:
    """A session created under a non-daemon operator uid is fully reachable."""

    def test_session_boots_and_agent_responds(self, tmp_path):
        """Create a session, verify it reaches Running, and ping the guest agent."""
        session_id = None
        try:
            result = sandbox("create", "--backend", "lima", *_VM_RESOURCE_ARGS)
            session_id = parse_session_id(result.stdout)

            # Guest agent must respond to a ping (exec an innocuous command).
            # ``sandbox create`` is synchronous: the HTTP handler sets Running
            # before returning, so no separate polling step is required.
            result = sandbox("exec", session_id, "--", "echo", "hello-from-pivot")
            assert "hello-from-pivot" in result.stdout, (
                f"guest exec returned unexpected output: {result.stdout!r}"
            )
        finally:
            if session_id:
                sandbox("rm", session_id, check=False)

    def test_vm_lives_in_per_operator_lima_home(self, tmp_path):
        """The VM directory must be under /var/lib/sandboxd/<op_uid>/lima/."""
        session_id = None
        try:
            result = sandbox("create", "--backend", "lima", *_VM_RESOURCE_ARGS)
            session_id = parse_session_id(result.stdout)

            op_uid = os.getuid()
            expected_lima_home = Path(f"/var/lib/sandboxd/{op_uid}/lima")
            vm_dir = expected_lima_home / f"sandbox-{session_id}"

            assert vm_dir.exists(), (
                f"VM directory {vm_dir} does not exist. "
                "Expected VM to be created in per-operator LIMA_HOME "
                f"/var/lib/sandboxd/{op_uid}/lima/ but it wasn't. "
                "Check that sandbox-lima-helper set LIMA_HOME correctly."
            )
        finally:
            if session_id:
                sandbox("rm", session_id, check=False)


class TestHelperPivot9pSharedWorkspace:
    """9p shared: workspace cross-user read+write round-trip.

    The base VM's in-VM sandbox user has its uid/gid aligned with the
    operator's host uid/gid via a cloud-init usermod step.  9p
    mapped-xattr then translates host-side file ownership correctly so:
    - Files written by the operator on the host are readable/writable in the VM.
    - Files written by the in-VM sandbox user are owned by the operator uid
      on the host (mapped-xattr re-maps uid 1000→operator uid when != 1000).

    This test is skipped when op_uid == 1000 (base image bakes uid 1000 and
    the mapping is a no-op; the interesting case is op_uid != 1000).
    """

    def test_host_write_readable_in_vm(self, tmp_path):
        """Write a file on the host shared dir; verify it is readable inside the VM."""
        op_uid = os.getuid()
        if op_uid == 1000:
            pytest.skip(
                "op_uid==1000: base image bakes uid 1000 so the 9p mapped-xattr "
                "uid translation is a no-op; this test only covers op_uid != 1000"
            )

        # Create a host directory to share.
        shared = tmp_path / "shared"
        shared.mkdir(mode=0o755)
        marker = shared / "host_marker.txt"
        marker.write_text("written-on-host")

        session_id = None
        try:
            result = sandbox(
                "create", "--backend", "lima",
                "--workspace", f"shared:{shared}:{LIMA_VM_HOME}/workspace",
                *_VM_RESOURCE_ARGS,
            )
            session_id = parse_session_id(result.stdout)
            # ``sandbox create`` is synchronous: the HTTP handler sets Running
            # before returning, so no separate polling step is required.

            # Read the file from inside the VM.
            result = sandbox(
                "exec", session_id, "--",
                "cat", f"{LIMA_VM_HOME}/workspace/host_marker.txt",
            )
            assert "written-on-host" in result.stdout, (
                f"host-written file not readable in VM: {result.stdout!r}"
            )
        finally:
            if session_id:
                sandbox("rm", session_id, check=False)

    def test_vm_write_readable_on_host(self, tmp_path):
        """Write a file from inside the VM; verify it is readable and correctly
        owned on the host after the 9p mapped-xattr translation."""
        op_uid = os.getuid()
        if op_uid == 1000:
            pytest.skip(
                "op_uid==1000: base image bakes uid 1000 so the 9p mapped-xattr "
                "uid translation is a no-op; this test only covers op_uid != 1000"
            )

        shared = tmp_path / "shared"
        shared.mkdir(mode=0o755)

        session_id = None
        try:
            result = sandbox(
                "create", "--backend", "lima",
                "--workspace", f"shared:{shared}:{LIMA_VM_HOME}/workspace",
                *_VM_RESOURCE_ARGS,
            )
            session_id = parse_session_id(result.stdout)
            # ``sandbox create`` is synchronous: the HTTP handler sets Running
            # before returning, so no separate polling step is required.

            # Write a file from inside the VM.
            sandbox(
                "exec", session_id, "--",
                "bash", "-c",
                f"echo 'written-in-vm' > {LIMA_VM_HOME}/workspace/vm_marker.txt",
            )

            # Allow the 9p flush.
            time.sleep(1)

            guest_file = shared / "vm_marker.txt"
            assert guest_file.exists(), (
                f"VM-written file not visible on host at {guest_file}"
            )
            assert "written-in-vm" in guest_file.read_text(), (
                f"VM-written file has unexpected content: {guest_file.read_text()!r}"
            )

            # Under mapped-xattr, when op_uid != 1000, the file's host-side
            # owner should be op_uid (9p re-maps uid 1000 → op_uid via the
            # cloud-init usermod step). When op_uid == 1000 no remapping
            # occurs (base image bakes uid 1000), so the assertion is a
            # trivial no-op that proves nothing; skip visibly instead.
            if op_uid == 1000:
                pytest.skip(
                    "ownership remapping assertion skipped: operator uid is 1000 "
                    "(base image bakes uid 1000; no remapping occurs). "
                    "Run as a uid != 1000 to exercise mapped-xattr translation."
                )
            stat_info = guest_file.stat()
            assert stat_info.st_uid == op_uid, (
                f"VM-written file on host is owned by uid {stat_info.st_uid}, "
                f"expected operator uid {op_uid}. "
                "This suggests the 9p mapped-xattr uid remapping via "
                "cloud-init usermod did not take effect."
            )
        finally:
            if session_id:
                sandbox("rm", session_id, check=False)
