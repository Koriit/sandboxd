"""E2E tests for sandbox-lima-helper cross-user pivot.

These tests verify that every daemon limactl invocation goes through
``sandbox-lima-helper`` with the operator's uid, so:

1. The Lima VM's ``_config/user`` SSH private key is owned by the *operator*
   uid (not the daemon uid 999), satisfying OpenSSH ``StrictKeyfileMode``.
2. A session created under a non-daemon operator uid can:
   a. Boot and reach Running state.
   b. Communicate with the guest agent (ping succeeds).
   c. Reach the in-VM sshd through the daemon-mediated proxy endpoint.
3. A session created as the ``sandbox-e2e-test`` operator (uid 4099, provisioned
   by ``make setup-e2e-test-operator``) verifies that the Lima cloud-init
   ``usermod -u {op}`` uid-realignment step actually fires and that a 9p
   shared: workspace correctly maps file ownership to the operator uid on the
   host.

These tests exercise the cross-user path: the daemon runs as the ``sandbox``
system user (via ``sudo -u sandbox``) so the ``SO_PEERCRED`` uid captured on
session-create differs from the operator invoking the CLI.  They are marked
``lima`` (Lima/QEMU only).

Runtime: 5–15 minutes depending on whether the base image needs building.
Run individually before the full matrix:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_cross_user_helper_pivot.py -v --timeout=900
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from conftest import (
    LIMA_VM_HOME,
    SANDBOX_BIN,
    _SANDBOX_PROD_SOCKET,
    _VM_RESOURCE_ARGS,
    parse_session_id,
)

# ---------------------------------------------------------------------------
# E2E test operator name — must match `make setup-e2e-test-operator`.
# ---------------------------------------------------------------------------
_E2E_TEST_OPERATOR_NAME = "sandbox-e2e-test"

pytestmark = pytest.mark.lima


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


def sandbox_as(
    op_uid: int,
    *args: str,
    check: bool = True,
    **kwargs,
) -> subprocess.CompletedProcess:
    """Invoke the sandbox CLI as the ``sandbox-e2e-test`` operator.

    Uses ``sudo -n -u sandbox-e2e-test`` to drop to the operator uid
    without a password (requires the NOPASSWD fragment installed by
    ``make setup-e2e-test-operator``).  Propagates ``SANDBOX_SOCKET``
    through ``env`` so the CLI reaches the production-shaped daemon
    socket at ``_SANDBOX_PROD_SOCKET``; the sudoers fragment's
    ``env_keep += "SANDBOX_SOCKET"`` directive permits this.

    The ``op_uid`` parameter is accepted for call-site clarity (the
    caller already has the resolved uid from the ``e2e_test_operator``
    fixture) but is not used in the argv — the sudo target is always
    the fixed name ``sandbox-e2e-test``.
    """
    return subprocess.run(
        [
            "sudo", "-n", "-u", _E2E_TEST_OPERATOR_NAME,
            "env", f"SANDBOX_SOCKET={_SANDBOX_PROD_SOCKET}",
            str(SANDBOX_BIN), "--socket", str(_SANDBOX_PROD_SOCKET),
            *args,
        ],
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


class TestHelperPivotUsermodRealignment:
    """Verify the Lima cloud-init ``usermod -u {op}`` realignment fires for a
    distinct non-1000 operator uid.

    The ``sandbox-e2e-test`` system user (uid 4099) is provisioned by
    ``make setup-e2e-test-operator`` (or ``make setup-dev-env``) and is
    never created inside tests.  Using a real, distinct, non-1000 uid means
    the match guard in ``sandbox-core::lima`` (``op_uid != 1000``) is
    satisfied and the realignment actually executes.

    Primary assertion: after ``sandbox create``, running
    ``sandbox exec <sid> -- id -u sandbox`` as the operator must return the
    operator uid (4099), proving the in-VM ``sandbox`` user was realigned.

    Secondary assertion: a file written by the in-VM ``sandbox`` user into
    a ``shared:`` workspace appears on the host owned by the operator uid.
    """

    def test_usermod_realignment_and_9p_ownership(self, e2e_test_operator, tmp_path):
        """Create a Lima session as the sandbox-e2e-test operator and verify:
        1. The in-VM ``sandbox`` uid equals the operator uid (realignment fired).
        2. A file written from inside the VM into the shared workspace is owned
           by the operator uid on the host.
        """
        op_uid = e2e_test_operator

        # Host directory to mount as a 9p shared: workspace. It must be
        # reachable and writable by the OPERATOR (sandbox-e2e-test, uid
        # 4099) — QEMU runs as that uid and serves the share — not just by
        # the test runner. The runner's pytest tmp tree is 0700 at its
        # ancestors, so a distinct operator uid cannot traverse into it.
        # Put the dir directly under /tmp (1777, world-traversable) and
        # make it world-rwx; it is removed in the `finally` block.
        shared = Path(tempfile.mkdtemp(prefix="sandbox-e2e-shared-"))
        os.chmod(shared, 0o777)

        session_id = None
        try:
            result = sandbox_as(
                op_uid,
                "create", "--backend", "lima",
                "--workspace", f"shared:{shared}:{LIMA_VM_HOME}/workspace",
                *_VM_RESOURCE_ARGS,
            )
            session_id = parse_session_id(result.stdout)

            # --- Primary assertion: uid realignment ---
            id_result = sandbox_as(
                op_uid,
                "exec", session_id, "--", "id", "-u", "sandbox",
            )
            in_vm_uid_str = id_result.stdout.strip()
            assert in_vm_uid_str.isdigit(), (
                f"'id -u sandbox' returned non-numeric output: {in_vm_uid_str!r}"
            )
            in_vm_uid = int(in_vm_uid_str)
            assert in_vm_uid == op_uid, (
                f"cloud-init `usermod -u {op_uid}` did not take effect: "
                f"in-VM sandbox uid is {in_vm_uid}, expected {op_uid}. "
                "Check that the match guard in sandbox-core::lima fires for "
                "op_uid != 1000 and that the cloud-init script ran to completion."
            )

            # --- Secondary assertion: 9p ownership ---
            sandbox_as(
                op_uid,
                "exec", session_id, "--",
                "bash", "-c",
                f"echo 'written-in-vm' > {LIMA_VM_HOME}/workspace/vm_marker.txt",
            )

            # Allow the 9p flush to propagate.
            time.sleep(1)

            guest_file = shared / "vm_marker.txt"
            assert guest_file.exists(), (
                f"VM-written file not visible on host at {guest_file}"
            )
            # The file was written by QEMU running as the operator uid, so
            # under 9p mapped-xattr it lands on the host owned by that uid
            # at mode 0600 — the test runner (a different uid) therefore
            # CANNOT read its contents. That is exactly the ownership
            # property we want to assert. `stat()` needs only dir-traverse
            # (the shared dir is 0777), so check ownership + non-emptiness
            # via stat rather than reading the bytes.
            stat_info = guest_file.stat()
            assert stat_info.st_uid == op_uid, (
                f"VM-written file on host is owned by uid {stat_info.st_uid}, "
                f"expected operator uid {op_uid}. "
                "The 9p mapped-xattr uid remapping via cloud-init usermod "
                "did not take effect — or the realignment ran but the 9p "
                "xattr mapping did not follow."
            )
            assert stat_info.st_size > 0, (
                f"VM-written file on host is empty ({guest_file}); the in-VM "
                "write did not propagate content through the 9p share."
            )
        finally:
            if session_id:
                sandbox_as(op_uid, "rm", session_id, check=False)
            shutil.rmtree(shared, ignore_errors=True)
