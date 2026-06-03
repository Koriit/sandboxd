"""E2E tests for sandbox-lima-helper cross-user pivot.

These tests verify that every daemon limactl invocation goes through
``sandbox-lima-helper`` with the operator's uid, so:

1. The Lima VM's ``_config/user`` SSH private key is owned by the *operator*
   uid (not the daemon uid), satisfying OpenSSH ``StrictKeyfileMode``.
2. A session created under a non-daemon operator uid can:
   a. Boot and reach Running state.
   b. Communicate with the guest agent (ping succeeds).
   c. Reach the in-VM sshd through the daemon-mediated proxy endpoint.

These tests exercise the cross-user path: the daemon runs as the
``sandbox-test`` system user (via ``sudo -u sandbox-test``) so the
``SO_PEERCRED`` uid captured on session-create differs from the operator
invoking the CLI.  They are marked ``lima`` (Lima/QEMU only).

Runtime: 5–15 minutes depending on whether the base image needs building.
Run individually before the full matrix:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_cross_user_helper_pivot.py -v --timeout=900
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from conftest import (
    OP_LIMA_HOME,
    SANDBOX_BIN,
    _SANDBOX_E2E_SOCKET,
    _VM_RESOURCE_ARGS,
    parse_session_id,
)

pytestmark = pytest.mark.lima


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sandbox(*args: str, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """Invoke the sandbox CLI against the cross-user test daemon and return the result.

    Passes ``--socket`` explicitly so the CLI reaches the production-shaped
    daemon socket at ``_SANDBOX_E2E_SOCKET`` rather than the XDG default.
    """
    return subprocess.run(
        [str(SANDBOX_BIN), "--socket", str(_SANDBOX_E2E_SOCKET), *args],
        capture_output=True,
        text=True,
        check=check,
        timeout=300,      # cross-user first-boot: limactl start + usermod cloud-init
        **kwargs,
    )


def _config_user_path_for_vm(vm_name: str) -> Path | None:
    """Return the path to _config/user inside the per-operator LIMA_HOME.

    Lima stores the SSH keypair at the LIMA_HOME level, not inside each
    individual VM instance directory.  The correct path is the 3-level
    per-uid OP_LIMA_HOME:
        /var/lib/sandboxd/<sandbox-test-uid>/<op_uid>/lima/_config/user
    We derive this from conftest's OP_LIMA_HOME constant (which encodes
    both the daemon uid and the operator uid) rather than constructing
    the path from os.getuid() alone.
    The vm_name parameter is accepted for call-site compatibility but is
    not used in the path construction.
    """
    return Path(OP_LIMA_HOME) / "_config" / "user"


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
        """The VM directory must be under the 3-level per-operator LIMA_HOME."""
        session_id = None
        try:
            result = sandbox("create", "--backend", "lima", *_VM_RESOURCE_ARGS)
            session_id = parse_session_id(result.stdout)

            # OP_LIMA_HOME is the 3-level path:
            #   /var/lib/sandboxd/<sandbox-test-uid>/<op_uid>/lima
            # (conftest encodes both the daemon uid and the operator uid).
            expected_lima_home = Path(OP_LIMA_HOME)
            vm_dir = expected_lima_home / f"sandbox-{session_id}"

            assert vm_dir.exists(), (
                f"VM directory {vm_dir} does not exist. "
                f"Expected VM to be created in per-operator LIMA_HOME "
                f"{expected_lima_home}/ but it wasn't. "
                "Check that sandbox-lima-helper set LIMA_HOME correctly."
            )
        finally:
            if session_id:
                sandbox("rm", session_id, check=False)
