"""E2E tests for the macOS full (Lima/QEMU) backend.

These tests cover the default-backend path where ``sandbox create`` (without
``--lite``) provisions a per-operator QEMU VM through the Lima control plane,
brokered by the per-operator ``sandbox-agent``.

Architecture under test:
- ``sandbox create`` (no flags) targets the Lima/QEMU backend.
- The daemon routes every ``limactl`` call for a non-daemon uid through the
  operator's checked-in ``sandbox-agent`` over the broker socket.
- The session VM gets a ``socket_vmnet`` NIC slot with its network funnelled
  through the ``sandboxd-gateway`` container pipeline (nftables deny-all,
  mitmproxy CONNECT allowlist, CoreDNS).
- Egress is restricted by default (``restrict=on``): curl to an arbitrary
  external host must be blocked.

These tests require on the host:
- The ``sandboxd-gateway`` Lima VM running.
- The ``sandbox-agent`` test binary installed by ``make install-agent-test``
  (the _macos_operator_agent conftest fixture launches it automatically).
- A ``socket_vmnet`` slot available in the pool.
- ``make setup-dev-env`` run at least once on this host.

DO NOT RUN during CI without the gateway VM provisioned and the test agent
installed.  Invoke manually after gateway bring-up::

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_fullbackend_macos.py -v --timeout=600

Individual test estimated runtime: 5–15 min (first run triggers base-image
build; subsequent runs reuse it).
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Platform guard: skip entire file on Linux.
# ---------------------------------------------------------------------------
pytestmark = [
    pytest.mark.macos_only,
    pytest.mark.lima,
    pytest.mark.skipif(
        os.uname().sysname != "Darwin",
        reason="Full-backend macOS tests require socket_vmnet + Lima + sandbox-agent",
    ),
]


# ---------------------------------------------------------------------------
# Helpers (mirror test_lite_macos.py)
# ---------------------------------------------------------------------------


def _sandbox(*args, check: bool = True, capture: bool = True, **kwargs):
    """Run the ``sandbox`` CLI and return the CompletedProcess."""
    cmd = ["sandbox"] + list(args)
    if capture:
        return subprocess.run(
            cmd,
            check=check,
            capture_output=True,
            text=True,
            **kwargs,
        )
    return subprocess.run(cmd, check=check, **kwargs)


def _sandbox_json(*args, **kwargs):
    """Run ``sandbox`` and parse stdout as JSON."""
    result = _sandbox(*args, **kwargs)
    return json.loads(result.stdout)


def _inspect_one(session_name: str, **kwargs) -> dict:
    """Inspect a single session and return its object."""
    arr = _sandbox_json("inspect", session_name, **kwargs)
    return arr[0]


def _session_exists(session_name: str) -> bool:
    result = _sandbox("inspect", session_name, check=False)
    return result.returncode == 0


def _wait_for_running(session_name: str, timeout: int = 600) -> None:
    """Poll until the session reaches running state.

    The first run triggers a lazy base-image build (apt-get install socat git
    rsync docker.io over slirp eth0), which can take several minutes.  The
    default 600 s matches START_VM_TIMEOUT in the daemon.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            arr = _sandbox_json("inspect", session_name)
            if arr and arr[0].get("state") == "running":
                return
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        time.sleep(5)
    raise TimeoutError(
        f"Session {session_name!r} did not reach running within {timeout}s"
    )


# ---------------------------------------------------------------------------
# Module-scoped routing fixture (mirrors test_lite_macos.py)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _route_cli_to_e2e_daemon(sandbox_binaries, sandbox_daemon):
    """Point bare ``sandbox`` calls in this module at the e2e daemon socket.

    Prepends the harness-built CLI directory to PATH and exports
    SANDBOX_SOCKET so _sandbox() reaches the cross-user test daemon.
    """
    socket_path = sandbox_daemon["socket"]
    cli_dir = str(Path(sandbox_binaries.sandbox).resolve().parent)

    prev_socket = os.environ.get("SANDBOX_SOCKET")
    prev_path = os.environ.get("PATH", "")
    os.environ["SANDBOX_SOCKET"] = socket_path
    os.environ["PATH"] = (
        os.pathsep.join([cli_dir, prev_path]) if prev_path else cli_dir
    )
    try:
        yield
    finally:
        if prev_socket is None:
            os.environ.pop("SANDBOX_SOCKET", None)
        else:
            os.environ["SANDBOX_SOCKET"] = prev_socket
        os.environ["PATH"] = prev_path


# ---------------------------------------------------------------------------
# Per-test session fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def lima_session(_macos_operator_agent):
    """Create a full-backend Lima session and tear it down after the test.

    Depends on _macos_operator_agent so the operator agent is running before
    the daemon tries to route the limactl call through the broker.

    Yields the session name.  On teardown, stops and removes the session
    regardless of test outcome.
    """
    name = f"e2e-lima-macos-{int(time.time())}"
    created = False
    try:
        # No --lite flag: targets the default Lima/QEMU backend.
        result = _sandbox("create", "--name", name, capture=True)
        assert result.returncode == 0, (
            f"sandbox create (Lima) failed:\n{result.stderr}"
        )
        created = True
        _wait_for_running(name, timeout=600)
        yield name
    finally:
        if created and _session_exists(name):
            _sandbox("stop", name, check=False)
            _sandbox("rm", name, check=False)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFullBackendMacosCreate:
    """Session creation + basic lifecycle for the macOS full/Lima backend."""

    def test_lima_session_reaches_running(self, lima_session):
        """A default-backend session must reach Running state.

        This exercises the full create flow:
        - agent broker check-in (operator uid 501 → sandbox-agent → broker)
        - per-operator base-image lazy build (apt-get over slirp eth0)
        - socket_vmnet NIC slot allocation
        - Lima VM provision and start
        - session state transition to Running
        """
        info = _inspect_one(lima_session)
        assert info["state"] == "running", (
            f"Expected running, got {info['state']!r}"
        )
        assert info["backend"] == "lima", (
            f"Expected lima backend, got {info['backend']!r}"
        )

    def test_lima_session_has_vmnet_slot(self, lima_session):
        """A full-backend session must consume a NIC slot from VmnetPool."""
        info = _inspect_one(lima_session)
        network = info.get("network", {})
        assert network.get("vmnet_slot") is not None, (
            f"Lima session must hold a vmnet_slot, got network: {network!r}"
        )

    def test_lima_session_exec_works(self, lima_session):
        """sandbox exec into the running Lima session must succeed."""
        result = _sandbox(
            "exec",
            lima_session,
            "--",
            "echo",
            "hello-from-lima",
        )
        assert result.returncode == 0, (
            f"sandbox exec failed:\n{result.stderr}"
        )
        assert "hello-from-lima" in result.stdout


class TestFullBackendMacosEgress:
    """Verify restrict=on egress enforcement for the full (Lima) backend.

    This is the live verification for the B1 fix: the base-image build must
    succeed over slirp eth0 (unrestricted, not in a session VM), while the
    session VM itself operates under the gateway nftables deny-all policy.
    """

    def test_denied_egress_is_blocked(self, lima_session):
        """Traffic to a non-allowlisted host must be blocked inside the session.

        The default policy (restrict=on) routes all egress through the gateway
        pipeline which denies connections to hosts not on the allowlist.
        A curl to example.com (not allowlisted) must fail (timeout or refused).

        This is the core egress-enforcement assertion: proves the session VM
        is behind the gateway pipeline and that restrict=on is in force.
        """
        result = _sandbox(
            "exec",
            lima_session,
            "--",
            "curl",
            "--max-time",
            "10",
            "--silent",
            "--show-error",
            "http://example.com",
            check=False,
        )
        # Curl exits non-zero when blocked: exit 28 (timeout) or exit 7 (refused).
        assert result.returncode != 0, (
            "Expected curl to fail (egress blocked by restrict=on) but it "
            "succeeded — the session VM may not be behind the gateway pipeline, "
            "or restrict=on was not applied.\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )
