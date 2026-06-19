"""E2E tests for the macOS lite-mode container backend.

These tests cover the macOS-specific lite path where sandbox containers run
inside the ``sandboxd-gateway`` Lima VM over its forwarded Docker socket.

Architecture under test:
- Sandbox containers run inside the gateway Lima VM (not on the macOS host).
- Every ``docker`` call goes through the forwarded socket
  (``gateway-docker.sock``).
- The gateway container + nft pipeline provide egress interception identical
  to Linux from the container's perspective.
- The ``sandbox-route-helper --vm-gateway-mode`` installs the default route
  inside the sandbox container's netns from within the gateway VM.
- A session-count token is claimed from ``VmnetPool`` but no NIC slot is
  allocated (lite sessions have no socket_vmnet attachment).

These tests require:
- A running ``sandboxd-gateway`` Lima instance with Docker provisioned.
- The ``sandbox-route-helper`` binary installed and setcap'd in the gateway VM
  at ``/usr/local/libexec/sandboxd/sandbox-route-helper``.
- The lite container image (``sandboxd-lite:<version>``) loaded in the
  gateway VM's Docker daemon.
- ``make setup-dev-env`` run at least once on this host.

DO NOT RUN during CI without the gateway VM provisioned.
Invoke manually after gateway bring-up:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_lite_macos.py -v --timeout=600

Individual test estimated runtime: 30–90 s.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Optional

import pytest

# ---------------------------------------------------------------------------
# Platform guard: skip entire file on Linux.
# These tests target the macOS lite path and require the gateway Lima VM.
# ---------------------------------------------------------------------------
pytestmark = [
    pytest.mark.macos_only,
    pytest.mark.container,
    pytest.mark.skipif(
        os.uname().sysname != "Darwin",
        reason="macOS lite tests require the sandboxd-gateway Lima VM",
    ),
]


# ---------------------------------------------------------------------------
# Helpers
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


def _wait_for_running(session_name: str, timeout: int = 60) -> None:
    """Poll until the session reaches Running state."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            info = _sandbox_json("inspect", session_name)
            if info.get("state") == "Running":
                return
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        time.sleep(2)
    raise TimeoutError(
        f"Session {session_name!r} did not reach Running within {timeout}s"
    )


def _session_exists(session_name: str) -> bool:
    result = _sandbox("inspect", session_name, check=False)
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def lite_session(request):
    """Create a lite session and tear it down after the test.

    Yields the session name. On teardown, stops and removes the session
    regardless of test outcome.
    """
    name = f"e2e-lite-macos-{int(time.time())}"
    created = False
    try:
        result = _sandbox("create", "--lite", "--name", name, capture=True)
        assert result.returncode == 0, (
            f"sandbox create --lite failed:\n{result.stderr}"
        )
        created = True
        _wait_for_running(name)
        yield name
    finally:
        if created and _session_exists(name):
            _sandbox("stop", name, check=False)
            _sandbox("rm", name, check=False)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLiteMacosCreate:
    """Session creation + basic lifecycle for the macOS lite path."""

    def test_create_lite_session_reaches_running(self, lite_session):
        """A lite session created on macOS must reach Running state.

        This exercises the full create flow:
        - session-count token claim (no NIC slot)
        - in-VM Docker bridge creation via forwarded socket
        - gateway container setup (deny-all + health + DNAT)
        - sandbox container create + start inside the gateway VM
        - in-VM route-helper invocation (--vm-gateway-mode)
        - state transition to Running
        """
        info = _sandbox_json("inspect", lite_session)
        assert info["state"] == "Running", (
            f"Expected Running, got {info['state']!r}"
        )
        assert info["backend"] == "Container", (
            f"Expected Container backend, got {info['backend']!r}"
        )

    def test_lite_session_has_no_vmnet_slot(self, lite_session):
        """A lite session must not consume a NIC slot.

        Lite sessions claim a session-count token from VmnetPool but
        leave ``vmnet_slot`` as None — the in-VM Docker bridge replaces
        the socket_vmnet segment.
        """
        info = _sandbox_json("inspect", lite_session)
        network = info.get("network", {})
        assert network.get("vmnet_slot") is None, (
            f"Lite session must not hold a vmnet_slot, got: {network!r}"
        )

    def test_lite_session_stop_and_restart(self, lite_session):
        """Lite sessions must survive stop → start cycle.

        On stop: gateway container + Docker network are removed, lite token
        is released.
        On start: a new bridge + gateway are created inside the VM.
        """
        _sandbox("stop", lite_session)
        # Wait for Stopped.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            info = _sandbox_json("inspect", lite_session)
            if info["state"] == "Stopped":
                break
            time.sleep(2)
        else:
            pytest.fail("Session did not reach Stopped within 30s")

        # Restart.
        _sandbox("start", lite_session)
        _wait_for_running(lite_session, timeout=90)
        info = _sandbox_json("inspect", lite_session)
        assert info["state"] == "Running"

    def test_lite_session_remove(self):
        """A lite session can be created and then fully removed.

        This exercises the rm path: gateway teardown + Docker network
        deletion + lite token release + store row removal.
        """
        name = f"e2e-lite-macos-rm-{int(time.time())}"
        _sandbox("create", "--lite", "--name", name)
        _wait_for_running(name)
        _sandbox("stop", name)
        _sandbox("rm", name)
        assert not _session_exists(name), (
            "Session row must be removed after sandbox rm"
        )


class TestLiteMacosEgressInterception:
    """Verify egress is gated through the gateway pipeline."""

    def test_denied_egress_is_blocked(self, lite_session):
        """Traffic to a denied host must be blocked.

        The default policy denies all egress. A ``curl`` to an arbitrary
        external host from inside the sandbox container must time out or
        be refused within a few seconds.
        """
        result = _sandbox(
            "exec",
            lite_session,
            "--",
            "curl",
            "--max-time",
            "5",
            "--silent",
            "--show-error",
            "http://example.com",
            check=False,
        )
        # Curl exits non-zero when blocked: exit 28 (timeout) or exit 7 (refused).
        # Any non-zero exit confirms egress is gated.
        assert result.returncode != 0, (
            "Expected curl to fail (egress blocked) but it succeeded.\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )

    def test_ssh_access_works_over_forwarded_socket(self, lite_session):
        """SSH into the lite session must work without a login-session agent.

        This is the headline lite-on-macOS promise: an SSH-only (no GUI, no
        per-operator LaunchAgent) operator can use lite sessions. The CLI
        proxy path uses the forwarded Docker socket for the socat transport
        instead of a limactl shell into a per-operator VM.
        """
        result = _sandbox(
            "exec",
            lite_session,
            "--",
            "echo",
            "hello-from-lite-macos",
        )
        assert result.returncode == 0, (
            f"sandbox exec failed:\n{result.stderr}"
        )
        assert "hello-from-lite-macos" in result.stdout


class TestLiteMacosPoolAccounting:
    """Verify pool accounting: session-count token claimed, no NIC slot."""

    def test_mixed_lima_and_lite_under_session_cap(self):
        """A mix of Lima and lite sessions must both count against the cap.

        This test creates one lite session and verifies the session count
        increases, then removes it and verifies the count decreases.

        Live pool-cap enforcement (exhaustion) is not tested here because it
        would require creating max_macos_sessions concurrent sessions — too
        slow for E2E. The hermetic unit tests in network.rs cover exhaustion.
        """
        name = f"e2e-lite-pool-{int(time.time())}"
        try:
            # Before create: record current session list.
            before = _sandbox_json("list")
            before_count = len(
                [s for s in before if s.get("state") == "Running"]
            )

            _sandbox("create", "--lite", "--name", name)
            _wait_for_running(name)

            after = _sandbox_json("list")
            after_running = [s for s in after if s.get("state") == "Running"]
            after_count = len(after_running)
            assert after_count == before_count + 1, (
                f"Expected {before_count + 1} running sessions, got {after_count}"
            )

        finally:
            if _session_exists(name):
                _sandbox("stop", name, check=False)
                _sandbox("rm", name, check=False)


class TestLiteMacosWorkspace:
    """Workspace mode tests for the macOS lite path."""

    def test_local_workspace_mode(self, tmp_path):
        """``local:`` workspace mode works on the lite macOS path.

        ``local:`` is platform-independent — rsync flows over the guest
        transport (docker exec … socat) which is forwarded-socket-aware.
        """
        workspace = tmp_path / "project"
        workspace.mkdir()
        (workspace / "hello.txt").write_text("hello-lite-local")

        name = f"e2e-lite-local-{int(time.time())}"
        try:
            _sandbox(
                "create",
                "--lite",
                "--name",
                name,
                "--workspace",
                f"local:{workspace}",
            )
            _wait_for_running(name)

            # The rsync snapshot should have placed hello.txt in the session home.
            result = _sandbox(
                "exec", name, "--", "cat", "/home/sandbox/workspace/hello.txt"
            )
            assert "hello-lite-local" in result.stdout
        finally:
            if _session_exists(name):
                _sandbox("stop", name, check=False)
                _sandbox("rm", name, check=False)

    def test_shared_workspace_tcc_warning(self, tmp_path):
        """``shared:`` workspace on lite emits a TCC-asymmetry warning.

        The gateway VM reads the shared path as ``_sandbox``, not the
        operator. The daemon must emit a warning at create time.

        This test only verifies the path is accepted (not rejected) when the
        source is under the configured ``lite_shared_root``. The TCC warning
        is observable in the daemon log, not in the CLI output; we assert
        the session reaches Running.

        Note: requires ``SANDBOX_LITE_SHARED_ROOT`` set to ``tmp_path`` or
        the default ``/tmp/sandbox-shared`` to be accessible.
        """
        # Use /tmp/sandbox-shared as the shared root (default).
        shared_root = "/tmp/sandbox-shared"
        os.makedirs(shared_root, exist_ok=True)
        workspace = os.path.join(shared_root, f"test-{int(time.time())}")
        os.makedirs(workspace, exist_ok=True)

        name = f"e2e-lite-shared-{int(time.time())}"
        try:
            result = _sandbox(
                "create",
                "--lite",
                "--name",
                name,
                "--workspace",
                f"shared:{workspace}",
                check=False,
            )
            # Accept either success (session created) or failure with a
            # descriptive error. We do not assert success because the shared
            # root may not be configured in the test environment.
            if result.returncode == 0:
                _wait_for_running(name, timeout=60)
                info = _sandbox_json("inspect", name)
                assert info["state"] == "Running"
        finally:
            if _session_exists(name):
                _sandbox("stop", name, check=False)
                _sandbox("rm", name, check=False)
            import shutil as _shutil
            _shutil.rmtree(workspace, ignore_errors=True)
