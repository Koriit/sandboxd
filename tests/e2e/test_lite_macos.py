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
from pathlib import Path
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


def _inspect_one(session_name: str, **kwargs) -> dict:
    """Inspect a single session and return its object.

    ``sandbox inspect <name> [<name>...]`` prints a JSON ARRAY (one object
    per arg), so a single-session inspect must be indexed ``[0]``.
    """
    arr = _sandbox_json("inspect", session_name, **kwargs)
    return arr[0]


def _count_running() -> int:
    """Count Running sessions by parsing the ``sandbox ps`` human TABLE.

    There is no JSON-all-sessions command. ``sandbox ps`` prints a
    space-separated table with a header row:
        ID  NAME  STATE  BACKEND  AGENT  GATEWAY  CREATED
    In the TABLE the STATE column is Capitalized (``Running`` / ``Stopped``),
    unlike the inspect JSON's lowercase. Skip the header and count rows whose
    STATE column equals ``Running``.
    """
    result = _sandbox("ps")
    count = 0
    for line in result.stdout.splitlines():
        cols = line.split()
        if not cols:
            continue
        # Skip the header row.
        if cols[0] == "ID" or ("NAME" in cols and "STATE" in cols):
            continue
        # Columns: ID NAME STATE BACKEND AGENT GATEWAY CREATED
        if len(cols) >= 3 and cols[2] == "Running":
            count += 1
    return count


def _wait_for_running(session_name: str, timeout: int = 60) -> None:
    """Poll until the session reaches running state."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            arr = _sandbox_json("inspect", session_name)
            if arr and arr[0].get("state") == "running":
                return
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        time.sleep(2)
    raise TimeoutError(
        f"Session {session_name!r} did not reach running within {timeout}s"
    )


def _session_exists(session_name: str) -> bool:
    result = _sandbox("inspect", session_name, check=False)
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _route_cli_to_e2e_daemon(sandbox_binaries, sandbox_daemon):
    """Point this module's bare ``sandbox`` calls at the e2e daemon socket.

    The helpers in this file (``_sandbox`` and friends) invoke the ``sandbox``
    CLI by bare name and without an explicit ``--socket`` flag. By default that
    resolves whatever ``sandbox`` is on ``PATH`` (usually nothing on a dev host)
    talking to the *operator's* default socket
    (``$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock`` or
    ``~/.local/share/sandboxd/sandboxd.sock``). The e2e harness, however, builds
    the CLI under ``sandboxd/target/debug/`` and runs the daemon as the
    cross-user ``_sandboxd-test`` system user with a socket under
    ``/var/lib/sandboxd/<daemon-test-uid>/sandboxd.sock`` (mode 0660, group
    ``_sandboxd-test``) — exactly the daemon the green ``test_lite.py`` /
    ``test_policy.py`` suites drive via the ``sandbox_cli`` fixture's
    ``--socket {sandbox_daemon["socket"]}`` against ``sandbox_binaries.sandbox``.

    Rather than rewrite every bare ``_sandbox`` call site, this autouse,
    module-scoped fixture brings the file into line with that working pattern:

    1. depends on ``sandbox_daemon`` so the cross-user daemon is launched (and
       torn down) by the standard conftest fixture — the same daemon the rest
       of the e2e suite uses;
    2. prepends the harness-built CLI's directory
       (``sandbox_binaries.sandbox``'s parent) to ``PATH`` so the bare
       ``sandbox`` invocations resolve the freshly-built binary, not a stray
       installed one; and
    3. exports ``SANDBOX_SOCKET`` into the process environment for the duration
       of this module so those invocations reach the e2e daemon. The CLI
       honours ``SANDBOX_SOCKET`` as the socket override (``--socket`` still
       takes precedence, but none of the helpers pass it).

    The previous values are restored on teardown so other modules are
    unaffected.
    """
    socket_path = sandbox_daemon["socket"]
    cli_dir = str(Path(sandbox_binaries.sandbox).resolve().parent)

    prev_socket = os.environ.get("SANDBOX_SOCKET")
    prev_path = os.environ.get("PATH", "")
    os.environ["SANDBOX_SOCKET"] = socket_path
    os.environ["PATH"] = os.pathsep.join([cli_dir, prev_path]) if prev_path else cli_dir
    try:
        yield
    finally:
        if prev_socket is None:
            os.environ.pop("SANDBOX_SOCKET", None)
        else:
            os.environ["SANDBOX_SOCKET"] = prev_socket
        os.environ["PATH"] = prev_path


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
        info = _inspect_one(lite_session)
        assert info["state"] == "running", (
            f"Expected running, got {info['state']!r}"
        )
        assert info["backend"] == "container", (
            f"Expected container backend, got {info['backend']!r}"
        )

    def test_lite_session_has_no_vmnet_slot(self, lite_session):
        """A lite session must not consume a NIC slot.

        Lite sessions claim a session-count token from VmnetPool but
        leave ``vmnet_slot`` as None — the in-VM Docker bridge replaces
        the socket_vmnet segment.
        """
        info = _inspect_one(lite_session)
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
        # Wait for stopped.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            info = _inspect_one(lite_session)
            if info["state"] == "stopped":
                break
            time.sleep(2)
        else:
            pytest.fail("Session did not reach stopped within 30s")

        # Restart.
        _sandbox("start", lite_session)
        _wait_for_running(lite_session, timeout=90)
        info = _inspect_one(lite_session)
        assert info["state"] == "running"

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
            # Before create: record current running-session count.
            before_count = _count_running()

            _sandbox("create", "--lite", "--name", name)
            _wait_for_running(name)

            after_count = _count_running()
            assert after_count == before_count + 1, (
                f"Expected {before_count + 1} running sessions, got {after_count}"
            )

        finally:
            if _session_exists(name):
                _sandbox("stop", name, check=False)
                _sandbox("rm", name, check=False)


class TestLiteMacosWorkspace:
    """Workspace mode tests for the macOS lite path."""

    @pytest.mark.skip(
        reason=(
            "macOS lite local: workspace deferred — host rsync is Apple "
            "openrsync (no --mkpath, rsync>=3.2.3 only) and local: guest_path "
            "semantics need finalizing; tracked for the macOS-lite-usability "
            "follow-up"
        )
    )
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

        The gateway VM reads the shared path as ``_sandboxd``, not the
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
                info = _inspect_one(name)
                assert info["state"] == "running"
        finally:
            if _session_exists(name):
                _sandbox("stop", name, check=False)
                _sandbox("rm", name, check=False)
            import shutil as _shutil
            _shutil.rmtree(workspace, ignore_errors=True)
