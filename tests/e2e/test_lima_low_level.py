"""E2E tests ported from sandboxd/sandbox-core/tests/lima_integration.rs.

The original tests drove ``LimaManager`` / ``LimaRuntime`` directly
(bypassing the daemon) to exercise inert (never-started) VMs.  This
file exercises the same behaviour through the public CLI surface.

Key adaptation notes
--------------------
* ``sandbox create`` always creates **and starts** the VM (state ->
  Running).  Tests that originally checked ``Stopped`` status now do so
  after an explicit ``sandbox stop`` call.
* ``refresh-guest`` is not exposed as a CLI subcommand or HTTP route.
  ``test_lima_guest_refresh_backend`` exercises the nearest observable
  equivalent: ``sandbox stop`` followed by ``sandbox start``, which
  internally calls ``refresh_guest_binary`` when a guest-protocol
  version mismatch is detected.  The outcome contract matches the
  original test: ``rc == 0`` (compatible agent) or a non-zero exit
  whose stderr names a Lima/guest domain step.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from conftest import (
    _VM_RESOURCE_ARGS,
    lima_vm_name,
    parse_session_id,
    wait_for_state,
)

# Whole-file Lima-only: gates the per-test Lima prereq fixture and
# lets ``-m "not lima"`` exclude this file on container-only runs.
pytestmark = pytest.mark.lima


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def limactl_list_json() -> list[dict]:
    """Run ``limactl list --json`` and return parsed entries."""
    result = subprocess.run(
        ["limactl", "list", "--json"],
        capture_output=True,
        text=True,
        timeout=30,
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.timeout(600)
def test_lima_create_and_delete(sandbox_cli):
    """Create a Lima VM via the CLI, verify it appears in limactl, destroy it.

    Port of ``integration_lima_create_and_delete``.
    """
    session_id = None
    try:
        # 1. Create the session (create + start).
        result = sandbox_cli(
            "create",
            "--name", "ll-create-delete",
            *_VM_RESOURCE_ARGS,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

        # 2. Parse session id.
        session_id = parse_session_id(result.stdout)
        vm_name = lima_vm_name(session_id)

        # 3. Verify the Lima VM appears in limactl list.
        lima_vms = limactl_list_json()
        vm_names = [v.get("name", "") for v in lima_vms]
        assert vm_name in vm_names, (
            f"Expected Lima VM {vm_name!r} in limactl list, got: {vm_names}"
        )

        # 4. Destroy the session.
        rm_result = sandbox_cli("rm", "ll-create-delete", timeout=120)
        assert rm_result.returncode == 0, (
            f"sandbox rm failed (rc={rm_result.returncode}).\n"
            f"stdout: {rm_result.stdout}\nstderr: {rm_result.stderr}"
        )

        # 5. Verify the VM is gone from limactl.
        lima_vms = limactl_list_json()
        vm_names = [v.get("name", "") for v in lima_vms]
        assert vm_name not in vm_names, (
            f"Lima VM {vm_name!r} still present after sandbox rm. VMs: {vm_names}"
        )

        session_id = None  # cleanup not needed; test passed

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ll-create-delete", timeout=120)


@pytest.mark.timeout(600)
def test_lima_runtime_status_stopped(sandbox_cli):
    """Create a session, stop it, assert CLI reports state ``stopped``.

    Port of ``integration_lima_runtime_lifecycle`` (status-is-Stopped
    assertion).

    Adaptation: ``sandbox create`` always starts the VM (state =
    ``running``).  We stop it with ``sandbox stop`` to reach the
    ``Stopped`` state the original inert-VM test checked.
    """
    session_id = None
    try:
        # 1. Create (and start) the session.
        result = sandbox_cli(
            "create",
            "--name", "ll-status-stopped",
            *_VM_RESOURCE_ARGS,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)

        # Wait for Running before we try to stop.
        wait_for_state(sandbox_cli, "ll-status-stopped", "Running", timeout=30)

        # 2. Stop the session so the VM reaches Stopped state.
        stop_result = sandbox_cli("stop", "ll-status-stopped", timeout=120)
        assert stop_result.returncode == 0, (
            f"sandbox stop failed (rc={stop_result.returncode}).\n"
            f"stdout: {stop_result.stdout}\nstderr: {stop_result.stderr}"
        )

        # 3. Assert CLI reports state = stopped.
        describe_result = sandbox_cli("describe", session_id, timeout=30)
        assert describe_result.returncode == 0, (
            f"sandbox describe failed (rc={describe_result.returncode}).\n"
            f"stdout: {describe_result.stdout}\nstderr: {describe_result.stderr}"
        )
        assert "State:        stopped" in describe_result.stdout, (
            f"Expected 'State:        stopped' in describe output.\n"
            f"stdout: {describe_result.stdout}"
        )

        # 4. Cleanup.
        sandbox_cli("rm", "ll-status-stopped", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ll-status-stopped", timeout=120)


@pytest.mark.timeout(600)
def test_lima_transport_socat_spawn(sandbox_cli):
    """Assert that spawning socat through limactl shell does not raise FileNotFoundError.

    Port of ``integration_lima_transport_socat_smoke``.

    The assertion is that the **spawn itself** does not raise
    ``FileNotFoundError`` or similar — i.e. ``limactl`` and ``socat``
    are on PATH and the argument wiring is correct.  We do not assert
    that socat actually connects to the guest agent's TCP port.
    """
    session_id = None
    try:
        # 1. Create (and start) the session.
        result = sandbox_cli(
            "create",
            "--name", "ll-socat-smoke",
            *_VM_RESOURCE_ARGS,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)

        # 2. Derive the VM name: sandbox-<session_id>.
        vm_name = lima_vm_name(session_id)

        # 3. Spawn limactl shell ... socat.  We use a very short timeout
        #    because we only need to confirm the subprocess starts, not
        #    that the socat session completes.  The process may exit
        #    non-zero (socat can't connect if the agent isn't listening
        #    on 5123 yet, or the session is in an intermediate state).
        #    What must NOT happen: FileNotFoundError (missing binary) or
        #    PermissionError (argument wiring broken).
        try:
            spawn_result = subprocess.run(
                ["limactl", "shell", vm_name, "--", "socat", "-", "TCP:127.0.0.1:5123"],
                capture_output=True,
                timeout=10,
            )
            # Any exit code is acceptable; the spawn itself succeeded.
        except FileNotFoundError as exc:
            pytest.fail(
                f"limactl shell socat spawn raised FileNotFoundError: {exc}. "
                f"Ensure limactl and socat are on PATH."
            )
        except subprocess.TimeoutExpired:
            # Timeout means the process ran long enough that we hit our
            # deadline — the spawn succeeded, which is what we care about.
            pass

        # 4. Cleanup.
        sandbox_cli("rm", "ll-socat-smoke", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ll-socat-smoke", timeout=120)


@pytest.mark.timeout(600)
def test_lima_guest_refresh_backend(sandbox_cli):
    """Exercise the Lima guest-refresh code path via sandbox stop + start.

    Port of ``integration_guest_refresh_lima_backend``.

    ``refresh-guest`` is not exposed as a standalone CLI subcommand or
    HTTP endpoint.  ``start_session`` (the ``sandbox start`` handler)
    internally calls ``runtime.refresh_guest_binary`` when the persisted
    guest protocol version does not match the daemon's compiled-in
    constant (spec § 7.5 / Spec 2 § 3.3).

    This test exercises the nearest observable equivalent:
    1. ``sandbox create`` — create + start the session.
    2. ``sandbox stop`` — stop the session (VM halts).
    3. ``sandbox start`` — re-start; if there is a guest version
       mismatch the daemon calls ``refresh_guest_binary`` automatically.

    Outcome contract (mirrors the Rust original):
    * ``rc == 0`` — agent compatible, start completed successfully.
    * non-zero rc with stderr mentioning ``guest``, ``limactl``, or
      ``sandbox-guest`` — Lima domain error from the refresh path.
    * Anything else (generic internal error with no Lima context) — FAIL.
    """
    session_id = None
    try:
        # 1. Create (and start) the session.
        result = sandbox_cli(
            "create",
            "--name", "ll-refresh-guest",
            *_VM_RESOURCE_ARGS,
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)

        # Wait for Running before we stop.
        wait_for_state(sandbox_cli, "ll-refresh-guest", "Running", timeout=30)

        # 2. Stop the session.
        stop_result = sandbox_cli("stop", "ll-refresh-guest", timeout=120)
        assert stop_result.returncode == 0, (
            f"sandbox stop failed (rc={stop_result.returncode}).\n"
            f"stdout: {stop_result.stdout}\nstderr: {stop_result.stderr}"
        )

        # 3. Re-start — triggers refresh_guest_binary if needed.
        start_result = sandbox_cli("start", "ll-refresh-guest", timeout=600)

        if start_result.returncode == 0:
            # Happy path: compatible (or refreshed) agent, start succeeded.
            pass
        else:
            # Failure path: accept only Lima-domain errors.
            combined = (start_result.stdout + start_result.stderr).lower()
            assert any(
                kw in combined for kw in ("guest", "limactl", "sandbox-guest")
            ), (
                f"sandbox start failed with a non-Lima-domain error.\n"
                f"Expected stderr/stdout to mention 'guest', 'limactl', or "
                f"'sandbox-guest'; got:\n"
                f"stdout: {start_result.stdout}\nstderr: {start_result.stderr}"
            )

    finally:
        # 4. Best-effort cleanup even if start (or stop) failed.
        if session_id is not None:
            vm_name = lima_vm_name(session_id)
            sandbox_cli("rm", "ll-refresh-guest", timeout=120)

            # 5. Verify the VM is gone.
            lima_vms = limactl_list_json()
            vm_names = [v.get("name", "") for v in lima_vms]
            assert vm_name not in vm_names, (
                f"Lima VM {vm_name!r} still present after cleanup. VMs: {vm_names}"
            )
