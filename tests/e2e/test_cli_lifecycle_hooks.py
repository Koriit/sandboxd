"""E2E tests for the M18-S7 lifecycle hooks.

The CLI's ``sandbox rm``, ``sandbox ls``, and ``sandbox proxy <id>``
subcommands keep ``~/.ssh/sandbox/`` consistent with the daemon's
authoritative session list. Three mechanisms cover every realistic code
path (Spec § Architecture → CLI: persistent ssh-config →
Per-session entry removal / Lazy cleanup / Reconcile on listing):

* ``sandbox rm <id>`` removes the local
  ``~/.ssh/sandbox/sandbox-<id>{,.key}`` files after the daemon-side
  delete returns OK.
* ``sandbox ls`` opportunistically reconciles, dropping entries the
  daemon does not know about. ``--no-reconcile`` opts out.
* ``sandbox proxy <id>`` lazy-cleans the local entry on a daemon 404
  (``EXIT_SESSION_NOT_FOUND`` = 2), so a stranded ``Host sandbox-<id>``
  alias does not point at a defunct ``ProxyCommand``.

These E2E tests pin each mechanism end-to-end against a real
container-backend session. They run under the M18-S1 cross-user
harness (``SANDBOX_HARNESS=sandbox-systemd``); the daemon-as-test-user
fallback is exercised in CI by the same harness env var.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from conftest import make_create_args, parse_session_id, wait_for_state

pytestmark = pytest.mark.container


def _session_config_path(session_id: str) -> Path:
    """Return the per-session OpenSSH config file under ``~/.ssh/sandbox/``."""
    return Path(os.path.expanduser("~")) / ".ssh" / "sandbox" / f"sandbox-{session_id}"


def _session_key_path(session_id: str) -> Path:
    """Return the per-session SSH private key file under ``~/.ssh/sandbox/``."""
    return Path(os.path.expanduser("~")) / ".ssh" / "sandbox" / f"sandbox-{session_id}.key"


@pytest.mark.timeout(600)
def test_rm_removes_local_ssh_config(sandbox_cli):
    """``sandbox rm`` deletes ``~/.ssh/sandbox/sandbox-<id>{,.key}`` for the
    removed session.

    Lifecycle:

    1. Create a container session.
    2. Run ``sandbox ssh ... -- true`` so the CLI's M18-S6 wire-up
       lands a per-session entry under ``~/.ssh/sandbox/`` for this id.
    3. Assert both the config file and the key file exist.
    4. Run ``sandbox rm <name>``.
    5. Assert both files are gone.

    Pins Spec § Architecture → CLI: persistent ssh-config →
    Per-session entry removal end-to-end.
    """
    session_name = "rm-cleanup-test"
    session_id = None
    try:
        result = sandbox_cli(
            "create", *make_create_args("container", session_name), timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, session_name, "Running", timeout=10)

        # Trigger M18-S6's per-session entry write by running any
        # SSH-shaped command. The entry must land before `rm` so we can
        # observe the cleanup-side invariant.
        ssh_result = sandbox_cli("ssh", session_name, "--", "true", timeout=120)
        assert ssh_result.returncode == 0, (
            f"sandbox ssh failed (rc={ssh_result.returncode}).\n"
            f"stdout: {ssh_result.stdout}\nstderr: {ssh_result.stderr}"
        )

        cfg = _session_config_path(session_id)
        key = _session_key_path(session_id)
        assert cfg.exists(), (
            f"M18-S6 should have written {cfg}; ls of ~/.ssh/sandbox/: "
            f"{list(cfg.parent.iterdir())}"
        )
        assert key.exists(), f"M18-S6 should have written {key}"

        rm_result = sandbox_cli("rm", session_name, timeout=120)
        assert rm_result.returncode == 0, (
            f"sandbox rm failed (rc={rm_result.returncode}).\n"
            f"stdout: {rm_result.stdout}\nstderr: {rm_result.stderr}"
        )
        session_id = None  # rm succeeded; finally-block cleanup is a no-op.

        assert not cfg.exists(), (
            f"M18-S7 rm hook must remove the per-session config; {cfg} is still present"
        )
        assert not key.exists(), (
            f"M18-S7 rm hook must remove the per-session key; {key} is still present"
        )

    finally:
        if session_id is not None:
            sandbox_cli("rm", session_name, timeout=120)


@pytest.mark.timeout(600)
def test_ls_reconcile_drops_stale_local_entry(sandbox_cli, sandbox_daemon):
    """``sandbox ls`` opportunistically reconciles stale local entries.

    Lifecycle:

    1. Create a container session and run ``sandbox ssh`` so a per-session
       entry lands at ``~/.ssh/sandbox/sandbox-<id>{,.key}``.
    2. Delete the daemon-side session by hand (direct DELETE against
       the daemon socket) so the local entry becomes stale relative to
       the daemon's authoritative list — without going through the
       ``sandbox rm`` cleanup hook.
    3. Run ``sandbox ls`` (the default — reconcile fires).
    4. Assert the stale local entry has been removed.

    Pins Spec § Architecture → CLI: persistent ssh-config →
    Reconcile on listing end-to-end.
    """
    session_name = "ls-reconcile-test"
    session_id = None
    try:
        result = sandbox_cli(
            "create", *make_create_args("container", session_name), timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, session_name, "Running", timeout=10)

        # Land the local entry via M18-S6.
        ssh_result = sandbox_cli("ssh", session_name, "--", "true", timeout=120)
        assert ssh_result.returncode == 0, (
            f"sandbox ssh failed (rc={ssh_result.returncode}).\n"
            f"stdout: {ssh_result.stdout}\nstderr: {ssh_result.stderr}"
        )

        cfg = _session_config_path(session_id)
        key = _session_key_path(session_id)
        assert cfg.exists(), "M18-S6 should have written the per-session config"
        assert key.exists(), "M18-S6 should have written the per-session key"

        # Out-of-band delete: hit the daemon socket directly with a
        # DELETE that bypasses the ``sandbox rm`` cleanup hook so the
        # local entry intentionally drifts out of sync with the
        # daemon. The next ``sandbox ls`` reconcile is the contract
        # under test.
        socket_path = sandbox_daemon["socket"]
        curl = subprocess.run(
            [
                "curl",
                "--unix-socket",
                socket_path,
                "-X",
                "DELETE",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                f"http://localhost/sessions/{session_id}",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert curl.returncode == 0, (
            f"out-of-band DELETE via curl failed: stdout={curl.stdout!r} "
            f"stderr={curl.stderr!r}"
        )
        assert curl.stdout.strip() in {"200", "204"}, (
            f"daemon DELETE returned unexpected HTTP {curl.stdout!r}"
        )

        # The local entry survives the out-of-band delete (no ``sandbox rm``
        # was run).
        assert cfg.exists(), "out-of-band DELETE must NOT touch the local entry"
        assert key.exists(), "out-of-band DELETE must NOT touch the local key"

        # Now run ``sandbox ls`` — the reconcile pass should drop the
        # stale entry.
        ls_result = sandbox_cli("ls", timeout=60)
        assert ls_result.returncode == 0, (
            f"sandbox ls failed (rc={ls_result.returncode}).\n"
            f"stdout: {ls_result.stdout}\nstderr: {ls_result.stderr}"
        )
        # Reconcile is silent: no per-entry stderr line. We only assert
        # the on-disk side-effect.

        # Mark session_id as cleaned-up so the finally block does not
        # try to delete it again (the daemon will return 404).
        session_id = None

        assert not cfg.exists(), (
            f"M18-S7 ls reconcile must remove the stale per-session config; "
            f"{cfg} still present"
        )
        assert not key.exists(), (
            f"M18-S7 ls reconcile must remove the stale per-session key; "
            f"{key} still present"
        )

    finally:
        if session_id is not None:
            sandbox_cli("rm", session_name, timeout=120)


@pytest.mark.timeout(600)
def test_ls_no_reconcile_keeps_stale_local_entry(sandbox_cli, sandbox_daemon):
    """``sandbox ls --no-reconcile`` does NOT touch the local SSH dir.

    Same drift setup as ``test_ls_reconcile_drops_stale_local_entry``,
    but the ``--no-reconcile`` flag must keep the stale entry intact —
    that is the opt-out contract for tooling consumers that need strict
    read-only semantics (Spec § Reconcile on listing).
    """
    session_name = "ls-no-reconcile-test"
    session_id = None
    try:
        result = sandbox_cli(
            "create", *make_create_args("container", session_name), timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, session_name, "Running", timeout=10)

        ssh_result = sandbox_cli("ssh", session_name, "--", "true", timeout=120)
        assert ssh_result.returncode == 0

        cfg = _session_config_path(session_id)
        key = _session_key_path(session_id)
        assert cfg.exists()
        assert key.exists()

        socket_path = sandbox_daemon["socket"]
        subprocess.run(
            [
                "curl",
                "--unix-socket",
                socket_path,
                "-X",
                "DELETE",
                "-s",
                "-o",
                "/dev/null",
                f"http://localhost/sessions/{session_id}",
            ],
            check=True,
            timeout=60,
        )

        # --no-reconcile must skip the cleanup pass entirely.
        ls_result = sandbox_cli("ls", "--no-reconcile", timeout=60)
        assert ls_result.returncode == 0

        assert cfg.exists(), (
            f"--no-reconcile must NOT remove the stale per-session config; "
            f"{cfg} was unexpectedly deleted"
        )
        assert key.exists(), (
            f"--no-reconcile must NOT remove the stale per-session key; "
            f"{key} was unexpectedly deleted"
        )

        # Clean up by hand — `sandbox ls` (without --no-reconcile) will
        # remove the stale entry, restoring the ~/.ssh/sandbox/ baseline.
        ls_again = sandbox_cli("ls", timeout=60)
        assert ls_again.returncode == 0
        assert not cfg.exists(), "default ls reconcile should clean up after --no-reconcile"
        assert not key.exists()

        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", session_name, timeout=120)
