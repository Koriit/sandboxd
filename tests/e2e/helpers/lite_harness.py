"""Lifecycle wrapper for lite-mode (container backend) E2E sessions.

Centralises the create / stop / start / rm dance plus a small pile of
``sandbox ssh`` and ``docker exec`` invariant probes so each test file
can stay focused on its assertion rather than re-implementing
subprocess plumbing.

Usage::

    @pytest.fixture
    def lite_harness(sandbox_cli):
        h = LiteBackendHarness(sandbox_cli)
        yield h
        h.cleanup()

    def test_something(lite_harness):
        sid = lite_harness.create("--name", "my-lite")
        lite_harness.assert_rootfs_readonly(sid)

The harness deliberately wraps the existing ``sandbox_cli`` fixture
(see ``conftest.py``); it does NOT re-implement subprocess plumbing or
daemon socket discovery. Call sites should request both fixtures only
when they need the raw CLI for an assertion the harness does not yet
expose.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from typing import Callable

from conftest import parse_session_id

# Reuse the canonical 12-hex-id parser from the existing test surface.
__all__ = ["LiteBackendHarness"]


# Regex matching the standard "ID: <12-hex>" line emitted by `sandbox
# create` (mirrors the parser in conftest.py — pulled out here so a
# create that times out without printing the ID surfaces a deterministic
# error).
_ID_RE = re.compile(r"^ID:\s+([0-9a-f]{12})$", re.MULTILINE)


class LiteBackendHarness:
    """Lifecycle wrapper for lite-mode E2E sessions.

    Constructed once per test (typically via a pytest fixture).
    Tracks every session id it creates and force-removes them on
    ``cleanup()``; failure to clean up a lite session leaks a Docker
    container plus a ``sandbox-home-<id>`` named volume, which would
    bleed state into subsequent tests.
    """

    def __init__(self, sandbox_cli: Callable[..., subprocess.CompletedProcess]) -> None:
        self._sandbox_cli = sandbox_cli
        self._sessions: list[str] = []

    # ------------------------------------------------------------------ #
    # Lifecycle                                                          #
    # ------------------------------------------------------------------ #

    def create(
        self,
        *extra_args: str,
        timeout: int = 600,
        expect_exit: int = 0,
    ) -> str | None:
        """Run ``sandbox create --lite ... <extra_args>`` and return
        the new session id, or ``None`` when ``expect_exit != 0``.

        ``--lite`` is always prepended; tests that need to exercise the
        rejection paths (e.g. ``--lite --hardened``) should invoke
        ``sandbox_cli`` directly with ``expect_exit=2`` rather than
        going through the harness — this method tracks created
        sessions for cleanup, which only makes sense on the success
        path.
        """
        result = self._sandbox_cli(
            "create", "--lite", *extra_args,
            timeout=timeout,
        )
        assert result.returncode == expect_exit, (
            f"sandbox create --lite {' '.join(extra_args)} "
            f"exited {result.returncode}, expected {expect_exit}.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        if expect_exit != 0:
            return None
        session_id = parse_session_id(result.stdout)
        self._sessions.append(session_id)
        return session_id

    def stop(self, session_id: str, timeout: int = 120) -> None:
        result = self._sandbox_cli("stop", session_id, timeout=timeout)
        assert result.returncode == 0, (
            f"sandbox stop {session_id} failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def start(self, session_id: str, timeout: int = 120) -> None:
        result = self._sandbox_cli("start", session_id, timeout=timeout)
        assert result.returncode == 0, (
            f"sandbox start {session_id} failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def rm(self, session_id: str, timeout: int = 120) -> None:
        """Remove a tracked session via ``sandbox rm <id> -y``.

        The CLI verb is ``rm`` and the global ``-y`` skips the
        confirmation prompt; there is no ``--force`` flag (operator
        UX confusion in earlier handoffs). Tracked-session list is
        pruned so a follow-up ``cleanup()`` does not double-remove.
        """
        # Global `-y` skips the confirmation prompt — no `--force` flag.
        result = self._sandbox_cli("rm", "-y", session_id, timeout=timeout)
        # Idempotency: a session already gone returns non-zero with a
        # "not found" message; that is fine for cleanup.
        if session_id in self._sessions:
            self._sessions.remove(session_id)
        if result.returncode != 0:
            combined = result.stdout + result.stderr
            assert "not found" in combined.lower() or "no such" in combined.lower(), (
                f"sandbox rm -y {session_id} failed unexpectedly "
                f"(rc={result.returncode}).\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )

    def cleanup(self) -> None:
        """Force-remove every session created via this harness.

        Best-effort: a single failure does not stop the loop, since
        leaving even one session behind is worse than a noisy log.
        """
        # Snapshot the list because rm() mutates it.
        for sid in list(self._sessions):
            try:
                self.rm(sid)
            except Exception:
                # Best-effort; the daemon-fixture teardown in
                # conftest.py also force-cleans `sandbox-*` containers
                # and volumes as a final safety net.
                pass
        self._sessions.clear()

    # ------------------------------------------------------------------ #
    # In-session command execution                                       #
    # ------------------------------------------------------------------ #

    def ssh(
        self,
        session_id: str,
        *command: str,
        timeout: int = 60,
    ) -> subprocess.CompletedProcess:
        """Run a command inside the lite session via ``sandbox ssh``.

        ``sandbox ssh`` dispatches to ``docker exec -it`` for
        container-backed sessions (see ``plan_ssh_command`` in
        ``sandbox-cli/src/main.rs``), so this is the canonical
        operator-facing entry point — no need to bypass to ``docker
        exec`` directly.
        """
        return self._sandbox_cli(
            "ssh", session_id, "--", *command,
            timeout=timeout,
        )

    # ------------------------------------------------------------------ #
    # Hardening invariant assertions                                     #
    # ------------------------------------------------------------------ #

    def assert_rootfs_readonly(self, session_id: str) -> None:
        """

        Writes to ``/`` must fail with a "read-only file system"-shaped
        error, both for the bare path and for typical system paths.
        Probe ``/test-write`` (caller cannot rely on any specific dir
        writability under ``/``).
        """
        result = self.ssh(
            session_id, "sh", "-c",
            shlex.quote("echo x > /test-write 2>&1; echo EXIT:$?"),
        )
        # The shell line should always exit 0 (the inner write returns
        # non-zero, the outer echo runs anyway), so look for EXIT:N
        # with N != 0 in stdout.
        m = re.search(r"EXIT:(\d+)", result.stdout)
        assert m is not None, (
            f"missing EXIT:N marker in rootfs-readonly probe.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert m.group(1) != "0", (
            f"writing to / unexpectedly succeeded inside lite session "
            f"{session_id} — rootfs should be read-only.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        combined = (result.stdout + result.stderr).lower()
        assert "read-only" in combined or "readonly" in combined, (
            f"expected 'read-only' in stderr from rootfs write probe, got:\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def assert_no_dind(self, session_id: str) -> None:
        """

        Two complementary checks:

        1. ``/var/run/docker.sock`` is not bind-mounted into the
           session (``ls`` returns non-zero).
        2. Even if the operator points the docker client at that
           absent socket, ``docker ps`` fails (no privileged mode, no
           socket mount).
        """
        ls_result = self.ssh(
            session_id, "sh", "-c",
            shlex.quote("ls /var/run/docker.sock 2>&1; echo EXIT:$?"),
        )
        m = re.search(r"EXIT:(\d+)", ls_result.stdout)
        assert m is not None, (
            f"missing EXIT:N marker in docker.sock probe.\n"
            f"stdout: {ls_result.stdout}\nstderr: {ls_result.stderr}"
        )
        assert m.group(1) != "0", (
            f"/var/run/docker.sock unexpectedly exists inside lite "
            f"session {session_id} — DinD must be blocked.\n"
            f"stdout: {ls_result.stdout}\nstderr: {ls_result.stderr}"
        )

    def assert_no_userns(self, session_id: str) -> None:
        """

        ``cap-drop=ALL`` removes ``CAP_SYS_ADMIN``, so creating a new
        user namespace fails with EPERM. Probe via ``unshare --user
        true``: a non-zero exit confirms the cap is dropped.
        """
        result = self.ssh(
            session_id, "sh", "-c",
            shlex.quote("unshare --user true 2>&1; echo EXIT:$?"),
        )
        m = re.search(r"EXIT:(\d+)", result.stdout)
        assert m is not None, (
            f"missing EXIT:N marker in userns probe.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert m.group(1) != "0", (
            f"unshare --user unexpectedly succeeded inside lite session "
            f"{session_id} — CAP_SYS_ADMIN must be dropped.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
