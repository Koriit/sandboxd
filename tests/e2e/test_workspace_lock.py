"""E2E tests for the ``sandbox workspace`` lock subsystem.

The lock subsystem ships alongside the ``sandbox workspace
push|pull|unlock`` CLI surface; this file exercises the operator-facing
edge cases that aren't covered by the daemon-spawning integration tests
in ``sandboxd/sandboxd/tests/integration_workspace_lock.rs``:

- ``test_workspace_lock_blocks_stop_during_push`` — A held lock makes
  ``sandbox stop`` return a 409 with the prescribed
  ``sandbox workspace unlock <s> --force`` hint. After release via
  HTTP, ``sandbox stop`` succeeds.
- ``test_workspace_lock_unlock_force_recovery`` — A held lock is
  cleared via ``sandbox workspace unlock --force``; the previously
  blocked ``sandbox stop`` then succeeds.
- ``test_workspace_unlock_idempotent`` — ``sandbox workspace unlock``
  against an unlocked session is a 200 no-op success for both with-
  and without- ``--force``.

These tests acquire the lock directly via the daemon's UDS HTTP socket
(``POST /sessions/<id>/workspace-lock``) rather than racing a
subprocess against ``sandbox stop``: the HTTP-direct path is
deterministic, the subprocess race is timing-sensitive and flake-prone.
The harness's ``sandbox_daemon`` fixture exposes the socket path; we
speak raw HTTP/1.1 over the Unix socket from Python's stdlib (no extra
dependencies needed — the
``conftest.py::_query_base_image_status`` helper is the established
precedent for this pattern).

Backend coverage: container backend only. The lock subsystem is
backend-agnostic — the daemon's per-session mutex does not care
whether the underlying session is Lima or container — and the
container-backend coverage runs in ~30s per test, where Lima would
add 3-10 minutes per parametrization without exercising any
additional contract surface.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile

import pytest

from conftest import (
    LIMA_VM_HOME,
    make_create_args,
    parse_session_id,
    wait_for_state,
)


# ---------------------------------------------------------------------------
# HTTP-over-unix helpers (stdlib only)
# ---------------------------------------------------------------------------

def _http_request(
    socket_path: str,
    method: str,
    path: str,
    body: str | None = None,
    timeout: float = 15.0,
) -> tuple[int, str]:
    """Send a minimal HTTP/1.1 request over a Unix-domain socket.

    Mirrors ``conftest.py::_query_base_image_status`` — a stdlib-only
    client so this test file adds no new Python dependencies. Returns
    ``(status_code, body_str)``; raises on transport-level errors.
    """
    headers = [
        f"{method} {path} HTTP/1.1",
        "Host: localhost",
        "Connection: close",
    ]
    if body is not None:
        headers.append("Content-Type: application/json")
        headers.append(f"Content-Length: {len(body)}")
    req = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8")
    if body is not None:
        req += body.encode("utf-8")

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(socket_path)
        s.sendall(req)
        chunks: list[bytes] = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    raw = b"".join(chunks)
    head, _, body_bytes = raw.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0] if head else b""
    # `HTTP/1.1 200 OK` → status code in the second field.
    parts = status_line.split(b" ", 2)
    if len(parts) < 2:
        raise RuntimeError(f"malformed response: {raw!r}")
    status = int(parts[1])
    return status, body_bytes.decode("utf-8", errors="replace")


def _acquire_lock(socket_path: str, session_id: str, op: str = "push") -> str:
    """Acquire a workspace lock via ``POST`` and return the lock_token."""
    status, body = _http_request(
        socket_path,
        "POST",
        f"/sessions/{session_id}/workspace-lock",
        body=json.dumps({"op": op}),
    )
    assert status == 200, (
        f"acquire lock op={op!r} must return 200; got {status}, body: {body}"
    )
    parsed = json.loads(body)
    token = parsed.get("lock_token")
    assert isinstance(token, str) and token, (
        f"acquire body must carry a non-empty `lock_token`; got: {parsed!r}"
    )
    return token


def _release_lock(
    socket_path: str,
    session_id: str,
    token: str,
    force: bool = False,
) -> tuple[int, str]:
    """Release a workspace lock via ``DELETE``; return ``(status, body)``."""
    return _http_request(
        socket_path,
        "DELETE",
        f"/sessions/{session_id}/workspace-lock",
        body=json.dumps({"lock_token": token, "force": force}),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.container
@pytest.mark.timeout(600)
def test_workspace_lock_blocks_stop_during_push(
    sandbox_cli, sandbox_daemon, tmp_path,
):
    """

    Create a ``local:`` session. Acquire the workspace lock directly
    via HTTP (simulating an in-flight push). Try ``sandbox stop``.
    Assert:

    1. ``sandbox stop`` exits non-zero.
    2. The CLI output names the recovery path
       (``sandbox workspace unlock ... --force``).

    Then release the lock via HTTP. Re-try ``sandbox stop``. Assert
    exit 0.

    Container backend per file docstring — the lock subsystem is
    backend-agnostic.
    """
    backend = "container"
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-lock-blocks-stop-")
        with open(os.path.join(host_dir, "placeholder.txt"), "w") as f:
            f.write("ok\n")

        guest_path = f"{LIMA_VM_HOME}/work"
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-lock-stop",
                "--workspace", f"local:{host_dir}:{guest_path}",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-lock-stop", "Running", timeout=10)

        # Acquire the lock directly via HTTP. The CLI's push subcommand
        # would acquire-then-release inside one process and the test
        # would have to race the subprocess; the HTTP-direct path is
        # deterministic.
        socket_path = sandbox_daemon["socket"]
        token = _acquire_lock(socket_path, session_id, op="push")

        # `sandbox stop` must refuse with 409 + recovery hint.
        stop = sandbox_cli("stop", "ws-lock-stop", timeout=60)
        assert stop.returncode != 0, (
            f"sandbox stop must refuse while the lock is held; "
            f"rc={stop.returncode}\nstdout: {stop.stdout}\nstderr: {stop.stderr}"
        )
        combined = (stop.stdout or "") + (stop.stderr or "")
        assert "active push operation" in combined, (
            f"stop refusal must name the active op; got:\n"
            f"stdout: {stop.stdout}\nstderr: {stop.stderr}"
        )
        assert "sandbox workspace unlock" in combined, (
            f"stop refusal must carry the `sandbox workspace unlock` "
            f"recovery hint; got:\nstdout: {stop.stdout}\nstderr: {stop.stderr}"
        )

        # Release the lock via HTTP — clean (matching-token) release.
        rel_status, rel_body = _release_lock(
            socket_path, session_id, token, force=False,
        )
        assert rel_status == 200, (
            f"clean release must return 200; got {rel_status}, body: {rel_body}"
        )

        # Re-try stop — must succeed now that the lock is clear.
        stop2 = sandbox_cli("stop", "ws-lock-stop", timeout=120)
        assert stop2.returncode == 0, (
            f"sandbox stop after release must succeed; "
            f"rc={stop2.returncode}\nstdout: {stop2.stdout}\nstderr: {stop2.stderr}"
        )

        sandbox_cli("rm", "ws-lock-stop", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-lock-stop", timeout=120)
        if host_dir is not None:
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass


@pytest.mark.container
@pytest.mark.timeout(600)
def test_workspace_lock_unlock_force_recovery(
    sandbox_cli, sandbox_daemon, tmp_path,
):
    """

    Acquire a lock via HTTP. Confirm ``sandbox stop`` is blocked. Run
    ``sandbox workspace unlock <session> --force``. Assert exit 0.
    Re-try ``sandbox stop``. Assert success.

    This pins the operator-facing escape hatch for an orphan lock —
    the typical case is "CLI killed mid-push, no token persisted,
    cannot release normally", so ``--force`` is the documented
    recovery path.
    """
    backend = "container"
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-lock-unlock-force-")
        with open(os.path.join(host_dir, "placeholder.txt"), "w") as f:
            f.write("ok\n")

        guest_path = f"{LIMA_VM_HOME}/work"
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-lock-force",
                "--workspace", f"local:{host_dir}:{guest_path}",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-lock-force", "Running", timeout=10)

        # Acquire the lock; intentionally discard the token to simulate
        # the "CLI killed mid-push" orphan case.
        socket_path = sandbox_daemon["socket"]
        _acquire_lock(socket_path, session_id, op="push")

        # Confirm stop is blocked while the lock is held.
        stop = sandbox_cli("stop", "ws-lock-force", timeout=60)
        assert stop.returncode != 0, (
            f"sandbox stop must refuse while lock is held; "
            f"rc={stop.returncode}\nstdout: {stop.stdout}\nstderr: {stop.stderr}"
        )

        # Run the operator-facing recovery — `unlock --force`.
        unlock = sandbox_cli(
            "workspace", "unlock", "ws-lock-force", "--force",
            timeout=60,
        )
        assert unlock.returncode == 0, (
            f"`sandbox workspace unlock --force` must succeed; "
            f"rc={unlock.returncode}\nstdout: {unlock.stdout}\nstderr: {unlock.stderr}"
        )

        # Re-try stop — must now succeed.
        stop2 = sandbox_cli("stop", "ws-lock-force", timeout=120)
        assert stop2.returncode == 0, (
            f"sandbox stop after `unlock --force` must succeed; "
            f"rc={stop2.returncode}\nstdout: {stop2.stdout}\nstderr: {stop2.stderr}"
        )

        sandbox_cli("rm", "ws-lock-force", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-lock-force", timeout=120)
        if host_dir is not None:
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass


@pytest.mark.container
@pytest.mark.timeout(600)
def test_workspace_unlock_idempotent(
    sandbox_cli, sandbox_daemon, tmp_path,
):
    """

    Create a ``local:`` session (no lock held). Run ``sandbox workspace
    unlock <session>`` without ``--force``. Assert exit 0 — the daemon
    treats release-on-Unlocked as idempotent regardless of token
    validity (the wrong-token vs. force=true / force=false adjudication
    only fires when a lock is actually held).

    Repeat with ``--force``. Assert exit 0.

    Both runs must surface the success message so an automation system
    re-issuing ``unlock`` blindly doesn't see spurious 409s.
    """
    backend = "container"
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-lock-idempotent-")
        with open(os.path.join(host_dir, "placeholder.txt"), "w") as f:
            f.write("ok\n")

        guest_path = f"{LIMA_VM_HOME}/work"
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-lock-idem",
                "--workspace", f"local:{host_dir}:{guest_path}",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-lock-idem", "Running", timeout=10)

        # (1) Unlock without --force on an unlocked session.
        unlock1 = sandbox_cli(
            "workspace", "unlock", "ws-lock-idem",
            timeout=60,
        )
        assert unlock1.returncode == 0, (
            f"`unlock` (no --force) on an unlocked session must exit 0; "
            f"rc={unlock1.returncode}\nstdout: {unlock1.stdout}\n"
            f"stderr: {unlock1.stderr}"
        )
        # The CLI prints "workspace lock released" on success regardless
        # of whether anything was actually held — see 
        # command → idempotent on already-unlocked.
        assert "workspace lock released" in (unlock1.stdout or "") + (unlock1.stderr or ""), (
            f"unlock success output must surface the documented `workspace "
            f"lock released` token; got:\n"
            f"stdout: {unlock1.stdout}\nstderr: {unlock1.stderr}"
        )

        # (2) Unlock with --force on the still-unlocked session.
        unlock2 = sandbox_cli(
            "workspace", "unlock", "ws-lock-idem", "--force",
            timeout=60,
        )
        assert unlock2.returncode == 0, (
            f"`unlock --force` on an unlocked session must exit 0; "
            f"rc={unlock2.returncode}\nstdout: {unlock2.stdout}\n"
            f"stderr: {unlock2.stderr}"
        )
        assert "workspace lock released" in (unlock2.stdout or "") + (unlock2.stderr or ""), (
            f"unlock --force success output must surface the documented "
            f"`workspace lock released` token; got:\n"
            f"stdout: {unlock2.stdout}\nstderr: {unlock2.stderr}"
        )

        sandbox_cli("rm", "ws-lock-idem", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-lock-idem", timeout=120)
        if host_dir is not None:
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass
