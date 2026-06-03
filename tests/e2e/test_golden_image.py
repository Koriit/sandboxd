"""E2E tests for the golden base image / clone-path (M8.5).

Backend coverage: **Lima only**. The golden-image / clone-path machinery
(``sandbox-base`` Lima VM, ``base-image-meta.json``, ``rebuild-image``)
is entirely a Lima concept — the lite container backend pulls a
prebuilt OCI image (``ghcr.io/.../sandbox-lite-base``) and has no
clone path. These tests therefore do not take the ``backend`` fixture
and run unparametrised against Lima only.

These tests verify:

1. ``sandbox rebuild-image`` builds the golden ``sandbox-base`` Lima VM from
   scratch and the image is usable afterwards.
2. Session creation (with no flags that disable caching) takes the clone path
   rather than the legacy full-create path.
3. Staleness is detected via ``base-image-meta.json`` (hash mismatch / age)
   and the daemon honours the documented policy: "don't auto-rebuild on
   create -- use the stale image anyway, surface ``stale`` on status".

Because the base image is shared session state (created once per pytest
session by the ``_ensure_base_image`` fixture), the tests mutate/restore it
carefully:

- ``test_session_uses_clone_path`` is read-only with respect to the base
  image.
- ``test_staleness_detection`` mutates ``base-image-meta.json`` and restores
  it in ``finally``.
- ``test_rebuild_image_from_scratch`` runs last; it deletes and rebuilds
  the base image, leaving a fresh image suitable for any later tests.

Run with:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_golden_image.py -v --timeout=600
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from conftest import (
    OP_LIMA_HOME,
    _VM_RESOURCE_ARGS,
    limactl_cmd,
    parse_session_id,
    wait_for_state,
)

# Whole-file Lima-only: gates the per-test Lima prereq fixture and lets
# `-m "not lima"` exclude this file on container-only runs.
pytestmark = pytest.mark.lima

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Read the same env var the daemon uses; conftest defaults this to
# `sandbox-test-base` for the e2e suite so the test daemon never collides
# with the operator's production `sandbox-base` Lima instance.
BASE_VM_NAME = os.environ.get("SANDBOX_BASE_VM_NAME", "sandbox-test-base")
BASE_META_FILENAME = "base-image-meta.json"


def _base_meta_path(sandbox_daemon) -> Path:
    """Return the path to the daemon's base-image-meta.json.

    The daemon (running as the ``sandbox-test`` system user) writes this
    file to the 3-level per-operator LIMA_HOME:
        /var/lib/sandboxd/<sandbox-test-uid>/<op_uid>/lima/base-image-meta.json
    which is ``OP_LIMA_HOME/base-image-meta.json`` in conftest terms.
    The file is owned by the ``sandbox-test`` system user (daemon uid) with
    mode 0600; use the meta-file I/O helpers below rather than accessing
    the path directly.
    """
    return Path(OP_LIMA_HOME) / BASE_META_FILENAME


def _meta_exists(meta_path: Path) -> bool:
    """Return True if the meta file exists.

    The file is owned by ``sandbox-test`` with mode 0600. Route existence
    checks through ``sudo -n -u sandbox-test`` so the check succeeds even
    when the operator uid cannot read the file directly.
    """
    result = subprocess.run(
        ["sudo", "-n", "-u", "sandbox-test", "test", "-f", str(meta_path)],
        capture_output=True, timeout=10,
    )
    return result.returncode == 0


def _meta_read_text(meta_path: Path) -> str:
    """Read the meta file, routing through ``sudo -u sandbox-test``.

    The daemon writes the file as the ``sandbox-test`` system user with
    mode 0600 and no ACL entry for the operator uid, so a direct ``open()``
    raises PermissionError.  We use ``sudo -n -u sandbox-test cat`` to read
    it on behalf of the daemon user.
    """
    result = subprocess.run(
        ["sudo", "-n", "-u", "sandbox-test", "cat", str(meta_path)],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise PermissionError(
            f"sudo -u sandbox-test cat {meta_path} failed "
            f"(rc={result.returncode}): {result.stderr.strip()!r}"
        )
    return result.stdout


def _meta_write_text(meta_path: Path, content: str) -> None:
    """Write ``content`` to the meta file, routing through ``sudo -u sandbox-test``
    (see ``_meta_read_text`` for the ownership rationale).
    """
    result = subprocess.run(
        ["sudo", "-n", "-u", "sandbox-test",
         "tee", str(meta_path)],
        input=content, capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise PermissionError(
            f"sudo -u sandbox-test tee {meta_path} failed "
            f"(rc={result.returncode}): {result.stderr.strip()!r}"
        )


def _meta_unlink(meta_path: Path) -> None:
    """Remove the meta file, routing through ``sudo -u sandbox-test``."""
    subprocess.run(
        ["sudo", "-n", "-u", "sandbox-test", "rm", "-f", str(meta_path)],
        capture_output=True, timeout=10,
    )


# ---------------------------------------------------------------------------
# Daemon log capture
# ---------------------------------------------------------------------------

def _daemon_log_snapshot(sandbox_daemon) -> int:
    """Return the current byte length of the daemon stdout log.

    Used as a window start: a later :func:`_daemon_logs_since` reads only
    the bytes appended after this point. The daemon (launched via
    ``sudo -u sandbox-test``) writes its tracing output to a single
    per-session ``_stdout_log`` file, so capturing the size just before a
    test action
    and reading from it afterwards yields exactly that action's log window
    — excluding session-startup and base-image pre-warm output that would
    otherwise produce false positives (e.g. the pre-warm's "building golden
    base image" line). This is the file-based equivalent of the windowing
    the systemd harness got from ``journalctl --since``.
    """
    log_path = Path(sandbox_daemon["_stdout_log"])
    try:
        return log_path.stat().st_size
    except OSError:
        return 0


def _daemon_logs_since(sandbox_daemon, since_offset: int) -> str:
    """Return daemon log text appended since the byte offset captured by
    :func:`_daemon_log_snapshot`.
    """
    log_path = Path(sandbox_daemon["_stdout_log"])
    try:
        with open(log_path, "r", errors="replace") as f:
            f.seek(since_offset)
            return f.read()
    except FileNotFoundError:
        return ""


def _get_base_image_status(socket_path: str, timeout: float = 10.0) -> dict:
    """Issue ``GET /base-image-status`` over the daemon Unix socket.

    Returns the parsed JSON body. Raises AssertionError on failure.
    """
    # Minimal HTTP/1.1 client over a Unix socket -- avoids an extra dependency
    # (the existing E2E suite keeps third-party Python deps minimal).
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect(socket_path)
                sock.sendall(
                    b"GET /base-image-status HTTP/1.1\r\n"
                    b"Host: localhost\r\n"
                    b"Connection: close\r\n\r\n"
                )
                chunks: list[bytes] = []
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
            raw = b"".join(chunks)
            head, _, body = raw.partition(b"\r\n\r\n")
            status_line = head.split(b"\r\n", 1)[0]
            if b"200" not in status_line:
                raise AssertionError(
                    f"GET /base-image-status returned non-200: {status_line!r}\n"
                    f"body: {body!r}"
                )
            # Body may be chunked (Transfer-Encoding: chunked); handle the
            # common case of a single chunk by falling back to parsing the
            # last JSON object if direct parsing fails.
            try:
                return json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                text = body.decode("utf-8", errors="replace")
                # Try to find the JSON object in the chunked body.
                start = text.find("{")
                end = text.rfind("}")
                if start != -1 and end != -1 and end > start:
                    return json.loads(text[start : end + 1])
                raise
        except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
            last_err = e
            time.sleep(0.2)
    raise AssertionError(
        f"Could not reach daemon socket {socket_path} within {timeout}s: {last_err!r}"
    )


def _lima_list_names() -> list[str]:
    """List all Lima VM names from the per-operator LIMA_HOME.

    Uses ``limactl_cmd()`` so the correct per-operator LIMA_HOME is set
    for the cross-user harness.
    """
    result = subprocess.run(
        limactl_cmd("list", "--json"),
        capture_output=True, text=True, timeout=30,
    )
    names: list[str] = []
    for line in (result.stdout or "").strip().splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = entry.get("name")
        if name:
            names.append(name)
    return names


def _force_delete_base_vm() -> None:
    """Best-effort: force-delete the Lima base VM and its orphan directory.

    Uses ``limactl_cmd()`` so the correct LIMA_HOME (``OP_LIMA_HOME``) is set
    under the cross-user harness.  The orphan directory is cleaned from
    ``OP_LIMA_HOME``, not from the legacy ``~/.lima/``.
    """
    subprocess.run(
        limactl_cmd("delete", "--force", BASE_VM_NAME),
        capture_output=True, timeout=120,
    )
    # Remove any orphan <base-vm-name> directory left behind by a partial /
    # broken VM (e.g. from a hard crash mid-build).  The base VM lives at
    # OP_LIMA_HOME/<name>/.
    orphan = Path(OP_LIMA_HOME) / BASE_VM_NAME
    if orphan.exists():
        shutil.rmtree(orphan, ignore_errors=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.timeout(600)
def test_session_uses_clone_path(sandbox_cli, sandbox_daemon):
    """With a fresh golden image, session creation takes the clone path.

    The clone path is detected via two daemon log markers emitted by
    ``lima::clone_vm``:

      - ``"cloning base image"`` (entry)
      - ``"VM cloned from base image"`` (success)

    The legacy-path marker (``"creating VM"`` from ``lima::create_vm``) is
    asserted to be absent within the time window of this test's create call.
    """
    name = "m85-clone-path"
    session_id = None

    # 0. Sanity: base image is fresh (the _ensure_base_image fixture just
    #    ran rebuild-image). If it's not, bail out rather than produce a
    #    misleading assertion later.
    status = _get_base_image_status(sandbox_daemon["socket"])
    assert status.get("status") == "fresh", (
        f"Expected fresh base image before clone-path test; got {status!r}. "
        f"The _ensure_base_image fixture should have rebuilt it."
    )

    # 1. Snapshot log position so we only inspect output produced by this
    #    test.  The daemon writes its log to a per-session file; the
    #    timestamp marks the start of this test's window.
    log_since = _daemon_log_snapshot(sandbox_daemon)

    try:
        result = sandbox_cli(
            "create", "--name", name, *_VM_RESOURCE_ARGS, timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)

        wait_for_state(sandbox_cli, name, "Running", timeout=10)

        # 2. Inspect daemon log produced during this test.
        logs = _daemon_logs_since(sandbox_daemon, log_since)

        assert "cloning base image" in logs, (
            "Expected daemon to log 'cloning base image' on the clone path.\n"
            f"Daemon log since test start:\n{logs}"
        )
        assert "VM cloned from base image" in logs, (
            "Expected daemon to log 'VM cloned from base image' on success.\n"
            f"Daemon log since test start:\n{logs}"
        )
        # The legacy path would log "VM created" (from lima::create_vm) or
        # "VM created with custom template" (from
        # create_vm_with_custom_template). We search per-line to avoid a
        # false positive on substrings like "base VM created" (which comes
        # from build_base_image, not from the per-session create path).
        legacy_markers = ("VM created", "VM created with custom template")
        legacy_hits = [
            line
            for line in logs.splitlines()
            for marker in legacy_markers
            # Require "VM created" to be preceded by a space and the session
            # vm name (e.g. "sandbox-<id>"), which rules out "base VM created".
            if marker in line and "base VM" not in line
        ]
        assert not legacy_hits, (
            f"Unexpected legacy-create markers in daemon log: {legacy_hits!r}\n"
            f"Daemon log since test start:\n{logs}"
        )

    finally:
        if session_id is not None:
            sandbox_cli("rm", name, timeout=120)


@pytest.mark.timeout(600)
def test_staleness_detection(sandbox_cli, sandbox_daemon):
    """Mutating base-image-meta.json must flip status to 'stale' and
    session creation must still succeed via the clone path ("use anyway").

    The daemon's documented policy is NOT to auto-rebuild on create when the
    image is stale (see sandboxd/src/main.rs: "Don't auto-rebuild on create
    -- use the stale image."). We verify:

      1. ``GET /base-image-status`` returns ``{"status": "stale", ...}``
         after we corrupt the metadata's content_hash.
      2. A session created while metadata is marked stale still goes through
         the clone path and the daemon logs "base image is stale, using
         anyway" rather than rebuilding.
      3. After restoring the original metadata, status flips back to
         ``fresh`` so this test doesn't poison the rest of the suite.
    """
    meta_path = _base_meta_path(sandbox_daemon)
    assert _meta_exists(meta_path), (
        f"Expected daemon to have written {meta_path} during the "
        f"_ensure_base_image fixture, but it's missing."
    )

    original_contents = _meta_read_text(meta_path)
    name = "m85-staleness"
    session_id = None

    try:
        # 1. Corrupt content_hash so check_base_image returns Stale{hash_mismatch=true}.
        meta = json.loads(original_contents)
        meta["content_hash"] = "0" * 64  # 32 bytes hex -- matches sha256 output shape
        _meta_write_text(meta_path, json.dumps(meta, indent=2))

        # 2. Status endpoint now reports stale.
        status = _get_base_image_status(sandbox_daemon["socket"])
        assert status.get("status") == "stale", (
            f"Expected 'stale' after corrupting content_hash, got {status!r}."
        )
        # hash_mismatch must be true; age_days is whatever the image's real age is.
        assert status.get("hash_mismatch") is True, (
            f"Expected hash_mismatch=true, got {status!r}."
        )

        # 3. Create a session and verify:
        #    - clone path still taken ("cloning base image" in log)
        #    - daemon logs "base image is stale, using anyway" (policy)
        #    Snapshot log position before the create so we only inspect
        #    output produced by this test window.
        log_since = _daemon_log_snapshot(sandbox_daemon)
        result = sandbox_cli(
            "create", "--name", name, *_VM_RESOURCE_ARGS, timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed with stale image (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, name, "Running", timeout=10)

        logs = _daemon_logs_since(sandbox_daemon, log_since)
        assert "base image is stale, using anyway" in logs, (
            "Expected daemon to log the stale-but-use-anyway policy message.\n"
            f"Daemon log since test start:\n{logs}"
        )
        assert "cloning base image" in logs, (
            "Expected clone path to be taken even with a stale base image "
            "(documented policy is: don't auto-rebuild on create).\n"
            f"Daemon log since test start:\n{logs}"
        )
        # Rebuild must NOT have been triggered: base-image rebuild emits
        # "building golden base image" from LimaManager::build_base_image.
        assert "building golden base image" not in logs, (
            "Stale image should NOT trigger rebuild on create (per policy).\n"
            f"Daemon log since test start:\n{logs}"
        )

    finally:
        # Restore the original metadata so subsequent tests see 'fresh'.
        _meta_write_text(meta_path, original_contents)
        if session_id is not None:
            sandbox_cli("rm", name, timeout=120)

        # Sanity-check restoration.
        try:
            status = _get_base_image_status(sandbox_daemon["socket"])
            if status.get("status") != "fresh":
                pytest.fail(
                    f"Failed to restore base image metadata to 'fresh' state; "
                    f"got {status!r}. Subsequent tests may be affected."
                )
        except AssertionError:
            # Already failing -- don't mask the primary failure.
            pass


@pytest.mark.timeout(600)
def test_rebuild_image_from_scratch(sandbox_binaries, sandbox_daemon, _ensure_base_image):
    """Delete the golden base image and run ``sandbox rebuild-image``;
    the command must succeed and leave a usable base image behind.

    NB: this test is intentionally placed last in the file. It mutates the
    session-scoped base image (delete + rebuild). The end state is a FRESH
    golden image, which is exactly what any subsequent test expects.
    """
    # 1. Delete the Lima base VM (and orphan directory) so rebuild truly
    #    rebuilds from scratch rather than picking up an existing image.
    _force_delete_base_vm()

    # Also remove the metadata file so check_base_image returns Missing.
    meta_path = _base_meta_path(sandbox_daemon)
    if _meta_exists(meta_path):
        _meta_unlink(meta_path)

    # Sanity: VM really is gone.
    vm_names = _lima_list_names()
    assert BASE_VM_NAME not in vm_names, (
        f"Base VM still present after delete: {vm_names!r}"
    )

    # Status should now be 'missing'.
    status = _get_base_image_status(sandbox_daemon["socket"])
    assert status.get("status") == "missing", (
        f"Expected status 'missing' after deleting base VM + metadata, got {status!r}."
    )

    # 2. Invoke `sandbox rebuild-image`. Budget well above the ~82s typical:
    #    cloud-init + apt can occasionally push past 3 minutes.
    socket_path = sandbox_daemon["socket"]
    rebuild = subprocess.run(
        [str(sandbox_binaries.sandbox), "--socket", socket_path, "rebuild-image"],
        capture_output=True, text=True, timeout=480,
    )
    assert rebuild.returncode == 0, (
        f"sandbox rebuild-image failed (rc={rebuild.returncode}).\n"
        f"stdout: {rebuild.stdout}\nstderr: {rebuild.stderr}"
    )

    # 3. Base VM exists again.
    vm_names_after = _lima_list_names()
    assert BASE_VM_NAME in vm_names_after, (
        f"Base VM not present after rebuild: {vm_names_after!r}"
    )

    # 4. Metadata file was recreated with a fresh timestamp + hash.
    assert _meta_exists(meta_path), (
        f"Expected {meta_path} to be written by rebuild-image, but it's missing."
    )
    meta = json.loads(_meta_read_text(meta_path))
    assert "built_at" in meta and "content_hash" in meta, (
        f"base-image-meta.json is missing required fields: {meta!r}"
    )
    assert meta["content_hash"], "content_hash must be a non-empty string"

    # 5. Status endpoint reports the image is usable.
    status = _get_base_image_status(sandbox_daemon["socket"])
    assert status.get("status") == "fresh", (
        f"Expected 'fresh' after rebuild-image, got {status!r}."
    )

    # 6. The rebuilt image is reachable via limactl list (it's stopped,
    #    so use `start` probe-free alternative: `limactl list --json` entry
    #    has an `sshLocalPort` only when running, which we don't require.
    #    Asserting presence in the list is sufficient -- a VM that failed
    #    to provision is cleaned up by build_base_image's error path).
    #    Uses limactl_cmd() so OP_LIMA_HOME is set under the cross-user
    #    harness.
    entry = next(
        (
            json.loads(line)
            for line in subprocess.run(
                limactl_cmd("list", "--json"),
                capture_output=True, text=True, timeout=30,
            ).stdout.strip().splitlines()
            if BASE_VM_NAME in line
        ),
        None,
    )
    assert entry is not None, f"{BASE_VM_NAME} not in limactl list --json output"
    # Expect VM to be Stopped (build_base_image stops it after install).
    assert entry.get("status") in {"Stopped", "Running"}, (
        f"Unexpected status for rebuilt base VM: {entry!r}"
    )
