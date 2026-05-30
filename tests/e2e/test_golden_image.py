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
    SANDBOX_HARNESS,
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

    Under the production-shaped harnesses (sandbox-systemd / sandbox-sudo)
    the daemon writes this file to the per-operator LIMA_HOME:
        /var/lib/sandboxd/<op_uid>/lima/base-image-meta.json
    which is ``OP_LIMA_HOME/base-image-meta.json`` in conftest terms.
    The file is owned by the operator uid, so the test process can read
    and write it directly without sudo.

    Under the legacy test-user harness the daemon and test process share a
    uid, so the file lives in the daemon's base_dir as before.
    """
    if SANDBOX_HARNESS in ("sandbox-systemd", "sandbox-sudo"):
        return Path(OP_LIMA_HOME) / BASE_META_FILENAME
    return Path(sandbox_daemon["base_dir"]) / BASE_META_FILENAME


def _read_log_since(log_path: Path, offset: int) -> str:
    """Return log contents starting at ``offset`` bytes."""
    try:
        with open(log_path, "rb") as f:
            f.seek(offset)
            return f.read().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def _log_size(log_path: Path) -> int:
    try:
        return log_path.stat().st_size
    except FileNotFoundError:
        return 0


def _daemon_log_path(sandbox_daemon) -> Path:
    """Return the file path the daemon writes tracing output to.

    ``tracing_subscriber::fmt`` writes to stdout by default, so we read the
    daemon's stdout log file (not stderr). Stderr is currently unused by the
    daemon -- this may change when the deferred --log-file flag lands.
    """
    return Path(sandbox_daemon["_stdout_log"])


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

    Uses ``limactl_cmd()`` so the correct LIMA_HOME is set under the
    cross-user harness (sandbox-systemd / sandbox-sudo).
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
    # broken VM (e.g. from a hard crash mid-build).  Under the cross-user
    # harness the base VM lives at OP_LIMA_HOME/<name>/; under the legacy
    # test-user harness it lives at ~/.lima/<name>/.
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
    log_path = _daemon_log_path(sandbox_daemon)
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

    # 1. Snapshot log offset so we only inspect output produced by this test.
    log_offset = _log_size(log_path)

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
        logs = _read_log_since(log_path, log_offset)

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
    assert meta_path.exists(), (
        f"Expected daemon to have written {meta_path} during the "
        f"_ensure_base_image fixture, but it's missing."
    )

    original_contents = meta_path.read_text()
    log_path = _daemon_log_path(sandbox_daemon)
    name = "m85-staleness"
    session_id = None

    try:
        # 1. Corrupt content_hash so check_base_image returns Stale{hash_mismatch=true}.
        meta = json.loads(original_contents)
        meta["content_hash"] = "0" * 64  # 32 bytes hex -- matches sha256 output shape
        meta_path.write_text(json.dumps(meta, indent=2))

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
        log_offset = _log_size(log_path)
        result = sandbox_cli(
            "create", "--name", name, *_VM_RESOURCE_ARGS, timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed with stale image (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, name, "Running", timeout=10)

        logs = _read_log_since(log_path, log_offset)
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
        meta_path.write_text(original_contents)
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
    if meta_path.exists():
        meta_path.unlink()

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
    assert meta_path.exists(), (
        f"Expected {meta_path} to be written by rebuild-image, but it's missing."
    )
    meta = json.loads(meta_path.read_text())
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
